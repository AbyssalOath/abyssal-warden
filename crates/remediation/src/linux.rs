//! Linux quarantine store.
//!
//! Layout (all created 0700/0600 and owned by the store's user):
//!
//! ```text
//! <root>/
//!   .lock                exclusive flock held while the store is open
//!   audit.log            hash-chained JSON Lines
//!   items/<id>.json      record + journal state
//!   items/<id>.data      "AWQDATA1" header + XOR-encoded content
//! ```
//!
//! Quarantine sequence (crash-safe; see `recover`):
//! 1. open the file relative to a pinned parent-directory handle, no symlinks;
//! 2. copy it, encoded, to `items/<id>.data.tmp`; fsync; re-read and verify;
//! 3. check the hash against the expected (detected) hash;
//! 4. write the record as `pending`;
//! 5. rename the copy to `items/<id>.data`; fsync the directory;
//! 6. confirm the name still refers to the same inode, then `unlinkat` it;
//!    fsync the parent directory;
//! 7. mark the record `quarantined`; append to the audit log.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    self as rfs, AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags,
    Stat,
};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use warden_core::{ObservedPath, Sha256Digest};

use crate::allowlist::{ALLOWLIST_FILE, AllowEntry, AllowlistFile, MAX_ALLOWLIST_BYTES};
use crate::audit::{AuditEntry, ChainHead, encode, verify_chain};
use crate::policy::{is_protected_path, native_path};
use crate::record::{hex, unhex};
use crate::{
    ItemState, OriginalFile, QuarantineId, QuarantineRecord, QuarantineRequest,
    RECORD_FORMAT_VERSION, RecoveryAction, RemediationError,
};

const DATA_MAGIC: &[u8; 8] = b"AWQDATA1";
const KEY_LEN: usize = 32;
const CHUNK: usize = 64 * 1024;
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

type Result<T> = std::result::Result<T, RemediationError>;

fn io_err(op: &'static str, path: &Path, e: impl Into<io::Error>) -> RemediationError {
    RemediationError::Io {
        op,
        path: path.to_owned(),
        source: e.into(),
    }
}

/// Points where tests simulate a crash. Only the test build can arm them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Crash after the pending record is written, before the copy is renamed.
    PendingRecordWritten,
    /// Crash after the copy is in place, before the original is removed.
    CopyCommitted,
    /// Crash after the original is removed, before the record is finalised.
    OriginalRemoved,
}

/// A quarantine store, opened and locked for exclusive use.
#[derive(Debug)]
pub struct QuarantineStore {
    root: PathBuf,
    root_fd: OwnedFd,
    items_fd: OwnedFd,
    _lock: OwnedFd,
    audit: File,
    head: ChainHead,
    euid: u32,
    on_behalf_of: Option<u32>,
    recovered: Vec<RecoveryAction>,
    /// Where audit anchors go (`None`: disabled).
    anchor: Option<PathBuf>,
    /// An audit anchor could not be sent to the system log.
    anchor_failed: bool,
    #[cfg(test)]
    pub(crate) fault: Option<Fault>,
}

impl QuarantineStore {
    /// Open (creating if needed) the store at `root`, lock it, and replay any
    /// interrupted operations.
    ///
    /// `root` and `root/items` must be directories owned by the effective
    /// user with no group/other permissions; they are created that way if
    /// missing. The store refuses to open if its audit log's hash chain is
    /// broken, since that indicates tampering or corruption that an operator
    /// must look at.
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_with(root, &AnchorTarget::FromEnvironment)
    }

    /// [`QuarantineStore::open`] with an explicit audit anchor target.
    pub fn open_with(root: &Path, anchor: &AnchorTarget) -> Result<Self> {
        let (parent, name) = split_checked(root)?;
        std::fs::create_dir_all(&parent).map_err(|e| io_err("create", &parent, e))?;
        let parent = std::fs::canonicalize(&parent).map_err(|e| io_err("resolve", &parent, e))?;
        let root = parent.join(&name);
        let euid = rustix::process::geteuid().as_raw();

        let parent_fd = open_dir_no_symlinks(&parent)?;
        mkdir_private(&parent_fd, &name, &root)?;
        let root_fd = open_private_dir(&parent_fd, &name, &root, euid)?;
        let items_path = root.join("items");
        mkdir_private(&root_fd, "items", &items_path)?;
        let items_fd = open_private_dir(&root_fd, "items", &items_path, euid)?;

        let lock = rfs::openat(
            &root_fd,
            ".lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| io_err("open", &root.join(".lock"), e))?;
        match rfs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(Errno::WOULDBLOCK) => return Err(RemediationError::StoreBusy),
            Err(e) => return Err(io_err("lock", &root, e)),
        }

        let audit_path = root.join("audit.log");
        let audit_fd = rfs::openat(
            &root_fd,
            "audit.log",
            OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| io_err("open", &audit_path, e))?;
        check_private(
            &rfs::fstat(&audit_fd).map_err(|e| io_err("stat", &audit_path, e))?,
            &audit_path,
            euid,
        )?;
        let mut audit = File::from(audit_fd);
        let head = verify_chain(&mut audit).map_err(|e| RemediationError::StoreInsecure {
            path: audit_path.clone(),
            reason: format!(
                "audit log failed verification ({e}); move it aside after investigating"
            ),
        })?;

        let mut store = Self {
            root,
            root_fd,
            items_fd,
            _lock: lock,
            audit,
            head,
            on_behalf_of: None,
            euid,
            recovered: Vec::new(),
            anchor: anchor.resolve(),
            anchor_failed: false,
            #[cfg(test)]
            fault: None,
        };
        store.recover()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Interrupted operations resolved when the store was opened.
    pub fn recovered(&self) -> &[RecoveryAction] {
        &self.recovered
    }

    /// Quarantine one file. On any error before the original is removed,
    /// the original is untouched and partial copies are cleaned up.
    pub fn quarantine(&mut self, req: &QuarantineRequest) -> Result<QuarantineRecord> {
        let result = self.quarantine_inner(req);
        if let Err(e) = &result {
            #[cfg(test)]
            if matches!(e, RemediationError::InjectedFault) {
                return result;
            }
            self.audit_event(
                "quarantine",
                None,
                Some(&req.path),
                req.expected_sha256,
                Err(e.to_string()),
            )?;
        }
        result
    }

    fn quarantine_inner(&mut self, req: &QuarantineRequest) -> Result<QuarantineRecord> {
        let path = &req.path;
        let (parent, name) = split_checked(path)?;
        if !req.allow_protected && is_protected_path(path) {
            return Err(RemediationError::Protected(path.clone()));
        }
        if path.starts_with(&self.root) {
            return Err(RemediationError::InsideStore(path.clone()));
        }
        let dir = open_dir_no_symlinks(&parent).map_err(|e| symlink_as_path_error(e, path))?;
        self.reject_store_dir(&dir, path)?;

        let fd = rfs::openat(
            &dir,
            name.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            Errno::LOOP => RemediationError::SymlinkInPath(path.clone()),
            e => io_err("open", path, e),
        })?;
        let st = rfs::fstat(&fd).map_err(|e| io_err("stat", path, e))?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(RemediationError::NotRegularFile(path.clone()));
        }
        let size = u64::try_from(st.st_size).unwrap_or(0);
        if size > req.max_size {
            return Err(RemediationError::TooLarge {
                path: path.clone(),
                limit: req.max_size,
            });
        }
        #[allow(clippy::useless_conversion)] // nlink_t is u32 on some targets.
        let links = u64::from(st.st_nlink);
        if links > 1 {
            return Err(RemediationError::HardLinked {
                path: path.clone(),
                links,
            });
        }

        // Processes running (mapping) this exact file. With `kill_processes`
        // they are paused now; the guard resumes them if anything below
        // fails, and they are killed only once the file is safely stored.
        let users = processes::processes_using(st.st_dev, st.st_ino);
        let mut process_notes = Vec::new();
        let paused = if req.kill_processes && !users.is_empty() {
            let (guard, problems) = processes::Paused::pause(&users);
            process_notes.extend(problems);
            Some(guard)
        } else {
            None
        };

        let id = QuarantineId::random().map_err(|e| io_err("random", path, io::Error::other(e)))?;
        let mut key = [0u8; KEY_LEN];
        getrandom::fill(&mut key).map_err(|e| io_err("random", path, io::Error::other(e)))?;
        let tmp_name = format!("{id}.data.tmp");
        let data_name = format!("{id}.data");

        // Steps 2-3: copy, verify, compare.
        let mut src = File::from(fd);
        let (sha256, copied) =
            match self.write_encoded(&mut src, &tmp_name, &key, req.max_size, path) {
                Ok(v) => v,
                Err(e) => {
                    let _ = rfs::unlinkat(&self.items_fd, tmp_name.as_str(), AtFlags::empty());
                    return Err(e);
                }
            };
        if let Some(expected) = req.expected_sha256
            && expected != sha256
        {
            let _ = rfs::unlinkat(&self.items_fd, tmp_name.as_str(), AtFlags::empty());
            return Err(RemediationError::FileChanged {
                path: path.clone(),
                expected,
                actual: sha256,
            });
        }

        // Step 4: journal.
        let now = OffsetDateTime::now_utc();
        let mut rec = QuarantineRecord {
            format_version: RECORD_FORMAT_VERSION,
            id: id.clone(),
            state: ItemState::Pending,
            original: OriginalFile {
                path: ObservedPath::from_path(path),
                size: copied,
                sha256,
                mode: st.st_mode & 0o7777,
                uid: st.st_uid,
                gid: st.st_gid,
                dev: st.st_dev,
                ino: st.st_ino,
                modified: OffsetDateTime::from_unix_timestamp(st.st_mtime).ok(),
            },
            key_hex: hex(&key),
            reason: req.reason.clone(),
            actor_uid: self.euid,
            created_at: now,
            updated_at: now,
            restored_to: None,
            notes: Vec::new(),
        };
        self.save(&rec)?;
        self.fault_point(Fault::PendingRecordWritten)?;

        // Step 5: commit the copy.
        rfs::renameat(
            &self.items_fd,
            tmp_name.as_str(),
            &self.items_fd,
            data_name.as_str(),
        )
        .map_err(|e| io_err("rename", &self.root.join("items").join(&data_name), e))?;
        rfs::fsync(&self.items_fd).map_err(|e| io_err("sync", &self.root, e))?;
        self.fault_point(Fault::CopyCommitted)?;

        // Step 6: remove the original, only if it is still the same file.
        let still_same = rfs::statat(&dir, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map(|now| now.st_dev == st.st_dev && now.st_ino == st.st_ino)
            .unwrap_or(false);
        if !still_same {
            self.roll_back(&mut rec, "the path no longer referred to the copied file")?;
            return Err(RemediationError::Replaced { path: path.clone() });
        }
        if let Err(e) = rfs::unlinkat(&dir, name.as_os_str(), AtFlags::empty()) {
            self.roll_back(&mut rec, &format!("removing the original failed: {e}"))?;
            return Err(io_err("remove", path, e));
        }
        rfs::fsync(&dir).map_err(|e| io_err("sync", &parent, e))?;
        self.fault_point(Fault::OriginalRemoved)?;

        if !users.is_empty() {
            let list = users
                .iter()
                .map(|p| format!("PID {} ({})", p.pid, p.name))
                .collect::<Vec<_>>()
                .join(", ");
            match paused {
                Some(guard) => {
                    process_notes.extend(guard.kill());
                    rec.notes
                        .push(format!("killed process(es) running the file: {list}"));
                }
                None => rec.notes.push(format!(
                    "still running from the quarantined file: {list} (not stopped; use \
                     --kill-processes to stop them)"
                )),
            }
            rec.notes.extend(process_notes);
        }

        // Step 7.
        rec.state = ItemState::Quarantined;
        rec.updated_at = OffsetDateTime::now_utc();
        self.save(&rec)?;
        self.audit_event("quarantine", Some(&id), Some(path), Some(sha256), Ok(None))?;
        Ok(rec)
    }

    /// Restore an item to its original directory, or to `dest_dir`.
    ///
    /// Refuses to overwrite, to write into a directory writable by group or
    /// others, or into a directory owned by someone other than root, the
    /// caller or the file's original owner. Setuid/setgid bits are not
    /// restored.
    pub fn restore(&mut self, id: &QuarantineId, dest_dir: Option<&Path>) -> Result<PathBuf> {
        let result = self.restore_inner(id, dest_dir);
        let outcome = match &result {
            Ok(p) => Ok(Some(format!("restored to {}", p.display()))),
            Err(e) => Err(e.to_string()),
        };
        self.audit_event("restore", Some(id), None, None, outcome)?;
        result
    }

    fn restore_inner(&mut self, id: &QuarantineId, dest_dir: Option<&Path>) -> Result<PathBuf> {
        let mut rec = self.get(id)?;
        if rec.state != ItemState::Quarantined {
            return Err(RemediationError::InvalidState {
                id: id.clone(),
                state: rec.state,
            });
        }
        let original = native_path(&rec.original.path)
            .ok_or_else(|| corrupt(id, "original path cannot be reconstructed"))?;
        let (orig_parent, name) = split_checked(&original)?;
        let target_dir = match dest_dir {
            Some(d) => {
                let (p, n) = split_checked(d)?;
                p.join(n)
            }
            None => orig_parent,
        };
        let target = target_dir.join(&name);
        if target.starts_with(&self.root) {
            return Err(RemediationError::InsideStore(target));
        }
        let dir = open_dir_no_symlinks(&target_dir).map_err(|e| match e {
            RemediationError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                RemediationError::UnsafeTarget {
                    path: target_dir.clone(),
                    reason: "the directory does not exist".into(),
                }
            }
            e => e,
        })?;
        self.reject_store_dir(&dir, &target)?;
        let dst = rfs::fstat(&dir).map_err(|e| io_err("stat", &target_dir, e))?;
        if dst.st_mode & 0o022 != 0 {
            return Err(RemediationError::UnsafeTarget {
                path: target_dir,
                reason: "the directory is writable by group or others".into(),
            });
        }
        if ![0, self.euid, rec.original.uid].contains(&dst.st_uid) {
            return Err(RemediationError::UnsafeTarget {
                path: target_dir,
                reason: format!("the directory is owned by uid {}", dst.st_uid),
            });
        }

        let key = unhex(&rec.key_hex)
            .filter(|k| k.len() == KEY_LEN)
            .ok_or_else(|| corrupt(id, "invalid key"))?;
        let tmp_name = format!(".aw-restore-{id}");
        let out_fd = rfs::openat(
            &dir,
            tmp_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| io_err("create", &target_dir.join(&tmp_name), e))?;
        let cleanup = |dir: &OwnedFd| {
            let _ = rfs::unlinkat(dir, tmp_name.as_str(), AtFlags::empty());
        };
        let mut out = File::from(out_fd);
        let (sha, _) = match self.decode_to(id, &key, Some(&mut out)) {
            Ok(v) => v,
            Err(e) => {
                cleanup(&dir);
                return Err(e);
            }
        };
        if sha != rec.original.sha256 {
            cleanup(&dir);
            return Err(corrupt(
                id,
                "decoded content does not match the recorded SHA-256",
            ));
        }

        let mut notes = Vec::new();
        let mode = rec.original.mode & 0o777;
        if rec.original.mode & 0o6000 != 0 {
            notes.push("setuid/setgid bits were not restored".to_owned());
        }
        let finish = || -> io::Result<()> {
            rfs::fchmod(&out, Mode::from_raw_mode(mode))?;
            if self.euid == 0 {
                rfs::fchown(
                    &out,
                    Some(rustix::fs::Uid::from_raw(rec.original.uid)),
                    Some(rustix::fs::Gid::from_raw(rec.original.gid)),
                )?;
            }
            out.sync_all()
        };
        if let Err(e) = finish() {
            cleanup(&dir);
            return Err(io_err("finalise", &target, e));
        }
        if self.euid != 0 && rec.original.uid != self.euid {
            notes.push(format!(
                "owner not restored (was uid {}; restoring as uid {})",
                rec.original.uid, self.euid
            ));
        }

        match rfs::renameat_with(
            &dir,
            tmp_name.as_str(),
            &dir,
            name.as_os_str(),
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EXIST) => {
                cleanup(&dir);
                return Err(RemediationError::TargetExists(target));
            }
            // Filesystems without RENAME_NOREPLACE: link(2) also refuses to
            // replace an existing name.
            Err(Errno::INVAL) => {
                let linked = rfs::linkat(
                    &dir,
                    tmp_name.as_str(),
                    &dir,
                    name.as_os_str(),
                    AtFlags::empty(),
                );
                cleanup(&dir);
                match linked {
                    Ok(()) => {}
                    Err(Errno::EXIST) => return Err(RemediationError::TargetExists(target)),
                    Err(e) => return Err(io_err("restore", &target, e)),
                }
            }
            Err(e) => {
                cleanup(&dir);
                return Err(io_err("restore", &target, e));
            }
        }
        rfs::fsync(&dir).map_err(|e| io_err("sync", &target_dir, e))?;

        let data_name = format!("{id}.data");
        rfs::unlinkat(&self.items_fd, data_name.as_str(), AtFlags::empty())
            .map_err(|e| io_err("remove", &self.root.join("items").join(&data_name), e))?;
        rec.state = ItemState::Restored;
        rec.updated_at = OffsetDateTime::now_utc();
        rec.restored_to = Some(ObservedPath::from_path(&target));
        rec.notes.extend(notes);
        self.save(&rec)?;
        Ok(target)
    }

    /// Permanently delete a quarantined item's content. The record is kept
    /// (state `deleted`) for the audit trail.
    pub fn delete(&mut self, id: &QuarantineId) -> Result<()> {
        let result = self.delete_inner(id);
        let outcome = result.as_ref().map(|()| None).map_err(ToString::to_string);
        self.audit_event("delete", Some(id), None, None, outcome)?;
        result
    }

    fn delete_inner(&mut self, id: &QuarantineId) -> Result<()> {
        let mut rec = self.get(id)?;
        if rec.state != ItemState::Quarantined {
            return Err(RemediationError::InvalidState {
                id: id.clone(),
                state: rec.state,
            });
        }
        let data_name = format!("{id}.data");
        match rfs::unlinkat(&self.items_fd, data_name.as_str(), AtFlags::empty()) {
            Ok(()) => {}
            Err(Errno::NOENT) => rec.notes.push("content was already missing".into()),
            Err(e) => {
                return Err(io_err(
                    "remove",
                    &self.root.join("items").join(&data_name),
                    e,
                ));
            }
        }
        rfs::fsync(&self.items_fd).map_err(|e| io_err("sync", &self.root, e))?;
        rec.state = ItemState::Deleted;
        rec.updated_at = OffsetDateTime::now_utc();
        self.save(&rec)
    }

    /// The allow-list (exact SHA-256 values the user chose to keep).
    pub fn allowlist(&self) -> Result<Vec<AllowEntry>> {
        Ok(self.read_allowlist_file()?.entries)
    }

    /// Add `sha256` to the allow-list (no-op if present). Audit-logged.
    pub fn allow(
        &mut self,
        sha256: Sha256Digest,
        reason: &str,
        item: Option<&QuarantineId>,
        detection_name: Option<&str>,
    ) -> Result<()> {
        let mut list = self.read_allowlist_file()?;
        if !list.entries.iter().any(|e| e.sha256 == sha256) {
            if list.entries.len() >= crate::MAX_ALLOW_ENTRIES {
                return Err(RemediationError::StoreInsecure {
                    path: self.root.join(ALLOWLIST_FILE),
                    reason: format!(
                        "the allow-list is full ({} entries)",
                        crate::MAX_ALLOW_ENTRIES
                    ),
                });
            }
            list.entries.push(AllowEntry {
                sha256,
                added_at: OffsetDateTime::now_utc(),
                reason: reason.to_owned(),
                item: item.map(ToString::to_string),
                detection_name: detection_name.map(str::to_owned),
            });
            self.write_allowlist_file(&list)?;
        }
        self.audit_event(
            "allow",
            item,
            None,
            Some(sha256),
            Ok(Some(reason.to_owned())),
        )
    }

    /// Remove `sha256` from the allow-list. Returns whether it was present.
    pub fn disallow(&mut self, sha256: Sha256Digest) -> Result<bool> {
        let mut list = self.read_allowlist_file()?;
        let before = list.entries.len();
        list.entries.retain(|e| e.sha256 != sha256);
        let removed = list.entries.len() != before;
        if removed {
            self.write_allowlist_file(&list)?;
            self.audit_event("disallow", None, None, Some(sha256), Ok(None))?;
        }
        Ok(removed)
    }

    fn read_allowlist_file(&self) -> Result<AllowlistFile> {
        let path = self.root.join(ALLOWLIST_FILE);
        let fd = match rfs::openat(
            &self.root_fd,
            ALLOWLIST_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                return Ok(AllowlistFile {
                    format_version: 1,
                    entries: Vec::new(),
                });
            }
            Err(e) => return Err(io_err("open", &path, e)),
        };
        let mut data = Vec::new();
        File::from(fd)
            .take(MAX_ALLOWLIST_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|e| io_err("read", &path, e))?;
        if data.len() as u64 > MAX_ALLOWLIST_BYTES {
            return Err(RemediationError::StoreInsecure {
                path,
                reason: "the allow-list is too large".into(),
            });
        }
        crate::allowlist::parse(&data, &path)
    }

    fn write_allowlist_file(&self, list: &AllowlistFile) -> Result<()> {
        let path = self.root.join(ALLOWLIST_FILE);
        let data = serde_json::to_vec_pretty(list)
            .map_err(|e| io_err("encode", &path, io::Error::other(e)))?;
        write_atomic(&self.root_fd, ALLOWLIST_FILE, &data, &path)
    }

    /// Load one record.
    pub fn get(&self, id: &QuarantineId) -> Result<QuarantineRecord> {
        let name = format!("{id}.json");
        let path = self.root.join("items").join(&name);
        let fd = match rfs::openat(
            &self.items_fd,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Err(RemediationError::UnknownItem(id.clone())),
            Err(e) => return Err(io_err("open", &path, e)),
        };
        let mut data = Vec::new();
        File::from(fd)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|e| io_err("read", &path, e))?;
        if data.len() as u64 > MAX_RECORD_BYTES {
            return Err(corrupt(id, "record too large"));
        }
        let rec: QuarantineRecord = serde_json::from_slice(&data)
            .map_err(|e| corrupt(id, &format!("invalid record: {e}")))?;
        if &rec.id != id || rec.format_version != RECORD_FORMAT_VERSION {
            return Err(corrupt(id, "record ID or format version mismatch"));
        }
        Ok(rec)
    }

    /// All records, oldest first.
    pub fn list(&self) -> Result<Vec<QuarantineRecord>> {
        let mut out = Vec::new();
        for name in self.item_names()? {
            if let Some(id) = name
                .strip_suffix(".json")
                .and_then(|s| s.parse::<QuarantineId>().ok())
            {
                out.push(self.get(&id)?);
            }
        }
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    /// Records `uid` as the user later actions are performed for (a
    /// service acting on a client's request). The actor stays this
    /// process's own uid.
    pub fn on_behalf_of(&mut self, uid: Option<u32>) {
        self.on_behalf_of = uid;
    }

    /// The audit log's current head: sequence number and SHA-256 (hex) of
    /// the last entry, as anchored in the system log.
    pub fn audit_head(&self) -> (u64, &str) {
        (self.head.seq, &self.head.hash)
    }

    /// True if any audit anchor in this session could not be delivered to
    /// the system log.
    pub fn anchor_failed(&self) -> bool {
        self.anchor_failed
    }

    /// Re-verify the audit log's hash chain; returns the number of entries.
    /// Verifies the audit chain and returns every entry's sequence number
    /// and hash, for comparison with the system log's anchors.
    pub fn audit_chain(&mut self) -> Result<Vec<(u64, String)>> {
        use std::io::Seek;
        self.audit
            .rewind()
            .map_err(|e| io_err("read", &self.root.join("audit.log"), e))?;
        Ok(crate::audit::audit_chain(&mut self.audit)?)
    }

    /// The audit chain's identifier (in every anchor), once it has entries.
    pub fn chain_id(&self) -> Option<String> {
        self.head.chain_id()
    }

    pub fn verify_audit_log(&mut self) -> Result<u64> {
        use std::io::Seek;
        self.audit
            .rewind()
            .map_err(|e| io_err("read", &self.root.join("audit.log"), e))?;
        Ok(verify_chain(&mut self.audit)?.seq)
    }

    /// Replay interrupted operations; see the module docs. Idempotent.
    fn recover(&mut self) -> Result<()> {
        let names = self.item_names()?;
        let mut pending = Vec::new();
        for name in &names {
            if let Some(id) = name
                .strip_suffix(".json")
                .and_then(|s| s.parse::<QuarantineId>().ok())
            {
                let rec = self.get(&id)?;
                if rec.state == ItemState::Pending {
                    pending.push(rec);
                }
            }
        }
        for mut rec in pending {
            let (outcome, detail) = self.resolve_pending(&mut rec)?;
            rec.state = outcome;
            rec.updated_at = OffsetDateTime::now_utc();
            rec.notes.push(format!("recovery: {detail}"));
            self.save(&rec)?;
            let path = native_path(&rec.original.path);
            let result = if outcome == ItemState::Failed {
                Err(detail.clone())
            } else {
                Ok(Some(detail.clone()))
            };
            self.audit_event(
                "recover",
                Some(&rec.id),
                path.as_deref(),
                Some(rec.original.sha256),
                result,
            )?;
            self.recovered.push(RecoveryAction {
                id: rec.id.clone(),
                outcome,
                detail,
            });
        }
        // Stray temporaries: copies whose record was never written, and
        // record temporaries (the committed record is intact by rename).
        for name in self.item_names()? {
            let stray_record_tmp = name.starts_with('.') && name.ends_with(".json.tmp");
            let stray_data_tmp = name
                .strip_suffix(".data.tmp")
                .and_then(|s| s.parse::<QuarantineId>().ok())
                .is_some_and(|id| self.get(&id).is_err());
            if stray_record_tmp || stray_data_tmp {
                let _ = rfs::unlinkat(&self.items_fd, name.as_str(), AtFlags::empty());
            }
        }
        Ok(())
    }

    fn resolve_pending(&self, rec: &mut QuarantineRecord) -> Result<(ItemState, String)> {
        let id = rec.id.clone();
        let original_present = native_path(&rec.original.path)
            .and_then(|p| split_checked(&p).ok())
            .and_then(|(parent, name)| {
                let dir = open_dir_no_symlinks(&parent).ok()?;
                let st = rfs::statat(&dir, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW).ok()?;
                Some(st.st_dev == rec.original.dev && st.st_ino == rec.original.ino)
            })
            .unwrap_or(false);
        let data_name = format!("{id}.data");
        let tmp_name = format!("{id}.data.tmp");

        if original_present {
            let _ = rfs::unlinkat(&self.items_fd, data_name.as_str(), AtFlags::empty());
            let _ = rfs::unlinkat(&self.items_fd, tmp_name.as_str(), AtFlags::empty());
            let _ = rfs::fsync(&self.items_fd);
            return Ok((
                ItemState::RolledBack,
                "interrupted before the original was removed; the copy was discarded".into(),
            ));
        }
        let key = unhex(&rec.key_hex).filter(|k| k.len() == KEY_LEN);
        let verified = match key {
            Some(k) => self
                .decode_to(&id, &k, None)
                .map(|(sha, _)| sha == rec.original.sha256)
                .unwrap_or(false),
            None => false,
        };
        if verified {
            let _ = rfs::unlinkat(&self.items_fd, tmp_name.as_str(), AtFlags::empty());
            Ok((
                ItemState::Quarantined,
                "interrupted after the original was removed; the verified copy was kept".into(),
            ))
        } else {
            Ok((
                ItemState::Failed,
                "original is gone and no verified copy exists; the file was removed by \
                 something other than the quarantine operation"
                    .into(),
            ))
        }
    }

    fn roll_back(&mut self, rec: &mut QuarantineRecord, why: &str) -> Result<()> {
        let data_name = format!("{}.data", rec.id);
        let _ = rfs::unlinkat(&self.items_fd, data_name.as_str(), AtFlags::empty());
        let _ = rfs::fsync(&self.items_fd);
        rec.state = ItemState::RolledBack;
        rec.updated_at = OffsetDateTime::now_utc();
        rec.notes.push(format!("rolled back: {why}"));
        self.save(rec)
    }

    /// Copy `src` into `items/<tmp_name>` encoded, fsync, then re-read and
    /// verify. Returns the SHA-256 and size of the original content.
    fn write_encoded(
        &self,
        src: &mut File,
        tmp_name: &str,
        key: &[u8; KEY_LEN],
        max: u64,
        path: &Path,
    ) -> Result<(Sha256Digest, u64)> {
        let out_fd = rfs::openat(
            &self.items_fd,
            tmp_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| io_err("create", &self.root.join("items").join(tmp_name), e))?;
        let mut out = File::from(out_fd);
        out.write_all(DATA_MAGIC)
            .map_err(|e| io_err("write", &self.root, e))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut total: u64 = 0;
        loop {
            let n = match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_err("read", path, e)),
            };
            total += n as u64;
            if total > max {
                return Err(RemediationError::TooLarge {
                    path: path.to_owned(),
                    limit: max,
                });
            }
            hasher.update(&buf[..n]);
            xor_in_place(&mut buf[..n], key, total - n as u64);
            out.write_all(&buf[..n])
                .map_err(|e| io_err("write", &self.root, e))?;
        }
        out.sync_all().map_err(|e| io_err("sync", &self.root, e))?;
        let sha = Sha256Digest::from_bytes(hasher.finalize().into());

        // Read back what is on disk and check it decodes to the same content.
        let id_part = tmp_name.trim_end_matches(".data.tmp");
        let id: QuarantineId = id_part.parse()?;
        let (check, len) = self.decode_file(&id, tmp_name, key, None)?;
        if check != sha || len != total {
            return Err(corrupt(&id, "verification of the written copy failed"));
        }
        Ok((sha, total))
    }

    /// Decode `items/<id>.data`, hashing it and optionally writing it out.
    fn decode_to(
        &self,
        id: &QuarantineId,
        key: &[u8],
        out: Option<&mut File>,
    ) -> Result<(Sha256Digest, u64)> {
        self.decode_file(id, &format!("{id}.data"), key, out)
    }

    fn decode_file(
        &self,
        id: &QuarantineId,
        name: &str,
        key: &[u8],
        mut out: Option<&mut File>,
    ) -> Result<(Sha256Digest, u64)> {
        let path = self.root.join("items").join(name);
        let fd = rfs::openat(
            &self.items_fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| io_err("open", &path, e))?;
        let mut f = File::from(fd);
        let mut magic = [0u8; 8];
        f.read_exact(&mut magic)
            .map_err(|_| corrupt(id, "missing header"))?;
        if &magic != DATA_MAGIC {
            return Err(corrupt(id, "bad header"));
        }
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut total: u64 = 0;
        loop {
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_err("read", &path, e)),
            };
            xor_in_place(&mut buf[..n], key, total);
            total += n as u64;
            hasher.update(&buf[..n]);
            if let Some(o) = out.as_deref_mut() {
                o.write_all(&buf[..n])
                    .map_err(|e| io_err("write", &path, e))?;
            }
        }
        Ok((Sha256Digest::from_bytes(hasher.finalize().into()), total))
    }

    /// Atomically replace `items/<id>.json`.
    fn save(&self, rec: &QuarantineRecord) -> Result<()> {
        let name = format!("{}.json", rec.id);
        let path = self.root.join("items").join(&name);
        let data = serde_json::to_vec_pretty(rec)
            .map_err(|e| io_err("encode", &path, io::Error::other(e)))?;
        write_atomic(&self.items_fd, &name, &data, &path)
    }

    fn audit_event(
        &mut self,
        action: &str,
        id: Option<&QuarantineId>,
        path: Option<&Path>,
        sha256: Option<Sha256Digest>,
        outcome: std::result::Result<Option<String>, String>,
    ) -> Result<()> {
        let (outcome, detail) = match outcome {
            Ok(d) => ("ok", d),
            Err(e) => ("error", Some(e)),
        };
        let entry = AuditEntry {
            seq: 0,
            time: OffsetDateTime::now_utc(),
            actor_uid: self.euid,
            on_behalf_of: self.on_behalf_of,
            action: action.to_owned(),
            item: id.map(ToString::to_string),
            path: path.map(ObservedPath::from_path),
            sha256,
            outcome: outcome.to_owned(),
            detail,
            prev: String::new(),
        };
        let (line, head) = encode(entry, &self.head)?;
        let audit_path = self.root.join("audit.log");
        self.audit
            .write_all(&line)
            .map_err(|e| io_err("append", &audit_path, e))?;
        self.audit
            .sync_data()
            .map_err(|e| io_err("sync", &audit_path, e))?;
        let chain = head.chain_id().unwrap_or_default();
        if !anchor::send(
            self.anchor.as_deref(),
            head.seq,
            &head.hash,
            &chain,
            action,
            outcome,
        ) {
            self.anchor_failed = true;
        }
        self.head = head;
        Ok(())
    }

    fn item_names(&self) -> Result<Vec<String>> {
        let items = self.root.join("items");
        let dir = rfs::Dir::read_from(&self.items_fd).map_err(|e| io_err("list", &items, e))?;
        let mut names = Vec::new();
        for entry in dir {
            let entry = entry.map_err(|e| io_err("list", &items, e))?;
            if let Ok(n) = entry.file_name().to_str()
                && n != "."
                && n != ".."
            {
                names.push(n.to_owned());
            }
        }
        Ok(names)
    }

    fn reject_store_dir(&self, dir: &OwnedFd, path: &Path) -> Result<()> {
        let st = rfs::fstat(dir).map_err(|e| io_err("stat", path, e))?;
        for fd in [&self.root_fd, &self.items_fd] {
            let s = rfs::fstat(fd).map_err(|e| io_err("stat", &self.root, e))?;
            if s.st_dev == st.st_dev && s.st_ino == st.st_ino {
                return Err(RemediationError::InsideStore(path.to_owned()));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn fault_point(&self, at: Fault) -> Result<()> {
        if self.fault == Some(at) {
            return Err(RemediationError::InjectedFault);
        }
        Ok(())
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn fault_point(&self, _at: Fault) -> Result<()> {
        Ok(())
    }
}

/// Atomically replace `dir/name` with `data`: write a private temporary
/// file, fsync it, rename it over the target, fsync the directory.
fn write_atomic(dir: &OwnedFd, name: &str, data: &[u8], display: &Path) -> Result<()> {
    let tmp = format!(".{name}.tmp");
    let fd = rfs::openat(
        dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| io_err("create", display, e))?;
    let mut f = File::from(fd);
    f.write_all(data).map_err(|e| io_err("write", display, e))?;
    f.sync_all().map_err(|e| io_err("sync", display, e))?;
    rfs::renameat(dir, tmp.as_str(), dir, name).map_err(|e| io_err("rename", display, e))?;
    rfs::fsync(dir).map_err(|e| io_err("sync", display, e))
}

fn corrupt(id: &QuarantineId, reason: &str) -> RemediationError {
    RemediationError::Corrupt {
        id: id.clone(),
        reason: reason.to_owned(),
    }
}

fn xor_in_place(buf: &mut [u8], key: &[u8], offset: u64) {
    let klen = key.len() as u64;
    for (i, b) in buf.iter_mut().enumerate() {
        let k = key[((offset + i as u64) % klen) as usize];
        *b ^= k;
    }
}

/// Split an absolute path into parent and final component, rejecting `..`
/// and paths without a final normal component.
fn split_checked(path: &Path) -> Result<(PathBuf, OsString)> {
    let invalid = || RemediationError::InvalidPath(path.to_owned());
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Err(invalid());
    }
    let Some(Component::Normal(name)) = path.components().next_back() else {
        return Err(invalid());
    };
    let parent = path.parent().ok_or_else(invalid)?.to_path_buf();
    Ok((parent, name.to_owned()))
}

/// Open a directory, refusing symbolic links (and magic links) in *every*
/// component of the path.
fn open_dir_no_symlinks(path: &Path) -> Result<OwnedFd> {
    rfs::openat2(
        CWD,
        path.as_os_str().as_bytes(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::XDEV => RemediationError::SymlinkInPath(path.to_owned()),
        Errno::NOSYS => RemediationError::Io {
            op: "open (openat2 needs Linux 5.6 or later)",
            path: path.to_owned(),
            source: e.into(),
        },
        e => io_err("open", path, e),
    })
}

fn symlink_as_path_error(e: RemediationError, path: &Path) -> RemediationError {
    match e {
        RemediationError::SymlinkInPath(_) => RemediationError::SymlinkInPath(path.to_owned()),
        e => e,
    }
}

fn mkdir_private<P: rustix::path::Arg>(dir: &OwnedFd, name: P, display: &Path) -> Result<()> {
    match rfs::mkdirat(dir, name, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(io_err("create", display, e)),
    }
}

fn open_private_dir<P: rustix::path::Arg>(
    parent: &OwnedFd,
    name: P,
    display: &Path,
    euid: u32,
) -> Result<OwnedFd> {
    let fd = rfs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::NOTDIR => RemediationError::StoreInsecure {
            path: display.to_owned(),
            reason: "not a directory (or a symbolic link)".into(),
        },
        e => io_err("open", display, e),
    })?;
    check_private(
        &rfs::fstat(fd.as_fd()).map_err(|e| io_err("stat", display, e))?,
        display,
        euid,
    )?;
    Ok(fd)
}

fn check_private(st: &Stat, path: &Path, euid: u32) -> Result<()> {
    if st.st_uid != euid {
        return Err(RemediationError::StoreInsecure {
            path: path.to_owned(),
            reason: format!("owned by uid {}, not {euid}", st.st_uid),
        });
    }
    if st.st_mode & 0o077 != 0 {
        return Err(RemediationError::StoreInsecure {
            path: path.to_owned(),
            reason: format!("mode {:o} gives group/other access", st.st_mode & 0o7777),
        });
    }
    Ok(())
}

mod anchor;
mod processes;
pub use anchor::AnchorTarget;
#[cfg(test)]
mod tests;
