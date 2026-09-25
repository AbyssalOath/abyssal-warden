//! Windows quarantine store.
//!
//! Same layout, record format, audit chain and crash-safe sequence as the
//! Linux store (`linux.rs`); the Windows mechanisms differ:
//!
//! * **Private store:** the root gets a protected DACL (SYSTEM,
//!   Administrators, the owner) and is verified on every open; the store
//!   refuses to open if anyone else has access or if it is a reparse point.
//! * **No link following:** files are opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT`, and the handle's final path must equal
//!   the requested path, so a junction or symbolic link anywhere in the
//!   path is refused.
//! * **Pinned file:** the original is opened with `DELETE` access while
//!   sharing only `READ`, so nobody can modify, rename or delete it until it
//!   has been copied, verified and then deleted *through that handle*.
//! * **Restore without overwrite:** a temporary file is hard-linked to the
//!   target name (which fails if it exists), and target directories that
//!   other users may write into are refused.
//! * **Anchors:** each audit entry is also written to the Application event
//!   log (source `AbyssalWarden`).
//! * **Running programs:** found by image path; with `kill_processes` they
//!   are terminated after the copy is committed (Windows cannot pause them).
//!
//! Quarantine sequence: open and pin; copy encoded to `items/<id>.data.tmp`,
//! flush, re-read and verify; compare with the expected hash; write the
//! record as `pending`; rename the copy to `items/<id>.data`; delete the
//! original by handle; mark `quarantined`; audit.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use warden_core::{ObservedPath, Sha256Digest};
use warden_winsec::sddl;

use crate::allowlist::{ALLOWLIST_FILE, AllowEntry, AllowlistFile, MAX_ALLOWLIST_BYTES};
use crate::audit::{AuditEntry, ChainHead, encode, verify_chain};
use crate::common::{
    CHUNK, DATA_MAGIC, KEY_LEN, MAX_RECORD_BYTES, Result, anchor_text, corrupt, io_err,
    split_checked, xor_in_place,
};
use crate::policy::{is_protected_path, native_path};
use crate::record::{hex, unhex};
use crate::{
    ItemState, OriginalFile, QuarantineId, QuarantineRecord, QuarantineRequest,
    RECORD_FORMAT_VERSION, RecoveryAction, RemediationError,
};

const FILE_GENERIC_READ: u32 = 0x0012_0089;
const DELETE: u32 = 0x0001_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
/// Rights that let someone create or replace files in a directory.
const CREATE_IN_DIR: u32 = 0x2 | 0x4 | 0x40 | 0x1000_0000 | 0x4000_0000 | 0x0004_0000 | 0x0008_0000;
const EVENT_SOURCE: &str = "AbyssalWarden";
const SOCKET_ENV: &str = "ABYSSAL_WARDEN_SYSLOG_SOCKET";

/// Points where tests simulate a crash (shared with the Linux store's tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    PendingRecordWritten,
    CopyCommitted,
    OriginalRemoved,
}

/// Where audit anchors are written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AnchorTarget {
    /// The Application event log, unless `ABYSSAL_WARDEN_SYSLOG_SOCKET` is
    /// set to an empty value (tests).
    #[default]
    FromEnvironment,
    Disabled,
    EventLog,
}

impl AnchorTarget {
    fn enabled(&self) -> bool {
        match self {
            Self::Disabled => false,
            Self::EventLog => true,
            Self::FromEnvironment => std::env::var_os(SOCKET_ENV).is_none_or(|v| !v.is_empty()),
        }
    }
}

/// Lower-case path without the `\\?\` prefix, `\` separators, no trailing
/// separator: for comparing paths the way Windows resolves them.
pub(crate) fn norm(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    let s = if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned()
    };
    s.to_ascii_lowercase().trim_end_matches('\\').to_owned()
}

fn is_in_use(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
    )
}

/// A quarantine store, opened and locked for exclusive use.
#[derive(Debug)]
pub struct QuarantineStore {
    root: PathBuf,
    root_norm: String,
    items: PathBuf,
    _lock: File,
    audit: File,
    head: ChainHead,
    user_sid: String,
    on_behalf_of: Option<String>,
    recovered: Vec<RecoveryAction>,
    anchor: bool,
    anchor_failed: bool,
    #[cfg(test)]
    pub(crate) fault: Option<Fault>,
}

fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Opens `path` as a directory and checks that no reparse point was
/// followed anywhere along it.
fn open_dir_no_reparse(path: &Path) -> Result<File> {
    let dir = open_dir(path).map_err(|e| io_err("open", path, e))?;
    let meta = dir.metadata().map_err(|e| io_err("stat", path, e))?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RemediationError::SymlinkInPath(path.to_owned()));
    }
    let actual = warden_winsec::final_path(&dir).map_err(|e| io_err("resolve", path, e))?;
    if norm(&actual) != norm(path) {
        return Err(RemediationError::SymlinkInPath(path.to_owned()));
    }
    Ok(dir)
}

impl QuarantineStore {
    /// Open (creating if needed) the store at `root`, lock it, and replay any
    /// interrupted operations. See the Linux store for the guarantees.
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_with(root, &AnchorTarget::FromEnvironment)
    }

    pub fn open_with(root: &Path, anchor: &AnchorTarget) -> Result<Self> {
        let (parent, name) = split_checked(root)?;
        std::fs::create_dir_all(&parent).map_err(|e| io_err("create", &parent, e))?;
        let parent = std::fs::canonicalize(&parent).map_err(|e| io_err("resolve", &parent, e))?;
        let root = parent.join(&name);
        let user_sid =
            warden_winsec::process_user_sid().map_err(|e| io_err("identify", &root, e))?;

        let created = match std::fs::create_dir(&root) {
            Ok(()) => true,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(io_err("create", &root, e)),
        };
        if created {
            warden_winsec::set_protected_dacl(&root, &sddl::private_dacl(&user_sid))
                .map_err(|e| io_err("protect", &root, e))?;
        }
        open_dir_no_reparse(&root).map_err(|_| RemediationError::StoreInsecure {
            path: root.clone(),
            reason: "not a directory, or reached through a junction or symbolic link".into(),
        })?;
        let text = warden_winsec::security_descriptor(&root)
            .map_err(|e| io_err("read security of", &root, e))?;
        sddl::check_private(&text, &[sddl::SYSTEM, sddl::ADMINISTRATORS, &user_sid]).map_err(
            |reason| RemediationError::StoreInsecure {
                path: root.clone(),
                reason,
            },
        )?;

        let items = root.join("items");
        match std::fs::create_dir(&items) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_err("create", &items, e)),
        }
        open_dir_no_reparse(&items).map_err(|_| RemediationError::StoreInsecure {
            path: items.clone(),
            reason: "not a directory, or a junction or symbolic link".into(),
        })?;

        let lock_path = root.join(".lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&lock_path)
            .map_err(|e| io_err("open", &lock_path, e))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(RemediationError::StoreBusy),
            Err(std::fs::TryLockError::Error(e)) => return Err(io_err("lock", &root, e)),
        }

        let audit_path = root.join("audit.log");
        let mut audit = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&audit_path)
            .map_err(|e| io_err("open", &audit_path, e))?;
        let head = verify_chain(&mut audit).map_err(|e| RemediationError::StoreInsecure {
            path: audit_path.clone(),
            reason: format!(
                "audit log failed verification ({e}); move it aside after investigating"
            ),
        })?;

        let mut store = Self {
            root_norm: norm(&root),
            root,
            items,
            _lock: lock,
            audit,
            head,
            user_sid,
            on_behalf_of: None,
            recovered: Vec::new(),
            anchor: anchor.enabled(),
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

    pub fn recovered(&self) -> &[RecoveryAction] {
        &self.recovered
    }

    fn inside_store(&self, p: &Path) -> bool {
        let n = norm(p);
        n == self.root_norm || n.starts_with(&format!("{}\\", self.root_norm))
    }

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
        split_checked(path)?;
        if !req.allow_protected && is_protected_path(path) {
            return Err(RemediationError::Protected(path.clone()));
        }
        if self.inside_store(path) {
            return Err(RemediationError::InsideStore(path.clone()));
        }
        // Pin the file: read + delete for us, read-only sharing for others.
        let mut src = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| {
                if is_in_use(&e) {
                    RemediationError::InUse(path.clone())
                } else {
                    io_err("open", path, e)
                }
            })?;
        let meta = src.metadata().map_err(|e| io_err("stat", path, e))?;
        if meta.file_type().is_symlink()
            || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(RemediationError::SymlinkInPath(path.clone()));
        }
        if !meta.is_file() {
            return Err(RemediationError::NotRegularFile(path.clone()));
        }
        let actual = warden_winsec::final_path(&src).map_err(|e| io_err("resolve", path, e))?;
        if norm(&actual) != norm(path) {
            return Err(RemediationError::SymlinkInPath(path.clone()));
        }
        if self.inside_store(&actual) {
            return Err(RemediationError::InsideStore(path.clone()));
        }
        if meta.len() > req.max_size {
            return Err(RemediationError::TooLarge {
                path: path.clone(),
                limit: req.max_size,
            });
        }
        let info = winapi_util::file::information(&src).map_err(|e| io_err("stat", path, e))?;
        if info.number_of_links() > 1 {
            return Err(RemediationError::HardLinked {
                path: path.clone(),
                links: info.number_of_links(),
            });
        }
        let owner_sid = warden_winsec::security_descriptor(path)
            .ok()
            .and_then(|s| sddl::parse(&s))
            .and_then(|d| d.owner);
        let running: Vec<warden_winsec::ProcessInfo> = warden_winsec::processes()
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.image.as_deref().is_some_and(|i| norm(i) == norm(path)))
            .collect();

        let id = QuarantineId::random().map_err(|e| io_err("random", path, io::Error::other(e)))?;
        let mut key = [0u8; KEY_LEN];
        getrandom::fill(&mut key).map_err(|e| io_err("random", path, io::Error::other(e)))?;
        let tmp = self.items.join(format!("{id}.data.tmp"));
        let data = self.items.join(format!("{id}.data"));

        let (sha256, copied) =
            match self.write_encoded(&mut src, &tmp, &id, &key, req.max_size, path) {
                Ok(v) => v,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
            };
        if let Some(expected) = req.expected_sha256
            && expected != sha256
        {
            let _ = std::fs::remove_file(&tmp);
            return Err(RemediationError::FileChanged {
                path: path.clone(),
                expected,
                actual: sha256,
            });
        }

        let now = OffsetDateTime::now_utc();
        let mut rec = QuarantineRecord {
            format_version: RECORD_FORMAT_VERSION,
            id: id.clone(),
            state: ItemState::Pending,
            original: OriginalFile {
                path: ObservedPath::from_path(path),
                size: copied,
                sha256,
                mode: meta.file_attributes(),
                uid: 0,
                gid: 0,
                dev: info.volume_serial_number(),
                ino: info.file_index(),
                owner_sid,
                modified: meta.modified().ok().map(OffsetDateTime::from),
            },
            key_hex: hex(&key),
            reason: req.reason.clone(),
            actor_uid: 0,
            created_at: now,
            updated_at: now,
            restored_to: None,
            notes: Vec::new(),
        };
        self.save(&rec)?;
        self.fault_point(Fault::PendingRecordWritten)?;
        std::fs::rename(&tmp, &data).map_err(|e| io_err("rename", &data, e))?;
        self.fault_point(Fault::CopyCommitted)?;

        // Delete through the pinned handle. A running program's image cannot
        // be deleted; with `kill_processes` it is terminated first.
        let mut deleted = warden_winsec::delete_by_handle(&src);
        if deleted.is_err() && req.kill_processes && !running.is_empty() {
            let mut killed = Vec::new();
            for p in &running {
                match warden_winsec::terminate_if_image(p.pid, path) {
                    Ok(true) => killed.push(format!("PID {} ({})", p.pid, p.name)),
                    Ok(false) => {}
                    Err(e) => rec.notes.push(format!("could not stop PID {}: {e}", p.pid)),
                }
            }
            if !killed.is_empty() {
                rec.notes.push(format!(
                    "killed process(es) running the file: {}",
                    killed.join(", ")
                ));
            }
            for _ in 0..50 {
                std::thread::sleep(Duration::from_millis(100));
                deleted = warden_winsec::delete_by_handle(&src);
                if deleted.is_ok() {
                    break;
                }
            }
        }
        if let Err(e) = deleted {
            let why = if running.is_empty() {
                format!("removing the original failed: {e}")
            } else {
                format!("removing the original failed ({e}); it is running (use --kill-processes)")
            };
            self.roll_back(&mut rec, &why)?;
            return Err(if running.is_empty() {
                io_err("remove", path, e)
            } else {
                RemediationError::InUse(path.clone())
            });
        }
        drop(src);
        self.fault_point(Fault::OriginalRemoved)?;
        if !running.is_empty() && !req.kill_processes {
            let list = running
                .iter()
                .map(|p| format!("PID {} ({})", p.pid, p.name))
                .collect::<Vec<_>>()
                .join(", ");
            rec.notes.push(format!("was running as {list}"));
        }

        rec.state = ItemState::Quarantined;
        rec.updated_at = OffsetDateTime::now_utc();
        self.save(&rec)?;
        self.audit_event("quarantine", Some(&id), Some(path), Some(sha256), Ok(None))?;
        Ok(rec)
    }

    /// Restore an item to its original directory, or to `dest_dir`. Refuses
    /// to overwrite and to write into a directory that users other than
    /// SYSTEM, Administrators, this user or the file's original owner can
    /// write to.
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
        if self.inside_store(&target) {
            return Err(RemediationError::InsideStore(target));
        }
        open_dir_no_reparse(&target_dir).map_err(|e| match e {
            RemediationError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => {
                RemediationError::UnsafeTarget {
                    path: target_dir.clone(),
                    reason: "the directory does not exist".into(),
                }
            }
            e => e,
        })?;
        let text = warden_winsec::security_descriptor(&target_dir)
            .map_err(|e| io_err("read security of", &target_dir, e))?;
        let desc = sddl::parse(&text).ok_or_else(|| RemediationError::UnsafeTarget {
            path: target_dir.clone(),
            reason: "its security descriptor could not be analysed".into(),
        })?;
        let mut trusted: Vec<&str> = vec![
            sddl::SYSTEM,
            sddl::ADMINISTRATORS,
            sddl::TRUSTED_INSTALLER,
            &self.user_sid,
        ];
        if let Some(owner) = rec.original.owner_sid.as_deref() {
            trusted.push(owner);
        }
        let others = sddl::granted_to_others(&desc, CREATE_IN_DIR, &trusted);
        if !others.is_empty() {
            return Err(RemediationError::UnsafeTarget {
                path: target_dir,
                reason: format!("other users can create files there ({})", others.join(", ")),
            });
        }

        let key = unhex(&rec.key_hex)
            .filter(|k| k.len() == KEY_LEN)
            .ok_or_else(|| corrupt(id, "invalid key"))?;
        let tmp = target_dir.join(format!(".aw-restore-{id}"));
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&tmp)
            .map_err(|e| io_err("create", &tmp, e))?;
        let cleanup = |f: &File| {
            let _ = warden_winsec::delete_by_handle(f);
        };
        let (sha, _) = match self.decode_to(id, &key, Some(&mut out)) {
            Ok(v) => v,
            Err(e) => {
                cleanup(&out);
                return Err(e);
            }
        };
        if sha != rec.original.sha256 {
            cleanup(&out);
            return Err(corrupt(
                id,
                "decoded content does not match the recorded SHA-256",
            ));
        }
        if let Err(e) = out.sync_all() {
            cleanup(&out);
            return Err(io_err("sync", &tmp, e));
        }
        // Give the content its real name without replacing anything.
        match std::fs::hard_link(&tmp, &target) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                cleanup(&out);
                return Err(RemediationError::TargetExists(target));
            }
            Err(e) => {
                cleanup(&out);
                return Err(io_err("restore", &target, e));
            }
        }
        cleanup(&out);
        drop(out);

        let data = self.items.join(format!("{id}.data"));
        std::fs::remove_file(&data).map_err(|e| io_err("remove", &data, e))?;
        rec.state = ItemState::Restored;
        rec.updated_at = OffsetDateTime::now_utc();
        rec.restored_to = Some(ObservedPath::from_path(&target));
        rec.notes
            .push("file owner and attributes were not restored".into());
        self.save(&rec)?;
        Ok(target)
    }

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
        let data = self.items.join(format!("{id}.data"));
        match std::fs::remove_file(&data) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                rec.notes.push("content was already missing".into())
            }
            Err(e) => return Err(io_err("remove", &data, e)),
        }
        rec.state = ItemState::Deleted;
        rec.updated_at = OffsetDateTime::now_utc();
        self.save(&rec)
    }

    pub fn allowlist(&self) -> Result<Vec<AllowEntry>> {
        Ok(self.read_allowlist_file()?.entries)
    }

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

    fn read_bounded(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
        let f = match OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut data = Vec::new();
        f.take(max + 1).read_to_end(&mut data)?;
        Ok(Some(data))
    }

    fn read_allowlist_file(&self) -> Result<AllowlistFile> {
        let path = self.root.join(ALLOWLIST_FILE);
        match Self::read_bounded(&path, MAX_ALLOWLIST_BYTES)
            .map_err(|e| io_err("read", &path, e))?
        {
            None => Ok(AllowlistFile {
                format_version: 1,
                entries: Vec::new(),
            }),
            Some(d) if d.len() as u64 > MAX_ALLOWLIST_BYTES => {
                Err(RemediationError::StoreInsecure {
                    path,
                    reason: "the allow-list is too large".into(),
                })
            }
            Some(d) => crate::allowlist::parse(&d, &path),
        }
    }

    fn write_allowlist_file(&self, list: &AllowlistFile) -> Result<()> {
        let path = self.root.join(ALLOWLIST_FILE);
        let data = serde_json::to_vec_pretty(list)
            .map_err(|e| io_err("encode", &path, io::Error::other(e)))?;
        write_atomic(&path, &data)
    }

    pub fn get(&self, id: &QuarantineId) -> Result<QuarantineRecord> {
        let path = self.items.join(format!("{id}.json"));
        let data = Self::read_bounded(&path, MAX_RECORD_BYTES)
            .map_err(|e| io_err("read", &path, e))?
            .ok_or_else(|| RemediationError::UnknownItem(id.clone()))?;
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

    /// Records the client (a SID) later actions are performed for.
    pub fn on_behalf_of(&mut self, principal: Option<String>) {
        self.on_behalf_of = principal;
    }

    pub fn audit_head(&self) -> (u64, &str) {
        (self.head.seq, &self.head.hash)
    }

    pub fn anchor_failed(&self) -> bool {
        self.anchor_failed
    }

    pub fn audit_chain(&mut self) -> Result<Vec<(u64, String)>> {
        self.audit
            .rewind()
            .map_err(|e| io_err("read", &self.root.join("audit.log"), e))?;
        Ok(crate::audit::audit_chain(&mut self.audit)?)
    }

    pub fn chain_id(&self) -> Option<String> {
        self.head.chain_id()
    }

    pub fn verify_audit_log(&mut self) -> Result<u64> {
        self.audit
            .rewind()
            .map_err(|e| io_err("read", &self.root.join("audit.log"), e))?;
        Ok(verify_chain(&mut self.audit)?.seq)
    }

    fn recover(&mut self) -> Result<()> {
        let mut pending = Vec::new();
        for name in self.item_names()? {
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
            let (outcome, detail) = self.resolve_pending(&rec);
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
        for name in self.item_names()? {
            let stray_record_tmp = name.starts_with('.') && name.ends_with(".json.tmp");
            let stray_data_tmp = name
                .strip_suffix(".data.tmp")
                .and_then(|s| s.parse::<QuarantineId>().ok())
                .is_some_and(|id| self.get(&id).is_err());
            if stray_record_tmp || stray_data_tmp {
                let _ = std::fs::remove_file(self.items.join(&name));
            }
        }
        Ok(())
    }

    fn resolve_pending(&self, rec: &QuarantineRecord) -> (ItemState, String) {
        let id = rec.id.clone();
        let original_present = native_path(&rec.original.path)
            .and_then(|p| {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(p)
                    .ok()
            })
            .and_then(|f| winapi_util::file::information(&f).ok())
            .is_some_and(|i| {
                i.volume_serial_number() == rec.original.dev && i.file_index() == rec.original.ino
            });
        let data = self.items.join(format!("{id}.data"));
        let tmp = self.items.join(format!("{id}.data.tmp"));
        if original_present {
            let _ = std::fs::remove_file(&data);
            let _ = std::fs::remove_file(&tmp);
            return (
                ItemState::RolledBack,
                "interrupted before the original was removed; the copy was discarded".into(),
            );
        }
        let verified = unhex(&rec.key_hex)
            .filter(|k| k.len() == KEY_LEN)
            .and_then(|k| self.decode_to(&id, &k, None).ok())
            .is_some_and(|(sha, _)| sha == rec.original.sha256);
        if verified {
            let _ = std::fs::remove_file(&tmp);
            (
                ItemState::Quarantined,
                "interrupted after the original was removed; the verified copy was kept".into(),
            )
        } else {
            (
                ItemState::Failed,
                "original is gone and no verified copy exists; the file was removed by something other than the quarantine operation".into(),
            )
        }
    }

    fn roll_back(&mut self, rec: &mut QuarantineRecord, why: &str) -> Result<()> {
        let _ = std::fs::remove_file(self.items.join(format!("{}.data", rec.id)));
        rec.state = ItemState::RolledBack;
        rec.updated_at = OffsetDateTime::now_utc();
        rec.notes.push(format!("rolled back: {why}"));
        self.save(rec)
    }

    fn write_encoded(
        &self,
        src: &mut File,
        tmp: &Path,
        id: &QuarantineId,
        key: &[u8; KEY_LEN],
        max: u64,
        path: &Path,
    ) -> Result<(Sha256Digest, u64)> {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(tmp)
            .map_err(|e| io_err("create", tmp, e))?;
        out.write_all(DATA_MAGIC)
            .map_err(|e| io_err("write", tmp, e))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut total: u64 = 0;
        loop {
            let n = match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if is_in_use(&e) => return Err(RemediationError::InUse(path.to_owned())),
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
                .map_err(|e| io_err("write", tmp, e))?;
        }
        out.sync_all().map_err(|e| io_err("sync", tmp, e))?;
        drop(out);
        let sha = Sha256Digest::from_bytes(hasher.finalize().into());
        let (check, len) = self.decode_path(id, tmp, key, None)?;
        if check != sha || len != total {
            return Err(corrupt(id, "verification of the written copy failed"));
        }
        Ok((sha, total))
    }

    fn decode_to(
        &self,
        id: &QuarantineId,
        key: &[u8],
        out: Option<&mut File>,
    ) -> Result<(Sha256Digest, u64)> {
        self.decode_path(id, &self.items.join(format!("{id}.data")), key, out)
    }

    fn decode_path(
        &self,
        id: &QuarantineId,
        path: &Path,
        key: &[u8],
        mut out: Option<&mut File>,
    ) -> Result<(Sha256Digest, u64)> {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|e| io_err("open", path, e))?;
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
                Err(e) => return Err(io_err("read", path, e)),
            };
            xor_in_place(&mut buf[..n], key, total);
            total += n as u64;
            hasher.update(&buf[..n]);
            if let Some(o) = out.as_deref_mut() {
                o.write_all(&buf[..n])
                    .map_err(|e| io_err("write", path, e))?;
            }
        }
        Ok((Sha256Digest::from_bytes(hasher.finalize().into()), total))
    }

    fn save(&self, rec: &QuarantineRecord) -> Result<()> {
        let path = self.items.join(format!("{}.json", rec.id));
        let data = serde_json::to_vec_pretty(rec)
            .map_err(|e| io_err("encode", &path, io::Error::other(e)))?;
        write_atomic(&path, &data)
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
            actor_uid: 0,
            actor_sid: Some(self.user_sid.clone()),
            on_behalf_of: self.on_behalf_of.clone(),
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
        if self.anchor {
            let text = anchor_text(
                head.seq,
                &head.hash,
                &head.chain_id().unwrap_or_default(),
                action,
                outcome,
            );
            if warden_winsec::report_event(EVENT_SOURCE, &text, outcome != "ok").is_err() {
                self.anchor_failed = true;
            }
        }
        self.head = head;
        Ok(())
    }

    fn item_names(&self) -> Result<Vec<String>> {
        let entries = std::fs::read_dir(&self.items).map_err(|e| io_err("list", &self.items, e))?;
        let mut names = Vec::new();
        for e in entries {
            let e = e.map_err(|e| io_err("list", &self.items, e))?;
            if let Some(n) = e.file_name().to_str() {
                names.push(n.to_owned());
            }
        }
        Ok(names)
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

/// Atomically replace `path` (a file in a store directory) with `data`.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&tmp)
        .map_err(|e| io_err("create", &tmp, e))?;
    f.write_all(data).map_err(|e| io_err("write", &tmp, e))?;
    f.sync_all().map_err(|e| io_err("sync", &tmp, e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| io_err("rename", path, e))
}

#[cfg(test)]
mod tests;
