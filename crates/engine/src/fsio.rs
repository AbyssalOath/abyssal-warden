//! Hardened file opening and hashing.
//!
//! Every scanned path is attacker-influenced: between directory enumeration
//! and `open`, a regular file can be replaced by a symlink, a FIFO or a
//! device. The routines here therefore:
//!
//! 1. open without following links when the policy is [`SymlinkPolicy::Skip`]:
//!    on Linux no link is followed in *any* path component
//!    (`openat2(RESOLVE_NO_SYMLINKS)`). On other platforms, and on Linux
//!    kernels without `openat2`, the file is opened relative to a handle on
//!    its scan root ([`ScanBase`], via `cap-std`), resolving one component at
//!    a time, so resolution can never leave the root; the final component is
//!    never followed,
//! 2. open non-blocking on Unix so a FIFO swapped in cannot hang a worker,
//! 3. re-check the type and size from the *opened handle* (`fstat`), and
//! 4. read at most `max_size + 1` bytes, so a file growing during the read
//!    cannot exceed the limit.
//!
//! On Linux, files are opened with `O_NOATIME` when the kernel permits it
//! (the caller owns the file or has `CAP_FOWNER`), so scanning does not
//! update access times.

use std::collections::HashSet;
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use warden_core::{CancellationToken, FileMetadata, Sha256Digest, SkipReason, SymlinkPolicy};

const READ_CHUNK: usize = 64 * 1024;

/// A file that was opened, verified and fully hashed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashedFile {
    pub sha256: Sha256Digest,
    pub metadata: FileMetadata,
}

#[derive(Debug, thiserror::Error)]
pub enum HashFileError {
    #[error("not scanned: {0:?}")]
    Skipped(SkipReason),
    #[error("cancelled")]
    Cancelled,
    #[error("time limit exceeded after reading {bytes_read} bytes")]
    TimedOut { bytes_read: u64 },
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Parameters for [`read_file`].
#[derive(Debug)]
pub(crate) struct ReadOptions<'a> {
    pub(crate) policy: SymlinkPolicy,
    pub(crate) max_size: u64,
    /// Keep the bytes in the caller's buffer if the file is at most this
    /// large. `None` means hash only.
    pub(crate) content_limit: Option<u64>,
    pub(crate) deadline: Option<Instant>,
    pub(crate) cancel: &'a CancellationToken,
    /// Files already scanned, by (device, inode) on Unix or (volume serial,
    /// file index) on Windows. When set, a file seen before is skipped as
    /// [`SkipReason::DuplicateFile`].
    pub(crate) seen: Option<&'a Mutex<HashSet<(u64, u64)>>>,
    /// The scan root the file lies under, for root-relative opens.
    pub(crate) base: Option<&'a ScanBase>,
    /// Keep content only for files whose first bytes may hold a ZIP archive
    /// (used when archives are expanded but no detector needs content).
    pub(crate) keep_only_archives: bool,
}

/// What [`read_file`] produced.
#[derive(Debug)]
pub(crate) struct ReadOutcome {
    pub(crate) hashed: HashedFile,
    /// The caller's buffer holds the complete file.
    pub(crate) has_content: bool,
    /// The file starts with a ZIP signature.
    pub(crate) zip_magic: bool,
}

/// A scan root held open as a capability. Files below it can be opened
/// relative to this handle; resolution can never leave the directory,
/// whatever links or directory swaps happen during the scan.
#[derive(Debug)]
pub(crate) struct ScanBase {
    path: PathBuf,
    dir: cap_std::fs::Dir,
}

impl ScanBase {
    /// Open `dir` (an absolute, canonical directory path) as a base.
    pub(crate) fn open(dir: &Path) -> io::Result<Self> {
        Ok(Self {
            path: dir.to_path_buf(),
            dir: cap_std::fs::Dir::open_ambient_dir(dir, cap_std::ambient_authority())?,
        })
    }
}

/// Open `path` relative to `base`, never leaving it and never following a
/// final-component link. `unix_flags` are extra `open(2)` flags (ignored on
/// other platforms).
fn open_beneath(base: &ScanBase, path: &Path, unix_flags: i32) -> io::Result<File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};

    let rel = path.strip_prefix(&base.path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not below its scan root",
        )
    })?;
    let mut opts = cap_std::fs::OpenOptions::new();
    opts.read(true);
    opts.follow(FollowSymlinks::No);
    #[cfg(unix)]
    cap_std::fs::OpenOptionsExt::custom_flags(&mut opts, unix_flags);
    #[cfg(not(unix))]
    let _ = unix_flags;
    base.dir
        .open_with(rel, &opts)
        .map(cap_std::fs::File::into_std)
}

/// True if `e` is cap-std's refusal to let resolution leave the base
/// directory (a link or `..` pointing outside the scan root). cap-std reports
/// this as `PermissionDenied` with a fixed message and no distinct error
/// type, so the message is the only way to tell it apart.
fn is_escape_refusal(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied
        && e.to_string() == "a path led outside of the filesystem"
}

/// Open `path` with the hardening described in the module docs and compute
/// its SHA-256.
pub fn hash_file(
    path: &Path,
    policy: SymlinkPolicy,
    max_size: u64,
    cancel: &CancellationToken,
) -> Result<HashedFile, HashFileError> {
    let opts = ReadOptions {
        policy,
        max_size,
        content_limit: None,
        deadline: None,
        cancel,
        seen: None,
        base: None,
        keep_only_archives: false,
    };
    read_file(path, &opts, &mut Vec::new()).map(|r| r.hashed)
}

/// Read a file once: hash it and, if requested and small enough, keep its
/// bytes in `content`. Returns whether `content` holds the complete file.
///
/// `content` is cleared first. When the content is not kept, it is left
/// empty.
pub(crate) fn read_file(
    path: &Path,
    opts: &ReadOptions<'_>,
    content: &mut Vec<u8>,
) -> Result<ReadOutcome, HashFileError> {
    content.clear();
    let file = open_for_scan(path, opts.policy, opts.base).map_err(|e| {
        if is_symlink_refusal(&e) || is_escape_refusal(&e) {
            HashFileError::Skipped(SkipReason::SymlinkNotFollowed)
        } else {
            HashFileError::Io(e)
        }
    })?;
    let meta = file.metadata()?;
    if meta.file_type().is_symlink() {
        // Windows: FILE_FLAG_OPEN_REPARSE_POINT opened the link itself.
        return Err(HashFileError::Skipped(SkipReason::SymlinkNotFollowed));
    }
    if !meta.is_file() {
        return Err(HashFileError::Skipped(SkipReason::NotRegularFile));
    }
    if meta.len() > opts.max_size {
        return Err(HashFileError::Skipped(SkipReason::ExceedsMaxFileSize));
    }
    if let (Some(seen), Some(id)) = (opts.seen, file_id(&file, &meta)) {
        // A poisoned lock only means another worker panicked; the set is
        // still valid.
        let mut set = seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !set.insert(id) {
            return Err(HashFileError::Skipped(SkipReason::DuplicateFile));
        }
    }
    let content_limit = opts.content_limit.filter(|&limit| meta.len() <= limit);
    let mut keep = content_limit.is_some();
    if keep && !opts.keep_only_archives {
        content.reserve(usize::try_from(meta.len()).unwrap_or(0));
    }
    let mut zip_magic = false;

    let mut hasher = Sha256::new();
    let mut reader = file.take(opts.max_size.saturating_add(1));
    let mut buf = vec![0u8; READ_CHUNK];
    let mut total: u64 = 0;
    loop {
        if opts.cancel.is_cancelled() {
            return Err(HashFileError::Cancelled);
        }
        if opts.deadline.is_some_and(|d| Instant::now() >= d) {
            content.clear();
            return Err(HashFileError::TimedOut { bytes_read: total });
        }
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if total == 0 {
            zip_magic = crate::archive::looks_like_zip(&buf[..n]);
            if opts.keep_only_archives && !crate::archive::may_contain_zip(&buf[..n]) {
                keep = false;
            }
        }
        total += n as u64;
        if total > opts.max_size {
            // The file grew after the size check.
            content.clear();
            return Err(HashFileError::Skipped(SkipReason::ExceedsMaxFileSize));
        }
        hasher.update(&buf[..n]);
        if keep {
            if content_limit.is_some_and(|limit| total > limit) {
                // Grew past the content limit mid-read: keep hashing only.
                keep = false;
                content.clear();
            } else {
                content.extend_from_slice(&buf[..n]);
            }
        }
    }

    let hashed = HashedFile {
        sha256: Sha256Digest::from_bytes(hasher.finalize().into()),
        metadata: FileMetadata {
            // Bytes actually hashed, which may differ from the stat size if
            // the file changed while it was being read.
            size: total,
            modified: meta.modified().ok().map(OffsetDateTime::from),
            unix_mode: unix_mode(&meta),
        },
    };
    Ok(ReadOutcome {
        hashed,
        has_content: keep,
        zip_magic,
    })
}

#[cfg(target_os = "linux")]
fn open_for_scan(path: &Path, policy: SymlinkPolicy, base: Option<&ScanBase>) -> io::Result<File> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags};
    use rustix::io::Errno;

    // O_NONBLOCK: a FIFO swapped in cannot block the open. O_NOCTTY: never
    // acquire a controlling terminal.
    let base_flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let open = |flags: OFlags| -> io::Result<File> {
        match policy {
            SymlinkPolicy::Skip => match rustix::fs::openat2(
                CWD,
                path,
                flags | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            ) {
                Ok(fd) => Ok(File::from(fd)),
                // openat2 needs Linux 5.6. Older kernels: resolve relative to
                // the scan root, one component at a time.
                Err(Errno::NOSYS) => match base {
                    Some(b) => {
                        let extra = flags & (OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOATIME);
                        #[allow(clippy::cast_possible_wrap)] // Open flags fit in i32.
                        open_beneath(b, path, extra.bits() as i32)
                    }
                    None => Ok(File::from(rustix::fs::openat(
                        CWD,
                        path,
                        flags | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )?)),
                },
                Err(e) => Err(e.into()),
            },
            SymlinkPolicy::Follow => Ok(File::from(rustix::fs::openat(
                CWD,
                path,
                flags,
                Mode::empty(),
            )?)),
        }
    };
    // O_NOATIME is only allowed for the file's owner (or CAP_FOWNER);
    // otherwise the kernel returns EPERM and we open normally.
    match open(base_flags | OFlags::NOATIME) {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => open(base_flags),
        other => other,
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_for_scan(path: &Path, policy: SymlinkPolicy, base: Option<&ScanBase>) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    // O_NONBLOCK: opening a FIFO for reading otherwise blocks until a writer
    // appears. It has no effect on reads from regular files.
    // O_NOCTTY: never acquire a controlling terminal from a tty device.
    let flags = libc::O_NONBLOCK | libc::O_NOCTTY;
    match (policy, base) {
        (SymlinkPolicy::Skip, Some(b)) => open_beneath(b, path, flags),
        (SymlinkPolicy::Skip, None) => OpenOptions::new()
            .read(true)
            .custom_flags(flags | libc::O_NOFOLLOW)
            .open(path),
        (SymlinkPolicy::Follow, _) => OpenOptions::new().read(true).custom_flags(flags).open(path),
    }
}

#[cfg(windows)]
fn open_for_scan(path: &Path, policy: SymlinkPolicy, base: Option<&ScanBase>) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    // winbase.h; defined here to avoid a windows-sys dependency for one flag.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    match (policy, base) {
        (SymlinkPolicy::Skip, Some(b)) => open_beneath(b, path, 0),
        (SymlinkPolicy::Skip, None) => OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path),
        (SymlinkPolicy::Follow, _) => OpenOptions::new().read(true).open(path),
    }
}

#[cfg(not(any(unix, windows)))]
fn open_for_scan(
    path: &Path,
    _policy: SymlinkPolicy,
    _base: Option<&ScanBase>,
) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn is_symlink_refusal(e: &io::Error) -> bool {
    // O_NOFOLLOW on a symlink fails with ELOOP (EMLINK on some BSDs).
    matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::EMLINK))
}

#[cfg(not(unix))]
fn is_symlink_refusal(_e: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn file_id(_file: &File, meta: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

/// Volume serial number and file index, from the open handle
/// (`GetFileInformationByHandle`, via winapi-util's safe wrapper).
#[cfg(windows)]
fn file_id(file: &File, _meta: &Metadata) -> Option<(u64, u64)> {
    let info = winapi_util::file::information(file).ok()?;
    Some((info.volume_serial_number(), info.file_index()))
}

#[cfg(not(any(unix, windows)))]
fn file_id(_file: &File, _meta: &Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn unix_mode(meta: &Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn unix_mode(_meta: &Metadata) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn hash(path: &Path, max: u64) -> Result<HashedFile, HashFileError> {
        hash_file(path, SymlinkPolicy::Skip, max, &CancellationToken::new())
    }

    #[test]
    fn hashes_known_vectors() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        File::create(&empty).unwrap();
        assert_eq!(
            hash(&empty, 10).unwrap().sha256.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc = dir.path().join("abc");
        std::fs::write(&abc, b"abc").unwrap();
        let h = hash(&abc, 10).unwrap();
        assert_eq!(
            h.sha256.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.metadata.size, 3);
        assert!(h.metadata.modified.is_some());
    }

    #[test]
    fn multi_chunk_file_matches_one_shot_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big");
        let data: Vec<u8> = (0..(READ_CHUNK * 3 + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        File::create(&p).unwrap().write_all(&data).unwrap();
        let expected: [u8; 32] = Sha256::digest(&data).into();
        let h = hash(&p, u64::MAX).unwrap();
        assert_eq!(h.sha256.as_bytes(), &expected);
        assert_eq!(h.metadata.size, data.len() as u64);
    }

    #[test]
    fn enforces_size_limit_at_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, [0u8; 100]).unwrap();
        assert!(hash(&p, 100).is_ok());
        assert!(matches!(
            hash(&p, 99),
            Err(HashFileError::Skipped(SkipReason::ExceedsMaxFileSize))
        ));
    }

    fn opts(
        content_limit: Option<u64>,
        deadline: Option<Instant>,
        cancel: &CancellationToken,
    ) -> ReadOptions<'_> {
        ReadOptions {
            policy: SymlinkPolicy::Skip,
            max_size: u64::MAX,
            content_limit,
            deadline,
            cancel,
            seen: None,
            base: None,
            keep_only_archives: false,
        }
    }

    #[test]
    fn keeps_content_within_limit_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        let data: Vec<u8> = (0..(READ_CHUNK * 2 + 5)).map(|i| (i % 7) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        let token = CancellationToken::new();
        let mut buf = vec![1, 2, 3];

        let r = read_file(&p, &opts(Some(data.len() as u64), None, &token), &mut buf).unwrap();
        let (h, kept) = (r.hashed, r.has_content);
        assert!(kept);
        assert_eq!(buf, data);
        let expected: [u8; 32] = Sha256::digest(&data).into();
        assert_eq!(h.sha256.as_bytes(), &expected);

        let r = read_file(
            &p,
            &opts(Some(data.len() as u64 - 1), None, &token),
            &mut buf,
        )
        .unwrap();
        let (h2, kept) = (r.hashed, r.has_content);
        assert!(!kept);
        assert!(buf.is_empty());
        assert_eq!(
            h2.sha256, h.sha256,
            "hash is unaffected by content retention"
        );

        let kept = read_file(&p, &opts(None, None, &token), &mut buf)
            .unwrap()
            .has_content;
        assert!(!kept);
        assert!(buf.is_empty());
    }

    #[test]
    fn archive_only_retention_keeps_zips_and_drops_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let token = CancellationToken::new();
        let zip = dir.path().join("a.zip");
        std::fs::write(&zip, crate::archive::tests::zip_of(&[("m", b"member")])).unwrap();
        let txt = dir.path().join("a.txt");
        std::fs::write(&txt, b"plain text").unwrap();
        let mut o = opts(Some(1024), None, &token);
        o.keep_only_archives = true;
        let mut buf = Vec::new();

        let r = read_file(&zip, &o, &mut buf).unwrap();
        assert!(r.has_content && r.zip_magic);
        let r = read_file(&txt, &o, &mut buf).unwrap();
        assert!(!r.has_content && !r.zip_magic);
        assert!(buf.is_empty());
        // Too large to keep: still identified as a ZIP.
        o.content_limit = Some(10);
        let r = read_file(&zip, &o, &mut buf).unwrap();
        assert!(!r.has_content && r.zip_magic);
    }

    #[test]
    fn enforces_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        let token = CancellationToken::new();
        let past = Instant::now();
        let mut buf = Vec::new();
        assert!(matches!(
            read_file(&p, &opts(Some(10), Some(past), &token), &mut buf),
            Err(HashFileError::TimedOut { bytes_read: 0 })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_files_are_skipped_once_seen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        let token = CancellationToken::new();
        let seen = Mutex::new(HashSet::new());
        let mut o = opts(None, None, &token);
        o.policy = SymlinkPolicy::Follow;
        o.seen = Some(&seen);
        let mut buf = Vec::new();
        assert!(read_file(&p, &o, &mut buf).is_ok());
        assert!(matches!(
            read_file(&link, &o, &mut buf),
            Err(HashFileError::Skipped(SkipReason::DuplicateFile))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlinked_directory_in_path_is_refused_under_skip() {
        // A directory component that is a link (e.g. swapped in mid-scan) is
        // refused, not just a link in the final component.
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("f"), b"abc").unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("linkdir")).unwrap();
        let through_link = dir.path().join("linkdir").join("f");
        assert!(matches!(
            hash(&through_link, 10),
            Err(HashFileError::Skipped(SkipReason::SymlinkNotFollowed))
        ));
        assert!(hash(&real.join("f"), 10).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scanning_does_not_update_atime_of_own_files() {
        use std::os::unix::fs::MetadataExt;
        use std::time::{Duration, SystemTime};

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        // atime == mtime in the past: under the default `relatime` mount
        // option a normal read would update atime.
        let past = SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800);
        let f = File::options().write(true).open(&p).unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(past)
                .set_modified(past),
        )
        .unwrap();
        drop(f);
        let before = std::fs::metadata(&p).unwrap().atime();
        hash(&p, 10).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().atime(), before);
    }

    /// The root-relative path used on Windows, other Unixes, and Linux
    /// kernels without openat2.
    #[cfg(unix)]
    #[test]
    fn root_relative_open_cannot_leave_the_root() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let top = std::fs::canonicalize(dir.path()).unwrap();
        let root = top.join("root");
        std::fs::create_dir_all(root.join("inner")).unwrap();
        std::fs::write(root.join("inner/f"), b"inside").unwrap();
        std::fs::create_dir(top.join("outside")).unwrap();
        std::fs::write(top.join("outside/secret"), b"outside").unwrap();
        // A directory swapped for a link to outside the root.
        symlink(top.join("outside"), root.join("swapped")).unwrap();
        symlink(root.join("inner/f"), root.join("final-link")).unwrap();
        let base = ScanBase::open(&root).unwrap();

        let mut s = String::new();
        open_beneath(&base, &root.join("inner/f"), 0)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "inside");

        let escape = open_beneath(&base, &root.join("swapped/secret"), 0).unwrap_err();
        assert!(is_escape_refusal(&escape), "{escape:?}");

        let final_link = open_beneath(&base, &root.join("final-link"), 0).unwrap_err();
        assert!(is_symlink_refusal(&final_link), "{final_link:?}");

        let elsewhere = open_beneath(&base, &top.join("outside/secret"), 0).unwrap_err();
        assert_eq!(elsewhere.kind(), io::ErrorKind::InvalidInput);

        // Through read_file, an escape is a policy skip, not an I/O issue. (On
        // Linux, openat2 refuses the same path first, with the same result.)
        let token = CancellationToken::new();
        let mut o = opts(None, None, &token);
        o.base = Some(&base);
        assert!(matches!(
            read_file(&root.join("swapped/secret"), &o, &mut Vec::new()),
            Err(HashFileError::Skipped(SkipReason::SymlinkNotFollowed))
        ));
    }

    #[test]
    fn honours_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let token = CancellationToken::new();
        token.cancel();
        assert!(matches!(
            hash_file(&p, SymlinkPolicy::Skip, 10, &token),
            Err(HashFileError::Cancelled)
        ));
    }

    #[test]
    fn directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let r = hash(dir.path(), 10);
        // Linux: open(dir, O_RDONLY) succeeds and fstat reports a directory.
        // Windows: opening a directory without backup semantics fails.
        assert!(matches!(
            r,
            Err(HashFileError::Skipped(SkipReason::NotRegularFile)) | Err(HashFileError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_under_skip_policy_and_follows_under_follow() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"abc").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(matches!(
            hash(&link, 10),
            Err(HashFileError::Skipped(SkipReason::SymlinkNotFollowed))
        ));
        let followed =
            hash_file(&link, SymlinkPolicy::Follow, 10, &CancellationToken::new()).unwrap();
        assert_eq!(followed.metadata.size, 3);
    }
}
