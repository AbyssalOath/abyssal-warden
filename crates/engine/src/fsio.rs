//! Hardened file opening and hashing.
//!
//! Every scanned path is attacker-influenced: between directory enumeration
//! and `open`, a regular file can be replaced by a symlink, a FIFO or a
//! device. The routines here therefore:
//!
//! 1. open without following a final-component link when the policy is
//!    [`SymlinkPolicy::Skip`] (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`),
//! 2. open non-blocking on Unix so a FIFO swapped in cannot hang a worker,
//! 3. re-check the type and size from the *opened handle* (`fstat`), and
//! 4. read at most `max_size + 1` bytes, so a file growing during the read
//!    cannot exceed the limit.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
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
    };
    read_file(path, &opts, &mut Vec::new()).map(|(h, _)| h)
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
) -> Result<(HashedFile, bool), HashFileError> {
    content.clear();
    let file = open_for_scan(path, opts.policy).map_err(|e| {
        if is_symlink_refusal(&e) {
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
    let content_limit = opts.content_limit.filter(|&limit| meta.len() <= limit);
    let mut keep = content_limit.is_some();
    if keep {
        content.reserve(usize::try_from(meta.len()).unwrap_or(0));
    }

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
    Ok((hashed, keep))
}

#[cfg(unix)]
fn open_for_scan(path: &Path, policy: SymlinkPolicy) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    // O_NONBLOCK: opening a FIFO for reading otherwise blocks until a writer
    // appears. It has no effect on reads from regular files.
    // O_NOCTTY: never acquire a controlling terminal from a tty device.
    let mut flags = libc::O_NONBLOCK | libc::O_NOCTTY;
    if policy == SymlinkPolicy::Skip {
        flags |= libc::O_NOFOLLOW;
    }
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

#[cfg(windows)]
fn open_for_scan(path: &Path, policy: SymlinkPolicy) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    // winbase.h; defined here to avoid a windows-sys dependency for one flag.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let mut opts = OpenOptions::new();
    opts.read(true);
    if policy == SymlinkPolicy::Skip {
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_for_scan(path: &Path, _policy: SymlinkPolicy) -> io::Result<File> {
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

        let (h, kept) =
            read_file(&p, &opts(Some(data.len() as u64), None, &token), &mut buf).unwrap();
        assert!(kept);
        assert_eq!(buf, data);
        let expected: [u8; 32] = Sha256::digest(&data).into();
        assert_eq!(h.sha256.as_bytes(), &expected);

        let (h2, kept) = read_file(
            &p,
            &opts(Some(data.len() as u64 - 1), None, &token),
            &mut buf,
        )
        .unwrap();
        assert!(!kept);
        assert!(buf.is_empty());
        assert_eq!(
            h2.sha256, h.sha256,
            "hash is unaffected by content retention"
        );

        let (_, kept) = read_file(&p, &opts(None, None, &token), &mut buf).unwrap();
        assert!(!kept);
        assert!(buf.is_empty());
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
