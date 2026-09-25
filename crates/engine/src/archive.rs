//! ZIP archive expansion.
//!
//! Archives are untrusted input. Members are decompressed **in memory only**:
//! nothing is ever written to disk, so member names (which may contain `..`,
//! absolute paths, or control characters) are only ever data. The scanner
//! evaluates each member with every detector, as if it were a file.
//!
//! Resource controls (see [`ArchiveLimits`]): nesting depth, members per
//! archive, a total decompressed-bytes budget per file on disk (the
//! decompression-bomb defence), the per-file deadline and cancellation
//! (checked every 64 KiB of output), a per-member size limit, and a cap on
//! member bytes kept in memory. Whatever is not inspected is reported, never
//! silently dropped.
//!
//! Supported: stored, deflate and deflate64 entries, in pure-Rust
//! decompressors. Other methods, encrypted entries and symlink entries are
//! reported as not inspected.

use std::io::{Cursor, Read};
use std::time::Instant;

use sha2::{Digest, Sha256};
use warden_core::{ArchiveLimits, CancellationToken, ObservedPath, Sha256Digest, SkipReason};
use zip::ZipArchive;
use zip::result::ZipError;

const CHUNK: usize = 64 * 1024;

/// True if `prefix` starts with a ZIP signature (local file header, empty
/// archive, or spanned-archive marker).
pub(crate) fn looks_like_zip(prefix: &[u8]) -> bool {
    prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(b"PK\x05\x06")
        || prefix.starts_with(b"PK\x07\x08")
}

/// True if the data may hold a ZIP archive: a ZIP, or a Windows executable,
/// which may be a self-extracting archive with a ZIP appended.
pub(crate) fn may_contain_zip(prefix: &[u8]) -> bool {
    looks_like_zip(prefix) || prefix.starts_with(b"MZ")
}

/// Something the expander found, delivered to the scanner.
pub(crate) enum Event<'a> {
    /// A member was decompressed and hashed. `content` is set when it is
    /// within `max_member_content`.
    Member {
        chain: &'a [ObservedPath],
        sha256: Sha256Digest,
        size: u64,
        content: Option<&'a [u8]>,
    },
    /// A member (or, with an empty chain, the archive itself) was not fully
    /// inspected.
    Skipped {
        chain: Vec<ObservedPath>,
        reason: SkipReason,
    },
    /// A malformed archive or member.
    Error {
        chain: Vec<ObservedPath>,
        message: String,
    },
}

/// Why expansion stopped early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Cancelled,
    Deadline,
}

/// Expands one file on disk, including nested archives, within one budget.
pub(crate) struct Expander<'a> {
    limits: &'a ArchiveLimits,
    /// Largest member accepted (the scan's `max_file_size`).
    max_member_size: u64,
    deadline: Instant,
    cancel: &'a CancellationToken,
    budget_left: u64,
    budget_reported: bool,
}

impl<'a> Expander<'a> {
    pub(crate) fn new(
        limits: &'a ArchiveLimits,
        max_member_size: u64,
        deadline: Instant,
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            limits,
            max_member_size,
            deadline,
            cancel,
            budget_left: limits.max_total_bytes,
            budget_reported: false,
        }
    }

    /// Expand `data`, the content of a file on disk.
    ///
    /// Data that starts with a ZIP signature but cannot be parsed is reported
    /// as an error; other data (e.g. an executable that is not a
    /// self-extracting archive) is silently ignored.
    pub(crate) fn expand_file(
        &mut self,
        data: &[u8],
        visit: &mut dyn FnMut(Event<'_>),
    ) -> Result<(), Stop> {
        let strict = looks_like_zip(data);
        self.expand(data, &mut Vec::new(), 1, strict, visit)
    }

    fn check(&self) -> Result<(), Stop> {
        if self.cancel.is_cancelled() {
            return Err(Stop::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Stop::Deadline);
        }
        Ok(())
    }

    /// Expand the archive in `data`, whose members are at nesting `depth`
    /// (1 for members of a file on disk) and which was reached via `chain`.
    fn expand(
        &mut self,
        data: &[u8],
        chain: &mut Vec<ObservedPath>,
        depth: u32,
        strict: bool,
        visit: &mut dyn FnMut(Event<'_>),
    ) -> Result<(), Stop> {
        let mut zip = match ZipArchive::new(Cursor::new(data)) {
            Ok(z) => z,
            Err(e) => {
                if strict {
                    visit(Event::Error {
                        chain: chain.clone(),
                        message: format!("not a readable ZIP archive: {e}"),
                    });
                }
                return Ok(());
            }
        };

        let count = zip.len();
        let limit = usize::try_from(self.limits.max_entries).unwrap_or(usize::MAX);
        if count > limit {
            visit(Event::Skipped {
                chain: chain.clone(),
                reason: SkipReason::ArchiveLimitReached,
            });
        }

        for index in 0..count.min(limit) {
            self.check()?;
            if self.budget_left == 0 {
                if !self.budget_reported {
                    self.budget_reported = true;
                    visit(Event::Skipped {
                        chain: chain.clone(),
                        reason: SkipReason::ArchiveLimitReached,
                    });
                }
                return Ok(());
            }

            // Read the entry's metadata without decompressing it.
            let (name, encrypted, is_dir, is_symlink) = match zip.by_index_raw(index) {
                Ok(raw) => (
                    member_name(raw.name(), raw.name_raw()),
                    raw.encrypted(),
                    raw.is_dir(),
                    raw.is_symlink(),
                ),
                Err(e) => {
                    visit(Event::Error {
                        chain: chain.clone(),
                        message: format!("unreadable entry #{index}: {e}"),
                    });
                    continue;
                }
            };
            if is_dir {
                continue;
            }
            chain.push(name);
            let outcome = if encrypted {
                visit(Event::Skipped {
                    chain: chain.clone(),
                    reason: SkipReason::ArchiveMemberEncrypted,
                });
                Ok(())
            } else if is_symlink {
                visit(Event::Skipped {
                    chain: chain.clone(),
                    reason: SkipReason::ArchiveMemberUnsupported,
                });
                Ok(())
            } else {
                self.member(&mut zip, index, chain, depth, visit)
            };
            chain.pop();
            outcome?;
        }
        Ok(())
    }

    fn member(
        &mut self,
        zip: &mut ZipArchive<Cursor<&[u8]>>,
        index: usize,
        chain: &mut Vec<ObservedPath>,
        depth: u32,
        visit: &mut dyn FnMut(Event<'_>),
    ) -> Result<(), Stop> {
        let mut entry = match zip.by_index(index) {
            Ok(e) => e,
            Err(ZipError::UnsupportedArchive(_) | ZipError::CompressionMethodNotSupported(_)) => {
                visit(Event::Skipped {
                    chain: chain.clone(),
                    reason: SkipReason::ArchiveMemberUnsupported,
                });
                return Ok(());
            }
            Err(e) => {
                visit(Event::Error {
                    chain: chain.clone(),
                    message: format!("unreadable member: {e}"),
                });
                return Ok(());
            }
        };

        // The declared size is untrusted: it only bounds the initial
        // allocation, never the amount read.
        let keep_limit = self.limits.max_member_content;
        let mut content =
            Vec::with_capacity(usize::try_from(entry.size().min(keep_limit)).unwrap_or(0));
        let mut keep = true;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        let mut total: u64 = 0;
        loop {
            self.check()?;
            let n = match entry.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                // Includes CRC mismatches and malformed compressed data.
                Err(e) => {
                    visit(Event::Error {
                        chain: chain.clone(),
                        message: format!("corrupt member: {e}"),
                    });
                    self.budget_left = self.budget_left.saturating_sub(total);
                    return Ok(());
                }
            };
            total += n as u64;
            if total > self.budget_left {
                self.budget_left = 0;
                self.budget_reported = true;
                visit(Event::Skipped {
                    chain: chain.clone(),
                    reason: SkipReason::ArchiveLimitReached,
                });
                return Ok(());
            }
            if total > self.max_member_size {
                self.budget_left -= total;
                visit(Event::Skipped {
                    chain: chain.clone(),
                    reason: SkipReason::ExceedsMaxFileSize,
                });
                return Ok(());
            }
            hasher.update(&buf[..n]);
            if keep {
                if total > keep_limit {
                    keep = false;
                    content = Vec::new();
                } else {
                    content.extend_from_slice(&buf[..n]);
                }
            }
        }
        drop(entry);
        self.budget_left -= total;

        let kept = keep.then_some(content.as_slice());
        visit(Event::Member {
            chain,
            sha256: Sha256Digest::from_bytes(hasher.finalize().into()),
            size: total,
            content: kept,
        });

        if let Some(bytes) = kept
            && looks_like_zip(bytes)
        {
            if depth < self.limits.max_depth {
                self.expand(bytes, chain, depth + 1, true, visit)?;
            } else {
                visit(Event::Skipped {
                    chain: chain.clone(),
                    reason: SkipReason::ArchiveLimitReached,
                });
            }
        }
        Ok(())
    }
}

/// A member name as an [`ObservedPath`]: the decoded name (UTF-8, or CP437
/// when the entry is not flagged UTF-8), plus the raw bytes in hex when they
/// are not valid UTF-8.
fn member_name(decoded: &str, raw: &[u8]) -> ObservedPath {
    use std::fmt::Write as _;
    let raw_hex = std::str::from_utf8(raw).is_err().then(|| {
        raw.iter()
            .fold(String::with_capacity(raw.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    });
    ObservedPath {
        text: decoded.to_owned(),
        raw_hex,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;
    use zip::write::SimpleFileOptions;

    /// Build a ZIP in memory from (name, data, compressed) entries.
    pub(crate) fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(*name, SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    struct Collected {
        members: Vec<(Vec<String>, u64, bool)>,
        skipped: Vec<(Vec<String>, SkipReason)>,
        errors: Vec<(Vec<String>, String)>,
    }

    fn names(chain: &[ObservedPath]) -> Vec<String> {
        chain.iter().map(|p| p.text.clone()).collect()
    }

    fn run(data: &[u8], limits: ArchiveLimits) -> (Collected, Result<(), Stop>) {
        let token = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut exp = Expander::new(&limits, u64::MAX, deadline, &token);
        let mut c = Collected {
            members: vec![],
            skipped: vec![],
            errors: vec![],
        };
        let r = exp.expand_file(data, &mut |ev| match ev {
            Event::Member {
                chain,
                size,
                content,
                ..
            } => c.members.push((names(chain), size, content.is_some())),
            Event::Skipped { chain, reason } => c.skipped.push((names(&chain), reason)),
            Event::Error { chain, message } => c.errors.push((names(&chain), message)),
        });
        (c, r)
    }

    #[test]
    fn expands_members_and_nested_archives() {
        let inner = zip_of(&[("payload.bin", b"inner data")]);
        let outer = zip_of(&[("readme.txt", b"hello"), ("nested.zip", &inner)]);
        let (c, r) = run(&outer, ArchiveLimits::default());
        assert!(r.is_ok());
        assert!(c.errors.is_empty() && c.skipped.is_empty());
        let got: Vec<Vec<String>> = c.members.iter().map(|m| m.0.clone()).collect();
        assert_eq!(
            got,
            vec![
                vec!["readme.txt".to_string()],
                vec!["nested.zip".to_string()],
                vec!["nested.zip".to_string(), "payload.bin".to_string()],
            ]
        );
    }

    #[test]
    fn nesting_depth_is_limited() {
        let l3 = zip_of(&[("deep.txt", b"deep")]);
        let l2 = zip_of(&[("l3.zip", &l3)]);
        let l1 = zip_of(&[("l2.zip", &l2)]);
        let limits = ArchiveLimits {
            max_depth: 2,
            ..ArchiveLimits::default()
        };
        let (c, _) = run(&l1, limits);
        // l2.zip (depth 1) and l3.zip (depth 2) are scanned as members; l3's
        // contents would be depth 3, so l3.zip is reported, not expanded.
        assert_eq!(c.members.len(), 2);
        assert_eq!(
            c.skipped,
            vec![(
                vec!["l2.zip".to_string(), "l3.zip".to_string()],
                SkipReason::ArchiveLimitReached
            )]
        );
    }

    #[test]
    fn decompression_bomb_is_stopped_by_the_budget() {
        // 16 MiB of zeros compresses to about 16 KiB (1000:1).
        let zeros = vec![0u8; 16 * 1024 * 1024];
        let bomb = zip_of(&[("zeros.bin", &zeros), ("after.txt", b"x")]);
        assert!(bomb.len() < 64 * 1024, "{}", bomb.len());
        let limits = ArchiveLimits {
            max_total_bytes: 1024 * 1024,
            ..ArchiveLimits::default()
        };
        let (c, r) = run(&bomb, limits);
        assert!(r.is_ok());
        assert!(c.members.is_empty(), "no member should be fully expanded");
        assert_eq!(
            c.skipped,
            vec![(
                vec!["zeros.bin".to_string()],
                SkipReason::ArchiveLimitReached
            )]
        );
    }

    #[test]
    fn entry_count_is_limited() {
        let entries: Vec<(String, Vec<u8>)> =
            (0..5).map(|i| (format!("f{i}"), vec![i as u8])).collect();
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let limits = ArchiveLimits {
            max_entries: 3,
            ..ArchiveLimits::default()
        };
        let (c, _) = run(&zip_of(&refs), limits);
        assert_eq!(c.members.len(), 3);
        assert_eq!(c.skipped, vec![(vec![], SkipReason::ArchiveLimitReached)]);
    }

    #[test]
    fn large_members_are_hashed_but_not_kept() {
        let big = vec![7u8; 2000];
        let limits = ArchiveLimits {
            max_member_content: 1000,
            ..ArchiveLimits::default()
        };
        let (c, _) = run(&zip_of(&[("big", &big), ("small", b"s")]), limits);
        assert_eq!(c.members[0], (vec!["big".to_string()], 2000, false));
        assert_eq!(c.members[1], (vec!["small".to_string()], 1, true));
    }

    #[test]
    fn hostile_member_names_are_data_only() {
        let z = zip_of(&[("../../etc/evil", b"x"), ("/abs/path", b"y")]);
        let (c, _) = run(&z, ArchiveLimits::default());
        assert_eq!(c.members[0].0, vec!["../../etc/evil".to_string()]);
        assert_eq!(c.members[1].0, vec!["/abs/path".to_string()]);
    }

    #[test]
    fn corrupt_and_non_zip_input() {
        // Starts like a ZIP but is not one: reported.
        let (c, r) = run(b"PK\x03\x04garbage", ArchiveLimits::default());
        assert!(r.is_ok());
        assert_eq!(c.errors.len(), 1);
        // An executable that is not a self-extracting archive: ignored.
        let (c, _) = run(b"MZ\x90\x00 not an archive", ArchiveLimits::default());
        assert!(c.errors.is_empty() && c.members.is_empty());
        // Corrupted compressed data (the stream starts after the 30-byte
        // local header and the 5-byte name): a reported member error, no
        // member, no panic.
        let mut z = zip_of(&[("a.txt", &vec![b'a'; 10_000])]);
        z[36] ^= 0xff;
        z[37] ^= 0xff;
        let (c, r) = run(&z, ArchiveLimits::default());
        assert!(r.is_ok());
        assert!(c.members.is_empty(), "{:?}", c.members);
        assert_eq!(c.errors.len(), 1);
        assert_eq!(c.errors[0].0, vec!["a.txt".to_string()]);
    }

    #[test]
    fn cancellation_and_deadline_stop_expansion() {
        let z = zip_of(&[("a", b"a")]);
        let limits = ArchiveLimits::default();
        let token = CancellationToken::new();
        token.cancel();
        let mut exp = Expander::new(
            &limits,
            u64::MAX,
            Instant::now() + Duration::from_secs(9),
            &token,
        );
        assert_eq!(exp.expand_file(&z, &mut |_| {}), Err(Stop::Cancelled));
        let token = CancellationToken::new();
        let mut exp = Expander::new(&limits, u64::MAX, Instant::now(), &token);
        assert_eq!(exp.expand_file(&z, &mut |_| {}), Err(Stop::Deadline));
    }

    #[test]
    fn signatures() {
        assert!(looks_like_zip(b"PK\x03\x04rest"));
        assert!(!looks_like_zip(b"MZ"));
        assert!(may_contain_zip(b"MZ\x90"));
        assert!(!may_contain_zip(b"\x7fELF"));
    }
}
