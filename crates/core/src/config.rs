use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How the scanner treats symbolic links (and, on Windows, reparse points)
/// found *below* a scan root. Scan roots themselves are always resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymlinkPolicy {
    /// Do not follow links. Links are reported as skipped, and files are
    /// opened without following a link that was swapped in after
    /// enumeration (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`).
    #[default]
    Skip,
    /// Follow links, with loop detection. Followed links may lead outside the
    /// scan roots; the same file may then be scanned more than once.
    Follow,
}

/// Limits for expanding archives (ZIP, and ZIP-based formats such as JAR,
/// APK and Office documents). Members are decompressed in memory only.
///
/// Worst-case buffer memory per worker is roughly
/// `max_content_size + max_depth * max_member_content`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArchiveLimits {
    /// Expand archives and scan their members.
    pub enabled: bool,
    /// Maximum nesting: 1 expands members of a top-level archive only; 3
    /// reaches an archive inside an archive inside an archive.
    pub max_depth: u32,
    /// Members inspected per archive; the rest are reported as not inspected.
    pub max_entries: u32,
    /// Total bytes decompressed for one file on disk, across all members and
    /// nesting levels (decompression-bomb budget).
    pub max_total_bytes: u64,
    /// Largest member kept in memory for content detectors and nested
    /// expansion. Larger members are still hashed.
    pub max_member_content: u64,
}

impl ArchiveLimits {
    pub const DEFAULT_MAX_DEPTH: u32 = 3;
    pub const DEFAULT_MAX_ENTRIES: u32 = 10_000;
    pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
    pub const DEFAULT_MAX_MEMBER_CONTENT: u64 = 8 * 1024 * 1024;
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: Self::DEFAULT_MAX_DEPTH,
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            max_total_bytes: Self::DEFAULT_MAX_TOTAL_BYTES,
            max_member_content: Self::DEFAULT_MAX_MEMBER_CONTENT,
        }
    }
}

/// Resource limits applied to a scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanLimits {
    /// Files larger than this many bytes are skipped (and reported as such).
    pub max_file_size: u64,
    /// Maximum directory depth below each root. The root itself is depth 0.
    pub max_depth: usize,
    /// Maximum number of skipped entries and issues retained individually in
    /// the report. Beyond this they are only counted.
    pub max_recorded_entries: usize,
    /// Maximum number of findings retained individually in the report.
    pub max_recorded_findings: usize,
    /// Largest file whose content is buffered in memory for content-based
    /// detectors (YARA). Larger files are still hashed and hash-matched, but
    /// content detectors do not run on them; each such file is reported as
    /// skipped with [`SkipReason::ContentNotInspected`].
    ///
    /// Worst-case buffer memory is roughly `workers * max_content_size`.
    ///
    /// [`SkipReason::ContentNotInspected`]: crate::SkipReason::ContentNotInspected
    pub max_content_size: u64,
    /// Time budget for reading and evaluating one file, in milliseconds.
    ///
    /// Enforced cooperatively: between read chunks, between detectors, and
    /// by detectors that honour [`FileObservation::deadline`]. A single
    /// blocking read (e.g. a hung network filesystem) cannot be interrupted
    /// and can exceed it.
    ///
    /// [`FileObservation::deadline`]: crate::FileObservation::deadline
    pub file_timeout_ms: u64,
    /// Time budget for the whole scan, in milliseconds. `None` means no
    /// limit. When reached, the scan stops and reports
    /// [`ScanStatus::TimeLimitReached`] with partial results.
    ///
    /// [`ScanStatus::TimeLimitReached`]: crate::ScanStatus::TimeLimitReached
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_timeout_ms: Option<u64>,
    pub archives: ArchiveLimits,
}

impl ScanLimits {
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
    pub const DEFAULT_MAX_DEPTH: usize = 256;
    pub const DEFAULT_MAX_RECORDED_ENTRIES: usize = 10_000;
    pub const DEFAULT_MAX_RECORDED_FINDINGS: usize = 100_000;
    pub const DEFAULT_MAX_CONTENT_SIZE: u64 = 64 * 1024 * 1024;
    pub const DEFAULT_FILE_TIMEOUT_MS: u64 = 60_000;

    pub fn file_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.file_timeout_ms)
    }
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_size: Self::DEFAULT_MAX_FILE_SIZE,
            max_depth: Self::DEFAULT_MAX_DEPTH,
            max_recorded_entries: Self::DEFAULT_MAX_RECORDED_ENTRIES,
            max_recorded_findings: Self::DEFAULT_MAX_RECORDED_FINDINGS,
            max_content_size: Self::DEFAULT_MAX_CONTENT_SIZE,
            file_timeout_ms: Self::DEFAULT_FILE_TIMEOUT_MS,
            scan_timeout_ms: None,
            archives: ArchiveLimits::default(),
        }
    }
}

/// What to scan and how.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Files or directories to scan.
    pub roots: Vec<PathBuf>,
    /// Paths to exclude. Matching is component-wise prefix matching after
    /// the path has been made absolute.
    #[serde(default)]
    pub excludes: Vec<PathBuf>,
    #[serde(default)]
    pub symlink_policy: SymlinkPolicy,
    /// Do not descend into directories on a different filesystem/volume from
    /// the root they were reached from.
    #[serde(default)]
    pub same_file_system: bool,
    #[serde(default)]
    pub limits: ScanLimits,
    /// Number of worker threads that open, hash and evaluate files.
    pub workers: usize,
}

impl ScanConfig {
    /// Upper bound on `workers`. Scanning is mostly I/O bound; more threads
    /// than this mainly increase contention and memory use.
    pub const MAX_WORKERS: usize = 64;

    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            excludes: Vec::new(),
            symlink_policy: SymlinkPolicy::default(),
            same_file_system: false,
            limits: ScanLimits::default(),
            workers: Self::default_workers(),
        }
    }

    /// Available parallelism, clamped to `1..=8`.
    pub fn default_workers() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 8)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.roots.is_empty() {
            return Err(ConfigError::NoRoots);
        }
        if self
            .roots
            .iter()
            .chain(&self.excludes)
            .any(|p| p.as_os_str().is_empty())
        {
            return Err(ConfigError::EmptyPath);
        }
        if self.limits.max_file_size == 0 {
            return Err(ConfigError::ZeroLimit("max_file_size"));
        }
        if self.limits.max_recorded_findings == 0 {
            return Err(ConfigError::ZeroLimit("max_recorded_findings"));
        }
        if self.limits.file_timeout_ms == 0 {
            return Err(ConfigError::ZeroLimit("file_timeout_ms"));
        }
        if self.limits.scan_timeout_ms == Some(0) {
            return Err(ConfigError::ZeroLimit("scan_timeout_ms"));
        }
        let a = &self.limits.archives;
        if a.enabled {
            if a.max_depth == 0 {
                return Err(ConfigError::ZeroLimit("archives.max_depth"));
            }
            if a.max_entries == 0 {
                return Err(ConfigError::ZeroLimit("archives.max_entries"));
            }
            if a.max_total_bytes == 0 {
                return Err(ConfigError::ZeroLimit("archives.max_total_bytes"));
            }
            if a.max_member_content == 0 {
                return Err(ConfigError::ZeroLimit("archives.max_member_content"));
            }
        }
        if self.workers == 0 || self.workers > Self::MAX_WORKERS {
            return Err(ConfigError::InvalidWorkers {
                requested: self.workers,
                max: Self::MAX_WORKERS,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("no scan paths were given")]
    NoRoots,
    #[error("an empty path was given")]
    EmptyPath,
    #[error("limit `{0}` must be greater than zero")]
    ZeroLimit(&'static str),
    #[error("worker count must be between 1 and {max}, got {requested}")]
    InvalidWorkers { requested: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> ScanConfig {
        ScanConfig::new(vec![PathBuf::from("/tmp")])
    }

    #[test]
    fn defaults_are_valid() {
        let c = valid();
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.symlink_policy, SymlinkPolicy::Skip);
        assert!((1..=8).contains(&c.workers));
    }

    #[test]
    fn rejects_invalid_configs() {
        assert_eq!(
            ScanConfig::new(vec![]).validate(),
            Err(ConfigError::NoRoots)
        );

        let mut c = valid();
        c.excludes.push(PathBuf::new());
        assert_eq!(c.validate(), Err(ConfigError::EmptyPath));

        let mut c = valid();
        c.limits.max_file_size = 0;
        assert_eq!(c.validate(), Err(ConfigError::ZeroLimit("max_file_size")));

        let mut c = valid();
        c.workers = 0;
        assert!(matches!(
            c.validate(),
            Err(ConfigError::InvalidWorkers { .. })
        ));
        c.workers = ScanConfig::MAX_WORKERS + 1;
        assert!(matches!(
            c.validate(),
            Err(ConfigError::InvalidWorkers { .. })
        ));
    }

    #[test]
    fn deserialisation_rejects_unknown_fields() {
        let json = r#"{"roots":["/tmp"],"workers":2,"follow_everything":true}"#;
        assert!(serde_json::from_str::<ScanConfig>(json).is_err());
        let json = r#"{"roots":["/tmp"],"workers":2}"#;
        let c: ScanConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.limits, ScanLimits::default());
    }
}
