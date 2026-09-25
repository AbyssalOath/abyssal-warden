use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DetectorInfo, Finding, ObservedPath, SymlinkPolicy};

/// Version of the JSON report schema. Incremented on any change that could
/// break an existing consumer (removed/renamed fields, changed meaning).
/// Adding optional fields or enum variants does not increment it; consumers
/// should ignore unknown fields and tolerate unknown enum values.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ScanStatus {
    /// Every reachable entry was processed. Individual entries may still
    /// have been skipped or failed; see `skipped` and `issues`.
    Completed,
    /// The scan was cancelled; results are partial.
    Cancelled,
    /// The whole-scan time limit was reached, or too many files stalled
    /// past their per-file limit; results are partial.
    TimeLimitReached,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineInfo {
    pub name: String,
    pub version: String,
}

/// The effective settings a scan ran with, after path resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSettings {
    pub roots: Vec<ObservedPath>,
    pub excludes: Vec<ObservedPath>,
    pub symlink_policy: SymlinkPolicy,
    pub same_file_system: bool,
    pub max_file_size: u64,
    pub max_depth: usize,
    pub workers: usize,
    #[serde(default)]
    pub max_content_size: u64,
    #[serde(default)]
    pub file_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_timeout_ms: Option<u64>,
    #[serde(default)]
    pub archives: crate::ArchiveLimits,
}

/// Why an entry was not scanned. Skips are the result of policy, not errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SkipReason {
    SymlinkNotFollowed,
    /// FIFO, socket, device node, or other non-regular file.
    NotRegularFile,
    ExceedsMaxFileSize,
    Excluded,
    /// A directory at the maximum depth; its contents were not visited.
    DepthLimitReached,
    /// The same file (device and inode) was already scanned through another
    /// path, e.g. a followed symbolic link. Unix only.
    DuplicateFile,
    /// An archive larger than `max_content_size`; its members were not
    /// inspected (the archive itself was hashed).
    ArchiveTooLarge,
    /// An archive limit (nesting depth, entry count, total decompressed
    /// bytes) was reached; the listed member or the rest of the archive was
    /// not inspected.
    ArchiveLimitReached,
    /// An encrypted archive member; its content cannot be inspected.
    ArchiveMemberEncrypted,
    /// An archive member using an unsupported compression method, or a
    /// symbolic-link entry.
    ArchiveMemberUnsupported,
    /// The file was hashed and hash-matched, but it exceeds
    /// `max_content_size`, so content-based detectors (YARA) did not run on
    /// it. The file is also counted in `files_scanned`.
    ContentNotInspected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub path: ObservedPath,
    pub reason: SkipReason,
    /// For entries inside an archive: the member names from the outermost
    /// archive inward (`path` is the archive on disk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<Vec<ObservedPath>>,
}

/// Why an entry could not be fully processed. Issues mean coverage is
/// incomplete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IssueKind {
    PermissionDenied,
    NotFound,
    FilesystemLoop,
    Io,
    DetectorFailed,
    /// The per-file time budget ran out; some or all checks did not run.
    Timeout,
    /// An archive or archive member is malformed (bad structure, CRC
    /// mismatch) or its parser failed.
    ArchiveError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanIssue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<ObservedPath>,
    pub kind: IssueKind,
    /// Detector id, for `detector_failed` issues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<String>,
    pub message: String,
    /// For issues inside an archive: the member names from the outermost
    /// archive inward (`path` is the archive on disk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<Vec<ObservedPath>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub directories_visited: u64,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub entries_skipped: u64,
    pub skipped_by_reason: BTreeMap<SkipReason, u64>,
    pub issues: u64,
    pub findings: u64,
    /// Files inside archives that were decompressed and evaluated.
    #[serde(default)]
    pub archive_members_scanned: u64,
}

/// How many entries were counted but not individually recorded because a
/// recording limit was reached.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truncation {
    pub findings_omitted: u64,
    pub skipped_omitted: u64,
    pub issues_omitted: u64,
}

impl Truncation {
    pub fn any(&self) -> bool {
        self.findings_omitted + self.skipped_omitted + self.issues_omitted > 0
    }
}

/// A signed content bundle the scan's detectors were loaded from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentBundleInfo {
    pub name: String,
    pub sequence: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub issued: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires: OffsetDateTime,
    /// Key IDs whose signatures on the manifest were accepted.
    pub signers: Vec<String>,
    pub manifest_sha256: crate::Sha256Digest,
    pub files: u64,
    /// The bundle had expired and was used only because expired content was
    /// explicitly allowed.
    pub expired: bool,
}

/// The structured result of one scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub scan_id: Uuid,
    pub engine: EngineInfo,
    pub status: ScanStatus,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    pub settings: ScanSettings,
    pub detectors: Vec<DetectorInfo>,
    pub stats: ScanStats,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedEntry>,
    pub issues: Vec<ScanIssue>,
    pub truncated: Truncation,
    /// Signed content bundles in use (empty when content was loaded from
    /// individually signed files, or not at all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub content_bundles: Vec<ContentBundleInfo>,
    /// Statements about the coverage and meaning of this report that a
    /// reader must see, e.g. "no detectors were configured".
    pub warnings: Vec<String>,
}

impl ScanReport {
    /// True if the scan ran to completion and no entry failed. Policy skips
    /// (size limit, symlinks, exclusions) do not make a scan incomplete.
    pub fn is_complete(&self) -> bool {
        self.status == ScanStatus::Completed && self.stats.issues == 0
    }
}
