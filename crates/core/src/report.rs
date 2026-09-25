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
    /// The file was hashed and hash-matched, but it exceeds
    /// `max_content_size`, so content-based detectors (YARA) did not run on
    /// it. The file is also counted in `files_scanned`.
    ContentNotInspected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub path: ObservedPath,
    pub reason: SkipReason,
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
