use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::{FileMetadata, Finding, FindingTarget, ObservedPath, Sha256Digest};

/// Identity and version of a detector, recorded in every scan report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorInfo {
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseInfo>,
}

/// Identity of the rule/signature database a detector evaluates.
///
/// `signer` is the key ID (hex) of the trusted key that verified the
/// database's signature, or `None` if it was loaded unsigned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub name: String,
    pub version: String,
    pub entries: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// What a detector needs from the scanner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DetectorRequirements {
    /// The detector inspects file bytes and must be given
    /// [`FileObservation::content`]. Files whose content is not available
    /// (larger than `max_content_size`) are not passed to it.
    pub content: bool,
}

/// What the scanner has established about a file before detectors run.
///
/// The scanner opens the file (without following links unless configured),
/// verifies from the open handle that it is a regular file within the size
/// limit, and reads it **exactly once**, computing its SHA-256. If any
/// detector requires content and the file is within `max_content_size`, the
/// bytes read are kept in a per-worker buffer and shared, read-only, with
/// every detector.
#[derive(Debug)]
pub struct FileObservation<'a> {
    pub path: &'a Path,
    pub sha256: &'a Sha256Digest,
    pub metadata: &'a FileMetadata,
    /// The exact bytes that were hashed, when content was requested and the
    /// file is within the content limit. Untrusted input.
    pub content: Option<&'a [u8]>,
    /// When the per-file time budget runs out. Long-running detectors must
    /// stop and return an error once it has passed.
    pub deadline: Instant,
    /// Set when this observation is a member of an archive at `path`: the
    /// member names from the outermost archive inward.
    pub member: Option<&'a [ObservedPath]>,
}

impl FileObservation<'_> {
    /// Time left in the per-file budget (zero once it has passed).
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// The [`FindingTarget`] describing this file, or this archive member.
    pub fn target(&self) -> FindingTarget {
        match self.member {
            None => FindingTarget::File {
                path: ObservedPath::from_path(self.path),
                sha256: Some(*self.sha256),
                metadata: Some(self.metadata.clone()),
            },
            Some(chain) => FindingTarget::ArchiveMember {
                archive: ObservedPath::from_path(self.path),
                member: chain.to_vec(),
                sha256: Some(*self.sha256),
                size: self.metadata.size,
            },
        }
    }
}

/// A detection provider.
///
/// Implementations must be:
/// * **Pure with respect to the host**: never execute, modify, move or delete
///   the file under inspection. Remediation is a separate subsystem.
/// * **Bounded**: finish in time proportional to the input, and honour any
///   limits they are configured with. Content is untrusted input.
/// * **Thread-safe**: one instance is shared by all scan workers.
///
/// A detector that panics does not abort the scan: the scanner isolates the
/// panic and reports it as an issue for that file.
pub trait Detector: Send + Sync {
    fn info(&self) -> DetectorInfo;

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements::default()
    }

    /// Evaluate one file. Returning an error records an issue for the file;
    /// it does not stop the scan.
    fn inspect_file(&self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError>;

    /// Create per-worker state. The scanner calls this once per worker
    /// thread per scan, and again if the worker panics, then routes every
    /// file that thread handles through the returned worker.
    ///
    /// Override it when evaluation needs expensive, non-shareable state (a
    /// YARA-X scanner, parser caches). The worker may borrow `self`. The
    /// default forwards to [`Detector::inspect_file`].
    fn worker(&self) -> Box<dyn DetectorWorker + '_> {
        Box::new(StatelessWorker(self))
    }
}

/// Per-worker evaluation state; see [`Detector::worker`]. Used from a single
/// thread, so it need not be `Send` or `Sync`.
pub trait DetectorWorker {
    fn inspect_file(&mut self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError>;
}

struct StatelessWorker<'a, D: ?Sized>(&'a D);

impl<D: Detector + ?Sized> DetectorWorker for StatelessWorker<'_, D> {
    fn inspect_file(&mut self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        self.0.inspect_file(file)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DetectorError {
    pub message: String,
}

impl DetectorError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
