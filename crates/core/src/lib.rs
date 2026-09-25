//! Shared types for Abyssal Warden.
//!
//! This crate is deliberately free of I/O, platform code and heavy
//! dependencies. It defines the data model that every other component (scan
//! engine, CLI, and the future service and GUI) exchanges:
//!
//! * [`ScanConfig`] - what to scan and under which resource limits.
//! * [`Finding`] - a single, explainable detection result.
//! * [`ScanReport`] - the structured, serialisable outcome of a scan.
//! * [`Detector`] - the interface every detection provider implements.
//! * [`CancellationToken`] - cooperative cancellation shared across threads.
//!
//! The JSON form of [`ScanReport`] is a compatibility contract and is
//! versioned by [`REPORT_SCHEMA_VERSION`]. The Rust API is internal to the
//! workspace until the project reaches 1.0.

mod cancel;
mod config;
mod detector;
mod digest;
mod finding;
mod path;
mod report;
pub mod text;

pub use cancel::CancellationToken;
pub use config::{ConfigError, ScanConfig, ScanLimits, SymlinkPolicy};
pub use detector::{
    DatabaseInfo, Detector, DetectorError, DetectorInfo, DetectorRequirements, DetectorWorker,
    FileObservation,
};
pub use digest::{DigestParseError, Sha256Digest};
pub use finding::{
    Confidence, DetectionSource, Evidence, EvidenceKind, FileMetadata, Finding, FindingId,
    FindingKind, FindingTarget, RecommendedAction, RemediationStatus, Severity, ThreatCategory,
};
pub use path::ObservedPath;
pub use report::{
    EngineInfo, IssueKind, REPORT_SCHEMA_VERSION, ScanIssue, ScanReport, ScanSettings, ScanStats,
    ScanStatus, SkipReason, SkippedEntry, Truncation,
};
