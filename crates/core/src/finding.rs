use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ObservedPath, Sha256Digest};

/// Unique identifier of one finding occurrence (not of the rule that
/// produced it; see [`DetectionSource::rule_id`] for that).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FindingId(Uuid);

impl FindingId {
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for FindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What sort of conclusion a finding represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FindingKind {
    /// The target matches a curated indicator (e.g. an exact hash from a
    /// signature database).
    KnownIndicator,
    /// The target has characteristics commonly associated with malicious
    /// content, but no known indicator matched.
    Suspicious,
    /// Produced by a heuristic that may have a meaningful false-positive rate.
    Heuristic,
    /// Noteworthy but not, by itself, an indication of compromise.
    Informational,
}

/// Potential impact if the finding is a true positive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

/// How strongly the evidence supports the finding's conclusion about the
/// *target*. See `docs/architecture/detection-pipeline.md` for definitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    /// Deterministic match against a curated indicator, such as an exact
    /// cryptographic hash. Confirms the target *is* the indicator; the label
    /// is only as accurate as the indicator's source.
    Confirmed,
}

/// What the matched indicator or rule is believed to describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ThreatCategory {
    Malware,
    PotentiallyUnwanted,
    /// A synthetic or industry test indicator. Not a threat.
    TestIndicator,
    Unknown,
}

/// What the product recommends. A recommendation is never an action taken;
/// see [`RemediationStatus`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecommendedAction {
    None,
    Review,
    Quarantine,
}

/// State of remediation for a finding. Detectors always produce
/// `NotAttempted`; only the remediation subsystem changes it, and
/// [`Finding::remediation_detail`] then says what happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RemediationStatus {
    NotAttempted,
    /// Moved into quarantine; the detail holds the quarantine ID.
    Quarantined,
    /// Automatic remediation was requested but the finding did not meet the
    /// safety policy (e.g. not a confirmed malware match, or a protected
    /// path); the detail says why.
    NotEligible,
    /// Remediation was attempted and failed; the original file is left in
    /// place and the detail holds the error.
    Failed,
}

/// The detector, rule and database that produced a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionSource {
    pub detector: String,
    pub detector_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_version: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EvidenceKind {
    ExactSha256Match,
    YaraRuleMatch,
}

/// One piece of evidence supporting a finding, with a human-readable summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub summary: String,
}

/// File metadata captured from the opened file handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub modified: Option<OffsetDateTime>,
    /// Unix permission bits (`st_mode & 0o7777`); absent on other platforms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_mode: Option<u32>,
}

/// The object a finding is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FindingTarget {
    File {
        path: ObservedPath,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<Sha256Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<FileMetadata>,
    },
}

impl FindingTarget {
    pub fn path(&self) -> Option<&ObservedPath> {
        match self {
            Self::File { path, .. } => Some(path),
        }
    }
}

/// A single explainable detection result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub kind: FindingKind,
    /// Detection name, e.g. a malware family or rule name.
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: ThreatCategory,
    pub target: FindingTarget,
    pub source: DetectionSource,
    pub evidence: Vec<Evidence>,
    /// Why the detector reached this conclusion, in plain language.
    pub explanation: String,
    pub recommended_action: RecommendedAction,
    /// Rule-supplied remediation guidance, if any. Untrusted text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_guidance: Option<String>,
    pub remediation_status: RemediationStatus,
    /// Quarantine ID, or why remediation was not performed or failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_detail: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub detected_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample() -> Finding {
        Finding {
            id: FindingId::new_random(),
            kind: FindingKind::KnownIndicator,
            name: "Test.Sample".into(),
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            category: ThreatCategory::TestIndicator,
            target: FindingTarget::File {
                path: ObservedPath::from_path(Path::new("/tmp/x")),
                sha256: Some(Sha256Digest::from_bytes([7; 32])),
                metadata: Some(FileMetadata {
                    size: 3,
                    modified: None,
                    unix_mode: Some(0o644),
                }),
            },
            source: DetectionSource {
                detector: "test".into(),
                detector_version: "0".into(),
                rule_id: Some("R1".into()),
                rule_version: Some(1),
                database_name: None,
                database_version: None,
            },
            evidence: vec![Evidence {
                kind: EvidenceKind::ExactSha256Match,
                summary: "matched".into(),
            }],
            explanation: "because".into(),
            recommended_action: RecommendedAction::None,
            remediation_guidance: None,
            remediation_status: RemediationStatus::NotAttempted,
            remediation_detail: None,
            detected_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn json_round_trip_and_field_names() {
        let f = sample();
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["kind"], "known_indicator");
        assert_eq!(v["severity"], "high");
        assert_eq!(v["confidence"], "confirmed");
        assert_eq!(v["target"]["type"], "file");
        assert_eq!(v["target"]["path"]["text"], "/tmp/x");
        assert_eq!(v["remediation_status"], "not_attempted");
        assert_eq!(v["detected_at"], "1970-01-01T00:00:00Z");
        let back: Finding = serde_json::from_value(v).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn severity_and_confidence_order() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Info);
        assert!(Confidence::Confirmed > Confidence::High);
    }
}
