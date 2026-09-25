//! YARA-X detection provider for Abyssal Warden.
//!
//! Compiles YARA rule sources with [YARA-X](https://virustotal.github.io/yara-x/)
//! and evaluates them against file content supplied by the scanner. See
//! `docs/detection/yara.md` for the supported feature set, the metadata
//! conventions and the limits.
//!
//! Hardening applied at compile time:
//! * `include` statements are **disabled**, so rules cannot make the
//!   compiler read other files.
//! * Patterns that YARA-X considers slow are **rejected**
//!   (`error_on_slow_pattern`), as are strict-syntax violations.
//! * Source size and rule count are capped.
//! * Only an explicit list of modules is compiled in (see `Cargo.toml`).
//!
//! At scan time: a per-file timeout (from the scanner's deadline, rounded up
//! to YARA-X's one-second granularity) and a cap on matches per pattern.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

use warden_core::text::has_unsafe_chars;
use warden_core::{
    Confidence, DatabaseInfo, DetectionSource, Detector, DetectorError, DetectorInfo,
    DetectorRequirements, DetectorWorker, Evidence, EvidenceKind, FileObservation, Finding,
    FindingId, FindingKind, RecommendedAction, RemediationStatus, Severity, Sha256Digest,
    ThreatCategory,
};

/// Detector id recorded in reports.
pub const DETECTOR_ID: &str = "yara-x";
/// Version of the YARA-X engine this crate is built against.
pub const YARA_X_VERSION: &str = "1.20";

/// Largest total rule source accepted, in bytes.
pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
/// Largest number of rules accepted.
pub const MAX_RULES: usize = 200_000;
/// Matches recorded per pattern. YARA-X's own default is much higher.
pub const MAX_MATCHES_PER_PATTERN: usize = 1_000;
/// Pattern matches listed as evidence per rule.
const EVIDENCE_MATCHES: usize = 8;
const MAX_META_TEXT: usize = 4096;
const MAX_NAME_LEN: usize = 256;

/// One rule source file.
#[derive(Clone, Debug)]
pub struct RuleSource {
    /// YARA namespace for the file's rules (usually the file stem). Must be
    /// 1-64 characters of `[A-Za-z0-9_]`.
    pub namespace: String,
    /// Name shown in errors (usually the path).
    pub origin: String,
    pub text: String,
}

#[derive(Debug, thiserror::Error)]
pub enum YaraLoadError {
    #[error("no rule sources given")]
    Empty,
    #[error("rule sources exceed the {MAX_SOURCE_BYTES}-byte limit")]
    TooLarge,
    #[error("more than {MAX_RULES} rules")]
    TooManyRules,
    #[error("invalid namespace {0:?}: use 1-64 characters of [A-Za-z0-9_]")]
    InvalidNamespace(String),
    #[error("{origin}: {message}")]
    Compile { origin: String, message: String },
    #[error("rule {rule}: metadata `{key}` {reason}")]
    InvalidMetadata {
        rule: String,
        key: String,
        reason: String,
    },
}

/// How a rule's match is to be interpreted, from its `aw_*` metadata.
#[derive(Clone, Debug)]
struct RuleMeta {
    kind: FindingKind,
    confidence: Confidence,
    severity: Severity,
    category: ThreatCategory,
    name: String,
    rule_version: Option<u32>,
    description: Option<String>,
}

/// Compiled, validated YARA rules.
pub struct YaraDetector {
    rules: yara_x::Rules,
    meta: HashMap<(String, String), RuleMeta>,
    info: DetectorInfo,
}

impl std::fmt::Debug for YaraDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraDetector")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl YaraDetector {
    /// Compile and validate `sources`. `signer` is the key ID that verified
    /// them, or `None` if they were loaded unsigned.
    pub fn compile(sources: &[RuleSource], signer: Option<String>) -> Result<Self, YaraLoadError> {
        if sources.is_empty() {
            return Err(YaraLoadError::Empty);
        }
        if sources.iter().map(|s| s.text.len()).sum::<usize>() > MAX_SOURCE_BYTES {
            return Err(YaraLoadError::TooLarge);
        }

        let mut compiler = yara_x::Compiler::new();
        compiler
            .enable_includes(false)
            .error_on_slow_pattern(true)
            .relaxed_re_syntax(false);
        let mut digest_input = Vec::new();
        for src in sources {
            validate_namespace(&src.namespace)?;
            compiler.new_namespace(&src.namespace);
            compiler
                .add_source(src.text.as_str())
                .map_err(|e| YaraLoadError::Compile {
                    origin: src.origin.clone(),
                    message: e.to_string(),
                })?;
            digest_input.extend_from_slice(src.namespace.as_bytes());
            digest_input.push(0);
            digest_input.extend_from_slice(src.text.as_bytes());
            digest_input.push(0);
        }
        let rules = compiler.build();
        if rules.iter().len() > MAX_RULES {
            return Err(YaraLoadError::TooManyRules);
        }

        let mut meta = HashMap::new();
        for rule in rules.iter() {
            let key = (rule.namespace().to_owned(), rule.identifier().to_owned());
            let m = parse_meta(&rule)?;
            meta.insert(key, m);
        }

        let info = DetectorInfo {
            id: DETECTOR_ID.to_owned(),
            version: YARA_X_VERSION.to_owned(),
            database: Some(DatabaseInfo {
                name: "yara-rules".to_owned(),
                // Content-addressed: identical sources give the same version.
                version: format!("sha256:{}", &sha256_hex(&digest_input)[..16]),
                entries: meta.len() as u64,
                signer,
            }),
        };
        Ok(Self { rules, meta, info })
    }

    pub fn rule_count(&self) -> usize {
        self.meta.len()
    }
}

impl Detector for YaraDetector {
    fn info(&self) -> DetectorInfo {
        self.info.clone()
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements { content: true }
    }

    /// Stand-alone evaluation with a fresh YARA-X scanner. The scan engine
    /// uses [`Detector::worker`] instead, which reuses one scanner per
    /// worker thread.
    fn inspect_file(&self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        YaraWorker::new(self).inspect_file(file)
    }

    fn worker(&self) -> Box<dyn DetectorWorker + '_> {
        Box::new(YaraWorker::new(self))
    }
}

/// One YARA-X scanner, reused for every file a scan worker handles.
/// Creating a scanner costs far more than scanning a small file
/// (docs/detection/yara.md#performance), so it is created once per worker.
struct YaraWorker<'r> {
    detector: &'r YaraDetector,
    scanner: yara_x::Scanner<'r>,
}

impl<'r> YaraWorker<'r> {
    fn new(detector: &'r YaraDetector) -> Self {
        let mut scanner = yara_x::Scanner::new(&detector.rules);
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);
        Self { detector, scanner }
    }
}

impl DetectorWorker for YaraWorker<'_> {
    fn inspect_file(&mut self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(data) = file.content else {
            return Err(DetectorError::new("file content was not provided"));
        };
        let remaining = file.remaining();
        if remaining.is_zero() {
            return Err(DetectorError::new(
                "per-file time limit reached before YARA ran",
            ));
        }
        // YARA-X measures timeouts with a one-second heartbeat.
        let timeout = Duration::from_secs(remaining.as_secs().max(1));

        self.scanner.set_timeout(timeout);
        let results = match self.scanner.scan(data) {
            Ok(r) => r,
            Err(yara_x::errors::ScanError::Timeout) => {
                return Err(DetectorError::new(format!(
                    "YARA scan exceeded its {}s time limit",
                    timeout.as_secs()
                )));
            }
            Err(e) => return Err(DetectorError::new(format!("YARA scan failed: {e}"))),
        };

        let mut findings = Vec::new();
        for rule in results.matching_rules() {
            let key = (rule.namespace().to_owned(), rule.identifier().to_owned());
            let Some(meta) = self.detector.meta.get(&key) else {
                continue;
            };
            let rule_id = format!("{}:{}", key.0, key.1);
            findings.push(self.detector.finding(file, &rule, &rule_id, meta));
        }
        Ok(findings)
    }
}

impl YaraDetector {
    fn finding(
        &self,
        file: &FileObservation<'_>,
        rule: &yara_x::Rule<'_, '_>,
        rule_id: &str,
        meta: &RuleMeta,
    ) -> Finding {
        let mut summary = format!("YARA rule {rule_id} matched");
        let mut listed = 0;
        for pattern in rule.patterns() {
            for m in pattern.matches() {
                if listed == EVIDENCE_MATCHES {
                    break;
                }
                let r = m.range();
                let _ = write!(
                    summary,
                    "{} {} at offset {:#x} ({} bytes)",
                    if listed == 0 { ":" } else { "," },
                    pattern.identifier(),
                    r.start,
                    r.len()
                );
                listed += 1;
            }
        }
        if listed == 0 {
            summary.push_str(" (condition only; no pattern matches)");
        }

        let mut explanation = format!(
            "The file's content satisfies YARA rule {rule_id}. A rule match shows the file has \
             the characteristics the rule describes; how reliably that indicates a threat \
             depends on the rule."
        );
        if let Some(d) = &meta.description {
            let _ = write!(explanation, " Rule description: {d}");
        }

        let db = self.info.database.as_ref();
        Finding {
            id: FindingId::new_random(),
            kind: meta.kind,
            name: meta.name.clone(),
            severity: meta.severity,
            confidence: meta.confidence,
            category: meta.category,
            target: file.target(),
            source: DetectionSource {
                detector: DETECTOR_ID.to_owned(),
                detector_version: YARA_X_VERSION.to_owned(),
                rule_id: Some(rule_id.to_owned()),
                rule_version: meta.rule_version,
                database_name: db.map(|d| d.name.clone()),
                database_version: db.map(|d| d.version.clone()),
            },
            evidence: vec![Evidence {
                kind: EvidenceKind::YaraRuleMatch,
                summary,
            }],
            explanation,
            recommended_action: recommended_action(meta),
            remediation_guidance: None,
            remediation_status: RemediationStatus::NotAttempted,
            remediation_detail: None,
            detected_at: time::OffsetDateTime::now_utc(),
        }
    }
}

/// Quarantine is recommended only for high-confidence known-indicator rules
/// that describe malware. Heuristic and suspicious rules recommend review.
fn recommended_action(m: &RuleMeta) -> RecommendedAction {
    match (m.kind, m.category) {
        (_, ThreatCategory::TestIndicator) | (FindingKind::Informational, _) => {
            RecommendedAction::None
        }
        (FindingKind::KnownIndicator, ThreatCategory::Malware)
            if m.confidence >= Confidence::High =>
        {
            RecommendedAction::Quarantine
        }
        _ => RecommendedAction::Review,
    }
}

fn validate_namespace(ns: &str) -> Result<(), YaraLoadError> {
    let ok = !ns.is_empty()
        && ns.len() <= 64
        && ns.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(YaraLoadError::InvalidNamespace(ns.to_owned()))
    }
}

fn parse_meta(rule: &yara_x::Rule<'_, '_>) -> Result<RuleMeta, YaraLoadError> {
    let rule_name = format!("{}:{}", rule.namespace(), rule.identifier());
    let err = |key: &str, reason: &str| YaraLoadError::InvalidMetadata {
        rule: rule_name.clone(),
        key: key.to_owned(),
        reason: reason.to_owned(),
    };
    let mut m = RuleMeta {
        kind: FindingKind::Suspicious,
        confidence: Confidence::Medium,
        severity: Severity::Medium,
        category: ThreatCategory::Unknown,
        name: rule.identifier().to_owned(),
        rule_version: None,
        description: None,
    };

    for (key, value) in rule.metadata() {
        let text = match &value {
            yara_x::MetaValue::String(s) => Some(*s),
            _ => None,
        };
        let need_text = || text.ok_or_else(|| err(key, "must be a string"));
        match key {
            "aw_kind" => {
                m.kind = match need_text()? {
                    "known_indicator" => FindingKind::KnownIndicator,
                    "suspicious" => FindingKind::Suspicious,
                    "heuristic" => FindingKind::Heuristic,
                    "informational" => FindingKind::Informational,
                    _ => {
                        return Err(err(
                            key,
                            "must be known_indicator, suspicious, heuristic or informational",
                        ));
                    }
                }
            }
            "aw_confidence" => {
                m.confidence = match need_text()? {
                    "low" => Confidence::Low,
                    "medium" => Confidence::Medium,
                    "high" => Confidence::High,
                    // A pattern match is never an identity proof.
                    "confirmed" => {
                        return Err(err(key, "`confirmed` is reserved for exact hash matches"));
                    }
                    _ => return Err(err(key, "must be low, medium or high")),
                }
            }
            "aw_severity" => {
                m.severity = match need_text()? {
                    "info" => Severity::Info,
                    "low" => Severity::Low,
                    "medium" => Severity::Medium,
                    "high" => Severity::High,
                    "critical" => Severity::Critical,
                    _ => return Err(err(key, "must be info, low, medium, high or critical")),
                }
            }
            "aw_category" => {
                m.category = match need_text()? {
                    "malware" => ThreatCategory::Malware,
                    "potentially_unwanted" => ThreatCategory::PotentiallyUnwanted,
                    "test_indicator" => ThreatCategory::TestIndicator,
                    "unknown" => ThreatCategory::Unknown,
                    _ => {
                        return Err(err(
                            key,
                            "must be malware, potentially_unwanted, test_indicator or unknown",
                        ));
                    }
                }
            }
            "aw_name" => {
                let t = need_text()?;
                if t.trim().is_empty() || t.len() > MAX_NAME_LEN || has_unsafe_chars(t, false) {
                    return Err(err(key, "must be 1-256 bytes without control characters"));
                }
                t.clone_into(&mut m.name);
            }
            "aw_rule_version" => match value {
                yara_x::MetaValue::Integer(v) if (1..=i64::from(u32::MAX)).contains(&v) => {
                    m.rule_version = u32::try_from(v).ok();
                }
                _ => return Err(err(key, "must be an integer >= 1")),
            },
            "description" => {
                // Standard YARA metadata; used if it is safe to display.
                if let Some(t) = text
                    && t.len() <= MAX_META_TEXT
                    && !has_unsafe_chars(t, true)
                {
                    m.description = Some(t.to_owned());
                }
            }
            k if k.starts_with("aw_") => return Err(err(k, "is not a recognised aw_* key")),
            _ => {}
        }
    }
    Ok(m)
}

fn sha256_hex(data: &[u8]) -> String {
    // Reuse the core digest type for formatting.
    use sha2::Digest as _;
    Sha256Digest::from_bytes(sha2::Sha256::digest(data).into()).to_hex()
}
