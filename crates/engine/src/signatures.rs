//! Exact SHA-256 signature database (format version 1) and its detector.
//!
//! The format is documented in `docs/detection/signatures.md`. Databases are
//! untrusted input: parsing is size-bounded, strict (unknown fields are
//! rejected) and fully validated before any signature is used.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use time::OffsetDateTime;
use warden_core::{
    Confidence, DatabaseInfo, DetectionSource, Detector, DetectorError, DetectorInfo, Evidence,
    EvidenceKind, FileObservation, Finding, FindingId, FindingKind, RecommendedAction,
    RemediationStatus, Severity, Sha256Digest, ThreatCategory,
};

use crate::ENGINE_VERSION;
use crate::trust::KeyId;

/// Value of the top-level `format` field.
pub const FORMAT_ID: &str = "abyssal-warden.hash-signatures";
/// The only format version this build understands.
pub const FORMAT_VERSION: u32 = 1;
/// Largest database file accepted, in bytes.
pub const MAX_DATABASE_BYTES: u64 = 256 * 1024 * 1024;
/// Largest number of signatures accepted in one database.
pub const MAX_SIGNATURES: usize = 2_000_000;

const MAX_ID_LEN: usize = 128;
const MAX_NAME_LEN: usize = 256;
const MAX_VERSION_LEN: usize = 64;
const MAX_TEXT_LEN: usize = 4096;

/// Detector id recorded in reports.
pub const DETECTOR_ID: &str = "hash-signatures";

#[derive(Debug, thiserror::Error)]
pub enum SignatureDbError {
    #[error("cannot read signature database {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("signature database is larger than the {limit}-byte limit")]
    TooLarge { limit: u64 },
    #[error("signature database is not valid JSON for format version {FORMAT_VERSION}: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not an Abyssal Warden hash signature database (format {found:?})")]
    WrongFormat { found: String },
    #[error("unsupported signature database format version {found} (supported: {FORMAT_VERSION})")]
    UnsupportedVersion { found: u32 },
    #[error("signature database has more than {MAX_SIGNATURES} signatures")]
    TooManySignatures,
    #[error("{location}: field `{field}` {reason}")]
    InvalidField {
        location: String,
        field: &'static str,
        reason: String,
    },
    #[error("duplicate signature id {0:?}")]
    DuplicateId(String),
    #[error("signatures {first:?} and {second:?} have the same sha256 {sha256}")]
    DuplicateHash {
        sha256: Sha256Digest,
        first: String,
        second: String,
    },
}

/// Metadata describing a database.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Licence under which the database contents are distributed.
    #[serde(default)]
    pub license: Option<String>,
}

/// One exact-hash signature.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashSignature {
    pub id: String,
    pub name: String,
    pub sha256: Sha256Digest,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub rule_version: u32,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
}

#[derive(Deserialize)]
struct Header {
    format: String,
    format_version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDatabase {
    #[allow(dead_code)] // Checked via `Header` before the strict parse.
    format: String,
    #[allow(dead_code)]
    format_version: u32,
    database: DatabaseMeta,
    signatures: Vec<HashSignature>,
}

/// A validated, indexed exact-hash signature database.
#[derive(Debug)]
pub struct HashSignatureDatabase {
    meta: DatabaseMeta,
    signatures: Vec<HashSignature>,
    by_hash: HashMap<Sha256Digest, usize>,
}

impl HashSignatureDatabase {
    /// Read and validate a database file, refusing files over
    /// [`MAX_DATABASE_BYTES`].
    pub fn from_path(path: &Path) -> Result<Self, SignatureDbError> {
        let io_err = |source| SignatureDbError::Io {
            path: path.to_owned(),
            source,
        };
        let file = File::open(path).map_err(io_err)?;
        let len = file.metadata().map_err(io_err)?.len();
        if len > MAX_DATABASE_BYTES {
            return Err(SignatureDbError::TooLarge {
                limit: MAX_DATABASE_BYTES,
            });
        }
        let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        file.take(MAX_DATABASE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(io_err)?;
        Self::from_slice(&data)
    }

    /// Parse and validate a database from bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, SignatureDbError> {
        if data.len() as u64 > MAX_DATABASE_BYTES {
            return Err(SignatureDbError::TooLarge {
                limit: MAX_DATABASE_BYTES,
            });
        }
        // Check identity and version first so that a newer database yields a
        // clear "unsupported version" error rather than "unknown field".
        let header: Header = serde_json::from_slice(data)?;
        if header.format != FORMAT_ID {
            return Err(SignatureDbError::WrongFormat {
                found: truncate(&header.format, 64),
            });
        }
        if header.format_version != FORMAT_VERSION {
            return Err(SignatureDbError::UnsupportedVersion {
                found: header.format_version,
            });
        }
        let raw: RawDatabase = serde_json::from_slice(data)?;
        Self::validate(raw.database, raw.signatures)
    }

    fn validate(
        meta: DatabaseMeta,
        signatures: Vec<HashSignature>,
    ) -> Result<Self, SignatureDbError> {
        if signatures.len() > MAX_SIGNATURES {
            return Err(SignatureDbError::TooManySignatures);
        }
        let db = "database".to_owned();
        check_text(&db, "name", &meta.name, MAX_NAME_LEN, false, true)?;
        check_text(&db, "version", &meta.version, MAX_VERSION_LEN, false, true)?;
        if let Some(d) = &meta.description {
            check_text(&db, "description", d, MAX_TEXT_LEN, true, false)?;
        }
        if let Some(l) = &meta.license {
            check_text(&db, "license", l, MAX_NAME_LEN, false, true)?;
        }

        let mut ids = HashSet::with_capacity(signatures.len());
        let mut by_hash = HashMap::with_capacity(signatures.len());
        for (i, sig) in signatures.iter().enumerate() {
            let loc = format!("signatures[{i}]");
            check_id(&loc, &sig.id)?;
            check_text(&loc, "name", &sig.name, MAX_NAME_LEN, false, true)?;
            if let Some(d) = &sig.description {
                check_text(&loc, "description", d, MAX_TEXT_LEN, true, false)?;
            }
            if let Some(r) = &sig.remediation {
                check_text(&loc, "remediation", r, MAX_TEXT_LEN, true, false)?;
            }
            if sig.rule_version == 0 {
                return Err(invalid(&loc, "rule_version", "must be at least 1"));
            }
            if !ids.insert(sig.id.as_str()) {
                return Err(SignatureDbError::DuplicateId(sig.id.clone()));
            }
            if let Some(&prev) = by_hash.get(&sig.sha256) {
                let first: &HashSignature = &signatures[prev];
                return Err(SignatureDbError::DuplicateHash {
                    sha256: sig.sha256,
                    first: first.id.clone(),
                    second: sig.id.clone(),
                });
            }
            by_hash.insert(sig.sha256, i);
        }

        Ok(Self {
            meta,
            signatures,
            by_hash,
        })
    }

    pub fn meta(&self) -> &DatabaseMeta {
        &self.meta
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn lookup(&self, sha256: &Sha256Digest) -> Option<&HashSignature> {
        self.by_hash.get(sha256).map(|&i| &self.signatures[i])
    }
}

fn invalid(location: &str, field: &'static str, reason: &str) -> SignatureDbError {
    SignatureDbError::InvalidField {
        location: location.to_owned(),
        field,
        reason: reason.to_owned(),
    }
}

fn check_id(location: &str, id: &str) -> Result<(), SignatureDbError> {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(invalid(location, "id", "must be 1 to 128 characters"));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
    {
        return Err(invalid(
            location,
            "id",
            "may contain only ASCII letters, digits, '.', '_', '-' and ':'",
        ));
    }
    Ok(())
}

/// Text fields are shown to users, so control characters (which could drive
/// a terminal) and bidirectional overrides (which could disguise text) are
/// rejected at load time. Renderers escape output as well.
fn check_text(
    location: &str,
    field: &'static str,
    value: &str,
    max_len: usize,
    allow_newlines: bool,
    required: bool,
) -> Result<(), SignatureDbError> {
    if required && value.trim().is_empty() {
        return Err(invalid(location, field, "must not be empty"));
    }
    if value.len() > max_len {
        return Err(invalid(
            location,
            field,
            &format!("must be at most {max_len} bytes"),
        ));
    }
    if warden_core::text::has_unsafe_chars(value, allow_newlines) {
        return Err(invalid(
            location,
            field,
            "contains control or bidirectional formatting characters",
        ));
    }
    Ok(())
}

fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Detector that reports files whose SHA-256 exactly matches a signature.
#[derive(Debug)]
pub struct HashSignatureDetector {
    db: HashSignatureDatabase,
    signer: Option<KeyId>,
}

impl HashSignatureDetector {
    /// A detector for a database that was not signature-verified. Reports
    /// carry a warning to that effect.
    pub fn new(db: HashSignatureDatabase) -> Self {
        Self { db, signer: None }
    }

    /// A detector for a database whose signature was verified by `signer`
    /// (see [`crate::trust::load_content`]).
    pub fn verified(db: HashSignatureDatabase, signer: KeyId) -> Self {
        Self {
            db,
            signer: Some(signer),
        }
    }

    pub fn database(&self) -> &HashSignatureDatabase {
        &self.db
    }
}

impl Detector for HashSignatureDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: DETECTOR_ID.to_owned(),
            version: ENGINE_VERSION.to_owned(),
            database: Some(DatabaseInfo {
                name: self.db.meta.name.clone(),
                version: self.db.meta.version.clone(),
                entries: self.db.len() as u64,
                signer: self.signer.map(|k| k.to_string()),
            }),
        }
    }

    fn inspect_file(&self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        let Some(sig) = self.db.lookup(file.sha256) else {
            return Ok(Vec::new());
        };
        let meta = &self.db.meta;
        let recommended_action = match sig.category {
            ThreatCategory::Malware => RecommendedAction::Quarantine,
            ThreatCategory::TestIndicator => RecommendedAction::None,
            _ => RecommendedAction::Review,
        };
        Ok(vec![Finding {
            id: FindingId::new_random(),
            kind: FindingKind::KnownIndicator,
            name: sig.name.clone(),
            severity: sig.severity,
            confidence: Confidence::Confirmed,
            category: sig.category,
            target: file.target(),
            source: DetectionSource {
                detector: DETECTOR_ID.to_owned(),
                detector_version: ENGINE_VERSION.to_owned(),
                rule_id: Some(sig.id.clone()),
                rule_version: Some(sig.rule_version),
                database_name: Some(meta.name.clone()),
                database_version: Some(meta.version.clone()),
            },
            evidence: vec![Evidence {
                kind: EvidenceKind::ExactSha256Match,
                summary: format!(
                    "SHA-256 {} equals signature {} (rule version {})",
                    file.sha256, sig.id, sig.rule_version
                ),
            }],
            explanation: format!(
                "The file is byte-for-byte identical to the indicator recorded as signature {} \
                 in database \"{}\" version {}. The label \"{}\" is only as accurate as that \
                 database entry.",
                sig.id, meta.name, meta.version, sig.name
            ),
            recommended_action,
            remediation_guidance: sig.remediation.clone(),
            remediation_status: RemediationStatus::NotAttempted,
            remediation_detail: None,
            detected_at: OffsetDateTime::now_utc(),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::FileMetadata;

    const H1: &str = "26d11a0d2767bb969011c61c58953c5d89035f8c2ca524efcafe3a9c92461eae";
    const H2: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn db_json(signatures: &str) -> String {
        format!(
            r#"{{"format":"{FORMAT_ID}","format_version":1,
                "database":{{"name":"test-db","version":"2026.09.24"}},
                "signatures":[{signatures}]}}"#
        )
    }

    fn sig(id: &str, hash: &str) -> String {
        format!(
            r#"{{"id":"{id}","name":"Test.{id}","sha256":"{hash}","category":"test_indicator",
                "severity":"info","rule_version":1}}"#
        )
    }

    fn parse(s: &str) -> Result<HashSignatureDatabase, SignatureDbError> {
        HashSignatureDatabase::from_slice(s.as_bytes())
    }

    #[test]
    fn parses_and_looks_up() {
        let db = parse(&db_json(&format!("{},{}", sig("A", H1), sig("B", H2)))).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.meta().name, "test-db");
        let d: Sha256Digest = H1.parse().unwrap();
        assert_eq!(db.lookup(&d).unwrap().id, "A");
        assert!(db.lookup(&Sha256Digest::from_bytes([0; 32])).is_none());
    }

    #[test]
    fn empty_database_is_valid() {
        assert!(parse(&db_json("")).unwrap().is_empty());
    }

    #[test]
    fn rejects_wrong_format_and_version() {
        let wrong = db_json("").replace(FORMAT_ID, "something-else");
        assert!(matches!(
            parse(&wrong),
            Err(SignatureDbError::WrongFormat { .. })
        ));
        // A future version with unknown fields must report the version, not
        // the unknown field.
        let future = db_json("").replace(
            r#""format_version":1,"#,
            r#""format_version":2,"new_field":true,"#,
        );
        assert!(matches!(
            parse(&future),
            Err(SignatureDbError::UnsupportedVersion { found: 2 })
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_json() {
        let extra =
            db_json(&sig("A", H1).replace(r#""rule_version":1"#, r#""rule_version":1,"x":1"#));
        assert!(matches!(parse(&extra), Err(SignatureDbError::Json(_))));
        assert!(matches!(parse("{"), Err(SignatureDbError::Json(_))));
        assert!(matches!(parse("[]"), Err(SignatureDbError::Json(_))));
        assert!(matches!(parse(""), Err(SignatureDbError::Json(_))));
    }

    #[test]
    fn rejects_bad_hash() {
        assert!(matches!(
            parse(&db_json(&sig("A", "abcd"))),
            Err(SignatureDbError::Json(_))
        ));
    }

    #[test]
    fn rejects_duplicates() {
        assert!(matches!(
            parse(&db_json(&format!("{},{}", sig("A", H1), sig("A", H2)))),
            Err(SignatureDbError::DuplicateId(id)) if id == "A"
        ));
        assert!(matches!(
            parse(&db_json(&format!("{},{}", sig("A", H1), sig("B", H1)))),
            Err(SignatureDbError::DuplicateHash { .. })
        ));
        // Hash comparison is on the decoded digest, not the text.
        assert!(matches!(
            parse(&db_json(&format!(
                "{},{}",
                sig("A", H1),
                sig("B", &H1.to_uppercase())
            ))),
            Err(SignatureDbError::DuplicateHash { .. })
        ));
    }

    #[test]
    fn rejects_invalid_fields() {
        let cases = [
            sig("", H1),
            sig("bad id", H1),
            sig(&"x".repeat(129), H1),
            sig("A", H1).replace(r#""rule_version":1"#, r#""rule_version":0"#),
            sig("A", H1).replace("Test.A", r"Evil\u001b[2J"),
            sig("A", H1).replace("Test.A", "Evil\u{202E}txt.exe"),
            sig("A", H1).replace("Test.A", "  "),
        ];
        for case in cases {
            assert!(
                matches!(
                    parse(&db_json(&case)),
                    Err(SignatureDbError::InvalidField { .. })
                ),
                "accepted: {case}"
            );
        }
        let bad_meta = db_json("").replace(r#""name":"test-db""#, r#""name":"""#);
        assert!(matches!(
            parse(&bad_meta),
            Err(SignatureDbError::InvalidField { .. })
        ));
    }

    #[test]
    fn descriptions_may_contain_newlines() {
        let s = sig("A", H1).replace(
            r#""rule_version":1"#,
            r#""rule_version":1,"description":"line one\nline two""#,
        );
        assert!(parse(&db_json(&s)).is_ok());
    }

    #[test]
    fn detector_produces_structured_finding() {
        let db = parse(&db_json(&sig("AW-TEST-1", H1))).unwrap();
        let det = HashSignatureDetector::new(db);
        let info = det.info();
        assert_eq!(info.id, DETECTOR_ID);
        assert_eq!(info.database.unwrap().entries, 1);

        let digest: Sha256Digest = H1.parse().unwrap();
        let meta = FileMetadata {
            size: 41,
            modified: None,
            unix_mode: None,
        };
        let obs = FileObservation {
            path: Path::new("/x/fixture"),
            sha256: &digest,
            metadata: &meta,
            content: None,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
        };
        let findings = det.inspect_file(&obs).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.kind, FindingKind::KnownIndicator);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert_eq!(f.category, ThreatCategory::TestIndicator);
        assert_eq!(f.recommended_action, RecommendedAction::None);
        assert_eq!(f.source.rule_id.as_deref(), Some("AW-TEST-1"));
        assert_eq!(f.source.database_version.as_deref(), Some("2026.09.24"));
        assert_eq!(f.remediation_status, RemediationStatus::NotAttempted);

        let other = Sha256Digest::from_bytes([1; 32]);
        let obs = FileObservation {
            sha256: &other,
            ..obs
        };
        assert!(det.inspect_file(&obs).unwrap().is_empty());
    }

    #[test]
    fn example_database_in_repository_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/signatures/synthetic-test-indicators.json");
        let db = HashSignatureDatabase::from_path(&path).unwrap();
        assert!(!db.is_empty());
        assert!(db.lookup(&H1.parse().unwrap()).is_some());
    }
}
