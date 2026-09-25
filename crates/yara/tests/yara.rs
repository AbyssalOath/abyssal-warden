//! YARA-X provider tests, end-to-end through the scan engine. Rules and
//! inputs are synthetic; no real malware or real-world rules are used.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use warden_core::{
    CancellationToken, Confidence, Detector, FindingKind, IssueKind, RecommendedAction, ScanConfig,
    ScanReport, Severity, SkipReason, ThreatCategory,
};
use warden_engine::Scanner;
use warden_yara::{RuleSource, YaraDetector, YaraLoadError};

fn src(text: &str) -> Vec<RuleSource> {
    vec![RuleSource {
        namespace: "test".into(),
        origin: "test.yar".into(),
        text: text.into(),
    }]
}

fn compile(text: &str) -> Result<YaraDetector, YaraLoadError> {
    YaraDetector::compile(&src(text), None)
}

fn scan(root: &Path, det: YaraDetector, tweak: impl FnOnce(&mut ScanConfig)) -> ScanReport {
    let mut c = ScanConfig::new(vec![root.to_path_buf()]);
    c.workers = 2;
    tweak(&mut c);
    let mut s = Scanner::new(c).unwrap();
    s.add_detector(Box::new(det));
    s.scan(&CancellationToken::new(), |_, _| {}).unwrap()
}

const MARKER_RULE: &str = r#"
rule Synthetic_Marker {
  meta:
    description = "Matches the synthetic marker string"
  strings:
    $m = "ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER"
  condition:
    $m
}
"#;

#[test]
fn detects_synthetic_marker_with_default_semantics() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("hit.bin"),
        b"prefix ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER suffix",
    )
    .unwrap();
    std::fs::write(dir.path().join("miss.bin"), b"nothing here").unwrap();

    let det = compile(MARKER_RULE).unwrap();
    assert_eq!(det.rule_count(), 1);
    let report = scan(dir.path(), det, |_| {});

    assert!(report.is_complete(), "{:?}", report.issues);
    assert_eq!(report.stats.files_scanned, 2);
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert!(f.target.path().unwrap().text.ends_with("hit.bin"));
    // Without aw_* metadata a match is only "suspicious": never confirmed.
    assert_eq!(f.kind, FindingKind::Suspicious);
    assert_eq!(f.confidence, Confidence::Medium);
    assert_eq!(f.recommended_action, RecommendedAction::Review);
    assert_eq!(f.source.rule_id.as_deref(), Some("test:Synthetic_Marker"));
    assert!(
        f.evidence[0]
            .summary
            .contains("$m at offset 0x7 (36 bytes)")
    );
    assert!(
        f.explanation
            .contains("Matches the synthetic marker string")
    );
    let db = report.detectors[0].database.as_ref().unwrap();
    assert!(db.version.starts_with("sha256:"));
    assert!(db.signer.is_none());
}

#[test]
fn aw_metadata_controls_finding_semantics() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("f"),
        b"xx ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER",
    )
    .unwrap();
    let rule = r#"
rule Family_X {
  meta:
    aw_kind = "known_indicator"
    aw_confidence = "high"
    aw_severity = "high"
    aw_category = "malware"
    aw_name = "Synthetic.FamilyX"
    aw_rule_version = 3
  strings:
    $m = "ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER"
  condition:
    $m
}"#;
    let report = scan(dir.path(), compile(rule).unwrap(), |_| {});
    let f = &report.findings[0];
    assert_eq!(f.kind, FindingKind::KnownIndicator);
    assert_eq!(f.confidence, Confidence::High);
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.category, ThreatCategory::Malware);
    assert_eq!(f.name, "Synthetic.FamilyX");
    assert_eq!(f.source.rule_version, Some(3));
    assert_eq!(f.recommended_action, RecommendedAction::Quarantine);
}

#[test]
fn rejects_unsafe_or_invalid_rules() {
    let cases: &[(&str, &str)] = &[
        (
            "include",
            "include \"/etc/passwd\"\nrule a { condition: true }",
        ),
        ("syntax", "rule { condition: }"),
        (
            "kind",
            r#"rule a { meta: aw_kind = "malicious" condition: true }"#,
        ),
        (
            "confirmed",
            r#"rule a { meta: aw_confidence = "confirmed" condition: true }"#,
        ),
        (
            "unknown aw key",
            r#"rule a { meta: aw_action = "delete" condition: true }"#,
        ),
        (
            "version type",
            r#"rule a { meta: aw_rule_version = "1" condition: true }"#,
        ),
        (
            "version zero",
            r#"rule a { meta: aw_rule_version = 0 condition: true }"#,
        ),
        (
            "name control",
            "rule a { meta: aw_name = \"x\\x1b[2J\" condition: true }",
        ),
        (
            "excluded module",
            "import \"cuckoo\"\nrule a { condition: true }",
        ),
        (
            "name bidi",
            "rule a { meta: aw_name = \"invoice\u{202E}fdp.exe\" condition: true }",
        ),
    ];
    for (label, text) in cases {
        match compile(text) {
            Ok(_) => panic!("accepted rule: {label}"),
            Err(e) => eprintln!("[{label}] {e}"),
        }
    }
    assert!(matches!(
        YaraDetector::compile(
            &[RuleSource {
                namespace: "../x".into(),
                origin: "o".into(),
                text: "rule a { condition: true }".into()
            }],
            None
        ),
        Err(YaraLoadError::InvalidNamespace(_))
    ));
    assert!(matches!(
        YaraDetector::compile(&[], None),
        Err(YaraLoadError::Empty)
    ));
}

#[test]
fn rejects_slow_patterns() {
    // A one-byte pattern has no useful atom and forces a full-content
    // verification pass; YARA-X flags it as slow, and we make that an error.
    let err = compile(r#"rule a { strings: $a = { 00 } condition: $a }"#).unwrap_err();
    assert!(err.to_string().contains("slow"), "{err}");
}

#[test]
fn common_modules_are_available() {
    for m in [
        "pe", "elf", "macho", "dotnet", "hash", "math", "string", "time", "lnk", "dex",
    ] {
        let r = format!("import \"{m}\"\nrule a {{ condition: true }}");
        assert!(compile(&r).is_ok(), "module {m} unavailable");
    }
}

#[test]
fn unsafe_description_is_not_displayed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("f"),
        b"ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER",
    )
    .unwrap();
    let rule = "rule a { meta: description = \"evil\\x1b]0;title\\x07\" strings: $m = \"ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER\" condition: $m }";
    let report = scan(dir.path(), compile(rule).unwrap(), |_| {});
    assert!(!report.findings[0].explanation.contains('\x1b'));
}

#[test]
fn files_over_content_limit_are_reported_not_silently_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let mut big = vec![b'x'; 4096];
    big.extend_from_slice(b"ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER");
    std::fs::write(dir.path().join("big"), &big).unwrap();
    let report = scan(dir.path(), compile(MARKER_RULE).unwrap(), |c| {
        c.limits.max_content_size = 1024;
    });
    assert!(report.findings.is_empty());
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(
        report
            .stats
            .skipped_by_reason
            .get(&SkipReason::ContentNotInspected),
        Some(&1)
    );
}

#[test]
fn pathological_rule_times_out_and_scan_continues() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("slow"), vec![1u8; 256 * 1024]).unwrap();
    // O(filesize^2) condition that can never be true.
    let rule = r#"
rule quadratic {
  condition:
    for any i in (0..filesize) : (
      for any j in (0..filesize) : ( uint8(i) + uint8(j) == 1000 )
    )
}"#;
    let started = std::time::Instant::now();
    let report = scan(dir.path(), compile(rule).unwrap(), |c| {
        c.limits.file_timeout_ms = 1_500;
    });
    let took = started.elapsed();
    assert_eq!(report.status, warden_core::ScanStatus::Completed);
    assert_eq!(report.issues.len(), 1, "{:?}", report.issues);
    assert_eq!(report.issues[0].kind, IssueKind::DetectorFailed);
    assert!(
        report.issues[0].message.contains("time limit"),
        "{}",
        report.issues[0].message
    );
    assert!(took < std::time::Duration::from_secs(10), "took {took:?}");
}

#[test]
fn signer_is_recorded() {
    let det = YaraDetector::compile(&src(MARKER_RULE), Some("ABCDEF0123456789".into())).unwrap();
    assert_eq!(
        det.info().database.unwrap().signer.as_deref(),
        Some("ABCDEF0123456789")
    );
}
