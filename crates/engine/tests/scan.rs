//! End-to-end scanner tests over synthetic fixtures in temporary directories.
//! No real malware is used; the "indicator" is a harmless synthetic file.

// Test helpers outside `#[test]` functions are not covered by clippy's
// `allow-unwrap-in-tests`; failing loudly is the desired behaviour here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use warden_core::{
    CancellationToken, Detector, DetectorError, DetectorInfo, FileObservation, Finding, IssueKind,
    ScanConfig, ScanReport, ScanStatus, SkipReason,
};
use warden_engine::signatures::{HashSignatureDatabase, HashSignatureDetector};
use warden_engine::{ProgressEvent, Scanner};

const INDICATOR: &[u8] = b"ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR\n";
const INDICATOR_SHA256: &str = "26d11a0d2767bb969011c61c58953c5d89035f8c2ca524efcafe3a9c92461eae";

fn test_db() -> HashSignatureDatabase {
    let json = format!(
        r#"{{"format":"abyssal-warden.hash-signatures","format_version":1,
            "database":{{"name":"it-db","version":"1"}},
            "signatures":[{{"id":"AW-IT-1","name":"Test.Indicator","sha256":"{INDICATOR_SHA256}",
              "category":"test_indicator","severity":"info","rule_version":1}}]}}"#
    );
    HashSignatureDatabase::from_slice(json.as_bytes()).unwrap()
}

fn config(root: &Path) -> ScanConfig {
    let mut c = ScanConfig::new(vec![root.to_path_buf()]);
    c.workers = 2;
    c
}

fn scan_with(config: ScanConfig, detectors: Vec<Box<dyn Detector>>) -> ScanReport {
    let mut scanner = Scanner::new(config).unwrap();
    for d in detectors {
        scanner.add_detector(d);
    }
    scanner.scan(&CancellationToken::new(), |_, _| {}).unwrap()
}

fn scan_db(config: ScanConfig) -> ScanReport {
    scan_with(
        config,
        vec![Box::new(HashSignatureDetector::new(test_db()))],
    )
}

fn write(path: &Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

fn canonical(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap()
}

fn skipped_count(report: &ScanReport, reason: SkipReason) -> u64 {
    report
        .stats
        .skipped_by_reason
        .get(&reason)
        .copied()
        .unwrap_or(0)
}

#[test]
fn nested_tree_detects_synthetic_indicator() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(&root.join("a/b/c/indicator.txt"), INDICATOR);
    write(&root.join("a/clean.txt"), b"hello");
    write(&root.join("a/b/empty"), b"");
    write(&root.join("top.bin"), &[0u8; 4096]);

    let report = scan_db(config(root));

    assert_eq!(report.status, ScanStatus::Completed);
    assert!(report.is_complete(), "issues: {:?}", report.issues);
    assert_eq!(report.stats.files_scanned, 4);
    assert_eq!(report.stats.bytes_scanned, 40 + 5 + 4096);
    assert_eq!(report.stats.directories_visited, 4); // root, a, a/b, a/b/c
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.stats.findings, 1);
    // The only warning is that the test database was not signature-verified.
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(report.warnings[0].contains("without signature verification"));

    let f = &report.findings[0];
    let expected = canonical(&root.join("a/b/c/indicator.txt"));
    assert_eq!(f.target.path().unwrap().text, expected.to_str().unwrap());
    assert_eq!(f.source.rule_id.as_deref(), Some("AW-IT-1"));
    match &f.target {
        warden_core::FindingTarget::File {
            sha256, metadata, ..
        } => {
            assert_eq!(sha256.unwrap().to_hex(), INDICATOR_SHA256);
            assert_eq!(metadata.as_ref().unwrap().size, 40);
        }
        other => panic!("unexpected target {other:?}"),
    }

    // The report is the structured contract: it must round-trip through JSON.
    let json = serde_json::to_string(&report).unwrap();
    let back: ScanReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["status"], "completed");
}

#[test]
fn single_file_root_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("indicator");
    write(&file, INDICATOR);
    let report = scan_db(config(&file));
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn warns_when_no_detectors_are_configured() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("indicator"), INDICATOR);
    let report = scan_with(config(dir.path()), vec![]);
    assert_eq!(report.stats.files_scanned, 1);
    assert!(report.findings.is_empty());
    assert!(report.detectors.is_empty());
    assert!(report.warnings.iter().any(|w| w.contains("No detectors")));
}

#[test]
fn oversized_files_are_skipped_not_hashed() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("small"), &[1u8; 10]);
    write(&dir.path().join("big"), &[1u8; 11]);
    let mut c = config(dir.path());
    c.limits.max_file_size = 10;
    let report = scan_db(c);
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(skipped_count(&report, SkipReason::ExceedsMaxFileSize), 1);
    assert!(report.skipped[0].path.text.ends_with("big"));
    // A policy skip is not an issue.
    assert!(report.is_complete());
}

#[test]
fn depth_limit_is_enforced_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("d1/f1"), b"1");
    write(&dir.path().join("d1/d2/f2"), b"2");
    let mut c = config(dir.path());
    c.limits.max_depth = 1;
    let report = scan_db(c);
    assert_eq!(report.stats.files_scanned, 0);
    assert_eq!(skipped_count(&report, SkipReason::DepthLimitReached), 1);

    let mut c = config(dir.path());
    c.limits.max_depth = 2;
    let report = scan_db(c);
    assert_eq!(report.stats.files_scanned, 1);
}

#[test]
fn excluded_directories_are_pruned() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("keep/indicator"), INDICATOR);
    write(&dir.path().join("skip/indicator"), INDICATOR);
    write(&dir.path().join("skip/deeper/x"), b"x");
    let mut c = config(dir.path());
    c.excludes.push(dir.path().join("skip"));
    let report = scan_db(c);
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(report.findings.len(), 1);
    assert!(
        report.findings[0]
            .target
            .path()
            .unwrap()
            .text
            .contains("keep")
    );
    // The excluded directory is one skip; its contents are never visited.
    assert_eq!(skipped_count(&report, SkipReason::Excluded), 1);
}

#[test]
fn exclude_matching_is_component_wise() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("skip/a"), b"a");
    write(&dir.path().join("skipnot/b"), b"b");
    let mut c = config(dir.path());
    c.excludes.push(dir.path().join("skip"));
    let report = scan_db(c);
    assert_eq!(report.stats.files_scanned, 1);
}

#[test]
fn missing_root_is_an_issue_and_other_roots_still_scan() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("present/f"), b"f");
    let mut c = config(&dir.path().join("present"));
    c.roots.push(dir.path().join("absent"));
    let report = scan_db(c);
    assert_eq!(report.status, ScanStatus::Completed);
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].kind, IssueKind::NotFound);
    assert!(!report.is_complete());
}

#[test]
fn nested_and_duplicate_roots_are_scanned_once() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("a/b/indicator"), INDICATOR);
    let mut c = config(dir.path());
    c.roots.push(dir.path().join("a"));
    c.roots.push(dir.path().join("a/b"));
    c.roots.push(dir.path().to_path_buf());
    let report = scan_db(c);
    assert_eq!(report.settings.roots.len(), 1);
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn cancellation_before_start_yields_cancelled_empty_report() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("f"), b"f");
    let scanner = Scanner::new(config(dir.path())).unwrap();
    let token = CancellationToken::new();
    token.cancel();
    let report = scanner.scan(&token, |_, _| {}).unwrap();
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert_eq!(report.stats.files_scanned, 0);
    assert!(report.warnings.iter().any(|w| w.contains("cancelled")));
}

#[test]
fn cancellation_mid_scan_stops_early() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..500 {
        write(&dir.path().join(format!("f{i:03}")), &[0u8; 1024]);
    }
    let mut c = config(dir.path());
    c.workers = 1;
    let scanner = Scanner::new(c).unwrap();
    let token = CancellationToken::new();
    let mut events = 0;
    let report = scanner
        .scan(&token, |ev, _| {
            if matches!(ev, ProgressEvent::FileScanned { .. }) {
                events += 1;
                token.cancel();
            }
        })
        .unwrap();
    assert_eq!(report.status, ScanStatus::Cancelled);
    assert!(events >= 1);
    // With one worker and bounded queues, only a handful of files can be
    // in flight when cancellation is observed.
    assert!(
        report.stats.files_scanned < 50,
        "scanned {} files after cancellation",
        report.stats.files_scanned
    );
}

#[test]
fn progress_reports_every_file_and_finding() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("indicator"), INDICATOR);
    write(&dir.path().join("x"), b"x");
    let mut scanner = Scanner::new(config(dir.path())).unwrap();
    scanner.add_detector(Box::new(HashSignatureDetector::new(test_db())));
    let (mut files, mut findings, mut last_bytes) = (0, 0, 0);
    let report = scanner
        .scan(&CancellationToken::new(), |ev, stats| {
            match ev {
                ProgressEvent::FileScanned { .. } => files += 1,
                ProgressEvent::Finding(_) => findings += 1,
                _ => {}
            }
            last_bytes = stats.bytes_scanned;
        })
        .unwrap();
    assert_eq!(files, 2);
    assert_eq!(findings, 1);
    assert_eq!(last_bytes, report.stats.bytes_scanned);
}

#[test]
fn finding_recording_limit_truncates_but_counts() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..3 {
        write(&dir.path().join(format!("copy{i}")), INDICATOR);
    }
    let mut c = config(dir.path());
    c.limits.max_recorded_findings = 1;
    let report = scan_db(c);
    assert_eq!(report.stats.findings, 3);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.truncated.findings_omitted, 2);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("Recording limits"))
    );
}

struct FaultyDetector {
    panic: bool,
}

impl Detector for FaultyDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: if self.panic { "panicky" } else { "failing" }.into(),
            version: "0".into(),
            database: None,
        }
    }

    fn inspect_file(&self, _: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        if self.panic {
            panic!("simulated parser bug");
        }
        Err(DetectorError::new("simulated failure"))
    }
}

#[test]
fn detector_failures_and_panics_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("indicator"), INDICATOR);
    let report = scan_with(
        config(dir.path()),
        vec![
            Box::new(FaultyDetector { panic: true }),
            Box::new(FaultyDetector { panic: false }),
            Box::new(HashSignatureDetector::new(test_db())),
        ],
    );
    assert_eq!(report.status, ScanStatus::Completed);
    assert_eq!(report.stats.files_scanned, 1);
    // The healthy detector still ran after the faulty ones.
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.issues.len(), 2);
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.kind == IssueKind::DetectorFailed)
    );
    let ids: Vec<_> = report
        .issues
        .iter()
        .filter_map(|i| i.detector.as_deref())
        .collect();
    assert!(ids.contains(&"panicky") && ids.contains(&"failing"));
    assert!(!report.is_complete());
}

#[test]
fn invalid_config_is_rejected() {
    let mut c = ScanConfig::new(vec![]);
    assert!(Scanner::new(c.clone()).is_err());
    c.roots.push(PathBuf::from("."));
    c.workers = 0;
    assert!(Scanner::new(c).is_err());
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;
    use warden_core::SymlinkPolicy;

    #[test]
    fn symlinks_are_skipped_by_default() {
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("indicator"), INDICATOR);
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("real"), b"r");
        symlink(
            outside.path().join("indicator"),
            dir.path().join("file-link"),
        )
        .unwrap();
        symlink(outside.path(), dir.path().join("dir-link")).unwrap();

        let report = scan_db(config(dir.path()));
        assert_eq!(report.stats.files_scanned, 1);
        assert!(report.findings.is_empty(), "link escaped the scan root");
        assert_eq!(skipped_count(&report, SkipReason::SymlinkNotFollowed), 2);
    }

    #[test]
    fn symlinks_are_followed_when_configured() {
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("indicator"), INDICATOR);
        let dir = tempfile::tempdir().unwrap();
        symlink(outside.path(), dir.path().join("dir-link")).unwrap();
        let mut c = config(dir.path());
        c.symlink_policy = SymlinkPolicy::Follow;
        let report = scan_db(c);
        assert_eq!(report.findings.len(), 1);
        assert!(report.warnings.iter().any(|w| w.contains("followed")));
    }

    #[test]
    fn symlink_loops_terminate_with_an_issue() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("sub/f"), b"f");
        symlink(dir.path(), dir.path().join("sub/loop")).unwrap();
        let mut c = config(dir.path());
        c.symlink_policy = SymlinkPolicy::Follow;
        let report = scan_db(c);
        assert_eq!(report.status, ScanStatus::Completed);
        assert_eq!(report.stats.files_scanned, 1);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.kind == IssueKind::FilesystemLoop)
        );
    }

    #[test]
    fn unreadable_directory_is_reported_and_scan_continues() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("ok/f"), b"f");
        write(&dir.path().join("locked/secret"), b"s");
        let locked = dir.path().join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let readable_anyway = fs::read_dir(&locked).is_ok(); // e.g. running as root
        let report = scan_db(config(dir.path()));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

        if readable_anyway {
            eprintln!("skipping assertion: process can read mode-000 directories");
            return;
        }
        assert_eq!(report.stats.files_scanned, 1);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.kind == IssueKind::PermissionDenied)
        );
    }

    #[test]
    fn unreadable_file_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("secret");
        write(&f, b"s");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
        let readable_anyway = fs::File::open(&f).is_ok();
        let report = scan_db(config(dir.path()));
        if readable_anyway {
            return;
        }
        assert_eq!(report.stats.files_scanned, 0);
        assert_eq!(report.issues[0].kind, IssueKind::PermissionDenied);
    }

    #[test]
    fn fifo_does_not_block_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        match Command::new("mkfifo").arg(&fifo).status() {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("skipping: mkfifo unavailable");
                return;
            }
        }
        write(&dir.path().join("f"), b"f");
        let report = scan_db(config(dir.path()));
        assert_eq!(report.stats.files_scanned, 1);
        assert_eq!(skipped_count(&report, SkipReason::NotRegularFile), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_file_name_is_reported_losslessly() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let name = OsStr::from_bytes(b"evil\xff\x1b[2Jname");
        write(&dir.path().join(name), INDICATOR);
        let report = scan_db(config(dir.path()));
        assert_eq!(report.findings.len(), 1);
        let path = report.findings[0].target.path().unwrap();
        assert!(path.is_lossy());
        assert!(
            path.raw_hex
                .as_deref()
                .unwrap()
                .ends_with("6576696cff1b5b324a6e616d65")
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("raw_hex"));
    }
}

/// Records the content it is given, and optionally sleeps.
struct ContentProbe {
    id: &'static str,
    needs_content: bool,
    sleep: std::time::Duration,
    seen: std::sync::Mutex<Vec<(String, Option<Vec<u8>>)>>,
}

impl ContentProbe {
    fn new(id: &'static str, needs_content: bool, sleep_ms: u64) -> Self {
        Self {
            id,
            needs_content,
            sleep: std::time::Duration::from_millis(sleep_ms),
            seen: std::sync::Mutex::new(Vec::new()),
        }
    }
}

/// Newtype so the test can keep a handle to the probe after boxing it.
struct Probe(std::sync::Arc<ContentProbe>);

impl Detector for Probe {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: self.0.id.into(),
            version: "0".into(),
            database: None,
        }
    }

    fn requirements(&self) -> warden_core::DetectorRequirements {
        warden_core::DetectorRequirements {
            content: self.0.needs_content,
        }
    }

    fn inspect_file(&self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        std::thread::sleep(self.0.sleep);
        let name = file
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        self.0
            .seen
            .lock()
            .unwrap()
            .push((name, file.content.map(<[u8]>::to_vec)));
        Ok(Vec::new())
    }
}

#[test]
fn content_is_shared_with_detectors_and_bounded() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("small"), b"hello content");
    write(&dir.path().join("large"), &[7u8; 100]);
    let content = Arc::new(ContentProbe::new("content", true, 0));
    let hash_only = Arc::new(ContentProbe::new("hash-only", false, 0));
    let mut c = config(dir.path());
    c.limits.max_content_size = 50;
    let report = scan_with(
        c,
        vec![
            Box::new(Probe(Arc::clone(&content))),
            Box::new(Probe(Arc::clone(&hash_only))),
            Box::new(HashSignatureDetector::new(test_db())),
        ],
    );

    assert_eq!(report.stats.files_scanned, 2);
    // The content detector saw the exact bytes of the small file only.
    let seen = content.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, "small");
    assert_eq!(seen[0].1.as_deref(), Some(&b"hello content"[..]));
    // A detector that does not need content still ran on both files.
    assert_eq!(hash_only.seen.lock().unwrap().len(), 2);
    // The coverage gap is reported, not silent.
    assert_eq!(skipped_count(&report, SkipReason::ContentNotInspected), 1);
    assert!(report.skipped[0].path.text.ends_with("large"));
}

#[test]
fn no_content_is_buffered_when_no_detector_needs_it() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("f"), b"data");
    let probe = Arc::new(ContentProbe::new("hash-only", false, 0));
    let report = scan_with(
        config(dir.path()),
        vec![Box::new(Probe(Arc::clone(&probe)))],
    );
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(probe.seen.lock().unwrap()[0].1, None);
    assert_eq!(skipped_count(&report, SkipReason::ContentNotInspected), 0);
}

#[test]
fn per_file_time_limit_stops_remaining_detectors() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("indicator"), INDICATOR);
    let slow = Arc::new(ContentProbe::new("slow", false, 300));
    let after = Arc::new(ContentProbe::new("after", false, 0));
    let mut c = config(dir.path());
    c.limits.file_timeout_ms = 50;
    let report = scan_with(
        c,
        vec![
            Box::new(Probe(Arc::clone(&slow))),
            Box::new(Probe(Arc::clone(&after))),
        ],
    );
    assert_eq!(report.stats.files_scanned, 1);
    assert!(
        after.seen.lock().unwrap().is_empty(),
        "detector ran after the deadline"
    );
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].kind, IssueKind::Timeout);
    assert!(report.issues[0].message.contains("after"));
    assert!(!report.is_complete());
}

/// Sleeps (ignoring its deadline) on files whose name starts with "stuck",
/// simulating a read blocked on a hung filesystem or a runaway detector.
struct Staller {
    on_stuck: std::time::Duration,
    on_other: std::time::Duration,
}

impl Detector for Staller {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "staller".into(),
            version: "0".into(),
            database: None,
        }
    }

    fn inspect_file(&self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError> {
        let stuck = file
            .path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("stuck"));
        std::thread::sleep(if stuck { self.on_stuck } else { self.on_other });
        Ok(Vec::new())
    }
}

#[test]
fn stalled_file_is_abandoned_and_scan_finishes() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("stuck-file"), b"s");
    for i in 0..20 {
        write(&dir.path().join(format!("ok{i}")), b"o");
    }
    let mut c = config(dir.path());
    c.workers = 1;
    c.limits.file_timeout_ms = 100;
    let started = std::time::Instant::now();
    let report = scan_with(
        c,
        vec![Box::new(Staller {
            on_stuck: std::time::Duration::from_secs(30),
            on_other: std::time::Duration::ZERO,
        })],
    );
    let took = started.elapsed();

    assert!(took < std::time::Duration::from_secs(10), "took {took:?}");
    assert_eq!(report.status, ScanStatus::Completed);
    // The replacement worker scanned everything else.
    assert_eq!(report.stats.files_scanned, 20);
    assert_eq!(report.issues.len(), 1, "{:?}", report.issues);
    assert_eq!(report.issues[0].kind, IssueKind::Timeout);
    assert!(
        report.issues[0]
            .path
            .as_ref()
            .unwrap()
            .text
            .ends_with("stuck-file")
    );
    assert!(report.issues[0].message.contains("abandoned"));
    assert!(report.warnings.iter().any(|w| w.contains("abandoned")));
}

#[test]
fn scan_stops_when_every_worker_is_stalled() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..5 {
        write(&dir.path().join(format!("stuck{i}")), b"s");
    }
    let mut c = config(dir.path());
    c.workers = 1;
    c.limits.file_timeout_ms = 100;
    let started = std::time::Instant::now();
    let report = scan_with(
        c,
        vec![Box::new(Staller {
            on_stuck: std::time::Duration::from_secs(60),
            on_other: std::time::Duration::ZERO,
        })],
    );
    // One original worker plus one replacement, each abandoned after
    // ~2.1s; then the scan stops instead of hanging.
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
    assert_eq!(report.status, ScanStatus::TimeLimitReached);
    assert_eq!(report.stats.files_scanned, 0);
    // Two files abandoned, plus one issue accounting for the three files
    // that were queued but never picked up.
    let abandoned = report
        .issues
        .iter()
        .filter(|i| i.message.contains("abandoned"))
        .count();
    assert_eq!(abandoned, 2, "{:?}", report.issues);
    assert!(
        report.issues.iter().any(|i| i.path.is_none()
            && i.message.starts_with("3 queued file(s) were not scanned")),
        "{:?}",
        report.issues
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("Too many files stalled"))
    );
}

#[test]
fn whole_scan_time_limit_returns_partial_results() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..200 {
        write(&dir.path().join(format!("f{i:03}")), b"x");
    }
    let mut c = config(dir.path());
    c.workers = 1;
    c.limits.scan_timeout_ms = Some(300);
    let started = std::time::Instant::now();
    let report = scan_with(
        c,
        vec![Box::new(Staller {
            on_stuck: std::time::Duration::ZERO,
            on_other: std::time::Duration::from_millis(20),
        })],
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(report.status, ScanStatus::TimeLimitReached);
    assert!(report.stats.files_scanned > 0);
    assert!(
        report.stats.files_scanned < 200,
        "{}",
        report.stats.files_scanned
    );
    assert_eq!(report.settings.scan_timeout_ms, Some(300));
    assert!(report.warnings.iter().any(|w| w.contains("time limit")));
}

#[test]
fn zero_scan_time_limit_is_rejected() {
    let mut c = ScanConfig::new(vec![PathBuf::from(".")]);
    c.limits.scan_timeout_ms = Some(0);
    assert!(Scanner::new(c).is_err());
}

#[cfg(unix)]
#[test]
fn followed_links_to_the_same_file_are_scanned_once() {
    use std::os::unix::fs::symlink;
    use warden_core::SymlinkPolicy;

    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("real/indicator"), INDICATOR);
    symlink(dir.path().join("real"), dir.path().join("dir-link")).unwrap();
    symlink(
        dir.path().join("real/indicator"),
        dir.path().join("file-link"),
    )
    .unwrap();
    let mut c = config(dir.path());
    c.symlink_policy = SymlinkPolicy::Follow;
    let report = scan_db(c);
    assert_eq!(report.stats.files_scanned, 1);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(skipped_count(&report, SkipReason::DuplicateFile), 2);
}

mod archives {
    use super::*;
    use std::io::{Cursor, Write};
    use warden_core::FindingTarget;
    use zip::write::SimpleFileOptions;

    fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(*name, SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn member_chain(f: &Finding) -> Vec<String> {
        match &f.target {
            FindingTarget::ArchiveMember { member, .. } => {
                member.iter().map(|m| m.text.clone()).collect()
            }
            other => panic!("expected an archive member, got {other:?}"),
        }
    }

    #[test]
    fn indicator_inside_nested_zip_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let inner = zip_of(&[("payload/indicator.txt", INDICATOR)]);
        let outer = zip_of(&[("readme.txt", b"hello"), ("inner.zip", &inner)]);
        write(&dir.path().join("delivery.zip"), &outer);

        let report = scan_db(config(dir.path()));
        assert!(report.is_complete(), "{:?}", report.issues);
        assert_eq!(report.stats.files_scanned, 1);
        assert_eq!(report.stats.archive_members_scanned, 3);
        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(member_chain(f), vec!["inner.zip", "payload/indicator.txt"]);
        assert!(f.target.path().unwrap().text.ends_with("delivery.zip"));
        assert_eq!(f.target.sha256().unwrap().to_hex(), INDICATOR_SHA256);

        // The member target round-trips through JSON.
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["findings"][0]["target"]["type"], "archive_member");
        assert_eq!(
            v["findings"][0]["target"]["member"][1]["text"],
            "payload/indicator.txt"
        );
        let back: ScanReport = serde_json::from_value(v).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn archives_can_be_disabled() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("a.zip"),
            &zip_of(&[("indicator.txt", INDICATOR)]),
        );
        let mut c = config(dir.path());
        c.limits.archives.enabled = false;
        let report = scan_db(c);
        assert!(report.findings.is_empty());
        assert_eq!(report.stats.archive_members_scanned, 0);
    }

    #[test]
    fn archive_larger_than_content_limit_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let noise: Vec<u8> = (0..20_000u32).flat_map(|i| i.to_le_bytes()).collect();
        write(
            &dir.path().join("big.zip"),
            &zip_of(&[("indicator.txt", INDICATOR), ("noise", &noise)]),
        );
        let mut c = config(dir.path());
        c.limits.max_content_size = 1024;
        let report = scan_db(c);
        assert!(report.findings.is_empty());
        assert_eq!(skipped_count(&report, SkipReason::ArchiveTooLarge), 1);
    }

    #[test]
    fn unsupported_members_and_corrupt_archives_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        // Rewrite the compression method of the only entry to 12 (bzip2),
        // which this build does not decompress.
        let mut z = zip_of(&[("m.bin", b"member")]);
        z[8] = 12;
        z[9] = 0;
        let cd = z.windows(4).position(|w| w == b"PK\x01\x02").unwrap();
        z[cd + 10] = 12;
        z[cd + 11] = 0;
        write(&dir.path().join("bzip2.zip"), &z);
        write(&dir.path().join("broken.zip"), b"PK\x03\x04 truncated");

        let report = scan_db(config(dir.path()));
        assert_eq!(report.stats.files_scanned, 2);
        assert_eq!(
            skipped_count(&report, SkipReason::ArchiveMemberUnsupported),
            1
        );
        let unsupported = report
            .skipped
            .iter()
            .find(|s| s.reason == SkipReason::ArchiveMemberUnsupported)
            .unwrap();
        assert_eq!(unsupported.member.as_ref().unwrap()[0].text, "m.bin");
        assert_eq!(report.issues.len(), 1, "{:?}", report.issues);
        assert_eq!(report.issues[0].kind, IssueKind::ArchiveError);
        assert!(
            report.issues[0]
                .path
                .as_ref()
                .unwrap()
                .text
                .ends_with("broken.zip")
        );
    }

    #[test]
    fn hash_only_scan_expands_archives_without_buffering_other_files() {
        // No content detectors: archives are still expanded; plain files are
        // hashed as before.
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("a.zip"),
            &zip_of(&[("indicator.txt", INDICATOR)]),
        );
        write(&dir.path().join("plain.txt"), b"plain");
        let report = scan_db(config(dir.path()));
        assert_eq!(report.stats.files_scanned, 2);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(member_chain(&report.findings[0]), vec!["indicator.txt"]);
    }

    #[test]
    fn office_style_zip_with_misleading_extension_is_expanded() {
        // Detection is by content signature, not by file name.
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("invoice.docx"),
            &zip_of(&[("word/media/indicator.bin", INDICATOR)]),
        );
        write(
            &dir.path().join("photo.jpg"),
            &zip_of(&[("x/indicator.txt", INDICATOR)]),
        );
        let report = scan_db(config(dir.path()));
        assert_eq!(report.findings.len(), 2);
    }
}
