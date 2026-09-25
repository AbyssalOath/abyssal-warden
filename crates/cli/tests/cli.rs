//! Black-box tests of the `abyssal-warden` binary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const INDICATOR: &[u8] = b"ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR\n";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_abyssal-warden"))
}

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn test_key() -> PathBuf {
    examples().join("keys/synthetic-test.pub")
}

/// `abyssal-warden scan` with the synthetic test key trusted.
fn trusted_scan() -> Command {
    let mut c = bin();
    c.arg("scan").arg("--trusted-key").arg(test_key());
    c
}

fn example_db() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/signatures/synthetic-test-indicators.json")
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("failed to run binary")
}

#[test]
fn json_scan_with_finding_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("indicator.txt"), INDICATOR).unwrap();
    fs::write(dir.path().join("clean.txt"), b"clean").unwrap();

    let out = run(bin()
        .args(["scan", "--trusted-key"])
        .arg(test_key())
        .args(["--format", "json", "--signatures"])
        .arg(example_db())
        .arg(dir.path()));
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["status"], "completed");
    assert_eq!(v["stats"]["files_scanned"], 2);
    assert_eq!(v["findings"][0]["source"]["rule_id"], "AW-TEST-0001");
    assert_eq!(v["findings"][0]["category"], "test_indicator");
}

#[test]
fn clean_scan_exits_0_and_is_honest_about_coverage() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("clean.txt"), b"clean").unwrap();
    let out = run(trusted_scan()
        .arg("--signatures")
        .arg(example_db())
        .arg(dir.path()));
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Files scanned:        1"));
    assert!(text.contains("not a guarantee"));
}

#[test]
fn scan_without_signatures_warns() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("indicator.txt"), INDICATOR).unwrap();
    let out = run(bin().arg("scan").arg(dir.path()));
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("NOT evaluated"));
    assert!(String::from_utf8_lossy(&out.stdout).contains("No detectors ran"));
}

#[test]
fn missing_path_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(bin().arg("scan").arg(dir.path().join("does-not-exist")));
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn invalid_database_exits_2_without_scanning() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("bad.json");
    fs::write(
        &db,
        br#"{"format":"abyssal-warden.hash-signatures","format_version":9}"#,
    )
    .unwrap();
    let out = run(bin()
        .args(["scan", "--allow-unsigned", "--signatures"])
        .arg(&db)
        .arg(dir.path()));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unsupported"));
    assert!(out.stdout.is_empty());
}

#[test]
fn output_file_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("scan");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("f"), b"f").unwrap();
    let report = dir.path().join("report.json");
    let out = run(bin()
        .args(["scan", "--format", "json", "--output"])
        .arg(&report)
        .arg(&target));
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    let v: serde_json::Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(v["schema_version"], 1);
}

#[test]
fn hash_prints_sha256sum_format() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("indicator.txt");
    fs::write(&f, INDICATOR).unwrap();
    let out = run(bin().arg("hash").arg(&f));
    assert_eq!(out.status.code(), Some(0));
    let line = String::from_utf8(out.stdout).unwrap();
    assert!(line.starts_with("26d11a0d2767bb969011c61c58953c5d89035f8c2ca524efcafe3a9c92461eae  "));
}

#[test]
fn signatures_validate_reports_summary() {
    let out = run(bin()
        .args(["signatures", "validate", "--trusted-key"])
        .arg(test_key())
        .arg(example_db()));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("1 signature(s)"));
    assert!(text.contains("signed by key 4B646D33D8084FE3"), "{text}");
}

#[test]
fn usage_error_exits_2() {
    let out = run(bin().arg("scan"));
    assert_eq!(out.status.code(), Some(2));
}

#[cfg(target_os = "linux")]
#[test]
fn hostile_file_name_cannot_inject_terminal_escapes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(OsStr::from_bytes(b"x\x1b]0;pwned\x07\xff")),
        INDICATOR,
    )
    .unwrap();
    let out = run(trusted_scan()
        .arg("--signatures")
        .arg(example_db())
        .arg(dir.path()));
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stdout.contains(&0x1b), "raw ESC reached stdout");
    assert!(!out.stdout.contains(&0x07), "raw BEL reached stdout");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("\\u{1b}]0;pwned\\u{7}"));
    assert!(text.contains("not valid Unicode"));
}

fn copy_signed(from: &Path, to_dir: &Path) -> PathBuf {
    let name = from.file_name().unwrap();
    let dest = to_dir.join(name);
    fs::copy(from, &dest).unwrap();
    let mut sig = from.as_os_str().to_owned();
    sig.push(".minisig");
    let mut dest_sig = dest.as_os_str().to_owned();
    dest_sig.push(".minisig");
    fs::copy(PathBuf::from(sig), PathBuf::from(dest_sig)).unwrap();
    dest
}

#[test]
fn unsigned_content_is_refused_unless_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("unsigned.json");
    fs::copy(example_db(), &db).unwrap();
    let target = dir.path().join("t");
    fs::create_dir(&target).unwrap();

    let out = run(trusted_scan().arg("-s").arg(&db).arg(&target));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not signed"));

    let out = run(bin()
        .args(["scan", "--allow-unsigned", "--format", "json", "-s"])
        .arg(&db)
        .arg(&target));
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("has no signature"));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["detectors"][0]["database"]["signer"].is_null());
    assert!(
        v["warnings"][0]
            .as_str()
            .unwrap()
            .contains("without signature verification")
    );
}

#[test]
fn tampered_database_is_refused_even_with_allow_unsigned() {
    let dir = tempfile::tempdir().unwrap();
    let db = copy_signed(&example_db(), dir.path());
    let text = fs::read_to_string(&db)
        .unwrap()
        .replace("\"info\"", "\"critical\"");
    fs::write(&db, text).unwrap();
    for extra in [&[][..], &["--allow-unsigned"][..]] {
        let out = run(trusted_scan()
            .args(extra)
            .arg("-s")
            .arg(&db)
            .arg(dir.path()));
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("does not verify"));
    }
}

#[test]
fn signature_from_untrusted_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let db = copy_signed(&example_db(), dir.path());
    // No --trusted-key: RequireTrusted with an empty key set.
    let out = run(bin().arg("scan").arg("-s").arg(&db).arg(dir.path()));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no trusted keys"));
}

#[test]
fn yara_scan_detects_synthetic_marker() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("marker.txt"),
        b"ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER\n",
    )
    .unwrap();
    fs::write(dir.path().join("clean.txt"), b"clean").unwrap();
    let out = run(trusted_scan()
        .args(["--format", "json", "--yara"])
        .arg(examples().join("rules"))
        .arg("-s")
        .arg(example_db())
        .arg(dir.path()));
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = &v["findings"][0];
    assert_eq!(f["source"]["detector"], "yara-x");
    assert_eq!(f["name"], "AbyssalWarden.Test.SyntheticYaraMarker");
    assert_eq!(f["evidence"][0]["kind"], "yara_rule_match");
    assert_eq!(v["detectors"][1]["database"]["signer"], "4B646D33D8084FE3");
    assert!(
        v["warnings"].as_array().unwrap().is_empty(),
        "{}",
        v["warnings"]
    );
}

#[test]
fn yara_validate_reports_rules_and_rejects_bad_rules() {
    let out = run(bin()
        .args(["yara", "validate", "--trusted-key"])
        .arg(test_key())
        .arg(examples().join("rules/synthetic-test.yar")));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 YARA rule(s), signed by key"));

    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yar");
    fs::write(&bad, "include \"/etc/passwd\"\nrule a { condition: true }").unwrap();
    let out = run(bin()
        .args(["yara", "validate", "--allow-unsigned"])
        .arg(&bad));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("include"));
}

#[cfg(target_os = "linux")]
mod quarantine {
    use super::*;

    const PAYLOAD: &[u8] = b"harmless synthetic payload labelled as malware for testing\n";

    /// An unsigned DB that labels the synthetic payload as malware.
    fn malware_db(dir: &Path) -> PathBuf {
        let db = dir.join("malware-db.json");
        let sha = sha256_of(PAYLOAD);
        fs::write(
            &db,
            format!(
                r#"{{"format":"abyssal-warden.hash-signatures","format_version":1,
                "database":{{"name":"cli-test","version":"1"}},
                "signatures":[{{"id":"AW-CLI-MAL-1","name":"Synthetic.Malware","sha256":"{sha}",
                "category":"malware","severity":"high","rule_version":1}}]}}"#
            ),
        )
        .unwrap();
        db
    }

    fn sha256_of(data: &[u8]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        fs::write(&f, data).unwrap();
        let out = run(bin().arg("hash").arg(&f));
        String::from_utf8(out.stdout).unwrap()[..64].to_owned()
    }

    fn q(store: &Path) -> Command {
        let mut c = bin();
        c.arg("quarantine").arg("--store").arg(store);
        c
    }

    #[test]
    fn scan_quarantine_restore_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let target = base.join("target");
        fs::create_dir(&target).unwrap();
        let evil = target.join("payload.bin");
        fs::write(&evil, PAYLOAD).unwrap();
        fs::write(target.join("clean.txt"), b"clean").unwrap();
        let store = base.join("store");

        let out = run(bin()
            .args([
                "scan",
                "--allow-unsigned",
                "--format",
                "json",
                "--quarantine",
                "--quarantine-store",
            ])
            .arg(&store)
            .arg("-s")
            .arg(malware_db(&base))
            .arg(&target));
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let f = &v["findings"][0];
        assert_eq!(f["remediation_status"], "quarantined", "{f}");
        let detail = f["remediation_detail"].as_str().unwrap();
        let id = detail.trim_start_matches("quarantine ID ").to_owned();
        assert!(!evil.exists(), "file should be quarantined");

        let out = run(q(&store).arg("list"));
        assert!(String::from_utf8_lossy(&out.stdout).contains(&id));

        let out = run(q(&store).args(["restore", &id]));
        assert_eq!(out.status.code(), Some(2), "restore must require --yes");
        assert!(!evil.exists());

        let out = run(q(&store).args(["restore", &id, "--yes"]));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(fs::read(&evil).unwrap(), PAYLOAD);

        let out = run(q(&store).arg("verify-log"));
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("2 entries"));
    }

    #[test]
    fn only_confirmed_malware_is_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let target = base.join("target");
        fs::create_dir(&target).unwrap();
        // Test indicator (hash DB) and a YARA match: neither is eligible.
        fs::write(target.join("indicator.txt"), INDICATOR).unwrap();
        fs::write(
            target.join("marker.txt"),
            b"ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER",
        )
        .unwrap();
        let out = run(trusted_scan()
            .args(["--format", "json", "--quarantine", "--quarantine-store"])
            .arg(base.join("store"))
            .arg("-s")
            .arg(example_db())
            .arg("--yara")
            .arg(examples().join("rules"))
            .arg(&target));
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        for f in findings {
            assert_eq!(f["remediation_status"], "not_eligible", "{f}");
        }
        assert!(target.join("indicator.txt").exists());
        assert!(target.join("marker.txt").exists());
        assert!(
            !base.join("store").exists(),
            "store is not even created when nothing is eligible"
        );
    }

    #[test]
    fn manual_add_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let f = base.join("suspicious.bin");
        fs::write(&f, PAYLOAD).unwrap();
        let store = base.join("store");

        let out = run(q(&store)
            .arg("add")
            .arg(&f)
            .args(["--sha256", &"0".repeat(64)]));
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("changed"));
        assert!(f.exists());

        let out = run(q(&store).arg("add").arg(&f).args(["--note", "manual test"]));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        let id = text.split_whitespace().last().unwrap().to_owned();
        assert!(!f.exists());

        assert_eq!(run(q(&store).args(["delete", &id])).status.code(), Some(2));
        assert_eq!(
            run(q(&store).args(["delete", &id, "--yes"])).status.code(),
            Some(0)
        );
        let out = run(q(&store).args(["show", &id]));
        let rec: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(rec["state"], "deleted");
        assert_eq!(rec["reason"]["note"], "manual test");

        let out = run(q(&store).args(["show", "../../etc/passwd"]));
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("invalid quarantine ID"));
    }

    #[test]
    fn protected_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(q(&dir.path().join("store")).args(["add", "/etc/hostname"]));
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("protected"));
    }
}
