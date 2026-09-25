//! Windows store tests (run by the Windows CI job).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use warden_core::Sha256Digest;

use super::{AnchorTarget, Fault, QuarantineStore};
use crate::{ItemState, QuarantineReason, QuarantineRequest, RemediationError};

const CONTENT: &[u8] = b"synthetic quarantine test content\n";

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    work: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(dir.path()).unwrap();
    let base = PathBuf::from(super::norm(&base));
    let work = base.join("work");
    std::fs::create_dir(&work).unwrap();
    Env {
        root: base.join("store"),
        work,
        _dir: dir,
    }
}

fn open(e: &Env) -> QuarantineStore {
    QuarantineStore::open_with(&e.root, &AnchorTarget::Disabled).unwrap()
}

fn sha(data: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(data).into())
}

fn req(path: &Path, expected: Option<Sha256Digest>) -> QuarantineRequest {
    QuarantineRequest {
        path: path.to_owned(),
        expected_sha256: expected,
        reason: QuarantineReason::default(),
        max_size: 1 << 20,
        allow_protected: false,
        kill_processes: false,
    }
}

#[test]
fn quarantine_restore_delete_round_trip() {
    let e = env();
    let mut store = open(&e);
    let f = e.work.join("sample.bin");
    std::fs::write(&f, CONTENT).unwrap();
    let rec = store.quarantine(&req(&f, Some(sha(CONTENT)))).unwrap();
    assert_eq!(rec.state, ItemState::Quarantined);
    assert!(!f.exists());
    let stored = std::fs::read(e.root.join("items").join(format!("{}.data", rec.id))).unwrap();
    assert!(
        !stored.windows(CONTENT.len()).any(|w| w == CONTENT),
        "stored content is encoded"
    );
    assert_eq!(store.restore(&rec.id, None).unwrap(), f);
    assert_eq!(std::fs::read(&f).unwrap(), CONTENT);

    let g = e.work.join("second.bin");
    std::fs::write(&g, b"second").unwrap();
    let rec2 = store.quarantine(&req(&g, None)).unwrap();
    store.delete(&rec2.id).unwrap();
    assert_eq!(store.get(&rec2.id).unwrap().state, ItemState::Deleted);
    assert_eq!(store.verify_audit_log().unwrap(), 4);
    let log = std::fs::read_to_string(e.root.join("audit.log")).unwrap();
    assert!(log.contains("\"actor_sid\":\"S-1-"));
}

#[test]
fn changed_locked_and_linked_files_are_left_alone() {
    let e = env();
    let mut store = open(&e);
    let f = e.work.join("x.bin");
    std::fs::write(&f, CONTENT).unwrap();
    let err = store.quarantine(&req(&f, Some(sha(b"other")))).unwrap_err();
    assert!(matches!(err, RemediationError::FileChanged { .. }), "{err}");
    assert_eq!(std::fs::read(&f).unwrap(), CONTENT);

    // Opened by another program without sharing.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&f)
        .unwrap();
    let err = store.quarantine(&req(&f, None)).unwrap_err();
    assert!(matches!(err, RemediationError::InUse(_)), "{err}");
    drop(held);
    assert_eq!(std::fs::read(&f).unwrap(), CONTENT);

    // A junction anywhere in the path is refused.
    let real = e.work.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("y.bin"), CONTENT).unwrap();
    let link = e.work.join("link");
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&real)
        .output();
    if made.is_ok_and(|o| o.status.success()) {
        let err = store
            .quarantine(&req(&link.join("y.bin"), None))
            .unwrap_err();
        assert!(matches!(err, RemediationError::SymlinkInPath(_)), "{err}");
        assert!(real.join("y.bin").exists());
    }
    // Hard links are refused.
    let h = e.work.join("hard.bin");
    std::fs::hard_link(&f, &h).unwrap();
    assert!(matches!(
        store.quarantine(&req(&f, None)).unwrap_err(),
        RemediationError::HardLinked { .. }
    ));
    // Nothing inside the store.
    let inside = e.root.join("audit.log");
    assert!(matches!(
        store.quarantine(&req(&inside, None)).unwrap_err(),
        RemediationError::InsideStore(_)
    ));
}

#[test]
fn restore_never_overwrites_or_writes_where_others_can() {
    let e = env();
    let mut store = open(&e);
    let f = e.work.join("x.bin");
    std::fs::write(&f, CONTENT).unwrap();
    let rec = store.quarantine(&req(&f, None)).unwrap();
    std::fs::write(&f, b"new file").unwrap();
    assert!(matches!(
        store.restore(&rec.id, None).unwrap_err(),
        RemediationError::TargetExists(_)
    ));
    assert_eq!(std::fs::read(&f).unwrap(), b"new file");

    let open_dir = e.work.join("everyone");
    std::fs::create_dir(&open_dir).unwrap();
    let granted = Command::new("icacls")
        .arg(&open_dir)
        .args(["/grant", "*S-1-1-0:(OI)(CI)M"])
        .output();
    if granted.is_ok_and(|o| o.status.success()) {
        let err = store.restore(&rec.id, Some(&open_dir)).unwrap_err();
        assert!(
            matches!(err, RemediationError::UnsafeTarget { .. }),
            "{err}"
        );
    }
    let own = e.work.join("mine");
    std::fs::create_dir(&own).unwrap();
    let _ = Command::new("icacls")
        .arg(&own)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!(
            "*{}:(OI)(CI)F",
            warden_winsec::process_user_sid().unwrap()
        ))
        .output();
    assert_eq!(
        store.restore(&rec.id, Some(&own)).unwrap(),
        own.join("x.bin")
    );
}

#[test]
fn insecure_or_busy_stores_are_refused() {
    let e = env();
    drop(open(&e));
    {
        let _first = open(&e);
        assert!(matches!(
            QuarantineStore::open_with(&e.root, &AnchorTarget::Disabled).unwrap_err(),
            RemediationError::StoreBusy
        ));
    }
    let granted = Command::new("icacls")
        .arg(&e.root)
        .args(["/grant", "*S-1-5-32-545:(R)"])
        .output();
    if granted.is_ok_and(|o| o.status.success()) {
        let err = QuarantineStore::open_with(&e.root, &AnchorTarget::Disabled).unwrap_err();
        assert!(
            matches!(err, RemediationError::StoreInsecure { .. }),
            "{err}"
        );
    }
}

#[test]
fn interrupted_operations_are_recovered() {
    let e = env();
    let f = e.work.join("x.bin");
    for (fault, expected, original_left) in [
        (Fault::PendingRecordWritten, ItemState::RolledBack, true),
        (Fault::CopyCommitted, ItemState::RolledBack, true),
        (Fault::OriginalRemoved, ItemState::Quarantined, false),
    ] {
        std::fs::write(&f, CONTENT).unwrap();
        let mut store = open(&e);
        store.fault = Some(fault);
        assert!(matches!(
            store.quarantine(&req(&f, None)).unwrap_err(),
            RemediationError::InjectedFault
        ));
        drop(store);
        let store = open(&e);
        let action = store.recovered().last().expect("recovered").clone();
        assert_eq!(action.outcome, expected, "{fault:?}");
        assert_eq!(f.exists(), original_left, "{fault:?}");
        let _ = std::fs::remove_file(&f);
    }
}

#[test]
fn running_programs_are_reported_or_stopped() {
    let e = env();
    let Some(sysroot) = std::env::var_os("SystemRoot") else {
        return;
    };
    let exe = e.work.join("aw-test-ping.exe");
    if std::fs::copy(PathBuf::from(sysroot).join(r"System32\PING.EXE"), &exe).is_err() {
        return;
    }
    let mut child = Command::new(&exe)
        .args(["-n", "60", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut store = open(&e);
    let err = store.quarantine(&req(&exe, None)).unwrap_err();
    assert!(matches!(err, RemediationError::InUse(_)), "{err}");
    assert!(exe.exists(), "rolled back");
    let mut kill = req(&exe, None);
    kill.kill_processes = true;
    let rec = store.quarantine(&kill).unwrap();
    assert!(
        rec.notes.iter().any(|n| n.contains("killed")),
        "{:?}",
        rec.notes
    );
    assert!(!exe.exists());
    let status = child.wait().unwrap();
    assert!(!status.success());
    let mut out = std::io::sink();
    let _ = writeln!(out);
}
