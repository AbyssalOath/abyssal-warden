use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::*;
use crate::{QuarantineReason, verify_audit_log};

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    work: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(dir.path()).unwrap();
    let work = base.join("work");
    fs::create_dir(&work).unwrap();
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    Env {
        root: base.join("store"),
        work,
        _dir: dir,
    }
}

fn sha(data: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(data).into())
}

fn req(path: &Path, expected: Option<Sha256Digest>) -> QuarantineRequest {
    QuarantineRequest {
        path: path.to_owned(),
        expected_sha256: expected,
        reason: QuarantineReason {
            detection_name: Some("Test.Synthetic".into()),
            ..QuarantineReason::default()
        },
        max_size: 1 << 20,
        allow_protected: false,
    }
}

fn write(path: &Path, data: &[u8], mode: u32) {
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn item_files(root: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(root.join("items"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn audit_len(root: &Path) -> u64 {
    verify_audit_log(fs::File::open(root.join("audit.log")).unwrap()).unwrap()
}

const CONTENT: &[u8] = b"synthetic quarantine test content \x7fELF not really";

#[test]
fn quarantine_and_restore_round_trip() {
    let e = env();
    let f = e.work.join("sample.bin");
    write(&f, CONTENT, 0o640);
    let mut store = QuarantineStore::open(&e.root).unwrap();

    let rec = store.quarantine(&req(&f, Some(sha(CONTENT)))).unwrap();
    assert_eq!(rec.state, ItemState::Quarantined);
    assert!(!f.exists(), "original must be removed");
    assert_eq!(rec.original.sha256, sha(CONTENT));
    assert_eq!(rec.original.mode, 0o640);

    // Stored content is inert: not the plaintext, and private.
    let data_path = e.root.join("items").join(format!("{}.data", rec.id));
    let stored = fs::read(&data_path).unwrap();
    assert!(stored.starts_with(DATA_MAGIC));
    assert!(!stored.windows(9).any(|w| w == b"synthetic"));
    assert_eq!(
        fs::metadata(&data_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&e.root).unwrap().permissions().mode() & 0o777,
        0o700
    );

    assert_eq!(store.list().unwrap().len(), 1);
    let restored = store.restore(&rec.id, None).unwrap();
    assert_eq!(restored, f);
    assert_eq!(fs::read(&f).unwrap(), CONTENT);
    assert_eq!(
        fs::metadata(&f).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let after = store.get(&rec.id).unwrap();
    assert_eq!(after.state, ItemState::Restored);
    assert!(!data_path.exists());
    assert_eq!(store.verify_audit_log().unwrap(), 2);
}

#[test]
fn changed_file_is_not_touched() {
    let e = env();
    let f = e.work.join("sample.bin");
    write(&f, CONTENT, 0o600);
    let mut store = QuarantineStore::open(&e.root).unwrap();
    let err = store
        .quarantine(&req(&f, Some(sha(b"something else"))))
        .unwrap_err();
    assert!(matches!(err, RemediationError::FileChanged { .. }), "{err}");
    assert_eq!(fs::read(&f).unwrap(), CONTENT);
    assert!(item_files(&e.root).is_empty(), "{:?}", item_files(&e.root));
    drop(store);
    assert_eq!(audit_len(&e.root), 1, "failures are audited too");
}

#[test]
fn refuses_links_special_files_and_protected_paths() {
    let e = env();
    let real_dir = e.work.join("real");
    fs::create_dir(&real_dir).unwrap();
    let target = real_dir.join("t");
    write(&target, CONTENT, 0o600);
    symlink(&real_dir, e.work.join("linkdir")).unwrap();
    symlink(&target, e.work.join("linkfile")).unwrap();
    fs::hard_link(&target, e.work.join("hard")).unwrap();
    let mut store = QuarantineStore::open(&e.root).unwrap();

    type Check = fn(&RemediationError) -> bool;
    let cases: Vec<(PathBuf, Check)> = vec![
        (e.work.join("linkdir/t"), |e| {
            matches!(e, RemediationError::SymlinkInPath(_))
        }),
        (e.work.join("linkfile"), |e| {
            matches!(e, RemediationError::SymlinkInPath(_))
        }),
        (e.work.join("hard"), |e| {
            matches!(e, RemediationError::HardLinked { links: 2, .. })
        }),
        (real_dir.clone(), |e| {
            matches!(e, RemediationError::NotRegularFile(_))
        }),
        (PathBuf::from("relative/x"), |e| {
            matches!(e, RemediationError::InvalidPath(_))
        }),
        (e.work.join("real/../real/t"), |e| {
            matches!(e, RemediationError::InvalidPath(_))
        }),
        (PathBuf::from("/etc/hostname"), |e| {
            matches!(e, RemediationError::Protected(_))
        }),
        (e.root.join("audit.log"), |e| {
            matches!(e, RemediationError::InsideStore(_))
        }),
    ];
    for (path, expected) in cases {
        let err = store.quarantine(&req(&path, None)).unwrap_err();
        assert!(expected(&err), "{}: {err}", path.display());
    }
    assert_eq!(fs::read(&target).unwrap(), CONTENT);
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn restore_never_overwrites_and_checks_the_directory() {
    let e = env();
    let f = e.work.join("sample.bin");
    write(&f, CONTENT, 0o600);
    let mut store = QuarantineStore::open(&e.root).unwrap();
    let rec = store.quarantine(&req(&f, None)).unwrap();

    write(&f, b"new legitimate file", 0o600);
    let err = store.restore(&rec.id, None).unwrap_err();
    assert!(matches!(err, RemediationError::TargetExists(_)), "{err}");
    assert_eq!(fs::read(&f).unwrap(), b"new legitimate file");

    let open_dir = e.work.join("world-writable");
    fs::create_dir(&open_dir).unwrap();
    fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).unwrap();
    let err = store.restore(&rec.id, Some(&open_dir)).unwrap_err();
    assert!(
        matches!(err, RemediationError::UnsafeTarget { .. }),
        "{err}"
    );

    let err = store
        .restore(&rec.id, Some(&e.work.join("missing")))
        .unwrap_err();
    assert!(
        matches!(err, RemediationError::UnsafeTarget { .. }),
        "{err}"
    );

    // No leftovers from the failed attempts; the item is still quarantined.
    assert_eq!(fs::read_dir(&open_dir).unwrap().count(), 0);
    assert_eq!(store.get(&rec.id).unwrap().state, ItemState::Quarantined);

    let alt = e.work.join("alt");
    fs::create_dir(&alt).unwrap();
    let restored = store.restore(&rec.id, Some(&alt)).unwrap();
    assert_eq!(restored, alt.join("sample.bin"));
    assert_eq!(fs::read(&restored).unwrap(), CONTENT);
}

#[test]
fn setuid_bits_are_not_restored() {
    let e = env();
    let f = e.work.join("suid");
    write(&f, CONTENT, 0o4755);
    let mut store = QuarantineStore::open(&e.root).unwrap();
    let rec = store.quarantine(&req(&f, None)).unwrap();
    assert_eq!(rec.original.mode, 0o4755);
    store.restore(&rec.id, None).unwrap();
    assert_eq!(
        fs::metadata(&f).unwrap().permissions().mode() & 0o7777,
        0o755
    );
    assert!(
        store
            .get(&rec.id)
            .unwrap()
            .notes
            .iter()
            .any(|n| n.contains("setuid"))
    );
}

#[test]
fn delete_is_final() {
    let e = env();
    let f = e.work.join("sample.bin");
    write(&f, CONTENT, 0o600);
    let mut store = QuarantineStore::open(&e.root).unwrap();
    let rec = store.quarantine(&req(&f, None)).unwrap();
    store.delete(&rec.id).unwrap();
    assert_eq!(store.get(&rec.id).unwrap().state, ItemState::Deleted);
    assert_eq!(item_files(&e.root), vec![format!("{}.json", rec.id)]);
    assert!(matches!(
        store.delete(&rec.id),
        Err(RemediationError::InvalidState { .. })
    ));
    assert!(matches!(
        store.restore(&rec.id, None),
        Err(RemediationError::InvalidState { .. })
    ));
    assert!(!f.exists());
}

fn crash_at(fault: Fault) -> (Env, QuarantineId, Vec<RecoveryAction>) {
    let e = env();
    let f = e.work.join("sample.bin");
    write(&f, CONTENT, 0o600);
    {
        let mut store = QuarantineStore::open(&e.root).unwrap();
        store.fault = Some(fault);
        let err = store.quarantine(&req(&f, None)).unwrap_err();
        assert!(matches!(err, RemediationError::InjectedFault));
        // Dropping the store here is the "crash": nothing is cleaned up.
    }
    let store = QuarantineStore::open(&e.root).unwrap();
    let recovered = store.recovered().to_vec();
    assert_eq!(recovered.len(), 1, "{recovered:?}");
    let id = recovered[0].id.clone();
    (e, id, recovered)
}

#[test]
fn crash_before_copy_is_committed_rolls_back() {
    let (e, id, rec) = crash_at(Fault::PendingRecordWritten);
    assert_eq!(rec[0].outcome, ItemState::RolledBack);
    assert_eq!(fs::read(e.work.join("sample.bin")).unwrap(), CONTENT);
    assert_eq!(item_files(&e.root), vec![format!("{id}.json")]);
}

#[test]
fn crash_before_original_is_removed_rolls_back() {
    let (e, id, rec) = crash_at(Fault::CopyCommitted);
    assert_eq!(rec[0].outcome, ItemState::RolledBack);
    assert_eq!(fs::read(e.work.join("sample.bin")).unwrap(), CONTENT);
    assert_eq!(item_files(&e.root), vec![format!("{id}.json")]);
}

#[test]
fn crash_after_original_is_removed_completes() {
    let (e, id, rec) = crash_at(Fault::OriginalRemoved);
    assert_eq!(rec[0].outcome, ItemState::Quarantined);
    assert!(!e.work.join("sample.bin").exists());
    let mut store = QuarantineStore::open(&e.root).unwrap();
    assert!(store.recovered().is_empty(), "recovery is idempotent");
    store.restore(&id, None).unwrap();
    assert_eq!(fs::read(e.work.join("sample.bin")).unwrap(), CONTENT);
    // quarantine error is not audited for injected faults; recover + restore are.
    assert_eq!(store.verify_audit_log().unwrap(), 2);
}

#[test]
fn store_is_exclusive_and_must_be_private() {
    let e = env();
    let store = QuarantineStore::open(&e.root).unwrap();
    assert!(matches!(
        QuarantineStore::open(&e.root),
        Err(RemediationError::StoreBusy)
    ));
    drop(store);

    fs::set_permissions(&e.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        QuarantineStore::open(&e.root),
        Err(RemediationError::StoreInsecure { .. })
    ));
    fs::set_permissions(&e.root, fs::Permissions::from_mode(0o700)).unwrap();

    let link = e.work.join("store-link");
    symlink(&e.root, &link).unwrap();
    assert!(matches!(
        QuarantineStore::open(&link),
        Err(RemediationError::StoreInsecure { .. })
    ));
}

#[test]
fn tampered_audit_log_blocks_the_store() {
    let e = env();
    let f = e.work.join("a");
    write(&f, CONTENT, 0o600);
    {
        let mut store = QuarantineStore::open(&e.root).unwrap();
        let rec = store.quarantine(&req(&f, None)).unwrap();
        store.delete(&rec.id).unwrap();
    }
    let log = e.root.join("audit.log");
    let text = fs::read_to_string(&log).unwrap();
    let first_line_end = text.find('\n').unwrap() + 1;
    fs::write(&log, &text[first_line_end..]).unwrap();
    let err = QuarantineStore::open(&e.root).unwrap_err();
    assert!(
        matches!(err, RemediationError::StoreInsecure { .. }),
        "{err}"
    );
}

#[test]
fn failed_removal_rolls_back() {
    let e = env();
    let locked = e.work.join("locked");
    fs::create_dir(&locked).unwrap();
    let f = locked.join("sample.bin");
    write(&f, CONTENT, 0o600);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
    let can_write_anyway = fs::File::create(locked.join("probe")).is_ok();
    let mut store = QuarantineStore::open(&e.root).unwrap();
    let result = store.quarantine(&req(&f, None));
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    if can_write_anyway {
        eprintln!("skipping: running with privileges that ignore directory permissions");
        return;
    }
    let err = result.unwrap_err();
    assert!(
        matches!(err, RemediationError::Io { op: "remove", .. }),
        "{err}"
    );
    assert_eq!(fs::read(&f).unwrap(), CONTENT);
    let records = store.list().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, ItemState::RolledBack);
    assert_eq!(item_files(&e.root), vec![format!("{}.json", records[0].id)]);
}

#[test]
fn non_utf8_names_round_trip() {
    use std::ffi::OsStr;
    let e = env();
    let f = e.work.join(OsStr::from_bytes(b"bad\xffname"));
    write(&f, CONTENT, 0o600);
    let mut store = QuarantineStore::open(&e.root).unwrap();
    let rec = store.quarantine(&req(&f, None)).unwrap();
    assert!(rec.original.path.is_lossy());
    assert_eq!(store.restore(&rec.id, None).unwrap(), f);
    assert_eq!(fs::read(&f).unwrap(), CONTENT);
}
