use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use super::processes;
use super::*;
use crate::{QuarantineReason, verify_audit_log};

/// Tests never send audit anchors to the real system log.
fn open_store(root: &Path) -> Result<QuarantineStore> {
    QuarantineStore::open_with(root, &AnchorTarget::Disabled)
}

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
        kill_processes: false,
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
    let mut store = open_store(&e.root).unwrap();

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
    let mut store = open_store(&e.root).unwrap();
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
    let mut store = open_store(&e.root).unwrap();

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
    let mut store = open_store(&e.root).unwrap();
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
    let mut store = open_store(&e.root).unwrap();
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
    let mut store = open_store(&e.root).unwrap();
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
        let mut store = open_store(&e.root).unwrap();
        store.fault = Some(fault);
        let err = store.quarantine(&req(&f, None)).unwrap_err();
        assert!(matches!(err, RemediationError::InjectedFault));
        // Dropping the store here is the "crash": nothing is cleaned up.
    }
    let store = open_store(&e.root).unwrap();
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
    let mut store = open_store(&e.root).unwrap();
    assert!(store.recovered().is_empty(), "recovery is idempotent");
    store.restore(&id, None).unwrap();
    assert_eq!(fs::read(e.work.join("sample.bin")).unwrap(), CONTENT);
    // quarantine error is not audited for injected faults; recover + restore are.
    assert_eq!(store.verify_audit_log().unwrap(), 2);
}

#[test]
fn store_is_exclusive_and_must_be_private() {
    let e = env();
    let store = open_store(&e.root).unwrap();
    assert!(matches!(
        open_store(&e.root),
        Err(RemediationError::StoreBusy)
    ));
    drop(store);

    fs::set_permissions(&e.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        open_store(&e.root),
        Err(RemediationError::StoreInsecure { .. })
    ));
    fs::set_permissions(&e.root, fs::Permissions::from_mode(0o700)).unwrap();

    let link = e.work.join("store-link");
    symlink(&e.root, &link).unwrap();
    assert!(matches!(
        open_store(&link),
        Err(RemediationError::StoreInsecure { .. })
    ));
}

#[test]
fn tampered_audit_log_blocks_the_store() {
    let e = env();
    let f = e.work.join("a");
    write(&f, CONTENT, 0o600);
    {
        let mut store = open_store(&e.root).unwrap();
        let rec = store.quarantine(&req(&f, None)).unwrap();
        store.delete(&rec.id).unwrap();
    }
    let log = e.root.join("audit.log");
    let text = fs::read_to_string(&log).unwrap();
    let first_line_end = text.find('\n').unwrap() + 1;
    fs::write(&log, &text[first_line_end..]).unwrap();
    let err = open_store(&e.root).unwrap_err();
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
    let mut store = open_store(&e.root).unwrap();
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
    let mut store = open_store(&e.root).unwrap();
    let rec = store.quarantine(&req(&f, None)).unwrap();
    assert!(rec.original.path.is_lossy());
    assert_eq!(store.restore(&rec.id, None).unwrap(), f);
    assert_eq!(fs::read(&f).unwrap(), CONTENT);
}

#[test]
fn audit_entries_are_anchored_to_syslog() {
    use std::os::unix::net::UnixDatagram;
    let e = env();
    let sock_path = e.work.join("log.sock");
    let sock = UnixDatagram::bind(&sock_path).unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let f = e.work.join("sample.bin");
    write(&f, CONTENT, 0o600);

    let mut store =
        QuarantineStore::open_with(&e.root, &AnchorTarget::Socket(sock_path.clone())).unwrap();
    store.quarantine(&req(&f, None)).unwrap();
    let mut buf = [0u8; 512];
    let n = sock.recv(&mut buf).unwrap();
    let msg = std::str::from_utf8(&buf[..n]).unwrap();
    let (seq, head) = store.audit_head();
    assert_eq!(seq, 1);
    assert_eq!(head.len(), 64);
    assert!(msg.starts_with("<85>abyssal-warden["), "{msg}");
    assert!(
        msg.ends_with(&format!(
            "audit seq=1 hash={head} chain={} action=quarantine outcome=ok",
            &head[..16]
        )),
        "{msg}"
    );
    assert!(!store.anchor_failed());
    // What the log received matches the store's own chain.
    let anchor = crate::parse_anchor(msg).unwrap();
    assert_eq!(store.chain_id().as_deref(), Some(&head[..16]));
    let chain = store.audit_chain().unwrap();
    let cmp = crate::compare_anchors(&chain, &[anchor]);
    assert!(cmp.consistent());
    assert_eq!((cmp.entries, cmp.matched), (1, 1));

    // An unreachable anchor is reported, not fatal.
    let mut store2 = {
        drop(store);
        QuarantineStore::open_with(&e.root, &AnchorTarget::Socket(e.work.join("missing.sock")))
            .unwrap()
    };
    let g = e.work.join("second.bin");
    write(&g, b"second", 0o600);
    store2.quarantine(&req(&g, None)).unwrap();
    assert!(store2.anchor_failed());
}

/// Copy `sleep` into the test directory and run it, so the test owns a
/// process executing a file it can quarantine. `None` if that is not
/// possible here (e.g. the temporary directory is mounted noexec).
fn running_copy_of_sleep(e: &Env) -> Option<(PathBuf, std::process::Child)> {
    let sleep = ["/usr/bin/sleep", "/bin/sleep"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())?;
    let exe = e.work.join("fake-malware");
    fs::copy(sleep, &exe).ok()?;
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).ok()?;
    let child = std::process::Command::new(&exe).arg("30").spawn().ok()?;
    // Wait until the new process image is mapped.
    let st = fs::metadata(&exe).ok()?;
    for _ in 0..200 {
        use std::os::unix::fs::MetadataExt;
        if processes::processes_using(st.dev(), st.ino())
            .iter()
            .any(|p| u32::try_from(p.pid).ok() == Some(child.id()))
        {
            return Some((exe, child));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    None
}

#[test]
fn kill_processes_stops_the_running_file() {
    let e = env();
    let Some((exe, mut child)) = running_copy_of_sleep(&e) else {
        eprintln!("skipping: cannot execute a copied binary here");
        return;
    };
    let mut store = open_store(&e.root).unwrap();
    let mut r = req(&exe, None);
    r.kill_processes = true;
    let rec = store.quarantine(&r).unwrap();
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9), "{status:?}");
    assert!(
        rec.notes.iter().any(|n| n.contains("killed process")),
        "{:?}",
        rec.notes
    );
    assert!(!exe.exists());
}

#[test]
fn running_processes_are_reported_but_not_stopped_by_default() {
    let e = env();
    let Some((exe, mut child)) = running_copy_of_sleep(&e) else {
        return;
    };
    let mut store = open_store(&e.root).unwrap();
    let rec = store.quarantine(&req(&exe, None)).unwrap();
    assert!(
        rec.notes.iter().any(|n| n.contains("still running")),
        "{:?}",
        rec.notes
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "the process must not be touched"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn failed_quarantine_resumes_paused_processes() {
    let e = env();
    let Some((exe, mut child)) = running_copy_of_sleep(&e) else {
        return;
    };
    let mut store = open_store(&e.root).unwrap();
    let mut r = req(&exe, Some(sha(b"something else")));
    r.kill_processes = true;
    assert!(matches!(
        store.quarantine(&r),
        Err(RemediationError::FileChanged { .. })
    ));
    // Resumed: the process is running (state R or S), not stopped (T).
    let stat = fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
    let state = stat
        .rsplit(')')
        .next()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    assert_ne!(state, "T", "process left stopped: {stat}");
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn allow_list_add_remove_and_read_only_access() {
    let e = env();
    let mut store = open_store(&e.root).unwrap();
    let digest = sha(b"keep me");
    store
        .allow(digest, "restored from quarantine", None, Some("Test.X"))
        .unwrap();
    store.allow(digest, "again", None, None).unwrap(); // no duplicate
    assert_eq!(store.allowlist().unwrap().len(), 1);
    let listed = crate::read_allowlist(&e.root).unwrap();
    assert_eq!(listed[0].sha256, digest);
    assert!(store.disallow(digest).unwrap());
    assert!(!store.disallow(digest).unwrap());
    assert!(crate::read_allowlist(&e.root).unwrap().is_empty());
    assert!(
        crate::read_allowlist(&e.work.join("no-store"))
            .unwrap()
            .is_empty()
    );
    // Two allows and one effective disallow; removing an absent entry
    // changes nothing and is not logged.
    assert_eq!(store.verify_audit_log().unwrap(), 3);
}
