//! System checks for Abyssal Warden (Linux).
//!
//! * **Persistence inventory**: systemd units and timers, cron and anacron,
//!   `/etc/ld.so.preload`, shell startup files, environment files, XDG
//!   autostart, SSH `authorized_keys`, PAM, `rc.local` and udev rules. Every
//!   entry is listed, and heuristic rules flag the suspicious ones.
//! * **Integrity checks** of the running system: kernel module cross-view,
//!   kernel taint, hidden processes, deleted executables, and package
//!   verification with rpm or dpkg.
//!
//! Checks are read-only. Files are read through the `fsx` module, confined to the
//! inspected root, so an offline image (`root` other than `/`) is inspected
//! without its symbolic links reaching the host. Kernel and process checks
//! only apply to the running system.
//!
//! Rules and their false positives: `docs/detection/system-checks.md`.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
mod boot;
#[cfg(target_os = "linux")]
mod ctx;
#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "linux")]
mod fsx;
mod heuristics;
#[cfg(target_os = "linux")]
mod kernel;
#[cfg(target_os = "linux")]
mod packages;
#[cfg(target_os = "linux")]
mod persistence;
#[cfg(target_os = "linux")]
mod processes;
mod rules;
#[cfg(target_os = "linux")]
mod tool;
mod users;
#[cfg(windows)]
mod windows;
#[cfg_attr(not(windows), allow(dead_code))]
mod winrules;

use std::path::{Path, PathBuf};
use std::time::Duration;

use warden_core::{
    CancellationToken, CheckResult, Finding, FindingTarget, HostInfo, ObservedPath,
    PersistenceEntry, ScanIssue,
};

pub use rules::DETECTOR_ID;

/// What to check.
#[derive(Clone, Debug)]
pub struct SystemCheckOptions {
    /// Root of the system to inspect: `/` for the running system, or the
    /// mount point of an offline image.
    pub root: PathBuf,
    /// Probe every PID for processes missing from the /proc listing.
    pub hidden_processes: bool,
    /// Verify critical and referenced files with rpm/dpkg.
    pub packages: bool,
    /// Verify every installed package (slow).
    pub verify_all_packages: bool,
    /// Longest a package-manager run may take.
    pub package_timeout: Duration,
}

impl Default for SystemCheckOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/"),
            hidden_processes: true,
            packages: true,
            verify_all_packages: false,
            package_timeout: Duration::from_secs(300),
        }
    }
}

/// Everything the checks produced.
#[derive(Clone, Debug)]
pub struct SystemCheckOutcome {
    pub host: HostInfo,
    pub checks: Vec<CheckResult>,
    pub findings: Vec<Finding>,
    pub persistence: Vec<PersistenceEntry>,
    pub issues: Vec<ScanIssue>,
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SystemCheckError {
    #[error("cannot open root {path}: {source}")]
    Root {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("system checks are not implemented for this platform")]
    Unsupported,
    #[error(
        "inspecting an offline Windows installation (--root) is not supported yet; run on the live system"
    )]
    OfflineWindows,
}

/// What in-OS checks can and cannot show; included in every report.
pub const LIMITS_WARNING: &str = "System checks run inside the inspected operating system. A kernel-level \
    rootkit can hide from every view they use, so a clean result is not proof that the system is \
    clean; for a trustworthy answer, inspect the disk offline (--root) from known-good media.";

/// Effective capability bits of this process (`CapEff` in
/// `/proc/self/status`).
#[cfg(target_os = "linux")]
fn effective_caps() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .unwrap_or(0)
}

/// Whether this process can read every file: root, or holding
/// `CAP_DAC_READ_SEARCH` (the service's scanner account).
#[cfg(target_os = "linux")]
pub(crate) fn can_read_everything() -> bool {
    const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
    rustix::process::geteuid().is_root() || effective_caps() & CAP_DAC_READ_SEARCH != 0
}

/// Whether this process can inspect every process (`CAP_SYS_PTRACE`).
#[cfg(target_os = "linux")]
pub(crate) fn can_inspect_processes() -> bool {
    const CAP_SYS_PTRACE: u64 = 1 << 19;
    rustix::process::geteuid().is_root() || effective_caps() & CAP_SYS_PTRACE != 0
}

/// Runs all checks.
#[cfg(target_os = "linux")]
pub fn run_checks(
    opts: &SystemCheckOptions,
    cancel: &CancellationToken,
) -> Result<SystemCheckOutcome, SystemCheckError> {
    use warden_core::CheckStatus;

    let root = fsx::Root::open(&opts.root).map_err(|source| SystemCheckError::Root {
        path: opts.root.clone(),
        source,
    })?;
    let live = root.is_live();
    let euid = rustix::process::geteuid().as_raw();
    let mut ctx = ctx::Ctx::new(root, cancel);

    // Users whose home directories are inspected.
    let mut warnings = vec![LIMITS_WARNING.to_owned()];
    match ctx.root.read_text(Path::new("/etc/passwd")) {
        Ok(t) => {
            let all = users::parse_passwd(&t.text);
            if live && !can_read_everything() {
                ctx.users = all.into_iter().filter(|u| u.uid == euid).collect();
                ctx.users_limited = true;
            } else {
                ctx.users = all;
            }
        }
        Err(e) => warnings.push(format!(
            "cannot read /etc/passwd ({e}); user files were not inspected"
        )),
    }
    if live && !can_read_everything() {
        warnings.push(
            "not running as root: other users' files, root's crontab and other processes could not \
             all be inspected"
                .into(),
        );
    }

    let mut checks = persistence::run_all(&mut ctx);

    let proc = Path::new("/proc");
    let sys = Path::new("/sys");
    let offline =
        "not the running system (--root); inspect the kernel and processes on the live system";
    checks.push(boot::check(&mut ctx, proc, sys));
    if live {
        checks.push(processes::self_integrity(&mut ctx, proc));
        checks.push(kernel::modules(&mut ctx, proc, sys));
        checks.push(ebpf::check(&mut ctx, proc, sys, opts.package_timeout));
        checks.push(kernel::taint(&mut ctx, proc));
        checks.push(if opts.hidden_processes {
            processes::hidden(&mut ctx, proc)
        } else {
            ctx::skipped(
                "processes.hidden",
                "Hidden processes",
                CheckStatus::Skipped,
                "disabled",
            )
        });
        checks.push(processes::deleted(&mut ctx, proc));
    } else {
        for (id, title) in [
            (
                "processes.self_integrity",
                "Code injected into this scanner",
            ),
            ("kernel.modules", "Kernel module cross-view"),
            ("kernel.ebpf", "Loaded eBPF programs"),
            ("kernel.taint", "Kernel taint flags"),
            ("processes.hidden", "Hidden processes"),
            ("processes.deleted_executables", "Deleted executables"),
        ] {
            checks.push(ctx::skipped(id, title, CheckStatus::Skipped, offline));
        }
    }
    checks.push(if opts.packages {
        packages::check(
            &mut ctx,
            &packages::Options {
                verify_all: opts.verify_all_packages,
                timeout: opts.package_timeout,
            },
        )
    } else {
        ctx::skipped(
            packages::ID,
            "Package file verification",
            CheckStatus::Skipped,
            "disabled",
        )
    });

    let read_trim = |p: &Path| std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned());
    let host = HostInfo {
        os: "linux".into(),
        kernel: if live {
            read_trim(Path::new("/proc/sys/kernel/osrelease"))
        } else {
            None
        },
        hostname: if live {
            read_trim(Path::new("/proc/sys/kernel/hostname"))
        } else {
            ctx.root
                .read_text(Path::new("/etc/hostname"))
                .ok()
                .map(|t| t.text.trim().to_owned())
        },
        root: ObservedPath::from_path(&opts.root),
        live,
        euid: Some(euid),
    };
    Ok(SystemCheckOutcome {
        host,
        checks,
        findings: ctx.findings,
        persistence: ctx.persistence,
        issues: ctx.issues,
        warnings,
    })
}

#[cfg(windows)]
pub fn run_checks(
    opts: &SystemCheckOptions,
    cancel: &CancellationToken,
) -> Result<SystemCheckOutcome, SystemCheckError> {
    windows::run_checks(opts, cancel)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn run_checks(
    _opts: &SystemCheckOptions,
    _cancel: &CancellationToken,
) -> Result<SystemCheckOutcome, SystemCheckError> {
    Err(SystemCheckError::Unsupported)
}

/// A check that did not run.
#[cfg(windows)]
pub(crate) fn skipped_check(
    id: &str,
    title: &str,
    status: warden_core::CheckStatus,
    why: &str,
) -> CheckResult {
    CheckResult {
        id: id.into(),
        title: title.into(),
        status,
        examined: 0,
        detail: Some(why.into()),
    }
}

/// The host path of the regular file that `logical` (a path inside the
/// inspected system) resolves to, with links resolved inside `root`.
#[cfg(target_os = "linux")]
pub fn host_path(root: &Path, logical: &Path) -> std::io::Result<PathBuf> {
    fsx::Root::open(root)?.host_path(logical)
}

#[cfg(not(target_os = "linux"))]
pub fn host_path(_root: &Path, _logical: &Path) -> std::io::Result<PathBuf> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Findings linking persistence entries to content detections.
/// `detected` pairs the logical executable path with the content finding.
pub fn correlate(
    entries: &[PersistenceEntry],
    detected: &[(ObservedPath, &Finding)],
) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in entries {
        let Some(exe) = &e.executable else {
            continue;
        };
        for (path, f) in detected {
            if path == exe {
                out.push(rules::LAUNCHES_DETECTED.finding(
                    FindingTarget::Persistence {
                        mechanism: e.mechanism,
                        location: e.location.clone(),
                        entry: e.command.as_deref().map(heuristics::snippet),
                    },
                    format!(
                        "starts {} which {} detected as {}",
                        exe.text,
                        f.source.detector,
                        heuristics::snippet(&f.name)
                    ),
                ));
            }
        }
    }
    out
}

/// Runs every configuration parser and command pattern on `text`, which
/// may be anything an offline image contains. For fuzzing only.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn fuzz_parsers(text: &str) {
    let _ = persistence::systemd::parse_unit(text);
    let _ = persistence::files::parse_desktop(text);
    let _ = persistence::ssh::parse_keys(text);
    let _ = persistence::logical_lines(text);
    let _ = packages::parse_rpm_query(text);
    let _ = packages::parse_md5sums(text, "p");
    let _ = boot::weak_cmdline(text);
    let _ = ebpf::parse_bpftool(text);
    let _ = ebpf::parse_fdinfo(text);
    let _ = processes::injected_libraries(text, "/x");
    let _ = winrules::parse_task(text);
    let _ = winrules::parse_task(&winrules::decode_text(text.as_bytes()));
    let mut c = winrules::Collector::default();
    c.record(winrules::WinEntry {
        mechanism: warden_core::PersistenceMechanism::ScheduledTask,
        scope: warden_core::PersistenceScope::System,
        location: "x".into(),
        command: Some(text.chars().take(8192).collect()),
        enabled: None,
        detail: None,
        hidden: true,
    });
    let _ = kernel::proc_modules(text);
    let _ = users::parse_passwd(text);
    for line in text.lines().take(256) {
        let _ = persistence::cron::parse_cron_line(line, true);
        let _ = persistence::cron::parse_cron_line(line, false);
        let _ = persistence::cron::env_assignment(line);
        let _ = persistence::pam::parse_line(line, false);
        let _ = persistence::pam::parse_line(line, true);
        let _ = persistence::udev::programs(line);
        let _ = persistence::parse_modprobe_command(line);
        let _ = packages::usrmerge_alias(line);
        let _ = winrules::command_executable(line);
        let _ = winrules::classify(line);
        let _ = winrules::expand_env(line, &|n| (n.len() < 8).then(|| n.repeat(2)));
        let _ = winrules::normalize_image_path(line, r"C:\Windows");
        let _ = winrules::winlogon_modified("Userinit", line, r"C:\Windows");
        let _ = heuristics::command_indicators(line);
        let _ = heuristics::command_executable(line);
        let _ = processes::deleted_exe_reason(line);
    }
}
