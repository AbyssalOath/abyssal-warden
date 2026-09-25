//! Process checks on the running system: PIDs hidden from the /proc
//! listing, and deleted executables running from writable locations.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use warden_core::{CancellationToken, CheckResult, FindingTarget, ObservedPath};

use crate::ctx::{Ctx, Run};
use crate::heuristics::{in_temp_dir, is_hidden};
use crate::rules;

/// Highest PID probed, whatever `pid_max` says.
const PID_LIMIT: u32 = 4_194_304;

fn listed_pids(proc: &Path) -> std::io::Result<BTreeSet<u32>> {
    let mut out = BTreeSet::new();
    for e in std::fs::read_dir(proc)? {
        if let Some(pid) = e?.file_name().to_str().and_then(|n| n.parse().ok()) {
            out.insert(pid);
        }
    }
    Ok(out)
}

/// What a direct probe of `/proc/PID` finds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Probe {
    Absent,
    /// A thread of another process (reachable, but never listed).
    Thread,
    Process,
}

fn probe(proc: &Path, pid: u32) -> Probe {
    let status = proc.join(pid.to_string()).join("status");
    match std::fs::read_to_string(status) {
        Ok(s) => {
            let tgid = s
                .lines()
                .find_map(|l| l.strip_prefix("Tgid:"))
                .and_then(|v| v.trim().parse::<u32>().ok());
            if tgid == Some(pid) {
                Probe::Process
            } else {
                Probe::Thread
            }
        }
        Err(_) => Probe::Absent,
    }
}

/// PIDs that answer a direct probe as processes but are not in the listing.
/// Candidates are confirmed against a fresh listing so a process started
/// during the sweep is not reported.
pub(crate) fn find_hidden(
    listed: &BTreeSet<u32>,
    pid_max: u32,
    probe: impl Fn(u32) -> Probe + Sync,
    relist: impl Fn() -> Option<BTreeSet<u32>>,
    cancelled: impl Fn() -> bool + Sync,
) -> Vec<u32> {
    // The sweep is millions of failed opens; spread it over a few threads.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .clamp(1, 8) as u32;
    let chunk = pid_max.div_ceil(threads).max(1);
    let mut candidates: Vec<u32> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let (probe, cancelled) = (&probe, &cancelled);
                let start = t * chunk + 1;
                let end = ((t + 1) * chunk).min(pid_max);
                s.spawn(move || {
                    let mut found = Vec::new();
                    for pid in start..=end {
                        if pid % 65_536 == 0 && cancelled() {
                            break;
                        }
                        if !listed.contains(&pid) && probe(pid) == Probe::Process {
                            found.push(pid);
                        }
                    }
                    found
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    candidates.sort_unstable();
    if candidates.is_empty() {
        return candidates;
    }
    let Some(now) = relist() else {
        return Vec::new();
    };
    candidates
        .into_iter()
        .filter(|pid| !now.contains(pid) && probe(*pid) == Probe::Process)
        .collect()
}

fn process_name(proc: &Path, pid: u32) -> String {
    std::fs::read_to_string(proc.join(pid.to_string()).join("comm"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

pub(crate) fn hidden(ctx: &mut Ctx<'_>, proc: &Path) -> CheckResult {
    let mut run = Run::default();
    let listed = match listed_pids(proc) {
        Ok(l) => l,
        Err(e) => {
            ctx.io_error(&mut run, proc, &e);
            return run.finish("processes.hidden", "Hidden processes", ctx.cancel);
        }
    };
    let pid_max = std::fs::read_to_string(proc.join("sys/kernel/pid_max"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(32_768)
        .min(PID_LIMIT);
    run.examined = u64::from(pid_max);
    let cancel: &CancellationToken = ctx.cancel;
    let found = find_hidden(
        &listed,
        pid_max,
        |pid| probe(proc, pid),
        || listed_pids(proc).ok(),
        || cancel.is_cancelled(),
    );
    for pid in found {
        let name = process_name(proc, pid);
        ctx.report(
            &rules::HIDDEN_PROCESS,
            FindingTarget::Process {
                pid,
                name: name.clone(),
                exe: std::fs::read_link(proc.join(pid.to_string()).join("exe"))
                    .ok()
                    .map(|p| ObservedPath::from_path(&p)),
            },
            format!("pid {pid} ({name}) answers directly but is not listed in /proc"),
        );
    }
    if !crate::can_inspect_processes() {
        run.partial = true;
        run.notes
            .push("not running as root: processes hidden by hidepid cannot be told apart".into());
    }
    run.notes.push(format!("probed PIDs 1 to {pid_max}"));
    run.finish("processes.hidden", "Hidden processes", ctx.cancel)
}

/// Why a deleted executable at `exe` is suspicious, if it is.
pub(crate) fn deleted_exe_reason(link: &str) -> Option<String> {
    let path = link.strip_suffix(" (deleted)")?;
    if path.starts_with("/memfd:") {
        return Some("runs from an anonymous memory file (memfd), not from disk".into());
    }
    let p = Path::new(path);
    if in_temp_dir(p) {
        return Some(format!("was in temporary directory ({path})"));
    }
    if p.starts_with("/home") || p.starts_with("/root") || p.starts_with("/run/user") {
        return Some(format!("was in a home directory ({path})"));
    }
    if is_hidden(p) {
        return Some(format!("was a hidden file ({path})"));
    }
    None
}

pub(crate) fn deleted(ctx: &mut Ctx<'_>, proc: &Path) -> CheckResult {
    let mut run = Run::default();
    let listed = match listed_pids(proc) {
        Ok(l) => l,
        Err(e) => {
            ctx.io_error(&mut run, proc, &e);
            return run.finish(
                "processes.deleted_executables",
                "Deleted executables",
                ctx.cancel,
            );
        }
    };
    let mut denied = 0u64;
    for pid in listed {
        if ctx.cancelled() {
            break;
        }
        let exe: PathBuf = proc.join(pid.to_string()).join("exe");
        match std::fs::read_link(&exe) {
            Ok(link) => {
                run.examined += 1;
                let text = link.to_string_lossy();
                if let Some(reason) = deleted_exe_reason(&text) {
                    let name = process_name(proc, pid);
                    ctx.report(
                        &rules::DELETED_EXEC,
                        FindingTarget::Process {
                            pid,
                            name: name.clone(),
                            exe: Some(ObservedPath::from_path(&link)),
                        },
                        format!("pid {pid} ({name}): executable deleted; {reason}"),
                    );
                }
            }
            // Kernel threads have no executable; other users' processes are
            // not readable without privileges.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => denied += 1,
            Err(_) => {}
        }
    }
    if denied > 0 {
        run.partial = true;
        run.notes
            .push(format!("{denied} process(es) not readable; run as root"));
    }
    run.finish(
        "processes.deleted_executables",
        "Deleted executables",
        ctx.cancel,
    )
}

/// Libraries this program itself links (glibc and the Rust runtime's
/// dependencies). Anything else mapped into the process was injected.
const OWN_LIBRARIES: &[&str] = &[
    "ld-linux",
    "ld64.so",
    "ld-musl",
    "libc.so",
    "libc-",
    "libm.so",
    "libm-",
    "libgcc_s",
    "libpthread",
    "libdl.so",
    "libdl-",
    "librt.so",
    "librt-",
    "libutil",
];

/// Shared objects in `maps` (the text of `/proc/self/maps`) that are not
/// ours: neither `own_exe` nor one of [`OWN_LIBRARIES`].
pub(crate) fn injected_libraries(maps: &str, own_exe: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in maps.lines() {
        // address perms offset dev inode path
        let Some(path) = line.splitn(6, ' ').nth(5).map(str::trim) else {
            continue;
        };
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        if !path.starts_with('/') || path == own_exe {
            continue;
        }
        let base = path.rsplit('/').next().unwrap_or(path);
        let shared_object = base.contains(".so") || path.starts_with("/memfd:");
        if shared_object
            && !OWN_LIBRARIES.iter().any(|p| base.starts_with(p))
            && !out.iter().any(|o| o == path)
        {
            out.push(path.to_owned());
        }
    }
    out
}

/// Looks for code injected into this very process: the cross-view that
/// catches a user-mode rootkit even when it hides its own configuration.
pub(crate) fn self_integrity(ctx: &mut Ctx<'_>, proc: &Path) -> CheckResult {
    let mut run = Run::default();
    let maps = proc.join("self/maps");
    match std::fs::read_to_string(&maps) {
        Ok(text) => {
            run.examined = text.lines().count() as u64;
            let own = std::fs::read_link(proc.join("self/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let env: Vec<String> = ["LD_PRELOAD", "LD_AUDIT"]
                .iter()
                .filter_map(|k| {
                    std::env::var(k)
                        .ok()
                        .filter(|v| !v.is_empty())
                        .map(|v| format!("{k}={v}"))
                })
                .collect();
            for lib in injected_libraries(&text, &own) {
                let how = if env.is_empty() {
                    "not requested by this program or its environment (ld.so.preload, possibly hidden)".to_owned()
                } else {
                    format!("this process was started with {}", env.join(" "))
                };
                ctx.report(
                    &rules::INJECTED_LIBRARY,
                    FindingTarget::Process {
                        pid: std::process::id(),
                        name: "abyssal-warden".into(),
                        exe: Some(ObservedPath::from_path(Path::new(&lib))),
                    },
                    format!("{lib} is loaded into the scanner; {how}"),
                );
            }
        }
        Err(e) => ctx.io_error(&mut run, &maps, &e),
    }
    run.finish(
        "processes.self_integrity",
        "Code injected into this scanner",
        ctx.cancel,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_injected_libraries() {
        let maps = "55d0-55d1 r--p 00000000 fd:01 123   /usr/bin/abyssal-warden\n\
                    7f00-7f01 r-xp 00000000 fd:01 124   /usr/lib64/libc.so.6\n\
                    7f02-7f03 r-xp 00000000 fd:01 125   /usr/lib64/libgcc_s.so.1\n\
                    7f04-7f05 r-xp 00000000 fd:01 126   /usr/lib/libhide.so\n\
                    7f06-7f07 r--p 00001000 fd:01 126   /usr/lib/libhide.so\n\
                    7f08-7f09 r-xp 00000000 00:01 9     /memfd:x (deleted)\n\
                    7f0a-7f0b r--p 00000000 fd:01 127   /usr/lib/locale/locale-archive\n\
                    7ffc-7ffd r-xp 00000000 00:00 0     [vdso]\n\
                    7f0c-7f0d r-xp 00000000 fd:01 128   /usr/lib64/ld-linux-x86-64.so.2\n";
        assert_eq!(
            injected_libraries(maps, "/usr/bin/abyssal-warden"),
            ["/usr/lib/libhide.so", "/memfd:x"]
        );
    }

    #[test]
    fn this_test_process_is_clean() {
        // Read-only look at our own mappings. Fails only if something (a
        // sanitizer, LD_PRELOAD, or a rootkit) injects a library here.
        let maps = std::fs::read_to_string("/proc/self/maps").expect("maps");
        let own = std::fs::read_link("/proc/self/exe").expect("exe");
        if std::env::var_os("LD_PRELOAD").is_none() {
            assert!(injected_libraries(&maps, &own.to_string_lossy()).is_empty());
        }
    }

    #[test]
    fn hidden_needs_confirmation() {
        let listed: BTreeSet<u32> = [1, 2, 3].into();
        let probe = |pid| match pid {
            1..=3 | 7 | 9 => Probe::Process,
            8 => Probe::Thread,
            _ => Probe::Absent,
        };
        // 9 appears in the fresh listing (it just started): not hidden.
        let found = find_hidden(&listed, 20, probe, || Some([1, 2, 3, 9].into()), || false);
        assert_eq!(found, [7]);
        assert!(find_hidden(&listed, 20, probe, || None, || false).is_empty());
    }

    #[test]
    fn deleted_executables() {
        assert!(deleted_exe_reason("/usr/bin/foo (deleted)").is_none());
        assert!(deleted_exe_reason("/tmp/x").is_none());
        assert!(deleted_exe_reason("/tmp/x (deleted)").is_some());
        assert!(deleted_exe_reason("/dev/shm/.a (deleted)").is_some());
        assert!(deleted_exe_reason("/memfd:x (deleted)").is_some());
        assert!(deleted_exe_reason("/home/u/a.out (deleted)").is_some());
        assert!(deleted_exe_reason("/opt/.hid/x (deleted)").is_some());
    }

    #[test]
    fn real_proc_is_readable() {
        // Read-only: lists this machine's /proc and probes our own PID.
        let listed = listed_pids(Path::new("/proc")).expect("list /proc");
        assert!(listed.contains(&std::process::id()));
        assert_eq!(
            probe(Path::new("/proc"), std::process::id()),
            Probe::Process
        );
    }
}
