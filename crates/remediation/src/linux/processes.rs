//! Processes using a file that is being quarantined.
//!
//! A process "uses" the file if the file is mapped into it: its executable
//! and shared libraries appear in `/proc/<pid>/maps` with the file's device
//! and inode, even after the file is deleted. Matching is by device and
//! inode, never by path.
//!
//! Limits: interpreted scripts (a shell or Python process reading a script)
//! are not mappings and are not found. Processes the caller may not inspect
//! (other users' processes, without root) are not visible. A process can
//! start between the check and the move.

use std::path::Path;

use rustix::process::{Pid, Signal, kill_process};

/// A process that maps the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcessRef {
    pub(crate) pid: i32,
    /// Short command name (`/proc/<pid>/comm`), untrusted text.
    pub(crate) name: String,
}

/// Processes (other than this one, and never PID 1) that map the file with
/// device `dev` and inode `ino`.
pub(crate) fn processes_using(dev: u64, ino: u64) -> Vec<ProcessRef> {
    processes_using_in(Path::new("/proc"), dev, ino)
}

fn processes_using_in(proc_root: &Path, dev: u64, ino: u64) -> Vec<ProcessRef> {
    let want_dev = format!(
        "{:02x}:{:02x}",
        rustix::fs::major(dev),
        rustix::fs::minor(dev)
    );
    let own = std::process::id();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        if pid <= 1 || u32::try_from(pid).is_ok_and(|p| p == own) {
            continue;
        }
        // Unreadable maps (another user's process, or it exited): skip.
        let Ok(maps) = std::fs::read_to_string(entry.path().join("maps")) else {
            continue;
        };
        if maps_contain(&maps, &want_dev, ino) {
            let name = std::fs::read_to_string(entry.path().join("comm"))
                .map(|s| s.trim_end().to_owned())
                .unwrap_or_default();
            out.push(ProcessRef { pid, name });
        }
    }
    out.sort_by_key(|p| p.pid);
    out
}

/// True if a `/proc/<pid>/maps` text has a mapping of device `dev`
/// (`MM:mm`, hex) and inode `ino`.
fn maps_contain(maps: &str, dev: &str, ino: u64) -> bool {
    maps.lines().any(|line| {
        // address perms offset dev inode [path]
        let mut fields = line.split_whitespace();
        let (Some(_), Some(_), Some(_), Some(d), Some(i)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return false;
        };
        d.eq_ignore_ascii_case(dev) && i.parse::<u64>().is_ok_and(|i| i == ino)
    })
}

fn signal(pid: i32, sig: Signal) -> std::io::Result<()> {
    let pid = Pid::from_raw(pid).ok_or_else(|| std::io::Error::other("invalid pid"))?;
    kill_process(pid, sig).map_err(Into::into)
}

/// Processes paused (SIGSTOP) for the duration of a quarantine. Dropping the
/// guard resumes them (SIGCONT), so an error on any path leaves them
/// running as before; [`Paused::kill`] ends them instead.
pub(crate) struct Paused {
    pids: Vec<i32>,
}

impl Paused {
    /// Pause each process; returns the guard and a note per process that
    /// could not be paused.
    pub(crate) fn pause(procs: &[ProcessRef]) -> (Self, Vec<String>) {
        let mut pids = Vec::new();
        let mut problems = Vec::new();
        for p in procs {
            match signal(p.pid, Signal::STOP) {
                Ok(()) => pids.push(p.pid),
                Err(e) => problems.push(format!("could not pause PID {}: {e}", p.pid)),
            }
        }
        (Self { pids }, problems)
    }

    /// Kill the paused processes (SIGKILL). Returns a note per failure.
    pub(crate) fn kill(mut self) -> Vec<String> {
        let mut problems = Vec::new();
        for pid in std::mem::take(&mut self.pids) {
            if let Err(e) = signal(pid, Signal::KILL) {
                problems.push(format!("could not kill PID {pid}: {e}"));
                let _ = signal(pid, Signal::CONT);
            }
        }
        problems
    }
}

impl Drop for Paused {
    fn drop(&mut self) {
        for &pid in &self.pids {
            let _ = signal(pid, Signal::CONT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_lines() {
        let maps = "\
55d0c0a00000-55d0c0a02000 r--p 00000000 fd:01 1234567                    /usr/bin/sleep
7f1c2e000000-7f1c2e022000 r-xp 00000000 fd:01 7654321                    /usr/lib64/libc.so.6 (deleted)
7ffd5e1f3000-7ffd5e214000 rw-p 00000000 00:00 0                          [stack]
garbage line";
        assert!(maps_contain(maps, "fd:01", 1234567));
        assert!(maps_contain(maps, "FD:01", 7654321));
        assert!(!maps_contain(maps, "fd:02", 1234567));
        assert!(!maps_contain(maps, "fd:01", 1));
    }
}
