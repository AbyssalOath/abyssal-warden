//! Running scanner children with reduced privileges.
//!
//! Scans run in a separate process, never in the service: parsers of
//! untrusted content (YARA-X, ZIP, PE/ELF) then run without the service's
//! privileges, and a job that hangs (for example on a stuck network read)
//! is killed rather than leaking a thread.
//!
//! When the service runs as root, the child is started through util-linux
//! `setpriv`, which switches identity before `exec` without any unsafe code
//! here:
//!
//! * privileged jobs run as the scanner account with **only**
//!   `CAP_DAC_READ_SEARCH` (read any file, write nothing it does not own),
//!   plus `CAP_SYS_PTRACE` for system checks, in the ambient, inheritable
//!   and bounding sets, with `no_new_privs`;
//! * jobs requested by non-administrators run as the requesting user with
//!   their groups and no capabilities, so the kernel enforces that they
//!   scan only what they can read.
//!
//! Children get their own process group, a minimal environment, `/` as
//! working directory, bounded output and a deadline.

use std::ffi::OsString;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Who a child runs as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Identity {
    /// The service's own identity (only when the service is not root).
    Inherit,
    /// A service account with only the listed capabilities.
    Account {
        uid: u32,
        gid: u32,
        caps: &'static [&'static str],
    },
    /// A local user, with their groups and no capabilities.
    User { uid: u32, gid: u32 },
}

pub(crate) const SCAN_CAPS: &[&str] = &["dac_read_search"];
pub(crate) const SYSTEM_CHECK_CAPS: &[&str] = &["dac_read_search", "sys_ptrace"];

/// `setpriv` arguments for `identity`, ending with `--`.
pub(crate) fn setpriv_args(identity: &Identity) -> Vec<OsString> {
    let caps = |list: &[&str]| {
        let mut s = String::from("-all");
        for c in list {
            s.push_str(",+");
            s.push_str(c);
        }
        s
    };
    let mut a: Vec<String> = Vec::new();
    match identity {
        Identity::Inherit => return Vec::new(),
        Identity::Account {
            uid,
            gid,
            caps: list,
        } => {
            a.extend([
                format!("--reuid={uid}"),
                format!("--regid={gid}"),
                "--clear-groups".into(),
            ]);
            a.push(format!("--inh-caps={}", caps(list)));
            if !list.is_empty() {
                a.push(format!("--ambient-caps={}", caps(list)));
            }
            a.push(format!("--bounding-set={}", caps(list)));
        }
        Identity::User { uid, gid } => {
            a.extend([
                format!("--reuid={uid}"),
                format!("--regid={gid}"),
                "--init-groups".into(),
            ]);
            a.push("--inh-caps=-all".into());
            a.push("--bounding-set=-all".into());
        }
    }
    a.push("--no-new-privs".into());
    a.push("--".into());
    a.into_iter().map(OsString::from).collect()
}

/// The command for `binary args` as `identity`. `setpriv` is required for
/// any identity other than [`Identity::Inherit`].
pub(crate) fn command(
    setpriv: Option<&Path>,
    binary: &Path,
    identity: &Identity,
    args: &[OsString],
) -> Result<Command, String> {
    let mut cmd = match (identity, setpriv) {
        (Identity::Inherit, _) => Command::new(binary),
        (_, Some(sp)) => {
            let mut c = Command::new(sp);
            c.args(setpriv_args(identity)).arg(binary);
            c
        }
        (_, None) => return Err("changing identity needs setpriv (util-linux)".into()),
    };
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        // Children never quarantine, so they never write audit anchors.
        .env("ABYSSAL_WARDEN_SYSLOG_SOCKET", "")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    Ok(cmd)
}

#[derive(Debug, Default)]
pub(crate) struct Outcome {
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_tail: String,
    pub(crate) timed_out: bool,
    pub(crate) cancelled: bool,
}

const STDERR_TAIL: usize = 4096;

/// Runs `cmd` until it exits, `timeout` passes or `cancel` is set (then the
/// whole process group is killed).
pub(crate) fn run(
    mut cmd: Command,
    timeout: Duration,
    cancel: &AtomicBool,
    max_stdout: usize,
) -> Result<Outcome, String> {
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start scanner: {e}"))?;
    let pgid = rustix::process::Pid::from_child(&child);
    let (Some(mut out), Some(mut err)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        return Err("scanner pipes unavailable".into());
    };
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut out).take(max_stdout as u64 + 1).read_to_end(&mut buf);
        let _ = std::io::copy(&mut out, &mut std::io::sink());
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut tail: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n) = err.read(&mut chunk) {
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&chunk[..n]);
            if tail.len() > STDERR_TAIL {
                tail.drain(..tail.len() - STDERR_TAIL);
            }
        }
        String::from_utf8_lossy(&tail).into_owned()
    });
    let deadline = Instant::now() + timeout;
    let mut outcome = Outcome::default();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                let expired = Instant::now() >= deadline;
                if expired || cancel.load(Ordering::SeqCst) {
                    outcome.timed_out = expired;
                    outcome.cancelled = !expired;
                    let _ =
                        rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
                    let _ = child.kill();
                    break child.wait().map_err(|e| e.to_string())?;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    outcome.exit_code = status.code();
    let mut stdout = out_thread.join().unwrap_or_default();
    if stdout.len() > max_stdout {
        stdout.truncate(max_stdout);
        outcome.stdout_truncated = true;
    }
    outcome.stdout = stdout;
    outcome.stderr_tail = err_thread.join().unwrap_or_default();
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: Vec<OsString>) -> Vec<String> {
        v.into_iter()
            .map(|s| s.into_string().unwrap_or_default())
            .collect()
    }

    #[test]
    fn setpriv_arguments() {
        assert!(setpriv_args(&Identity::Inherit).is_empty());
        assert_eq!(
            strs(setpriv_args(&Identity::Account {
                uid: 990,
                gid: 990,
                caps: SCAN_CAPS
            })),
            [
                "--reuid=990",
                "--regid=990",
                "--clear-groups",
                "--inh-caps=-all,+dac_read_search",
                "--ambient-caps=-all,+dac_read_search",
                "--bounding-set=-all,+dac_read_search",
                "--no-new-privs",
                "--"
            ]
        );
        assert_eq!(
            strs(setpriv_args(&Identity::User {
                uid: 1000,
                gid: 1000
            })),
            [
                "--reuid=1000",
                "--regid=1000",
                "--init-groups",
                "--inh-caps=-all",
                "--bounding-set=-all",
                "--no-new-privs",
                "--"
            ]
        );
    }

    #[test]
    fn runs_times_out_and_cancels() {
        let never = AtomicBool::new(false);
        let echo = command(
            None,
            Path::new("/bin/sh"),
            &Identity::Inherit,
            &["-c".into(), "echo out; echo err >&2; exit 3".into()],
        )
        .expect("cmd");
        let o = run(echo, Duration::from_secs(10), &never, 1024).expect("run");
        assert_eq!(
            (o.exit_code, o.stdout.as_slice(), o.stderr_tail.trim()),
            (Some(3), &b"out\n"[..], "err")
        );

        // A child and its grandchild are both killed at the deadline.
        let slow = command(
            None,
            Path::new("/bin/sh"),
            &Identity::Inherit,
            &["-c".into(), "sleep 30 & sleep 30".into()],
        )
        .expect("cmd");
        let start = Instant::now();
        let o = run(slow, Duration::from_millis(300), &never, 1024).expect("run");
        assert!(o.timed_out && start.elapsed() < Duration::from_secs(5));

        let cancel = AtomicBool::new(true);
        let o = run(
            command(
                None,
                Path::new("/bin/sleep"),
                &Identity::Inherit,
                &["30".into()],
            )
            .expect("cmd"),
            Duration::from_secs(30),
            &cancel,
            16,
        )
        .expect("run");
        assert!(o.cancelled);

        let big = command(
            None,
            Path::new("/bin/sh"),
            &Identity::Inherit,
            &["-c".into(), "head -c 100000 /dev/zero".into()],
        )
        .expect("cmd");
        let o = run(big, Duration::from_secs(10), &never, 1000).expect("run");
        assert!(o.stdout_truncated && o.stdout.len() == 1000);
        assert!(
            command(
                None,
                Path::new("/bin/true"),
                &Identity::User { uid: 1, gid: 1 },
                &[]
            )
            .is_err()
        );
    }

    /// Proves the privilege drop for real, without root: in a user
    /// namespace with subordinate ids, a child run as another uid with only
    /// CAP_DAC_READ_SEARCH can read a file it does not own but not write it.
    /// Skipped where unprivileged user namespaces or setpriv are missing.
    #[test]
    fn setpriv_drops_to_read_only_access() {
        let script = r#"
set -e
d=$(mktemp -d); echo secret > "$d/f"; chown 2:2 "$d/f"; chmod 600 "$d/f"; chmod 755 "$d"
run() { setpriv "$@" -- /bin/sh -c "$CMD" 2>/dev/null && echo yes || echo no; }
CMD="cat $d/f >/dev/null"; export CMD
echo "read_with=$(run $ACCOUNT)"
echo "read_user=$(run $USERARGS)"
CMD="echo x >> $d/f"; echo "write_with=$(run $ACCOUNT)"
CMD="grep ^CapEff: /proc/self/status | tr -d '\t'"; setpriv $ACCOUNT -- /bin/sh -c "$CMD"
rm -rf "$d"
"#;
        let account = setpriv_args(&Identity::Account {
            uid: 1,
            gid: 1,
            caps: SCAN_CAPS,
        });
        let user = setpriv_args(&Identity::Account {
            uid: 1,
            gid: 1,
            caps: &[],
        });
        let join = |v: Vec<OsString>| {
            strs(v)
                .into_iter()
                .filter(|a| a != "--")
                .collect::<Vec<_>>()
                .join(" ")
        };
        let out = Command::new("unshare")
            .args(["--map-auto", "--map-root-user", "/bin/sh", "-c", script])
            .env("ACCOUNT", join(account))
            .env("USERARGS", join(user))
            .output();
        let Ok(out) = out else {
            eprintln!("skipped: unshare not available");
            return;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() || !text.contains("read_with=") {
            eprintln!(
                "skipped: user namespaces with subordinate ids unavailable ({})",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return;
        }
        assert!(text.contains("read_with=yes"), "{text}");
        assert!(text.contains("read_user=no"), "{text}");
        assert!(text.contains("write_with=no"), "{text}");
        assert!(text.contains("CapEff:0000000000000004"), "{text}");
    }
}
