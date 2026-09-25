//! Running external programs (rpm, bpftool) defensively: fixed absolute
//! paths, an empty environment, a deadline and bounded output.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use warden_core::CancellationToken;

/// Most output kept from one run.
const MAX_OUTPUT: usize = 128 << 20;

/// Runs `program` with `args`, a clean environment and a deadline; returns
/// stdout (lossy UTF-8, bounded). A non-zero exit is not an error: the
/// verifiers exit non-zero when they find differences.
pub(crate) fn run(
    program: &Path,
    args: &[String],
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<String, String> {
    let name = program.display();
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .current_dir("/")
        .spawn()
        .map_err(|e| format!("could not run {name}: {e}"))?;
    let Some(mut stdout) = child.stdout.take() else {
        return Err(format!("{name}: no output pipe"));
    };
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(MAX_OUTPUT as u64).read_to_end(&mut buf);
        // Drain the rest so the child is not blocked on a full pipe.
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        buf
    });
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline || cancel.is_cancelled() => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(if cancel.is_cancelled() {
                    format!("{name}: cancelled")
                } else {
                    format!("{name} did not finish within {} s", timeout.as_secs())
                });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("{name}: {e}")),
        }
    }
    let buf = reader
        .join()
        .map_err(|_| format!("{name}: output reader failed"))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_and_output() {
        let cancel = CancellationToken::new();
        let out = run(
            Path::new("/bin/echo"),
            &["hi".into()],
            Duration::from_secs(10),
            &cancel,
        );
        assert_eq!(out.as_deref(), Ok("hi\n"));
        let slow = run(
            Path::new("/bin/sleep"),
            &["5".into()],
            Duration::from_millis(200),
            &cancel,
        );
        assert!(slow.is_err_and(|e| e.contains("did not finish")));
        assert!(
            run(
                Path::new("/nonexistent/tool"),
                &[],
                Duration::from_secs(1),
                &cancel
            )
            .is_err()
        );
    }
}
