//! Work done off the UI thread. Standalone scans and updates run the
//! `abyssal-warden` program as a child process, exactly as the service does,
//! so the GUI never parses hostile files itself and reuses the scanner's
//! content verification unchanged. With the service, requests go over the
//! authenticated local endpoint.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;
use warden_core::ScanReport;
use warden_ipc::{JobState, Op, QuarantineItem, Reply, ScheduleInfo, ServiceStatus};

/// Largest report read from the scanner (reports list every finding).
const MAX_REPORT_BYTES: u64 = 256 << 20;
/// Most stderr lines kept for display.
const MAX_MESSAGES: usize = 200;

/// Live counts from `scan --progress-json`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) files_scanned: u64,
    pub(crate) bytes_scanned: u64,
    pub(crate) findings: u64,
    pub(crate) entries_skipped: u64,
    pub(crate) issues: u64,
}

/// What a finished update reported (`update --format json`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UpdateInfo {
    pub(crate) bundle: String,
    pub(crate) sequence: u64,
    pub(crate) changed: bool,
    pub(crate) expires: String,
}

/// Messages from background work to the UI.
#[derive(Debug)]
pub(crate) enum Event {
    Service(Result<Box<ServiceStatus>, String>),
    Progress(Progress),
    /// A job was accepted by the service.
    JobStarted(Uuid),
    ScanDone {
        result: Result<Box<ScanReport>, String>,
        messages: Vec<String>,
    },
    UpdateDone(Result<UpdateInfo, String>),
    Quarantine(Result<Vec<QuarantineItem>, String>),
    Schedules(Result<Vec<ScheduleInfo>, String>),
    /// A service request that only returns a message (restore, delete, run).
    Done(Result<String, String>),
}

/// What to scan and how.
#[derive(Clone, Debug)]
pub(crate) struct ScanRequest {
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) heuristics: bool,
    pub(crate) archives: bool,
    /// Standalone only: load content installed by `update`.
    pub(crate) installed_content: bool,
}

/// Cancels whatever is running: kills the scanner child, or asks the
/// service to cancel its job.
#[derive(Clone, Debug, Default)]
pub(crate) struct CancelHandle {
    child: Arc<Mutex<Option<Child>>>,
}

impl CancelHandle {
    pub(crate) fn cancel_local(&self) {
        if let Ok(mut guard) = self.child.lock()
            && let Some(child) = guard.as_mut()
        {
            let _ = child.kill();
        }
    }
}

/// The `abyssal-warden` program: next to this one (as installed and in
/// test builds), else found on `PATH`.
pub(crate) fn scanner_program() -> PathBuf {
    let name = format!("abyssal-warden{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join(&name)))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

pub(crate) fn endpoint() -> PathBuf {
    PathBuf::from(warden_ipc::default_endpoint())
}

fn command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: no console window flashing up for the child.
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

/// What a finished child left behind.
struct ChildOutput {
    /// `None` if it was killed.
    code: Option<i32>,
    /// Stdout, bounded by [`MAX_REPORT_BYTES`].
    stdout: Vec<u8>,
    /// Stderr lines other than progress, escaped.
    messages: Vec<String>,
}

/// Runs `cmd`, forwarding `--progress-json` lines.
fn run_child(
    mut cmd: Command,
    cancel: &CancelHandle,
    on_progress: &dyn Fn(Progress),
) -> Result<ChildOutput, String> {
    let mut child = cmd.spawn().map_err(|e| {
        format!("cannot start the scanner ({e}); is abyssal-warden installed next to this app?")
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    if let Ok(mut guard) = cancel.child.lock() {
        *guard = Some(child);
    }

    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(out) = stdout {
            let _ = out.take(MAX_REPORT_BYTES).read_to_end(&mut buf);
        }
        buf
    });
    let mut messages = Vec::new();
    if let Some(err) = stderr {
        for line in BufReader::new(err).lines() {
            let Ok(line) = line else { break };
            if let Some(p) = parse_progress(&line) {
                on_progress(p);
            } else if !line.trim().is_empty() && messages.len() < MAX_MESSAGES {
                messages.push(warden_core::text::escape_unsafe_chars(&line));
            }
        }
    }
    let stdout = out_thread.join().unwrap_or_default();
    let status = cancel
        .child
        .lock()
        .ok()
        .and_then(|mut g| g.take())
        .map(|mut c| c.wait());
    let code = match status {
        Some(Ok(s)) => s.code(),
        Some(Err(e)) => return Err(e.to_string()),
        None => None,
    };
    Ok(ChildOutput {
        code,
        stdout,
        messages,
    })
}

pub(crate) fn parse_progress(line: &str) -> Option<Progress> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("type")?.as_str()? != "progress" {
        return None;
    }
    let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    Some(Progress {
        files_scanned: n("files_scanned"),
        bytes_scanned: n("bytes_scanned"),
        findings: n("findings"),
        entries_skipped: n("entries_skipped"),
        issues: n("issues"),
    })
}

/// Arguments for a standalone scan. Paths come after `--`, so a folder
/// named like an option cannot change the scan.
pub(crate) fn scan_args(req: &ScanRequest) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = ["scan", "--format", "json", "--progress-json"]
        .iter()
        .map(Into::into)
        .collect();
    if req.heuristics {
        a.push("--heuristics".into());
    }
    if !req.archives {
        a.push("--no-archives".into());
    }
    if req.installed_content {
        a.push("--installed".into());
    }
    a.push("--".into());
    a.extend(req.paths.iter().map(|p| p.as_os_str().to_owned()));
    a
}

pub(crate) fn scan_local(
    req: ScanRequest,
    cancel: CancelHandle,
    tx: Sender<Event>,
    repaint: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || {
        let mut cmd = command(&scanner_program());
        cmd.args(scan_args(&req));
        let progress_tx = tx.clone();
        let result = run_child(cmd, &cancel, &|p| {
            let _ = progress_tx.send(Event::Progress(p));
            repaint();
        });
        let (result, messages) = match result {
            Err(e) => (Err(e), Vec::new()),
            // Exit codes: 0 clean, 1 findings, 3 incomplete; all have a report.
            Ok(ChildOutput {
                code: Some(0 | 1 | 3),
                stdout,
                messages,
            }) => (
                serde_json::from_slice::<ScanReport>(&stdout)
                    .map(Box::new)
                    .map_err(|e| format!("unreadable scan report: {e}")),
                messages,
            ),
            Ok(ChildOutput {
                code: None,
                messages,
                ..
            }) => (Err("the scan was cancelled".into()), messages),
            Ok(ChildOutput { messages, .. }) => (
                Err(messages
                    .iter()
                    .rev()
                    .find(|m| m.starts_with("error"))
                    .cloned()
                    .unwrap_or_else(|| "the scan failed".into())),
                messages,
            ),
        };
        let _ = tx.send(Event::ScanDone { result, messages });
        repaint();
    });
}

pub(crate) fn update_local(tx: Sender<Event>, repaint: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let mut cmd = command(&scanner_program());
        cmd.args(["update", "--format", "json"]);
        let result = run_child(cmd, &CancelHandle::default(), &|_| {}).and_then(|out| {
            let ChildOutput {
                code,
                stdout: out,
                messages,
            } = out;
            if code != Some(0) {
                return Err(messages
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "the update failed".into()));
            }
            let v: serde_json::Value = serde_json::from_slice(&out).map_err(|e| e.to_string())?;
            let text = |k: &str| {
                warden_core::text::escape_unsafe_chars(
                    v.get(k).and_then(serde_json::Value::as_str).unwrap_or(""),
                )
            };
            Ok(UpdateInfo {
                bundle: text("bundle"),
                sequence: v
                    .get("sequence")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                changed: v.get("changed").and_then(serde_json::Value::as_bool) == Some(true),
                expires: text("timestamp_expires"),
            })
        });
        let _ = tx.send(Event::UpdateDone(result));
        repaint();
    });
}

fn call(op: Op) -> Result<Reply, String> {
    match warden_service::client::call(&endpoint(), op)? {
        Reply::Error { code, message } => Err(format!(
            "{} ({code:?})",
            warden_core::text::escape_unsafe_chars(&message)
        )),
        other => Ok(other),
    }
}

pub(crate) fn service_status(tx: Sender<Event>, repaint: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let result = call(Op::Status {}).and_then(|r| match r {
            Reply::Status(s) => Ok(s),
            _ => Err("unexpected reply".into()),
        });
        let _ = tx.send(Event::Service(result));
        repaint();
    });
}

/// Scans through the service: submit, poll until finished, fetch the report.
pub(crate) fn scan_service(
    req: ScanRequest,
    tx: Sender<Event>,
    repaint: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || {
        let result = (|| {
            let paths = req
                .paths
                .iter()
                .map(|p| {
                    p.to_str()
                        .map(str::to_owned)
                        .ok_or("paths must be valid Unicode for the service")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let job = match call(Op::Scan {
                paths,
                heuristics: req.heuristics,
                no_archives: !req.archives,
                quarantine: false,
            })? {
                Reply::JobStarted { job } => job,
                _ => return Err("unexpected reply".into()),
            };
            let _ = tx.send(Event::JobStarted(job));
            repaint();
            loop {
                std::thread::sleep(Duration::from_millis(750));
                let Reply::Job(j) = call(Op::Job { job })? else {
                    return Err("unexpected reply".to_owned());
                };
                if j.state.finished() {
                    if j.state != JobState::Completed {
                        return Err(match j.error {
                            Some(e) => warden_core::text::escape_unsafe_chars(&e),
                            None => format!("the job ended as {:?}", j.state),
                        });
                    }
                    break;
                }
            }
            match call(Op::Report { job })? {
                Reply::Report { report, .. } => serde_json::from_value::<ScanReport>(report)
                    .map(Box::new)
                    .map_err(|e| format!("unreadable scan report: {e}")),
                _ => Err("unexpected reply".into()),
            }
        })();
        let _ = tx.send(Event::ScanDone {
            result,
            messages: Vec::new(),
        });
        repaint();
    });
}

pub(crate) fn cancel_service_job(job: Uuid) {
    std::thread::spawn(move || {
        let _ = call(Op::Cancel { job });
    });
}

pub(crate) fn quarantine_list(tx: Sender<Event>, repaint: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let result = call(Op::QuarantineList {}).and_then(|r| match r {
            Reply::Quarantine { items } => Ok(items),
            _ => Err("unexpected reply".into()),
        });
        let _ = tx.send(Event::Quarantine(result));
        repaint();
    });
}

pub(crate) fn schedules(tx: Sender<Event>, repaint: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let result = call(Op::Schedules {}).and_then(|r| match r {
            Reply::Schedules { schedules } => Ok(schedules),
            _ => Err("unexpected reply".into()),
        });
        let _ = tx.send(Event::Schedules(result));
        repaint();
    });
}

/// A service request answered with `Done` (restore, delete, run schedule).
pub(crate) fn service_action(op: Op, tx: Sender<Event>, repaint: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let result = call(op).map(|r| match r {
            Reply::Done { message } => warden_core::text::escape_unsafe_chars(&message),
            Reply::JobStarted { job } => format!("started job {job}"),
            _ => "done".to_owned(),
        });
        let _ = tx.send(Event::Done(result));
        repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_lines_are_recognised() {
        let p = parse_progress(
            r#"{"type":"progress","files_scanned":3,"bytes_scanned":10,"findings":1,"entries_skipped":0,"issues":2}"#,
        );
        assert_eq!(
            p,
            Some(Progress {
                files_scanned: 3,
                bytes_scanned: 10,
                findings: 1,
                entries_skipped: 0,
                issues: 2
            })
        );
        assert_eq!(parse_progress("warning: no content"), None);
        assert_eq!(parse_progress(r#"{"type":"other"}"#), None);
    }

    #[test]
    fn paths_come_after_the_separator() {
        let a = scan_args(&ScanRequest {
            paths: vec![PathBuf::from("--quarantine")],
            heuristics: true,
            archives: false,
            installed_content: true,
        });
        let a: Vec<String> = a.iter().map(|s| s.to_string_lossy().into_owned()).collect();
        assert_eq!(
            a,
            [
                "scan",
                "--format",
                "json",
                "--progress-json",
                "--heuristics",
                "--no-archives",
                "--installed",
                "--",
                "--quarantine"
            ]
        );
    }
}
