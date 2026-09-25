//! `abyssal-warden service ...`: talk to the local service
//! (`abyssal-wardend`) over its socket.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use uuid::Uuid;
use warden_core::{ScanReport, SystemReport};
use warden_ipc::{JobKind, JobState, JobSummary, Op, Reply};

use crate::output::{label, render_human, render_system, sanitize};
use crate::{EXIT_ERROR, Format};

#[derive(Args, Debug)]
pub(crate) struct ServiceArgs {
    /// Service endpoint [default: /run/abyssal-warden/wardend.sock, or
    /// \\.\pipe\AbyssalWarden on Windows, or $ABYSSAL_WARDEN_SOCKET].
    #[arg(long, value_name = "PATH", global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Subcommand, Debug)]
enum ServiceCommand {
    /// Show the service's state and your role.
    Status,
    /// Ask the service to scan paths. Without administrator rights the scan
    /// runs with your own permissions.
    Scan {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long)]
        heuristics: bool,
        #[arg(long)]
        no_archives: bool,
        /// Quarantine confirmed malware (administrators).
        #[arg(long)]
        quarantine: bool,
        #[command(flatten)]
        wait: WaitArgs,
    },
    /// Run a system check with the service's privileges (administrators).
    SystemCheck {
        #[arg(long)]
        heuristics: bool,
        #[command(flatten)]
        wait: WaitArgs,
    },
    /// List jobs (yours, or all for administrators).
    Jobs,
    /// Show one job.
    Job { id: Uuid },
    /// Print a finished job's report.
    Report {
        id: Uuid,
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
    /// Cancel a queued or running job.
    Cancel { id: Uuid },
    /// List schedules and when they run next.
    Schedules,
    /// Start a schedule now (administrators).
    RunSchedule {
        name: String,
        #[command(flatten)]
        wait: WaitArgs,
    },
    /// The service's quarantine store (administrators).
    #[command(subcommand)]
    Quarantine(QuarantineOp),
    /// Compare the quarantine audit log with the system journal
    /// (administrators).
    VerifyAudit,
}

#[derive(Subcommand, Debug)]
enum QuarantineOp {
    List,
    Restore {
        id: String,
        /// Do not allow-list the restored content.
        #[arg(long)]
        no_allow: bool,
    },
    Delete {
        id: String,
        /// Confirm permanent deletion.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Args, Debug)]
struct WaitArgs {
    /// Wait for the job and print its report; the exit status is then that
    /// of a local scan or system check.
    #[arg(long)]
    wait: bool,
    /// Report format with --wait.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
}

pub(crate) fn run(args: ServiceArgs) -> ExitCode {
    match run_inner(args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {}", sanitize(&e));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn call(_socket: &std::path::Path, _op: Op) -> Result<Reply, String> {
    Err("the service is only available on Linux so far".into())
}

#[cfg(any(unix, windows))]
fn call(socket: &std::path::Path, op: Op) -> Result<Reply, String> {
    match warden_service::client::call(socket, op)? {
        Reply::Error { code, message } => Err(format!("{} ({})", message, label(&code))),
        r => Ok(r),
    }
}

fn socket(args: &ServiceArgs) -> PathBuf {
    args.socket
        .clone()
        .or_else(|| std::env::var_os("ABYSSAL_WARDEN_SOCKET").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(warden_ipc::default_endpoint()))
}

fn absolute(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    paths
        .iter()
        .map(|p| {
            let abs = std::path::absolute(p).map_err(|e| format!("{}: {e}", p.display()))?;
            abs.to_str().map(str::to_owned).ok_or_else(|| {
                format!(
                    "{}: paths must be valid UTF-8 to send to the service",
                    abs.display()
                )
            })
        })
        .collect()
}

fn run_inner(args: ServiceArgs) -> Result<u8, String> {
    let sock = socket(&args);
    let started = |reply: Reply, wait: &WaitArgs| -> Result<u8, String> {
        let Reply::JobStarted { job } = reply else {
            return Err("unexpected reply".into());
        };
        if !wait.wait {
            println!("started job {job}");
            println!("  abyssal-warden service job {job}");
            return Ok(0);
        }
        wait_and_print(&sock, job, wait.format)
    };
    match args.command {
        ServiceCommand::Status => {
            let Reply::Status(s) = call(&sock, Op::Status {})? else {
                return Err("unexpected reply".into());
            };
            println!(
                "Abyssal Warden service {} (running as {})",
                sanitize(&s.server_version),
                if s.running_as_root {
                    "root"
                } else {
                    "an unprivileged user"
                }
            );
            println!("  started:   {}", fmt_time(s.started_at));
            println!(
                "  jobs:      {} running, {} queued",
                s.jobs_running, s.jobs_queued
            );
            println!("  schedules: {}", s.schedules);
            println!(
                "  you:       {}{}",
                who(&s.caller),
                if s.caller_is_admin {
                    " (administrator)"
                } else {
                    ""
                }
            );
            if let Some(a) = s.last_audit {
                println!(
                    "  audit log: {} ({}, checked {})",
                    if a.consistent {
                        "consistent"
                    } else {
                        "MISMATCH"
                    },
                    sanitize(&a.detail),
                    fmt_time(a.checked_at)
                );
            }
            Ok(0)
        }
        ServiceCommand::Scan {
            paths,
            heuristics,
            no_archives,
            quarantine,
            wait,
        } => {
            let op = Op::Scan {
                paths: absolute(&paths)?,
                heuristics,
                no_archives,
                quarantine,
            };
            started(call(&sock, op)?, &wait)
        }
        ServiceCommand::SystemCheck { heuristics, wait } => {
            started(call(&sock, Op::SystemCheck { heuristics })?, &wait)
        }
        ServiceCommand::RunSchedule { name, wait } => {
            started(call(&sock, Op::RunSchedule { name })?, &wait)
        }
        ServiceCommand::Jobs => {
            let Reply::Jobs { jobs } = call(&sock, Op::Jobs {})? else {
                return Err("unexpected reply".into());
            };
            if jobs.is_empty() {
                println!("no jobs");
            }
            for j in &jobs {
                println!(
                    "{}  {:<12} {:<10} {:<10} {}  {}",
                    j.id,
                    label(&j.kind),
                    label(&j.state),
                    who(&j.owner),
                    fmt_time(j.created_at),
                    sanitize(
                        &j.schedule
                            .clone()
                            .map(|s| format!("schedule {s}"))
                            .unwrap_or_else(|| j.paths.join(" "))
                    )
                );
            }
            Ok(0)
        }
        ServiceCommand::Job { id } => {
            let Reply::Job(j) = call(&sock, Op::Job { job: id })? else {
                return Err("unexpected reply".into());
            };
            print_job(&j);
            Ok(0)
        }
        ServiceCommand::Report { id, format } => {
            let j = job(&sock, id)?;
            print_report(&sock, &j, format)
        }
        ServiceCommand::Cancel { id } => done(call(&sock, Op::Cancel { job: id })?),
        ServiceCommand::Schedules => {
            let Reply::Schedules { schedules } = call(&sock, Op::Schedules {})? else {
                return Err("unexpected reply".into());
            };
            if schedules.is_empty() {
                println!("no schedules configured");
            }
            for s in schedules {
                let every = match &s.at_utc {
                    Some(at) => format!("every {} day(s) at {at} UTC", s.every_hours / 24),
                    None => format!("every {} hour(s)", s.every_hours),
                };
                println!(
                    "{}: {} {}",
                    sanitize(&s.name),
                    label(&s.kind),
                    sanitize(&s.paths.join(" "))
                );
                println!(
                    "  {every}; next {}; last {}",
                    fmt_time(s.next_run),
                    s.last_run.map_or("never".into(), fmt_time)
                );
            }
            Ok(0)
        }
        ServiceCommand::Quarantine(QuarantineOp::List) => {
            let Reply::Quarantine { items } = call(&sock, Op::QuarantineList {})? else {
                return Err("unexpected reply".into());
            };
            if items.is_empty() {
                println!("the quarantine store is empty");
            }
            for i in items {
                println!(
                    "{}  {:<12} {}  {}  {}",
                    i.id,
                    sanitize(&i.state),
                    fmt_time(i.created_at),
                    sanitize(&i.reason),
                    sanitize(&i.original_path)
                );
            }
            Ok(0)
        }
        ServiceCommand::Quarantine(QuarantineOp::Restore { id, no_allow }) => done(call(
            &sock,
            Op::QuarantineRestore {
                id,
                allow: !no_allow,
            },
        )?),
        ServiceCommand::Quarantine(QuarantineOp::Delete { id, yes }) => {
            if !yes {
                return Err("permanent deletion needs --yes".into());
            }
            done(call(&sock, Op::QuarantineDelete { id })?)
        }
        ServiceCommand::VerifyAudit => {
            let Reply::Audit(a) = call(&sock, Op::VerifyAudit {})? else {
                return Err("unexpected reply".into());
            };
            println!(
                "{}: {}",
                if a.consistent {
                    "consistent"
                } else {
                    "MISMATCH"
                },
                sanitize(&a.detail)
            );
            println!(
                "  chain valid: {}; {} entries; {} matched; {} unanchored; {} anchors of other chains",
                a.chain_ok, a.entries, a.matched, a.unanchored, a.other_chains
            );
            if !a.mismatched.is_empty() {
                println!("  altered entries: {:?}", a.mismatched);
            }
            if !a.missing_locally.is_empty() {
                println!(
                    "  entries missing from the local log: {:?}",
                    a.missing_locally
                );
            }
            Ok(if a.consistent { 0 } else { 1 })
        }
    }
}

/// "uid 1000" on Unix; a Windows SID as it is.
fn who(principal: &str) -> String {
    if principal.starts_with("S-") {
        sanitize(principal)
    } else {
        format!("uid {}", sanitize(principal))
    }
}

fn done(reply: Reply) -> Result<u8, String> {
    match reply {
        Reply::Done { message } => {
            println!("{}", sanitize(&message));
            Ok(0)
        }
        _ => Err("unexpected reply".into()),
    }
}

fn fmt_time(t: time::OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn job(sock: &std::path::Path, id: Uuid) -> Result<JobSummary, String> {
    match call(sock, Op::Job { job: id })? {
        Reply::Job(j) => Ok(*j),
        _ => Err("unexpected reply".into()),
    }
}

fn print_job(j: &JobSummary) {
    println!("job {} ({}): {}", j.id, label(&j.kind), label(&j.state));
    println!(
        "  owner {}{}",
        who(&j.owner),
        if j.as_owner {
            " (ran with the owner's permissions)"
        } else {
            " (ran with the service's scanner account)"
        }
    );
    if let Some(s) = &j.schedule {
        println!("  schedule {}", sanitize(s));
    }
    if !j.paths.is_empty() {
        println!("  paths {}", sanitize(&j.paths.join(" ")));
    }
    println!("  created {}", fmt_time(j.created_at));
    if let Some(t) = j.finished_at {
        println!("  finished {}", fmt_time(t));
    }
    if let Some(n) = j.findings {
        println!("  findings {n}");
    }
    if let Some(n) = j.quarantined {
        println!("  quarantined {n}");
    }
    if let Some(e) = &j.error {
        println!("  error: {}", sanitize(e));
    }
}

fn wait_and_print(sock: &std::path::Path, id: Uuid, format: Format) -> Result<u8, String> {
    loop {
        let j = job(sock, id)?;
        if j.state.finished() {
            return print_report(sock, &j, format);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn print_report(sock: &std::path::Path, j: &JobSummary, format: Format) -> Result<u8, String> {
    if j.state != JobState::Completed {
        print_job(j);
        return Ok(match j.state {
            JobState::Cancelled => crate::EXIT_CANCELLED,
            _ => EXIT_ERROR,
        });
    }
    let Reply::Report { report, .. } = call(sock, Op::Report { job: j.id })? else {
        return Err("unexpected reply".into());
    };
    match j.kind {
        JobKind::Scan => {
            let r: ScanReport = serde_json::from_value(report).map_err(|e| e.to_string())?;
            print!("{}", render(format, &r, |r| render_human(r, false))?);
            Ok(crate::exit_code(&r))
        }
        JobKind::SystemCheck => {
            let r: SystemReport = serde_json::from_value(report).map_err(|e| e.to_string())?;
            print!("{}", render(format, &r, |r| render_system(r, false))?);
            Ok(crate::system_cmd::exit_code(&r))
        }
    }
}

fn render<T: serde::Serialize>(
    format: Format,
    r: &T,
    human: impl Fn(&T) -> String,
) -> Result<String, String> {
    match format {
        Format::Human => Ok(human(r)),
        Format::Json => serde_json::to_string_pretty(r)
            .map(|s| s + "\n")
            .map_err(|e| e.to_string()),
    }
}
