//! `abyssal-wardend`: the Abyssal Warden service (Linux and Windows).
//! See docs/user/service.md and docs/security/privilege-model.md.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// Abyssal Warden service: scheduled and on-request scans over an
/// authenticated local socket (Linux) or named pipe (Windows).
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Configuration file [default: /etc/abyssal-warden/service.json, or
    /// %ProgramData%\AbyssalWarden\service.json on Windows].
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Socket path or pipe name (overrides the configuration).
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// State directory for job history and reports (overrides the
    /// configuration).
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// Windows: run under the Service Control Manager (used by the
    /// registered service; not for interactive use).
    #[cfg(windows)]
    #[arg(long, conflicts_with_all = ["install", "uninstall"])]
    service: bool,
    /// Windows: register the service (automatic start, LocalSystem).
    #[cfg(windows)]
    #[arg(long, conflicts_with = "uninstall")]
    install: bool,
    /// Windows: stop and remove the service.
    #[cfg(windows)]
    #[arg(long)]
    uninstall: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let result = run(args);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "abyssal-wardend: error: {}",
                warden_core::text::escape_unsafe_chars(&e)
            );
            ExitCode::from(2)
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    #[cfg(windows)]
    {
        if args.install {
            warden_service::install_windows_service()?;
            println!(
                "installed the {} service; start it with: sc start {}",
                warden_service::WINDOWS_SERVICE_NAME,
                warden_service::WINDOWS_SERVICE_NAME
            );
            return Ok(());
        }
        if args.uninstall {
            warden_service::uninstall_windows_service()?;
            println!(
                "removed the {} service",
                warden_service::WINDOWS_SERVICE_NAME
            );
            return Ok(());
        }
        if args.service {
            return warden_service::run_windows_service();
        }
    }
    warden_service::run(warden_service::DaemonOptions {
        config: args.config,
        socket: args.socket,
        state_dir: args.state_dir,
    })
}
