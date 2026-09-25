//! `abyssal-wardend`: the Abyssal Warden service (Linux).
//! See docs/user/service.md and docs/security/privilege-model.md.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// Abyssal Warden service: scheduled and on-request scans over an
/// authenticated local socket.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Configuration file [default: /etc/abyssal-warden/service.json].
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Socket path (overrides the configuration).
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// State directory for job history and reports (overrides the
    /// configuration).
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let opts = warden_service::DaemonOptions {
        config: args.config,
        socket: args.socket,
        state_dir: args.state_dir,
    };
    match warden_service::run(opts) {
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
