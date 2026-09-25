//! The Abyssal Warden service (`abyssal-wardend`), Linux and Windows.
//!
//! * Listens on a local endpoint (a Unix socket, or a named pipe on
//!   Windows); every connection is identified by the operating system
//!   (`SO_PEERCRED`, or the client's token) and every request is validated
//!   and authorised (`warden_ipc::policy`). There is no network listener.
//! * Runs scans and system checks as **jobs** in separate, killable child
//!   processes (with reduced privileges on Linux, see `runner`), queued and
//!   bounded.
//! * Keeps job history and reports, runs **schedules**, applies the
//!   allow-list and (when asked) automatic quarantine in the service
//!   itself, and periodically compares the quarantine audit chain with the
//!   system log.
//!
//! Design: docs/security/privilege-model.md,
//! docs/architecture/decisions/0018-service-and-ipc.md,
//! docs/architecture/decisions/0019-windows-unsafe-boundary.md.

#[cfg(unix)]
mod accounts;
#[cfg(any(unix, windows))]
mod audit;
#[cfg(any(unix, windows))]
pub mod client;
pub mod config;
#[cfg(any(unix, windows))]
mod jobs;
#[cfg(any(unix, windows))]
mod runner;
#[cfg(any(unix, windows))]
mod schedule;
#[cfg(any(unix, windows))]
mod server;
#[cfg(any(unix, windows))]
mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Name of the Windows service.
pub const WINDOWS_SERVICE_NAME: &str = "AbyssalWarden";

/// Command-line overrides for the daemon.
#[derive(Clone, Debug, Default)]
pub struct DaemonOptions {
    pub config: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
}

pub(crate) fn sanitize(s: &str) -> String {
    warden_core::text::escape_unsafe_chars(s)
}

/// Log line to standard error (journald under systemd; on Windows the
/// Service Control Manager discards it, so important events also go to the
/// Event Log through the quarantine store's anchors).
pub(crate) fn log(msg: &str) {
    eprintln!("abyssal-wardend: {}", sanitize(msg));
}

/// The service's own principal: its uid (Unix) or SID (Windows). Owner of
/// scheduled jobs.
#[cfg(unix)]
pub(crate) fn service_principal() -> String {
    rustix::process::geteuid().as_raw().to_string()
}

#[cfg(windows)]
pub(crate) fn service_principal() -> String {
    warden_winsec::process_user_sid().unwrap_or_else(|_| warden_winsec::sddl::SYSTEM.into())
}

/// Whether the service runs with full privileges (root, or an elevated
/// administrator / SYSTEM on Windows).
#[cfg(unix)]
fn privileged() -> bool {
    rustix::process::geteuid().is_root()
}

#[cfg(windows)]
fn privileged() -> bool {
    warden_winsec::process_is_admin().unwrap_or(false)
}

/// Runs in the foreground until Ctrl-C or SIGTERM.
#[cfg(any(unix, windows))]
pub fn run(opts: DaemonOptions) -> Result<(), String> {
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || stop.store(true, std::sync::atomic::Ordering::SeqCst))
            .map_err(|e| format!("signal handler: {e}"))?;
    }
    run_with_stop(opts, &stop)
}

#[cfg(not(any(unix, windows)))]
pub fn run(_opts: DaemonOptions) -> Result<(), String> {
    Err("the service is not implemented for this platform".into())
}

/// Runs under the Windows Service Control Manager (`abyssal-wardend
/// --service`, as registered by `install`).
#[cfg(windows)]
pub fn run_windows_service() -> Result<(), String> {
    warden_winsec::scm::run_as_service(WINDOWS_SERVICE_NAME, |stop| {
        run_with_stop(DaemonOptions::default(), &stop)
    })
    .map_err(|e| format!("cannot start as a service: {e}"))
}

/// Registers the Windows service (automatic start, LocalSystem).
#[cfg(windows)]
pub fn install_windows_service() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    warden_winsec::scm::install(
        WINDOWS_SERVICE_NAME,
        "Abyssal Warden",
        "Scheduled and on-request malware scanning; local named-pipe IPC only.",
        &exe,
        &["--service"],
    )
    .map_err(|e| e.to_string())
}

#[cfg(windows)]
pub fn uninstall_windows_service() -> Result<(), String> {
    warden_winsec::scm::uninstall(WINDOWS_SERVICE_NAME).map_err(|e| e.to_string())
}

/// The scanner binary: configured, or `abyssal-warden` next to this one.
/// When privileged, it must not be modifiable by unprivileged users.
#[cfg(any(unix, windows))]
fn scanner_binary(cfg: &config::ServiceConfig, privileged: bool) -> Result<PathBuf, String> {
    let binary = match &cfg.scanner_binary {
        Some(b) => b.clone(),
        None => std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("cannot locate the service binary's directory")?
            .join(if cfg!(windows) {
                "abyssal-warden.exe"
            } else {
                "abyssal-warden"
            }),
    };
    let file = std::fs::File::open(&binary)
        .map_err(|e| format!("scanner binary {}: {e}", binary.display()))?;
    if privileged {
        config::check_trusted_file(&binary, &file)?;
    }
    Ok(binary)
}

/// Runs the service until `stop` is set.
#[cfg(any(unix, windows))]
pub fn run_with_stop(opts: DaemonOptions, stop: &Arc<AtomicBool>) -> Result<(), String> {
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    let root = privileged();
    let config_path = opts.config.unwrap_or_else(config::default_config_path);
    let mut cfg = config::ServiceConfig::load(&config_path, root)?;
    if let Some(s) = opts.socket {
        cfg.socket = s;
    }
    if let Some(d) = opts.state_dir {
        cfg.state_dir = d;
    }
    cfg.validate()?;
    let cfg = Arc::new(cfg);
    let binary = scanner_binary(&cfg, root)?;

    #[cfg(unix)]
    let accounts = accounts::Accounts::load();
    #[cfg(unix)]
    let (setpriv, scanner) = if root {
        let sp = ["/usr/bin/setpriv", "/bin/setpriv"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or("setpriv (util-linux) is required to run scans with reduced privileges")?;
        let user = accounts.user_by_name(&cfg.scanner_user).ok_or_else(|| {
            format!(
                "scanner account {:?} does not exist (see packaging/linux/abyssal-warden.sysusers)",
                cfg.scanner_user
            )
        })?;
        if user.uid == 0 {
            return Err("the scanner account must not be root".into());
        }
        (Some(sp), Some((user.uid, user.gid)))
    } else {
        log("not running as root: jobs run with this account's own permissions (development mode)");
        (None, None)
    };
    #[cfg(windows)]
    let (setpriv, scanner) = {
        if !root {
            log(
                "not running elevated: jobs run with this account's own permissions (development mode)",
            );
        }
        (None, None)
    };

    // Claim the endpoint before touching any state, so a second instance
    // fails here instead of marking the running instance's jobs as
    // interrupted.
    #[cfg(unix)]
    let listener = server::bind(&cfg, &accounts)?;
    #[cfg(windows)]
    let listener = server::bind_pipe(&cfg.socket.to_string_lossy())?;

    let store = Arc::new(store::Store::open(&cfg.state_dir)?);
    let manager = jobs::Manager::new(
        store::Store::open(&cfg.state_dir)?,
        jobs::Environment {
            cfg: Arc::clone(&cfg),
            binary,
            setpriv,
            scanner,
        },
    );
    let workers = manager.start_workers();
    let ctx = Arc::new(server::Ctx {
        cfg: Arc::clone(&cfg),
        manager: Arc::clone(&manager),
        store: Arc::clone(&store),
        started_at: time::OffsetDateTime::now_utc(),
        root,
        audit: Mutex::new(store.last_audit()),
    });

    let scheduler = {
        let (cfg, manager, store, stop) = (
            Arc::clone(&cfg),
            Arc::clone(&manager),
            Arc::clone(&store),
            Arc::clone(stop),
        );
        std::thread::spawn(move || schedule::run(cfg, manager, store, stop))
    };
    let auditor = {
        let (ctx, stop) = (Arc::clone(&ctx), Arc::clone(stop));
        std::thread::spawn(move || {
            let hours = u64::from(ctx.cfg.audit_check_hours);
            if hours == 0 {
                return;
            }
            let mut wait = 60u64; // first check a minute after start
            loop {
                for _ in 0..wait {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
                let a = audit::check(&ctx.cfg.quarantine_store);
                ctx.record_audit(&a);
                wait = hours * 3600;
            }
        })
    };

    log(&format!(
        "listening on {} (version {})",
        cfg.socket.display(),
        env!("CARGO_PKG_VERSION")
    ));
    #[cfg(unix)]
    let served: Result<(), String> = {
        server::serve(&listener, &ctx, stop);
        Ok(())
    };
    #[cfg(windows)]
    let served = server::serve_pipe(listener, &cfg.socket.to_string_lossy(), &ctx, stop);
    stop.store(true, Ordering::SeqCst);
    log("stopping");
    manager.shutdown();
    for w in workers {
        let _ = w.join();
    }
    let _ = scheduler.join();
    let _ = auditor.join();
    #[cfg(unix)]
    let _ = std::fs::remove_file(&cfg.socket);
    served
}
