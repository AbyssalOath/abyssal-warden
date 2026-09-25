//! The Abyssal Warden service (`abyssal-wardend`), Linux.
//!
//! * Listens on a Unix socket; every connection is identified by the
//!   kernel (`SO_PEERCRED`) and every request is validated and authorised
//!   (`warden_ipc::policy`). There is no network listener.
//! * Runs scans and system checks as **jobs** in separate, killable child
//!   processes with reduced privileges (see `runner`), queued and bounded.
//! * Keeps job history and reports, runs **schedules**, applies the
//!   allow-list and (when asked) automatic quarantine in the service
//!   itself, and periodically compares the quarantine audit chain with the
//!   system journal.
//!
//! Design: docs/security/privilege-model.md,
//! docs/architecture/decisions/0018-service-and-ipc.md.

#[cfg(target_os = "linux")]
mod accounts;
#[cfg(target_os = "linux")]
mod audit;
#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
mod jobs;
#[cfg(target_os = "linux")]
mod runner;
#[cfg(target_os = "linux")]
mod schedule;
#[cfg(target_os = "linux")]
mod server;
#[cfg(target_os = "linux")]
mod store;

use std::path::PathBuf;

/// Command-line overrides for the daemon.
#[derive(Clone, Debug, Default)]
pub struct DaemonOptions {
    pub config: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
pub(crate) fn sanitize(s: &str) -> String {
    warden_core::text::escape_unsafe_chars(s)
}

/// Log line to standard error (journald when run by systemd).
#[cfg(target_os = "linux")]
pub(crate) fn log(msg: &str) {
    eprintln!("abyssal-wardend: {}", sanitize(msg));
}

#[cfg(not(target_os = "linux"))]
pub fn run(_opts: DaemonOptions) -> Result<(), String> {
    Err("the service is only implemented for Linux so far".into())
}

#[cfg(target_os = "linux")]
pub fn run(opts: DaemonOptions) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let root = rustix::process::geteuid().is_root();
    let config_path = opts
        .config
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_CONFIG));
    let mut cfg = config::ServiceConfig::load(&config_path, root)?;
    if let Some(s) = opts.socket {
        cfg.socket = s;
    }
    if let Some(d) = opts.state_dir {
        cfg.state_dir = d;
    }
    cfg.validate()?;
    let cfg = Arc::new(cfg);
    let accounts = accounts::Accounts::load();

    let binary = match &cfg.scanner_binary {
        Some(b) => b.clone(),
        None => std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("cannot locate the service binary's directory")?
            .join("abyssal-warden"),
    };
    let meta = std::fs::metadata(&binary)
        .map_err(|e| format!("scanner binary {}: {e}", binary.display()))?;
    if root && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
        return Err(format!(
            "scanner binary {} must be owned by root and not writable by others",
            binary.display()
        ));
    }
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
    let listener = server::bind(&cfg, &accounts)?;
    let ctx = Arc::new(server::Ctx {
        cfg: Arc::clone(&cfg),
        manager: Arc::clone(&manager),
        store: Arc::clone(&store),
        started_at: time::OffsetDateTime::now_utc(),
        root,
        audit: Mutex::new(store.last_audit()),
    });

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .map_err(|e| format!("signal handler: {e}"))?;
    }
    let scheduler = {
        let (cfg, manager, store, stop) = (
            Arc::clone(&cfg),
            Arc::clone(&manager),
            Arc::clone(&store),
            Arc::clone(&stop),
        );
        std::thread::spawn(move || schedule::run(cfg, manager, store, stop))
    };
    let auditor = {
        let (ctx, stop) = (Arc::clone(&ctx), Arc::clone(&stop));
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
    server::serve(&listener, &ctx, &stop);
    log("stopping");
    manager.shutdown();
    for w in workers {
        let _ = w.join();
    }
    let _ = scheduler.join();
    let _ = auditor.join();
    let _ = std::fs::remove_file(&cfg.socket);
    let _ = Path::new(&cfg.socket);
    Ok(())
}
