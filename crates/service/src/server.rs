//! The service endpoint and request dispatch.
//!
//! * **Unix:** a Unix stream socket; the peer's uid comes from the kernel
//!   (`SO_PEERCRED`) when it connects.
//! * **Windows:** a named pipe with an explicit security descriptor that
//!   refuses remote clients and lets only SYSTEM and Administrators create
//!   instances; the client's identity comes from its token (impersonation).
//!
//! Every request is then validated and authorised (`warden_ipc::policy`).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;
use warden_ipc::policy::{self, Caller};
use warden_ipc::{
    AuditStatus, ErrorCode, FrameError, JobKind, MAX_REQUEST, MAX_RESPONSE, Op, QuarantineItem,
    Rejection, Reply, Request, Response, ServiceStatus,
};
use warden_remediation::{QuarantineId, QuarantineStore};

use crate::config::ServiceConfig;
use crate::jobs::{JobSpec, Manager, RunAs};
use crate::store::Store;
use crate::{audit, log, sanitize, schedule};

const MAX_CONNECTIONS: usize = 64;
const MAX_REQUESTS_PER_CONNECTION: usize = 1000;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// An authenticated client.
#[derive(Clone, Debug)]
pub(crate) struct Peer {
    pub(crate) caller: Caller,
    /// Unix: the identity a scan for this client runs as.
    #[cfg(unix)]
    pub(crate) ids: (u32, u32),
}

pub(crate) struct Ctx {
    pub(crate) cfg: Arc<ServiceConfig>,
    pub(crate) manager: Arc<Manager>,
    pub(crate) store: Arc<Store>,
    pub(crate) started_at: OffsetDateTime,
    pub(crate) root: bool,
    pub(crate) audit: Mutex<Option<AuditStatus>>,
}

impl Ctx {
    pub(crate) fn record_audit(&self, a: &AuditStatus) {
        if !a.consistent {
            log(&format!("AUDIT LOG CHECK FAILED: {}", a.detail));
        }
        if let Err(e) = self.store.save_audit(a) {
            log(&format!("cannot save the audit check result: {e}"));
        }
        *self
            .audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(a.clone());
    }
}

/// Creates the listening socket, refusing to take over a live one.
#[cfg(unix)]
pub(crate) fn bind(
    cfg: &ServiceConfig,
    accounts: &crate::accounts::Accounts,
) -> Result<std::os::unix::net::UnixListener, String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    let path = &cfg.socket;
    let dir = path.parent().ok_or("socket path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(format!(
                    "{} is in use: another instance is running",
                    path.display()
                ));
            }
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(_) => return Err(format!("{} exists and is not a socket", path.display())),
        Err(_) => {}
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // Access is authorised per request; the mode only narrows who may ask.
    let mode = match &cfg.socket_group {
        Some(name) => {
            let group = accounts
                .group_by_name(name)
                .ok_or_else(|| format!("socket_group {name:?} does not exist"))?;
            std::os::unix::fs::chown(path, None, Some(group.gid))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            0o660
        }
        None => 0o666,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(listener)
}

/// Accepts connections until `stop` is set.
#[cfg(unix)]
pub(crate) fn serve(
    listener: &std::os::unix::net::UnixListener,
    ctx: &Arc<Ctx>,
    stop: &AtomicBool,
) {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => spawn_client(&active, ctx, move |ctx| handle_unix(stream, ctx)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(e) => {
                log(&format!("accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn spawn_client(
    active: &Arc<AtomicUsize>,
    ctx: &Arc<Ctx>,
    work: impl FnOnce(&Ctx) + Send + 'static,
) {
    if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
        return; // dropped: closes the connection
    }
    active.fetch_add(1, Ordering::SeqCst);
    let (ctx, active) = (Arc::clone(ctx), Arc::clone(active));
    let spawned = std::thread::Builder::new()
        .name("client".into())
        .spawn(move || {
            work(&ctx);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    if spawned.is_err() {
        log("cannot start a client thread");
    }
}

/// Serves requests on one connection. `identify` is called after the
/// first request has been read (Windows needs data before impersonation).
fn converse<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    ctx: &Ctx,
    mut identify: impl FnMut(&S) -> Option<Peer>,
    mut progress: impl FnMut(),
) {
    let mut peer: Option<Peer> = None;
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let response = match warden_ipc::read_frame::<Request>(stream, MAX_REQUEST) {
            Ok(req) => {
                if peer.is_none() {
                    peer = identify(stream);
                }
                let Some(p) = peer.as_ref() else {
                    log("cannot identify a client");
                    return;
                };
                dispatch(ctx, p, &req)
            }
            Err(FrameError::Closed | FrameError::Io(_)) => return,
            Err(e) => {
                let _ = warden_ipc::write_frame(
                    stream,
                    &Response::error(0, Rejection::new(ErrorCode::BadRequest, e.to_string())),
                    MAX_RESPONSE,
                );
                return;
            }
        };
        if warden_ipc::write_frame(stream, &response, MAX_RESPONSE).is_err() {
            return;
        }
        progress();
    }
}

#[cfg(unix)]
fn handle_unix(mut stream: std::os::unix::net::UnixStream, ctx: &Ctx) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    // The kernel's view of the peer, captured when it connected.
    let cred = match rustix::net::sockopt::socket_peercred(&stream) {
        Ok(c) => c,
        Err(e) => {
            log(&format!("cannot identify a client: {e}"));
            return;
        }
    };
    let uid = cred.uid.as_raw();
    let accounts = crate::accounts::Accounts::load();
    let peer = Peer {
        caller: Caller {
            principal: uid.to_string(),
            admin: accounts.is_admin(uid, &ctx.cfg),
        },
        ids: (uid, accounts.user(uid).map_or(cred.gid.as_raw(), |u| u.gid)),
    };
    converse(&mut stream, ctx, |_| Some(peer.clone()), || {});
}

/// The pipe's security: SYSTEM, Administrators and the owner (the service)
/// have full control; authenticated users may only read and write data,
/// not create pipe instances. Remote clients are refused by the pipe mode.
#[cfg(windows)]
pub(crate) const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12008b;;;AU)";

/// Creates the pipe; fails if the name exists (another instance, or a
/// process squatting the name).
#[cfg(windows)]
pub(crate) fn bind_pipe(name: &str) -> Result<warden_winsec::PipeListener, String> {
    warden_winsec::PipeListener::bind(name, PIPE_SDDL)
        .map_err(|e| format!("{name} is in use: {e} (is another instance running?)"))
}

/// Accepts pipe clients until `stop` is set.
#[cfg(windows)]
pub(crate) fn serve_pipe(
    mut listener: warden_winsec::PipeListener,
    name: &str,
    ctx: &Arc<Ctx>,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    // `accept` blocks; when asked to stop, connect once to wake it.
    let waker = {
        let (stop, name) = (Arc::clone(stop), name.to_owned());
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
            }
            let _ = std::fs::OpenOptions::new().read(true).open(&name);
        })
    };
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(conn) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                spawn_client(&active, ctx, move |ctx| handle_pipe(conn, ctx));
            }
            Err(e) => {
                log(&format!("accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let _ = waker.join();
    Ok(())
}

#[cfg(windows)]
fn handle_pipe(mut conn: warden_winsec::PipeConnection, ctx: &Ctx) {
    use std::sync::mpsc;
    // Synchronous pipes have no read timeout: a watchdog disconnects a
    // client that stays idle longer than IO_TIMEOUT.
    let Ok(disconnector) = conn.disconnector() else {
        return;
    };
    let (tick, ticks) = mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        loop {
            match ticks.recv_timeout(IO_TIMEOUT) {
                Ok(()) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    disconnector.disconnect();
                    return;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });
    let identify = |conn: &warden_winsec::PipeConnection| {
        conn.client()
            .map_err(|e| log(&format!("cannot identify a client: {e}")))
            .ok()
            .map(|who| Peer {
                caller: Caller {
                    principal: who.sid,
                    admin: who.admin,
                },
            })
    };
    converse(&mut conn, ctx, identify, || {
        let _ = tick.send(());
    });
    drop(tick);
    let _ = watchdog.join();
}
fn not_found() -> Rejection {
    Rejection::new(ErrorCode::NotFound, "no such job")
}

fn internal(e: impl std::fmt::Display) -> Rejection {
    Rejection::new(ErrorCode::Internal, sanitize(&e.to_string()))
}

pub(crate) fn dispatch(ctx: &Ctx, peer: &Peer, req: &Request) -> Response {
    let caller = &peer.caller;
    let result = req
        .validate()
        .and_then(|()| policy::authorize(caller, &req.op))
        .and_then(|()| execute(ctx, peer, &req.op));
    match result {
        Ok(reply) => Response::new(req.id, reply),
        Err(r) => {
            if r.code == ErrorCode::Unauthorized {
                log(&format!(
                    "denied {:?} for {}",
                    op_name(&req.op),
                    caller.principal
                ));
            }
            Response::error(req.id, r)
        }
    }
}

fn op_name(op: &Op) -> &'static str {
    match op {
        Op::Ping {} => "ping",
        Op::Status {} => "status",
        Op::Scan { .. } => "scan",
        Op::SystemCheck { .. } => "system_check",
        Op::Jobs {} => "jobs",
        Op::Job { .. } => "job",
        Op::Report { .. } => "report",
        Op::Cancel { .. } => "cancel",
        Op::Schedules {} => "schedules",
        Op::RunSchedule { .. } => "run_schedule",
        Op::QuarantineList {} => "quarantine_list",
        Op::QuarantineRestore { .. } => "quarantine_restore",
        Op::QuarantineDelete { .. } => "quarantine_delete",
        Op::VerifyAudit {} => "verify_audit",
    }
}

fn open_quarantine(ctx: &Ctx, caller: &Caller) -> Result<QuarantineStore, Rejection> {
    let mut store = QuarantineStore::open(&ctx.cfg.quarantine_store).map_err(internal)?;
    store.on_behalf_of(Some(caller.principal.clone()));
    Ok(store)
}

fn parse_id(id: &str) -> Result<QuarantineId, Rejection> {
    id.parse()
        .map_err(|_| Rejection::new(ErrorCode::BadRequest, "invalid quarantine id"))
}

/// Where a scan for this client runs: as the client on Unix; on Windows
/// the service cannot yet run a job with the client's identity, so
/// non-administrators scan with the CLI instead.
fn scan_identity(peer: &Peer) -> Result<RunAs, Rejection> {
    if !policy::scan_as_caller(&peer.caller) {
        return Ok(RunAs::Service);
    }
    #[cfg(unix)]
    {
        Ok(RunAs::Caller {
            uid: peer.ids.0,
            gid: peer.ids.1,
        })
    }
    #[cfg(windows)]
    {
        Err(Rejection::new(
            ErrorCode::Unsupported,
            "on Windows the service scans only for administrators; run `abyssal-warden scan` yourself",
        ))
    }
}

fn execute(ctx: &Ctx, peer: &Peer, op: &Op) -> Result<Reply, Rejection> {
    let caller = &peer.caller;
    let visible = |owner: &str| policy::can_access_job(caller, owner);
    Ok(match op {
        Op::Ping {} => Reply::Pong {
            server_version: env!("CARGO_PKG_VERSION").into(),
        },
        Op::Status {} => {
            let (running, queued) = ctx.manager.counts();
            Reply::Status(Box::new(ServiceStatus {
                server_version: env!("CARGO_PKG_VERSION").into(),
                started_at: ctx.started_at,
                running_as_root: ctx.root,
                jobs_running: running,
                jobs_queued: queued,
                schedules: ctx.cfg.schedules.len() as u32,
                caller: caller.principal.clone(),
                caller_is_admin: caller.admin,
                last_audit: if caller.admin {
                    ctx.audit
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone()
                } else {
                    None
                },
            }))
        }
        Op::Scan {
            paths,
            heuristics,
            no_archives,
            quarantine,
        } => {
            let run_as = scan_identity(peer)?;
            let spec = JobSpec {
                kind: JobKind::Scan,
                paths: paths.clone(),
                heuristics: *heuristics,
                no_archives: *no_archives,
                quarantine: *quarantine,
                run_as,
            };
            let job = ctx.manager.submit(caller.principal.clone(), None, spec)?;
            log(&format!("{} started scan job {job}", caller.principal));
            Reply::JobStarted { job }
        }
        Op::SystemCheck { heuristics } => {
            let spec = JobSpec {
                kind: JobKind::SystemCheck,
                paths: Vec::new(),
                heuristics: *heuristics,
                no_archives: false,
                quarantine: false,
                run_as: RunAs::Service,
            };
            Reply::JobStarted {
                job: ctx.manager.submit(caller.principal.clone(), None, spec)?,
            }
        }
        Op::Jobs {} => Reply::Jobs {
            jobs: ctx.manager.list(|j| visible(&j.owner)),
        },
        Op::Job { job } => match ctx.manager.get(*job) {
            Some(j) if visible(&j.owner) => Reply::Job(Box::new(j)),
            _ => return Err(not_found()),
        },
        Op::Report { job } => match ctx.manager.get(*job) {
            Some(j) if visible(&j.owner) => match ctx.manager.report(*job).map_err(internal)? {
                Some(report) => Reply::Report { job: *job, report },
                None => {
                    return Err(Rejection::new(
                        ErrorCode::NotFound,
                        "no report: the job has not finished, or it failed",
                    ));
                }
            },
            _ => return Err(not_found()),
        },
        Op::Cancel { job } => match ctx.manager.get(*job) {
            Some(j) if visible(&j.owner) => {
                ctx.manager.cancel(*job)?;
                Reply::Done {
                    message: format!("cancelling job {job}"),
                }
            }
            _ => return Err(not_found()),
        },
        Op::Schedules {} => Reply::Schedules {
            schedules: schedule::info(&ctx.cfg, &ctx.store, OffsetDateTime::now_utc()),
        },
        Op::RunSchedule { name } => {
            let s = ctx
                .cfg
                .schedules
                .iter()
                .find(|s| &s.name == name)
                .ok_or_else(|| Rejection::new(ErrorCode::NotFound, "no such schedule"))?;
            Reply::JobStarted {
                job: schedule::start(s, &ctx.manager, &ctx.store)?,
            }
        }
        Op::QuarantineList {} => {
            if !ctx.cfg.quarantine_store.exists() {
                return Ok(Reply::Quarantine { items: Vec::new() });
            }
            let store = open_quarantine(ctx, caller)?;
            let items = store
                .list()
                .map_err(internal)?
                .into_iter()
                .map(|r| QuarantineItem {
                    id: r.id.to_string(),
                    state: serde_json::to_value(r.state)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default(),
                    original_path: r.original.path.text.clone(),
                    sha256: r.original.sha256.to_hex(),
                    reason: r
                        .reason
                        .detection_name
                        .clone()
                        .or(r.reason.note.clone())
                        .unwrap_or_default(),
                    created_at: r.created_at,
                })
                .collect();
            Reply::Quarantine { items }
        }
        Op::QuarantineRestore { id, allow } => {
            let mut store = open_quarantine(ctx, caller)?;
            let qid = parse_id(id)?;
            let target = store.restore(&qid, None).map_err(internal)?;
            let mut message = format!("restored {qid} to {}", sanitize(&target.to_string_lossy()));
            if *allow {
                let rec = store.get(&qid).map_err(internal)?;
                store
                    .allow(
                        rec.original.sha256,
                        "restored from quarantine",
                        Some(&qid),
                        rec.reason.detection_name.as_deref(),
                    )
                    .map_err(internal)?;
                message.push_str("; allow-listed");
            }
            log(&format!("{} restored {qid}", caller.principal));
            Reply::Done { message }
        }
        Op::QuarantineDelete { id } => {
            let mut store = open_quarantine(ctx, caller)?;
            let qid = parse_id(id)?;
            store.delete(&qid).map_err(internal)?;
            log(&format!("{} deleted {qid}", caller.principal));
            Reply::Done {
                message: format!("deleted {qid}"),
            }
        }
        Op::VerifyAudit {} => {
            let a = audit::check(&ctx.cfg.quarantine_store);
            ctx.record_audit(&a);
            Reply::Audit(Box::new(a))
        }
    })
}
