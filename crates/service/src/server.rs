//! The Unix socket server: peer authentication with `SO_PEERCRED`, per
//! request validation and authorisation, dispatch.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
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

use crate::accounts::Accounts;
use crate::config::ServiceConfig;
use crate::jobs::{JobSpec, Manager, RunAs};
use crate::store::Store;
use crate::{audit, log, sanitize, schedule};

const MAX_CONNECTIONS: usize = 64;
const MAX_REQUESTS_PER_CONNECTION: usize = 1000;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

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
pub(crate) fn bind(cfg: &ServiceConfig, accounts: &Accounts) -> Result<UnixListener, String> {
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
pub(crate) fn serve(listener: &UnixListener, ctx: &Arc<Ctx>, stop: &AtomicBool) {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    continue; // dropped: closes the connection
                }
                active.fetch_add(1, Ordering::SeqCst);
                let (ctx, active) = (Arc::clone(ctx), Arc::clone(&active));
                let spawned = std::thread::Builder::new()
                    .name("client".into())
                    .spawn(move || {
                        handle(stream, &ctx);
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    log("cannot start a client thread");
                }
            }
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

fn handle(mut stream: UnixStream, ctx: &Ctx) {
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
    let accounts = Accounts::load();
    let caller = Caller {
        uid,
        admin: accounts.is_admin(uid, &ctx.cfg),
    };
    let gid = accounts.user(uid).map_or(cred.gid.as_raw(), |u| u.gid);
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let response = match warden_ipc::read_frame::<Request>(&mut stream, MAX_REQUEST) {
            Ok(req) => dispatch(ctx, caller, gid, &req),
            Err(FrameError::Closed) => return,
            Err(FrameError::Io(_)) => return,
            Err(e) => {
                let _ = warden_ipc::write_frame(
                    &mut stream,
                    &Response::error(0, Rejection::new(ErrorCode::BadRequest, e.to_string())),
                    MAX_RESPONSE,
                );
                return;
            }
        };
        if warden_ipc::write_frame(&mut stream, &response, MAX_RESPONSE).is_err() {
            return;
        }
    }
}

fn not_found() -> Rejection {
    Rejection::new(ErrorCode::NotFound, "no such job")
}

fn internal(e: impl std::fmt::Display) -> Rejection {
    Rejection::new(ErrorCode::Internal, sanitize(&e.to_string()))
}

pub(crate) fn dispatch(ctx: &Ctx, caller: Caller, gid: u32, req: &Request) -> Response {
    let result = req
        .validate()
        .and_then(|()| policy::authorize(caller, &req.op))
        .and_then(|()| execute(ctx, caller, gid, &req.op));
    match result {
        Ok(reply) => Response::new(req.id, reply),
        Err(r) => {
            if r.code == ErrorCode::Unauthorized {
                log(&format!(
                    "denied {:?} for uid {}",
                    op_name(&req.op),
                    caller.uid
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

fn open_quarantine(ctx: &Ctx, caller: Caller) -> Result<QuarantineStore, Rejection> {
    let mut store = QuarantineStore::open(&ctx.cfg.quarantine_store).map_err(internal)?;
    store.on_behalf_of(Some(caller.uid));
    Ok(store)
}

fn parse_id(id: &str) -> Result<QuarantineId, Rejection> {
    id.parse()
        .map_err(|_| Rejection::new(ErrorCode::BadRequest, "invalid quarantine id"))
}

fn execute(ctx: &Ctx, caller: Caller, gid: u32, op: &Op) -> Result<Reply, Rejection> {
    let visible = |owner: u32| policy::can_access_job(caller, owner);
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
                caller_uid: caller.uid,
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
            let run_as = if policy::scan_as_caller(caller) {
                RunAs::Caller {
                    uid: caller.uid,
                    gid,
                }
            } else {
                RunAs::Service
            };
            let spec = JobSpec {
                kind: JobKind::Scan,
                paths: paths.clone(),
                heuristics: *heuristics,
                no_archives: *no_archives,
                quarantine: *quarantine,
                run_as,
            };
            let job = ctx.manager.submit(caller.uid, None, spec)?;
            log(&format!("uid {} started scan job {job}", caller.uid));
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
                job: ctx.manager.submit(caller.uid, None, spec)?,
            }
        }
        Op::Jobs {} => Reply::Jobs {
            jobs: ctx.manager.list(|j| visible(j.owner_uid)),
        },
        Op::Job { job } => match ctx.manager.get(*job) {
            Some(j) if visible(j.owner_uid) => Reply::Job(Box::new(j)),
            _ => return Err(not_found()),
        },
        Op::Report { job } => match ctx.manager.get(*job) {
            Some(j) if visible(j.owner_uid) => match ctx.manager.report(*job).map_err(internal)? {
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
            Some(j) if visible(j.owner_uid) => {
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
            log(&format!("uid {} restored {qid}", caller.uid));
            Reply::Done { message }
        }
        Op::QuarantineDelete { id } => {
            let mut store = open_quarantine(ctx, caller)?;
            let qid = parse_id(id)?;
            store.delete(&qid).map_err(internal)?;
            log(&format!("uid {} deleted {qid}", caller.uid));
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
