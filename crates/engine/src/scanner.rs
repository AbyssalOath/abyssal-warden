//! Scan orchestration.
//!
//! Threads (one walker, `workers` workers, and the caller's thread as
//! coordinator):
//!
//! ```text
//!             work queue (bounded)            results (bounded)
//! walker ───────────────────────► workers ─────────────────────► coordinator
//!   │  (paths of regular files)   (open, hash, detect)             (aggregate,
//!   └──────────── directories / skips / walk errors ─────────────►  progress,
//!                                                                   deadlines,
//!                                                                   watchdog)
//! ```
//!
//! Both channels are bounded, so memory stays proportional to `workers`
//! rather than to the size of the tree. The coordinator does the aggregation
//! and invokes the progress callback, so the callback needs neither `Send`
//! nor `Sync`.
//!
//! Walker and workers are ordinary (not scoped) threads sharing state through
//! an `Arc`. That lets the coordinator **abandon** a worker that is stuck on
//! one file well past its per-file deadline (a read blocked on a hung
//! network filesystem cannot be interrupted, and a detector may ignore its
//! deadline): the file is reported, a replacement worker is started, and the
//! scan finishes without waiting for the stuck thread. The scan ends when the
//! walker and every non-abandoned worker have sent their exit message.
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use uuid::Uuid;
use walkdir::WalkDir;
use warden_core::{
    CancellationToken, ConfigError, Detector, DetectorInfo, DetectorRequirements, DetectorWorker,
    EngineInfo, FileObservation, Finding, IssueKind, ObservedPath, REPORT_SCHEMA_VERSION,
    ScanConfig, ScanIssue, ScanReport, ScanSettings, ScanStats, ScanStatus, SkipReason,
    SkippedEntry, SymlinkPolicy, Truncation,
};

use crate::fsio::{HashFileError, ReadOptions, ScanBase, read_file};
use crate::{ENGINE_NAME, ENGINE_VERSION};

/// Fatal scan errors. Per-file problems are never fatal; they are recorded
/// as [`ScanIssue`]s in the report.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("invalid scan configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("failed to start scan thread: {0}")]
    ThreadSpawn(#[source] io::Error),
    #[error("an internal scan thread panicked")]
    ThreadPanicked,
}

/// Progress notifications delivered on the thread that called
/// [`Scanner::scan`], together with the running [`ScanStats`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ProgressEvent<'a> {
    FileScanned { path: &'a Path, bytes: u64 },
    Finding(&'a Finding),
    Skipped { path: &'a Path, reason: SkipReason },
    Issue(&'a ScanIssue),
}

/// How long past its per-file deadline a worker may stay on one file before
/// the watchdog abandons it. Covers YARA-X's one-second timeout granularity.
const STALL_GRACE: Duration = Duration::from_secs(2);
/// How often the coordinator checks deadlines and stalled workers.
const TICK: Duration = Duration::from_millis(50);

/// A configured scanner: validated settings plus the detectors to run.
pub struct Scanner {
    config: ScanConfig,
    detectors: Vec<Arc<dyn Detector>>,
    detector_infos: Vec<DetectorInfo>,
    detector_reqs: Vec<DetectorRequirements>,
}

impl fmt::Debug for Scanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanner")
            .field("config", &self.config)
            .field("detectors", &self.detector_infos)
            .finish()
    }
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Result<Self, ScanError> {
        config.validate()?;
        Ok(Self {
            config,
            detectors: Vec::new(),
            detector_infos: Vec::new(),
            detector_reqs: Vec::new(),
        })
    }

    pub fn add_detector(&mut self, detector: Box<dyn Detector>) {
        self.detector_infos.push(detector.info());
        self.detector_reqs.push(detector.requirements());
        self.detectors.push(Arc::from(detector));
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub fn detectors(&self) -> &[DetectorInfo] {
        &self.detector_infos
    }

    /// Run a scan to completion, until `cancel` is triggered, or until the
    /// scan time limit is reached.
    ///
    /// Returns a report in every case; a stopped scan has
    /// [`ScanStatus::Cancelled`] or [`ScanStatus::TimeLimitReached`] and
    /// partial results.
    pub fn scan<F>(
        &self,
        cancel: &CancellationToken,
        mut on_progress: F,
    ) -> Result<ScanReport, ScanError>
    where
        F: FnMut(&ProgressEvent<'_>, &ScanStats),
    {
        let started_at = OffsetDateTime::now_utc();
        let started = Instant::now();
        let limits = self.config.limits;
        let scan_deadline = limits
            .scan_timeout_ms
            .map(|ms| started + Duration::from_millis(ms));
        let targets = Arc::new(resolve_targets(&self.config));
        let mut agg = Aggregator::new(&self.config);
        for issue in targets.issues.iter().cloned() {
            agg.issue(issue, &mut on_progress);
        }

        let n_workers = self.config.workers;
        let (work_tx, work_rx) = mpsc::sync_channel::<WorkItem>(n_workers * 16);
        let (msg_tx, msg_rx) = mpsc::sync_channel::<Msg>(256);
        let stop = CancellationToken::new();
        // Stops the walker and workers however this function exits,
        // including by a panic in the progress callback.
        let _stop_on_exit = StopOnDrop(stop.clone());
        let mut stop_reason = None;
        if cancel.is_cancelled() {
            stop.cancel();
            stop_reason = Some(StopReason::Cancelled);
        }

        // Under the default policy, hold each root open so files below it are
        // opened relative to it where needed (see `fsio::ScanBase`).
        let bases: Vec<Option<ScanBase>> = if self.config.symlink_policy == SymlinkPolicy::Skip {
            targets.roots.iter().map(|r| open_base(r)).collect()
        } else {
            Vec::new()
        };

        let shared = Arc::new(Shared {
            config: self.config.clone(),
            detectors: self.detectors.clone(),
            infos: self.detector_infos.clone(),
            reqs: self.detector_reqs.clone(),
            stop: stop.clone(),
            seen: (self.config.symlink_policy == SymlinkPolicy::Follow)
                .then(|| Mutex::new(HashSet::new())),
            work_rx: Mutex::new(work_rx),
            bases,
            enqueued: AtomicU64::new(0),
            dequeued: AtomicU64::new(0),
        });

        let mut workers: Vec<WorkerHandle> = Vec::with_capacity(n_workers);
        let mut spawn_error = None;
        for id in 0..n_workers {
            match spawn_worker(id, &shared, &msg_tx) {
                Ok(w) => workers.push(w),
                Err(e) => {
                    spawn_error = Some(e);
                    break;
                }
            }
        }
        let mut walker = None;
        if spawn_error.is_none() {
            let (shared, targets, tx) = (Arc::clone(&shared), Arc::clone(&targets), msg_tx.clone());
            match thread::Builder::new()
                .name("warden-walker".into())
                .spawn(move || walker_main(&targets, &shared, &work_tx, tx))
            {
                Ok(h) => walker = Some(h),
                Err(e) => spawn_error = Some(e),
            }
        } else {
            drop(work_tx);
        }
        if spawn_error.is_some() {
            stop.cancel();
        }

        let mut walker_done = walker.is_none();
        let mut panicked = false;
        let mut abandoned = 0usize;
        let stall_limit = limits.file_timeout() + STALL_GRACE;
        loop {
            if walker_done && workers.iter().all(|w| !w.live) {
                break;
            }
            match msg_rx.recv_timeout(TICK) {
                Ok(Msg::Exited { who, panicked: p }) => {
                    panicked |= p;
                    match who {
                        Who::Walker => walker_done = true,
                        Who::Worker(id) => workers[id].live = false,
                    }
                }
                Ok(msg) => agg.handle(msg, &mut on_progress),
                Err(RecvTimeoutError::Timeout) => {}
                // Unreachable while `msg_tx` is held here; kept for safety.
                Err(RecvTimeoutError::Disconnected) => break,
            }

            if stop_reason.is_none() {
                if cancel.is_cancelled() {
                    stop_reason = Some(StopReason::Cancelled);
                    stop.cancel();
                } else if scan_deadline.is_some_and(|d| Instant::now() >= d) {
                    stop_reason = Some(StopReason::ScanTimeLimit);
                    stop.cancel();
                }
            }

            // Watchdog: abandon workers stuck on one file far past its limit.
            for id in 0..workers.len() {
                if !workers[id].live {
                    continue;
                }
                let Some(path) = workers[id].slot.stalled_file(stall_limit) else {
                    continue;
                };
                workers[id].abandon();
                abandoned += 1;
                agg.issue(
                    ScanIssue {
                        path: Some(ObservedPath::from_path(&path)),
                        kind: IssueKind::Timeout,
                        detector: None,
                        message: format!(
                            "no result {}s after the {} ms per-file limit; the file was \
                             abandoned (a read may be blocked on a hung filesystem, or a \
                             detector ignored its deadline)",
                            STALL_GRACE.as_secs(),
                            limits.file_timeout_ms
                        ),
                        member: None,
                    },
                    &mut on_progress,
                );
                // Replace the worker, up to `n_workers` replacements in total,
                // so a handful of hung files cannot starve the scan. If the
                // spawn fails the scan continues with fewer workers; if none
                // remain, the checks below stop it and report unscanned work.
                if abandoned <= n_workers
                    && stop_reason.is_none()
                    && let Ok(w) = spawn_worker(workers.len(), &shared, &msg_tx)
                {
                    workers.push(w);
                }
            }
            if stop_reason.is_none() && workers.iter().all(|w| !w.live) && !walker_done {
                // Every worker is stalled and no replacements are allowed:
                // stop so the walker can finish.
                stop_reason = Some(StopReason::TooManyStalls);
                stop.cancel();
            }
        }
        drop(msg_rx);

        // Work left on the queue means every worker stalled before the queue
        // drained. Never report that as a completed scan.
        let unscanned = shared
            .enqueued
            .load(Ordering::Acquire)
            .saturating_sub(shared.dequeued.load(Ordering::Acquire));
        if unscanned > 0 && stop_reason.is_none() {
            stop_reason = Some(StopReason::TooManyStalls);
            agg.issue(
                ScanIssue {
                    path: None,
                    kind: IssueKind::Timeout,
                    detector: None,
                    message: format!(
                        "{unscanned} queued file(s) were not scanned because every worker \
                         stalled"
                    ),
                    member: None,
                },
                &mut on_progress,
            );
        }

        for w in workers {
            if let Some(h) = w.handle {
                panicked |= h.join().is_err();
            }
            // Abandoned workers have no handle: they are detached and exit
            // on their own once their blocked call returns.
        }
        if let Some(h) = walker {
            panicked |= h.join().is_err();
        }
        if let Some(e) = spawn_error {
            return Err(ScanError::ThreadSpawn(e));
        }
        if panicked {
            return Err(ScanError::ThreadPanicked);
        }

        let status = match stop_reason {
            None => ScanStatus::Completed,
            Some(StopReason::Cancelled) => ScanStatus::Cancelled,
            Some(StopReason::ScanTimeLimit | StopReason::TooManyStalls) => {
                ScanStatus::TimeLimitReached
            }
        };
        Ok(agg.finish(self, &targets, status, stop_reason, abandoned, started_at))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopReason {
    Cancelled,
    ScanTimeLimit,
    TooManyStalls,
}

struct StopOnDrop(CancellationToken);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// State shared by the walker and all workers for one scan.
struct Shared {
    config: ScanConfig,
    detectors: Vec<Arc<dyn Detector>>,
    infos: Vec<DetectorInfo>,
    reqs: Vec<DetectorRequirements>,
    /// Internal stop signal: user cancellation, scan time limit, or teardown.
    stop: CancellationToken,
    /// (device, inode) of files already scanned; only when following links.
    seen: Option<Mutex<HashSet<(u64, u64)>>>,
    work_rx: Mutex<Receiver<WorkItem>>,
    /// One capability handle per scan root (policy `skip` only).
    bases: Vec<Option<ScanBase>>,
    /// Files put on the work queue, and files taken from it. The difference
    /// when the scan ends is work that no worker picked up.
    enqueued: AtomicU64,
    dequeued: AtomicU64,
}

/// A file to scan and the index of the scan root it was found under.
type WorkItem = (usize, PathBuf);

/// Open the base for a scan root: the root itself, or the directory holding
/// it when the root is a single file. `None` if it cannot be opened; files
/// below it are then opened by path, as before.
fn open_base(root: &Path) -> Option<ScanBase> {
    let dir = if root.is_dir() { root } else { root.parent()? };
    ScanBase::open(dir).ok()
}

/// What one worker is doing, visible to the coordinator's watchdog.
#[derive(Default)]
struct Slot {
    current: Mutex<Option<(PathBuf, Instant)>>,
    abandoned: AtomicBool,
}

impl Slot {
    fn set(&self, value: Option<(PathBuf, Instant)>) {
        *lock(&self.current) = value;
    }

    fn stalled_file(&self, limit: Duration) -> Option<PathBuf> {
        lock(&self.current)
            .as_ref()
            .filter(|(_, since)| since.elapsed() > limit)
            .map(|(p, _)| p.clone())
    }
}

struct WorkerHandle {
    slot: Arc<Slot>,
    handle: Option<JoinHandle<()>>,
    live: bool,
}

impl WorkerHandle {
    fn abandon(&mut self) {
        self.slot.abandoned.store(true, Ordering::Release);
        self.live = false;
        // Detach: never join a thread that may be blocked indefinitely.
        self.handle = None;
    }
}

/// Lock, ignoring poisoning: the protected data stays valid if another thread
/// panicked while holding the lock.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn spawn_worker(
    id: usize,
    shared: &Arc<Shared>,
    msg_tx: &SyncSender<Msg>,
) -> io::Result<WorkerHandle> {
    let slot = Arc::new(Slot::default());
    let (shared, thread_slot, tx) = (Arc::clone(shared), Arc::clone(&slot), msg_tx.clone());
    let handle = thread::Builder::new()
        .name(format!("warden-worker-{id}"))
        .spawn(move || worker_main(id, &shared, &thread_slot, tx))?;
    Ok(WorkerHandle {
        slot,
        handle: Some(handle),
        live: true,
    })
}

#[derive(Clone, Copy, Debug)]
enum Who {
    Walker,
    Worker(usize),
}

/// Sends the thread's exit message when dropped, including during a panic.
struct ExitNotice {
    tx: SyncSender<Msg>,
    who: Who,
}

impl Drop for ExitNotice {
    fn drop(&mut self) {
        let _ = self.tx.send(Msg::Exited {
            who: self.who,
            panicked: thread::panicking(),
        });
    }
}

/// Resolved roots and excludes.
struct Targets {
    roots: Vec<PathBuf>,
    excludes: Vec<PathBuf>,
    issues: Vec<ScanIssue>,
}

fn resolve_targets(config: &ScanConfig) -> Targets {
    let mut issues = Vec::new();
    let mut resolved = Vec::new();
    for root in &config.roots {
        // Roots are resolved (links followed) regardless of symlink policy:
        // the user named them explicitly. The policy governs entries found
        // below them.
        match std::fs::canonicalize(root) {
            Ok(p) => resolved.push(p),
            Err(e) => issues.push(io_issue(Some(root), &e)),
        }
    }
    // Drop duplicate and nested roots so nothing is scanned twice. Path
    // ordering is component-wise, so a parent sorts before its children.
    resolved.sort();
    let mut roots: Vec<PathBuf> = Vec::with_capacity(resolved.len());
    for r in resolved {
        if !roots.iter().any(|kept| r.starts_with(kept)) {
            roots.push(r);
        }
    }

    let excludes = config
        .excludes
        .iter()
        .map(|p| {
            std::fs::canonicalize(p)
                .or_else(|_| std::path::absolute(p))
                .unwrap_or_else(|_| p.clone())
        })
        .collect();

    Targets {
        roots,
        excludes,
        issues,
    }
}

enum Msg {
    Directory,
    Scanned {
        path: PathBuf,
        bytes: u64,
        findings: Vec<Finding>,
        issues: Vec<ScanIssue>,
        /// Policy skips inside the file (content not inspected, archive
        /// limits), with the archive member chain if any.
        skips: Vec<(SkipReason, Option<Vec<ObservedPath>>)>,
        /// Archive members evaluated.
        members: u64,
    },
    Skipped {
        path: PathBuf,
        reason: SkipReason,
    },
    Issue(ScanIssue),
    Exited {
        who: Who,
        panicked: bool,
    },
}

fn walker_main(
    targets: &Targets,
    shared: &Shared,
    work_tx: &SyncSender<WorkItem>,
    tx: SyncSender<Msg>,
) {
    let _notice = ExitNotice {
        tx: tx.clone(),
        who: Who::Walker,
    };
    walk(targets, shared, work_tx, &tx);
}

/// Queue a path for the workers without blocking indefinitely: if the queue
/// stays full (e.g. every worker is stalled), give up once the scan stops.
fn enqueue(work_tx: &SyncSender<WorkItem>, path: WorkItem, shared: &Shared) -> bool {
    let mut item = path;
    loop {
        match work_tx.try_send(item) {
            Ok(()) => {
                shared.enqueued.fetch_add(1, Ordering::AcqRel);
                return true;
            }
            Err(TrySendError::Full(p)) => {
                if shared.stop.is_cancelled() {
                    return false;
                }
                item = p;
                thread::sleep(Duration::from_millis(2));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

fn walk(
    targets: &Targets,
    shared: &Shared,
    work_tx: &SyncSender<WorkItem>,
    msg_tx: &SyncSender<Msg>,
) {
    let config = &shared.config;
    let cancel = &shared.stop;
    let max_depth = config.limits.max_depth;
    for (root_idx, root) in targets.roots.iter().enumerate() {
        let mut entries = WalkDir::new(root)
            .follow_links(config.symlink_policy == SymlinkPolicy::Follow)
            .follow_root_links(true)
            .same_file_system(config.same_file_system)
            .max_depth(max_depth)
            .into_iter();

        loop {
            if cancel.is_cancelled() {
                return;
            }
            let Some(entry) = entries.next() else { break };
            let msg = match entry {
                Err(err) => Msg::Issue(walk_issue(&err)),
                Ok(entry) => {
                    let ft = entry.file_type();
                    if targets
                        .excludes
                        .iter()
                        .any(|ex| entry.path().starts_with(ex))
                    {
                        if ft.is_dir() {
                            entries.skip_current_dir();
                        }
                        Msg::Skipped {
                            path: entry.into_path(),
                            reason: SkipReason::Excluded,
                        }
                    } else if ft.is_file() {
                        if !enqueue(work_tx, (root_idx, entry.into_path()), shared) {
                            return;
                        }
                        continue;
                    } else if ft.is_dir() {
                        if msg_tx.send(Msg::Directory).is_err() {
                            return;
                        }
                        if entry.depth() < max_depth {
                            continue;
                        }
                        Msg::Skipped {
                            path: entry.into_path(),
                            reason: SkipReason::DepthLimitReached,
                        }
                    } else if ft.is_symlink() {
                        Msg::Skipped {
                            path: entry.into_path(),
                            reason: SkipReason::SymlinkNotFollowed,
                        }
                    } else {
                        Msg::Skipped {
                            path: entry.into_path(),
                            reason: SkipReason::NotRegularFile,
                        }
                    }
                }
            };
            if msg_tx.send(msg).is_err() {
                return;
            }
        }
    }
}

struct WorkerCtx<'a> {
    config: &'a ScanConfig,
    detectors: &'a [Arc<dyn Detector>],
    detector_infos: &'a [DetectorInfo],
    detector_reqs: &'a [DetectorRequirements],
    cancel: &'a CancellationToken,
    seen: Option<&'a Mutex<HashSet<(u64, u64)>>>,
    bases: &'a [Option<ScanBase>],
}

/// Per-worker content buffers keep at most this much capacity between files,
/// so an idle worker does not pin a `max_content_size` allocation.
const RETAINED_BUFFER_CAPACITY: usize = 8 * 1024 * 1024;

fn worker_main(id: usize, shared: &Shared, slot: &Slot, tx: SyncSender<Msg>) {
    let _notice = ExitNotice {
        tx: tx.clone(),
        who: Who::Worker(id),
    };
    let ctx = WorkerCtx {
        config: &shared.config,
        detectors: &shared.detectors,
        detector_infos: &shared.infos,
        detector_reqs: &shared.reqs,
        cancel: &shared.stop,
        seen: shared.seen.as_ref(),
        bases: &shared.bases,
    };
    let mut content = Vec::new();
    // Per-thread detector state, created once and reused for every file.
    let mut workers: Vec<Box<dyn DetectorWorker + '_>> =
        ctx.detectors.iter().map(|d| d.worker()).collect();
    loop {
        let next = lock(&shared.work_rx).recv();
        let Ok((root_idx, path)) = next else { return };
        shared.dequeued.fetch_add(1, Ordering::AcqRel);
        if ctx.cancel.is_cancelled() {
            // Keep draining so the walker is never blocked on a full queue.
            continue;
        }
        slot.set(Some((path.clone(), Instant::now())));
        let base = ctx.bases.get(root_idx).and_then(Option::as_ref);
        let msg = process_file(path, base, &ctx, &mut content, &mut workers);
        slot.set(None);
        content.clear();
        content.shrink_to(RETAINED_BUFFER_CAPACITY);
        // Abandoned while stuck: the file was already reported; take no more
        // work, since the coordinator no longer waits for this thread.
        if slot.abandoned.load(Ordering::Acquire) {
            return;
        }
        if let Some(msg) = msg
            && tx.send(msg).is_err()
        {
            return;
        }
    }
}

/// Everything a worker learned about one file on disk, including archive
/// members.
#[derive(Default)]
struct FileResult {
    findings: Vec<Finding>,
    issues: Vec<ScanIssue>,
    /// Policy skips inside this file, with the archive member chain if any.
    skips: Vec<(SkipReason, Option<Vec<ObservedPath>>)>,
    members: u64,
}

/// The scan was cancelled while evaluating.
struct Cancelled;

fn process_file<'d>(
    path: PathBuf,
    base: Option<&ScanBase>,
    ctx: &WorkerCtx<'d>,
    content: &mut Vec<u8>,
    workers: &mut [Box<dyn DetectorWorker + 'd>],
) -> Option<Msg> {
    let limits = &ctx.config.limits;
    let archives = &limits.archives;
    let deadline = Instant::now() + limits.file_timeout();
    let wants_content = ctx.detector_reqs.iter().any(|r| r.content);
    let opts = ReadOptions {
        policy: ctx.config.symlink_policy,
        max_size: limits.max_file_size,
        content_limit: (wants_content || archives.enabled).then_some(limits.max_content_size),
        deadline: Some(deadline),
        cancel: ctx.cancel,
        seen: ctx.seen,
        base,
        keep_only_archives: archives.enabled && !wants_content,
    };
    let read = match read_file(&path, &opts, content) {
        Ok(r) => r,
        Err(HashFileError::Cancelled) => return None,
        Err(HashFileError::Skipped(reason)) => return Some(Msg::Skipped { path, reason }),
        Err(HashFileError::Io(e)) => return Some(Msg::Issue(io_issue(Some(&path), &e))),
        Err(e @ HashFileError::TimedOut { .. }) => {
            return Some(Msg::Issue(ScanIssue {
                path: Some(ObservedPath::from_path(&path)),
                kind: IssueKind::Timeout,
                detector: None,
                message: format!(
                    "{e}; the {} ms per-file limit was reached, so the file was not evaluated",
                    limits.file_timeout_ms
                ),
                member: None,
            }));
        }
    };
    let hashed = &read.hashed;
    let data = read.has_content.then_some(content.as_slice());

    let mut out = FileResult::default();
    let observation = FileObservation {
        path: &path,
        sha256: &hashed.sha256,
        metadata: &hashed.metadata,
        content: data.filter(|_| wants_content),
        deadline,
        member: None,
    };
    if run_detectors(&observation, ctx, workers, &mut out).is_err() {
        return None;
    }

    if archives.enabled {
        match data {
            Some(bytes) if crate::archive::may_contain_zip(bytes) => {
                if expand_archive(&path, bytes, deadline, ctx, workers, &mut out).is_err() {
                    return None;
                }
            }
            None if read.zip_magic => out.skips.push((SkipReason::ArchiveTooLarge, None)),
            _ => {}
        }
    }

    Some(Msg::Scanned {
        bytes: hashed.metadata.size,
        path,
        findings: out.findings,
        issues: out.issues,
        skips: out.skips,
        members: out.members,
    })
}

/// Evaluate one observation (a file or an archive member) with every
/// detector, isolating panics and honouring the deadline.
fn run_detectors<'d>(
    obs: &FileObservation<'_>,
    ctx: &WorkerCtx<'d>,
    workers: &mut [Box<dyn DetectorWorker + 'd>],
    out: &mut FileResult,
) -> Result<(), Cancelled> {
    let limits = &ctx.config.limits;
    let member = || obs.member.map(<[ObservedPath]>::to_vec);
    let mut content_skipped = false;
    let detectors = ctx
        .detectors
        .iter()
        .zip(ctx.detector_infos)
        .zip(ctx.detector_reqs);
    for (i, ((detector, info), reqs)) in detectors.enumerate() {
        if ctx.cancel.is_cancelled() {
            return Err(Cancelled);
        }
        if Instant::now() >= obs.deadline {
            let not_run: Vec<&str> = ctx.detector_infos[i..]
                .iter()
                .map(|d| d.id.as_str())
                .collect();
            out.issues.push(ScanIssue {
                path: Some(ObservedPath::from_path(obs.path)),
                kind: IssueKind::Timeout,
                detector: None,
                message: format!(
                    "the {} ms per-file limit was reached; detectors not run: {}",
                    limits.file_timeout_ms,
                    not_run.join(", ")
                ),
                member: member(),
            });
            break;
        }
        if reqs.content && obs.content.is_none() {
            content_skipped = true;
            continue;
        }
        // Detectors parse untrusted content. A panic in one must not take
        // down the scan; it is recorded as a failure for this file only.
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| workers[i].inspect_file(obs)));
        let message = match outcome {
            Ok(Ok(found)) => {
                out.findings.extend(found);
                continue;
            }
            Ok(Err(e)) => e.message,
            Err(_) => {
                // The worker's state may be inconsistent after a panic.
                workers[i] = detector.worker();
                "detector panicked; its results for this file are missing".to_owned()
            }
        };
        out.issues.push(ScanIssue {
            path: Some(ObservedPath::from_path(obs.path)),
            kind: IssueKind::DetectorFailed,
            detector: Some(info.id.clone()),
            message,
            member: member(),
        });
    }
    if content_skipped {
        out.skips.push((SkipReason::ContentNotInspected, member()));
    }
    Ok(())
}

/// Expand an archive held in memory and evaluate every member with every
/// detector. The ZIP parser and decompressors run inside `catch_unwind`: a
/// panic on hostile input is reported, not fatal.
fn expand_archive<'d>(
    path: &Path,
    bytes: &[u8],
    deadline: Instant,
    ctx: &WorkerCtx<'d>,
    workers: &mut [Box<dyn DetectorWorker + 'd>],
    out: &mut FileResult,
) -> Result<(), Cancelled> {
    use crate::archive::{Event, Expander, Stop};

    let limits = &ctx.config.limits;
    let wants_content = ctx.detector_reqs.iter().any(|r| r.content);
    let observed = ObservedPath::from_path(path);
    let mut cancelled = false;
    let mut expander = Expander::new(&limits.archives, limits.max_file_size, deadline, ctx.cancel);
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        expander.expand_file(bytes, &mut |event| match event {
            Event::Member {
                chain,
                sha256,
                size,
                content,
            } => {
                out.members += 1;
                let metadata = warden_core::FileMetadata {
                    size,
                    modified: None,
                    unix_mode: None,
                };
                let obs = FileObservation {
                    path,
                    sha256: &sha256,
                    metadata: &metadata,
                    content: content.filter(|_| wants_content),
                    deadline,
                    member: Some(chain),
                };
                if run_detectors(&obs, ctx, workers, out).is_err() {
                    cancelled = true;
                }
            }
            Event::Skipped { chain, reason } => {
                out.skips
                    .push((reason, (!chain.is_empty()).then_some(chain)));
            }
            Event::Error { chain, message } => out.issues.push(ScanIssue {
                path: Some(observed.clone()),
                kind: IssueKind::ArchiveError,
                detector: None,
                message,
                member: (!chain.is_empty()).then_some(chain),
            }),
        })
    }));
    match result {
        Ok(Ok(())) => {}
        Ok(Err(Stop::Cancelled)) => return Err(Cancelled),
        Ok(Err(Stop::Deadline)) => out.issues.push(ScanIssue {
            path: Some(observed),
            kind: IssueKind::Timeout,
            detector: None,
            message: format!(
                "archive expansion stopped at the {} ms per-file limit; remaining members \
                 were not inspected",
                limits.file_timeout_ms
            ),
            member: None,
        }),
        Err(_) => out.issues.push(ScanIssue {
            path: Some(observed),
            kind: IssueKind::ArchiveError,
            detector: None,
            message: "the archive parser panicked; remaining members were not inspected".to_owned(),
            member: None,
        }),
    }
    if cancelled {
        return Err(Cancelled);
    }
    Ok(())
}

fn io_issue(path: Option<&Path>, e: &io::Error) -> ScanIssue {
    let kind = match e.kind() {
        io::ErrorKind::PermissionDenied => IssueKind::PermissionDenied,
        io::ErrorKind::NotFound => IssueKind::NotFound,
        _ => IssueKind::Io,
    };
    ScanIssue {
        path: path.map(ObservedPath::from_path),
        kind,
        detector: None,
        message: e.to_string(),
        member: None,
    }
}

fn walk_issue(err: &walkdir::Error) -> ScanIssue {
    if err.loop_ancestor().is_some() {
        return ScanIssue {
            path: err.path().map(ObservedPath::from_path),
            kind: IssueKind::FilesystemLoop,
            detector: None,
            message: err.to_string(),
            member: None,
        };
    }
    match err.io_error() {
        Some(io) => io_issue(err.path(), io),
        None => ScanIssue {
            path: err.path().map(ObservedPath::from_path),
            kind: IssueKind::Io,
            detector: None,
            message: err.to_string(),
            member: None,
        },
    }
}

/// Accumulates results on the caller's thread, enforcing recording limits.
struct Aggregator {
    stats: ScanStats,
    findings: Vec<Finding>,
    skipped: Vec<SkippedEntry>,
    issues: Vec<ScanIssue>,
    truncated: Truncation,
    max_entries: usize,
    max_findings: usize,
}

impl Aggregator {
    fn new(config: &ScanConfig) -> Self {
        Self {
            stats: ScanStats::default(),
            findings: Vec::new(),
            skipped: Vec::new(),
            issues: Vec::new(),
            truncated: Truncation::default(),
            max_entries: config.limits.max_recorded_entries,
            max_findings: config.limits.max_recorded_findings,
        }
    }

    fn handle<F>(&mut self, msg: Msg, on_progress: &mut F)
    where
        F: FnMut(&ProgressEvent<'_>, &ScanStats),
    {
        match msg {
            Msg::Directory => self.stats.directories_visited += 1,
            Msg::Scanned {
                path,
                bytes,
                findings,
                issues,
                skips,
                members,
            } => {
                self.stats.files_scanned += 1;
                self.stats.bytes_scanned += bytes;
                self.stats.archive_members_scanned += members;
                on_progress(
                    &ProgressEvent::FileScanned { path: &path, bytes },
                    &self.stats,
                );
                for f in findings {
                    self.finding(f, on_progress);
                }
                for i in issues {
                    self.issue(i, on_progress);
                }
                for (reason, member) in skips {
                    self.skip(&path, reason, member, on_progress);
                }
            }
            Msg::Skipped { path, reason } => self.skip(&path, reason, None, on_progress),
            Msg::Issue(issue) => self.issue(issue, on_progress),
            // Handled by the coordinator loop.
            Msg::Exited { .. } => {}
        }
    }

    fn skip<F>(
        &mut self,
        path: &Path,
        reason: SkipReason,
        member: Option<Vec<ObservedPath>>,
        on_progress: &mut F,
    ) where
        F: FnMut(&ProgressEvent<'_>, &ScanStats),
    {
        self.stats.entries_skipped += 1;
        *self.stats.skipped_by_reason.entry(reason).or_default() += 1;
        on_progress(&ProgressEvent::Skipped { path, reason }, &self.stats);
        if self.skipped.len() < self.max_entries {
            self.skipped.push(SkippedEntry {
                path: ObservedPath::from_path(path),
                reason,
                member,
            });
        } else {
            self.truncated.skipped_omitted += 1;
        }
    }

    fn finding<F>(&mut self, f: Finding, on_progress: &mut F)
    where
        F: FnMut(&ProgressEvent<'_>, &ScanStats),
    {
        self.stats.findings += 1;
        on_progress(&ProgressEvent::Finding(&f), &self.stats);
        if self.findings.len() < self.max_findings {
            self.findings.push(f);
        } else {
            self.truncated.findings_omitted += 1;
        }
    }

    fn issue<F>(&mut self, issue: ScanIssue, on_progress: &mut F)
    where
        F: FnMut(&ProgressEvent<'_>, &ScanStats),
    {
        self.stats.issues += 1;
        on_progress(&ProgressEvent::Issue(&issue), &self.stats);
        if self.issues.len() < self.max_entries {
            self.issues.push(issue);
        } else {
            self.truncated.issues_omitted += 1;
        }
    }

    fn finish(
        mut self,
        scanner: &Scanner,
        targets: &Targets,
        status: ScanStatus,
        stop_reason: Option<StopReason>,
        abandoned: usize,
        started_at: OffsetDateTime,
    ) -> ScanReport {
        // Worker completion order is nondeterministic; sort for stable output.
        self.findings.sort_by(|a, b| {
            (a.target.path(), &a.name, &a.source.rule_id).cmp(&(
                b.target.path(),
                &b.name,
                &b.source.rule_id,
            ))
        });
        self.skipped.sort_by(|a, b| a.path.cmp(&b.path));
        self.issues.sort_by(|a, b| a.path.cmp(&b.path));

        let config = &scanner.config;
        let mut warnings = Vec::new();
        if scanner.detectors.is_empty() {
            warnings.push(
                "No detectors were configured: files were enumerated and hashed but not evaluated \
                 for threats. The absence of findings means nothing."
                    .to_owned(),
            );
        }
        let unsigned: Vec<&str> = scanner
            .detector_infos
            .iter()
            .filter_map(|d| d.database.as_ref())
            .filter(|db| db.signer.is_none())
            .map(|db| db.name.as_str())
            .collect();
        if !unsigned.is_empty() {
            warnings.push(format!(
                "Detection content was loaded without signature verification: {}. Its \
                 authenticity is unknown.",
                unsigned.join(", ")
            ));
        }
        match stop_reason {
            Some(StopReason::Cancelled) => {
                warnings.push("The scan was cancelled; results are partial.".to_owned());
            }
            Some(StopReason::ScanTimeLimit) => warnings.push(format!(
                "The scan time limit ({} s) was reached; results are partial.",
                config.limits.scan_timeout_ms.unwrap_or(0) / 1000
            )),
            Some(StopReason::TooManyStalls) => warnings.push(
                "Too many files stalled past their time limit, so the scan was stopped; \
                 results are partial."
                    .to_owned(),
            ),
            None => {}
        }
        if abandoned > 0 {
            warnings.push(format!(
                "{abandoned} file(s) stalled and were abandoned (see timeout issues). Their \
                 threads may stay blocked in the background until the process exits."
            ));
        }
        if self.stats.issues > 0 {
            warnings.push(format!(
                "{} entries could not be fully scanned; coverage is incomplete (see issues).",
                self.stats.issues
            ));
        }
        if self.truncated.any() {
            warnings.push(
                "Recording limits were reached: some entries are counted in stats but not listed."
                    .to_owned(),
            );
        }
        if config.symlink_policy == SymlinkPolicy::Follow {
            warnings.push(
                "Symbolic links were followed; scanned files may lie outside the scan roots."
                    .to_owned(),
            );
        }

        ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            scan_id: Uuid::new_v4(),
            engine: EngineInfo {
                name: ENGINE_NAME.to_owned(),
                version: ENGINE_VERSION.to_owned(),
            },
            status,
            started_at,
            finished_at: OffsetDateTime::now_utc(),
            settings: ScanSettings {
                roots: targets
                    .roots
                    .iter()
                    .map(|p| ObservedPath::from_path(p))
                    .collect(),
                excludes: targets
                    .excludes
                    .iter()
                    .map(|p| ObservedPath::from_path(p))
                    .collect(),
                symlink_policy: config.symlink_policy,
                same_file_system: config.same_file_system,
                max_file_size: config.limits.max_file_size,
                max_depth: config.limits.max_depth,
                workers: config.workers,
                max_content_size: config.limits.max_content_size,
                file_timeout_ms: config.limits.file_timeout_ms,
                scan_timeout_ms: config.limits.scan_timeout_ms,
                archives: config.limits.archives,
            },
            detectors: scanner.detector_infos.clone(),
            stats: self.stats,
            findings: self.findings,
            skipped: self.skipped,
            issues: self.issues,
            truncated: self.truncated,
            content_bundles: Vec::new(),
            warnings,
        }
    }
}
