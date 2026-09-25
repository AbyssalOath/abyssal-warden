//! Scan orchestration.
//!
//! Threads (all scoped to one `scan` call):
//!
//! ```text
//!             work queue (bounded)            results (bounded)
//! walker ───────────────────────► workers ─────────────────────► caller thread
//!   │  (paths of regular files)   (open, hash, detect)             (aggregate,
//!   └──────────── directories / skips / walk errors ─────────────►  progress)
//! ```
//!
//! Both channels are bounded, so memory stays proportional to
//! `workers` rather than to the size of the tree. The caller's thread does
//! the aggregation and invokes the progress callback, so the callback needs
//! neither `Send` nor `Sync`.

use std::fmt;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use time::OffsetDateTime;
use uuid::Uuid;
use walkdir::WalkDir;
use warden_core::{
    CancellationToken, ConfigError, Detector, DetectorInfo, DetectorRequirements, DetectorWorker,
    EngineInfo, FileObservation, Finding, IssueKind, ObservedPath, REPORT_SCHEMA_VERSION,
    ScanConfig, ScanIssue, ScanReport, ScanSettings, ScanStats, ScanStatus, SkipReason,
    SkippedEntry, SymlinkPolicy, Truncation,
};

use crate::fsio::{HashFileError, ReadOptions, read_file};
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

/// A configured scanner: validated settings plus the detectors to run.
pub struct Scanner {
    config: ScanConfig,
    detectors: Vec<Box<dyn Detector>>,
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
        self.detectors.push(detector);
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub fn detectors(&self) -> &[DetectorInfo] {
        &self.detector_infos
    }

    /// Run a scan to completion or until `cancel` is triggered.
    ///
    /// Returns a report in both cases; a cancelled scan has
    /// [`ScanStatus::Cancelled`] and partial results.
    pub fn scan<F>(
        &self,
        cancel: &CancellationToken,
        mut on_progress: F,
    ) -> Result<ScanReport, ScanError>
    where
        F: FnMut(&ProgressEvent<'_>, &ScanStats),
    {
        let started_at = OffsetDateTime::now_utc();
        let targets = resolve_targets(&self.config);
        let mut agg = Aggregator::new(&self.config);
        for issue in targets.issues.iter().cloned() {
            agg.issue(issue, &mut on_progress);
        }

        let workers = self.config.workers;
        let (work_tx, work_rx) = mpsc::sync_channel::<PathBuf>(workers * 16);
        let (msg_tx, msg_rx) = mpsc::sync_channel::<Msg>(256);
        let work_rx = Arc::new(Mutex::new(work_rx));

        thread::scope(|s| {
            let mut handles = Vec::with_capacity(workers + 1);
            let mut spawn_error = None;

            for i in 0..workers {
                let ctx = WorkerCtx {
                    config: &self.config,
                    detectors: &self.detectors,
                    detector_infos: &self.detector_infos,
                    detector_reqs: &self.detector_reqs,
                    cancel,
                };
                let rx = Arc::clone(&work_rx);
                let tx = msg_tx.clone();
                match thread::Builder::new()
                    .name(format!("warden-worker-{i}"))
                    .spawn_scoped(s, move || worker_loop(&rx, &tx, &ctx))
                {
                    Ok(h) => handles.push(h),
                    Err(e) => {
                        spawn_error = Some(e);
                        break;
                    }
                }
            }
            // Workers hold the only remaining receiver handles, so the
            // walker's sends fail (and it stops) if every worker exits.
            drop(work_rx);

            if spawn_error.is_none() {
                let tx = msg_tx.clone();
                let targets = &targets;
                let config = &self.config;
                match thread::Builder::new()
                    .name("warden-walker".into())
                    .spawn_scoped(s, move || walk(targets, config, cancel, &work_tx, &tx))
                {
                    Ok(h) => handles.push(h),
                    Err(e) => spawn_error = Some(e),
                }
            } else {
                drop(work_tx);
            }
            drop(msg_tx);

            // Drain until every sender is gone: this is what guarantees that
            // no thread stays blocked on a full channel.
            for msg in msg_rx {
                agg.handle(msg, &mut on_progress);
            }

            let panicked = handles.into_iter().any(|h| h.join().is_err());
            match (spawn_error, panicked) {
                (Some(e), _) => Err(ScanError::ThreadSpawn(e)),
                (None, true) => Err(ScanError::ThreadPanicked),
                (None, false) => Ok(()),
            }
        })?;

        let status = if cancel.is_cancelled() {
            ScanStatus::Cancelled
        } else {
            ScanStatus::Completed
        };
        Ok(agg.finish(self, &targets, status, started_at))
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
        /// Content detectors were skipped because the file exceeds the
        /// content limit.
        content_skipped: bool,
    },
    Skipped {
        path: PathBuf,
        reason: SkipReason,
    },
    Issue(ScanIssue),
}

fn walk(
    targets: &Targets,
    config: &ScanConfig,
    cancel: &CancellationToken,
    work_tx: &SyncSender<PathBuf>,
    msg_tx: &SyncSender<Msg>,
) {
    let max_depth = config.limits.max_depth;
    for root in &targets.roots {
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
                        if work_tx.send(entry.into_path()).is_err() {
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
    detectors: &'a [Box<dyn Detector>],
    detector_infos: &'a [DetectorInfo],
    detector_reqs: &'a [DetectorRequirements],
    cancel: &'a CancellationToken,
}

/// Per-worker content buffers keep at most this much capacity between files,
/// so an idle worker does not pin a `max_content_size` allocation.
const RETAINED_BUFFER_CAPACITY: usize = 8 * 1024 * 1024;

fn worker_loop(rx: &Mutex<Receiver<PathBuf>>, tx: &SyncSender<Msg>, ctx: &WorkerCtx<'_>) {
    let mut content = Vec::new();
    // Per-thread detector state, created once and reused for every file.
    let mut workers: Vec<Box<dyn DetectorWorker + '_>> =
        ctx.detectors.iter().map(|d| d.worker()).collect();
    loop {
        // A poisoned lock only means another worker panicked while waiting;
        // the receiver itself is still usable.
        let next = match rx.lock() {
            Ok(guard) => guard.recv(),
            Err(poisoned) => poisoned.into_inner().recv(),
        };
        let Ok(path) = next else { return };
        if ctx.cancel.is_cancelled() {
            // Keep draining so the walker is never blocked on a full queue.
            continue;
        }
        let msg = process_file(path, ctx, &mut content, &mut workers);
        content.clear();
        content.shrink_to(RETAINED_BUFFER_CAPACITY);
        if let Some(msg) = msg
            && tx.send(msg).is_err()
        {
            return;
        }
    }
}

fn process_file<'d>(
    path: PathBuf,
    ctx: &WorkerCtx<'d>,
    content: &mut Vec<u8>,
    workers: &mut [Box<dyn DetectorWorker + 'd>],
) -> Option<Msg> {
    let limits = &ctx.config.limits;
    let deadline = Instant::now() + limits.file_timeout();
    let wants_content = ctx.detector_reqs.iter().any(|r| r.content);
    let opts = ReadOptions {
        policy: ctx.config.symlink_policy,
        max_size: limits.max_file_size,
        content_limit: wants_content.then_some(limits.max_content_size),
        deadline: Some(deadline),
        cancel: ctx.cancel,
    };
    let (hashed, has_content) = match read_file(&path, &opts, content) {
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
            }));
        }
    };

    let observation = FileObservation {
        path: &path,
        sha256: &hashed.sha256,
        metadata: &hashed.metadata,
        content: has_content.then_some(content.as_slice()),
        deadline,
    };
    let mut findings = Vec::new();
    let mut issues = Vec::new();
    let mut content_skipped = false;
    let detectors = ctx
        .detectors
        .iter()
        .zip(ctx.detector_infos)
        .zip(ctx.detector_reqs);
    for (i, ((detector, info), reqs)) in detectors.enumerate() {
        if ctx.cancel.is_cancelled() {
            return None;
        }
        if Instant::now() >= deadline {
            let not_run: Vec<&str> = ctx.detector_infos[i..]
                .iter()
                .map(|d| d.id.as_str())
                .collect();
            issues.push(ScanIssue {
                path: Some(ObservedPath::from_path(&path)),
                kind: IssueKind::Timeout,
                detector: None,
                message: format!(
                    "the {} ms per-file limit was reached; detectors not run: {}",
                    limits.file_timeout_ms,
                    not_run.join(", ")
                ),
            });
            break;
        }
        if reqs.content && observation.content.is_none() {
            content_skipped = true;
            continue;
        }
        // Detectors parse untrusted content. A panic in one must not take
        // down the scan; it is recorded as a failure for this file only.
        let outcome =
            panic::catch_unwind(AssertUnwindSafe(|| workers[i].inspect_file(&observation)));
        let message = match outcome {
            Ok(Ok(found)) => {
                findings.extend(found);
                continue;
            }
            Ok(Err(e)) => e.message,
            Err(_) => {
                // The worker's state may be inconsistent after a panic.
                workers[i] = detector.worker();
                "detector panicked; its results for this file are missing".to_owned()
            }
        };
        issues.push(ScanIssue {
            path: Some(ObservedPath::from_path(&path)),
            kind: IssueKind::DetectorFailed,
            detector: Some(info.id.clone()),
            message,
        });
    }

    Some(Msg::Scanned {
        bytes: hashed.metadata.size,
        path,
        findings,
        issues,
        content_skipped,
    })
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
    }
}

fn walk_issue(err: &walkdir::Error) -> ScanIssue {
    if err.loop_ancestor().is_some() {
        return ScanIssue {
            path: err.path().map(ObservedPath::from_path),
            kind: IssueKind::FilesystemLoop,
            detector: None,
            message: err.to_string(),
        };
    }
    match err.io_error() {
        Some(io) => io_issue(err.path(), io),
        None => ScanIssue {
            path: err.path().map(ObservedPath::from_path),
            kind: IssueKind::Io,
            detector: None,
            message: err.to_string(),
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
                content_skipped,
            } => {
                self.stats.files_scanned += 1;
                self.stats.bytes_scanned += bytes;
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
                if content_skipped {
                    self.skip(&path, SkipReason::ContentNotInspected, on_progress);
                }
            }
            Msg::Skipped { path, reason } => self.skip(&path, reason, on_progress),
            Msg::Issue(issue) => self.issue(issue, on_progress),
        }
    }

    fn skip<F>(&mut self, path: &Path, reason: SkipReason, on_progress: &mut F)
    where
        F: FnMut(&ProgressEvent<'_>, &ScanStats),
    {
        self.stats.entries_skipped += 1;
        *self.stats.skipped_by_reason.entry(reason).or_default() += 1;
        on_progress(&ProgressEvent::Skipped { path, reason }, &self.stats);
        if self.skipped.len() < self.max_entries {
            self.skipped.push(SkippedEntry {
                path: ObservedPath::from_path(path),
                reason,
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
        if status == ScanStatus::Cancelled {
            warnings.push("The scan was cancelled; results are partial.".to_owned());
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
            },
            detectors: scanner.detector_infos.clone(),
            stats: self.stats,
            findings: self.findings,
            skipped: self.skipped,
            issues: self.issues,
            truncated: self.truncated,
            warnings,
        }
    }
}
