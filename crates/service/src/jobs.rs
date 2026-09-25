//! Job queue, workers and result processing.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use warden_core::{RemediationStatus, ScanReport, ScanStatus};
use warden_ipc::{ErrorCode, JobKind, JobState, JobSummary, Rejection};

use crate::config::ServiceConfig;
use crate::log;
use crate::runner::{self, Identity};
use crate::store::Store;

/// Most output accepted from one child.
const MAX_OUTPUT: usize = 256 << 20;
/// Jobs listed at most per request.
const MAX_LISTED: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunAs {
    /// The scanner account with read-everything capability (Unix), or the
    /// service account (Windows).
    Service,
    /// The requesting user (uid, primary gid). Unix only.
    #[cfg(unix)]
    Caller { uid: u32, gid: u32 },
}

impl RunAs {
    fn is_caller(self) -> bool {
        #[cfg(unix)]
        if let Self::Caller { .. } = self {
            return true;
        }
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JobSpec {
    pub(crate) kind: JobKind,
    pub(crate) paths: Vec<String>,
    pub(crate) heuristics: bool,
    pub(crate) no_archives: bool,
    pub(crate) quarantine: bool,
    pub(crate) run_as: RunAs,
}

/// How children are started.
#[derive(Clone, Debug)]
pub(crate) struct Environment {
    pub(crate) cfg: Arc<ServiceConfig>,
    pub(crate) binary: PathBuf,
    /// Present when the service runs as root.
    pub(crate) setpriv: Option<PathBuf>,
    /// Scanner account (uid, gid), when the service runs as root.
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) scanner: Option<(u32, u32)>,
}

#[derive(Default)]
struct State {
    jobs: BTreeMap<Uuid, JobSummary>,
    specs: HashMap<Uuid, JobSpec>,
    queue: VecDeque<Uuid>,
    cancels: HashMap<Uuid, Arc<AtomicBool>>,
    shutdown: bool,
}

pub(crate) struct Manager {
    state: Mutex<State>,
    wake: Condvar,
    store: Store,
    env: Environment,
}

impl Manager {
    /// Loads the history. Jobs that were queued or running when the service
    /// stopped are marked failed.
    pub(crate) fn new(store: Store, env: Environment) -> Arc<Self> {
        let (jobs, errors) = store.load_jobs();
        for e in errors {
            log(&format!("ignoring unreadable job record {e}"));
        }
        let mut state = State::default();
        for mut j in jobs {
            if !j.state.finished() {
                j.state = JobState::Failed;
                j.error = Some("interrupted: the service stopped".into());
                j.finished_at = Some(OffsetDateTime::now_utc());
                let _ = store.save_job(&j);
            }
            state.jobs.insert(j.id, j);
        }
        Arc::new(Self {
            state: Mutex::new(state),
            wake: Condvar::new(),
            store,
            env,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn start_workers(self: &Arc<Self>) -> Vec<std::thread::JoinHandle<()>> {
        (0..self.env.cfg.max_concurrent_jobs)
            .map(|i| {
                let me = Arc::clone(self);
                std::thread::Builder::new()
                    .name(format!("job-worker-{i}"))
                    .spawn(move || me.worker())
                    .unwrap_or_else(|e| panic!("cannot start worker thread: {e}"))
            })
            .collect()
    }

    pub(crate) fn submit(
        &self,
        owner: String,
        schedule: Option<String>,
        spec: JobSpec,
    ) -> Result<Uuid, Rejection> {
        let mut st = self.lock();
        if st.shutdown {
            return Err(Rejection::new(
                ErrorCode::Busy,
                "the service is shutting down",
            ));
        }
        if st.queue.len() >= self.env.cfg.max_queued_jobs as usize {
            return Err(Rejection::new(
                ErrorCode::Busy,
                "too many queued jobs; try again later",
            ));
        }
        let id = Uuid::new_v4();
        let summary = JobSummary {
            id,
            kind: spec.kind,
            state: JobState::Queued,
            owner,
            schedule,
            paths: spec.paths.clone(),
            heuristics: spec.heuristics,
            quarantine: spec.quarantine,
            as_owner: spec.run_as.is_caller(),
            created_at: OffsetDateTime::now_utc(),
            started_at: None,
            finished_at: None,
            exit_code: None,
            findings: None,
            quarantined: None,
            error: None,
        };
        self.store
            .save_job(&summary)
            .map_err(|e| Rejection::new(ErrorCode::Internal, e))?;
        st.jobs.insert(id, summary);
        st.specs.insert(id, spec);
        st.queue.push_back(id);
        drop(st);
        self.wake.notify_one();
        Ok(id)
    }

    pub(crate) fn get(&self, id: Uuid) -> Option<JobSummary> {
        self.lock().jobs.get(&id).cloned()
    }

    /// Jobs matching `visible`, newest first.
    pub(crate) fn list(&self, visible: impl Fn(&JobSummary) -> bool) -> Vec<JobSummary> {
        let st = self.lock();
        let mut v: Vec<JobSummary> = st.jobs.values().filter(|j| visible(j)).cloned().collect();
        v.sort_by_key(|j| std::cmp::Reverse(j.created_at));
        v.truncate(MAX_LISTED);
        v
    }

    pub(crate) fn counts(&self) -> (u32, u32) {
        let st = self.lock();
        (st.cancels.len() as u32, st.queue.len() as u32)
    }

    pub(crate) fn report(&self, id: Uuid) -> Result<Option<serde_json::Value>, String> {
        self.store.report(id)
    }

    pub(crate) fn cancel(&self, id: Uuid) -> Result<(), Rejection> {
        let mut st = self.lock();
        if let Some(flag) = st.cancels.get(&id) {
            flag.store(true, Ordering::SeqCst);
            return Ok(());
        }
        if let Some(pos) = st.queue.iter().position(|q| *q == id) {
            st.queue.remove(pos);
            st.specs.remove(&id);
            if let Some(j) = st.jobs.get_mut(&id) {
                j.state = JobState::Cancelled;
                j.finished_at = Some(OffsetDateTime::now_utc());
                let _ = self.store.save_job(j);
            }
            return Ok(());
        }
        Err(Rejection::new(
            ErrorCode::NotFound,
            "the job is not queued or running",
        ))
    }

    /// Stops accepting work, cancels running jobs and wakes the workers.
    pub(crate) fn shutdown(&self) {
        let mut st = self.lock();
        st.shutdown = true;
        for flag in st.cancels.values() {
            flag.store(true, Ordering::SeqCst);
        }
        drop(st);
        self.wake.notify_all();
    }

    fn worker(self: Arc<Self>) {
        loop {
            let (id, spec, cancel) = {
                let mut st = self.lock();
                loop {
                    if st.shutdown {
                        return;
                    }
                    if let Some(id) = st.queue.pop_front() {
                        let Some(spec) = st.specs.remove(&id) else {
                            continue;
                        };
                        let cancel = Arc::new(AtomicBool::new(false));
                        st.cancels.insert(id, Arc::clone(&cancel));
                        if let Some(j) = st.jobs.get_mut(&id) {
                            j.state = JobState::Running;
                            j.started_at = Some(OffsetDateTime::now_utc());
                            let _ = self.store.save_job(j);
                        }
                        break (id, spec, cancel);
                    }
                    st = self
                        .wake
                        .wait(st)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            };
            let result = self.execute(id, &spec, &cancel);
            let mut st = self.lock();
            st.cancels.remove(&id);
            if let Some(j) = st.jobs.get_mut(&id) {
                j.finished_at = Some(OffsetDateTime::now_utc());
                result.apply(j);
                if let Err(e) = self.store.save_job(j) {
                    log(&format!("cannot save job {id}: {e}"));
                }
                log(&format!("job {id} ({:?}) finished: {:?}", j.kind, j.state));
            }
            let all: Vec<JobSummary> = st.jobs.values().cloned().collect();
            for removed in self.store.prune(&all, self.env.cfg.history_limit as usize) {
                st.jobs.remove(&removed);
            }
        }
    }

    #[cfg(windows)]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn identity(&self, _spec: &JobSpec) -> Result<Identity, String> {
        Ok(Identity::Inherit)
    }

    #[cfg(unix)]
    fn identity(&self, spec: &JobSpec) -> Result<Identity, String> {
        let caps = match spec.kind {
            JobKind::Scan => runner::SCAN_CAPS,
            JobKind::SystemCheck => runner::SYSTEM_CHECK_CAPS,
        };
        match (spec.run_as, self.env.scanner) {
            (RunAs::Service, Some((uid, gid))) => Ok(Identity::Account { uid, gid, caps }),
            (RunAs::Caller { uid, gid }, Some(_)) => Ok(Identity::User { uid, gid }),
            (RunAs::Service, None) => Ok(Identity::Inherit),
            (RunAs::Caller { uid, .. }, None) if uid == rustix::process::geteuid().as_raw() => {
                Ok(Identity::Inherit)
            }
            (RunAs::Caller { .. }, None) => {
                Err("the service is not running as root, so it cannot scan as another user".into())
            }
        }
    }

    fn execute(&self, id: Uuid, spec: &JobSpec, cancel: &AtomicBool) -> JobResult {
        let identity = match self.identity(spec) {
            Ok(i) => i,
            Err(e) => return JobResult::failed(e),
        };
        #[cfg(unix)]
        let (who, child_dir) = {
            let (uid, gid) = match identity {
                Identity::Account { uid, gid, .. } | Identity::User { uid, gid } => (uid, gid),
                Identity::Inherit => (
                    rustix::process::geteuid().as_raw(),
                    rustix::process::getegid().as_raw(),
                ),
            };
            (format!("uid {uid}"), self.store.child_dir(uid, gid))
        };
        #[cfg(windows)]
        let (who, child_dir) = ("the service account".to_owned(), self.store.child_dir());
        let child_dir = match child_dir {
            Ok(d) => d,
            Err(e) => {
                return JobResult::failed(format!("cannot prepare the job's state directory: {e}"));
            }
        };
        let timeout_secs = u64::from(self.env.cfg.job_timeout_minutes) * 60;
        let args = child_args(
            spec,
            &self.env.cfg,
            &child_dir.join("content-state.json"),
            timeout_secs,
        );
        let cmd = match runner::command(
            self.env.setpriv.as_deref(),
            &self.env.binary,
            &identity,
            &args,
        ) {
            Ok(c) => c,
            Err(e) => return JobResult::failed(e),
        };
        log(&format!("job {id}: starting {:?} as {who}", spec.kind));
        let outcome = match runner::run(
            cmd,
            Duration::from_secs(timeout_secs + 60),
            cancel,
            MAX_OUTPUT,
        ) {
            Ok(o) => o,
            Err(e) => return JobResult::failed(e),
        };
        if outcome.cancelled {
            return JobResult {
                state: JobState::Cancelled,
                exit_code: outcome.exit_code,
                ..JobResult::default()
            };
        }
        if outcome.timed_out {
            return JobResult {
                state: JobState::TimedOut,
                error: Some(format!(
                    "killed after {} minutes",
                    self.env.cfg.job_timeout_minutes + 1
                )),
                ..JobResult::default()
            };
        }
        let stderr = || crate::sanitize(outcome.stderr_tail.trim());
        if outcome.exit_code == Some(2) || outcome.exit_code.is_none() || outcome.stdout_truncated {
            return JobResult {
                exit_code: outcome.exit_code,
                ..JobResult::failed(if outcome.stdout_truncated {
                    "report larger than 256 MiB".into()
                } else {
                    stderr()
                })
            };
        }
        let mut result = JobResult {
            state: JobState::Completed,
            exit_code: outcome.exit_code,
            ..JobResult::default()
        };
        let report_bytes = match spec.kind {
            JobKind::Scan => match serde_json::from_slice::<ScanReport>(&outcome.stdout) {
                Ok(mut report) => {
                    self.remediate(spec, &mut report, &mut result);
                    result.findings = Some(
                        report
                            .findings
                            .iter()
                            .filter(|f| f.remediation_status != RemediationStatus::Allowed)
                            .count() as u64,
                    );
                    serde_json::to_vec(&report).unwrap_or_default()
                }
                Err(e) => {
                    return JobResult::failed(format!("unreadable scan report: {e}; {}", stderr()));
                }
            },
            JobKind::SystemCheck => {
                match serde_json::from_slice::<serde_json::Value>(&outcome.stdout) {
                    Ok(v) => {
                        result.findings = v
                            .get("findings")
                            .and_then(|f| f.as_array())
                            .map(|a| a.len() as u64);
                        outcome.stdout.clone()
                    }
                    Err(e) => {
                        return JobResult::failed(format!(
                            "unreadable system report: {e}; {}",
                            stderr()
                        ));
                    }
                }
            }
        };
        if let Err(e) = self.store.save_report(id, &report_bytes) {
            result.error = Some(format!("report not saved: {e}"));
        }
        result
    }

    /// Applies the system allow-list and, when requested, quarantines
    /// confirmed malware. Runs in the service (as root), never in the child.
    fn remediate(&self, spec: &JobSpec, report: &mut ScanReport, result: &mut JobResult) {
        let store_path = &self.env.cfg.quarantine_store;
        if store_path.exists() {
            match warden_remediation::read_allowlist(store_path) {
                Ok(entries) => {
                    warden_remediation::mark_allowed(report, &entries);
                }
                Err(e) => report.warnings.push(format!("allow-list not applied: {e}")),
            }
        }
        if !spec.quarantine {
            return;
        }
        if report.status != ScanStatus::Completed {
            report
                .warnings
                .push("the scan did not complete; nothing was quarantined".into());
            return;
        }
        let max = report.settings.max_file_size;
        let errors = warden_remediation::quarantine_report(
            report,
            || warden_remediation::QuarantineStore::open(store_path).map_err(|e| e.to_string()),
            max,
            false,
        );
        for e in &errors {
            log(&format!("quarantine failed: {}", crate::sanitize(e)));
        }
        result.quarantined = Some(
            report
                .findings
                .iter()
                .filter(|f| f.remediation_status == RemediationStatus::Quarantined)
                .count() as u64,
        );
    }
}

/// Arguments for the `abyssal-warden` child.
pub(crate) fn child_args(
    spec: &JobSpec,
    cfg: &ServiceConfig,
    state_file: &Path,
    timeout_secs: u64,
) -> Vec<OsString> {
    let content = &cfg.content;
    let mut a: Vec<OsString> = Vec::new();
    match spec.kind {
        JobKind::Scan => {
            a.extend(
                [
                    "scan",
                    "--format",
                    "json",
                    "--no-progress",
                    "--no-allowlist",
                ]
                .map(OsString::from),
            );
            a.push("--scan-timeout".into());
            a.push(timeout_secs.to_string().into());
            if spec.no_archives {
                a.push("--no-archives".into());
            }
        }
        JobKind::SystemCheck => {
            a.extend(["system-check", "--format", "json"].map(OsString::from));
        }
    }
    if spec.heuristics {
        a.push("--heuristics".into());
    }
    for c in content {
        a.push("--content".into());
        a.push(c.clone().into());
    }
    for k in &cfg.keyrings {
        a.push("--keyring".into());
        a.push(k.clone().into());
    }
    if !content.is_empty() {
        a.push("--content-state".into());
        a.push(state_file.into());
    }
    if spec.kind == JobKind::Scan {
        a.push("--".into());
        a.extend(spec.paths.iter().map(OsString::from));
    }
    a
}

#[derive(Debug)]
struct JobResult {
    state: JobState,
    exit_code: Option<i32>,
    findings: Option<u64>,
    quarantined: Option<u64>,
    error: Option<String>,
}

impl Default for JobResult {
    fn default() -> Self {
        Self {
            state: JobState::Failed,
            exit_code: None,
            findings: None,
            quarantined: None,
            error: None,
        }
    }
}

impl JobResult {
    fn failed(e: String) -> Self {
        Self {
            error: Some(e),
            ..Self::default()
        }
    }

    fn apply(self, j: &mut JobSummary) {
        j.state = self.state;
        j.exit_code = self.exit_code;
        j.findings = self.findings;
        j.quarantined = self.quarantined;
        j.error = self.error;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_arguments_put_paths_after_the_separator() {
        let spec = JobSpec {
            kind: JobKind::Scan,
            paths: vec!["/home/--quarantine".into()],
            heuristics: true,
            no_archives: true,
            quarantine: true,
            run_as: RunAs::Service,
        };
        let cfg = ServiceConfig {
            content: vec![PathBuf::from("/usr/share/aw")],
            keyrings: vec![PathBuf::from("/etc/k.json")],
            ..ServiceConfig::default()
        };
        let a: Vec<String> = child_args(&spec, &cfg, Path::new("/s/cs.json"), 60)
            .into_iter()
            .map(|s| s.into_string().unwrap_or_default())
            .collect();
        assert_eq!(
            a,
            [
                "scan",
                "--format",
                "json",
                "--no-progress",
                "--no-allowlist",
                "--scan-timeout",
                "60",
                "--no-archives",
                "--heuristics",
                "--content",
                "/usr/share/aw",
                "--keyring",
                "/etc/k.json",
                "--content-state",
                "/s/cs.json",
                "--",
                "/home/--quarantine"
            ]
        );
        // The child never quarantines; the service does, after reading the report.
        assert!(!a[..a.len() - 1].contains(&"--quarantine".to_owned()));
        let sys = JobSpec {
            kind: JobKind::SystemCheck,
            paths: vec![],
            quarantine: false,
            ..spec
        };
        let a: Vec<String> = child_args(&sys, &ServiceConfig::default(), Path::new("/x"), 60)
            .into_iter()
            .map(|s| s.into_string().unwrap_or_default())
            .collect();
        assert_eq!(a, ["system-check", "--format", "json", "--heuristics"]);
    }
}
