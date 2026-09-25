//! Persistent job history: `jobs/<id>.json` (summaries) and
//! `reports/<id>.json` (full reports), plus scheduler and audit state.
//! Everything is written atomically, files 0600 in 0700 directories.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use uuid::Uuid;
use warden_ipc::{AuditStatus, JobSummary};

const MAX_REPORT_READ: u64 = warden_ipc::MAX_RESPONSE as u64 / 2;

#[derive(Debug)]
pub(crate) struct Store {
    dir: PathBuf,
}

fn private_dir(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let euid = rustix::process::geteuid().as_raw();
    if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} must be a directory owned by uid {euid} with mode 0700 (owner {}, mode {:04o})",
            path.display(),
            meta.uid(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Atomically replaces `path` with `data` (0600).
pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("no parent directory")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    tmp.write_all(data).map_err(|e| e.to_string())?;
    tmp.as_file().sync_all().map_err(|e| e.to_string())?;
    tmp.persist(path).map_err(|e| e.error.to_string())?;
    Ok(())
}

impl Store {
    pub(crate) fn open(dir: &Path) -> Result<Self, String> {
        for sub in ["", "jobs", "reports"] {
            private_dir(&dir.join(sub))?;
        }
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    fn job_path(&self, id: Uuid) -> PathBuf {
        self.dir.join("jobs").join(format!("{id}.json"))
    }

    fn report_path(&self, id: Uuid) -> PathBuf {
        self.dir.join("reports").join(format!("{id}.json"))
    }

    pub(crate) fn save_job(&self, job: &JobSummary) -> Result<(), String> {
        let data = serde_json::to_vec_pretty(job).map_err(|e| e.to_string())?;
        write_private(&self.job_path(job.id), &data)
    }

    pub(crate) fn save_report(&self, id: Uuid, data: &[u8]) -> Result<(), String> {
        write_private(&self.report_path(id), data)
    }

    pub(crate) fn report(&self, id: Uuid) -> Result<Option<serde_json::Value>, String> {
        use std::io::Read;
        let path = self.report_path(id);
        let f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let mut data = Vec::new();
        f.take(MAX_REPORT_READ)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        serde_json::from_slice(&data)
            .map(Some)
            .map_err(|e| e.to_string())
    }

    /// Every stored job; unreadable files are skipped and reported.
    pub(crate) fn load_jobs(&self) -> (Vec<JobSummary>, Vec<String>) {
        let mut jobs = Vec::new();
        let mut errors = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.dir.join("jobs")) else {
            return (jobs, errors);
        };
        for e in entries.flatten().take(1_000_000) {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            match std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|d| serde_json::from_slice::<JobSummary>(&d).map_err(|e| e.to_string()))
            {
                Ok(j) => jobs.push(j),
                Err(err) => errors.push(format!("{}: {err}", path.display())),
            }
        }
        jobs.sort_by_key(|j| j.created_at);
        (jobs, errors)
    }

    /// Deletes the oldest finished jobs beyond `keep`; returns the removed ids.
    pub(crate) fn prune(&self, jobs: &[JobSummary], keep: usize) -> Vec<Uuid> {
        let finished: Vec<&JobSummary> = jobs.iter().filter(|j| j.state.finished()).collect();
        let excess = finished.len().saturating_sub(keep);
        let mut removed = Vec::new();
        for j in finished.iter().take(excess) {
            let _ = std::fs::remove_file(self.report_path(j.id));
            if std::fs::remove_file(self.job_path(j.id)).is_ok() {
                removed.push(j.id);
            }
        }
        removed
    }

    pub(crate) fn schedule_state(&self) -> BTreeMap<String, OffsetDateTime> {
        #[derive(serde::Deserialize)]
        struct Entry(#[serde(with = "time::serde::rfc3339")] OffsetDateTime);
        std::fs::read(self.dir.join("schedules.json"))
            .ok()
            .and_then(|d| serde_json::from_slice::<BTreeMap<String, Entry>>(&d).ok())
            .map(|m| m.into_iter().map(|(k, v)| (k, v.0)).collect())
            .unwrap_or_default()
    }

    pub(crate) fn save_schedule_state(
        &self,
        state: &BTreeMap<String, OffsetDateTime>,
    ) -> Result<(), String> {
        let m: BTreeMap<&String, String> = state
            .iter()
            .map(|(k, v)| {
                (
                    k,
                    v.format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                )
            })
            .collect();
        write_private(
            &self.dir.join("schedules.json"),
            &serde_json::to_vec_pretty(&m).map_err(|e| e.to_string())?,
        )
    }

    pub(crate) fn last_audit(&self) -> Option<AuditStatus> {
        std::fs::read(self.dir.join("audit.json"))
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
    }

    pub(crate) fn save_audit(&self, a: &AuditStatus) -> Result<(), String> {
        write_private(
            &self.dir.join("audit.json"),
            &serde_json::to_vec_pretty(a).map_err(|e| e.to_string())?,
        )
    }

    /// A directory owned by `uid` (0700) for a job child's writable state
    /// (content rollback records).
    pub(crate) fn child_dir(&self, uid: u32, gid: u32) -> Result<PathBuf, String> {
        let base = self.dir.join("children");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o711)
            .create(&base)
            .map_err(|e| e.to_string())?;
        let dir = base.join(uid.to_string());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let meta = std::fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
        if !meta.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }
        if rustix::process::geteuid().is_root() && (meta.uid() != uid || meta.gid() != gid) {
            std::os::unix::fs::chown(&dir, Some(uid), Some(gid))
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        Ok(dir)
    }
}
