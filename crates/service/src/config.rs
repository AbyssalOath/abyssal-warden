//! Service configuration (`/etc/abyssal-warden/service.json`).
//!
//! The file decides who is an administrator and what runs as root, so as
//! root it must be owned by root and not writable by group or others.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use warden_ipc::JobKind;

pub const DEFAULT_CONFIG: &str = "/etc/abyssal-warden/service.json";
const MAX_CONFIG: u64 = 1 << 20;
const MAX_SCHEDULES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Socket path.
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// Restrict connecting to members of this group (socket mode 0660).
    /// Default: every local user may connect (0666); each request is still
    /// authorised.
    #[serde(default)]
    pub socket_group: Option<String>,
    /// Job history and reports.
    #[serde(default = "default_state")]
    pub state_dir: PathBuf,
    /// Quarantine store used for automatic quarantine and the quarantine
    /// operations.
    #[serde(default = "default_store")]
    pub quarantine_store: PathBuf,
    /// Administrators besides root (user names or numeric uids).
    #[serde(default)]
    pub admin_users: Vec<String>,
    /// Members of this group are administrators.
    #[serde(default)]
    pub admin_group: Option<String>,
    /// Account privileged scans run as (with `CAP_DAC_READ_SEARCH` only).
    #[serde(default = "default_scanner_user")]
    pub scanner_user: String,
    /// The `abyssal-warden` binary [default: next to the service binary].
    #[serde(default)]
    pub scanner_binary: Option<PathBuf>,
    /// Signed content bundle directories used by every job.
    #[serde(default)]
    pub content: Vec<PathBuf>,
    /// Keyrings trusted for that content, in addition to the system keyring
    /// (`/etc/abyssal-warden/keyring.json`, always loaded).
    #[serde(default)]
    pub keyrings: Vec<PathBuf>,
    #[serde(default = "one")]
    pub max_concurrent_jobs: u32,
    #[serde(default = "default_queue")]
    pub max_queued_jobs: u32,
    #[serde(default = "default_timeout")]
    pub job_timeout_minutes: u32,
    #[serde(default = "default_history")]
    pub history_limit: u32,
    /// Compare the quarantine audit chain with the system log this often
    /// (0: only on request).
    #[serde(default = "day")]
    pub audit_check_hours: u32,
    #[serde(default)]
    pub schedules: Vec<Schedule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub name: String,
    #[serde(default = "scan_kind")]
    pub kind: JobKind,
    #[serde(default)]
    pub paths: Vec<String>,
    pub every_hours: u32,
    /// Time of day (UTC, `HH:MM`); needs `every_hours` to be a multiple of 24.
    #[serde(default)]
    pub at_utc: Option<String>,
    #[serde(default)]
    pub heuristics: bool,
    /// Quarantine confirmed malware found by this schedule.
    #[serde(default)]
    pub quarantine: bool,
}

fn default_socket() -> PathBuf {
    PathBuf::from(warden_ipc::DEFAULT_SOCKET)
}
fn default_state() -> PathBuf {
    PathBuf::from("/var/lib/abyssal-warden/service")
}
fn default_store() -> PathBuf {
    PathBuf::from("/var/lib/abyssal-warden/quarantine")
}
fn default_scanner_user() -> String {
    "abyssal-warden".into()
}
fn one() -> u32 {
    1
}
fn default_queue() -> u32 {
    32
}
fn default_timeout() -> u32 {
    240
}
fn default_history() -> u32 {
    200
}
fn day() -> u32 {
    24
}
fn scan_kind() -> JobKind {
    JobKind::Scan
}

impl Default for ServiceConfig {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap_or_else(|_| unreachable!("defaults deserialize"))
    }
}

/// Parses `HH:MM`.
pub fn parse_hhmm(s: &str) -> Option<(u8, u8)> {
    let (h, m) = s.split_once(':')?;
    let (h, m) = (h.parse::<u8>().ok()?, m.parse::<u8>().ok()?);
    (h < 24 && m < 60 && s.len() == 5).then_some((h, m))
}

impl ServiceConfig {
    pub fn validate(&self) -> Result<(), String> {
        let range = |v: u32, lo: u32, hi: u32, what: &str| {
            if (lo..=hi).contains(&v) {
                Ok(())
            } else {
                Err(format!("{what} must be between {lo} and {hi}"))
            }
        };
        range(self.max_concurrent_jobs, 1, 8, "max_concurrent_jobs")?;
        range(self.max_queued_jobs, 1, 1000, "max_queued_jobs")?;
        range(
            self.job_timeout_minutes,
            1,
            7 * 24 * 60,
            "job_timeout_minutes",
        )?;
        range(self.history_limit, 1, 100_000, "history_limit")?;
        range(self.audit_check_hours, 0, 24 * 365, "audit_check_hours")?;
        for p in [&self.socket, &self.state_dir, &self.quarantine_store] {
            if !p.is_absolute() {
                return Err(format!("{} must be an absolute path", p.display()));
            }
        }
        // sockaddr_un.sun_path is 108 bytes including the terminating NUL.
        if self.socket.as_os_str().len() >= 108 {
            return Err(format!(
                "socket path {} is too long (Unix sockets allow at most 107 bytes)",
                self.socket.display()
            ));
        }
        for c in self.content.iter().chain(&self.keyrings) {
            if !c.is_absolute() {
                return Err(format!(
                    "content directory {} must be absolute",
                    c.display()
                ));
            }
        }
        if self.schedules.len() > MAX_SCHEDULES {
            return Err(format!("at most {MAX_SCHEDULES} schedules"));
        }
        let mut names = std::collections::BTreeSet::new();
        for s in &self.schedules {
            let valid = !s.name.is_empty()
                && s.name.len() <= 128
                && s.name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
            if !valid || !names.insert(&s.name) {
                return Err(format!("schedule name {:?} is invalid or repeated", s.name));
            }
            range(s.every_hours, 1, 24 * 366, "every_hours")?;
            if let Some(at) = &s.at_utc {
                if parse_hhmm(at).is_none() {
                    return Err(format!("schedule {}: at_utc must be HH:MM", s.name));
                }
                if s.every_hours % 24 != 0 {
                    return Err(format!(
                        "schedule {}: at_utc needs every_hours to be a multiple of 24",
                        s.name
                    ));
                }
            }
            match s.kind {
                JobKind::Scan => {
                    if s.paths.is_empty() || s.paths.len() > warden_ipc::MAX_PATHS {
                        return Err(format!(
                            "schedule {}: a scan needs 1 to {} paths",
                            s.name,
                            warden_ipc::MAX_PATHS
                        ));
                    }
                    if let Some(p) = s
                        .paths
                        .iter()
                        .find(|p| !Path::new(p).is_absolute() || p.contains('\0'))
                    {
                        return Err(format!("schedule {}: path {p:?} must be absolute", s.name));
                    }
                }
                JobKind::SystemCheck => {
                    if !s.paths.is_empty() || s.quarantine {
                        return Err(format!(
                            "schedule {}: a system check takes no paths and does not quarantine",
                            s.name
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Loads the configuration. A missing file gives the defaults. With
    /// `require_secure`, the file must be owned by root and not writable by
    /// group or others.
    pub fn load(path: &Path, require_secure: bool) -> Result<Self, String> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let c = Self::default();
                c.validate()?;
                return Ok(c);
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let meta = file
            .metadata()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if require_secure && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
            return Err(format!(
                "{} must be owned by root and not writable by group or others (owner {}, mode {:04o})",
                path.display(),
                meta.uid(),
                meta.mode() & 0o7777
            ));
        }
        let mut text = String::new();
        file.take(MAX_CONFIG + 1)
            .read_to_string(&mut text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if text.len() as u64 > MAX_CONFIG {
            return Err(format!("{} is larger than 1 MiB", path.display()));
        }
        let c: Self =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        c.validate()?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<ServiceConfig, String> {
        let c: ServiceConfig = serde_json::from_str(s).map_err(|e| e.to_string())?;
        c.validate().map(|()| c)
    }

    #[test]
    fn defaults_and_schedules() {
        let c = ServiceConfig::default();
        assert_eq!(c.socket, PathBuf::from(warden_ipc::DEFAULT_SOCKET));
        assert_eq!(c.max_concurrent_jobs, 1);
        assert!(c.validate().is_ok());
        let ok = parse(r#"{"schedules":[{"name":"daily-home","paths":["/home"],"every_hours":24,"at_utc":"03:30","heuristics":true},
                                        {"name":"sys","kind":"system_check","every_hours":6}]}"#).expect("valid");
        assert_eq!(ok.schedules.len(), 2);
    }

    #[test]
    fn rejects_bad_configs() {
        for bad in [
            r#"{"unknown":1}"#,
            r#"{"max_concurrent_jobs":0}"#,
            r#"{"socket":"relative.sock"}"#,
            r#"{"socket":"/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock"}"#,
            r#"{"schedules":[{"name":"a","paths":["/x"],"every_hours":0}]}"#,
            r#"{"schedules":[{"name":"a","paths":["x"],"every_hours":1}]}"#,
            r#"{"schedules":[{"name":"a","paths":[],"every_hours":1}]}"#,
            r#"{"schedules":[{"name":"a","paths":["/x"],"every_hours":12,"at_utc":"03:00"}]}"#,
            r#"{"schedules":[{"name":"a","paths":["/x"],"every_hours":24,"at_utc":"25:00"}]}"#,
            r#"{"schedules":[{"name":"a","paths":["/x"],"every_hours":1},{"name":"a","paths":["/y"],"every_hours":1}]}"#,
            r#"{"schedules":[{"name":"../a","paths":["/x"],"every_hours":1}]}"#,
            r#"{"schedules":[{"name":"s","kind":"system_check","every_hours":1,"quarantine":true}]}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_hhmm("03:05"), Some((3, 5)));
        // The packaged example is valid.
        parse(include_str!("../../../packaging/linux/service.json")).expect("packaged example");
        assert_eq!(parse_hhmm("3:05"), None);
    }
}
