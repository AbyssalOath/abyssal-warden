//! Types for system checks: persistence inventory, check results and the
//! system report.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{EngineInfo, Finding, ObservedPath, ScanIssue, ScanReport};

/// Version of the JSON system report schema; same rules as
/// [`crate::REPORT_SCHEMA_VERSION`].
pub const SYSTEM_REPORT_SCHEMA_VERSION: u32 = 1;

/// How something makes itself run again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PersistenceMechanism {
    SystemdService,
    SystemdTimer,
    Cron,
    LdPreload,
    ShellProfile,
    Environment,
    XdgAutostart,
    SshAuthorizedKeys,
    Pam,
    RcLocal,
    Udev,
    /// SysV init scripts (`/etc/init.d`).
    SysvInit,
    /// One-off `at` jobs.
    AtJob,
    /// systemd generators, run at every boot and daemon reload.
    SystemdGenerator,
    /// Kernel modules loaded at boot (`modules-load.d`) and `modprobe.d`
    /// `install`/`remove` commands.
    KernelModule,
    /// Scripts run at login to build the message of the day.
    Motd,
    /// `~/.ssh/rc` and `/etc/ssh/sshrc`, run at every SSH login.
    SshRc,
    /// Hooks that add code to the initramfs (dracut, initramfs-tools).
    InitramfsHook,
    /// Boot loader configuration scripts (`/etc/grub.d`).
    BootLoader,
    /// Loaded eBPF programs (pinned in bpffs or held by a process).
    Ebpf,
    /// Windows `Run`/`RunOnce` registry values.
    RegistryRun,
    /// Windows services and drivers set to start automatically.
    WindowsService,
    /// Windows Task Scheduler tasks.
    ScheduledTask,
    /// Files in Windows Startup folders.
    StartupFolder,
    /// Winlogon `Shell`/`Userinit`, `AppInit_DLLs`, Image File Execution
    /// Options debuggers.
    Winlogon,
}

/// Whose persistence it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceScope {
    /// Runs for or as the system (usually root).
    System,
    /// Runs for one user.
    User,
}

/// One inventoried persistence entry. All text fields are untrusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub mechanism: PersistenceMechanism,
    pub scope: PersistenceScope,
    /// The file that defines the entry.
    pub location: ObservedPath,
    /// The command or program it runs, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The executable the command starts, when it could be determined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<ObservedPath>,
    /// Whether it is enabled, when that is knowable (systemd, autostart).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Extra context (timer schedule, cron schedule, key count, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckStatus {
    Completed,
    /// Ran, but could not see everything (e.g. permission denied).
    Partial,
    /// Not run by request or because it does not apply (e.g. offline root).
    Skipped,
    /// Not available on this platform or system.
    Unsupported,
    Failed,
}

/// The outcome of one check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub status: CheckStatus,
    /// Things examined (files, processes, modules, packages).
    pub examined: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The filesystem root that was inspected (`/` for the running system).
    pub root: ObservedPath,
    /// Checks of the running kernel and processes apply (root is `/`).
    pub live: bool,
    /// Effective user ID the checks ran as (Unix).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub euid: Option<u32>,
}

/// The result of `system-check`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemReport {
    pub schema_version: u32,
    pub report_id: Uuid,
    pub engine: EngineInfo,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub finished_at: OffsetDateTime,
    pub host: HostInfo,
    pub checks: Vec<CheckResult>,
    pub findings: Vec<Finding>,
    /// Every persistence entry found, suspicious or not.
    pub persistence: Vec<PersistenceEntry>,
    pub issues: Vec<ScanIssue>,
    /// Scan of the executables that persistence entries start, when
    /// detection content was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referenced_files: Option<ScanReport>,
    pub warnings: Vec<String>,
}
