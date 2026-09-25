//! Live Windows persistence inventory: registry Run keys, Winlogon,
//! AppInit_DLLs, Image File Execution Options, services and drivers,
//! Task Scheduler tasks and Startup folders. Read-only; the rules are in
//! `winrules.rs`.

use std::io;
use std::path::{Path, PathBuf};

use warden_core::{
    CancellationToken, CheckResult, CheckStatus, HostInfo, IssueKind, ObservedPath,
    PersistenceMechanism as M, PersistenceScope, ScanIssue,
};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY};

use crate::rules::DETECTOR_ID;
use crate::winrules::{
    Collector, WinEntry, decode_text, expand_env, normalize_image_path, parse_task,
    system_principal,
};
use crate::{LIMITS_WARNING, SystemCheckError, SystemCheckOptions, SystemCheckOutcome};

const RUN_KEYS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];
const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const WINDOWS_NT: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
];
const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const SILENT_EXIT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
const MAX_TASK_FILES: usize = 20_000;
const MAX_FILE: u64 = 1 << 20;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

struct Win<'a> {
    c: Collector,
    issues: Vec<ScanIssue>,
    cancel: &'a CancellationToken,
    system_root: String,
}

#[derive(Default)]
struct Run {
    examined: u64,
    denied: u64,
    notes: Vec<String>,
}

impl Run {
    fn finish(self, id: &str, title: &str, cancel: &CancellationToken) -> CheckResult {
        let mut notes = self.notes;
        if self.denied > 0 {
            notes.push(format!(
                "{} location(s) not readable; run as Administrator",
                self.denied
            ));
        }
        let partial = self.denied > 0 || cancel.is_cancelled();
        CheckResult {
            id: id.into(),
            title: title.into(),
            status: if partial {
                CheckStatus::Partial
            } else {
                CheckStatus::Completed
            },
            examined: self.examined,
            detail: (!notes.is_empty()).then(|| notes.join("; ")),
        }
    }
}

impl Win<'_> {
    fn expand(&self, s: &str) -> String {
        expand_env(s, &env)
    }

    fn open(
        &mut self,
        run: &mut Run,
        root: &RegKey,
        root_name: &str,
        path: &str,
    ) -> Option<RegKey> {
        match root.open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY) {
            Ok(k) => Some(k),
            Err(e) => {
                self.error(run, &format!(r"{root_name}\{path}"), &e);
                None
            }
        }
    }

    fn error(&mut self, run: &mut Run, location: &str, e: &io::Error) {
        if e.kind() == io::ErrorKind::NotFound {
            return;
        }
        if e.kind() == io::ErrorKind::PermissionDenied {
            run.denied += 1;
        }
        self.issues.push(ScanIssue {
            path: Some(ObservedPath {
                text: location.to_owned(),
                raw_hex: None,
            }),
            kind: if e.kind() == io::ErrorKind::PermissionDenied {
                IssueKind::PermissionDenied
            } else {
                IssueKind::Io
            },
            detector: Some(DETECTOR_ID.into()),
            message: e.to_string(),
            member: None,
        });
    }

    fn string(key: &RegKey, name: &str) -> Option<String> {
        key.get_value::<String, _>(name).ok()
    }

    /// Loaded user hives under HKEY_USERS (logged-on users, .DEFAULT).
    fn user_hives(&mut self, run: &mut Run) -> Vec<String> {
        let hku = RegKey::predef(HKEY_USERS);
        let mut out = Vec::new();
        for name in hku.enum_keys() {
            match name {
                Ok(n) if !n.ends_with("_Classes") => out.push(n),
                Ok(_) => {}
                Err(e) => self.error(run, "HKU", &e),
            }
        }
        out
    }

    fn run_keys(&mut self) -> CheckResult {
        let mut run = Run::default();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let hku = RegKey::predef(HKEY_USERS);
        let mut roots: Vec<(&RegKey, String, PersistenceScope)> =
            vec![(&hklm, "HKLM".into(), PersistenceScope::System)];
        for sid in self.user_hives(&mut run) {
            roots.push((&hku, format!(r"HKU\{sid}"), PersistenceScope::User));
        }
        for (root, name, scope) in roots {
            for path in RUN_KEYS {
                let (root_name, full) = match name.strip_prefix(r"HKU\") {
                    Some(sid) => ("HKU", format!(r"{sid}\{path}")),
                    None => ("HKLM", (*path).to_owned()),
                };
                let Some(key) = self.open(&mut run, root, root_name, &full) else {
                    continue;
                };
                for v in key.enum_values() {
                    let Ok((vname, _)) = v else { continue };
                    let Some(cmd) = Self::string(&key, &vname) else {
                        continue;
                    };
                    run.examined += 1;
                    self.c.record(WinEntry {
                        mechanism: M::RegistryRun,
                        scope,
                        location: format!(r"{name}\{path}\{vname}"),
                        command: Some(self.expand(&cmd)),
                        enabled: Some(true),
                        detail: None,
                        hidden: false,
                    });
                }
            }
        }
        run.notes
            .push("users who are not logged on (hive not loaded) are not inspected".into());
        run.finish("persistence.registry_run", "Registry Run keys", self.cancel)
    }

    fn winlogon(&mut self) -> CheckResult {
        let mut run = Run::default();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Some(key) = self.open(&mut run, &hklm, "HKLM", WINLOGON) {
            for name in ["Shell", "Userinit", "Taskman", "AppSetup"] {
                let Some(value) = Self::string(&key, name) else {
                    continue;
                };
                run.examined += 1;
                let expanded = self.expand(&value);
                let root = self.system_root.clone();
                self.c.winlogon_value(
                    format!(r"HKLM\{WINLOGON}\{name}"),
                    name,
                    &value,
                    expanded,
                    &root,
                );
            }
        }
        for path in WINDOWS_NT {
            let Some(key) = self.open(&mut run, &hklm, "HKLM", path) else {
                continue;
            };
            let dlls = Self::string(&key, "AppInit_DLLs").unwrap_or_default();
            let load = key.get_value::<u32, _>("LoadAppInit_DLLs").unwrap_or(0);
            run.examined += 1;
            let expanded = self.expand(&dlls);
            self.c
                .appinit(format!(r"HKLM\{path}\AppInit_DLLs"), &dlls, load, expanded);
        }
        for (base, value_name) in [(IFEO, "Debugger"), (SILENT_EXIT, "MonitorProcess")] {
            let Some(key) = self.open(&mut run, &hklm, "HKLM", base) else {
                continue;
            };
            for image in key.enum_keys().flatten().take(10_000) {
                let Ok(sub) = key.open_subkey_with_flags(&image, KEY_READ) else {
                    continue;
                };
                run.examined += 1;
                let Some(cmd) = Self::string(&sub, value_name) else {
                    continue;
                };
                let expanded = self.expand(&cmd);
                self.c.launch_redirect(
                    format!(r"HKLM\{base}\{image}\{value_name}"),
                    &image,
                    value_name,
                    &cmd,
                    expanded,
                );
            }
        }
        run.finish(
            "persistence.winlogon",
            "Winlogon, AppInit_DLLs and launch redirection",
            self.cancel,
        )
    }

    fn services(&mut self) -> CheckResult {
        let mut run = Run::default();
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Some(key) = self.open(&mut run, &hklm, "HKLM", SERVICES) else {
            return run.finish("persistence.services", "Services and drivers", self.cancel);
        };
        for name in key.enum_keys().flatten().take(20_000) {
            if self.cancel.is_cancelled() {
                break;
            }
            let Ok(svc) = key.open_subkey_with_flags(&name, KEY_READ) else {
                continue;
            };
            let start = svc.get_value::<u32, _>("Start").unwrap_or(u32::MAX);
            let kind = svc.get_value::<u32, _>("Type").unwrap_or(0);
            if start > 2 {
                continue; // demand-start or disabled
            }
            run.examined += 1;
            let what = if kind & 0x3 != 0 { "driver" } else { "service" };
            let when = ["boot", "system", "automatic"][start as usize];
            let account = Self::string(&svc, "ObjectName");
            let scope = match account.as_deref() {
                Some(a)
                    if !system_principal(Some(a))
                        && !a.eq_ignore_ascii_case("LocalSystem")
                        && kind & 0x3 == 0 =>
                {
                    PersistenceScope::User
                }
                _ => PersistenceScope::System,
            };
            let location = format!(r"HKLM\{SERVICES}\{name}");
            if let Some(image) = Self::string(&svc, "ImagePath") {
                let cmd = normalize_image_path(&self.expand(&image), &self.system_root);
                self.c.record(WinEntry {
                    mechanism: M::WindowsService,
                    scope,
                    location: location.clone(),
                    command: Some(cmd),
                    enabled: Some(true),
                    detail: Some(format!(
                        "{what}, {when} start{}",
                        account
                            .map(|a| format!(", runs as {a}"))
                            .unwrap_or_default()
                    )),
                    hidden: false,
                });
            }
            if let Ok(params) = svc.open_subkey_with_flags("Parameters", KEY_READ)
                && let Some(dll) = Self::string(&params, "ServiceDll")
            {
                self.c.record(WinEntry {
                    mechanism: M::WindowsService,
                    scope,
                    location: format!(r"{location}\Parameters\ServiceDll"),
                    command: Some(self.expand(&dll)),
                    enabled: Some(true),
                    detail: Some(format!("service DLL, {when} start")),
                    hidden: false,
                });
            }
        }
        run.finish("persistence.services", "Services and drivers", self.cancel)
    }

    fn read_file(&mut self, run: &mut Run, path: &Path) -> Option<Vec<u8>> {
        use std::io::Read;
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                self.error(run, &path.to_string_lossy(), &e);
                return None;
            }
        };
        let mut buf = Vec::new();
        match f.take(MAX_FILE).read_to_end(&mut buf) {
            Ok(_) => Some(buf),
            Err(e) => {
                self.error(run, &path.to_string_lossy(), &e);
                None
            }
        }
    }

    fn tasks(&mut self) -> CheckResult {
        let mut run = Run::default();
        let base = PathBuf::from(&self.system_root).join(r"System32\Tasks");
        let mut stack = vec![(base, 0u32)];
        let mut files = Vec::new();
        while let Some((dir, depth)) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    self.error(&mut run, &dir.to_string_lossy(), &e);
                    continue;
                }
            };
            for e in entries.flatten() {
                // Never follow links or junctions.
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() && depth < 8 {
                    stack.push((e.path(), depth + 1));
                } else if ft.is_file() && files.len() < MAX_TASK_FILES {
                    files.push(e.path());
                }
            }
        }
        for path in files {
            if self.cancel.is_cancelled() {
                break;
            }
            let Some(bytes) = self.read_file(&mut run, &path) else {
                continue;
            };
            run.examined += 1;
            let task = parse_task(&decode_text(&bytes));
            let scope = if system_principal(task.user.as_deref()) {
                PersistenceScope::System
            } else {
                PersistenceScope::User
            };
            let location = path.to_string_lossy().into_owned();
            let detail = task.user.as_ref().map(|u| format!("runs as {u}"));
            let mut hidden = task.hidden;
            for cmd in &task.commands {
                self.c.record(WinEntry {
                    mechanism: M::ScheduledTask,
                    scope,
                    location: location.clone(),
                    command: Some(self.expand(cmd)),
                    enabled: Some(task.enabled),
                    detail: detail.clone(),
                    hidden,
                });
                hidden = false;
            }
            for clsid in &task.com_handlers {
                self.c.record(WinEntry {
                    mechanism: M::ScheduledTask,
                    scope,
                    location: location.clone(),
                    command: None,
                    enabled: Some(task.enabled),
                    detail: Some(format!("COM handler {clsid}")),
                    hidden,
                });
                hidden = false;
            }
        }
        run.finish(
            "persistence.scheduled_tasks",
            "Task Scheduler tasks",
            self.cancel,
        )
    }

    fn startup_folders(&mut self) -> CheckResult {
        let mut run = Run::default();
        let mut dirs: Vec<(PathBuf, PersistenceScope)> = Vec::new();
        if let Some(pd) = env("ProgramData") {
            dirs.push((
                PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
                PersistenceScope::User,
            ));
        }
        let users = PathBuf::from(env("SystemDrive").unwrap_or_else(|| "C:".into()) + r"\Users");
        match std::fs::read_dir(&users) {
            Ok(entries) => {
                for e in entries.flatten() {
                    dirs.push((
                        e.path()
                            .join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
                        PersistenceScope::User,
                    ));
                }
            }
            Err(e) => self.error(&mut run, &users.to_string_lossy(), &e),
        }
        for (dir, scope) in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                let path = e.path();
                let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                if name == "desktop.ini" || !e.file_type().is_ok_and(|t| t.is_file()) {
                    continue;
                }
                run.examined += 1;
                let location = path.to_string_lossy().into_owned();
                let ext = name.rsplit('.').next().unwrap_or("");
                let script = matches!(
                    ext,
                    "bat" | "cmd" | "ps1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "hta"
                );
                if script && let Some(bytes) = self.read_file(&mut run, &path) {
                    for line in decode_text(&bytes).lines().take(2000) {
                        for (rule, matched) in crate::heuristics::command_indicators(line) {
                            self.c.report(
                                rule,
                                M::StartupFolder,
                                &location,
                                Some(line),
                                format!("matched: {matched}"),
                            );
                        }
                    }
                }
                self.c.record(WinEntry {
                    mechanism: M::StartupFolder,
                    scope,
                    location: location.clone(),
                    command: (ext != "lnk").then_some(location),
                    enabled: Some(true),
                    detail: Some(if ext == "lnk" {
                        "shortcut (target not resolved)".into()
                    } else {
                        format!(".{ext} file")
                    }),
                    hidden: false,
                });
            }
        }
        run.finish(
            "persistence.startup_folders",
            "Startup folders",
            self.cancel,
        )
    }
}

pub(crate) fn run_checks(
    opts: &SystemCheckOptions,
    cancel: &CancellationToken,
) -> Result<SystemCheckOutcome, SystemCheckError> {
    let drive = env("SystemDrive").unwrap_or_else(|| "C:".into());
    let root_text = opts.root.to_string_lossy();
    let live_root = [
        "/",
        "\\",
        &format!("{drive}\\"),
        &format!("{drive}/"),
        &drive,
    ]
    .iter()
    .any(|r| root_text.eq_ignore_ascii_case(r));
    if !live_root {
        return Err(SystemCheckError::OfflineWindows);
    }
    let system_root = env("SystemRoot").unwrap_or_else(|| format!(r"{drive}\Windows"));
    let mut w = Win {
        c: Collector::default(),
        issues: Vec::new(),
        cancel,
        system_root,
    };
    let mut checks = vec![
        w.run_keys(),
        w.winlogon(),
        w.services(),
        w.tasks(),
        w.startup_folders(),
    ];
    for (id, title, why) in [
        (
            "persistence.wmi",
            "WMI event subscriptions",
            "not implemented on Windows yet",
        ),
        (
            "kernel.drivers",
            "Loaded driver cross-view",
            "not implemented on Windows yet",
        ),
        (
            "processes.hidden",
            "Hidden processes",
            "not implemented on Windows yet",
        ),
        (
            "packages.verify",
            "Authenticode and catalog verification",
            "not implemented on Windows yet",
        ),
    ] {
        checks.push(crate::skipped_check(
            id,
            title,
            CheckStatus::Unsupported,
            why,
        ));
    }
    let version = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ)
        .ok()
        .map(|k| {
            let s = |n| Win::string(&k, n).unwrap_or_default();
            format!("{} build {}", s("ProductName"), s("CurrentBuild"))
        });
    let host = HostInfo {
        os: "windows".into(),
        kernel: version,
        hostname: env("COMPUTERNAME"),
        root: ObservedPath {
            text: format!("{drive}\\"),
            raw_hex: None,
        },
        live: true,
        euid: None,
    };
    Ok(SystemCheckOutcome {
        host,
        checks,
        findings: w.c.findings,
        persistence: w.c.persistence,
        issues: w.issues,
        warnings: vec![
            LIMITS_WARNING.to_owned(),
            "Windows coverage: Run keys, Winlogon, AppInit_DLLs, Image File Execution Options, services, \
             scheduled tasks and Startup folders. WMI subscriptions, COM hijacks, drivers, hidden \
             processes and file signatures are not checked yet."
                .into(),
        ],
    })
}
