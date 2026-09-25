//! systemd services and timers (system and user units, drop-ins).

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use warden_core::{CheckResult, PersistenceMechanism, PersistenceScope};

use super::{files_in, logical_lines, note_user_limits, read};
use crate::ctx::{Ctx, Found, Run};
use crate::fsx::Kind;
use crate::heuristics::{LOADER_VARS, shell_tokens};

pub(crate) const ID: &str = "persistence.systemd";
const TITLE: &str = "systemd services and timers";

const SYSTEM_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];
const GLOBAL_USER_DIRS: &[&str] = &[
    "/etc/systemd/user",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
];
const EXEC_KEYS: &[&str] = &[
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPost",
    "ExecReload",
    "ExecCondition",
];

pub(crate) fn check(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut dirs: Vec<(PathBuf, PersistenceScope, Option<u32>)> = SYSTEM_DIRS
        .iter()
        .map(|d| (PathBuf::from(d), PersistenceScope::System, None))
        .collect();
    dirs.extend(
        GLOBAL_USER_DIRS
            .iter()
            .map(|d| (PathBuf::from(d), PersistenceScope::User, None)),
    );
    for u in ctx.users.clone() {
        dirs.push((
            u.home.join(".config/systemd/user"),
            PersistenceScope::User,
            Some(u.uid),
        ));
    }

    // Units wanted by some target (enabled).
    let mut wanted: HashSet<String> = HashSet::new();
    for (dir, _, _) in &dirs {
        if let Ok(entries) = ctx.root.read_dir(dir) {
            for e in entries {
                if e.kind == Kind::Dir
                    && (e.name.ends_with(".wants") || e.name.ends_with(".requires"))
                    && let Ok(links) = ctx.root.read_dir(&dir.join(&e.name))
                {
                    wanted.extend(links.into_iter().map(|l| l.name));
                }
            }
        }
    }

    let mut seen_files: HashSet<(u64, u64)> = HashSet::new();
    for (dir, scope, owner) in dirs {
        if ctx.cancelled() {
            break;
        }
        let mut units: Vec<(PathBuf, String)> = Vec::new();
        for (path, meta) in files_in(ctx, &mut run, &dir) {
            if !seen_files.insert((meta.dev, meta.ino)) {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name.ends_with(".service") || name.ends_with(".timer") {
                units.push((path, name));
            }
        }
        // Drop-ins: NAME.service.d/*.conf
        if let Ok(entries) = ctx.root.read_dir(&dir) {
            for e in entries {
                if e.kind == Kind::Dir
                    && (e.name.ends_with(".service.d") || e.name.ends_with(".timer.d"))
                {
                    let unit = e.name.trim_end_matches(".d").to_owned();
                    for (path, meta) in files_in(ctx, &mut run, &dir.join(&e.name)) {
                        if path.extension().is_some_and(|x| x == "conf")
                            && seen_files.insert((meta.dev, meta.ino))
                        {
                            units.push((path, unit.clone()));
                        }
                    }
                }
            }
        }
        for (path, unit) in units {
            let enabled = Some(wanted.contains(&unit));
            inspect_unit(ctx, &mut run, &path, &unit, scope, owner, enabled);
        }
    }
    note_user_limits(ctx, &mut run);
    run.finish(ID, TITLE, ctx.cancel)
}

fn inspect_unit(
    ctx: &mut Ctx<'_>,
    run: &mut Run,
    path: &Path,
    unit: &str,
    scope: PersistenceScope,
    owner: Option<u32>,
    enabled: Option<bool>,
) {
    let Some((text, meta)) = read(ctx, run, path) else {
        return;
    };
    let parsed = parse_unit(&text);
    // A service with User= set to a non-root account does not run as root.
    let scope = if scope == PersistenceScope::System
        && parsed
            .user
            .as_deref()
            .is_some_and(|u| u != "root" && u != "0")
    {
        PersistenceScope::User
    } else {
        scope
    };
    let timer = unit.ends_with(".timer");
    let mechanism = if timer {
        PersistenceMechanism::SystemdTimer
    } else {
        PersistenceMechanism::SystemdService
    };
    let base = Found {
        mechanism,
        scope,
        location: path,
        command: None,
        enabled,
        detail: None,
        def_meta: Some(meta),
        owner_uid: owner,
        find_executable: true,
    };
    if timer {
        let mut detail: Vec<String> = parsed.schedule.clone();
        if let Some(u) = &parsed.timer_unit {
            detail.push(format!("Unit={u}"));
        }
        ctx.record(
            Found {
                detail: (!detail.is_empty()).then(|| detail.join(", ")),
                find_executable: false,
                ..base
            },
            None,
        );
        return;
    }
    // Environment values often hold secrets (tokens, passwords): only
    // dynamic-loader variables are ever recorded.
    for assignment in parsed.environment.iter().flat_map(|e| shell_tokens(e)) {
        if let Some((k, _)) = assignment.split_once('=')
            && LOADER_VARS.contains(&k)
        {
            ctx.record(
                Found {
                    command: Some(assignment.clone()),
                    detail: Some(format!("unit {unit}, Environment")),
                    find_executable: false,
                    ..base.clone()
                },
                None,
            );
        }
    }
    if parsed.exec.is_empty() {
        // Drop-in or unit without commands: still inventoried, and its
        // permissions checked.
        ctx.record(
            Found {
                detail: Some(format!("unit {unit}")),
                find_executable: false,
                ..base.clone()
            },
            None,
        );
        return;
    }
    for (key, cmd) in parsed.exec {
        ctx.record(
            Found {
                command: Some(cmd),
                detail: Some(format!("unit {unit}, {key}")),
                ..base.clone()
            },
            None,
        );
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Unit {
    exec: Vec<(String, String)>,
    environment: Vec<String>,
    user: Option<String>,
    schedule: Vec<String>,
    timer_unit: Option<String>,
}

pub(crate) fn parse_unit(text: &str) -> Unit {
    let mut unit = Unit::default();
    let schedule_keys: BTreeSet<&str> = [
        "OnCalendar",
        "OnBootSec",
        "OnStartupSec",
        "OnUnitActiveSec",
        "OnUnitInactiveSec",
        "OnActiveSec",
    ]
    .into_iter()
    .collect();
    for line in logical_lines(text) {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('[')
        {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if EXEC_KEYS.contains(&k) {
            if !v.is_empty() {
                unit.exec.push((k.to_owned(), v.to_owned()));
            }
        } else if k == "Environment" {
            unit.environment.push(v.to_owned());
        } else if k == "User" {
            unit.user = Some(v.to_owned());
        } else if k == "Unit" {
            unit.timer_unit = Some(v.to_owned());
        } else if schedule_keys.contains(k) {
            unit.schedule.push(format!("{k}={v}"));
        }
        if unit.exec.len() > 64 {
            break;
        }
    }
    unit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        let u = parse_unit(
            "[Unit]\nDescription=x\n[Service]\nUser=svc\nEnvironment=\"A=1\" LD_PRELOAD=/x.so\n\
             ExecStartPre=-/usr/bin/true\nExecStart=/usr/bin/foo \\\n  --bar\nExecStop=\n",
        );
        assert_eq!(u.user.as_deref(), Some("svc"));
        assert_eq!(u.exec.len(), 2);
        assert_eq!(u.exec[1].1, "/usr/bin/foo    --bar");
        assert_eq!(u.environment.len(), 1);
        let t = parse_unit("[Timer]\nOnCalendar=daily\nUnit=x.service\n");
        assert_eq!(t.schedule, ["OnCalendar=daily"]);
        assert_eq!(t.timer_unit.as_deref(), Some("x.service"));
    }
}
