//! File-based mechanisms: ld.so.preload, shell profiles, environment files,
//! XDG autostart and rc.local.

use std::path::{Path, PathBuf};

use warden_core::{
    CheckResult, FindingTarget, ObservedPath, PersistenceMechanism, PersistenceScope,
};

use super::{files_in, note_user_limits, read};
use crate::ctx::{Ctx, Found, Run};
use crate::heuristics::snippet;
use crate::rules;

const SYSTEM_PROFILES: &[&str] = &[
    "/etc/profile",
    "/etc/bashrc",
    "/etc/bash.bashrc",
    "/etc/bash.bash_logout",
    "/etc/zshenv",
    "/etc/zprofile",
    "/etc/zshrc",
    "/etc/zlogin",
    "/etc/zsh/zshenv",
    "/etc/zsh/zprofile",
    "/etc/zsh/zshrc",
    "/etc/zsh/zlogin",
    "/etc/fish/config.fish",
];
const SYSTEM_PROFILE_DIRS: &[&str] = &["/etc/profile.d", "/etc/fish/conf.d"];
const USER_PROFILES: &[&str] = &[
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
    ".bash_logout",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".config/fish/config.fish",
    ".xprofile",
    ".xsession",
    ".xinitrc",
];

pub(crate) fn ld_preload(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let path = Path::new("/etc/ld.so.preload");
    if let Some((text, meta)) = read(ctx, &mut run, path) {
        let libs: Vec<&str> = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .flat_map(|l| l.split([' ', '\t', ':']))
            .filter(|t| !t.is_empty())
            .take(256)
            .collect();
        for lib in &libs {
            ctx.report(
                &rules::LD_SO_PRELOAD,
                FindingTarget::Persistence {
                    mechanism: PersistenceMechanism::LdPreload,
                    location: ObservedPath::from_path(path),
                    entry: Some(snippet(lib)),
                },
                format!("preloads {lib}"),
            );
            ctx.record(
                Found {
                    mechanism: PersistenceMechanism::LdPreload,
                    scope: PersistenceScope::System,
                    location: path,
                    command: Some((*lib).to_owned()),
                    enabled: Some(true),
                    detail: Some("loaded into every dynamically linked program".into()),
                    def_meta: Some(meta),
                    owner_uid: None,
                    find_executable: true,
                },
                None,
            );
        }
    }
    run.finish(
        "persistence.ld_preload",
        "Preloaded libraries (/etc/ld.so.preload)",
        ctx.cancel,
    )
}

pub(crate) fn shell_profiles(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut files: Vec<(PathBuf, PersistenceScope, Option<u32>)> = SYSTEM_PROFILES
        .iter()
        .map(|p| (PathBuf::from(p), PersistenceScope::System, None))
        .collect();
    for dir in SYSTEM_PROFILE_DIRS {
        for (p, _) in files_in(ctx, &mut run, Path::new(dir)) {
            files.push((p, PersistenceScope::System, None));
        }
    }
    for u in ctx.users.clone() {
        let scope = if u.uid == 0 {
            PersistenceScope::System
        } else {
            PersistenceScope::User
        };
        for f in USER_PROFILES {
            files.push((u.home.join(f), scope, Some(u.uid)));
        }
    }
    for (path, scope, owner) in files {
        if ctx.cancelled() {
            break;
        }
        let Some((text, meta)) = read(ctx, &mut run, &path) else {
            continue;
        };
        let lines = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .count();
        ctx.record(
            Found {
                mechanism: PersistenceMechanism::ShellProfile,
                scope,
                location: &path,
                command: None,
                enabled: None,
                detail: Some(format!("{lines} command line(s)")),
                def_meta: Some(meta),
                owner_uid: owner,
                find_executable: true,
            },
            Some(&text),
        );
    }
    note_user_limits(ctx, &mut run);
    run.finish(
        "persistence.shell_profiles",
        "Shell startup files",
        ctx.cancel,
    )
}

pub(crate) fn environment(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut files: Vec<(PathBuf, PersistenceScope, Option<u32>)> = vec![
        (
            PathBuf::from("/etc/environment"),
            PersistenceScope::System,
            None,
        ),
        (
            PathBuf::from("/etc/security/pam_env.conf"),
            PersistenceScope::System,
            None,
        ),
    ];
    for (p, _) in files_in(ctx, &mut run, Path::new("/etc/environment.d")) {
        files.push((p, PersistenceScope::System, None));
    }
    for u in ctx.users.clone() {
        files.push((
            u.home.join(".pam_environment"),
            PersistenceScope::User,
            Some(u.uid),
        ));
        let dir = u.home.join(".config/environment.d");
        for (p, _) in files_in(ctx, &mut run, &dir) {
            files.push((p, PersistenceScope::User, Some(u.uid)));
        }
    }
    for (path, scope, owner) in files {
        let Some((text, meta)) = read(ctx, &mut run, &path) else {
            continue;
        };
        let vars = text
            .lines()
            .filter(|l| l.contains('=') && !l.trim_start().starts_with('#'))
            .count();
        ctx.record(
            Found {
                mechanism: PersistenceMechanism::Environment,
                scope,
                location: &path,
                command: None,
                enabled: None,
                detail: Some(format!("{vars} variable(s)")),
                def_meta: Some(meta),
                owner_uid: owner,
                find_executable: false,
            },
            Some(&text),
        );
    }
    note_user_limits(ctx, &mut run);
    run.finish(
        "persistence.environment",
        "Login environment files",
        ctx.cancel,
    )
}

pub(crate) fn xdg_autostart(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut dirs: Vec<(PathBuf, Option<u32>)> = vec![(PathBuf::from("/etc/xdg/autostart"), None)];
    for u in ctx.users.clone() {
        dirs.push((u.home.join(".config/autostart"), Some(u.uid)));
    }
    for (dir, owner) in dirs {
        for (path, _) in files_in(ctx, &mut run, &dir) {
            if !path.extension().is_some_and(|e| e == "desktop") {
                continue;
            }
            let Some((text, meta)) = read(ctx, &mut run, &path) else {
                continue;
            };
            let d = parse_desktop(&text);
            ctx.record(
                Found {
                    mechanism: PersistenceMechanism::XdgAutostart,
                    // Autostart entries run as the user who logs in.
                    scope: PersistenceScope::User,
                    location: &path,
                    command: d.exec,
                    enabled: Some(d.enabled),
                    detail: d.name.map(|n| format!("Name={n}")),
                    def_meta: Some(meta),
                    owner_uid: owner,
                    find_executable: true,
                },
                None,
            );
        }
    }
    note_user_limits(ctx, &mut run);
    run.finish(
        "persistence.xdg_autostart",
        "Desktop autostart entries",
        ctx.cancel,
    )
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Desktop {
    name: Option<String>,
    exec: Option<String>,
    enabled: bool,
}

pub(crate) fn parse_desktop(text: &str) -> Desktop {
    let mut d = Desktop {
        name: None,
        exec: None,
        enabled: true,
    };
    let mut in_entry = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match (k.trim(), v.trim()) {
            ("Exec", v) => d.exec = Some(v.to_owned()),
            ("Name", v) => d.name = Some(v.to_owned()),
            ("Hidden", "true") | ("X-GNOME-Autostart-enabled", "false") => d.enabled = false,
            _ => {}
        }
    }
    d
}

pub(crate) fn rc_local(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut seen = Vec::new();
    for p in ["/etc/rc.local", "/etc/rc.d/rc.local"] {
        let path = Path::new(p);
        let Some((text, meta)) = read(ctx, &mut run, path) else {
            continue;
        };
        if seen.contains(&(meta.dev, meta.ino)) {
            continue;
        }
        seen.push((meta.dev, meta.ino));
        let lines = text
            .lines()
            .filter(|l| {
                let l = l.trim();
                !l.is_empty() && !l.starts_with('#') && l != "exit 0"
            })
            .count();
        ctx.record(
            Found {
                mechanism: PersistenceMechanism::RcLocal,
                scope: PersistenceScope::System,
                location: path,
                command: None,
                // systemd's rc-local generator runs it only when executable.
                enabled: Some(meta.mode & 0o100 != 0),
                detail: Some(format!("{lines} command line(s)")),
                def_meta: Some(meta),
                owner_uid: None,
                find_executable: true,
            },
            Some(&text),
        );
    }
    run.finish("persistence.rc_local", "rc.local boot script", ctx.cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_desktop_entries() {
        let d = parse_desktop(
            "[Desktop Entry]\nName=X\nExec=/usr/bin/x --y\nX-GNOME-Autostart-enabled=false\n\
             [Desktop Action a]\nExec=/tmp/other\n",
        );
        assert_eq!(d.exec.as_deref(), Some("/usr/bin/x --y"));
        assert!(!d.enabled);
        assert_eq!(d.name.as_deref(), Some("X"));
    }
}
