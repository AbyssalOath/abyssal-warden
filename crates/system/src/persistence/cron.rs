//! cron and anacron: system crontabs, cron.d, per-user spools and the
//! periodic script directories.

use std::path::{Path, PathBuf};

use warden_core::{CheckResult, PersistenceMechanism, PersistenceScope};

use super::{files_in, read};
use crate::ctx::{Ctx, Found, Run};

pub(crate) const ID: &str = "persistence.cron";
const TITLE: &str = "cron and anacron jobs";

const PERIODIC: &[&str] = &[
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];
const SPOOLS: &[&str] = &["/var/spool/cron/crontabs", "/var/spool/cron"];

pub(crate) fn check(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();

    // System crontabs: minute hour dom month dow USER command.
    let mut system_tabs: Vec<PathBuf> = vec![PathBuf::from("/etc/crontab")];
    system_tabs.extend(
        files_in(ctx, &mut run, Path::new("/etc/cron.d"))
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| !is_backup(p)),
    );
    for tab in system_tabs {
        crontab(ctx, &mut run, &tab, true, None);
    }

    // Per-user spools: no user field.
    for spool in SPOOLS {
        for (path, meta) in files_in(ctx, &mut run, Path::new(spool)) {
            if is_backup(&path) {
                continue;
            }
            // The file name is the user; root's jobs run as root.
            let user_is_root = path.file_name().is_some_and(|n| n == "root");
            crontab(ctx, &mut run, &path, false, Some((user_is_root, meta.uid)));
        }
    }

    // anacrontab: period delay id command.
    if let Some((text, meta)) = read(ctx, &mut run, Path::new("/etc/anacrontab")) {
        for line in text.lines().map(str::trim).filter(|l| !skip_line(l)) {
            if let Some((k, v)) = env_assignment(line) {
                env_entry(ctx, Path::new("/etc/anacrontab"), k, v, meta);
                continue;
            }
            let fields: Vec<&str> = line
                .splitn(4, char::is_whitespace)
                .filter(|f| !f.is_empty())
                .collect();
            if let [period, _delay, id, cmd] = fields[..] {
                ctx.record(
                    Found {
                        mechanism: PersistenceMechanism::Cron,
                        scope: PersistenceScope::System,
                        location: Path::new("/etc/anacrontab"),
                        command: Some(cmd.trim().to_owned()),
                        enabled: None,
                        detail: Some(format!("anacron {id}, every {period}")),
                        def_meta: Some(meta),
                        owner_uid: None,
                        find_executable: true,
                    },
                    None,
                );
            }
        }
    }

    // Periodic script directories (run-parts): each script is an entry.
    for dir in PERIODIC {
        for (path, meta) in files_in(ctx, &mut run, Path::new(dir)) {
            if is_backup(&path) || ctx.cancelled() {
                continue;
            }
            let body = read(ctx, &mut run, &path).map(|(t, _)| t);
            let logical = path.to_string_lossy().into_owned();
            ctx.record(
                Found {
                    mechanism: PersistenceMechanism::Cron,
                    scope: PersistenceScope::System,
                    location: &path,
                    command: Some(logical),
                    enabled: Some(meta.mode & 0o111 != 0),
                    detail: Some(format!("run by {dir}")),
                    def_meta: Some(meta),
                    owner_uid: None,
                    find_executable: true,
                },
                body.as_deref(),
            );
        }
    }
    if ctx.users_limited {
        run.notes
            .push("per-user crontabs are readable only by root".into());
    }
    run.finish(ID, TITLE, ctx.cancel)
}

/// `user`: for spool files, (runs as root, file owner uid).
fn crontab(ctx: &mut Ctx<'_>, run: &mut Run, path: &Path, system: bool, user: Option<(bool, u32)>) {
    let Some((text, meta)) = read(ctx, run, path) else {
        return;
    };
    for line in text.lines().map(str::trim).filter(|l| !skip_line(l)) {
        if let Some((k, v)) = env_assignment(line) {
            env_entry(ctx, path, k, v, meta);
            continue;
        }
        let Some((schedule, run_as, cmd)) = parse_cron_line(line, system) else {
            continue;
        };
        let root_job = match (&run_as, user) {
            (Some(u), _) => u == "root",
            (None, Some((is_root, _))) => is_root,
            (None, None) => true,
        };
        let mut detail = schedule;
        if let Some(u) = &run_as {
            detail.push_str(&format!(", as {u}"));
        }
        ctx.record(
            Found {
                mechanism: PersistenceMechanism::Cron,
                scope: if root_job {
                    PersistenceScope::System
                } else {
                    PersistenceScope::User
                },
                location: path,
                command: Some(cmd),
                enabled: None,
                detail: Some(detail),
                def_meta: Some(meta),
                owner_uid: user.map(|(_, uid)| uid),
                find_executable: true,
            },
            None,
        );
    }
}

fn env_entry(ctx: &mut Ctx<'_>, path: &Path, key: &str, value: &str, meta: crate::fsx::Meta) {
    if key == "LD_PRELOAD" || key == "LD_LIBRARY_PATH" {
        ctx.record(
            Found {
                mechanism: PersistenceMechanism::Cron,
                scope: PersistenceScope::System,
                location: path,
                command: Some(format!("{key}={value}")),
                enabled: None,
                detail: Some("environment for all jobs in this file".into()),
                def_meta: Some(meta),
                owner_uid: None,
                find_executable: false,
            },
            None,
        );
    }
}

fn skip_line(l: &str) -> bool {
    l.is_empty() || l.starts_with('#')
}

fn is_backup(p: &Path) -> bool {
    let n = p
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    n.starts_with('.') || n.ends_with('~') || n.ends_with(".rpmsave") || n.ends_with(".dpkg-old")
}

/// `NAME=value` at the start of a line (cron environment setting).
pub(crate) fn env_assignment(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    let k = k.trim();
    (!k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then(|| (k, v.trim()))
}

/// (schedule, user, command) of a crontab line.
pub(crate) fn parse_cron_line(
    line: &str,
    with_user: bool,
) -> Option<(String, Option<String>, String)> {
    let mut rest = line;
    let take = |rest: &mut &str| -> Option<String> {
        let t = rest.trim_start();
        let end = t.find(char::is_whitespace)?;
        let (tok, r) = t.split_at(end);
        *rest = r;
        Some(tok.to_owned())
    };
    let schedule = if rest.starts_with('@') {
        take(&mut rest)?
    } else {
        let mut parts = Vec::new();
        for _ in 0..5 {
            parts.push(take(&mut rest)?);
        }
        parts.join(" ")
    };
    let user = if with_user {
        Some(take(&mut rest)?)
    } else {
        None
    };
    let cmd = rest.trim();
    (!cmd.is_empty()).then(|| (schedule, user, cmd.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cron_lines() {
        assert_eq!(
            parse_cron_line("*/5 * * * * root /usr/bin/x --y", true),
            Some((
                "*/5 * * * *".into(),
                Some("root".into()),
                "/usr/bin/x --y".into()
            ))
        );
        assert_eq!(
            parse_cron_line("@reboot /tmp/.x/run", false),
            Some(("@reboot".into(), None, "/tmp/.x/run".into()))
        );
        assert_eq!(parse_cron_line("* * * *", false), None);
        assert_eq!(
            env_assignment("SHELL=/bin/bash"),
            Some(("SHELL", "/bin/bash"))
        );
        assert_eq!(env_assignment("* * * * * a=b"), None);
    }
}
