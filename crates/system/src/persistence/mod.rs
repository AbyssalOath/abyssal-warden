//! Persistence inventory: every place Linux starts programs automatically,
//! with the rules applied to each entry.

pub(crate) mod cron;
mod extra;

pub(crate) use extra::parse_modprobe_command;
pub(crate) mod files;
pub(crate) mod pam;
pub(crate) mod ssh;
pub(crate) mod systemd;
pub(crate) mod udev;

use std::path::{Path, PathBuf};

use warden_core::CheckResult;

use crate::ctx::{Ctx, Run};
use crate::fsx::{Kind, Meta};

pub(crate) fn run_all(ctx: &mut Ctx<'_>) -> Vec<CheckResult> {
    let checks: [fn(&mut Ctx<'_>) -> CheckResult; 18] = [
        systemd::check,
        cron::check,
        files::ld_preload,
        files::shell_profiles,
        files::environment,
        files::xdg_autostart,
        ssh::check,
        pam::check,
        files::rc_local,
        udev::check,
        extra::sysv_init,
        extra::at_jobs,
        extra::generators,
        extra::kernel_modules,
        extra::motd,
        extra::ssh_rc,
        extra::initramfs_hooks,
        extra::boot_loader,
    ];
    checks.iter().map(|c| c(ctx)).collect()
}

/// Regular files directly in `dir` (links followed inside the root), with
/// their metadata. Missing directories give nothing.
pub(crate) fn files_in(ctx: &mut Ctx<'_>, run: &mut Run, dir: &Path) -> Vec<(PathBuf, Meta)> {
    let entries = match ctx.root.read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            ctx.io_error(run, dir, &e);
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for e in entries {
        if e.kind == Kind::Dir {
            continue;
        }
        let path = dir.join(&e.name);
        match ctx.root.stat(&path) {
            Ok(m) if m.kind == Kind::File => out.push((path, m)),
            Ok(_) => {}
            Err(err) => ctx.io_error(run, &path, &err),
        }
    }
    out
}

/// Reads a file for a check: `None` (and an issue, unless missing) on error.
pub(crate) fn read(ctx: &mut Ctx<'_>, run: &mut Run, path: &Path) -> Option<(String, Meta)> {
    match ctx.root.read_text(path) {
        Ok(t) => {
            run.examined += 1;
            if t.truncated {
                run.partial = true;
                run.notes.push(format!(
                    "{} is larger than 1 MiB; only the start was read",
                    path.display()
                ));
            }
            Some((t.text, t.meta))
        }
        Err(e) => {
            ctx.io_error(run, path, &e);
            None
        }
    }
}

/// Joins shell/systemd-style continuation lines (ending in `\`).
pub(crate) fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if let Some(stripped) = line.strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
        } else {
            cur.push_str(line);
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Notes that other users' files were not inspected.
pub(crate) fn note_user_limits(ctx: &Ctx<'_>, run: &mut Run) {
    if ctx.users_limited {
        run.partial = true;
        run.notes
            .push("only the current user's files were inspected; run as root for all users".into());
    }
}
