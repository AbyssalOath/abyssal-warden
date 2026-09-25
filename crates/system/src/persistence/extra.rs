//! Less common Linux persistence: SysV init scripts, `at` jobs, systemd
//! generators, kernel module loading, motd scripts, SSH rc files, initramfs
//! hooks and GRUB configuration scripts.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use warden_core::{CheckResult, PersistenceMechanism, PersistenceScope};

use super::{files_in, logical_lines, note_user_limits, read};
use crate::ctx::{Ctx, Found, Run};
use crate::fsx::{Kind, Meta};

/// Records an executable script or program as an entry. Its text is
/// searched for suspicious commands unless it is an ELF binary (binaries
/// contain strings such as `/dev/tcp` without running them).
#[allow(clippy::too_many_arguments)]
fn program(
    ctx: &mut Ctx<'_>,
    run: &mut Run,
    path: &Path,
    meta: Meta,
    mechanism: PersistenceMechanism,
    scope: PersistenceScope,
    enabled: Option<bool>,
    detail: String,
) {
    let body = match ctx.root.read_text(path) {
        Ok(t) => {
            run.examined += 1;
            let elf = t.text.starts_with("\u{7f}ELF");
            if t.truncated && !elf {
                run.partial = true;
                run.notes.push(format!(
                    "{} is larger than 1 MiB; only the start was read",
                    path.display()
                ));
            }
            (!elf).then_some(t.text)
        }
        Err(e) => {
            ctx.io_error(run, path, &e);
            None
        }
    };
    let text = body.as_deref();
    ctx.record(
        Found {
            mechanism,
            scope,
            location: path,
            command: Some(path.to_string_lossy().into_owned()),
            enabled,
            detail: Some(detail),
            def_meta: Some(meta),
            owner_uid: None,
            find_executable: true,
        },
        text,
    );
}

fn not_backup(p: &Path) -> bool {
    let n = p
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    !(n.starts_with('.')
        || n.ends_with('~')
        || n.ends_with(".rpmsave")
        || n.ends_with(".rpmnew")
        || n.ends_with(".dpkg-old")
        || n.ends_with(".dpkg-dist")
        || n == "README")
}

pub(crate) fn sysv_init(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    // Scripts started in a multi-user runlevel have an S## link there.
    let mut started: HashSet<String> = HashSet::new();
    for base in ["/etc", "/etc/rc.d"] {
        for level in 2..=5 {
            let dir = PathBuf::from(format!("{base}/rc{level}.d"));
            if let Ok(entries) = ctx.root.read_dir(&dir) {
                for e in entries {
                    if let Some(rest) = e.name.strip_prefix('S') {
                        started.insert(
                            rest.trim_start_matches(|c: char| c.is_ascii_digit())
                                .to_owned(),
                        );
                    }
                }
            }
        }
    }
    let mut seen = HashSet::new();
    for dir in ["/etc/init.d", "/etc/rc.d/init.d"] {
        for (path, meta) in files_in(ctx, &mut run, Path::new(dir)) {
            if !not_backup(&path) || !seen.insert((meta.dev, meta.ino)) || ctx.cancelled() {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let enabled = Some(started.contains(&name));
            program(
                ctx,
                &mut run,
                &path,
                meta,
                PersistenceMechanism::SysvInit,
                PersistenceScope::System,
                enabled,
                "SysV init script".into(),
            );
        }
    }
    run.finish("persistence.sysv_init", "SysV init scripts", ctx.cancel)
}

pub(crate) fn at_jobs(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    for dir in ["/var/spool/at", "/var/spool/cron/atjobs"] {
        for (path, meta) in files_in(ctx, &mut run, Path::new(dir)) {
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                continue;
            }
            let Some((text, _)) = read(ctx, &mut run, &path) else {
                continue;
            };
            // Job files start with the submitter's whole environment; it
            // is never copied into the report, only searched.
            ctx.record(
                Found {
                    mechanism: PersistenceMechanism::AtJob,
                    scope: if meta.uid == 0 {
                        PersistenceScope::System
                    } else {
                        PersistenceScope::User
                    },
                    location: &path,
                    command: None,
                    enabled: Some(meta.mode & 0o100 != 0),
                    detail: Some(format!("at job owned by uid {}", meta.uid)),
                    def_meta: Some(meta),
                    owner_uid: Some(meta.uid),
                    find_executable: true,
                },
                Some(&text),
            );
        }
    }
    if ctx.users_limited {
        run.notes
            .push("the at spool is readable only by root".into());
    }
    run.finish("persistence.at_jobs", "at jobs", ctx.cancel)
}

pub(crate) fn generators(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut seen = HashSet::new();
    for kind in [
        "system-generators",
        "user-generators",
        "system-environment-generators",
        "user-environment-generators",
    ] {
        for base in [
            "/etc/systemd",
            "/run/systemd",
            "/usr/local/lib/systemd",
            "/usr/lib/systemd",
            "/lib/systemd",
        ] {
            let dir = PathBuf::from(format!("{base}/{kind}"));
            for (path, meta) in files_in(ctx, &mut run, &dir) {
                if seen.insert((meta.dev, meta.ino)) {
                    program(
                        ctx,
                        &mut run,
                        &path,
                        meta,
                        PersistenceMechanism::SystemdGenerator,
                        PersistenceScope::System,
                        Some(meta.mode & 0o111 != 0),
                        format!("systemd {kind}"),
                    );
                }
            }
        }
    }
    run.finish(
        "persistence.systemd_generators",
        "systemd generators",
        ctx.cancel,
    )
}

pub(crate) fn kernel_modules(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut files: Vec<(PathBuf, Meta)> = Vec::new();
    for dir in [
        "/etc/modules-load.d",
        "/run/modules-load.d",
        "/usr/local/lib/modules-load.d",
        "/usr/lib/modules-load.d",
        "/lib/modules-load.d",
    ] {
        files.extend(
            files_in(ctx, &mut run, Path::new(dir))
                .into_iter()
                .filter(|(p, _)| p.extension().is_some_and(|e| e == "conf")),
        );
    }
    if let Ok(m) = ctx.root.stat(Path::new("/etc/modules")) {
        files.push((PathBuf::from("/etc/modules"), m));
    }
    for (path, _) in files {
        let Some((text, meta)) = read(ctx, &mut run, &path) else {
            continue;
        };
        for module in text
            .lines()
            .map(|l| l.split(['#', ';']).next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
            .take(1000)
        {
            ctx.record(
                Found {
                    mechanism: PersistenceMechanism::KernelModule,
                    scope: PersistenceScope::System,
                    location: &path,
                    command: Some(module.to_owned()),
                    enabled: Some(true),
                    detail: Some("module loaded at boot".into()),
                    def_meta: Some(meta),
                    owner_uid: None,
                    find_executable: false,
                },
                None,
            );
        }
    }
    // modprobe.d: `install NAME COMMAND` / `remove NAME COMMAND` run a
    // shell command as root whenever the module is loaded or removed.
    for dir in [
        "/etc/modprobe.d",
        "/run/modprobe.d",
        "/usr/local/lib/modprobe.d",
        "/usr/lib/modprobe.d",
        "/lib/modprobe.d",
    ] {
        for (path, _) in files_in(ctx, &mut run, Path::new(dir)) {
            if !path.extension().is_some_and(|e| e == "conf") {
                continue;
            }
            let Some((text, meta)) = read(ctx, &mut run, &path) else {
                continue;
            };
            for line in logical_lines(&text) {
                if let Some((verb, module, cmd)) = parse_modprobe_command(&line) {
                    ctx.record(
                        Found {
                            mechanism: PersistenceMechanism::KernelModule,
                            scope: PersistenceScope::System,
                            location: &path,
                            command: Some(cmd),
                            enabled: Some(true),
                            detail: Some(format!("modprobe {verb} {module}")),
                            def_meta: Some(meta),
                            owner_uid: None,
                            find_executable: true,
                        },
                        None,
                    );
                }
            }
        }
    }
    run.finish(
        "persistence.kernel_modules",
        "Kernel modules loaded at boot, modprobe commands",
        ctx.cancel,
    )
}

/// (`install`|`remove`, module, command) of a modprobe.d line.
pub(crate) fn parse_modprobe_command(line: &str) -> Option<(String, String, String)> {
    let line = line.trim();
    let (verb, rest) = line.split_once(char::is_whitespace)?;
    if verb != "install" && verb != "remove" {
        return None;
    }
    let (module, cmd) = rest.trim_start().split_once(char::is_whitespace)?;
    let cmd = cmd.trim();
    (!cmd.is_empty()).then(|| (verb.to_owned(), module.to_owned(), cmd.to_owned()))
}

pub(crate) fn motd(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    for (path, meta) in files_in(ctx, &mut run, Path::new("/etc/update-motd.d")) {
        if not_backup(&path) {
            program(
                ctx,
                &mut run,
                &path,
                meta,
                PersistenceMechanism::Motd,
                PersistenceScope::System,
                Some(meta.mode & 0o111 != 0),
                "run as root at login (pam_motd)".into(),
            );
        }
    }
    run.finish("persistence.motd", "Message-of-the-day scripts", ctx.cancel)
}

pub(crate) fn ssh_rc(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut files: Vec<(PathBuf, PersistenceScope, Option<u32>)> = vec![(
        PathBuf::from("/etc/ssh/sshrc"),
        PersistenceScope::System,
        None,
    )];
    for u in ctx.users.clone() {
        let scope = if u.uid == 0 {
            PersistenceScope::System
        } else {
            PersistenceScope::User
        };
        files.push((u.home.join(".ssh/rc"), scope, Some(u.uid)));
    }
    for (path, scope, owner) in files {
        let Some((text, meta)) = read(ctx, &mut run, &path) else {
            continue;
        };
        ctx.record(
            Found {
                mechanism: PersistenceMechanism::SshRc,
                scope,
                location: &path,
                command: None,
                enabled: Some(true),
                detail: Some("run by sshd at every login".into()),
                def_meta: Some(meta),
                owner_uid: owner,
                find_executable: true,
            },
            Some(&text),
        );
    }
    note_user_limits(ctx, &mut run);
    run.finish("persistence.ssh_rc", "SSH login scripts", ctx.cancel)
}

/// Regular files below `dir`, at most `depth` levels down.
fn files_below(
    ctx: &mut Ctx<'_>,
    run: &mut Run,
    dir: &Path,
    depth: u32,
    out: &mut Vec<(PathBuf, Meta)>,
) {
    out.extend(files_in(ctx, run, dir));
    if depth == 0 || out.len() > 5000 {
        return;
    }
    if let Ok(entries) = ctx.root.read_dir(dir) {
        for e in entries.into_iter().filter(|e| e.kind == Kind::Dir) {
            files_below(ctx, run, &dir.join(&e.name), depth - 1, out);
        }
    }
}

pub(crate) fn initramfs_hooks(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut files = Vec::new();
    files_below(
        ctx,
        &mut run,
        Path::new("/etc/initramfs-tools/hooks"),
        2,
        &mut files,
    );
    files_below(
        ctx,
        &mut run,
        Path::new("/etc/initramfs-tools/scripts"),
        3,
        &mut files,
    );
    for (path, meta) in files {
        if not_backup(&path) {
            program(
                ctx,
                &mut run,
                &path,
                meta,
                PersistenceMechanism::InitramfsHook,
                PersistenceScope::System,
                Some(true),
                "initramfs-tools hook or script (runs in early boot)".into(),
            );
        }
    }
    let mut confs = files_in(ctx, &mut run, Path::new("/etc/dracut.conf.d"));
    if let Ok(m) = ctx.root.stat(Path::new("/etc/dracut.conf")) {
        confs.push((PathBuf::from("/etc/dracut.conf"), m));
    }
    for (path, _) in confs {
        let Some((text, meta)) = read(ctx, &mut run, &path) else {
            continue;
        };
        let items: Vec<String> = text
            .lines()
            .filter(|l| {
                let l = l.trim_start();
                l.starts_with("install_items")
                    || l.starts_with("add_dracutmodules")
                    || l.starts_with("add_drivers")
            })
            .map(|l| l.trim().to_owned())
            .take(20)
            .collect();
        ctx.record(
            Found {
                mechanism: PersistenceMechanism::InitramfsHook,
                scope: PersistenceScope::System,
                location: &path,
                command: None,
                enabled: Some(true),
                detail: Some(if items.is_empty() {
                    "dracut configuration".into()
                } else {
                    items.join("; ")
                }),
                def_meta: Some(meta),
                owner_uid: None,
                find_executable: false,
            },
            Some(&text),
        );
    }
    run.finish("persistence.initramfs_hooks", "initramfs hooks", ctx.cancel)
}

pub(crate) fn boot_loader(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    for (path, meta) in files_in(ctx, &mut run, Path::new("/etc/grub.d")) {
        if not_backup(&path) {
            program(
                ctx,
                &mut run,
                &path,
                meta,
                PersistenceMechanism::BootLoader,
                PersistenceScope::System,
                Some(meta.mode & 0o111 != 0),
                "GRUB configuration script (run as root by grub-mkconfig)".into(),
            );
        }
    }
    if ctx.users_limited {
        run.notes
            .push("/etc/grub.d is readable only by root on some systems".into());
    }
    run.finish("persistence.boot_loader", "Boot loader scripts", ctx.cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modprobe_commands() {
        assert_eq!(
            parse_modprobe_command("install usb-storage /bin/true"),
            Some(("install".into(), "usb-storage".into(), "/bin/true".into()))
        );
        assert_eq!(
            parse_modprobe_command("remove x   /sbin/modprobe -r --ignore-remove x && /tmp/y"),
            Some((
                "remove".into(),
                "x".into(),
                "/sbin/modprobe -r --ignore-remove x && /tmp/y".into()
            ))
        );
        assert_eq!(parse_modprobe_command("options x a=1"), None);
        assert_eq!(parse_modprobe_command("install x"), None);
    }
}
