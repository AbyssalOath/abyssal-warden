//! Boot integrity: Secure Boot, kernel lockdown and module signature
//! enforcement (running system), risky kernel command-line options (running
//! and configured), and permissions of everything under /boot.
//!
//! This does not verify firmware, the boot loader binary or the initramfs
//! contents against a measurement (TPM event log); see the docs.

use std::path::{Path, PathBuf};

use warden_core::{CheckResult, FindingTarget, ObservedPath, PersistenceMechanism};

use crate::ctx::{Ctx, Run};
use crate::fsx::Kind;
use crate::heuristics::shell_tokens;
use crate::rules;

const SECURE_BOOT_VAR: &str =
    "firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const STANDARD_INIT: &[&str] = &[
    "/sbin/init",
    "/usr/sbin/init",
    "/usr/lib/systemd/systemd",
    "/lib/systemd/systemd",
    "/init",
];
/// Most files under /boot examined.
const MAX_BOOT_FILES: usize = 5000;

/// Command-line options that disable a security mechanism or replace
/// init, with the reason.
pub(crate) fn weak_cmdline(cmdline: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for tok in shell_tokens(cmdline) {
        let (key, value) = tok
            .split_once('=')
            .map_or((tok.as_str(), None), |(k, v)| (k, Some(v)));
        let why = match (key, value) {
            ("selinux", Some("0")) => Some("disables SELinux"),
            ("enforcing", Some("0")) => Some("puts SELinux in permissive mode"),
            ("apparmor", Some("0")) => Some("disables AppArmor"),
            ("security", Some("none" | "")) => Some("disables the security module"),
            ("audit", Some("0")) => Some("disables kernel auditing"),
            ("module.sig_enforce", Some("0")) => Some("turns off module signature enforcement"),
            ("ima_appraise", Some("off" | "fix" | "log")) => Some("turns off IMA appraisal"),
            ("rd.break", _) => Some("drops to a root shell in the initramfs"),
            ("systemd.debug_shell" | "systemd.debug-shell", v) if v != Some("0") => {
                Some("starts an unauthenticated root shell on tty9")
            }
            ("init" | "rdinit", Some(v)) if !STANDARD_INIT.contains(&v) => Some("replaces init"),
            _ => None,
        };
        if let Some(why) = why {
            out.push((tok.clone(), why));
        }
    }
    out
}

pub(crate) fn check(ctx: &mut Ctx<'_>, proc: &Path, sys: &Path) -> CheckResult {
    let mut run = Run::default();
    let live = ctx.root.is_live();

    if live {
        // Secure Boot: 4 attribute bytes, then 1 (on) or 0 (off).
        if !sys.join("firmware/efi").exists() {
            run.notes.push("legacy BIOS boot (no Secure Boot)".into());
        } else {
            match std::fs::read(sys.join(SECURE_BOOT_VAR)) {
                Ok(v) if v.len() >= 5 => {
                    run.examined += 1;
                    if v[4] == 1 {
                        run.notes.push("Secure Boot on".into());
                    } else {
                        ctx.report(
                            &rules::SECURE_BOOT_OFF,
                            FindingTarget::System {
                                component: "firmware".into(),
                            },
                            "SecureBoot EFI variable is 0".into(),
                        );
                    }
                }
                Ok(_) => run.notes.push("SecureBoot EFI variable malformed".into()),
                Err(e) => ctx.io_error(&mut run, &sys.join(SECURE_BOOT_VAR), &e),
            }
        }
        if let Ok(l) = std::fs::read_to_string(sys.join("kernel/security/lockdown")) {
            let mode = l
                .split_whitespace()
                .find(|w| w.starts_with('['))
                .unwrap_or("?");
            run.notes
                .push(format!("kernel lockdown {}", mode.trim_matches(['[', ']'])));
        }
        if let Ok(s) = std::fs::read_to_string(sys.join("module/module/parameters/sig_enforce")) {
            run.notes.push(format!(
                "module signatures {}",
                if s.trim() == "Y" {
                    "enforced"
                } else {
                    "not enforced"
                }
            ));
        }
        match std::fs::read_to_string(proc.join("cmdline")) {
            Ok(cmdline) => {
                run.examined += 1;
                for (tok, why) in weak_cmdline(&cmdline) {
                    ctx.report(
                        &rules::WEAK_CMDLINE,
                        FindingTarget::System {
                            component: "running kernel command line".into(),
                        },
                        format!("{tok}: {why}"),
                    );
                }
            }
            Err(e) => ctx.io_error(&mut run, &proc.join("cmdline"), &e),
        }
    }

    // Configured command lines (take effect at the next boot).
    let mut configs: Vec<(PathBuf, Vec<String>)> = Vec::new();
    for (path, keys) in [
        (
            "/etc/default/grub",
            &["GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"][..],
        ),
        ("/etc/kernel/cmdline", &[][..]),
    ] {
        if let Ok(t) = ctx.root.read_text(Path::new(path)) {
            run.examined += 1;
            let lines = if keys.is_empty() {
                t.text.lines().map(str::to_owned).collect()
            } else {
                t.text
                    .lines()
                    .filter_map(|l| {
                        let (k, v) = l.trim().split_once('=')?;
                        keys.contains(&k.trim())
                            .then(|| v.trim().trim_matches(['"', '\'']).to_owned())
                    })
                    .collect()
            };
            configs.push((PathBuf::from(path), lines));
        }
    }
    if let Ok(entries) = ctx.root.read_dir(Path::new("/boot/loader/entries")) {
        for e in entries
            .into_iter()
            .filter(|e| e.name.ends_with(".conf"))
            .take(200)
        {
            let path = PathBuf::from("/boot/loader/entries").join(&e.name);
            if let Ok(t) = ctx.root.read_text(&path) {
                run.examined += 1;
                let opts = t
                    .text
                    .lines()
                    .filter_map(|l| {
                        l.trim()
                            .strip_prefix("options")
                            .map(|o| o.trim().to_owned())
                    })
                    .collect();
                configs.push((path, opts));
            }
        }
    }
    for (path, lines) in configs {
        for line in lines {
            for (tok, why) in weak_cmdline(&line) {
                ctx.report(
                    &rules::WEAK_CMDLINE,
                    FindingTarget::Persistence {
                        mechanism: PersistenceMechanism::BootLoader,
                        location: ObservedPath::from_path(&path),
                        entry: Some(tok.clone()),
                    },
                    format!("configured for the next boot: {tok}: {why}"),
                );
            }
        }
    }

    // Permissions of everything under /boot.
    let mut stack = vec![PathBuf::from("/boot")];
    let mut count = 0usize;
    while let Some(dir) = stack.pop() {
        if ctx.cancelled() || count >= MAX_BOOT_FILES {
            break;
        }
        match ctx.root.lstat(&dir) {
            Ok(m) if m.kind == Kind::Dir => {
                if m.dir_writable_by_non_root() {
                    boot_writable(ctx, &dir, m);
                }
            }
            _ => continue,
        }
        let entries = match ctx.root.read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                ctx.io_error(&mut run, &dir, &e);
                continue;
            }
        };
        for e in entries {
            let path = dir.join(&e.name);
            match e.kind {
                Kind::Dir => stack.push(path),
                Kind::File => {
                    count += 1;
                    if let Ok(m) = ctx.root.lstat(&path)
                        && m.writable_by_non_root()
                    {
                        boot_writable(ctx, &path, m);
                    }
                }
                _ => {}
            }
        }
    }
    run.examined += count as u64;
    if count >= MAX_BOOT_FILES {
        run.partial = true;
        run.notes
            .push(format!("stopped after {MAX_BOOT_FILES} files under /boot"));
    }
    run.finish(
        "boot.integrity",
        "Boot configuration and /boot permissions",
        ctx.cancel,
    )
}

fn boot_writable(ctx: &mut Ctx<'_>, path: &Path, m: crate::fsx::Meta) {
    ctx.report(
        &rules::BOOT_WRITABLE,
        FindingTarget::File {
            path: ObservedPath::from_path(path),
            sha256: None,
            metadata: None,
        },
        format!("owner uid {}, group {}, mode {:04o}", m.uid, m.gid, m.mode),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_weakening_options() {
        let found: Vec<String> = weak_cmdline(
            "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet selinux=0 init=/bin/bash \
             systemd.debug-shell module.sig_enforce=0 audit=0 rd.break",
        )
        .into_iter()
        .map(|(t, _)| t)
        .collect();
        assert_eq!(
            found,
            [
                "selinux=0",
                "init=/bin/bash",
                "systemd.debug-shell",
                "module.sig_enforce=0",
                "audit=0",
                "rd.break"
            ]
        );
        assert!(
            weak_cmdline(
                "root=/dev/mapper/r ro rhgb quiet init=/usr/lib/systemd/systemd selinux=1"
            )
            .is_empty()
        );
        assert!(weak_cmdline("systemd.debug_shell=0").is_empty());
    }
}
