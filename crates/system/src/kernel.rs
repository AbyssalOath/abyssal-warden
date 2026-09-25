//! Kernel checks on the running system: loaded-module cross-view and taint
//! flags. A kernel rootkit controls every view a user-space tool can read,
//! so a clean result here is not proof of absence (see the docs).

use std::collections::BTreeSet;
use std::path::Path;

use warden_core::{CheckResult, FindingTarget};

use crate::ctx::{Ctx, Run};
use crate::rules;

/// Loadable modules according to `/proc/modules` (name, taint letters).
pub(crate) fn proc_modules(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let name = l.split_whitespace().next()?;
            let taint = l
                .rsplit_once('(')
                .filter(|(_, r)| r.ends_with(')') && !r.contains(' '))
                .map(|(_, r)| r.trim_end_matches(')').to_owned())
                .unwrap_or_default();
            Some((name.to_owned(), taint))
        })
        .collect()
}

/// Loadable modules according to `/sys/module/*/initstate`.
fn sys_modules(sys_module: &Path) -> std::io::Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for e in std::fs::read_dir(sys_module)? {
        let e = e?;
        if e.path().join("initstate").exists()
            && let Some(n) = e.file_name().to_str()
        {
            out.insert(n.to_owned());
        }
    }
    Ok(out)
}

/// Names present in only one of the views, as (name, where it is missing).
pub(crate) fn cross_view(
    proc_names: &BTreeSet<String>,
    sys_names: &BTreeSet<String>,
) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = sys_names
        .difference(proc_names)
        .map(|n| (n.clone(), "/proc/modules"))
        .collect();
    out.extend(
        proc_names
            .difference(sys_names)
            .map(|n| (n.clone(), "/sys/module")),
    );
    out
}

/// (`/proc/modules` entries with taint letters, `/sys/module` names).
type Views = (Vec<(String, String)>, BTreeSet<String>);

pub(crate) fn modules(ctx: &mut Ctx<'_>, proc: &Path, sys: &Path) -> CheckResult {
    let mut run = Run::default();
    let read_views = || -> std::io::Result<Views> {
        let p = proc_modules(&std::fs::read_to_string(proc.join("modules"))?);
        let s = sys_modules(&sys.join("module"))?;
        Ok((p, s))
    };
    let first = match read_views() {
        Ok(v) => v,
        Err(e) => {
            ctx.io_error(&mut run, &proc.join("modules"), &e);
            return run.finish("kernel.modules", "Kernel module cross-view", ctx.cancel);
        }
    };
    let names = |v: &[(String, String)]| v.iter().map(|(n, _)| n.clone()).collect::<BTreeSet<_>>();
    let mismatches = cross_view(&names(&first.0), &first.1);
    run.examined = first.0.len() as u64;
    if !mismatches.is_empty() {
        // Modules load and unload; only report what persists across a
        // second read.
        std::thread::sleep(std::time::Duration::from_millis(200));
        if let Ok(second) = read_views() {
            let again = cross_view(&names(&second.0), &second.1);
            for (name, missing) in mismatches.into_iter().filter(|m| again.contains(m)) {
                ctx.report(
                    &rules::MODULE_HIDDEN,
                    FindingTarget::System {
                        component: format!("kernel module {name}"),
                    },
                    format!("module {name} is missing from {missing}"),
                );
            }
        }
    }
    let tainted: Vec<String> = first
        .0
        .iter()
        .filter(|(_, t)| !t.is_empty())
        .map(|(n, t)| format!("{n} ({t})"))
        .collect();
    if !tainted.is_empty() {
        run.notes
            .push(format!("modules with taint flags: {}", tainted.join(", ")));
    }
    run.finish("kernel.modules", "Kernel module cross-view", ctx.cancel)
}

/// Kernel taint bits and letters (Documentation/admin-guide/tainted-kernels).
const TAINT: &[(u32, char, &str)] = &[
    (0, 'P', "proprietary module"),
    (1, 'F', "module force-loaded"),
    (2, 'S', "kernel running on an out-of-spec system"),
    (3, 'R', "module force-unloaded"),
    (4, 'M', "machine check"),
    (5, 'B', "bad page"),
    (6, 'U', "taint requested by user space"),
    (7, 'D', "kernel died recently (oops or BUG)"),
    (8, 'A', "ACPI table overridden"),
    (9, 'W', "kernel warning"),
    (10, 'C', "staging driver"),
    (11, 'I', "firmware bug workaround"),
    (12, 'O', "out-of-tree module"),
    (13, 'E', "unsigned module"),
    (14, 'L', "soft lockup"),
    (15, 'K', "kernel live-patched"),
    (16, 'X', "auxiliary taint"),
    (17, 'T', "struct randomization plugin"),
    (18, 'N', "in-kernel test"),
];

pub(crate) fn describe_taint(value: u64) -> Vec<(char, &'static str)> {
    TAINT
        .iter()
        .filter(|(bit, _, _)| value & (1 << bit) != 0)
        .map(|(_, c, d)| (*c, *d))
        .collect()
}

pub(crate) fn taint(ctx: &mut Ctx<'_>, proc: &Path) -> CheckResult {
    let mut run = Run::default();
    let path = proc.join("sys/kernel/tainted");
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            run.examined = 1;
            let value: u64 = text.trim().parse().unwrap_or(0);
            let flags = describe_taint(value);
            let list = |set: &[char]| {
                flags
                    .iter()
                    .filter(|(c, _)| set.contains(c))
                    .map(|(c, d)| format!("{c}: {d}"))
                    .collect::<Vec<_>>()
            };
            let forced = list(&['F', 'R']);
            if !forced.is_empty() {
                ctx.report(
                    &rules::KERNEL_FORCED,
                    FindingTarget::System {
                        component: "kernel".into(),
                    },
                    format!("taint {value}: {}", forced.join(", ")),
                );
            }
            let info = list(&['P', 'O', 'E']);
            if !info.is_empty() {
                ctx.report(
                    &rules::KERNEL_TAINT_INFO,
                    FindingTarget::System {
                        component: "kernel".into(),
                    },
                    format!("taint {value}: {}", info.join(", ")),
                );
            }
            if !flags.is_empty() {
                run.notes.push(format!(
                    "taint {value}: {}",
                    flags.iter().map(|(c, _)| c.to_string()).collect::<String>()
                ));
            }
        }
        Err(e) => ctx.io_error(&mut run, &path, &e),
    }
    run.finish("kernel.taint", "Kernel taint flags", ctx.cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_modules() {
        let m = proc_modules(
            "nvidia 1 2 - Live 0xffffffffc0000000 (POE)\nxfs 3 1 - Live 0xffffffffc1000000\n",
        );
        assert_eq!(
            m,
            [
                ("nvidia".into(), "POE".into()),
                ("xfs".into(), String::new())
            ]
        );
    }

    #[test]
    fn cross_view_both_directions() {
        let p: BTreeSet<String> = ["a", "b"].map(String::from).into();
        let s: BTreeSet<String> = ["b", "c"].map(String::from).into();
        assert_eq!(
            cross_view(&p, &s),
            [("c".into(), "/proc/modules"), ("a".into(), "/sys/module")]
        );
    }

    #[test]
    fn taint_letters() {
        let d: String = describe_taint(1 | 2 | (1 << 12) | (1 << 13))
            .iter()
            .map(|(c, _)| *c)
            .collect();
        assert_eq!(d, "PFOE");
        assert!(describe_taint(0).is_empty());
    }

    #[test]
    fn sys_view_from_fake_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("module/loaded")).expect("mkdir");
        std::fs::write(dir.path().join("module/loaded/initstate"), "live").expect("write");
        std::fs::create_dir_all(dir.path().join("module/builtin")).expect("mkdir");
        let s = sys_modules(&dir.path().join("module")).expect("read");
        assert_eq!(s.into_iter().collect::<Vec<_>>(), ["loaded"]);
    }
}
