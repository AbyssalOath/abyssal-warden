//! Inventory of loaded eBPF programs on the running system.
//!
//! Sources, most complete first: `bpftool -j prog show` (root; lists every
//! loaded program, including ones attached to cgroups or network devices
//! that no process holds), programs held open by processes
//! (`/proc/PID/fdinfo`), and objects pinned in bpffs. Programs are listed,
//! not judged: without inspecting their instructions there is no reliable
//! way to tell a malicious program from a monitoring tool.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use warden_core::{
    CheckResult, ObservedPath, PersistenceEntry, PersistenceMechanism, PersistenceScope,
};

use crate::ctx::{Ctx, Run};

const BPFTOOL: &[&str] = &["/usr/sbin/bpftool", "/usr/bin/bpftool", "/sbin/bpftool"];

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Prog {
    pub(crate) id: u64,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) tag: String,
    /// (pid, command) of processes holding it.
    pub(crate) holders: Vec<(u32, String)>,
}

/// Parses `bpftool -j prog show`.
pub(crate) fn parse_bpftool(json: &str) -> Vec<Prog> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(json)
    else {
        return Vec::new();
    };
    items
        .iter()
        .take(10_000)
        .filter_map(|p| {
            let s = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
            Some(Prog {
                id: p.get("id")?.as_u64()?,
                kind: s("type"),
                name: s("name"),
                tag: s("tag"),
                holders: p
                    .get("pids")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|h| {
                                Some((
                                    u32::try_from(h.get("pid")?.as_u64()?).ok()?,
                                    h.get("comm")
                                        .and_then(|c| c.as_str())
                                        .unwrap_or("")
                                        .to_owned(),
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// (prog_type, prog_id, prog_tag) from a bpf-prog fd's fdinfo.
pub(crate) fn parse_fdinfo(text: &str) -> Option<(String, u64, String)> {
    let get = |k: &str| {
        text.lines().find_map(|l| {
            l.strip_prefix(k)
                .map(|v| v.trim_start_matches(':').trim().to_owned())
        })
    };
    Some((
        get("prog_type")?,
        get("prog_id")?.parse().ok()?,
        get("prog_tag").unwrap_or_default(),
    ))
}

fn from_processes(proc: &Path, run: &mut Run, cancelled: impl Fn() -> bool) -> BTreeMap<u64, Prog> {
    let mut out: BTreeMap<u64, Prog> = BTreeMap::new();
    let Ok(dirs) = std::fs::read_dir(proc) else {
        return out;
    };
    let mut denied = 0u64;
    for d in dirs.flatten() {
        if cancelled() {
            break;
        }
        let Some(pid) = d.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let fd_dir = d.path().join("fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(_) => {
                denied += 1;
                continue;
            }
        };
        for fd in fds.flatten().take(65_536) {
            let is_prog =
                std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == "anon_inode:bpf-prog");
            if !is_prog {
                continue;
            }
            let info = d.path().join("fdinfo").join(fd.file_name());
            if let Some((kind, id, tag)) = std::fs::read_to_string(info)
                .ok()
                .as_deref()
                .and_then(parse_fdinfo)
            {
                let comm = std::fs::read_to_string(d.path().join("comm"))
                    .map(|c| c.trim().to_owned())
                    .unwrap_or_default();
                let p = out.entry(id).or_insert_with(|| Prog {
                    id,
                    kind,
                    tag,
                    ..Prog::default()
                });
                if !p.holders.iter().any(|(h, _)| *h == pid) {
                    p.holders.push((pid, comm));
                }
            }
        }
        run.examined += 1;
    }
    if denied > 0 {
        run.partial = true;
        run.notes
            .push(format!("{denied} process(es) not readable; run as root"));
    }
    out
}

fn pinned(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let ft = e.file_type()?;
        if ft.is_dir() && depth > 0 {
            let _ = pinned(&e.path(), depth - 1, out);
        } else if !ft.is_dir() {
            out.push(e.path());
        }
        if out.len() >= 10_000 {
            break;
        }
    }
    Ok(())
}

pub(crate) fn check(ctx: &mut Ctx<'_>, proc: &Path, sys: &Path, timeout: Duration) -> CheckResult {
    let mut run = Run::default();
    let euid = rustix::process::geteuid().as_raw();
    let mut progs: BTreeMap<u64, Prog> = BTreeMap::new();
    let mut source = "processes' open descriptors";
    if euid == 0
        && let Some(tool) = BPFTOOL.iter().map(Path::new).find(|p| p.exists())
    {
        match crate::tool::run(
            tool,
            &["-j".into(), "prog".into(), "show".into()],
            timeout,
            ctx.cancel,
        ) {
            Ok(out) => {
                progs = parse_bpftool(&out).into_iter().map(|p| (p.id, p)).collect();
                source = "bpftool";
            }
            Err(e) => run.notes.push(format!("bpftool failed ({e}); using /proc")),
        }
    }
    if source != "bpftool" {
        let cancel = ctx.cancel;
        progs = from_processes(proc, &mut run, || cancel.is_cancelled());
        run.notes.push("programs attached without a holding process (cgroup, XDP, tc) are only listed by bpftool as root".into());
        if !crate::can_inspect_processes() {
            run.partial = true;
        }
    }
    let proc_path = |id: u64| PathBuf::from(format!("bpf program {id}"));
    for p in progs.values() {
        let holders = p
            .holders
            .iter()
            .map(|(pid, c)| format!("{pid} ({c})"))
            .collect::<Vec<_>>()
            .join(", ");
        ctx.persistence.push(PersistenceEntry {
            mechanism: PersistenceMechanism::Ebpf,
            scope: PersistenceScope::System,
            location: ObservedPath::from_path(&proc_path(p.id)),
            command: None,
            executable: None,
            enabled: Some(true),
            detail: Some(format!(
                "id {}, type {}, name {}, tag {}, held by {}",
                p.id,
                p.kind,
                if p.name.is_empty() { "-" } else { &p.name },
                if p.tag.is_empty() { "-" } else { &p.tag },
                if holders.is_empty() {
                    "no process (attached or pinned)".into()
                } else {
                    holders
                }
            )),
        });
    }
    let bpffs = sys.join("fs/bpf");
    let mut pins = Vec::new();
    match pinned(&bpffs, 4, &mut pins) {
        Ok(()) => {
            for p in pins {
                ctx.persistence.push(PersistenceEntry {
                    mechanism: PersistenceMechanism::Ebpf,
                    scope: PersistenceScope::System,
                    location: ObservedPath::from_path(&p),
                    command: None,
                    executable: None,
                    enabled: Some(true),
                    detail: Some("pinned eBPF object (survives until reboot)".into()),
                });
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            run.partial = true;
            run.notes.push(format!("{}: {e}", bpffs.display()));
        }
    }
    run.notes
        .push(format!("{} program(s) from {source}", progs.len()));
    run.finish("kernel.ebpf", "Loaded eBPF programs", ctx.cancel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bpftool_json() {
        let p = parse_bpftool(
            r#"[{"id":7,"type":"cgroup_device","tag":"ab","gpl_compatible":true},
                {"id":9,"type":"kprobe","name":"trace","tag":"cd","pids":[{"pid":12,"comm":"agent"}]},
                {"type":"missing id"}]"#,
        );
        assert_eq!(p.len(), 2);
        assert_eq!(p[1].holders, [(12, "agent".to_owned())]);
        assert!(parse_bpftool("not json").is_empty());
    }

    #[test]
    fn parses_fdinfo() {
        assert_eq!(
            parse_fdinfo(
                "pos:\t0\nflags:\t02000002\nprog_type:\t8\nprog_jited:\t1\nprog_tag:\t3b18\nprog_id:\t42\n"
            ),
            Some(("8".into(), 42, "3b18".into()))
        );
        assert_eq!(parse_fdinfo("pos: 0\n"), None);
    }
}
