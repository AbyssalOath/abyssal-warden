//! PAM stacks: modules loaded from unusual places and pam_exec programs.

use std::path::Path;

use warden_core::{
    CheckResult, FindingTarget, ObservedPath, PersistenceMechanism, PersistenceScope,
};

use super::{files_in, read};
use crate::ctx::{Ctx, Found, Run};
use crate::heuristics::snippet;
use crate::rules;

/// Directories PAM modules are installed in.
const MODULE_DIRS: &[&str] = &[
    "/lib/security/",
    "/lib64/security/",
    "/usr/lib/security/",
    "/usr/lib64/security/",
    "/lib/x86_64-linux-gnu/security/",
    "/usr/lib/x86_64-linux-gnu/security/",
    "/lib/aarch64-linux-gnu/security/",
    "/usr/lib/aarch64-linux-gnu/security/",
    "/usr/lib/i386-linux-gnu/security/",
];

pub(crate) fn check(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut files = files_in(ctx, &mut run, Path::new("/etc/pam.d"));
    if let Ok(m) = ctx.root.stat(Path::new("/etc/pam.conf")) {
        files.push((Path::new("/etc/pam.conf").to_owned(), m));
    }
    for (path, _) in files {
        let Some((text, meta)) = read(ctx, &mut run, &path) else {
            continue;
        };
        let conf = path == Path::new("/etc/pam.conf");
        for line in text.lines().map(str::trim) {
            let Some(l) = parse_line(line, conf) else {
                continue;
            };
            let target = || FindingTarget::Persistence {
                mechanism: PersistenceMechanism::Pam,
                location: ObservedPath::from_path(&path),
                entry: Some(snippet(line)),
            };
            let nonstandard =
                l.module.starts_with('/') && !MODULE_DIRS.iter().any(|d| l.module.starts_with(d));
            if nonstandard {
                ctx.report(
                    &rules::PAM_NONSTANDARD,
                    target(),
                    format!("loads {}", l.module),
                );
            }
            let exec = l.module.rsplit('/').next() == Some("pam_exec.so");
            if exec {
                ctx.report(
                    &rules::PAM_EXEC,
                    target(),
                    format!("{} runs pam_exec", l.kind),
                );
            }
            if nonstandard || exec {
                let program = if exec {
                    l.args.iter().find(|a| a.starts_with('/')).cloned()
                } else {
                    Some(l.module.clone())
                };
                ctx.record(
                    Found {
                        mechanism: PersistenceMechanism::Pam,
                        scope: PersistenceScope::System,
                        location: &path,
                        command: program.map(|p| {
                            let rest = if exec {
                                l.args.join(" ")
                            } else {
                                String::new()
                            };
                            if rest.is_empty() { p } else { rest }
                        }),
                        enabled: Some(true),
                        detail: Some(format!("{} {}", l.kind, l.module)),
                        def_meta: Some(meta),
                        owner_uid: None,
                        find_executable: true,
                    },
                    None,
                );
            }
        }
    }
    run.finish("persistence.pam", "PAM modules", ctx.cancel)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PamLine {
    kind: String,
    module: String,
    args: Vec<String>,
}

/// `[-]type control module args...`; control may be a `[...]` group.
/// pam.conf lines start with the service name.
pub(crate) fn parse_line(line: &str, conf: bool) -> Option<PamLine> {
    if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
        return None;
    }
    let mut rest = line;
    if conf {
        rest = rest.trim_start().split_once(char::is_whitespace)?.1;
    }
    let (kind, r) = rest.trim_start().split_once(char::is_whitespace)?;
    let r = r.trim_start();
    let r = if let Some(stripped) = r.strip_prefix('[') {
        stripped.split_once(']')?.1
    } else {
        r.split_once(char::is_whitespace)?.1
    };
    let mut it = r.split_whitespace();
    let module = it.next()?.to_owned();
    if matches!(
        kind.trim_start_matches('-'),
        "auth" | "account" | "password" | "session"
    ) {
        Some(PamLine {
            kind: kind.to_owned(),
            module,
            args: it.map(str::to_owned).collect(),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pam_lines() {
        let l =
            parse_line("auth [success=1 default=ignore] pam_unix.so nullok", false).expect("line");
        assert_eq!(l.module, "pam_unix.so");
        assert_eq!(l.args, ["nullok"]);
        let l = parse_line("-session optional /tmp/x.so", false).expect("line");
        assert_eq!(l.module, "/tmp/x.so");
        let l = parse_line("sshd auth required pam_exec.so /bin/x", true).expect("line");
        assert_eq!(l.args, ["/bin/x"]);
        assert_eq!(parse_line("@include common-auth", false), None);
        assert_eq!(parse_line("#auth x y", false), None);
    }
}
