//! udev rules that run programs.

use std::collections::HashSet;
use std::path::Path;

use warden_core::{CheckResult, PersistenceMechanism, PersistenceScope};

use super::{files_in, read};
use crate::ctx::{Ctx, Found, Run};

const DIRS: &[&str] = &[
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
    "/usr/local/lib/udev/rules.d",
    "/usr/lib/udev/rules.d",
    "/lib/udev/rules.d",
];

pub(crate) fn check(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    let mut seen = HashSet::new();
    for dir in DIRS {
        for (path, meta) in files_in(ctx, &mut run, Path::new(dir)) {
            if !path.extension().is_some_and(|e| e == "rules") || !seen.insert((meta.dev, meta.ino))
            {
                continue;
            }
            let Some((text, meta)) = read(ctx, &mut run, &path) else {
                continue;
            };
            for line in super::logical_lines(&text) {
                for (key, program) in programs(&line) {
                    // Relative programs are looked up in the udev directory.
                    let command = if program.starts_with('/') {
                        program
                    } else {
                        format!("/usr/lib/udev/{program}")
                    };
                    ctx.record(
                        Found {
                            mechanism: PersistenceMechanism::Udev,
                            scope: PersistenceScope::System,
                            location: &path,
                            command: Some(command),
                            enabled: Some(true),
                            detail: Some(key),
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
        "persistence.udev",
        "udev rules that run programs",
        ctx.cancel,
    )
}

/// `RUN`, `PROGRAM` and `IMPORT{program}` values of one rule line.
/// `RUN{builtin}` runs code inside udev and is ignored.
pub(crate) fn programs(line: &str) -> Vec<(String, String)> {
    let line = line.trim();
    if line.starts_with('#') {
        return Vec::new();
    }
    let mut out = Vec::new();
    for part in split_rule(line) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let k = k.trim_end_matches(['+', ':', '!']).trim();
        let wanted = k == "RUN" || k == "RUN{program}" || k == "PROGRAM" || k == "IMPORT{program}";
        if wanted {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() {
                out.push((k.to_owned(), v.to_owned()));
            }
        }
        if out.len() >= 16 {
            break;
        }
    }
    out
}

/// Splits a rule line at commas outside quotes.
fn split_rule(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(line[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(line[start..].trim());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_programs() {
        let p = programs(
            "ACTION==\"add\", SUBSYSTEM==\"usb\", RUN+=\"/bin/sh -c 'a, b'\", RUN{builtin}+=\"kmod load\", PROGRAM=\"x\"",
        );
        assert_eq!(
            p,
            [
                ("RUN".to_owned(), "/bin/sh -c 'a, b'".to_owned()),
                ("PROGRAM".to_owned(), "x".to_owned())
            ]
        );
        assert!(programs("# RUN+=\"/x\"").is_empty());
    }
}
