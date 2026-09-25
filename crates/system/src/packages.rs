//! Package verification: are installed files still what the package
//! manager installed?
//!
//! Abyssal Warden reads and hashes every file itself, so a tampered `rpm`
//! or `dpkg` binary (or a user-mode rootkit hooking file reads in that
//! process) cannot hide a modified file:
//!
//! * **dpkg**: the database (`/var/lib/dpkg/info/*.list`, `*.md5sums`) is
//!   parsed directly; no dpkg program runs, so Debian-family images can be
//!   inspected from any host.
//! * **rpm**: the database format is not practical to parse without
//!   librpm, so the host's `/usr/bin/rpm` is asked only for the recorded
//!   digests (`rpm -q --qf`), with an empty environment, a timeout and no
//!   package scripts. The files are hashed here.
//!
//! The package database itself can be rewritten by anyone with root on the
//! inspected system; offline inspection from trusted media is the answer
//! (see the docs).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use md5::Md5;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use warden_core::{CheckResult, CheckStatus, FindingTarget, ObservedPath};

use crate::ctx::{Ctx, Run, skipped};
use crate::fsx::Kind;
use crate::heuristics::in_temp_dir;
use crate::rules;

pub(crate) const ID: &str = "packages.verify";
const TITLE: &str = "Package file verification";
const MAX_REFERENCED: usize = 2000;
/// Largest file hashed.
const MAX_HASH_BYTES: u64 = 1 << 30;
const RPM: &str = "/usr/bin/rpm";
const RPM_QUERY_FORMAT: &str =
    "[%{FILENAMES}\t%{=FILEDIGESTALGO}\t%{FILEDIGESTS}\t%{FILEFLAGS}\t%{FILEMODES}\n]";
const RPMFILE_CONFIG: u32 = 1;
const RPMFILE_GHOST: u32 = 1 << 6;

/// Programs and libraries rootkits commonly replace.
const CRITICAL: &[&str] = &[
    "/usr/bin/ls",
    "/usr/bin/ps",
    "/usr/bin/top",
    "/usr/bin/netstat",
    "/usr/bin/ss",
    "/usr/sbin/ss",
    "/usr/bin/lsof",
    "/usr/sbin/lsof",
    "/usr/bin/find",
    "/usr/bin/du",
    "/usr/bin/df",
    "/usr/bin/w",
    "/usr/bin/who",
    "/usr/bin/last",
    "/usr/bin/id",
    "/usr/bin/login",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/dash",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/systemctl",
    "/usr/lib/systemd/systemd",
    "/usr/bin/crontab",
    "/usr/sbin/crond",
    "/usr/sbin/cron",
    "/usr/bin/kill",
    "/usr/bin/pkill",
    "/usr/bin/pgrep",
    "/usr/bin/ip",
    "/usr/sbin/ip",
    "/usr/sbin/ifconfig",
    "/usr/bin/strace",
    "/usr/bin/ldd",
    "/usr/bin/md5sum",
    "/usr/bin/sha256sum",
    "/usr/bin/stat",
    "/usr/bin/file",
    "/usr/bin/rpm",
    "/usr/bin/dpkg",
    "/usr/bin/dpkg-query",
    "/usr/sbin/bpftool",
    "/usr/sbin/insmod",
    "/usr/sbin/modprobe",
    "/usr/sbin/lsmod",
    "/usr/bin/kmod",
    "/usr/lib64/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib64/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/lib64/librpm.so.10",
    "/usr/lib64/librpmio.so.10",
    "/usr/lib64/libpam.so.0",
    "/usr/lib/x86_64-linux-gnu/libpam.so.0",
    "/usr/lib64/security/pam_unix.so",
    "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
    "/usr/lib64/libkeyutils.so.1",
    "/usr/lib/x86_64-linux-gnu/libkeyutils.so.1",
    "/usr/lib64/libaudit.so.1",
    "/usr/lib/x86_64-linux-gnu/libaudit.so.1",
    "/usr/lib64/libselinux.so.1",
    "/usr/lib/x86_64-linux-gnu/libselinux.so.1",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algo {
    Md5,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Algo {
    /// rpm's `FILEDIGESTALGO` numbers (RFC 4880 hash IDs).
    fn from_rpm(n: u32) -> Option<Self> {
        match n {
            1 => Some(Self::Md5),
            8 => Some(Self::Sha256),
            9 => Some(Self::Sha384),
            10 => Some(Self::Sha512),
            11 => Some(Self::Sha224),
            _ => None,
        }
    }
}

/// A recorded digest for one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Recorded {
    pub(crate) path: String,
    pub(crate) algo: Algo,
    pub(crate) digest: String,
    pub(crate) package: Option<String>,
}

/// Parses rpm query output in [`RPM_QUERY_FORMAT`], keeping regular,
/// non-configuration, non-ghost files with a digest. Returns the records
/// and the number of files with an unsupported digest algorithm.
pub(crate) fn parse_rpm_query(output: &str) -> (Vec<Recorded>, u64) {
    let mut out = Vec::new();
    let mut unsupported = 0;
    for line in output.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let [path, algo, digest, flags, mode] = f[..] else {
            continue;
        };
        let (Ok(algo), Ok(flags), Ok(mode)) = (
            algo.parse::<u32>(),
            flags.parse::<u32>(),
            mode.parse::<u32>(),
        ) else {
            continue;
        };
        if !path.starts_with('/')
            || digest.is_empty()
            || flags & (RPMFILE_CONFIG | RPMFILE_GHOST) != 0
            || mode & 0o170000 != 0o100000
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            continue;
        }
        match Algo::from_rpm(algo) {
            Some(algo) => out.push(Recorded {
                path: path.to_owned(),
                algo,
                digest: digest.to_ascii_lowercase(),
                package: None,
            }),
            None => unsupported += 1,
        }
    }
    (out, unsupported)
}

/// Parses a dpkg `.md5sums` file (`<md5>  <path without leading />`).
pub(crate) fn parse_md5sums(text: &str, package: &str) -> Vec<Recorded> {
    text.lines()
        .filter_map(|l| {
            let (digest, path) = l.split_once(char::is_whitespace)?;
            let path = path.trim_start();
            (digest.len() == 32
                && digest.bytes().all(|b| b.is_ascii_hexdigit())
                && !path.is_empty())
            .then(|| Recorded {
                path: format!("/{}", path.trim_start_matches('/')),
                algo: Algo::Md5,
                digest: digest.to_ascii_lowercase(),
                package: Some(package.to_owned()),
            })
        })
        .collect()
}

/// The other spelling of a path under the merged-/usr layout
/// (`/bin/ls` and `/usr/bin/ls`).
pub(crate) fn usrmerge_alias(path: &str) -> Option<String> {
    for dir in ["/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/", "/libx32/"] {
        if path.starts_with(dir) {
            return Some(format!("/usr{path}"));
        }
        if let Some(rest) = path.strip_prefix("/usr")
            && rest.starts_with(dir)
        {
            return Some(rest.to_owned());
        }
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Manager {
    Rpm,
    Dpkg,
}

fn detect(ctx: &Ctx<'_>) -> Result<Manager, &'static str> {
    let exists = |p: &str| ctx.root.stat(Path::new(p)).is_ok();
    if exists("/var/lib/dpkg/status") {
        Ok(Manager::Dpkg)
    } else if exists("/var/lib/rpm") || exists("/usr/lib/sysimage/rpm") {
        if Path::new(RPM).exists() {
            Ok(Manager::Rpm)
        } else {
            Err("the inspected system uses rpm, but /usr/bin/rpm is not installed on this host")
        }
    } else {
        Err("no rpm or dpkg database in the inspected root")
    }
}

pub(crate) struct Options {
    pub(crate) verify_all: bool,
    pub(crate) timeout: Duration,
}

pub(crate) fn check(ctx: &mut Ctx<'_>, opts: &Options) -> CheckResult {
    let manager = match detect(ctx) {
        Ok(m) => m,
        Err(why) => return skipped(ID, TITLE, CheckStatus::Unsupported, why),
    };
    let mut run = Run::default();
    let targets: BTreeSet<String> = if opts.verify_all {
        BTreeSet::new()
    } else {
        let mut set: BTreeSet<String> = CRITICAL.iter().map(|s| (*s).to_owned()).collect();
        set.extend(
            ctx.persistence
                .iter()
                .filter_map(|e| e.executable.as_ref())
                .filter(|p| !p.is_lossy() && !in_temp_dir(Path::new(&p.text)))
                .map(|p| p.text.clone())
                .take(MAX_REFERENCED),
        );
        set.into_iter()
            .filter(|f| {
                ctx.root
                    .stat(Path::new(f))
                    .is_ok_and(|m| m.kind == Kind::File)
            })
            .collect()
    };
    if !opts.verify_all && targets.is_empty() {
        return run.finish(ID, TITLE, ctx.cancel);
    }

    let records = match manager {
        Manager::Rpm => rpm_records(ctx, &mut run, &targets, opts),
        Manager::Dpkg => Ok(dpkg_records(ctx, &mut run, &targets, opts.verify_all)),
    };
    let records = match records {
        Ok(r) => r,
        Err(e) => return skipped(ID, TITLE, CheckStatus::Failed, &e),
    };

    let mut too_large = 0u64;
    let mut unreadable: Vec<&str> = Vec::new();
    for r in &records {
        if ctx.cancelled() {
            break;
        }
        match hash_file(ctx, Path::new(&r.path), r.algo) {
            Ok(Some(actual)) => {
                run.examined += 1;
                if actual != r.digest {
                    let pkg = r
                        .package
                        .as_deref()
                        .map(|p| format!(" (package {p})"))
                        .unwrap_or_default();
                    ctx.report(
                        &rules::PACKAGE_MODIFIED,
                        FindingTarget::File {
                            path: ObservedPath::from_path(Path::new(&r.path)),
                            sha256: None,
                            metadata: None,
                        },
                        format!(
                            "{:?} digest {actual} differs from the package database's {}{pkg}",
                            r.algo, r.digest
                        ),
                    );
                }
            }
            Ok(None) => too_large += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable.push(&r.path),
        }
    }
    if too_large > 0 {
        run.notes
            .push(format!("{too_large} file(s) larger than 1 GiB not hashed"));
    }
    if !unreadable.is_empty() {
        run.partial = true;
        let mut names = unreadable
            .iter()
            .take(5)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        if unreadable.len() > 5 {
            names.push_str(", ...");
        }
        run.notes.push(format!(
            "{} file(s) could not be read ({names}); run as root",
            unreadable.len()
        ));
    }
    run.notes.push(match manager {
        Manager::Rpm => format!("rpm database queried with {RPM}; files hashed by Abyssal Warden"),
        Manager::Dpkg => {
            "dpkg database read directly (no dpkg program run); files hashed by Abyssal Warden"
                .into()
        }
    });
    if !opts.verify_all {
        run.notes.push(format!(
            "{} critical or referenced file(s) selected",
            targets.len()
        ));
    }
    run.finish(ID, TITLE, ctx.cancel)
}

fn rpm_records(
    ctx: &Ctx<'_>,
    run: &mut Run,
    targets: &BTreeSet<String>,
    opts: &Options,
) -> Result<Vec<Recorded>, String> {
    let mut args: Vec<String> = Vec::new();
    if !ctx.root.is_live() {
        args.push(format!("--root={}", ctx.root.path().display()));
    }
    args.extend(
        [
            "-q",
            "--nodigest",
            "--nosignature",
            "--qf",
            RPM_QUERY_FORMAT,
        ]
        .map(String::from),
    );
    if opts.verify_all {
        args.push("-a".into());
    } else {
        args.push("-f".into());
        args.extend(targets.iter().cloned());
    }
    let output = crate::tool::run(Path::new(RPM), &args, opts.timeout, ctx.cancel)?;
    let (records, unsupported) = parse_rpm_query(&output);
    if unsupported > 0 {
        run.notes.push(format!(
            "{unsupported} file(s) use an unsupported digest algorithm"
        ));
    }
    // One record per path; for a targeted run, only the selected files.
    let mut by_path: BTreeMap<String, Recorded> = BTreeMap::new();
    for r in records {
        if opts.verify_all || targets.contains(&r.path) {
            by_path.entry(r.path.clone()).or_insert(r);
        }
    }
    Ok(by_path.into_values().collect())
}

fn dpkg_records(
    ctx: &mut Ctx<'_>,
    run: &mut Run,
    targets: &BTreeSet<String>,
    all: bool,
) -> Vec<Recorded> {
    let info = Path::new("/var/lib/dpkg/info");
    let entries = match ctx.root.read_dir(info) {
        Ok(e) => e,
        Err(e) => {
            ctx.io_error(run, info, &e);
            return Vec::new();
        }
    };
    let stems: Vec<String> = entries
        .iter()
        .filter_map(|e| e.name.strip_suffix(".md5sums").map(str::to_owned))
        .collect();

    // Packages owning the selected files, from the *.list files.
    let mut wanted: HashMap<String, String> = HashMap::new(); // recorded path -> our path
    for t in targets {
        wanted.insert(t.clone(), t.clone());
        if let Some(a) = usrmerge_alias(t) {
            wanted.entry(a).or_insert_with(|| t.clone());
        }
    }
    let mut owning: BTreeSet<String> = BTreeSet::new();
    if !all {
        for e in entries.iter().filter(|e| e.name.ends_with(".list")) {
            if ctx.cancelled() {
                break;
            }
            let stem = e.name.trim_end_matches(".list");
            if let Ok(t) = ctx.root.read_text(&info.join(&e.name))
                && t.text.lines().any(|l| wanted.contains_key(l))
            {
                owning.insert(stem.to_owned());
            }
        }
    }

    let mut out = Vec::new();
    for stem in stems {
        if !all && !owning.contains(&stem) {
            continue;
        }
        let path = info.join(format!("{stem}.md5sums"));
        match ctx.root.read_text(&path) {
            Ok(t) => {
                if t.truncated {
                    run.partial = true;
                    run.notes.push(format!(
                        "{} is larger than 1 MiB; only the start was read",
                        path.display()
                    ));
                }
                let package = stem.split(':').next().unwrap_or(&stem).to_owned();
                for mut r in parse_md5sums(&t.text, &package) {
                    if all {
                        out.push(r);
                    } else if let Some(ours) = wanted.get(&r.path) {
                        // Hash the file where it is, under either spelling.
                        r.path = ours.clone();
                        out.push(r);
                    }
                }
            }
            Err(e) => ctx.io_error(run, &path, &e),
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|r| seen.insert(r.path.clone()));
    out
}

/// Lower-case hex digest of the file, or `None` if it is too large.
fn hash_file(ctx: &Ctx<'_>, path: &Path, algo: Algo) -> std::io::Result<Option<String>> {
    fn run<D: Digest>(ctx: &Ctx<'_>, path: &Path) -> std::io::Result<Option<String>> {
        let mut d = D::new();
        let complete = ctx
            .root
            .read_chunks(path, MAX_HASH_BYTES, |c| d.update(c))?;
        Ok(complete.then(|| hex(&d.finalize())))
    }
    match algo {
        Algo::Md5 => run::<Md5>(ctx, path),
        Algo::Sha224 => run::<Sha224>(ctx, path),
        Algo::Sha256 => run::<Sha256>(ctx, path),
        Algo::Sha384 => run::<Sha384>(ctx, path),
        Algo::Sha512 => run::<Sha512>(ctx, path),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rpm_query_output() {
        let out = "/usr/bin/ls\t8\tABCDEF01\t0\t33261\n\
                   /etc/x.conf\t8\t00ff\t1\t33188\n\
                   /usr/share/ghost\t8\t00ff\t64\t33188\n\
                   /usr/bin\t8\t\t0\t16877\n\
                   /usr/lib/old\t2\t00ff\t0\t33188\n\
                   file /tmp/y is not owned by any package\n\
                   /usr/bin/bad\t8\tnothex!\t0\t33188\n";
        let (r, unsupported) = parse_rpm_query(out);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].path, "/usr/bin/ls");
        assert_eq!(r[0].digest, "abcdef01");
        assert_eq!(r[0].algo, Algo::Sha256);
        assert_eq!(unsupported, 1);
    }

    #[test]
    fn parses_md5sums() {
        let r = parse_md5sums(
            "d41d8cd98f00b204e9800998ecf8427e  usr/bin/ls\nbad line\n0123  short\n",
            "coreutils",
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].path, "/usr/bin/ls");
        assert_eq!(r[0].package.as_deref(), Some("coreutils"));
    }

    #[test]
    fn usrmerge_aliases() {
        assert_eq!(usrmerge_alias("/bin/ls").as_deref(), Some("/usr/bin/ls"));
        assert_eq!(
            usrmerge_alias("/usr/lib/x.so").as_deref(),
            Some("/lib/x.so")
        );
        assert_eq!(usrmerge_alias("/usr/share/x"), None);
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
    }
}
