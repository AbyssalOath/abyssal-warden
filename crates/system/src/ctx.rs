//! State shared by the checks: the root, users, and the collected results.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

use warden_core::{
    CancellationToken, CheckResult, CheckStatus, Finding, FindingTarget, IssueKind, ObservedPath,
    PersistenceEntry, PersistenceMechanism, PersistenceScope, ScanIssue,
};

use crate::fsx::{Kind, Meta, Root};
use crate::heuristics::{command_executable, command_indicators, in_temp_dir, is_hidden, snippet};
use crate::rules::{self, Rule};
use crate::users::User;

pub(crate) struct Ctx<'a> {
    pub(crate) root: Root,
    pub(crate) cancel: &'a CancellationToken,
    /// Users whose files are inspected.
    pub(crate) users: Vec<User>,
    /// Some users' files were not inspected (not running as root).
    pub(crate) users_limited: bool,
    pub(crate) findings: Vec<Finding>,
    pub(crate) persistence: Vec<PersistenceEntry>,
    pub(crate) issues: Vec<ScanIssue>,
    seen: HashSet<(String, String, String)>,
}

/// Progress of one check.
#[derive(Debug, Default)]
pub(crate) struct Run {
    pub(crate) examined: u64,
    pub(crate) partial: bool,
    pub(crate) notes: Vec<String>,
}

impl Run {
    pub(crate) fn finish(self, id: &str, title: &str, cancel: &CancellationToken) -> CheckResult {
        let mut notes = self.notes;
        let mut partial = self.partial;
        if cancel.is_cancelled() {
            partial = true;
            notes.push("cancelled".into());
        }
        CheckResult {
            id: id.into(),
            title: title.into(),
            status: if partial {
                CheckStatus::Partial
            } else {
                CheckStatus::Completed
            },
            examined: self.examined,
            detail: (!notes.is_empty()).then(|| notes.join("; ")),
        }
    }
}

pub(crate) fn skipped(id: &str, title: &str, status: CheckStatus, why: &str) -> CheckResult {
    CheckResult {
        id: id.into(),
        title: title.into(),
        status,
        examined: 0,
        detail: Some(why.into()),
    }
}

/// A persistence entry as found, before evaluation.
#[derive(Clone, Debug)]
pub(crate) struct Found<'p> {
    pub(crate) mechanism: PersistenceMechanism,
    pub(crate) scope: PersistenceScope,
    pub(crate) location: &'p Path,
    pub(crate) command: Option<String>,
    pub(crate) enabled: Option<bool>,
    pub(crate) detail: Option<String>,
    /// Metadata of the defining file, for the permission rule.
    pub(crate) def_meta: Option<Meta>,
    /// The user an entry of user scope belongs to.
    pub(crate) owner_uid: Option<u32>,
    /// Look for a started executable (and check its location/permissions).
    pub(crate) find_executable: bool,
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(root: Root, cancel: &'a CancellationToken) -> Self {
        Self {
            root,
            cancel,
            users: Vec::new(),
            users_limited: false,
            findings: Vec::new(),
            persistence: Vec::new(),
            issues: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Records a read error: missing files are normal and ignored; other
    /// errors become issues and make the check partial.
    pub(crate) fn io_error(&mut self, run: &mut Run, path: &Path, e: &io::Error) {
        if e.kind() == io::ErrorKind::NotFound
            || e.raw_os_error() == Some(libc::ENOTDIR)
            || e.raw_os_error() == Some(libc::ELOOP)
        {
            return;
        }
        run.partial = true;
        self.issues.push(ScanIssue {
            path: Some(ObservedPath::from_path(path)),
            kind: if e.kind() == io::ErrorKind::PermissionDenied {
                IssueKind::PermissionDenied
            } else {
                IssueKind::Io
            },
            detector: Some(rules::DETECTOR_ID.into()),
            message: e.to_string(),
            member: None,
        });
    }

    /// Adds a finding once per (rule, target location, entry).
    pub(crate) fn report(&mut self, rule: &Rule, target: FindingTarget, summary: String) {
        let loc = target
            .path()
            .map(|p| p.text.clone())
            .unwrap_or_else(|| match &target {
                FindingTarget::System { component } => component.clone(),
                FindingTarget::Process { pid, .. } => pid.to_string(),
                _ => String::new(),
            });
        let entry = match &target {
            FindingTarget::Persistence { entry, .. } => entry.clone().unwrap_or_default(),
            _ => summary.clone(),
        };
        if self.seen.insert((rule.id.into(), loc, entry)) {
            self.findings.push(rule.finding(target, summary));
        }
    }

    /// Adds `found` to the inventory and applies the persistence rules to
    /// it. `text` is additional content (script body, profile lines) to
    /// search for suspicious commands, line by line.
    pub(crate) fn record(&mut self, found: Found<'_>, text: Option<&str>) {
        let location = ObservedPath::from_path(found.location);
        let target = |entry: Option<String>| FindingTarget::Persistence {
            mechanism: found.mechanism,
            location: location.clone(),
            entry: entry.map(|e| snippet(&e)),
        };

        // Suspicious commands, in the command and in the file text.
        let mut lines: Vec<&str> = Vec::new();
        if let Some(c) = &found.command {
            lines.push(c);
        }
        if let Some(t) = text {
            lines.extend(
                t.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#')),
            );
        }
        for line in &lines {
            for (rule, matched) in command_indicators(line) {
                self.report(
                    rule,
                    target(Some((*line).to_owned())),
                    format!("matched: {matched}"),
                );
            }
        }

        // Temporary/hidden locations of what the command (or each script
        // line) starts; permissions of the executable.
        let mut executable: Option<String> = None;
        if found.find_executable {
            executable = found.command.as_deref().and_then(command_executable);
            let mut starts: Vec<(String, Option<&str>)> = executable
                .iter()
                .map(|e| (e.clone(), found.command.as_deref()))
                .collect();
            if text.is_some() {
                for line in lines.iter().skip(usize::from(found.command.is_some())) {
                    if let Some(e) = command_executable(line) {
                        starts.push((e, Some(line)));
                    }
                }
            }
            for (exe, line) in starts {
                let path = PathBuf::from(&exe);
                let entry = line.map(str::to_owned);
                if in_temp_dir(&path) {
                    self.report(
                        &rules::TEMP_EXEC,
                        target(entry.clone()),
                        format!("starts {exe}"),
                    );
                } else if is_hidden(&path) && found.command.as_deref() == line {
                    self.report(
                        &rules::HIDDEN_EXEC,
                        target(entry.clone()),
                        format!("starts {exe}"),
                    );
                }
                if found.scope == PersistenceScope::System
                    && let Some(why) = self.writable_chain(&path)
                {
                    self.report(
                        &rules::WRITABLE_EXEC,
                        target(entry),
                        format!("{exe}: {why}"),
                    );
                }
            }
        }

        // Permissions of the defining file.
        if let Some(m) = found.def_meta {
            let problem = match found.scope {
                PersistenceScope::System => m
                    .writable_by_non_root()
                    .then(|| format!("owner uid {}, group {}, mode {:04o}", m.uid, m.gid, m.mode)),
                PersistenceScope::User => {
                    let foreign_owner = found.owner_uid.is_some_and(|u| m.uid != u && m.uid != 0);
                    (m.mode & 0o002 != 0 || foreign_owner)
                        .then(|| format!("owner uid {}, mode {:04o}", m.uid, m.mode))
                }
            };
            if let Some(p) = problem {
                self.report(&rules::WRITABLE_DEFINITION, target(None), p);
            }
        }

        self.persistence.push(PersistenceEntry {
            mechanism: found.mechanism,
            scope: found.scope,
            location,
            command: found.command.map(|c| snippet_long(&c)),
            executable: executable.map(|e| ObservedPath::from_path(Path::new(&e))),
            enabled: found.enabled,
            detail: found.detail,
        });
    }

    /// Why `exe` (logical) can be changed by a non-root user, checking the
    /// file and every parent directory. `None` if it cannot, or does not
    /// exist.
    pub(crate) fn writable_chain(&self, exe: &Path) -> Option<String> {
        let meta = self.root.stat(exe).ok()?;
        if meta.kind != Kind::File {
            return None;
        }
        if meta.writable_by_non_root() {
            return Some(format!(
                "owner uid {}, group {}, mode {:04o}",
                meta.uid, meta.gid, meta.mode
            ));
        }
        let mut dir = exe.parent();
        while let Some(d) = dir {
            if let Ok(m) = self.root.stat(d)
                && m.dir_writable_by_non_root()
            {
                return Some(format!(
                    "directory {} is writable by others (owner uid {}, mode {:04o})",
                    d.display(),
                    m.uid,
                    m.mode
                ));
            }
            dir = d.parent();
        }
        None
    }
}

/// Commands kept in the inventory: single line, bounded.
fn snippet_long(s: &str) -> String {
    let one: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(1024)
        .collect();
    one.trim().to_owned()
}
