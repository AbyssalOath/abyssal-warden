//! Command patterns shared by script heuristics and the system checks'
//! persistence rules: download-and-run, reverse shells, encoded payloads,
//! loader injection and misuse of built-in Windows programs.
//!
//! Patterns are case-insensitive regular expressions with a compiled-size
//! limit, applied to at most [`MAX_TEXT`] bytes at a time (linear time).

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};

/// Longest text a pattern is applied to at once (one line or command).
pub const MAX_TEXT: usize = 8192;

/// What a matched pattern indicates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Pattern {
    /// Fetches code from the network and runs it.
    DownloadExec,
    /// Connects a shell to a network socket.
    ReverseShell,
    /// Decodes and runs an encoded payload.
    EncodedExec,
    /// Sets `LD_PRELOAD`/`LD_AUDIT`.
    LoaderInjection,
    /// Uses a signed Windows program to run script or remote code.
    LolBin,
}

fn compile(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
        .ok()
}

fn table() -> &'static [(Pattern, Regex)] {
    use Pattern::{DownloadExec, EncodedExec, LoaderInjection, LolBin, ReverseShell};
    static PATTERNS: OnceLock<Vec<(Pattern, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let table: &[(Pattern, &str)] = &[
            // Download piped to an interpreter, or downloaded then made executable.
            (DownloadExec, r"\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"),
            (DownloadExec, r"\b(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|php|node)\b"),
            (DownloadExec, r"\b(curl|wget)\b[^\n]*(&&|;)\s*chmod\s+[0-7+]*x"),
            // Reverse shells.
            (ReverseShell, r"/dev/(tcp|udp)/[^\s/]+/[0-9]+"),
            (ReverseShell, r"\b(nc|ncat|netcat)\b[^\n]*\s-[a-z]*[ec]\s"),
            (ReverseShell, r"\bsocat\b[^\n]*\bexec:"),
            (ReverseShell, r"\b(ba)?sh\s+-i\s*[0-9]?>&"),
            (ReverseShell, r"\bmkfifo\b[^\n]*\b(nc|ncat|netcat|telnet)\b"),
            // Interpreter one-liners (python -c, perl -e, php -r, ruby -rsocket):
            // inline code that opens a socket and starts a shell, close together.
            (ReverseShell, r"\b(python[0-9.]*|perl|ruby|php)\b[^\n]{0,40}\s-[a-z]*[cer][a-z]*\b[^\n]{0,400}(socket|fsockopen)[^\n]{0,300}(subprocess|exec|pty|/bin/sh|popen)"),
            // Encoded payloads.
            (EncodedExec, r"\bbase64\s+(-d|--decode|-D)\b[^\n]*\|\s*(sudo\s+)?((ba|z|da)?sh|python[0-9.]*|perl)\b"),
            (EncodedExec, r"\beval\b[^\n]*\b(base64|b64decode|xxd\s+-r)"),
            (EncodedExec, r"\bexec\s*\([^\n]*b64decode"),
            // Windows: PowerShell download cradles, certutil, bitsadmin.
            (DownloadExec, r"\b(iex|invoke-expression)\b[^\n]*\b(downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod|net\.webclient)\b"),
            (DownloadExec, r"\b(downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*\|\s*(iex|invoke-expression)\b"),
            (DownloadExec, r"\bcertutil(\.exe)?\b[^\n]*[-/]urlcache\b"),
            (DownloadExec, r"\bbitsadmin(\.exe)?\b[^\n]*/transfer\b"),
            (ReverseShell, r"\bsystem\.net\.sockets\.tcpclient\b"),
            // Windows: encoded PowerShell.
            (EncodedExec, r"\b(powershell|pwsh)(\.exe)?\b[^\n]*\s[-/](e|ec|en|enc|enco\w*)\s+[a-z0-9+/=]{20,}"),
            (EncodedExec, r"\bfrombase64string\b"),
            // Windows: signed system programs used to run script or remote code.
            (LolBin, r"\bmshta(\.exe)?\b[^\n]*(https?:|javascript:|vbscript:)"),
            (LolBin, r"\brundll32(\.exe)?\b[^\n]*javascript:"),
            (LolBin, r"\bregsvr32(\.exe)?\b[^\n]*(/i:\s*https?:|scrobj\.dll)"),
            (LolBin, r"\bwmic(\.exe)?\b[^\n]*\bprocess\s+call\s+create\b"),
            (LolBin, r"\b(cscript|wscript)(\.exe)?\b[^\n]*(https?:|\\appdata\\|\\temp\\|\\users\\public\\)"),
            // Dynamic-loader injection.
            (LoaderInjection, r"\b(LD_PRELOAD|LD_AUDIT)\s*="),
        ];
        table
            .iter()
            .filter_map(|(kind, p)| compile(p).map(|r| (*kind, r)))
            .collect()
    })
}

/// Patterns matched by `text` (each kind once), with the matched fragment.
/// Only the first [`MAX_TEXT`] bytes are examined.
pub fn command_indicators(text: &str) -> Vec<(Pattern, &str)> {
    let text = truncate_at_char(text, MAX_TEXT);
    let mut out: Vec<(Pattern, &str)> = Vec::new();
    for (kind, re) in table() {
        if out.iter().any(|(k, _)| k == kind) {
            continue;
        }
        if let Some(m) = re.find(text) {
            out.push((*kind, m.as_str()));
        }
    }
    out
}

/// `s` cut to at most `max` bytes at a character boundary.
pub fn truncate_at_char(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A short, single-line excerpt for evidence.
pub fn snippet(s: &str) -> String {
    let one_line: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = one_line.trim();
    let t = truncate_at_char(trimmed, 160);
    if t.len() < trimmed.len() {
        format!("{t}...")
    } else {
        t.to_owned()
    }
}
