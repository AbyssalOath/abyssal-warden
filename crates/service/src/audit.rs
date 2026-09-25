//! Comparing the quarantine audit chain with the anchors in the system log
//! (docs/security/quarantine.md).
//!
//! * **Linux:** journald; only anchors journald attributes to the
//!   service's own uid (`_UID`, supplied by the kernel) are considered.
//! * **Windows:** the Application event log (source `AbyssalWarden`). Any
//!   user can write to that log, so extra anchors can be forged (causing a
//!   false alarm), but existing ones can only be removed by an
//!   administrator clearing the log.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use time::OffsetDateTime;
use warden_ipc::AuditStatus;
use warden_remediation::{Anchor, QuarantineStore, compare_anchors, parse_anchor};

use crate::runner::{self, Identity};

#[cfg(unix)]
const JOURNALCTL: &[&str] = &["/usr/bin/journalctl", "/bin/journalctl"];

/// Anchors from `wevtutil qe ... /f:xml` output: every `audit seq=...`
/// text up to the next markup.
#[cfg_attr(unix, allow(dead_code))]
pub(crate) fn parse_event_log(output: &str) -> Vec<Anchor> {
    let mut out = Vec::new();
    let mut rest = output;
    while let Some(i) = rest.find("audit seq=") {
        let tail = &rest[i..];
        let end = tail.find(['<', '\r', '\n']).unwrap_or(tail.len());
        if let Some(a) = parse_anchor(&tail[..end]) {
            out.push(a);
        }
        rest = &tail[end.max(1)..];
        if out.len() >= 10_000_000 {
            break;
        }
    }
    out
}

#[cfg_attr(windows, allow(dead_code))]
/// Anchors from `journalctl -o json` output (one object per line; MESSAGE
/// may be a string or, for non-UTF-8 data, an array of bytes).
pub(crate) fn parse_journal(output: &[u8]) -> Vec<Anchor> {
    let mut out = Vec::new();
    for line in output.split(|&b| b == b'\n').take(10_000_000) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let msg = match v.get("MESSAGE") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(bytes)) => String::from_utf8_lossy(
                &bytes
                    .iter()
                    .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                    .collect::<Vec<u8>>(),
            )
            .into_owned(),
            _ => continue,
        };
        if let Some(a) = parse_anchor(&msg) {
            out.push(a);
        }
    }
    out
}

#[cfg(unix)]
fn read_anchors() -> Result<Vec<Anchor>, String> {
    let tool = JOURNALCTL
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .ok_or("journalctl not available")?;
    let uid = rustix::process::geteuid().as_raw();
    let args: Vec<std::ffi::OsString> = [
        "-t",
        "abyssal-warden",
        &format!("_UID={uid}"),
        "-o",
        "json",
        "--no-pager",
        "--output-fields=MESSAGE",
    ]
    .iter()
    .map(|s| (*s).into())
    .collect();
    let o = runner::command(None, tool, &Identity::Inherit, &args).and_then(|cmd| {
        runner::run(
            cmd,
            Duration::from_secs(120),
            &AtomicBool::new(false),
            128 << 20,
        )
    })?;
    if o.exit_code == Some(0) || o.exit_code == Some(1) {
        Ok(parse_journal(&o.stdout))
    } else {
        Err(format!(
            "journal not readable: {}",
            crate::sanitize(o.stderr_tail.trim())
        ))
    }
}

#[cfg(windows)]
fn read_anchors() -> Result<Vec<Anchor>, String> {
    let tool = std::env::var_os("SystemRoot")
        .map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        )
        .join(r"System32\wevtutil.exe");
    let args: Vec<std::ffi::OsString> = [
        "qe",
        "Application",
        "/q:*[System[Provider[@Name='AbyssalWarden']]]",
        "/f:xml",
    ]
    .iter()
    .map(|s| (*s).into())
    .collect();
    let o = runner::command(None, &tool, &Identity::Inherit, &args).and_then(|cmd| {
        runner::run(
            cmd,
            Duration::from_secs(120),
            &AtomicBool::new(false),
            256 << 20,
        )
    })?;
    if o.exit_code == Some(0) {
        Ok(parse_event_log(&String::from_utf8_lossy(&o.stdout)))
    } else {
        Err(format!(
            "event log not readable: {}",
            crate::sanitize(o.stderr_tail.trim())
        ))
    }
}

pub(crate) fn check(store_path: &Path) -> AuditStatus {
    let mut status = AuditStatus {
        checked_at: OffsetDateTime::now_utc(),
        chain_ok: false,
        entries: 0,
        journal_checked: false,
        matched: 0,
        mismatched: Vec::new(),
        missing_locally: Vec::new(),
        unanchored: 0,
        other_chains: 0,
        consistent: false,
        detail: String::new(),
    };
    if !store_path.exists() {
        status.chain_ok = true;
        status.consistent = true;
        status.detail = "no quarantine store yet".into();
        return status;
    }
    let chain = match QuarantineStore::open(store_path).and_then(|mut s| s.audit_chain()) {
        Ok(c) => c,
        Err(e) => {
            status.detail = format!("audit chain invalid or unreadable: {e}");
            return status;
        }
    };
    status.chain_ok = true;
    status.entries = chain.len() as u64;
    let anchors = match read_anchors() {
        Ok(a) => a,
        Err(why) => {
            status.consistent = true;
            status.detail = format!("chain valid; anchors not compared ({why})");
            return status;
        }
    };
    let cmp = compare_anchors(&chain, &anchors);
    status.journal_checked = true;
    status.matched = cmp.matched;
    status.consistent = cmp.consistent();
    status.mismatched = cmp.mismatched;
    status.missing_locally = cmp.missing_locally;
    status.unanchored = cmp.unanchored;
    status.other_chains = cmp.other_chains;
    status.detail = if status.consistent {
        format!(
            "{} of {} entries anchored in the journal and matching",
            status.matched, status.entries
        )
    } else {
        "the audit log does not match the anchors in the system journal: it was altered or truncated".into()
    };
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_event_log_xml() {
        let h = "a".repeat(64);
        let c = "b".repeat(16);
        let xml = format!(
            "<Event><EventData><Data>audit seq=7 hash={h} chain={c} action=quarantine outcome=ok</Data></EventData></Event>\r\n<Event><EventData><Data>other</Data></EventData></Event>"
        );
        let a = parse_event_log(&xml);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].seq, 7);
        assert!(parse_event_log("audit seq=").is_empty());
    }

    #[test]
    fn parses_journal_json() {
        let h = "a".repeat(64);
        let c = "b".repeat(16);
        let msg = format!("audit seq=4 hash={h} chain={c} action=delete outcome=ok");
        let bytes: Vec<String> = msg.bytes().map(|b| b.to_string()).collect();
        let out = format!(
            "{{\"MESSAGE\":\"{msg}\"}}\n{{\"MESSAGE\":[{}]}}\n{{\"MESSAGE\":\"unrelated\"}}\nnot json\n",
            bytes.join(",")
        );
        let a = parse_journal(out.as_bytes());
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].seq, 4);
        assert_eq!(a[1].chain.as_deref(), Some(c.as_str()));
    }
}
