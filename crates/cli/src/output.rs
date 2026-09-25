//! Human-readable report rendering.
//!
//! Everything in a report that came from the scanned system (paths) or from
//! a rule database (names, descriptions) is untrusted. It passes through
//! [`sanitize`] before reaching the terminal so that file names cannot inject
//! terminal escape sequences or use bidirectional overrides to disguise
//! themselves.

use std::fmt::Write as _;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use warden_core::{
    Finding, FindingTarget, ObservedPath, RemediationStatus, ScanReport, ScanStatus,
};

/// Maximum issues/skips listed in human output; JSON output has them all.
const LIST_LIMIT: usize = 20;

/// Escape control characters and bidirectional formatting characters as
/// `\u{..}` so untrusted text is inert on a terminal.
pub(crate) fn sanitize(s: &str) -> String {
    warden_core::text::escape_unsafe_chars(s)
}

fn path(p: &ObservedPath) -> String {
    let mut s = sanitize(&p.text);
    if p.is_lossy() {
        s.push_str("  [name is not valid Unicode; exact bytes are in the JSON report]");
    }
    s
}

/// The JSON spelling of an enum value, with underscores as spaces.
pub(crate) fn label<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s.replace('_', " "),
        _ => "unknown".to_owned(),
    }
}

pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub(crate) fn render_human(report: &ScanReport, show_skipped: bool) -> String {
    let mut o = String::new();
    // Writing to a String cannot fail.
    let _ = write_report(&mut o, report, show_skipped);
    o
}

fn write_report(o: &mut String, r: &ScanReport, show_skipped: bool) -> std::fmt::Result {
    writeln!(o, "Abyssal Warden scan report")?;
    writeln!(o, "  Scan ID:     {}", r.scan_id)?;
    match r.status {
        ScanStatus::Completed => writeln!(o, "  Status:      completed")?,
        _ => writeln!(
            o,
            "  Status:      {} (results are partial)",
            label(&r.status).to_uppercase()
        )?,
    }
    let started = r.started_at.format(&Rfc3339).unwrap_or_default();
    let secs = (r.finished_at - r.started_at).as_seconds_f64();
    writeln!(o, "  Started:     {started} (took {secs:.2}s)")?;
    for (i, root) in r.settings.roots.iter().enumerate() {
        let heading = if i == 0 { "Scanned:" } else { "" };
        writeln!(o, "  {heading:<12} {}", path(root))?;
    }
    if r.detectors.is_empty() {
        writeln!(o, "  Detectors:   none")?;
    }
    for (i, d) in r.detectors.iter().enumerate() {
        let heading = if i == 0 { "Detectors:" } else { "" };
        write!(
            o,
            "  {heading:<12} {} {}",
            sanitize(&d.id),
            sanitize(&d.version)
        )?;
        if let Some(db) = &d.database {
            let signed = match &db.signer {
                Some(k) => format!("signed by key {}", sanitize(k)),
                None => "UNSIGNED".to_owned(),
            };
            write!(
                o,
                " (\"{}\" version {}, {} entries, {signed})",
                sanitize(&db.name),
                sanitize(&db.version),
                db.entries
            )?;
        }
        writeln!(o)?;
    }

    let s = &r.stats;
    writeln!(o)?;
    writeln!(o, "Summary")?;
    writeln!(
        o,
        "  Files scanned:        {} ({})",
        s.files_scanned,
        human_bytes(s.bytes_scanned)
    )?;
    writeln!(o, "  Directories visited:  {}", s.directories_visited)?;
    write!(o, "  Skipped by policy:    {}", s.entries_skipped)?;
    if !s.skipped_by_reason.is_empty() {
        let parts: Vec<String> = s
            .skipped_by_reason
            .iter()
            .map(|(reason, n)| format!("{}: {n}", label(reason)))
            .collect();
        write!(o, " ({})", parts.join(", "))?;
    }
    writeln!(o)?;
    writeln!(o, "  Issues:               {}", s.issues)?;
    writeln!(o, "  Findings:             {}", s.findings)?;

    if !r.findings.is_empty() {
        writeln!(o)?;
        writeln!(o, "Findings")?;
        for (i, f) in r.findings.iter().enumerate() {
            write_finding(o, i + 1, f)?;
        }
        if r.truncated.findings_omitted > 0 {
            writeln!(
                o,
                "  ... {} more findings not recorded",
                r.truncated.findings_omitted
            )?;
        }
    }

    if !r.issues.is_empty() {
        writeln!(o)?;
        writeln!(o, "Issues{}", list_suffix(r.issues.len(), s.issues))?;
        for issue in r.issues.iter().take(LIST_LIMIT) {
            let p = issue.path.as_ref().map(path).unwrap_or_default();
            write!(o, "  {:<18} {p}", label(&issue.kind))?;
            if let Some(d) = &issue.detector {
                write!(o, " [detector {}]", sanitize(d))?;
            }
            writeln!(o, ": {}", sanitize(&issue.message))?;
        }
    }

    if show_skipped && !r.skipped.is_empty() {
        writeln!(o)?;
        writeln!(
            o,
            "Skipped{}",
            list_suffix(r.skipped.len(), s.entries_skipped)
        )?;
        for sk in r.skipped.iter().take(LIST_LIMIT) {
            writeln!(o, "  {:<24} {}", label(&sk.reason), path(&sk.path))?;
        }
    }

    if !r.warnings.is_empty() {
        writeln!(o)?;
        writeln!(o, "Warnings")?;
        for w in &r.warnings {
            writeln!(o, "  ! {}", sanitize(w))?;
        }
    }

    writeln!(o)?;
    if s.findings == 0 {
        if r.detectors.is_empty() {
            writeln!(
                o,
                "No detectors ran; this scan cannot tell you whether anything is malicious."
            )?;
        } else {
            writeln!(
                o,
                "No findings. This means no file matched the loaded signatures; it is not a \
                 guarantee that the system is clean."
            )?;
        }
    } else {
        let quarantined = r
            .findings
            .iter()
            .filter(|f| f.remediation_status == RemediationStatus::Quarantined)
            .count();
        if quarantined == 0 {
            writeln!(o, "{} finding(s). No files were modified.", s.findings)?;
        } else {
            writeln!(
                o,
                "{} finding(s); {quarantined} file(s) quarantined. No other files were modified.",
                s.findings
            )?;
        }
    }
    Ok(())
}

fn list_suffix(listed: usize, total: u64) -> String {
    let shown = listed.min(LIST_LIMIT);
    if shown as u64 == total {
        String::new()
    } else {
        format!(" (showing {shown} of {total}; use --format json for the recorded list)")
    }
}

fn write_finding(o: &mut String, n: usize, f: &Finding) -> std::fmt::Result {
    writeln!(
        o,
        "  {n}. [{}] {}",
        label(&f.severity).to_uppercase(),
        sanitize(&f.name)
    )?;
    writeln!(
        o,
        "     Kind:         {} (confidence: {}, category: {})",
        label(&f.kind),
        label(&f.confidence),
        label(&f.category)
    )?;
    match &f.target {
        FindingTarget::File {
            path: p, sha256, ..
        } => {
            writeln!(o, "     File:         {}", path(p))?;
            if let Some(h) = sha256 {
                writeln!(o, "     SHA-256:      {h}")?;
            }
        }
        _ => writeln!(o, "     Target:       (not a file; see the JSON report)")?,
    }
    let src = &f.source;
    write!(
        o,
        "     Source:       {} {}",
        sanitize(&src.detector),
        sanitize(&src.detector_version)
    )?;
    if let Some(rule) = &src.rule_id {
        write!(o, ", rule {}", sanitize(rule))?;
        if let Some(v) = src.rule_version {
            write!(o, " v{v}")?;
        }
    }
    if let (Some(name), Some(version)) = (&src.database_name, &src.database_version) {
        write!(o, ", database \"{}\" {}", sanitize(name), sanitize(version))?;
    }
    writeln!(o)?;
    for e in &f.evidence {
        writeln!(o, "     Evidence:     {}", sanitize(&e.summary))?;
    }
    writeln!(o, "     Explanation:  {}", sanitize(&f.explanation))?;
    match f.remediation_status {
        RemediationStatus::NotAttempted => writeln!(
            o,
            "     Recommended:  {} (not performed)",
            label(&f.recommended_action)
        )?,
        status => {
            write!(o, "     Remediation:  {}", label(&status))?;
            if let Some(d) = &f.remediation_detail {
                write!(o, " ({})", sanitize(d))?;
            }
            writeln!(o)?;
        }
    }
    if let Some(g) = &f.remediation_guidance {
        writeln!(o, "     Guidance:     {}", sanitize(g))?;
    }
    writeln!(o, "     Finding ID:   {}", f.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_neutralises_terminal_and_bidi_controls() {
        assert_eq!(sanitize("plain/path.txt"), "plain/path.txt");
        assert_eq!(sanitize("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(sanitize("line\nbreak\r"), "line\\u{a}break\\u{d}");
        assert_eq!(sanitize("x\u{9b}y"), "x\\u{9b}y"); // C1 CSI
        assert_eq!(
            sanitize("invoice\u{202E}fdp.exe"),
            "invoice\\u{202e}fdp.exe"
        );
        assert_eq!(sanitize("日本語"), "日本語");
    }

    #[test]
    fn labels_match_json_spelling() {
        assert_eq!(
            label(&warden_core::SkipReason::ExceedsMaxFileSize),
            "exceeds max file size"
        );
        assert_eq!(label(&warden_core::Severity::High), "high");
    }

    #[test]
    fn human_bytes_formats() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }
}
