//! Applying the allow-list and the automatic quarantine policy to a scan
//! report. Shared by the CLI (`scan --quarantine`) and the service.

use warden_core::{Finding, RemediationStatus, ScanReport};

use crate::{
    AllowEntry, QuarantineReason, QuarantineRequest, QuarantineStore, auto_quarantine_target,
};

/// Marks findings whose file hash is allow-listed as `allowed` (they stay
/// in the report). Returns how many were marked.
pub fn mark_allowed(report: &mut ScanReport, entries: &[AllowEntry]) -> usize {
    let mut n = 0;
    for f in &mut report.findings {
        let Some(sha) = f.target.sha256() else {
            continue;
        };
        if let Some(e) = entries.iter().find(|e| &e.sha256 == sha) {
            f.remediation_status = RemediationStatus::Allowed;
            f.remediation_detail = Some(format!(
                "SHA-256 allow-listed on {} ({})",
                e.added_at.date(),
                e.reason
            ));
            n += 1;
        }
    }
    n
}

/// The quarantine reason recorded for a finding.
pub fn reason_for(f: &Finding) -> QuarantineReason {
    QuarantineReason {
        finding_id: Some(f.id.to_string()),
        detection_name: Some(f.name.clone()),
        detector: Some(f.source.detector.clone()),
        rule_id: f.source.rule_id.clone(),
        database_version: f.source.database_version.clone(),
        note: None,
    }
}

/// Quarantines every finding the automatic policy allows, recording the
/// outcome on each finding. `open` is called only if something is eligible.
/// Returns the errors, for the caller to report.
pub fn quarantine_report(
    report: &mut ScanReport,
    open: impl FnOnce() -> Result<QuarantineStore, String>,
    max_size: u64,
    kill_processes: bool,
) -> Vec<String> {
    let eligible = report.findings.iter().any(|f| {
        f.remediation_status != RemediationStatus::Allowed && auto_quarantine_target(f).is_ok()
    });
    let mut store = if eligible { Some(open()) } else { None };
    let mut errors = Vec::new();
    for finding in &mut report.findings {
        if finding.remediation_status == RemediationStatus::Allowed {
            continue;
        }
        let (path, sha) = match auto_quarantine_target(finding) {
            Ok(t) => t,
            Err(why) => {
                finding.remediation_status = RemediationStatus::NotEligible;
                finding.remediation_detail = Some(why);
                continue;
            }
        };
        let result = match store.as_mut() {
            Some(Ok(store)) => store
                .quarantine(&QuarantineRequest {
                    path,
                    expected_sha256: Some(sha),
                    reason: reason_for(finding),
                    max_size,
                    allow_protected: false,
                    kill_processes,
                })
                .map_err(|e| e.to_string()),
            Some(Err(e)) => Err(format!("quarantine store unavailable: {e}")),
            None => Err("quarantine store unavailable".into()),
        };
        match result {
            Ok(rec) => {
                finding.remediation_status = RemediationStatus::Quarantined;
                let mut detail = format!("quarantine ID {}", rec.id);
                for n in &rec.notes {
                    detail.push_str("; ");
                    detail.push_str(n);
                }
                finding.remediation_detail = Some(detail);
            }
            Err(e) => {
                errors.push(e.clone());
                finding.remediation_status = RemediationStatus::Failed;
                finding.remediation_detail = Some(e);
            }
        }
    }
    errors
}
