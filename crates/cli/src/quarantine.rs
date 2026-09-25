//! `abyssal-warden quarantine ...` and `scan --quarantine`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use warden_core::{Finding, RemediationStatus, ScanReport};
use warden_remediation::{
    QuarantineId, QuarantineReason, QuarantineRecord, QuarantineRequest, QuarantineStore,
    RemediationError, auto_quarantine_target, default_store_path,
};

use crate::output::{label, sanitize};
use crate::{EXIT_ERROR, parse_size};

#[derive(Args, Debug)]
pub(crate) struct QuarantineArgs {
    /// Quarantine store directory [default: /var/lib/abyssal-warden/quarantine
    /// as root, else ~/.local/share/abyssal-warden/quarantine].
    #[arg(long, value_name = "DIR", global = true)]
    store: Option<PathBuf>,
    #[command(subcommand)]
    command: QuarantineCommand,
}

#[derive(Subcommand, Debug)]
enum QuarantineCommand {
    /// Quarantine a file you have decided is malicious.
    Add {
        /// Absolute path, without symbolic links.
        path: PathBuf,
        /// Only proceed if the file's SHA-256 is this value.
        #[arg(long, value_name = "HEX")]
        sha256: Option<warden_core::Sha256Digest>,
        /// Note recorded with the item.
        #[arg(long)]
        note: Option<String>,
        /// Allow files under system directories (/usr, /etc, /boot, ...).
        #[arg(long)]
        allow_protected: bool,
        #[arg(long, value_name = "SIZE", default_value = "512M", value_parser = parse_size)]
        max_file_size: u64,
    },
    /// List quarantined items.
    List,
    /// Show one item's record as JSON.
    Show { id: String },
    /// Restore an item to its original location (or --to DIR). Never overwrites.
    Restore {
        id: String,
        #[arg(long, value_name = "DIR")]
        to: Option<PathBuf>,
        /// Confirm the restore of a file that was detected as malicious.
        #[arg(long)]
        yes: bool,
    },
    /// Permanently delete an item's content.
    Delete {
        id: String,
        /// Confirm permanent deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Verify the audit log's hash chain.
    VerifyLog,
}

fn store_path(explicit: Option<&Path>) -> Result<PathBuf, String> {
    match explicit {
        Some(p) => std::path::absolute(p).map_err(|e| format!("{}: {e}", p.display())),
        None => default_store_path()
            .ok_or_else(|| "cannot determine a default store; use --store".into()),
    }
}

fn open_store(explicit: Option<&Path>) -> Result<QuarantineStore, String> {
    let path = store_path(explicit)?;
    let store = QuarantineStore::open(&path).map_err(|e| e.to_string())?;
    for r in store.recovered() {
        eprintln!(
            "recovered interrupted operation {}: {} ({})",
            r.id,
            label(&r.outcome),
            sanitize(&r.detail)
        );
    }
    Ok(store)
}

pub(crate) fn run(args: QuarantineArgs) -> ExitCode {
    match run_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", sanitize(&e));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run_inner(args: QuarantineArgs) -> Result<(), String> {
    let explicit = args.store.as_deref();
    match args.command {
        QuarantineCommand::Add {
            path,
            sha256,
            note,
            allow_protected,
            max_file_size,
        } => {
            let mut store = open_store(explicit)?;
            let path = std::path::absolute(&path).map_err(|e| e.to_string())?;
            let rec = store
                .quarantine(&QuarantineRequest {
                    path,
                    expected_sha256: sha256,
                    reason: QuarantineReason {
                        note,
                        ..QuarantineReason::default()
                    },
                    max_size: max_file_size,
                    allow_protected,
                })
                .map_err(|e| e.to_string())?;
            println!(
                "quarantined {} as {}",
                sanitize(&rec.original.path.text),
                rec.id
            );
        }
        QuarantineCommand::List => {
            let store = open_store(explicit)?;
            let items = store.list().map_err(|e| e.to_string())?;
            if items.is_empty() {
                println!("quarantine store is empty");
            }
            for r in items {
                print_summary(&r);
            }
        }
        QuarantineCommand::Show { id } => {
            let store = open_store(explicit)?;
            let rec = store.get(&parse_id(&id)?).map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?;
            println!("{json}");
        }
        QuarantineCommand::Restore { id, to, yes } => {
            if !yes {
                return Err(
                    "restoring puts a detected file back on disk; re-run with --yes to confirm"
                        .into(),
                );
            }
            let mut store = open_store(explicit)?;
            let id = parse_id(&id)?;
            let to = to
                .map(|d| std::path::absolute(&d).map_err(|e| e.to_string()))
                .transpose()?;
            let target = store
                .restore(&id, to.as_deref())
                .map_err(|e| e.to_string())?;
            println!("restored {id} to {}", sanitize(&target.to_string_lossy()));
            for n in store.get(&id).map(|r| r.notes).unwrap_or_default() {
                println!("  note: {}", sanitize(&n));
            }
        }
        QuarantineCommand::Delete { id, yes } => {
            if !yes {
                return Err("deletion is permanent; re-run with --yes to confirm".into());
            }
            let mut store = open_store(explicit)?;
            let id = parse_id(&id)?;
            store.delete(&id).map_err(|e| e.to_string())?;
            println!("deleted {id}");
        }
        QuarantineCommand::VerifyLog => {
            let mut store = open_store(explicit)?;
            let n = store.verify_audit_log().map_err(|e| e.to_string())?;
            println!("audit log intact: {n} entries");
        }
    }
    Ok(())
}

fn parse_id(s: &str) -> Result<QuarantineId, String> {
    s.parse().map_err(|e: RemediationError| e.to_string())
}

fn print_summary(r: &QuarantineRecord) {
    let what = r
        .reason
        .detection_name
        .as_deref()
        .or(r.reason.note.as_deref())
        .unwrap_or("-");
    println!(
        "{}  {:<12} {}  {}  [{}]",
        r.id,
        label(&r.state),
        r.created_at.date(),
        sanitize(&r.original.path.text),
        sanitize(what)
    );
}

/// Quarantine every finding that meets the automatic-remediation policy,
/// recording the outcome on each finding in the report.
pub(crate) fn remediate_report(report: &mut ScanReport, store: Option<&Path>, max_size: u64) {
    let eligible: Vec<usize> = report
        .findings
        .iter()
        .enumerate()
        .filter(|(_, f)| auto_quarantine_target(f).is_ok())
        .map(|(i, _)| i)
        .collect();
    let mut opened = if eligible.is_empty() {
        None
    } else {
        Some(open_store(store))
    };

    for (i, finding) in report.findings.iter_mut().enumerate() {
        let (path, sha) = match auto_quarantine_target(finding) {
            Ok(t) => t,
            Err(why) => {
                finding.remediation_status = RemediationStatus::NotEligible;
                finding.remediation_detail = Some(why);
                continue;
            }
        };
        debug_assert!(eligible.contains(&i));
        let result = match opened.as_mut() {
            Some(Ok(store)) => store
                .quarantine(&QuarantineRequest {
                    path,
                    expected_sha256: Some(sha),
                    reason: reason_for(finding),
                    max_size,
                    allow_protected: false,
                })
                .map_err(|e| e.to_string()),
            Some(Err(e)) => Err(format!("quarantine store unavailable: {e}")),
            None => Err("quarantine store unavailable".into()),
        };
        match result {
            Ok(rec) => {
                finding.remediation_status = RemediationStatus::Quarantined;
                finding.remediation_detail = Some(format!("quarantine ID {}", rec.id));
            }
            Err(e) => {
                eprintln!("error: could not quarantine: {}", sanitize(&e));
                finding.remediation_status = RemediationStatus::Failed;
                finding.remediation_detail = Some(e);
            }
        }
    }
}

fn reason_for(f: &Finding) -> QuarantineReason {
    QuarantineReason {
        finding_id: Some(f.id.to_string()),
        detection_name: Some(f.name.clone()),
        detector: Some(f.source.detector.clone()),
        rule_id: f.source.rule_id.clone(),
        database_version: f.source.database_version.clone(),
        note: None,
    }
}
