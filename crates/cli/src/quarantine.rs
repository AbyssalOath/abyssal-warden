//! `abyssal-warden quarantine ...` and `scan --quarantine`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use warden_core::ScanReport;
use warden_core::Sha256Digest;
use warden_remediation::{
    QuarantineId, QuarantineReason, QuarantineRecord, QuarantineRequest, QuarantineStore,
    RemediationError, default_store_path, read_allowlist,
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
        /// Stop processes running this file: they are paused before the move
        /// and killed once the file is quarantined (Linux).
        #[arg(long)]
        kill_processes: bool,
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
        /// Do not add the file's SHA-256 to the allow-list (it will be
        /// detected, and eligible for quarantine, again).
        #[arg(long)]
        no_allow: bool,
    },
    /// Permanently delete an item's content.
    Delete {
        id: String,
        /// Confirm permanent deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Verify the audit log's hash chain and print its head, to compare with
    /// the anchors in the system log (`journalctl -t abyssal-warden`).
    VerifyLog,
    /// Show or edit the allow-list of restored file contents.
    #[command(subcommand)]
    Allowlist(AllowlistCommand),
}

#[derive(Subcommand, Debug)]
enum AllowlistCommand {
    /// List allow-listed SHA-256 values.
    List,
    /// Remove a SHA-256 from the allow-list.
    Remove { sha256: Sha256Digest },
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
            kill_processes,
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
                    kill_processes,
                })
                .map_err(|e| e.to_string())?;
            println!(
                "quarantined {} as {}",
                sanitize(&rec.original.path.text),
                rec.id
            );
            print_notes(&rec.notes);
            warn_if_unanchored(&store);
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
        QuarantineCommand::Restore {
            id,
            to,
            yes,
            no_allow,
        } => {
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
            let rec = store.get(&id).map_err(|e| e.to_string())?;
            print_notes(&rec.notes);
            if no_allow {
                println!("  not allow-listed: it will be detected again");
            } else {
                store
                    .allow(
                        rec.original.sha256,
                        "restored from quarantine",
                        Some(&id),
                        rec.reason.detection_name.as_deref(),
                    )
                    .map_err(|e| e.to_string())?;
                println!(
                    "  allow-listed SHA-256 {} (undo: quarantine allowlist remove {})",
                    rec.original.sha256, rec.original.sha256
                );
            }
            warn_if_unanchored(&store);
        }
        QuarantineCommand::Delete { id, yes } => {
            if !yes {
                return Err("deletion is permanent; re-run with --yes to confirm".into());
            }
            let mut store = open_store(explicit)?;
            let id = parse_id(&id)?;
            store.delete(&id).map_err(|e| e.to_string())?;
            println!("deleted {id}");
            warn_if_unanchored(&store);
        }
        QuarantineCommand::VerifyLog => {
            let mut store = open_store(explicit)?;
            let n = store.verify_audit_log().map_err(|e| e.to_string())?;
            let (seq, hash) = store.audit_head();
            println!("audit log intact: {n} entries");
            if seq > 0 {
                println!("head: seq={seq} hash={hash}");
                println!(
                    "compare with the system log: journalctl -t abyssal-warden | grep 'seq={seq} '"
                );
            }
        }
        QuarantineCommand::Allowlist(AllowlistCommand::List) => {
            let store = open_store(explicit)?;
            let entries = store.allowlist().map_err(|e| e.to_string())?;
            if entries.is_empty() {
                println!("the allow-list is empty");
            }
            for e in entries {
                println!(
                    "{}  {}  {}  [{}]",
                    e.sha256,
                    e.added_at.date(),
                    sanitize(&e.reason),
                    sanitize(e.detection_name.as_deref().unwrap_or("-"))
                );
            }
        }
        QuarantineCommand::Allowlist(AllowlistCommand::Remove { sha256 }) => {
            let mut store = open_store(explicit)?;
            if store.disallow(sha256).map_err(|e| e.to_string())? {
                println!("removed {sha256} from the allow-list");
            } else {
                return Err(format!("{sha256} is not on the allow-list"));
            }
            warn_if_unanchored(&store);
        }
    }
    Ok(())
}

fn print_notes(notes: &[String]) {
    for n in notes {
        println!("  note: {}", sanitize(n));
    }
}

fn warn_if_unanchored(store: &QuarantineStore) {
    if store.anchor_failed() {
        eprintln!(
            "warning: could not record the audit entry in the system log (/dev/log); the \
             local audit log has no external anchor for this operation"
        );
    }
}

/// Mark findings whose SHA-256 is on the allow-list of the store at
/// `store` (default location if `None`) as `allowed`. Nothing is created or
/// locked; a missing store means an empty list.
pub(crate) fn apply_allowlist(report: &mut ScanReport, store: Option<&Path>) -> Result<(), String> {
    let Ok(path) = store_path(store) else {
        return Ok(());
    };
    let entries = read_allowlist(&path).map_err(|e| e.to_string())?;
    warden_remediation::mark_allowed(report, &entries);
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
pub(crate) fn remediate_report(
    report: &mut ScanReport,
    store: Option<&Path>,
    max_size: u64,
    kill_processes: bool,
) {
    for e in warden_remediation::quarantine_report(
        report,
        || open_store(store),
        max_size,
        kill_processes,
    ) {
        eprintln!("error: could not quarantine: {}", sanitize(&e));
    }
}
