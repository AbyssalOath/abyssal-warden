//! `abyssal-warden system-check`: persistence inventory and integrity checks,
//! optionally scanning the executables persistence entries start.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use uuid::Uuid;
use warden_core::{
    CancellationToken, CheckStatus, EngineInfo, FindingKind, FindingTarget, ObservedPath,
    RemediationStatus, SYSTEM_REPORT_SCHEMA_VERSION, ScanConfig, ScanStatus, SymlinkPolicy,
    SystemReport,
};
use warden_engine::Scanner;
use warden_system::{SystemCheckOptions, correlate, host_path, run_checks};

use crate::output::{render_system, sanitize};
use crate::{
    EXIT_CANCELLED, EXIT_ERROR, EXIT_FINDINGS, EXIT_INCOMPLETE, Format, content, content_warnings,
    install_interrupt_handler, load_detectors, write_atomically,
};

/// Most referenced executables scanned.
const MAX_REFERENCED: usize = 5000;

#[derive(Args, Debug)]
pub(crate) struct SystemCheckArgs {
    /// Root of the system to inspect. Use a mounted disk image for offline
    /// inspection; kernel and process checks then do not apply.
    #[arg(long, value_name = "DIR", default_value = "/")]
    root: PathBuf,
    /// Do not probe for processes hidden from /proc (the probe checks every
    /// possible PID and takes a few seconds).
    #[arg(long)]
    no_hidden_processes: bool,
    /// Do not verify files with the package manager (rpm or dpkg).
    #[arg(long)]
    no_packages: bool,
    /// Verify every installed package, not only critical and referenced
    /// files (slow).
    #[arg(long, conflicts_with = "no_packages")]
    verify_all_packages: bool,
    /// Time limit for each package-manager run, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 300,
          value_parser = clap::value_parser!(u64).range(1..=86_400))]
    package_timeout: u64,
    /// Hash signature database used to scan the executables that persistence
    /// entries start. May be given more than once.
    #[arg(short = 's', long = "signatures", value_name = "FILE")]
    signatures: Vec<PathBuf>,
    /// YARA rules used to scan referenced executables.
    #[arg(short = 'y', long = "yara", value_name = "PATH")]
    yara: Vec<PathBuf>,
    #[command(flatten)]
    trust: content::TrustArgs,
    #[command(flatten)]
    bundles: content::BundleArgs,
    /// Do not scan referenced executables even when content is given.
    #[arg(long)]
    no_referenced_scan: bool,
    /// Also run the heuristic detectors on referenced programs.
    #[arg(long)]
    heuristics: bool,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    /// Write the report to FILE instead of standard output.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// List every persistence entry in human-readable output (JSON always
    /// has them all).
    #[arg(long)]
    show_inventory: bool,
}

pub(crate) fn run(args: SystemCheckArgs) -> ExitCode {
    match run_inner(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {}", sanitize(&e));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run_inner(args: &SystemCheckArgs) -> Result<u8, String> {
    let has_content =
        !args.signatures.is_empty() || !args.yara.is_empty() || !args.bundles.dirs.is_empty();
    let wants_content = !args.no_referenced_scan && (has_content || args.heuristics);
    let (mut detectors, bundle_infos) = if wants_content && has_content {
        load_detectors(&args.signatures, &args.yara, &args.trust, &args.bundles)?
    } else {
        (Vec::new(), Vec::new())
    };
    if wants_content && args.heuristics {
        detectors.push(Box::new(warden_heuristics::HeuristicsDetector::new()));
    }

    let token = CancellationToken::new();
    install_interrupt_handler(&token);
    let started_at = time::OffsetDateTime::now_utc();
    let opts = SystemCheckOptions {
        root: args.root.clone(),
        hidden_processes: !args.no_hidden_processes,
        packages: !args.no_packages,
        verify_all_packages: args.verify_all_packages,
        package_timeout: Duration::from_secs(args.package_timeout),
    };
    let outcome = run_checks(&opts, &token).map_err(|e| e.to_string())?;
    let mut findings = outcome.findings;
    let mut warnings = outcome.warnings;

    // Scan what persistence entries start, and link detections back.
    let mut referenced = None;
    if !detectors.is_empty() && !token.is_cancelled() {
        let mut logical_by_host: BTreeMap<PathBuf, ObservedPath> = BTreeMap::new();
        for exe in outcome
            .persistence
            .iter()
            .filter_map(|e| e.executable.as_ref())
        {
            if exe.is_lossy() || logical_by_host.len() >= MAX_REFERENCED {
                continue;
            }
            if let Ok(host) = host_path(&args.root, Path::new(&exe.text)) {
                logical_by_host.entry(host).or_insert_with(|| exe.clone());
            }
        }
        if !logical_by_host.is_empty() {
            let mut config = ScanConfig::new(logical_by_host.keys().cloned().collect());
            config.symlink_policy = SymlinkPolicy::Skip;
            let mut scanner = Scanner::new(config).map_err(|e| e.to_string())?;
            for d in detectors {
                scanner.add_detector(d);
            }
            let mut report = scanner.scan(&token, |_, _| {}).map_err(|e| e.to_string())?;
            report.content_bundles = bundle_infos;
            content_warnings(&args.signatures, &args.yara, &mut report);
            let detected: Vec<(ObservedPath, &warden_core::Finding)> = report
                .findings
                .iter()
                .filter_map(|f| match &f.target {
                    FindingTarget::File { path, .. }
                    | FindingTarget::ArchiveMember { archive: path, .. } => logical_by_host
                        .get(Path::new(&path.text))
                        .map(|l| (l.clone(), f)),
                    _ => None,
                })
                .collect();
            findings.extend(correlate(&outcome.persistence, &detected));
            referenced = Some(report);
        }
    } else if !wants_content && !args.no_referenced_scan {
        warnings.push(
            "No detection content given (--content, --signatures, --yara, --heuristics): the programs that \
             persistence entries start were not scanned."
                .into(),
        );
    }

    let cancelled = token.is_cancelled();
    let report = SystemReport {
        schema_version: SYSTEM_REPORT_SCHEMA_VERSION,
        report_id: Uuid::new_v4(),
        engine: EngineInfo {
            name: "abyssal-warden-system".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        started_at,
        finished_at: time::OffsetDateTime::now_utc(),
        host: outcome.host,
        checks: outcome.checks,
        findings,
        persistence: outcome.persistence,
        issues: outcome.issues,
        referenced_files: referenced,
        warnings,
    };

    let rendered = match args.format {
        Format::Json => {
            let mut s = serde_json::to_string_pretty(&report)
                .map_err(|e| format!("cannot serialise report: {e}"))?;
            s.push('\n');
            s
        }
        Format::Human => render_system(&report, args.show_inventory),
    };
    match &args.output {
        Some(path) => write_atomically(path, rendered.as_bytes()),
        None => io::stdout().lock().write_all(rendered.as_bytes()),
    }
    .map_err(|e| format!("cannot write report: {e}"))?;

    Ok(if cancelled {
        EXIT_CANCELLED
    } else {
        exit_code(&report)
    })
}

/// 1 if anything needs review, 3 if coverage was incomplete, else 0.
/// Informational findings (e.g. kernel taint from vendor drivers) and
/// allow-listed ones do not count.
pub(crate) fn exit_code(report: &SystemReport) -> u8 {
    let actionable = |f: &warden_core::Finding| {
        f.kind != FindingKind::Informational && f.remediation_status != RemediationStatus::Allowed
    };
    let referenced = report.referenced_files.as_ref();
    if report.findings.iter().any(actionable)
        || referenced.is_some_and(|r| r.findings.iter().any(actionable))
    {
        return EXIT_FINDINGS;
    }
    let incomplete_check = report.checks.iter().any(|c| {
        matches!(
            c.status,
            CheckStatus::Partial | CheckStatus::Failed | CheckStatus::Unsupported
        )
    });
    if incomplete_check
        || !report.issues.is_empty()
        || referenced.is_some_and(|r| r.status != ScanStatus::Completed || !r.is_complete())
    {
        EXIT_INCOMPLETE
    } else {
        0
    }
}
