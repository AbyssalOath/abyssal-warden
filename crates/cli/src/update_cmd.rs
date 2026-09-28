//! `abyssal-warden update`: fetch and install the latest signed content
//! bundle from an update source (docs/user/updates.md).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use time::format_description::well_known::Rfc3339;
use warden_update::{Source, UpdateOptions};

use crate::content::{Trust, TrustArgs, validate_bundle};
use crate::output::sanitize;
use crate::{EXIT_ERROR, Format};

/// Environment variable naming the default update source.
pub(crate) const SOURCE_ENV: &str = "ABYSSAL_WARDEN_UPDATE_SOURCE";

/// The project's official update channel (GitHub Releases of the content
/// repository; ADR-0020).
pub(crate) const OFFICIAL_SOURCE: &str =
    "https://github.com/AbyssalOath/abyssal-warden-content/releases/latest/download/";

#[derive(Args, Debug)]
pub(crate) struct UpdateArgs {
    /// Update source: an https:// URL or a local directory (mirror)
    /// [default: $ABYSSAL_WARDEN_UPDATE_SOURCE, else the official channel].
    #[arg(long, value_name = "URL|DIR")]
    source: Option<String>,
    /// Where bundles are installed, one subdirectory each [default:
    /// /var/lib/abyssal-warden/content as root, else per user].
    #[arg(long, value_name = "DIR")]
    content_dir: Option<PathBuf>,
    /// Rollback and freshness state [default: as for scans].
    #[arg(long, value_name = "FILE")]
    content_state: Option<PathBuf>,
    /// Accept an expired timestamp or bundle (offline mirrors). Stale
    /// content may miss current threats.
    #[arg(long)]
    allow_expired: bool,
    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,
    #[command(flatten)]
    trust: TrustArgs,
}

pub(crate) fn run(args: &UpdateArgs) -> ExitCode {
    match run_inner(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", sanitize(&e));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run_inner(args: &UpdateArgs) -> Result<(), String> {
    let source = args
        .source
        .clone()
        .or_else(|| std::env::var(SOURCE_ENV).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| OFFICIAL_SOURCE.to_owned());
    let source = Source::parse(&source).map_err(|e| e.to_string())?;
    let content_dir = args
        .content_dir
        .clone()
        .or_else(crate::paths::content_dir_path)
        .ok_or("cannot determine the content directory; use --content-dir")?;
    let state_path = args
        .content_state
        .clone()
        .or_else(crate::paths::content_state_path)
        .ok_or("cannot determine the content state location; use --content-state")?;
    let mut trust = Trust::from_args(&args.trust)?;
    trust.apply_recorded_revocations(&state_path)?;
    if trust.keys.is_empty() {
        return Err("no trusted keys: install the release keyring or give --keyring".into());
    }
    let outcome = warden_update::update(&UpdateOptions {
        source,
        content_dir,
        state_path,
        keys: &trust.keys,
        allow_expired: args.allow_expired,
        validate: &validate_bundle,
    })
    .map_err(|e| e.to_string())?;
    let expires = outcome
        .timestamp_expires
        .format(&Rfc3339)
        .unwrap_or_default();
    if args.format == Format::Json {
        let v = serde_json::json!({
            "bundle": outcome.bundle,
            "previous_sequence": outcome.previous,
            "sequence": outcome.sequence,
            "installed": outcome.installed,
            "changed": outcome.changed,
            "timestamp_version": outcome.timestamp_version,
            "timestamp_expires": expires,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if outcome.changed {
        let from = outcome
            .previous
            .map_or_else(|| "none".to_owned(), |p| p.to_string());
        println!(
            "updated bundle \"{}\": sequence {from} -> {}",
            sanitize(&outcome.bundle),
            outcome.sequence
        );
    } else {
        println!(
            "bundle \"{}\" is up to date (sequence {})",
            sanitize(&outcome.bundle),
            outcome.sequence
        );
    }
    println!(
        "  installed at {}",
        sanitize(&outcome.installed.to_string_lossy())
    );
    println!(
        "  update channel timestamp {} valid until {expires}",
        outcome.timestamp_version
    );
    Ok(())
}
