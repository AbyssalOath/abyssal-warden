//! `abyssal-warden content ...`: build and verify signed content bundles.
//!
//! Signing is deliberately **not** done by this tool: the secret key stays
//! with a dedicated signing tool (`minisign`, or `rsign2` in Rust), ideally on
//! an offline machine. See docs/security/content-trust.md.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use warden_core::Sha256Digest;
use warden_engine::bundle::{
    ContentKind, MANIFEST_FILE, MAX_CONTENT_FILE_BYTES, Manifest, ManifestFile, valid_relative_path,
};
use warden_engine::signatures::HashSignatureDatabase;
use warden_engine::trust::signature_path;
use warden_yara::{RuleSource, YaraDetector};

use crate::EXIT_ERROR;
use crate::content::{BundleArgs, Trust, TrustArgs, load_bundles};
use crate::output::sanitize;

/// Most files a manifest may list (matches the loader's limit).
const MAX_FILES: usize = 10_000;

#[derive(Subcommand, Debug)]
pub(crate) enum ContentCommand {
    /// Write DIR/manifest.json listing every content file in DIR, after
    /// checking that each one is valid. Sign the manifest afterwards with
    /// minisign or rsign.
    Manifest {
        dir: PathBuf,
        /// Bundle name; rollback protection is tracked per name.
        #[arg(long)]
        name: String,
        /// Release number; must be higher than every earlier release.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        sequence: u64,
        /// Days until the bundle expires.
        #[arg(long, value_name = "DAYS", default_value_t = 30,
              value_parser = clap::value_parser!(u64).range(1..=3650))]
        expires_in: u64,
        /// Replace an existing manifest.json.
        #[arg(long)]
        force: bool,
        /// Revoke this key ID in every client that accepts the bundle. May be
        /// given more than once. Revocations are permanent on the client.
        #[arg(long = "revoke-key", value_name = "KEY_ID")]
        revoke_keys: Vec<String>,
    },
    /// Verify bundles as a scan would (signature, key validity, expiry, file
    /// hashes, content validity, rollback) without recording anything.
    Verify {
        /// Bundle directories.
        #[arg(required = true, value_name = "DIR")]
        bundle_dirs: Vec<PathBuf>,
        #[command(flatten)]
        trust: TrustArgs,
        #[command(flatten)]
        bundles: BundleArgs,
    },
}

pub(crate) fn run(cmd: ContentCommand) -> ExitCode {
    let result = match cmd {
        ContentCommand::Manifest {
            dir,
            name,
            sequence,
            expires_in,
            force,
            revoke_keys,
        } => write_manifest(&dir, name, sequence, expires_in, force, revoke_keys),
        ContentCommand::Verify {
            bundle_dirs,
            trust,
            mut bundles,
        } => verify(bundle_dirs, &trust, &mut bundles),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", sanitize(&e));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn verify(dirs: Vec<PathBuf>, trust: &TrustArgs, bundles: &mut BundleArgs) -> Result<(), String> {
    bundles.dirs.extend(dirs);
    let trust = Trust::from_args(trust)?;
    let loaded = load_bundles(bundles, &trust, false)?;
    for b in &loaded.infos {
        let expires = b.expires.format(&Rfc3339).unwrap_or_default();
        println!(
            "valid: bundle \"{}\" sequence {}, {} file(s), signed by key {}, expires {}{}",
            sanitize(&b.name),
            b.sequence,
            b.files,
            sanitize(&b.signers.join(", ")),
            expires,
            if b.expired { " (EXPIRED)" } else { "" }
        );
    }
    println!("rollback check passed; nothing was recorded");
    Ok(())
}

fn write_manifest(
    dir: &Path,
    name: String,
    sequence: u64,
    expires_in: u64,
    force: bool,
    revoke_keys: Vec<String>,
) -> Result<(), String> {
    let manifest_path = dir.join(MANIFEST_FILE);
    if manifest_path.exists() && !force {
        return Err(format!(
            "{} already exists; use --force to replace it",
            manifest_path.display()
        ));
    }
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|e| e.to_string())?;
    let days = i64::try_from(expires_in).map_err(|e| e.to_string())?;
    let mut manifest = Manifest::new(name, sequence, now, now + Duration::days(days));
    manifest.revoke_keys = revoke_keys.iter().map(|k| k.to_ascii_uppercase()).collect();

    let mut files = Vec::new();
    collect(dir, dir, &mut files)?;
    files.sort();
    for rel in files {
        let path = dir.join(&rel);
        let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if data.len() as u64 > MAX_CONTENT_FILE_BYTES {
            return Err(format!(
                "{rel}: larger than the {MAX_CONTENT_FILE_BYTES}-byte limit"
            ));
        }
        let kind = content_kind(&rel, &data)?;
        manifest.files.push(ManifestFile {
            size: data.len() as u64,
            sha256: Sha256Digest::from_bytes(Sha256::digest(&data).into()),
            path: rel,
            kind,
        });
    }
    manifest.validate().map_err(|e| e.to_string())?;

    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    tmp.write_all(&json).map_err(|e| e.to_string())?;
    tmp.write_all(b"\n").map_err(|e| e.to_string())?;
    tmp.as_file().sync_all().map_err(|e| e.to_string())?;
    tmp.persist(&manifest_path)
        .map_err(|e| e.error.to_string())?;

    println!(
        "wrote {} ({} file(s), sequence {}, expires {})",
        sanitize(&manifest_path.to_string_lossy()),
        manifest.files.len(),
        manifest.sequence,
        manifest.expires.format(&Rfc3339).unwrap_or_default()
    );
    if signature_path(&manifest_path).exists() {
        println!("note: the existing manifest.json.minisig no longer matches; re-sign");
    }
    println!(
        "next: sign it on the signing machine, e.g.\n  rsign sign -s <secret.key> -t \"{name} {sequence}\" {path}\n  (or: minisign -S -s <secret.key> -t \"{name} {sequence}\" -m {path})",
        name = sanitize(&manifest.name),
        sequence = manifest.sequence,
        path = sanitize(&manifest_path.to_string_lossy())
    );
    Ok(())
}

/// Content files below `dir`, as `/`-separated paths relative to `root`.
/// Links are not followed; the manifest, signatures and dotfiles are skipped.
fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(format!("{}: file names must be UTF-8", dir.display()));
        };
        if name.starts_with('.') || name.ends_with(".minisig") {
            continue;
        }
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        let path = entry.path();
        if ft.is_dir() {
            collect(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if rel == MANIFEST_FILE {
                continue;
            }
            if !valid_relative_path(&rel) {
                return Err(format!("{rel:?}: not a valid bundle path"));
            }
            out.push(rel);
            if out.len() > MAX_FILES {
                return Err(format!("more than {MAX_FILES} content files"));
            }
        } else {
            return Err(format!(
                "{}: symbolic links and special files are not allowed in a bundle",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Kind by extension, after checking the content is valid for that kind.
fn content_kind(rel: &str, data: &[u8]) -> Result<ContentKind, String> {
    let ext = rel.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("json") => {
            HashSignatureDatabase::from_slice(data).map_err(|e| format!("{rel}: {e}"))?;
            Ok(ContentKind::HashDatabase)
        }
        Some("yar" | "yara") => {
            let text = std::str::from_utf8(data).map_err(|_| format!("{rel}: not UTF-8"))?;
            YaraDetector::compile(
                &[RuleSource {
                    namespace: "check".into(),
                    origin: rel.into(),
                    text: text.into(),
                }],
                None,
            )
            .map_err(|e| format!("{rel}: {e}"))?;
            Ok(ContentKind::YaraRules)
        }
        _ => Err(format!(
            "{rel}: unknown content file (expected .json hash databases or .yar/.yara rules)"
        )),
    }
}
