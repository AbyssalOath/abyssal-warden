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
use crate::content_import::{
    HashImport, Vetted, clean_rule_matches, drop_clean_hashes, parse_hash_list, vet_yara,
    yara_files,
};
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
        /// Refuse files in subdirectories. Needed for GitHub Releases, whose
        /// assets cannot have paths.
        #[arg(long)]
        flat: bool,
    },
    /// Write DIR/timestamp.json for the update channel, naming the bundle
    /// in DIR (its manifest.json). Sign it with a key that has the
    /// `timestamp` role: `rsign sign -s <timestamp.key> DIR/timestamp.json`.
    Timestamp {
        dir: PathBuf,
        /// Increases with every timestamp published for this bundle.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        version: u64,
        /// Hours until the timestamp expires; clients refuse it afterwards,
        /// so publish a new one well before.
        #[arg(long, value_name = "HOURS", default_value_t = 72,
              value_parser = clap::value_parser!(u64).range(1..=744))]
        expires_in: u64,
    },
    /// Convert a SHA-256 list (one digest per line, `sha256sum` output or a
    /// feed's hash file; `#` comments allowed) into a hash database. Record
    /// the feed's licence; only import feeds whose licence allows it
    /// (docs/detection/content-sources.md).
    ImportHashes {
        /// Hash list files.
        #[arg(required = true, value_name = "LIST")]
        lists: Vec<PathBuf>,
        /// Output database (.json), usually inside a bundle directory.
        #[arg(long, short)]
        output: PathBuf,
        /// Database name.
        #[arg(long)]
        db_name: String,
        /// Database version (for example the feed's commit or date).
        #[arg(long)]
        db_version: String,
        /// Detection name shown in findings.
        #[arg(long)]
        detection_name: String,
        /// Prefix for signature ids (`<prefix>-<first 16 hex digits>`).
        #[arg(long)]
        id_prefix: String,
        /// Licence and source of the feed, recorded in the database.
        #[arg(long)]
        license: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long, default_value = "malware",
              value_parser = ["malware", "potentially_unwanted", "unknown"])]
        category: String,
        #[arg(long, default_value = "high",
              value_parser = ["info", "low", "medium", "high", "critical"])]
        severity: String,
        /// Name detections after each list's directory: `<detection-name>.<dir>`
        /// (for feeds with one directory per campaign or family).
        #[arg(long)]
        name_by_directory: bool,
        /// Known-clean files or directories: hashes matching any of them are
        /// dropped and reported. Links inside are followed. Repeatable.
        #[arg(long, value_name = "DIR")]
        clean_corpus: Vec<PathBuf>,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
    },
    /// Vet third-party YARA files one by one and copy those that compile under
    /// this project's restrictions into OUTPUT_DIR; report the rest with the
    /// reason. One bad rule file does not sink a whole feed.
    ImportYara {
        /// Rule files or directories (searched for .yar/.yara).
        #[arg(required = true, value_name = "PATH")]
        inputs: Vec<PathBuf>,
        /// Directory to copy accepted files into (created if missing).
        #[arg(long, short)]
        output_dir: PathBuf,
        /// A file listing rule file names to skip, one per line (`#`
        /// comments allowed), e.g. rules that need external variables.
        #[arg(long)]
        exclude: Option<PathBuf>,
        /// Prefix for the copied files' names, so feeds cannot collide in a
        /// flat bundle (e.g. `rl-`).
        #[arg(long, default_value = "")]
        prefix: String,
        /// Known-clean files or directories: rule files with any rule that
        /// matches them are dropped and reported. Links inside are followed.
        /// Repeatable.
        #[arg(long, value_name = "DIR")]
        clean_corpus: Vec<PathBuf>,
    },
    /// Print keyring entries (ID, public key, roles) for minisign public key
    /// files, to paste into a keyring's `keys` list.
    KeyEntry {
        #[arg(required = true, value_name = "PUBLIC_KEY")]
        key_files: Vec<PathBuf>,
        /// Role of these keys.
        #[arg(long, value_parser = ["content", "timestamp"], default_value = "content")]
        role: String,
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
            flat,
        } => write_manifest(&dir, name, sequence, expires_in, force, revoke_keys, flat),
        ContentCommand::Timestamp {
            dir,
            version,
            expires_in,
        } => write_timestamp(&dir, version, expires_in),
        ContentCommand::ImportHashes {
            lists,
            output,
            db_name,
            db_version,
            detection_name,
            id_prefix,
            license,
            description,
            category,
            severity,
            name_by_directory,
            clean_corpus,
            force,
        } => import_hashes(
            &lists,
            &output,
            force,
            name_by_directory,
            &clean_corpus,
            &HashImport {
                db_name: &db_name,
                db_version: &db_version,
                detection_name: &detection_name,
                id_prefix: &id_prefix,
                category: &category,
                severity: &severity,
                license: &license,
                description: description.as_deref(),
            },
        ),
        ContentCommand::KeyEntry { key_files, role } => key_entries(&key_files, &role),
        ContentCommand::ImportYara {
            inputs,
            output_dir,
            exclude,
            prefix,
            clean_corpus,
        } => import_yara(
            &inputs,
            &output_dir,
            exclude.as_deref(),
            &prefix,
            &clean_corpus,
        ),
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

fn write_timestamp(dir: &Path, version: u64, expires_in: u64) -> Result<(), String> {
    use warden_engine::freshness::{TIMESTAMP_FILE, TIMESTAMP_FORMAT, Timestamp};
    let manifest_path = dir.join(MANIFEST_FILE);
    let data =
        std::fs::read(&manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    let manifest: Manifest =
        serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    manifest.validate().map_err(|e| e.to_string())?;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|e| e.to_string())?;
    let hours = i64::try_from(expires_in).map_err(|e| e.to_string())?;
    let ts = Timestamp {
        format: TIMESTAMP_FORMAT.into(),
        format_version: 1,
        version,
        bundle: manifest.name.clone(),
        sequence: manifest.sequence,
        manifest_sha256: Sha256Digest::from_bytes(Sha256::digest(&data).into()),
        manifest_size: data.len() as u64,
        issued: now,
        expires: now + Duration::hours(hours),
    };
    ts.validate(now).map_err(|e| e.to_string())?;
    let path = dir.join(TIMESTAMP_FILE);
    let json = serde_json::to_vec_pretty(&ts).map_err(|e| e.to_string())?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    tmp.write_all(&json).map_err(|e| e.to_string())?;
    tmp.write_all(b"\n").map_err(|e| e.to_string())?;
    tmp.persist(&path).map_err(|e| e.error.to_string())?;
    println!(
        "wrote {} (bundle {} sequence {}, version {version}, expires {})",
        sanitize(&path.to_string_lossy()),
        sanitize(&manifest.name),
        manifest.sequence,
        ts.expires.format(&Rfc3339).unwrap_or_default()
    );
    println!(
        "next: sign it with the timestamp key, e.g.\n  rsign sign -s <timestamp.key> {}",
        sanitize(&path.to_string_lossy())
    );
    Ok(())
}

/// Largest hash list read (a list of 2,000,000 `sha256sum` lines is ~200 MB).
const MAX_HASH_LIST_BYTES: u64 = 256 << 20;

fn write_new(path: &Path, data: &[u8], force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "{} already exists; use --force to replace it",
            path.display()
        ));
    }
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut tmp =
        tempfile::NamedTempFile::new_in(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    tmp.write_all(data).map_err(|e| e.to_string())?;
    tmp.as_file().sync_all().map_err(|e| e.to_string())?;
    tmp.persist(path).map_err(|e| e.error.to_string())?;
    Ok(())
}

fn import_hashes(
    lists: &[PathBuf],
    output: &Path,
    force: bool,
    name_by_directory: bool,
    clean_corpus: &[PathBuf],
    meta: &HashImport<'_>,
) -> Result<(), String> {
    // SHA-256 -> group; the first list naming a hash wins.
    let mut all = std::collections::BTreeMap::new();
    let mut rejected = 0;
    for list in lists {
        let size = std::fs::metadata(list)
            .map_err(|e| format!("{}: {e}", list.display()))?
            .len();
        if size > MAX_HASH_LIST_BYTES {
            return Err(format!(
                "{}: larger than {MAX_HASH_LIST_BYTES} bytes",
                list.display()
            ));
        }
        let group = if name_by_directory {
            let dir = list
                .parent()
                .and_then(Path::file_name)
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if crate::content_import::id_part(&dir).is_empty() {
                return Err(format!(
                    "{}: its directory name cannot name detections",
                    list.display()
                ));
            }
            dir
        } else {
            String::new()
        };
        let data = std::fs::read(list).map_err(|e| format!("{}: {e}", list.display()))?;
        let text = String::from_utf8_lossy(&data);
        let (set, bad) = parse_hash_list(&text);
        rejected += bad;
        for h in set {
            all.entry(h).or_insert_with(|| group.clone());
        }
    }
    if all.is_empty() {
        return Err("no SHA-256 values found".into());
    }
    if !clean_corpus.is_empty() {
        for (h, file) in drop_clean_hashes(&mut all, meta, clean_corpus)? {
            println!("dropped {h}: matches clean file {}", sanitize(&file));
        }
        if all.is_empty() {
            return Err("every hash matched the clean corpus".into());
        }
    }
    let json = crate::content_import::hash_database(&all, meta)?;
    write_new(output, &json, force)?;
    println!(
        "wrote {} ({} signature(s); {rejected} line(s) were not SHA-256 and were skipped)",
        sanitize(&output.to_string_lossy()),
        all.len()
    );
    Ok(())
}

fn import_yara(
    inputs: &[PathBuf],
    output_dir: &Path,
    exclude: Option<&Path>,
    prefix: &str,
    clean_corpus: &[PathBuf],
) -> Result<(), String> {
    let excluded: std::collections::BTreeSet<String> = match exclude {
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| format!("{}: {e}", p.display()))?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect(),
        None => Default::default(),
    };
    let mut files = Vec::new();
    for input in inputs {
        let meta =
            std::fs::symlink_metadata(input).map_err(|e| format!("{}: {e}", input.display()))?;
        if meta.is_dir() {
            files.extend(yara_files(input)?);
        } else if meta.is_file() {
            files.push(input.clone());
        } else {
            return Err(format!("{}: not a file or directory", input.display()));
        }
    }
    let skip = |file: &Path, reason: &str| {
        println!(
            "skipped {}: {}",
            sanitize(&file.to_string_lossy()),
            sanitize(reason)
        );
    };
    // Vet each file on its own: (output name, text, source).
    let mut candidates: Vec<(String, String, &PathBuf)> = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let mut skipped = 0usize;
    for file in &files {
        let Some(name) = file.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            skip(file, "file name is not UTF-8");
            skipped += 1;
            continue;
        };
        let out_name = format!("{prefix}{name}");
        let result = if excluded.contains(&name) {
            Err("excluded".to_owned())
        } else if !valid_relative_path(&out_name) || out_name.contains('/') {
            Err("not a valid bundle file name".to_owned())
        } else if !names.insert(out_name.clone()) {
            Err("another file has the same name".to_owned())
        } else {
            match std::fs::read(file) {
                Err(e) => Err(e.to_string()),
                Ok(d) if d.len() as u64 > MAX_CONTENT_FILE_BYTES => Err("too large".into()),
                Ok(d) => match String::from_utf8(d) {
                    Err(_) => Err("not UTF-8".into()),
                    Ok(text) => match vet_yara(&name, &text) {
                        Vetted::Accepted => Ok(text),
                        Vetted::Rejected(r) => Err(r),
                    },
                },
            }
        };
        match result {
            Ok(text) => candidates.push((out_name, text, file)),
            Err(r) => {
                skip(file, &r);
                skipped += 1;
            }
        }
    }
    // Then drop files with rules that fire on known-clean files.
    if !clean_corpus.is_empty() && !candidates.is_empty() {
        let pairs: Vec<(String, String)> = candidates
            .iter()
            .map(|(n, t, _)| (n.clone(), t.clone()))
            .collect();
        let bad = clean_rule_matches(&pairs, clean_corpus)?;
        let mut kept = Vec::new();
        for (i, c) in candidates.into_iter().enumerate() {
            if let Some(reason) = bad.get(&i) {
                skip(c.2, reason);
                skipped += 1;
            } else {
                kept.push(c);
            }
        }
        candidates = kept;
    }
    if candidates.is_empty() {
        return Err("no rule files were accepted".into());
    }
    std::fs::create_dir_all(output_dir).map_err(|e| format!("{}: {e}", output_dir.display()))?;
    for (out_name, text, _) in &candidates {
        write_new(&output_dir.join(out_name), text.as_bytes(), true)?;
    }
    println!(
        "accepted {} rule file(s) into {}; skipped {skipped}",
        candidates.len(),
        sanitize(&output_dir.to_string_lossy())
    );
    Ok(())
}

fn key_entries(files: &[PathBuf], role: &str) -> Result<(), String> {
    let mut entries = Vec::new();
    for f in files {
        let id = warden_engine::trust::TrustedKeys::new()
            .add_key_file(f)
            .map_err(|e| e.to_string())?;
        // The key line of a minisign public key file (checked by the parse above).
        let text = std::fs::read_to_string(f).map_err(|e| format!("{}: {e}", f.display()))?;
        let key = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .ok_or_else(|| format!("{}: no public key line", f.display()))?;
        let description = f
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        entries.push(serde_json::json!({
            "id": id.to_string(),
            "public_key": key,
            "roles": [role],
            "description": description,
        }));
    }
    for e in &entries {
        println!("{},", serde_json::to_string(e).map_err(|e| e.to_string())?);
    }
    Ok(())
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
    flat: bool,
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
    if flat
        && let Some(bad) = files.iter().find(|f| {
            !f.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return Err(format!(
            "{bad}: --flat bundles need file names of [A-Za-z0-9._-] only, with no \
             subdirectories (GitHub release assets have no paths and rename other characters)"
        ));
    }
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
    let base = rel.rsplit('/').next().unwrap_or(rel).to_ascii_uppercase();
    let notice = [
        "LICENSE", "LICENCE", "NOTICE", "COPYING", "AUTHORS", "README", "SOURCES",
    ]
    .iter()
    .any(|n| base.starts_with(n))
        || matches!(ext.as_deref(), Some("txt" | "md"));
    if notice {
        if data.len() > 1 << 20 || std::str::from_utf8(data).is_err() {
            return Err(format!(
                "{rel}: notices must be UTF-8 text of at most 1 MiB"
            ));
        }
        return Ok(ContentKind::Notice);
    }
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
            "{rel}: unknown content file (expected .json hash databases, .yar/.yara rules, or licence/notice text)"
        )),
    }
}
