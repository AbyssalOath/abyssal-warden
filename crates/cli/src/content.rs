//! Loading detection content (hash databases, YARA rules) with signature
//! verification. Nothing is parsed until its signature has been checked
//! (or unsigned loading was explicitly allowed).

use std::path::{Path, PathBuf};

use clap::Args;
use time::OffsetDateTime;
use warden_core::{ContentBundleInfo, Detector};
use warden_engine::bundle::{ContentKind, LoadOptions, VerifiedBundle, load_bundle};
use warden_engine::content_state::ContentState;
use warden_engine::signatures::{HashSignatureDatabase, HashSignatureDetector, MAX_DATABASE_BYTES};
use warden_engine::trust::{LoadedContent, SignaturePolicy, TrustedKeys, load_content};
use warden_yara::{MAX_SOURCE_BYTES, RuleSource, YaraDetector};

use crate::output::sanitize;

/// Largest number of rule files taken from one directory.
const MAX_RULE_FILES: usize = 10_000;

#[derive(Args, Debug, Default)]
pub(crate) struct TrustArgs {
    /// Trust signatures made with this minisign public key. May be given more
    /// than once. Content must be signed by one of these keys (as
    /// `FILE.minisig`) unless --allow-unsigned is given.
    #[arg(long = "trusted-key", value_name = "PUBKEY_FILE")]
    trusted_keys: Vec<PathBuf>,
    /// Keyring file (JSON) of trusted keys with validity windows and
    /// revocations. May be given more than once. The system keyring
    /// (/etc/abyssal-warden/keyring.json; on Windows
    /// %ProgramData%\AbyssalWarden\keyring.json) is always loaded if present.
    #[arg(long = "keyring", value_name = "FILE")]
    keyrings: Vec<PathBuf>,
    /// Load signature databases and rules that have no signature file. A
    /// signature that is present must still verify.
    #[arg(long)]
    allow_unsigned: bool,
}

pub(crate) struct Trust {
    keys: TrustedKeys,
    policy: SignaturePolicy,
}

impl Trust {
    /// Revoke keys that accepted bundle manifests revoked, as recorded in
    /// the content state at `state_path` (read-only; nothing is created).
    pub(crate) fn apply_recorded_revocations(&mut self, state_path: &Path) -> Result<(), String> {
        for id in ContentState::read_revoked_keys(state_path).map_err(|e| e.to_string())? {
            self.keys.revoke(&id);
        }
        Ok(())
    }

    pub(crate) fn from_args(args: &TrustArgs) -> Result<Self, String> {
        let mut keys = TrustedKeys::new();
        for path in &args.trusted_keys {
            keys.add_key_file(path).map_err(|e| e.to_string())?;
        }
        // Keyrings last: their revocations and validity windows also apply
        // to keys given with --trusted-key.
        if let Some(system) = system_keyring_path().filter(|p| p.is_file()) {
            keys.add_keyring_file(&system).map_err(|e| e.to_string())?;
        }
        for path in &args.keyrings {
            keys.add_keyring_file(path).map_err(|e| e.to_string())?;
        }
        let policy = if args.allow_unsigned {
            SignaturePolicy::AllowUnsigned
        } else {
            SignaturePolicy::RequireTrusted
        };
        Ok(Self { keys, policy })
    }

    fn load(&self, path: &Path, max: u64) -> Result<LoadedContent, String> {
        let loaded = load_content(path, max, &self.keys, self.policy).map_err(|e| e.to_string())?;
        if loaded.signer.is_none() {
            eprintln!(
                "warning: {} has no signature; loaded because --allow-unsigned was given",
                sanitize(&path.to_string_lossy())
            );
        }
        Ok(loaded)
    }
}

/// The system keyring, loaded automatically when it exists.
fn system_keyring_path() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(|p| PathBuf::from(p).join("AbyssalWarden").join("keyring.json"))
    } else {
        Some(PathBuf::from("/etc/abyssal-warden/keyring.json"))
    }
}

#[derive(Args, Debug, Default)]
pub(crate) struct BundleArgs {
    /// Signed content bundle directory (manifest.json + manifest.json.minisig).
    /// May be given more than once. Bundles get rollback and expiry
    /// protection; see docs/security/content-trust.md.
    #[arg(long = "content", value_name = "DIR")]
    pub(crate) dirs: Vec<PathBuf>,
    /// Accept bundles past their expiry time (e.g. offline systems). The
    /// report records it.
    #[arg(long)]
    allow_expired: bool,
    /// Rollback-protection state file [default: per user, or
    /// /var/lib/abyssal-warden/content-state.json as root].
    #[arg(long, value_name = "FILE")]
    content_state: Option<PathBuf>,
}

/// Detectors built from verified bundles, and what the report records.
impl BundleArgs {
    /// The content state location: `--content-state`, or the default.
    pub(crate) fn state_path(&self) -> Option<PathBuf> {
        self.content_state
            .clone()
            .or_else(crate::paths::content_state_path)
    }
}

pub(crate) struct LoadedBundles {
    pub(crate) detectors: Vec<Box<dyn Detector>>,
    pub(crate) infos: Vec<ContentBundleInfo>,
}

/// Verify every bundle, check rollback, build detectors, and (when `record`
/// is set) record the accepted sequences. Nothing is recorded unless every
/// bundle loads.
pub(crate) fn load_bundles(
    args: &BundleArgs,
    trust: &Trust,
    record: bool,
) -> Result<LoadedBundles, String> {
    let mut out = LoadedBundles {
        detectors: Vec::new(),
        infos: Vec::new(),
    };
    if args.dirs.is_empty() {
        return Ok(out);
    }
    let state_path = args
        .state_path()
        .ok_or("cannot determine a content state location; use --content-state")?;
    let mut state = ContentState::open(&state_path).map_err(|e| e.to_string())?;
    // Keys revoked by earlier accepted manifests no longer count.
    let mut keys = trust.keys.clone();
    for id in state.revoked_keys() {
        keys.revoke(id);
    }
    let now = OffsetDateTime::now_utc();
    let opts = LoadOptions {
        allow_expired: args.allow_expired,
        now,
    };
    let mut bundles = Vec::new();
    for dir in &args.dirs {
        let b = load_bundle(dir, &keys, opts).map_err(|e| e.to_string())?;
        if bundles
            .iter()
            .any(|o: &VerifiedBundle| o.manifest.name == b.manifest.name)
        {
            return Err(format!(
                "bundle name {:?} given more than once",
                b.manifest.name
            ));
        }
        state
            .check(&b, keys.min_sequence(&b.manifest.name))
            .map_err(|e| e.to_string())?;
        // Revocations take effect immediately, for later bundles in this run.
        for id in &b.manifest.revoke_keys {
            keys.revoke(id);
        }
        out.detectors.extend(bundle_detectors(&b)?);
        out.infos.push(ContentBundleInfo {
            name: b.manifest.name.clone(),
            sequence: b.manifest.sequence,
            issued: b.manifest.issued,
            expires: b.manifest.expires,
            signers: b.signers.iter().map(ToString::to_string).collect(),
            manifest_sha256: b.manifest_sha256,
            files: b.files.len() as u64,
            expired: b.expired,
        });
        bundles.push(b);
    }
    if record {
        for b in &bundles {
            state.record(b, now);
        }
        state.save().map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn bundle_detectors(b: &VerifiedBundle) -> Result<Vec<Box<dyn Detector>>, String> {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
    let mut sources = Vec::new();
    for f in &b.files {
        let origin = format!("{}:{}", b.manifest.name, f.path);
        match f.kind {
            ContentKind::HashDatabase => {
                let db = HashSignatureDatabase::from_slice(&f.data)
                    .map_err(|e| format!("{origin}: {e}"))?;
                detectors.push(Box::new(HashSignatureDetector::verified_by(db, &b.signers)));
            }
            ContentKind::YaraRules => {
                let text = String::from_utf8(f.data.clone())
                    .map_err(|_| format!("{origin}: rule source is not UTF-8"))?;
                sources.push(RuleSource {
                    namespace: namespace_for(Path::new(&f.path), sources.len()),
                    origin,
                    text,
                });
            }
        }
    }
    if !sources.is_empty() {
        let signers: Vec<String> = b.signers.iter().map(ToString::to_string).collect();
        let det =
            YaraDetector::compile(&sources, Some(signers.join(","))).map_err(|e| e.to_string())?;
        detectors.push(Box::new(det));
    }
    Ok(detectors)
}

pub(crate) fn load_hash_db(path: &Path, trust: &Trust) -> Result<HashSignatureDetector, String> {
    let loaded = trust.load(path, MAX_DATABASE_BYTES)?;
    let db = HashSignatureDatabase::from_slice(&loaded.data)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(match loaded.signer {
        Some(key) => HashSignatureDetector::verified(db, key),
        None => HashSignatureDetector::new(db),
    })
}

/// Compile YARA rules from files and/or directories (`*.yar`, `*.yara`, not
/// recursive). All sources must be signed by the same trust rules; the
/// resulting rule set is marked signed only if every source was signed.
pub(crate) fn load_yara(paths: &[PathBuf], trust: &Trust) -> Result<YaraDetector, String> {
    let mut files = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut found = rule_files_in(p)?;
            if found.is_empty() {
                return Err(format!("{}: no .yar or .yara files", p.display()));
            }
            files.append(&mut found);
        } else {
            files.push(p.clone());
        }
    }

    let mut sources = Vec::with_capacity(files.len());
    let mut signers = Vec::new();
    let mut total = 0usize;
    for f in &files {
        let loaded = trust.load(f, MAX_SOURCE_BYTES as u64)?;
        total += loaded.data.len();
        if total > MAX_SOURCE_BYTES {
            return Err(format!("YARA sources exceed {MAX_SOURCE_BYTES} bytes"));
        }
        let text = String::from_utf8(loaded.data)
            .map_err(|_| format!("{}: rule source is not UTF-8", f.display()))?;
        signers.push(loaded.signer);
        sources.push(RuleSource {
            namespace: namespace_for(f, sources.len()),
            origin: f.display().to_string(),
            text,
        });
    }
    let signer = if signers.iter().all(Option::is_some) {
        let mut ids: Vec<String> = signers.iter().flatten().map(ToString::to_string).collect();
        ids.sort();
        ids.dedup();
        Some(ids.join(","))
    } else {
        None
    };
    YaraDetector::compile(&sources, signer).map_err(|e| e.to_string())
}

fn rule_files_in(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        let is_rule = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"));
        // file_type() does not follow links: linked rule files are ignored.
        if is_rule && entry.file_type().is_ok_and(|t| t.is_file()) {
            out.push(path);
            if out.len() > MAX_RULE_FILES {
                return Err(format!(
                    "{}: more than {MAX_RULE_FILES} rule files",
                    dir.display()
                ));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// A valid, unique YARA namespace derived from the file stem.
fn namespace_for(path: &Path, index: usize) -> String {
    let stem: String = path
        .file_stem()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(48)
        .collect();
    let stem = if stem.is_empty() {
        "rules".to_owned()
    } else {
        stem
    };
    format!("{stem}_{index}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_are_valid_and_unique() {
        assert_eq!(
            namespace_for(Path::new("/r/My-Rules.v2.yar"), 0),
            "My_Rules_v2_0"
        );
        assert_eq!(namespace_for(Path::new("/r/.yar"), 3), "_yar_3");
        assert_eq!(namespace_for(Path::new("/r/файл.yar"), 1), "_____1");
    }
}
