//! Loading detection content (hash databases, YARA rules) with signature
//! verification. Nothing is parsed until its signature has been checked
//! (or unsigned loading was explicitly allowed).

use std::path::{Path, PathBuf};

use clap::Args;
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
    pub(crate) fn from_args(args: &TrustArgs) -> Result<Self, String> {
        let mut keys = TrustedKeys::new();
        for path in &args.trusted_keys {
            keys.add_key_file(path).map_err(|e| e.to_string())?;
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
