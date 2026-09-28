//! Content updates: fetch the latest signed content bundle from an update
//! source, verify it completely, and install it atomically.
//!
//! Order of checks (docs/architecture/decisions/0020-content-updates.md):
//! 1. `timestamp.json` and its signature, from a `timestamp`-role key; not
//!    expired; not older than one seen before; not naming an older bundle.
//! 2. `manifest.json` must match the size and SHA-256 the timestamp names.
//! 3. Its signatures, then every listed file (exact size and SHA-256 while
//!    downloading), into a private staging directory.
//! 4. The staged bundle is verified again exactly as a scan would
//!    (`load_bundle`: content-key signatures, threshold, expiry, hashes),
//!    checked for rollback, and parsed by the caller's validator (hash
//!    databases, YARA compilation).
//! 5. Only then is it swapped into place, and the state recorded.
//!
//! Nothing downloaded is trusted before step 4 completes; a failure at any
//! point leaves the installed bundle untouched.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use warden_core::Sha256Digest;
use warden_engine::bundle::{
    self, LoadOptions, MANIFEST_FILE, MAX_MANIFEST_BYTES, MAX_SIGNATURES, Manifest, VerifiedBundle,
};
use warden_engine::content_state::ContentState;
use warden_engine::freshness::{self, MAX_TIMESTAMP_BYTES, TIMESTAMP_FILE};
use warden_engine::trust::TrustedKeys;

const MAX_SIGNATURE_BYTES: u64 = 4096;

/// Where updates come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// An `https://` base URL (ending in `/`).
    Https(String),
    /// A local directory (a mirror on disk, removable media, tests).
    Dir(PathBuf),
}

impl Source {
    /// `https://...` or a directory path. Plain `http://` is refused.
    pub fn parse(s: &str) -> Result<Self, UpdateError> {
        if let Some(rest) = s.strip_prefix("https://") {
            if rest.is_empty() || rest.contains(char::is_whitespace) {
                return Err(UpdateError::Source(format!("invalid URL {s:?}")));
            }
            let mut base = s.to_owned();
            if !base.ends_with('/') {
                base.push('/');
            }
            return Ok(Self::Https(base));
        }
        if s.contains("://") {
            return Err(UpdateError::Source(format!(
                "{s}: only https:// sources and local directories are supported"
            )));
        }
        Ok(Self::Dir(PathBuf::from(s)))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("update source: {0}")]
    Source(String),
    #[error("{name}: not found on the update source")]
    Missing { name: String },
    #[error("{name}: {reason}")]
    Fetch { name: String, reason: String },
    #[error(transparent)]
    Freshness(#[from] freshness::FreshnessError),
    #[error(transparent)]
    State(#[from] warden_engine::content_state::StateError),
    #[error(transparent)]
    Bundle(#[from] bundle::BundleError),
    #[error("the downloaded bundle does not match the update channel: {0}")]
    Mismatch(String),
    #[error("the downloaded content is not usable: {0}")]
    Invalid(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> UpdateError + '_ {
    move |source| UpdateError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Percent-encodes a bundle path for a URL (segments keep their `/`).
fn url_path(rel: &str) -> String {
    let mut out = String::with_capacity(rel.len());
    for b in rel.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

enum Fetcher {
    Https { agent: ureq::Agent, base: String },
    Dir(PathBuf),
}

impl Fetcher {
    fn new(source: &Source) -> Self {
        match source {
            Source::Https(base) => {
                let tls = ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build();
                let agent = ureq::Agent::config_builder()
                    .https_only(true)
                    .max_redirects(3)
                    .timeout_connect(Some(Duration::from_secs(30)))
                    .timeout_global(Some(Duration::from_secs(900)))
                    .http_status_as_error(false)
                    .user_agent(format!("abyssal-warden/{}", env!("CARGO_PKG_VERSION")))
                    .tls_config(tls)
                    .build()
                    .into();
                Self::Https {
                    agent,
                    base: base.clone(),
                }
            }
            Source::Dir(d) => Self::Dir(d.clone()),
        }
    }

    /// The file `rel` (a validated relative path), at most `limit` bytes.
    /// `None` if it does not exist.
    fn get(&self, rel: &str, limit: u64) -> Result<Option<Vec<u8>>, UpdateError> {
        let fail = |reason: String| UpdateError::Fetch {
            name: rel.to_owned(),
            reason,
        };
        match self {
            Self::Https { agent, base } => {
                let url = format!("{base}{}", url_path(rel));
                let mut resp = agent.get(&url).call().map_err(|e| fail(e.to_string()))?;
                match resp.status().as_u16() {
                    200 => resp
                        .body_mut()
                        .with_config()
                        .limit(limit)
                        .read_to_vec()
                        .map(Some)
                        .map_err(|e| fail(e.to_string())),
                    404 | 410 => Ok(None),
                    code => Err(fail(format!("HTTP status {code}"))),
                }
            }
            Self::Dir(base) => {
                use std::io::Read;
                let path = base.join(rel);
                let f = match std::fs::File::open(&path) {
                    Ok(f) => f,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(fail(e.to_string())),
                };
                let mut data = Vec::new();
                f.take(limit + 1)
                    .read_to_end(&mut data)
                    .map_err(|e| fail(e.to_string()))?;
                if data.len() as u64 > limit {
                    return Err(fail(format!("larger than {limit} bytes")));
                }
                Ok(Some(data))
            }
        }
    }

    fn require(&self, rel: &str, limit: u64) -> Result<Vec<u8>, UpdateError> {
        self.get(rel, limit)?.ok_or_else(|| UpdateError::Missing {
            name: rel.to_owned(),
        })
    }
}

/// What an update did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateOutcome {
    pub bundle: String,
    /// Sequence installed before, if any.
    pub previous: Option<u64>,
    pub sequence: u64,
    /// Where the bundle is installed (give this to `--content`).
    pub installed: PathBuf,
    /// A new bundle was installed (false: already current).
    pub changed: bool,
    pub timestamp_version: u64,
    pub timestamp_expires: OffsetDateTime,
}

/// Validates the staged content beyond signatures and hashes (parse
/// databases, compile rules); supplied by the caller.
pub type Validator<'a> = &'a dyn Fn(&VerifiedBundle) -> Result<(), String>;

pub struct UpdateOptions<'a> {
    pub source: Source,
    /// Installed bundles live in `content_dir/<bundle name>`.
    pub content_dir: PathBuf,
    /// The content state (rollback and freshness records).
    pub state_path: PathBuf,
    pub keys: &'a TrustedKeys,
    pub allow_expired: bool,
    pub validate: Validator<'a>,
}

impl std::fmt::Debug for UpdateOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateOptions")
            .field("source", &self.source)
            .field("content_dir", &self.content_dir)
            .finish_non_exhaustive()
    }
}

/// Removes the staging directory unless disarmed.
struct Staging(Option<PathBuf>);

impl Drop for Staging {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

fn sha(data: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(data).into())
}

fn random_suffix() -> Result<String, UpdateError> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|e| UpdateError::Source(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn write_file(path: &Path, data: &[u8]) -> Result<(), UpdateError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io_err(dir))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_err(path))?;
    f.write_all(data).map_err(io_err(path))?;
    f.sync_all().map_err(io_err(path))
}

/// Finishes or undoes an interrupted swap: if the bundle directory is
/// missing but a previous copy was set aside, put it back; remove stale
/// staging directories.
fn recover(content_dir: &Path, name: &str) {
    let target = content_dir.join(name);
    let Ok(entries) = std::fs::read_dir(content_dir) else {
        return;
    };
    let mut old: Vec<PathBuf> = Vec::new();
    for e in entries.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.starts_with(&format!(".staging-{name}-")) {
            let _ = std::fs::remove_dir_all(e.path());
        } else if n.starts_with(&format!(".old-{name}-")) {
            old.push(e.path());
        }
    }
    if !target.exists()
        && let Some(latest) = old.iter().max().cloned()
        && std::fs::rename(&latest, &target).is_ok()
    {
        old.retain(|p| *p != latest);
    }
    for p in old {
        let _ = std::fs::remove_dir_all(p);
    }
}

/// Checks the source and installs a newer bundle if there is one.
pub fn update(opts: &UpdateOptions<'_>) -> Result<UpdateOutcome, UpdateError> {
    let now = OffsetDateTime::now_utc();
    let fetch = Fetcher::new(&opts.source);

    // 1. Freshness.
    let ts_data = fetch.require(TIMESTAMP_FILE, MAX_TIMESTAMP_BYTES)?;
    let ts_sig = fetch.require(&format!("{TIMESTAMP_FILE}.minisig"), MAX_SIGNATURE_BYTES)?;
    let ts_sig = String::from_utf8(ts_sig)
        .map_err(|_| UpdateError::Mismatch("timestamp signature is not text".into()))?;
    let mut state = ContentState::open(&opts.state_path)?;
    // Keys revoked by bundles accepted earlier stay revoked, whatever the
    // caller passed: this is how a leaked timestamp key is retired in favour
    // of a backup key without a software release.
    let mut keys = opts.keys.clone();
    for id in state.revoked_keys() {
        keys.revoke(id);
    }
    let verified_ts =
        freshness::verify_timestamp(&ts_data, &ts_sig, &keys, now, opts.allow_expired)?;
    let ts = &verified_ts.timestamp;
    state.check_timestamp(ts)?;
    let previous = state.record_for(&ts.bundle).map(|r| r.sequence);

    std::fs::create_dir_all(&opts.content_dir).map_err(io_err(&opts.content_dir))?;
    recover(&opts.content_dir, &ts.bundle);
    let target = opts.content_dir.join(&ts.bundle);
    let outcome = |changed: bool| UpdateOutcome {
        bundle: ts.bundle.clone(),
        previous,
        sequence: ts.sequence,
        installed: target.clone(),
        changed,
        timestamp_version: ts.version,
        timestamp_expires: ts.expires,
    };

    // Already current?
    if let Ok(installed) = std::fs::read(target.join(MANIFEST_FILE))
        && sha(&installed) == ts.manifest_sha256
    {
        state.record_timestamp(ts, now);
        state.save()?;
        return Ok(outcome(false));
    }

    // 2-3. Download into staging.
    let staging_path =
        opts.content_dir
            .join(format!(".staging-{}-{}", ts.bundle, random_suffix()?));
    std::fs::create_dir(&staging_path).map_err(io_err(&staging_path))?;
    let staging = Staging(Some(staging_path.clone()));

    let manifest_data = fetch.require(MANIFEST_FILE, MAX_MANIFEST_BYTES)?;
    if manifest_data.len() as u64 != ts.manifest_size || sha(&manifest_data) != ts.manifest_sha256 {
        return Err(UpdateError::Mismatch(
            "manifest.json differs from the one the timestamp names".into(),
        ));
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_data)
        .map_err(|e| UpdateError::Mismatch(format!("manifest.json: {e}")))?;
    manifest.validate()?;
    if manifest.name != ts.bundle || manifest.sequence != ts.sequence {
        return Err(UpdateError::Mismatch(
            "manifest name or sequence differs from the timestamp".into(),
        ));
    }
    write_file(&staging_path.join(MANIFEST_FILE), &manifest_data)?;
    let first_sig = format!("{MANIFEST_FILE}.minisig");
    write_file(
        &staging_path.join(&first_sig),
        &fetch.require(&first_sig, MAX_SIGNATURE_BYTES)?,
    )?;
    for n in 2..=MAX_SIGNATURES {
        let name = format!("{MANIFEST_FILE}.minisig.{n}");
        match fetch.get(&name, MAX_SIGNATURE_BYTES)? {
            Some(sig) => write_file(&staging_path.join(&name), &sig)?,
            None => break,
        }
    }
    for f in &manifest.files {
        let data = fetch.require(&f.path, f.size)?;
        if data.len() as u64 != f.size || sha(&data) != f.sha256 {
            return Err(UpdateError::Mismatch(format!(
                "{} differs from its manifest entry",
                f.path
            )));
        }
        write_file(&staging_path.join(&f.path), &data)?;
    }

    // 4. Verify exactly as a scan would, then rollback, then content.
    let verified = bundle::load_bundle(
        &staging_path,
        &keys,
        LoadOptions {
            allow_expired: opts.allow_expired,
            now,
        },
    )?;
    state.check(&verified, keys.min_sequence(&verified.manifest.name))?;
    (opts.validate)(&verified).map_err(UpdateError::Invalid)?;

    // 5. Swap into place.
    let old = opts
        .content_dir
        .join(format!(".old-{}-{}", ts.bundle, random_suffix()?));
    let had_old = target.exists();
    if had_old {
        std::fs::rename(&target, &old).map_err(io_err(&target))?;
    }
    if let Err(e) = std::fs::rename(&staging_path, &target) {
        if had_old {
            let _ = std::fs::rename(&old, &target);
        }
        return Err(io_err(&target)(e));
    }
    let mut staging = staging;
    staging.0 = None;
    state.record(&verified, now);
    state.record_timestamp(ts, now);
    state.save()?;
    if had_old {
        let _ = std::fs::remove_dir_all(&old);
    }
    Ok(outcome(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources() {
        assert_eq!(
            Source::parse("https://example.org/aw").unwrap_or(Source::Dir(PathBuf::new())),
            Source::Https("https://example.org/aw/".into())
        );
        assert!(Source::parse("http://example.org/").is_err());
        assert!(Source::parse("ftp://x/").is_err());
        assert_eq!(
            Source::parse("/srv/mirror").ok(),
            Some(Source::Dir(PathBuf::from("/srv/mirror")))
        );
        assert_eq!(url_path("rules/eset x.yar"), "rules/eset%20x.yar");
    }
}
