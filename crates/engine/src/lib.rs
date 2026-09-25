//! Abyssal Warden scan engine.
//!
//! * [`Scanner`] walks the configured roots, opens and hashes regular files
//!   with bounded resources, runs every configured [`Detector`] on each file,
//!   and assembles a [`ScanReport`].
//! * [`signatures`] provides the exact-hash signature database and the
//!   detector that evaluates it.
//! * [`hash_file`] is the same hardened open-and-hash routine the scanner
//!   uses, exposed for tools that hash individual files.
//!
//! The engine never modifies, executes or deletes scanned files.
//!
//! [`Detector`]: warden_core::Detector
//! [`ScanReport`]: warden_core::ScanReport

mod archive;
pub mod bundle;
pub mod content_state;
mod fsio;
mod scanner;
pub mod signatures;
pub mod trust;

pub use fsio::{HashFileError, HashedFile, hash_file};
pub use scanner::{ProgressEvent, ScanError, Scanner};

/// Fuzzing entry point: expand `data` as an archive with default limits and
/// return the number of members produced. Not a stable API.
#[doc(hidden)]
pub fn fuzz_expand_archive(data: &[u8]) -> usize {
    let limits = warden_core::ArchiveLimits::default();
    let cancel = warden_core::CancellationToken::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut members = 0;
    let _ = archive::Expander::new(&limits, u64::MAX, deadline, &cancel).expand_file(
        data,
        &mut |event| {
            if matches!(event, archive::Event::Member { .. }) {
                members += 1;
            }
        },
    );
    members
}

/// Name reported in [`warden_core::EngineInfo`].
pub const ENGINE_NAME: &str = "abyssal-warden-engine";
/// Engine version reported in scan reports and detection sources.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
