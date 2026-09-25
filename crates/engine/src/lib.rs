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

mod fsio;
mod scanner;
pub mod signatures;
pub mod trust;

pub use fsio::{HashFileError, HashedFile, hash_file};
pub use scanner::{ProgressEvent, ScanError, Scanner};

/// Name reported in [`warden_core::EngineInfo`].
pub const ENGINE_NAME: &str = "abyssal-warden-engine";
/// Engine version reported in scan reports and detection sources.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
