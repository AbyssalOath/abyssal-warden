//! Windows security primitives for Abyssal Warden.
//!
//! This is the **only** crate in the workspace allowed to contain `unsafe`
//! code, and only in its Windows module
//! (docs/architecture/decisions/0019-windows-unsafe-boundary.md). Every
//! `unsafe` block holds one operation and states why it is sound. The API
//! is safe; callers stay `forbid(unsafe_code)`.
//!
//! * [`sddl`]: parsing and analysing security descriptors (all platforms,
//!   pure, tested everywhere).
//! * `windows`: DACLs, token identity, named pipes with client
//!   identification, delete-by-handle, final paths, processes, Event Log.

#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]

pub mod sddl;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

/// Windows service registration and dispatch.
#[cfg(windows)]
#[allow(unsafe_code)]
pub mod scm;

#[cfg(windows)]
pub use windows::{
    ClientIdentity, Disconnector, PipeConnection, PipeListener, ProcessInfo, delete_by_handle,
    final_path, pipe_owner_sid, process_is_admin, process_user_sid, processes, report_event,
    security_descriptor, set_protected_dacl, terminate_if_image,
};
