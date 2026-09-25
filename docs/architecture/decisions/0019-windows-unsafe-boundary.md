# ADR-0019: Windows parity and the `unsafe` boundary

* **Status:** Accepted (applies rule 3 of crate-boundaries.md)
* **Date:** 2026-09-25

## Context

Phase 8 (Windows parity) needs Win32 security APIs that have no safe
equivalent in `std` or a vetted crate: protected DACLs, pipe security
descriptors, client identity by impersonation, pipe owner checks, delete by
handle, final paths, process termination and the Event Log. Each is an
`unsafe` FFI call. The workspace forbids `unsafe`; the documented exception
path is a crate-local exception with an ADR.

## Decision

1. **`warden-winsec` is the only crate that may contain `unsafe`, and only
   in its Windows modules.** It does not inherit the workspace lints; it
   sets `deny(unsafe_code)` with `allow` on the two Windows modules, and
   Clippy's `undocumented_unsafe_blocks` and
   `multiple_unsafe_ops_per_block` are errors. Every block performs one
   operation and states why it is sound. Handles and system allocations are
   owned by RAII types immediately. On other platforms the crate is
   `forbid(unsafe_code)`. Everything else stays `forbid`.
2. **Security-descriptor analysis is pure** (`sddl.rs`) and tested on every
   platform: parsing, "who else can write", private-directory checks.
3. **Windows quarantine store** with the Linux store's guarantees:
   protected DACL verified on every open; files opened with
   `FILE_FLAG_OPEN_REPARSE_POINT` and their final path compared with the
   request (no junction or link anywhere); the original pinned by opening it
   with `DELETE` access and read-only sharing, then deleted through that
   handle; restore through a temporary file and `CreateHardLink` (no
   overwrite), refusing directories others can write; anchors in the
   Application event log; running programs terminated (not paused) with
   `kill_processes`.
4. **Service on Windows:** named pipe with an explicit descriptor (SYSTEM,
   Administrators full; authenticated users read/write data only, not
   instance creation), remote clients refused, first instance exclusive.
   Clients are identified from their token after the first read; the
   client connects at identification level and refuses pipes not owned by
   SYSTEM, Administrators or itself. SCM integration via `windows-service`
   (`--install`, `--uninstall`, `--service`). Non-administrator scans are
   refused (they run the CLI directly); children run as the service account
   (no identity drop yet).
5. **Locked files** are reported as `locked` issues.
6. **The endpoint is claimed before any state is touched**, on both
   platforms (a second instance previously marked running jobs as
   interrupted; regression test added).

## Consequences

* Windows gets quarantine, the service and IPC with the same trust
  boundaries, at the cost of about 500 lines of audited `unsafe`.
* The Windows code is type-checked and linted here and runs only in Windows
  CI; it has not been exercised on a real Windows machine by the
  maintainers.
* Remaining gaps: no restricted token for Windows scanner children, no
  pausing of running programs, event-log anchors can be forged (added) by
  any user, file owner and attributes are not restored.
