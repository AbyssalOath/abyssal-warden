# ADR-0010: Root-relative file opens (cap-std) and cross-platform file IDs

* **Status:** Accepted
* **Date:** 2026-09-25

## Context

On Linux ≥ 5.6, scanned files are opened with `openat2(RESOLVE_NO_SYMLINKS)`,
so a directory swapped for a link mid-scan is refused. Elsewhere only the
final path component was protected (`O_NOFOLLOW`,
`FILE_FLAG_OPEN_REPARSE_POINT`): on Windows, and on Linux kernels without
`openat2`, a swapped *directory* could redirect a read outside the scan
roots. Also, `--follow-symlinks` de-duplication used Unix device/inode
numbers and did nothing on Windows.

## Options

| Option | Result |
|---|---|
| Our own FFI to `NtCreateFile` with a root handle | `unsafe` in our code (forbidden workspace-wide), Windows-internal API |
| Re-check the final path with `GetFinalPathNameByHandleW` | FFI again; comparing paths is fragile (8.3 names, case, prefixes) |
| **`cap-std`** (Bytecode Alliance; used by wasmtime) | Opens relative to a directory handle, resolving one component at a time and refusing anything that leaves the directory; `openat2(RESOLVE_BENEATH)` on Linux, manual resolution elsewhere |

For file IDs on Windows: `cap-fs-ext`'s cross-platform `dev()`/`ino()` needs
an unstable std feature. **`winapi-util`** (already in the tree through
walkdir) exposes `GetFileInformationByHandle` safely.

## Decision

* Each scan root (or, for a single-file root, its directory) is held open as
  a `ScanBase` (`cap_std::fs::Dir`) under the default `skip` policy.
* Windows and other non-Linux platforms: files are opened with
  `Dir::open_with(relative_path)`, final component never followed.
* Linux: `openat2(RESOLVE_NO_SYMLINKS)` stays primary (stricter: no links at
  all). On `ENOSYS` (kernel < 5.6) the root-relative open replaces the old
  `O_NOFOLLOW` fallback.
* cap-std's escape refusal (`PermissionDenied`, "a path led outside of the
  filesystem") is reported as a `symlink_not_followed` skip. It has no
  distinct error type, so it is recognised by message; if the message ever
  changes, the refusal still happens but shows up as an I/O issue instead.
* Windows de-duplication uses `winapi_util::file::information` (volume serial
  number and file index from the open handle).

## Consequences

* **Security property on all platforms: under the default policy a scan cannot
  read outside its roots**, even if directories are swapped during the scan.
* On the root-relative path, links that stay *inside* the root are resolved
  (cap-std sandbox semantics), so a swapped link can redirect a read to
  another file in the same root. That file is in scope anyway.
* About 11 more crates (cap-std, cap-primitives, cap-fs-ext, io-lifetimes,
  io-extras, fs-set-times, ambient-authority, maybe-owned, ipnet, winx;
  winapi-util was already present), licensed Apache-2.0 / MIT /
  Apache-2.0 WITH LLVM-exception.
* The Windows path is compiled and linted in CI but, like the rest of the
  Windows code, only runs in the Windows CI job.
