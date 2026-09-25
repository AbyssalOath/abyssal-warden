# ADR-0016: Package trust, scanner self-integrity, Windows persistence

* **Status:** Accepted (extends ADR-0015)
* **Date:** 2026-09-25

## Context

After ADR-0015, the open gaps were:

* Package verification trusted the host's `rpm`/`dpkg` both to read the
  database **and** to read the files.
* A user-mode rootkit that hides `/etc/ld.so.preload` from `read()` would
  go unnoticed.
* Several Linux persistence locations and all boot-chain settings were not
  inspected, and there were no Windows checks.
* Unprivileged runs have limited coverage.

## Decision

1. **Hash files ourselves.** Package verification reads each file through
   the root-confined reader and hashes it (MD5, SHA-2 family). dpkg's
   `*.list` and `*.md5sums` are plain text and are parsed natively, so no
   dpkg program runs. rpm's database (SQLite of binary headers) would need
   a SQLite engine and a header parser; instead `rpm -q --qf` is asked only
   for the recorded digests, with the same process hardening as before.
   Rejected: bundling SQLite (C code, large attack surface) or a partial
   pure-Rust SQLite reader (immature). Remaining trust: the database
   contents, and rpm's reading of them.
2. **Self-integrity cross-view.** The scanner lists the shared objects
   mapped into its own process (`/proc/self/maps`) and compares them with
   the few it links (glibc, libgcc). Any other object, including `memfd`
   mappings, is reported (AW-SYS-019). This catches preload rootkits even
   when their configuration is hidden, because the dynamic loader must map
   them. A rootkit that also filters `/proc/self/maps` defeats it, which
   needs kernel-level control.
3. **More Linux locations and boot checks**: SysV init, `at`, generators,
   module loading and `modprobe.d` commands, motd, SSH rc, initramfs hooks,
   GRUB scripts, eBPF programs (inventory only; `bpftool` when available as
   root, otherwise `/proc/*/fdinfo`), Secure Boot, lockdown, signature
   enforcement, running and configured kernel command lines, and `/boot`
   permissions. ELF files are never searched as text, since binaries contain
   command strings they do not run.
4. **Windows, live system first.** Registry values are read with the
   `winreg` crate (safe API, MIT, no `unsafe` in our code); task XML and
   Startup-folder scripts are parsed with small bounded parsers. All rule
   logic lives in a platform-neutral module and is unit-tested on Linux.
   Only registry and directory reading is Windows-specific; it is linted
   for the Windows target and exercised by tests in Windows CI. Offline
   Windows images (`--root`) are refused until a hive parser is chosen.
   Checks that do not exist yet (WMI subscriptions, drivers, hidden
   processes, Authenticode) are listed as `unsupported`, so the exit status
   never claims full coverage.
5. **Unprivileged runs stay partial.** Reading other users' files and
   processes is exactly what the OS forbids; working around it would be a
   privilege escalation. Coverage comes from running as root now and from
   the privileged service later (Phase 7). Checks keep reporting `partial`.

## Consequences

* A trojaned `rpm`/`dpkg`, or one hooked by a user-mode rootkit, can no
  longer hide a modified file from package verification, and Debian-family
  images can be verified from any host.
* Preload-style rootkits are visible from inside the process they infect.
* Windows gets persistence coverage for the most abused locations, with
  explicitly incomplete coverage elsewhere.
* New dependencies: `md-5` (MIT/Apache-2.0), `winreg` (MIT, Windows only),
  `serde_json` in `warden-system`.
