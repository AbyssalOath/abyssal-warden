# Abyssal Warden

An open-source malware detection, rootkit detection, system integrity and
remediation platform for Windows and Linux, written in Rust.

> **Status: early development (0.1.0, unreleased).** Abyssal Warden is
> **not** a complete anti-malware product. It has no real-time protection,
> only in-OS rootkit checks (which a kernel rootkit can defeat), and no
> malware signatures or rules of its own, and it must not be relied on to
> protect a system. See
> [Known limitations](docs/known-limitations.md) and [ROADMAP.md](ROADMAP.md).

## What works today

* **On-demand scanning engine**: recursive traversal, configurable roots and
  excludes, explicit symlink policy, file size/depth limits, bounded worker
  threads and memory, cancellation (Ctrl-C) and progress reporting.
* **Hardened file access**: files are opened without following links and
  without blocking on FIFOs, and their type and size are re-checked from the
  open handle. Scanned files are never executed or modified.
* **SHA-256 hashing** of every scanned file.
* **Exact-hash signature detection** against a versioned, validated JSON
  signature database format.
* **Heuristics** (`--heuristics`, opt-in): disguised executables, double
  extensions, packed or process-injecting PE files, unusual ELF files
  (writable code, UPX, unsafe library paths), malicious script patterns.
  Findings are explainable, never confirmed, and never quarantined
  automatically; clean-file hit rates are measured and published
  ([docs/detection/heuristics.md](docs/detection/heuristics.md)).
* **YARA rules** via [YARA-X](https://virustotal.github.io/yara-x/), with
  includes disabled, slow patterns rejected, explicit module list, per-file
  timeouts, and metadata that controls how matches are interpreted.
* **Signed content**: databases and rules must carry a valid minisign
  signature from a trusted key unless explicitly allowed otherwise. Signed
  **content bundles** add rollback, expiry and key-revocation protection.
* **Single, bounded read per file**, shared by all detectors, with a
  per-file time limit; a watchdog ensures no file can hang a scan.
* **ZIP archive scanning** (including JAR, APK, Office documents and nested
  archives): members are decompressed in memory and checked by every
  detector, with decompression-bomb limits.
* **Quarantine, restore and delete** (Linux): symlink-safe, crash-safe
  (journaled, fault-injection tested), never overwrites on restore,
  hash-chained audit log. Automatic quarantine only for confirmed malware
  hash matches, and only when asked (`scan --quarantine`).
* **Service** (Linux, `abyssal-wardend`): scheduled and on-request scans
  and system checks over an authenticated local socket, job history, and
  quarantine management for administrators. Scans run in separate processes
  with read-only privileges (or as the requesting user), and the quarantine
  audit log is checked against the system journal
  ([docs/user/service.md](docs/user/service.md)).
* **System check** (`system-check`): read-only inventory of persistence
  with documented rules for suspicious entries. Linux: systemd, cron, at,
  SysV init, generators, preload, shell profiles, autostart, SSH keys and
  rc, PAM, udev, module loading, motd, initramfs and GRUB hooks, eBPF
  programs; kernel module cross-view, taint, hidden-process,
  deleted-executable and self-injection checks; boot integrity; package
  verification with files hashed by Abyssal Warden; offline inspection of a
  mounted image (`--root`). Windows (live): Run keys, Winlogon,
  AppInit_DLLs, IFEO, services, scheduled tasks, Startup folders.
  See [docs/user/system-check.md](docs/user/system-check.md).
* No real malware signatures or rules are shipped; the repository contains
  only synthetic test content.
* **Structured results**: every finding carries a detection ID, kind,
  severity, confidence, category, file hash and metadata, detector/rule/
  database versions, evidence, explanation and recommended action. Reports
  are available as versioned JSON or as human-readable text.
* **CLI**: `abyssal-warden scan`, `hash`, `signatures validate`,
  `yara validate`, `quarantine add|list|show|restore|delete|verify-log`,
  `content manifest|verify`, `system-check`, `service ...`; daemon
  `abyssal-wardend`.

Every capability above has automated tests, including tests for hostile file
names, symlink escapes, FIFOs, permission errors and detector panics.

## Quick start

```sh
cargo build --release
mkdir -p /tmp/aw-demo
printf 'ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR\n' > /tmp/aw-demo/indicator.txt
printf 'ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER\n'    > /tmp/aw-demo/marker.txt
./target/release/abyssal-warden scan \
    --keyring examples/keys/keyring.json \
    --content examples/bundle /tmp/aw-demo
```

The example key is a **test key**; never trust it for real content.

`--format json` produces the machine-readable report. See
[docs/user/scanning.md](docs/user/scanning.md) for options and exit codes.

## Documentation

* [ARCHITECTURE.md](ARCHITECTURE.md): map of the codebase
* [Documentation index](docs/README.md)
* [Architecture overview](docs/architecture/overview.md)
* [Threat model](docs/security/threat-model.md)
* [Development setup](docs/development/setup.md)
* [Security policy](SECURITY.md)

## Licence

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`); see
[LICENSE](LICENSE) and
[ADR-0004](docs/architecture/decisions/0004-project-license.md).
