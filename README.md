# Abyssal Warden

An open-source malware detection, rootkit detection, system integrity and
remediation platform for Windows and Linux, written in Rust.

> **Status: early development (0.1.0, unreleased).** Abyssal Warden is
> **not** a complete anti-malware product. It has no real-time protection,
> no rootkit detection, and no malware signatures or rules of its own, and it
> must not be relied on to protect a system. See
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
* **YARA rules** via [YARA-X](https://virustotal.github.io/yara-x/), with
  includes disabled, slow patterns rejected, explicit module list, per-file
  timeouts, and metadata that controls how matches are interpreted.
* **Signed content**: databases and rules must carry a valid minisign
  signature from a trusted key unless explicitly allowed otherwise.
* **Single, bounded read per file**, shared by all detectors, with a
  per-file time limit.
* **Quarantine, restore and delete** (Linux): symlink-safe, crash-safe
  (journaled, fault-injection tested), never overwrites on restore,
  hash-chained audit log. Automatic quarantine only for confirmed malware
  hash matches, and only when asked (`scan --quarantine`).
* No real malware signatures or rules are shipped; the repository contains
  only synthetic test content.
* **Structured results**: every finding carries a detection ID, kind,
  severity, confidence, category, file hash and metadata, detector/rule/
  database versions, evidence, explanation and recommended action. Reports
  are available as versioned JSON or as human-readable text.
* **CLI**: `abyssal-warden scan`, `hash`, `signatures validate`,
  `yara validate`, `quarantine add|list|show|restore|delete|verify-log`.

Every capability above has automated tests, including tests for hostile file
names, symlink escapes, FIFOs, permission errors and detector panics.

## Quick start

```sh
cargo build --release
mkdir -p /tmp/aw-demo
printf 'ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR\n' > /tmp/aw-demo/indicator.txt
printf 'ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER\n'    > /tmp/aw-demo/marker.txt
./target/release/abyssal-warden scan \
    --trusted-key examples/keys/synthetic-test.pub \
    --signatures examples/signatures/synthetic-test-indicators.json \
    --yara examples/rules /tmp/aw-demo
```

The example key is a **test key**; never trust it for real content.

`--format json` produces the machine-readable report. See
[docs/user/scanning.md](docs/user/scanning.md) for options and exit codes.

## Documentation

* [Documentation index](docs/README.md)
* [Architecture overview](docs/architecture/overview.md)
* [Threat model](docs/security/threat-model.md)
* [Development setup](docs/development/setup.md)
* [Security policy](SECURITY.md)

## Licence

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`); see
[LICENSE](LICENSE) and
[ADR-0004](docs/architecture/decisions/0004-project-license.md).
