# Changelog

## Unreleased (0.1.0)

### Added (milestone 2: YARA, signed content, quarantine)
- `warden-yara`: YARA-X rules with includes disabled, slow patterns rejected,
  explicit module list, `aw_*` metadata, per-file timeouts, and one scanner
  per worker.
- Content access for detectors: single bounded read per file shared by all
  detectors (`max_content_size`), `DetectorRequirements`, per-worker
  `DetectorWorker` state, per-file time limit (`file_timeout_ms`), new
  `content_not_inspected` skip and `timeout` issue kinds.
- minisign signature verification for databases and rules (`trust` module),
  `--trusted-key`/`--allow-unsigned`, signer recorded in reports.
- `warden-remediation` (Linux): quarantine/restore/delete, crash recovery,
  hash-chained audit log, automatic-remediation policy; `scan --quarantine`
  and `quarantine` subcommands; `RemediationStatus` gains `quarantined`,
  `not_eligible` and `failed`, plus `remediation_detail`.
- `yara validate` command; example YARA rule, test public key and signatures.
- Fuzz targets `yara-scan` and `audit-log`.
- Licence: AGPL-3.0-only.

### Changed
- Detection content now requires a trusted signature by default.

### Added (milestone 1: scanner foundation)
- Cargo workspace: `warden-core`, `warden-engine`, `warden-cli`.
- Scanner: recursive traversal, symlink policy, excludes, size/depth limits,
  same-filesystem option, bounded concurrency, cancellation, progress.
- Hardened file opening (no-follow, non-blocking, handle re-verification) and
  streaming SHA-256.
- Exact-hash signature database format v1 and detector.
- Structured findings and versioned JSON scan report (schema 1).
- CLI: `scan`, `hash`, `signatures validate`; sanitised human output.
- Tests, fuzz harnesses, CI workflow, cargo-deny policy, documentation.
