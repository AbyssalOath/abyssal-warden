# Changelog

## Unreleased (0.1.0)

### Added (known limitations, phase 7: service, IPC, privilege separation)
- `abyssal-wardend` (Linux) and `abyssal-warden service ...` (ADR-0018):
  Unix-socket IPC with `SO_PEERCRED`, a versioned, size-limited protocol
  (`warden-ipc`) and an authorisation matrix; jobs, queue, history,
  schedules, reports; quarantine list/restore/delete over IPC.
- Scans and system checks run in killable child processes through
  `setpriv`: the scanner account with only `CAP_DAC_READ_SEARCH` (and
  `CAP_SYS_PTRACE` for system checks), or the requesting user without
  capabilities.
- Automatic comparison of the quarantine audit chain with journal anchors;
  anchors carry a chain identifier; audit entries record `on_behalf_of`.
- Hardened systemd unit, sysusers file and example configuration in
  `packaging/linux/`.
- `system-check` treats `CAP_DAC_READ_SEARCH`/`CAP_SYS_PTRACE` as full
  coverage, not only root.
- Fuzz target `ipc-decode`.

### Changed
- Report remediation (allow-list, automatic quarantine) moved into
  `warden-remediation`, shared by the CLI and the service.

### Added (known limitations, phase 6: heuristics)
- `warden-heuristics` crate and `scan --heuristics` / `system-check
  --heuristics` (ADR-0017): file-name (disguised executables, double
  extensions, bidi), PE (RWX sections, entry outside code, packers, packed
  code, injection imports, embedded executables, malformed headers), ELF
  (RWX segments, executable stack, UPX, no sections, unsafe RPATH, entry
  outside code, unusual interpreter), script and location rules
  AW-HEU-001 to AW-HEU-099, with evidence and measured clean hit rates.
- Command patterns shared between script heuristics and system checks.
- `corpus_eval` example for measuring hit rates; fuzz target `heuristics`.

### Added (phase 5 follow-up: coverage, package trust, Windows)
- Linux inventory: SysV init scripts, `at` jobs, systemd generators,
  `modules-load.d` and `modprobe.d` install/remove commands, motd scripts,
  SSH rc files, initramfs hooks, GRUB scripts, loaded eBPF programs.
- Boot integrity check: Secure Boot, lockdown, module signature
  enforcement, running and configured kernel command lines, `/boot`
  permissions (AW-SYS-027 to 029).
- Scanner self-integrity check for injected libraries (AW-SYS-019).
- Package verification now hashes files itself; dpkg database read natively
  (no dpkg program); rpm only queried for recorded digests (ADR-0016).
- Windows `system-check` for the live system: Run keys, Winlogon,
  AppInit_DLLs, IFEO, services, scheduled tasks, Startup folders
  (AW-SYS-020 to 025); Windows command patterns (PowerShell cradles,
  encoded commands, LOLBins).

### Added (known limitations, phase 5: Linux persistence and integrity)
- `warden-system` crate and `system-check` command (ADR-0015): read-only
  inventory of systemd units/timers, cron/anacron, `ld.so.preload`, shell
  startup and environment files, XDG autostart, SSH `authorized_keys`, PAM,
  `rc.local` and udev rules.
- Rules `AW-SYS-001` to `AW-SYS-018` (download-and-run, reverse shells,
  encoded payloads, preload injection, temp/hidden programs, writable
  root-run programs, PAM backdoors, and more), documented in
  docs/detection/system-checks.md.
- Kernel module cross-view, taint flags, hidden-PID sweep, deleted
  executables in writable locations (including memfd), and rpm/dpkg
  verification of critical and referenced files (`--verify-all-packages`).
- Offline inspection with `--root`, reads confined with
  `openat2(RESOLVE_IN_ROOT)`.
- Programs that persistence entries start can be scanned with detection
  content, and detections are linked to the entry (`AW-SYS-016`).
- Fuzz target `system-parsers`.
- `SystemReport` JSON schema v1; `FindingTarget` variants `persistence`,
  `process` and `system`; new evidence kinds.

### Added (known limitations, phase 4: remediation completeness)
- Allow-list of restored contents (exact SHA-256): restores add to it,
  scans mark matches `allowed` (still reported, not auto-quarantined, not
  exit 1); `quarantine allowlist list|remove`, `--no-allow`, `--no-allowlist`.
- Audit log anchored in syslog/journald (`authpriv`, tag `abyssal-warden`);
  `verify-log` prints the head to compare; `ABYSSAL_WARDEN_SYSLOG_SOCKET`.
- Processes running a quarantined file are listed; `--kill-processes`
  pauses them before the move, kills them after, resumes on failure.
- `remediation_status: allowed` (ADR-0014).

### Added (known limitations, phase 3: content trust)
- Signed content bundles (`--content DIR`): a minisign-signed manifest pins
  every file by size and SHA-256 and carries name, sequence, issued and
  expires (ADR-0012).
- Rollback and equivocation protection (local state, `--content-state`);
  expiry (freeze) protection with explicit `--allow-expired`; 7-day expiry
  warning.
- Keyrings (`--keyring`, system keyring) with revocation and validity
  windows, also applied to `--trusted-key`.
- `content manifest` and `content verify` commands; `content_bundles` in the
  report; warning for individually signed content.
- Project signing-key procedure (docs/security/content-trust.md).
- Threshold signatures (`policy.threshold`, `manifest.json.minisig.2`...),
  keyring sequence floors for fresh installations, and revocations carried
  by manifests (`revoke_keys`, `content manifest --revoke-key`) (ADR-0013).

### Changed
- Example content re-signed with a new throwaway test key
  (`70EF691BC71E4DD9`); example bundle and keyring added.

### Added (known limitations, phase 2: archive scanning)
- ZIP archive scanning (including JAR, APK, Office documents and
  self-extracting executables): members decompressed in memory and
  evaluated by every detector; nested archives expanded (ADR-0011).
- Decompression-bomb and exhaustion limits (`ArchiveLimits`; CLI
  `--no-archives`, `--archive-max-depth`, `--archive-max-total`).
- Report: `archive_member` finding target; `member` chain on skips and
  issues; skip reasons `archive_too_large`, `archive_limit_reached`,
  `archive_member_encrypted`, `archive_member_unsupported`; issue kind
  `archive_error`; `stats.archive_members_scanned`.
- Findings inside archives are never quarantined automatically.
- Fuzz target `archive-expand`.

### Added (known limitations, phase 1: scan robustness)
- Stall watchdog: a worker stuck on one file (blocked read, runaway
  detector) past its per-file limit plus 2 s is abandoned and replaced, and
  the file is reported; scans always finish. Queued work that was never
  scanned is reported, never counted as completed.
- Whole-scan time limit (`--scan-timeout`, `scan_timeout_ms`); new status
  `time_limit_reached`.
- Linux: files opened with `openat2(RESOLVE_NO_SYMLINKS)` (no link followed in
  any path component) and `O_NOATIME` where permitted.
- `--follow-symlinks`: files reached through several paths are scanned once
  (`duplicate_file` skip; Unix).
- MSRV 1.93 declared (`rust-version`) and checked by a CI job; CI tests run
  with `--no-fail-fast`.

- Root-relative opens (`cap-std`) on Windows, other platforms and Linux < 5.6:
  under the default policy a scan cannot read outside its roots on any
  platform (ADR-0010).
- Windows de-duplication under `--follow-symlinks` (volume serial number and
  file index).
- Toolchain pinned in `rust-toolchain.toml` (1.98.0); the MSRV job forces
  1.93 with `cargo +1.93.0`.

### Changed
- Scan threads are detached rather than scoped (ADR-0009); detectors are
  shared as `Arc<dyn Detector>`.

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
