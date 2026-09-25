# Roadmap

Commercial-scale coverage is a direction, not a promise. Each capability ships
only when it is implemented, tested and documented, including its
limitations. Detection quality claims require the evaluation methodology in
[docs/detection/testing.md](docs/detection/testing.md).

Status legend: **done** (implemented and tested) · **next** (active
milestone) · **planned** (designed or scoped) · **research** (needs
investigation before design).

## 1. Scanner foundation: done (0.1.0)

* done: workspace, core data model, versioned JSON report
* done: traversal with symlink policy, excludes, depth/size limits, same-filesystem option
* done: hardened open (no-follow, non-blocking, handle re-verification)
* done: SHA-256, bounded concurrency and memory, cancellation, progress
* done: CLI with human and JSON output, sanitised terminal output
* done: unit, integration and CLI tests; parser fuzz harnesses
* done: per-file time limit (cooperative)
* planned: whole-scan time budget; watchdog for reads blocked in the kernel
* planned: MSRV policy verified in CI

## 2. Signature and rule engine: mostly done

* done: exact SHA-256 database format v1 with strict validation
* done: minisign-signed databases and rules, verified before parsing ([ADR-0007](docs/architecture/decisions/0007-content-signing.md))
* done: YARA-X in `warden-yara` ([yara.md](docs/detection/yara.md))
* done: single bounded read per file shared by detectors; per-worker detector state ([ADR-0006](docs/architecture/decisions/0006-content-access-and-time-limits.md))
* next: archive scanning with extraction limits (ZIP first) and bomb protection
* planned: rollback/freeze protection and key management (with the updater)
* planned: PE and ELF parsing for metadata and heuristics
* research: pattern/family signature format

## 3. Quarantine and remediation: done on Linux

* done: store, restore, delete, hash-chained audit log, journaled crash recovery ([quarantine.md](docs/security/quarantine.md))
* done: automatic policy (confirmed malware hash matches only, never system directories)
* planned: Windows store (DACL-hardened, by-handle operations)
* planned: external anchoring of the audit log; allow-list for restored files
* planned: process termination and persistence cleanup (needs platform integrations)

## 4. Background service: planned

* planned: `warden-service` with scheduled scans and persistent state
* planned: authenticated local IPC ([privilege model](docs/security/privilege-model.md))
* planned: systemd unit/timer and Windows SCM integration

## 5. Windows security integrations: research

* PE analysis, Authenticode verification
* persistence enumeration: Run keys, services, scheduled tasks, WMI subscriptions
* AMSI provider, ETW telemetry, minifilter-based on-access scanning ([platform notes](docs/platform/windows.md))

## 6. Linux security integrations: research

* ELF analysis, package integrity (rpm/dpkg) checks
* persistence enumeration: systemd, cron, `ld.so.preload`, shell profiles, PAM, SSH keys
* fanotify-based on-access scanning; eBPF telemetry ([platform notes](docs/platform/linux.md))

## 7. Rootkit and persistence detection: research

* cross-view detection (e.g. `/proc` vs. other enumeration sources)
* kernel module inventory and verification
* limitations of in-OS detection documented; offline scan as the mitigation

## 8. Real-time protection: research

Depends on milestones 4-6. Requires platform-supported mechanisms
(minifilter drivers on Windows, fanotify permission events on Linux), not a
directory watcher.

## 9. Offline scanning: research

Scanning a mounted, non-running system image or disk from trusted boot media.

## 10. GUI: planned

egui is the provisional choice ([evaluation](docs/architecture/gui.md)).
Unprivileged, and talks only to the service over authenticated IPC.

## 11. Testing and release hardening: ongoing

* done: CI gates for fmt, clippy, tests (Linux and Windows), rustdoc and cargo-deny
* planned: scheduled fuzzing campaigns and a corpus in CI
* planned: reproducible builds, signed release artifacts, SBOM
* planned: detection evaluation harness with published methodology
