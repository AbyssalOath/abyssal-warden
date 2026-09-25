# Testing strategy

Tests are part of each change, not a later phase. Detection-quality
evaluation is a separate discipline: see
[detection/testing.md](../detection/testing.md).

## Layers

| Layer | Location | Covers |
|---|---|---|
| Unit | `#[cfg(test)]` modules in each crate | Digest parsing and serde, `ObservedPath` (non-UTF-8), config validation, finding serialisation, hashing vectors, size limits, symlink refusal, signature DB validation (every rejection rule), detector output, CLI size parsing, terminal sanitisation |
| Integration | `crates/engine/tests/scan.rs` | End-to-end scans of synthetic trees: nested directories, detection, JSON round trip, excludes, depth and size limits, missing roots, nested root de-duplication, cancellation (before start and mid-scan), progress events, recording limits, detector error and panic isolation; Unix: symlink skip/follow/loops, unreadable directories and files, FIFOs, hostile non-UTF-8 names |
| Remediation completeness | `crates/remediation/src/linux/tests.rs`, `anchor.rs`, `processes.rs`, `crates/cli/tests/cli.rs` | Allow-list add/remove/read-only access and audit; restored files reported `allowed`, not re-quarantined, exit 0, and a finding again after removal; audit anchors delivered to a syslog socket with the full hash and no paths, unreachable log is a warning; `/proc/<pid>/maps` parsing; a real running copy of `sleep` killed with `--kill-processes`, left running without it, and resumed when the quarantine fails. Tests never write to the real system log |
| Threshold, floors, revocation | `crates/engine/src/{trust,bundle,content_state}.rs`, `crates/cli/tests/cli.rs` | Threshold policy and strictest-wins merging; distinct-signer counting (duplicate and untrusted signatures don't count, revoked keys drop below threshold); per-file content refused under a threshold; keyring floor on fresh state; manifest revocations persisted, monotonic, applied to later bundles and individual files |
| Content trust | `crates/engine/src/{trust,bundle,content_state}.rs`, `crates/cli/tests/cli.rs` | Keyring parsing, revocation, validity windows, revocation overriding `--trusted-key`; bundle signature, same- and different-size tampering, unsigned/untrusted manifests, expiry and `--allow-expired`, paths escaping the bundle, manifest rules, unknown fields; rollback, equivocation, persistence across runs, corrupt state failing closed, state permissions; end-to-end CLI flow with `content manifest`, freshly signed bundles, `content verify` recording nothing |
| Archives | `crates/engine/src/archive.rs`, `crates/engine/tests/scan.rs`, `crates/yara/tests/yara.rs`, `crates/cli/tests/cli.rs` | Nested expansion; depth, entry-count and byte-budget (bomb) limits; large members hashed not kept; hostile member names; corrupt, truncated and unsupported-method archives; archive-too-large reporting; detection by content not extension; hash-only scans; YARA inside archives; JSON round trip of member targets; CLI rendering and flags; members never auto-quarantined |
| Engine: robustness | `crates/engine/tests/scan.rs`, `fsio.rs` | Stall watchdog abandons and replaces a stuck worker; every-worker-stalled stops with unscanned work reported; whole-scan time limit; duplicate files under `--follow-symlinks`; symlinked directory component refused (Linux); root-relative open refuses escapes and final links (the non-Linux and old-kernel path); no atime update on own files (Linux) |
| Engine: content and time limits | `crates/engine/tests/scan.rs`, `fsio.rs`, `trust.rs` | Content shared with detectors and bounded; no buffering when unneeded; `content_not_inspected` reporting; per-file deadline stops remaining detectors; read deadline; minisign verification (trusted, tampered, wrong key, unsigned, garbage, oversize) |
| YARA | `crates/yara/tests/yara.rs` | Detection end-to-end, metadata semantics, every rejection rule (include, syntax, invalid/unknown `aw_*`, bidi names, excluded modules, bad namespace), slow patterns, module availability, content limit, timeout on a pathological rule |
| Remediation | `crates/remediation/src/**` | Quarantine/restore round trip, inert storage, hash mismatch leaves file untouched, symlinks in any component, hard links, special files, protected paths, `..`, store paths; restore refusals (exists, world-writable, missing dir), setuid stripping, delete, **crash at each journal step + recovery**, store locking and permissions, audit-log tampering, permission-denied rollback, non-UTF-8 names; policy and ID parsing |
| System checks | `crates/system/src/**`, `crates/system/tests/fake_root.rs`, `crates/cli/tests/cli.rs` | Every configuration parser; command patterns (positive and negative); root confinement of absolute and `..` links; hidden-PID confirmation; taint decoding; `rpm -V`/`dpkg --verify` parsing; tool timeout; fake roots with planted persistence and a benign tree with no heuristic findings; correlation with a signed hash database; environment values never reported; sanitised output. Never modifies the real system |
| Heuristics | `crates/heuristics/src/**`, `crates/heuristics/tests/synthetic.rs`, `crates/cli/tests/cli.rs` | Every rule against minimal hand-built ELF and PE files (no malware) with exactly the property it looks for, plus clean baselines; names, scripts and locations; this machine's own binaries stay clean; arbitrary bytes never panic; CLI opt-in, evidence, review-only and never quarantined. Clean-corpus measurement with `examples/corpus_eval.rs` |
| Service and IPC | `crates/ipc/src/**`, `crates/service/src/**`, `crates/cli/tests/service.rs` | Framing and size limits, unknown operations and fields, validation, the full authorisation matrix; configuration validation (and the packaged example); admin decision from passwd/group; schedule arithmetic; child arguments (paths after `--`, never `--quarantine`); `setpriv` arguments; timeouts and cancellation killing the process group; **privilege drop verified in a user namespace** (read-only access with `CAP_DAC_READ_SEARCH`, nothing without it); journal anchor parsing; a running daemon: admin scan with signed content and heuristics, non-admin denials and scans as the caller, hostile frames, single instance, cancellation, history across restarts |
| CLI black-box | `crates/cli/tests/cli.rs` | Exit codes 0/1/2/3, JSON output, `--output`, invalid/unsigned/tampered/untrusted content, YARA scan and validate, `scan --quarantine` round trip, eligibility policy, manual add/delete with `--yes`, protected paths, ID traversal, terminal-escape injection via file names |
| Fuzzing | `fuzz/` | `signature-db`, `digest-parse`, `yara-scan` (YARA-X with all enabled format modules), `audit-log`, `archive-expand` (ZIP parser and decompressors), `system-parsers` (every system-check configuration parser and command pattern), `heuristics` (PE, ELF, script and name analysis on arbitrary files), `ipc-decode` (service request decoding, validation and authorisation) |

Current count on Linux: 278 tests (as of 2026-09-25): core 13, engine 60 unit + 36 integration, YARA 10, heuristics 7 unit + 7 synthetic, remediation 31, system 43 unit + 7 integration, IPC 5, service 10, CLI 7 unit + 38 black-box + 4 service black-box. Windows CI additionally runs 2 live system-check tests and 1 CLI test.

## Rules

* **No real malware in tests or the repository.** Use synthetic fixtures
  generated inside the test (see `INDICATOR` in the integration tests).
* Tests must not need elevated privileges. Tests that depend on privilege
  (e.g. "unreadable file") detect when they run as root and skip their
  assertion with a message, instead of failing.
* Platform-specific tests are `cfg`-gated and must have equivalents on the
  other platform, or an entry in the gap list below.
* Every new parser of untrusted input gets a fuzz target in the same change.
* Every new rejection rule in a parser gets a unit test that the rule
  rejects.

## Fuzzing

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz run signature-db -- -max_total_time=300
cargo +nightly fuzz run digest-parse -- -max_total_time=300
cargo +nightly fuzz run yara-scan -- -max_total_time=600 -max_len=262144
cargo +nightly fuzz run audit-log -- -max_total_time=300
cargo +nightly fuzz run archive-expand -- -max_total_time=600 -max_len=1048576
cargo +nightly fuzz run system-parsers -- -max_total_time=600 -max_len=16384
cargo +nightly fuzz run heuristics -- -max_total_time=600 -max_len=1048576
cargo +nightly fuzz run ipc-decode -- -max_total_time=600 -max_len=65536
```

CI only checks that the harnesses compile. Fuzzing campaigns are run
manually for now; scheduled fuzzing (e.g. a nightly workflow or OSS-Fuzz) is
on the roadmap. Crashes go into `fuzz/artifacts/`. Minimise them and add a
regression unit test.

## Known gaps

* Windows-specific integration tests (junctions, ACL-denied files, locked
  files, reparse points).
* Very large files (> 4 GiB) are covered only by the size-limit logic, not
  by an end-to-end test.
* A read blocked in the kernel is simulated with a detector that sleeps
  past its deadline (same watchdog path); no test uses a real hung
  filesystem.
* Quarantine tests run only on Linux; the store is unsupported elsewhere.
* Remediation tests run as an unprivileged user. Root-only behaviour
  (restoring ownership) is untested.
* No performance regression tests.
