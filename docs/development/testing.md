# Testing strategy

Tests are part of each change, not a later phase. Detection-quality
evaluation is a separate discipline: see
[detection/testing.md](../detection/testing.md).

## Layers

| Layer | Location | Covers |
|---|---|---|
| Unit | `#[cfg(test)]` modules in each crate | Digest parsing and serde, `ObservedPath` (non-UTF-8), config validation, finding serialisation, hashing vectors, size limits, symlink refusal, signature DB validation (every rejection rule), detector output, CLI size parsing, terminal sanitisation |
| Integration | `crates/engine/tests/scan.rs` | End-to-end scans of synthetic trees: nested directories, detection, JSON round trip, excludes, depth and size limits, missing roots, nested root de-duplication, cancellation (before start and mid-scan), progress events, recording limits, detector error and panic isolation; Unix: symlink skip/follow/loops, unreadable directories and files, FIFOs, hostile non-UTF-8 names |
| Engine: content and time limits | `crates/engine/tests/scan.rs`, `fsio.rs`, `trust.rs` | Content shared with detectors and bounded; no buffering when unneeded; `content_not_inspected` reporting; per-file deadline stops remaining detectors; read deadline; minisign verification (trusted, tampered, wrong key, unsigned, garbage, oversize) |
| YARA | `crates/yara/tests/yara.rs` | Detection end-to-end, metadata semantics, every rejection rule (include, syntax, invalid/unknown `aw_*`, bidi names, excluded modules, bad namespace), slow patterns, module availability, content limit, timeout on a pathological rule |
| Remediation | `crates/remediation/src/**` | Quarantine/restore round trip, inert storage, hash mismatch leaves file untouched, symlinks in any component, hard links, special files, protected paths, `..`, store paths; restore refusals (exists, world-writable, missing dir), setuid stripping, delete, **crash at each journal step + recovery**, store locking and permissions, audit-log tampering, permission-denied rollback, non-UTF-8 names; policy and ID parsing |
| CLI black-box | `crates/cli/tests/cli.rs` | Exit codes 0/1/2/3, JSON output, `--output`, invalid/unsigned/tampered/untrusted content, YARA scan and validate, `scan --quarantine` round trip, eligibility policy, manual add/delete with `--yes`, protected paths, ID traversal, terminal-escape injection via file names |
| Fuzzing | `fuzz/` | `signature-db`, `digest-parse`, `yara-scan` (YARA-X with all enabled format modules), `audit-log` |

Current count: 117 tests (as of 2026-09-24): core 13, engine 24 unit + 25 integration, YARA 9, remediation 20, CLI 7 unit + 19 black-box.

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
* No test for a read blocked in the kernel (the per-file limit cannot
  interrupt it).
* Quarantine tests run only on Linux; the store is unsupported elsewhere.
* Remediation tests run as an unprivileged user. Root-only behaviour
  (restoring ownership) is untested.
* No performance regression tests.
