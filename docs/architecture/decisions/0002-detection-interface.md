# ADR-0002: Detection interface and finding model

* **Status:** Accepted; amended by [ADR-0006](0006-content-access-and-time-limits.md) (content access, per-worker state, time limits)
* **Date:** 2026-09-24

## Context

Detection will combine several independent methods: hashes, YARA, format
analysis, heuristics, and platform checks. Results must be explainable,
distinguish confirmed matches from suspicion, carry provenance (detector,
rule and database versions), and evolve without breaking consumers such as
the future service and GUI.

## Decision

1. **A synchronous, object-safe `Detector` trait** in `warden-core`:
   `info()` plus `inspect_file(&FileObservation) -> Result<Vec<Finding>, DetectorError>`.
   Detectors are `Send + Sync` and shared by all workers. The scanner owns
   file access; detectors never open files themselves. This keeps the
   hardened-open policy in one place and allows one read per file.
2. **Structured findings, not scores.** Each `Finding` has separate `kind`,
   `confidence`, `severity`, `category`, evidence list, explanation,
   `recommended_action` and `remediation_status`. There is no numeric
   aggregate verdict.
3. **Recommendation is not action.** `recommended_action` never triggers
   anything by itself. `RemediationStatus` gained `quarantined`,
   `not_eligible` and `failed` only once the quarantine subsystem existed
   (ADR-0008); detectors always emit `not_attempted`.
4. **Coverage is explicit.** Skips, issues, truncation and warnings are
   first-class report fields, so "no findings" can be told apart from "not
   checked".
5. **Compatibility contract is JSON.** `ScanReport.schema_version` (now 1)
   increments on breaking changes. Enums are `#[non_exhaustive]`; consumers
   must tolerate unknown fields and enum values.
6. **Paths are `ObservedPath`**: lossless for non-Unicode names via
   `raw_hex`, so hostile file names cannot break serialisation.
7. **Panics are isolated** per detector call with `catch_unwind`.

## Alternatives rejected

* **Async trait:** detection is CPU- and I/O-bound on local files. Threads
  with bounded channels are simpler and avoid an async runtime in the core.
  This can be revisited for the service's IPC layer, which is a separate
  concern.
* **Detectors opening files themselves:** this would repeat reads and scatter
  the symlink/FIFO hardening across detectors.
* **Single risk score:** it cannot explain itself, and it merges unrelated
  evidence.

## Consequences

* Content-based detectors need a content accessor on `FileObservation`,
  designed together with the YARA integration
  ([detection-pipeline.md](../detection-pipeline.md#content-access-per-worker-state-and-time-limits)).
* Non-file targets (processes, registry, services) need new `FindingTarget`
  variants and probably a separate `inspect_*` entry point. The current trait
  is file-scoped by design.
