# ADR-0005: YARA engine

* **Status:** Accepted
* **Date:** 2026-09-24

## Context

The pattern-based detection layer needs YARA-compatible rules, and the
engine must safely scan untrusted content. The candidates were evaluated in
[docs/detection/yara.md](../../detection/yara.md#engine-choice): YARA-X,
libyara via FFI, and boreal.

## Decision

Use **YARA-X 1.x** (`yara-x` crate, BSD-3-Clause) in a dedicated
`warden-yara` crate that implements `warden_core::Detector`.

* **Default features off; modules listed explicitly.** Enabled: pe, elf,
  macho, dotnet, dex, lnk, hash, math, string, time, plus the performance
  features `constant-folding`, `exact-atoms` and `fast-regexp`. Excluded:
  `vt` (VirusTotal Livehunt metadata), `cuckoo` (sandbox reports), `console`
  (rule-driven output), `magic` (needs libmagic, a C library), `crx`,
  `olecf`, `vba`, `msi`, `zip` and the protobuf test modules. A module can be
  added later with a test and a doc update.
* **Compile-time hardening:** `include` disabled (on by default in YARA-X),
  slow patterns are errors, strict regex syntax, 64 MiB source cap, 200,000
  rule cap.
* **Scan-time limits:** timeout from the per-file deadline (whole seconds,
  because YARA-X uses a 1-second heartbeat), and 1,000 matches per pattern.
* **Rule semantics come from metadata** (`aw_kind`, `aw_confidence`, …),
  validated at load time. Without it a match is `suspicious`/`medium`.
  `confirmed` is refused, since a pattern match is not proof of identity.
* **One YARA-X `Scanner` per scan worker**, created through
  `Detector::worker` (ADR-0006). Creating a scanner costs about 50× a small
  scan.

## Consequences

* The build pulls in about 180 crates, including wasmtime/cranelift, which
  YARA-X uses to compile conditions. Isolating them in `warden-yara` keeps
  `warden-core` and `warden-engine` light.
* Rules that rely on excluded modules, on includes, or on patterns YARA-X
  considers slow are rejected with an explicit error.
* Compatibility is claimed only for what the test suite covers
  (`crates/yara/tests/yara.rs`); see the supported-feature table in
  `docs/detection/yara.md`.
