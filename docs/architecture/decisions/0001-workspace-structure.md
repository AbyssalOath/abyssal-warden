# ADR-0001: Workspace structure

* **Status:** Accepted
* **Date:** 2026-09-24

## Context

The repository started as a single `abyssal-warden` binary crate with a
"hello world". The product will eventually include a scan engine, several
detection providers, remediation, a privileged service, IPC, platform
integrations and a GUI. These have different dependency weights and different
privilege and trust levels.

## Options considered

1. **Single crate with modules.** This is simplest, but boundaries are not
   enforced. Any module can call remediation code, and every consumer pulls in
   every dependency.
2. **One crate per box in the logical architecture** (~12 crates). The
   boundaries would be enforced, but most crates would start as empty
   placeholders. That means speculative interfaces and churn.
3. **Minimal virtual workspace, growing only with a concrete boundary reason.**

## Decision

Option 3. Start with three crates: `warden-core` (types and `Detector`
trait), `warden-engine` (scanner and built-in hash detector), and
`warden-cli` (binary `abyssal-warden`). Crates live under `crates/`. Add a
crate only to isolate a heavy or risky dependency, to enforce a privilege or
trust boundary, or to give a consumed interface its own home. The planned
crates and their reasons are listed in
[crate-boundaries.md](../crate-boundaries.md).

Workspace-wide settings: edition 2024, resolver 3, `unsafe_code = "forbid"`,
Clippy `unwrap_used`/`expect_used` warnings (allowed in tests via
`clippy.toml`), and CI with `-D warnings`. Release builds keep
`panic = "unwind"` so detector panics can be isolated.

## Consequences

* The engine can be used without the CLI; the CLI does not reach into engine
  internals.
* Moving the hash detector into its own crate later is cheap, if needed.
* The fuzz crate is a separate workspace (`fuzz/`) because it needs nightly.
* Crate names use the `warden-` prefix and are `publish = false` until the
  licence (ADR-0004) is settled.
