# Contributing

## Workflow for every change

1. Read the relevant architecture and security docs, and ADRs.
2. Make the smallest complete increment, with tests in the same change.
3. Run the [required checks](setup.md#required-checks-identical-to-ci).
4. Update the documentation, including status tables and
   `docs/known-limitations.md`.
5. In the PR, describe what changed, how it was tested (actual results), and
   what remains.

A feature is not "done" while only its interface or a placeholder exists.
Unfinished work is labelled with `TODO(#issue)` comments, not hidden behind
options that look functional.

## Code standards

* Stable Rust, `cargo fmt`, Clippy clean with `-D warnings`.
* `unsafe` is forbidden workspace-wide. A future FFI crate needs an ADR and a
  crate-local exception, with a `// SAFETY:` comment on every block.
* No `unwrap`/`expect`/`panic!` in production paths (Clippy enforces
  `unwrap_used`/`expect_used`). Handle errors explicitly with typed errors
  (`thiserror`).
* Bounded resources: every loop over untrusted input has a limit; every
  channel is bounded.
* Platform code is `cfg`-gated and kept out of `warden-core`.
* Do not suppress lints broadly. A narrowly scoped `#[allow]` needs a comment
  saying why.

## Security review

Changes touching any of the following need a **security review section** in
the PR: privileged operations, service installation, quarantine or deletion,
rule/database parsing or updates, IPC, drivers, real-time blocking, or file
opening/path handling. The section states:

* the trust boundary crossed and the relevant threat-model entries
  (update [threat-model.md](../security/threat-model.md) if new);
* failure modes (what happens on error, crash, or malicious input);
* the tests that demonstrate the safety properties;
* for parsers, the fuzz target.

Significant or irreversible design choices need an ADR in
`docs/architecture/decisions/`.

## Samples and detection content

* **Never commit live malware**, even encoded or password-protected. Use
  synthetic fixtures.
* Third-party signatures or rules need a licence review before inclusion.
* Do not claim detection capability without evidence gathered under
  [the evaluation methodology](../detection/testing.md).
