# Release process

**Status:** there have been no releases. This document defines the gates and
the planned procedure.

## Repository configuration (to do before collaboration)

* Default branch `main`, protected: pull requests required, at least one
  review, and all CI jobs in `.github/workflows/ci.yml` required (rustfmt,
  clippy on Linux and Windows, tests on Linux and Windows, rustdoc,
  cargo-deny, fuzz build). No force pushes.
* Private vulnerability reporting enabled (see `SECURITY.md`).
* Dependabot or Renovate for Cargo and GitHub Actions updates. Actions are
  pinned to commit SHAs.

## Dependency policy

Enforced by `deny.toml` in CI:

* Licences: permissive allow-list only (see file). A new licence type needs
  review against [ADR-0004](../architecture/decisions/0004-project-license.md).
* Advisories: any RustSec advisory fails CI. An ignore needs a written
  justification in `deny.toml`.
* Sources: crates.io only; no git dependencies.
* Before adding a dependency, check: maintenance activity, `unsafe` use,
  transitive dependency count, licence, and whether a few lines of our own
  code would do. Record the reason in the PR.
* `Cargo.lock` is committed. CI uses `--locked`. Lockfile changes are
  reviewed like code.

## Release checklist (planned)

1. All CI gates green on the release commit; a fuzzing campaign (≥ 1 hour
   per target) with no new crashes.
2. Update `CHANGELOG.md`, `docs/known-limitations.md`, `SECURITY.md`
   ("what it protects against"), and the status tables in the docs.
3. Tag `vX.Y.Z`, signed.
4. Build artifacts in CI from the tag, never on a developer machine, with
   `--locked`. Aim for reproducible builds (`SOURCE_DATE_EPOCH`, remapped
   path prefixes) and verify by rebuilding.
5. Produce an SBOM (CycloneDX via `cargo-cyclonedx`, to be evaluated) and
   SHA-256 checksums.
6. Sign artifacts and checksums: Sigstore/cosign keyless signing or minisign
   with a published key (to be decided and recorded as an ADR). On Windows,
   also Authenticode-sign binaries once a certificate is obtained.
7. Publish verification instructions with every release.

## Never

* Automatic privileged installation, or execution of downloaded components
  that have not been verified.
* Releases built from uncommitted or unreviewed code.

## Accepted advisories

Advisories ignored in `deny.toml` and `.cargo/audit.toml`, with reasons.
All come from YARA-X's dependency tree; re-evaluate each whenever `yara-x` is
updated, and remove the ignore as soon as a fixed version can be reached.

| Advisory | Crate | Why it does not apply | Fix reachable? |
|---|---|---|---|
| RUSTSEC-2026-0222 | wasmtime 45.0.3 | Type indices mixed *between engines*; yara-x creates one global `Engine` | No: yara-x 1.20 pins `^45.0.3`, fixes are in 46.0.3 / 47.0.4 |
| RUSTSEC-2026-0269 | wasmtime 45.0.3 | WASI filesystem sandbox escape; no WASI crates in the tree (features: cranelift, runtime, std) | No (as above) |
| RUSTSEC-2023-0071 | rsa 0.9 | Marvin timing attack on private-key operations; yara-x only verifies signatures with public keys | No fixed rsa release |
| RUSTSEC-2025-0141 | bincode 2 (unmaintained) | Used only for compiled-rule serialisation, which Abyssal Warden refuses | n/a |

Reviewed 2026-09-24.
