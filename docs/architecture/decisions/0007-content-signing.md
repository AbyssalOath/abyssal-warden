# ADR-0007: Signed detection content

* **Status:** Accepted
* **Date:** 2026-09-24

## Context

Hash databases and YARA rules decide what is reported and, since
quarantine exists, what is moved off disk. Content from an unverified source
can cause false negatives or targeted false positives.

## Options

| Option | For | Against |
|---|---|---|
| **minisign (Ed25519)** | Standard, simple format with existing signing tools (`minisign`, `rsign2`); verification-only crate with no dependencies (`minisign-verify`, MIT); signed "trusted comment" | No key rotation or expiry built in |
| Raw Ed25519 (`ed25519-dalek`) + own format | Full control | We would have to build and maintain the signing tools |
| TUF (`tough`) | Rollback, freeze and key-rotation protection | Heavy; needs a repository and an updater, which don't exist yet |
| OpenPGP (`sequoia`) | Widely known | Large attack surface and dependency tree, LGPL components |

## Decision

**minisign detached signatures**, verified with `minisign-verify`:

* The signature for `X` is `X.minisig`. Only prehashed (`ED`) signatures are
  accepted.
* Verification happens **before** parsing.
* By default the CLI requires every database and rule file to be signed by
  a key given with `--trusted-key`. `--allow-unsigned` permits files with no
  signature. A signature that is present but invalid is always an error.
* The verifying key ID is recorded in the report (`database.signer`).
  Reports warn when any content was unsigned.
* No project signing key exists yet. The example content is signed with a
  throwaway test key whose secret was discarded; only its public key is in
  `examples/keys/`.

## Consequences

* Authenticity only. **Rollback and freeze protection are not provided:**
  an attacker who can substitute an *older* validly signed database is not
  stopped. That needs persistent "last installed version" state and expiring
  metadata, which belong to the updater (TUF is still the target design in
  `docs/security/update-security.md`).
* Key management (generation, offline storage, rotation, publication) must
  be defined before the first real signed content ships.
