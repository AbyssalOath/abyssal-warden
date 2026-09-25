# ADR-0012: Signed content bundles, keyrings and rollback protection

* **Status:** Accepted (extends ADR-0007); first-use, single-signer and revocation-speed gaps closed by [ADR-0013](0013-threshold-floors-revocation.md)
* **Date:** 2026-09-25

## Context

ADR-0007 verifies each content file's minisign signature but, as recorded
there, gives no rollback, freeze or mix-and-match protection and no key
rotation. TUF is the eventual target, but there is no updater yet, and
TUF's repository roles are more than local, offline-distributed content
needs today.

## Options

| Option | For | Against |
|---|---|---|
| Structured minisign trusted comments per file | No new file | Free-text parsing; no protection against mixing files from different releases |
| **Signed manifest per bundle** | Pins all files together; natural home for name, sequence and expiry; one signature to manage | New format (small) |
| TUF now (`tough`) | Complete: thresholds, role separation, key rotation | Needs repository tooling and a local datastore; designed around a network updater we don't have yet |

For keys: learning keys from signed content (TOFU chains) was rejected. A
compromised key could plant keys that survive its own revocation. Keyrings
come only from the software's installation channel, as with distribution
keyrings.

## Decision

* **Bundle** = directory + `manifest.json` (name, sequence, issued,
  expires, files with size and SHA-256) + `manifest.json.minisig`.
* **Rollback state** per bundle name (sequence + manifest hash), stored
  locally, written atomically under a lock. It refuses lower sequences and
  equal sequences with different manifests, and fails closed if corrupt.
* **Expiry** enforced by default; `--allow-expired` is explicit and shows up
  in the report.
* **Keyrings** with validity windows and revocation. The system keyring is
  always loaded when present.
* The scanner never signs. `content manifest` builds (and validates)
  manifests; signing happens with rsign2/minisign on an offline machine.
* Per-file signing remains for compatibility, with a report warning.

## Consequences

* Rollback protection is per host and per user. A fresh machine accepts any
  valid, unexpired sequence the first time. Expiry limits how old that can be.
* The state file is protected only against other users. An attacker who can
  write the user's files can reset it; that attacker already controls the
  scan.
* Single signature per manifest; no threshold. Moving to TUF remains the plan
  for automatic updates, and the manifest maps naturally onto TUF targets
  metadata.
