# ADR-0013: Threshold signatures, sequence floors, and revocation carried by content

* **Status:** Accepted (amends ADR-0012)
* **Date:** 2026-09-25

## Context

ADR-0012 left three gaps:

1. **First use:** a machine with no rollback record accepts any valid,
   unexpired release, however old.
2. **Single signer:** one stolen key is enough to publish content.
3. **Revocation speed:** revocation reached clients only through keyring
   updates in the package channel.

TUF solves these with role metadata and a network updater. Neither exists
yet, but each gap can be closed within the offline, keyring-based model.

## Decision

1. **Sequence floors in the keyring.** A keyring may list
   `bundles: [{name, min_sequence}]`. Keyrings ship with each release, so
   a fresh installation refuses anything older than what existed when that
   release was built. Several keyrings: the highest floor wins.
2. **Threshold signatures.** A manifest may carry up to 16 signature files
   (`manifest.json.minisig`, `manifest.json.minisig.2` … `.16`). The keyring
   `policy.threshold` (1 to 16; several keyrings: the highest wins) sets how
   many **distinct**, currently valid, unrevoked keys must have signed. The
   same key signing twice counts once. When the threshold is not met, the
   error lists why each signature did not count. With a threshold above 1,
   individually signed files (one signature) are refused.
3. **Revocation carried by content.** A manifest may list `revoke_keys`.
   Once the manifest passes the threshold and is accepted, those keys are
   recorded as revoked in the client's content state. From then on they are
   revoked for bundles and individually signed files alike, even if a
   keyring still lists them. Revocations apply immediately to later bundles
   in the same run.

The principle behind 3: **content can remove trust, never add it.**
Learning *keys* from content was rejected in ADR-0012, because a compromised
key could plant keys that outlive its revocation. Learning *revocations*
only moves in the safe direction.

## Consequences

* Fresh installations are bounded by the floor of the release they were
  installed from, and by expiry after that.
* With `threshold >= 2`, one compromised key can neither publish content nor
  revoke other keys (a revocation needs an accepted manifest).
* With `threshold = 1`, a compromised key could revoke the other keys (a
  denial of service; it still cannot add trust). A keyring update recovers,
  since revoked keys can be replaced by new ones. Use `threshold >= 2` for
  official content.
* A recorded revocation cannot be undone by content or by a keyring; only
  deleting the content state resets it (a deliberate, visible action).
* What still needs TUF: automatic online updates, freshness via short-lived
  timestamp metadata, and delegated roles.
