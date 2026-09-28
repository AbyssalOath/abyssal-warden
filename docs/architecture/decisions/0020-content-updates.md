# ADR-0020: Automatic content updates

* **Status:** Accepted (hosting location and project keys still to be chosen
  by the owner)
* **Date:** 2026-09-28

## Context

Signed content bundles (ADR-0007, ADR-0013) protect against tampering,
rollback, mix-and-match and indefinite freeze **once a bundle is on disk**,
but there was no way to get a bundle there. Daily detection content cannot
be signed by hand with offline keys, yet the keys that make a bundle
trustworthy must stay offline. A mirror that keeps serving an old, still
valid bundle (a freeze attack) is only caught when that bundle expires,
which for content signed rarely may be weeks.

The Update Framework (TUF) solves this with separate root, targets,
snapshot and timestamp roles. The `tough` crate implements it, but brings
its own metadata formats, key types and a large dependency tree, and would
duplicate the keyring, threshold, revocation and rollback rules this
project already has and tests.

## Decision

1. **Key roles in keyrings.** Each keyring key has `roles`: `content`
   (default; signs bundle manifests and content files) and/or `timestamp`
   (signs only the update channel's `timestamp.json`). A role is granted
   only by the keyring; a key given with `--trusted-key` is a content key.
   Content keys stay offline with their threshold; the timestamp key may be
   online (a CI secret or hardware key), because it can only **delay**
   updates, never introduce content.
2. **TUF-style timestamp, not full TUF.** `timestamp.json` names the
   bundle, its sequence, and the SHA-256 and size of its `manifest.json`,
   with a `version` that must never decrease and an expiry of at most 31
   days (72 hours by default). Clients refuse an expired, replayed or
   older timestamp, and a timestamp naming a bundle older than the one
   installed. A stale mirror is therefore detected within the timestamp
   lifetime, not the bundle lifetime.
3. **Update flow** (`warden-update`), in this order: fetch and verify the
   timestamp (role, expiry, replay); fetch the manifest and check it
   against the timestamp's hash and size before parsing; download each
   file into a private staging directory with its size and hash checked
   while streaming; re-verify the whole staged bundle with the same loader
   scans use (signatures, threshold, key validity, expiry, rollback), then
   parse and compile the content exactly as a scan would; swap it into
   place atomically; record the new sequence and timestamp. Anything that
   fails leaves the installed bundle untouched. An interrupted swap is
   recovered on the next run.
4. **Hosting-agnostic sources.** A source is an `https://` URL (any static
   host: GitHub Pages or Releases, object storage, a web server) or a local
   directory (an offline mirror). Plain `http` and other schemes are
   refused. The HTTP client is `ureq` with `rustls` (ring provider) and the
   platform verifier (the operating system's trust store), https only,
   three redirects at most, timeouts and size limits on every body.
   Signatures, not TLS, are what make content trustworthy; TLS adds
   privacy and stops trivial tampering.
5. **Unprivileged updates.** In the service, `update` schedules run the
   updater as the scanner account with **no** capabilities, into that
   account's state directory; jobs that run as the service account use the
   installed bundles. Content is data, never code: engine updates go
   through packages and signed releases only.
6. **Third-party feeds are converted and vetted by the publisher**, not
   the client: `content import-hashes` turns SHA-256 lists into hash
   databases with the source licence recorded; `content import-yara`
   compiles each rule file under this project's restrictions and keeps
   only those that pass. Licences are reviewed before a feed is used
   ([content-sources.md](../../detection/content-sources.md)).

## Consequences

* Stale-mirror detection within days, with content keys that never touch
  an online machine.
* A stolen timestamp key can withhold updates until its timestamps expire
  or it is revoked; it cannot install anything.
* Not full TUF: there is no signed snapshot of several bundles (one bundle
  per update source), and root rotation is through keyrings shipped with
  the software (unchanged from ADR-0013). Moving to `tough` later remains
  possible; the on-disk bundle format would not change.
* New dependencies: `ureq`, `rustls`, `ring` (Apache-2.0 AND ISC),
  `rustls-platform-verifier` and their platform crates, all permissive.
* Hosting: GitHub Releases of a content-only repository (owner decision,
  2026-09-28). Assets have no paths, so published bundles are flat
  (`content manifest --flat`).
* Key custody (owner decision, 2026-09-28): the online timestamp key is a
  GitHub Actions environment secret in the content repository, re-signing
  twice a day; an offline backup timestamp key is in the keyring from the
  first release and takes over through a content-carried revocation
  (`packaging/content-channel/`).
* Feeds (owner decision, 2026-09-28): ESET malware-ioc and ReversingLabs
  YARA rules, built by `packaging/content-channel/scripts/build-bundle.sh`
  from pinned commits; Neo23x0 signature-base noted for later.
