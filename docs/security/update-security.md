# Update security

**Status:** signature verification of detection content is **implemented**
([ADR-0007](../architecture/decisions/0007-content-signing.md)). There is
still **no update mechanism**: databases and rules are local files the user
passes on the command line. Everything below "Planned design" except item 1's
signature check is future work.

## Implemented now

* minisign (Ed25519) detached signatures on hash databases and YARA rule
  files, verified against keys given with `--trusted-key` **before** parsing.
* Signed content is required by default; unsigned content needs
  `--allow-unsigned` and produces a report warning. Invalid signatures are
  always fatal.
* Not implemented: rollback protection, expiry/freeze protection, key
  rotation, a project signing key.

## Threats addressed by the design

Compromised mirror or CDN, man-in-the-middle, a stolen signing key, rollback
to an old database that lacks new detections, indefinite freeze (serving a
stale but valid database), and malicious rule content.

## Planned design

1. **Signed metadata, verified before parsing content.** Adopt The Update
   Framework (TUF) model: separate root, targets, snapshot and timestamp
   roles; threshold signatures for root; expiry on every role. The Rust
   `tough` crate is the leading candidate and will be evaluated for
   maintenance, licence and audit history. If TUF is too heavy for the first
   version, use Ed25519 detached signatures over a manifest that carries
   version, expiry and content hashes, with the same rollback and expiry
   checks.
2. **Pinned trust root** shipped with the release, and rotated only through
   signed root rotation.
3. **Rollback protection:** the database `version` must be strictly greater
   than the last installed version (stored in service state).
4. **Freeze protection:** metadata expires. When an update is overdue, the
   product reports "detection content is out of date" instead of failing
   silently.
5. **Content is data, never code.** Updates may deliver signatures and rules
   only. Executable engine updates go through the OS package manager or
   signed installers, never through the rule channel.
6. **Atomic install:** download to a private staging directory, verify, parse
   and validate fully (the same strict loader), then swap atomically. Keep the
   previous version for rollback on load failure.
7. **Unprivileged download:** the network fetch runs without elevated
   privileges; only the verified swap needs service rights.

## Third-party content

Signature and rule sources are included only after reviewing their licence
and permitted redistribution. Each database records its licence in
`database.license`. Nothing third-party is bundled today.
