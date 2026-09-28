# Update security

**Status:** signed content and an **automatic updater** are
**implemented** ([ADR-0007](../architecture/decisions/0007-content-signing.md),
[ADR-0020](../architecture/decisions/0020-content-updates.md)). The project
does not publish an update channel or signing keys yet. The "Design" list
below records how each goal is met.

## Implemented now

* minisign (Ed25519) detached signatures on hash databases and YARA rule
  files, verified against keys given with `--trusted-key` **before** parsing.
* Signed content is required by default; unsigned content needs
  `--allow-unsigned` and produces a report warning. Invalid signatures are
  always fatal.
* **Signed content bundles** with rollback, equivocation, expiry (freeze)
  and mix-and-match protection, and **keyrings** with revocation and
  validity windows: see [content-trust.md](content-trust.md).
* **Threshold signatures, sequence floors for fresh installations, and
  revocations carried by content** (ADR-0013).
* **Automatic updates** (`abyssal-warden update`, service `update`
  schedules) with a TUF-style timestamp signed by a separate, online-capable
  `timestamp` key: stale mirrors are detected within the timestamp lifetime
  (at most 31 days, 72 hours by default). See [updates.md](../user/updates.md).
* Not implemented: the project's actual signing keys and update URL (the
  key procedure is defined in content-trust.md), and full TUF (no snapshot
  role over several bundles).

## Threats addressed by the design

Compromised mirror or CDN, man-in-the-middle, a stolen signing key, rollback
to an old database that lacks new detections, indefinite freeze (serving a
stale but valid database), and malicious rule content.

## Design

1. **Signed metadata, verified before parsing content.** Done: Ed25519
   (minisign) signatures over a manifest with sequence, expiry and content
   hashes, plus a signed timestamp naming the manifest's hash. Full TUF
   (`tough`) was not adopted (ADR-0020); the bundle format would not change
   if it were later.
2. **Pinned trust root** shipped with the release, rotated through
   keyrings delivered with the software, never learned from content. Done.
3. **Rollback protection:** the bundle `sequence` and the timestamp
   `version` must never decrease (content state). Done.
4. **Freeze protection:** bundles and timestamps expire; an expired one is
   refused unless `--allow-expired` is given, which the report records.
   Done.
5. **Content is data, never code.** Updates may deliver signatures and rules
   only. Executable engine updates go through the OS package manager or
   signed installers, never through the rule channel.
6. **Atomic install:** download to a private staging directory, verify, parse
   and validate fully (the same strict loader), then swap atomically; an
   interrupted swap is recovered. Done.
7. **Unprivileged download:** in the service the whole update runs as the
   scanner account with no capabilities. Done (Linux; on Windows jobs run as
   the service account).

## Third-party content

Signature and rule sources are included only after reviewing their licence
and permitted redistribution ([content-sources.md](../detection/content-sources.md)).
Each database records its licence in `database.license`, YARA findings
carry rule author, reference and licence, and bundles carry notice files.
Nothing third-party is bundled today.
