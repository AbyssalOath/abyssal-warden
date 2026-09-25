# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
for this repository ("Security" tab → "Report a vulnerability"). Do not open a
public issue for a suspected vulnerability.

Include the affected version or commit, the platform, reproduction steps, and
the impact you believe it has. Please do not attach live malware; describe the
sample or share a hash instead.

We aim to acknowledge reports within 7 days. This is a volunteer project
without a guaranteed fix timeline; we will keep you informed and credit you
in the advisory unless you ask us not to.

The private reporting channel must be enabled in the repository settings
before the first public release.

## Supported versions

Only the latest commit on `main` is supported. There are no releases yet.

## What Abyssal Warden currently protects against

Abyssal Warden is an on-demand scanner with optional quarantine. Within
that scope it aims to:

* Detect files that are **byte-for-byte identical** to entries in a loaded
  hash signature database, or that match loaded YARA rules.
* Load detection content only if it is signed by a key you trust (unless you
  explicitly allow unsigned content), and, for signed bundles, refuse
  rollback to older releases, stale (expired) releases, and revoked keys.
* Quarantine, restore and delete files (Linux) without following symlinks,
  without losing data on a crash, without overwriting on restore, and with
  a hash-chained audit log.
* Scan hostile directory trees safely: without following symlinks out of the
  scan roots (by default), without hanging on FIFOs, without exhausting memory
  on huge trees or files, and without letting file names inject terminal
  escape sequences into its output.
* Unpack hostile ZIP archives (bombs, deep nesting, malformed structures,
  hostile member names) without writing to disk, exhausting memory, or
  crashing.
* Reject malformed or hostile signature databases and YARA rules without
  crashing, and without letting rules read other files (`include` is
  disabled).

Bugs that break any of these properties are security vulnerabilities.

## What it does NOT protect against (yet)

* **It does not ship any real malware signatures or rules.** Without content
  you supply, it detects nothing.
* No real-time or on-access protection, and no blocking of execution.
* Limited detection of modified, packed or polymorphic malware: only as good
  as the YARA rules you supply; no heuristics or behavioural analysis.
* No rootkit, persistence or memory scanning. A compromised kernel can hide
  files from this scanner.
* Only ZIP-based archives are unpacked (stored/deflate/deflate64 entries).
  Malware inside 7z, RAR, tar/gzip, CAB, ISO or MSI containers, or in
  encrypted ZIP members, is not detected.
* No quarantine on Windows. Quarantine does not stop running processes or
  remove persistence.
* No automatic update mechanism, and no project signing key yet. Signed
  content bundles have rollback and expiry protection; individually signed
  files do not.

See [docs/known-limitations.md](docs/known-limitations.md) and the
[threat model](docs/security/threat-model.md) for the full picture.
