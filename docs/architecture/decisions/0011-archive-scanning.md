# ADR-0011: Archive scanning (ZIP)

* **Status:** Accepted
* **Date:** 2026-09-25

## Context

Malware is routinely delivered inside archives: email attachments, JARs and
APKs, Office documents (which are ZIPs), and archives inside archives. Before
this change the scanner hashed and YARA-scanned an archive's raw bytes, so
anything compressed inside it was invisible. Archives are also a classic
attack on scanners: decompression bombs, deep nesting, huge entry counts,
hostile member names, and malformed structures aimed at parser bugs.

## Options

| Option | Result |
|---|---|
| Extract to a temporary directory and scan it | Disk I/O, cleanup and path-traversal risk (zip-slip), and a place where live malware lands on disk |
| **Decompress members in memory and evaluate them like files** | No disk writes; member names are never used as paths; limits enforced as bytes are produced |
| Stream-only (no random access) | Cannot handle the central directory, self-extracting executables or nested archives well |

Library: **`zip` 8.6** (zip-rs; MIT). Only pure-Rust decompressors are
enabled: stored, deflate (`zlib-rs`) and deflate64. The C `zstd` bindings,
AES decryption and the rarer methods (bzip2, LZMA, XZ, PPMd) are left out:
each decompressor is attack surface, and these are rare in delivery archives.
Entries using them are reported, not skipped silently.

## Decision

* The engine's worker, after evaluating a file, expands it if it is a ZIP
  (by signature, not extension) or a Windows executable that is a
  self-extracting ZIP. Each member is evaluated by every detector as a
  `FileObservation` with `member` set. Findings use a new
  `FindingTarget::ArchiveMember { archive, member: [chain], sha256, size }`.
* Limits (`ArchiveLimits`, all configurable, defaults in brackets): nesting
  depth [3], members per archive [10,000], total decompressed bytes per file
  on disk [1 GiB; the bomb budget], member bytes kept in memory for content
  detectors and nesting [8 MiB], plus the existing per-file size limit,
  per-file deadline and cancellation, checked every 64 KiB of output.
* Only archives are buffered when no detector needs content, so hash-only
  scans do not buffer ordinary files.
* Everything not inspected is reported with the member chain:
  `archive_too_large`, `archive_limit_reached`, `archive_member_encrypted`,
  `archive_member_unsupported` skips, and `archive_error` issues for
  malformed archives and CRC failures.
* The ZIP parser and decompressors run inside `catch_unwind`; a panic is
  reported as an `archive_error`, not fatal. The stall watchdog (ADR-0009)
  covers a decompressor that never returns.
* Remediation: findings inside archives are **never** quarantined
  automatically. Quarantining a whole archive, which may be a user's backup
  or document, is a decision for a person.

## Consequences

* Detection now reaches content inside ZIP-based formats.
* Worst-case buffer memory per worker is about
  `max_content_size + max_depth × max_member_content` (64 MiB + 3 × 8 MiB
  with defaults).
* Other formats (7z, RAR, tar/gzip, CAB, ISO, MSI/OLE) remain unexpanded;
  each needs a vetted parser and its own limits.
* Archives larger than `max_content_size` are hashed but not expanded
  (reported as `archive_too_large`).
