# Known limitations

Abyssal Warden is in early development. It is **not** a replacement for an
established anti-malware product, and nothing here should be read as a claim
of protection.

## Detection

* **No real signatures or rules ship with the project.** Without content you
  provide, scans detect nothing (the CLI warns about this).
* Exact SHA-256 matching and YARA rules only. No heuristics, behavioural,
  memory or process scanning.
* YARA scans only files up to `--max-content-size` (default 64 MiB); larger
  files are hash-checked only (reported as `content not inspected`).
* YARA support covers the features listed in
  [yara.md](detection/yara.md#supported-features); some modules are
  deliberately excluded, and includes, slow patterns and compiled rules are
  refused.
* **Archives are not unpacked.** YARA sees an archive's raw bytes, so
  malware inside compressed ZIP, 7z, installers and similar is generally not
  detected.
* No detection-rate evaluation has been performed
  ([methodology](detection/testing.md)).

## Content trust

* Signed content is verified, but **there is no rollback protection**: an
  older, validly signed database is accepted. No expiry, no key rotation, no
  project signing key yet.
* The example key in `examples/keys/` is a test key and must never be
  trusted outside testing.

## Protection and remediation

* No real-time or on-access protection; nothing is blocked.
* Quarantine is **Linux only**. It does not kill running processes or remove
  persistence. It runs with the invoking user's privileges (no service or
  privilege separation yet). Restored files are not allow-listed.
* The audit log is tamper-evident only against partial edits; it has no
  external anchor.
* No rootkit, persistence, boot or integrity checks. A compromised kernel can
  hide files from the scanner.

## Scanning behaviour

* The per-file time limit is cooperative: a single read blocked on a hung
  network or FUSE filesystem cannot be interrupted. There is no whole-scan
  time limit.
* Files that change during a scan are hashed as read. A file that grows past
  the size limit mid-read is skipped.
* With `--follow-symlinks`, scanned files may lie outside the given roots,
  and a file reachable by several paths is scanned more than once.
* Symlink protection during scanning covers the final path component
  (remediation protects every component).
* Reading files updates atime on filesystems mounted with `strictatime`.
* Windows: locked system files cannot be read; the test suite has not yet
  been run on Windows outside CI.

## Operational

* No service, scheduling, GUI, update mechanism or signed releases.
* Scan reports are not signed.
* Minimum supported Rust version is not yet defined. The code is built and
  tested with Rust 1.97 (edition 2024).
