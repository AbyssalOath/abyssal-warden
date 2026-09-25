# Archive scanning

Decision record: [ADR-0011](../architecture/decisions/0011-archive-scanning.md).
Implementation: `crates/engine/src/archive.rs`.

**Status: implemented for ZIP** and ZIP-based formats (JAR, APK, Office
Open XML such as .docx/.xlsx/.pptx, and self-extracting ZIP executables).
Enabled by default; `--no-archives` turns it off.

## How it works

1. A file is recognised as an archive by its **content** (ZIP signature, or
   a Windows executable with a ZIP appended), never by its name.
2. Members are decompressed **in memory**. Nothing is written to disk, so
   member names such as `../../etc/passwd` are only data.
3. Every member is hashed and evaluated by every detector (hash signatures,
   YARA) exactly like a file. Members that are themselves ZIPs are expanded
   in turn, up to the nesting limit.
4. Findings in members name the archive on disk and the member chain:

   ```text
   In archive:   /home/u/mail.zip > attachment.zip > drop/payload.exe
   ```

   In JSON the target is
   `{"type": "archive_member", "archive": {...}, "member": [{...}, ...], "sha256": "...", "size": N}`.

## Limits

| Setting | CLI | Default | Protects against |
|---|---|---|---|
| Expand archives | `--no-archives` | on | |
| Nesting depth | `--archive-max-depth N` | 3 | Recursive archives ("zip quines", deep nesting) |
| Total decompressed bytes per file on disk | `--archive-max-total SIZE` | 1 GiB | Decompression bombs |
| Members per archive | (config) | 10,000 | Entry-count exhaustion |
| Member bytes kept for content detectors and nesting | (config) | 8 MiB | Memory exhaustion; larger members are still hashed |
| Member size | `--max-file-size` | 512 MiB | Oversized members |
| Archive size to expand | `--max-content-size` | 64 MiB | Larger archives are hashed but not expanded |
| Time | `--file-timeout` | 60 s per file on disk | Slow or pathological archives |

The byte budget, deadline and cancellation are checked every 64 KiB of
decompressed output. A member's declared size is never trusted.

## What is reported instead of inspected

| Report entry | Meaning |
|---|---|
| skip `archive_too_large` | The archive exceeds `--max-content-size`; hashed, not expanded |
| skip `archive_limit_reached` | Depth, entry-count or byte budget reached; the member (or the rest of the archive) was not inspected |
| skip `archive_member_encrypted` | Encrypted member |
| skip `archive_member_unsupported` | Compression method not supported, or a symlink entry |
| skip `content_not_inspected` (with member) | Member larger than 8 MiB: hashed, not YARA-scanned |
| issue `archive_error` | Malformed archive, corrupt member (CRC/decompression failure), or parser panic |

## Supported and not supported

| | Status |
|---|---|
| ZIP: stored, deflate, deflate64 | Supported (pure-Rust decompressors) |
| ZIP: bzip2, LZMA, XZ, zstd, PPMd | Not supported: reported as `archive_member_unsupported` |
| Encrypted ZIP (ZipCrypto, AES) | Not decrypted: reported |
| 7z, RAR, tar, gzip, bzip2, xz, CAB, ISO, MSI/OLE, DMG | Not expanded (scanned as raw bytes only) |

## Security notes

* Members are never extracted to disk, so zip-slip does not apply.
* The ZIP parser and decompressors process hostile input. They are Rust,
  run inside `catch_unwind`, are covered by the stall watchdog, and are
  fuzzed (`archive-expand` target).
* Findings inside archives are never quarantined automatically
  ([remediation policy](../security/quarantine.md#automatic-remediation-policy)).
