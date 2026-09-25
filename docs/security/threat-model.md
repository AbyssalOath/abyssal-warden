# Threat model

Abyssal Warden processes attacker-controlled input by design, and will
eventually hold privileges. Its own attack surface is a primary concern.
This document distinguishes what the **current implementation addresses**
from what depends on **future components**. Review and update it with every security-sensitive
change (see [contributing](../development/contributing.md#security-review)).

## Assets

| Asset | Why it matters |
|---|---|
| Integrity of the host | A scanner that can be turned into an exploit primitive (code execution, arbitrary file write or delete) is worse than no scanner |
| Accuracy of results | False negatives hide compromise; false positives drive destructive "remediation" |
| Detection content | Poisoned rules or hashes cause misses or mass false positives |
| Quarantined samples | Live malware; must not be executed, leaked or restored unsafely |
| Evidence and audit logs | Needed for incident response; must be tamper-evident |
| Availability | A scanner that hangs or exhausts resources can be used as a denial of service |

## Trust boundaries

```mermaid
flowchart LR
    subgraph Untrusted
        files[Scanned files, names,<br/>directory structure]
        rules[Signature and rule files,<br/>update data]
        clients[IPC clients<br/>future]
    end
    subgraph Trusted["Abyssal Warden process(es)"]
        engine[Engine]
        svc[Service, future]
    end
    files -->|read-only, hardened open| engine
    rules -->|strict parser, size caps| engine
    clients -->|authenticated, authorised IPC| svc
    engine -->|report| out[CLI output / JSON]
```

The **user running the CLI** is trusted to choose what to scan and which
databases to load. Everything they point it at is untrusted.

## Threats

Status key: **mitigated** (implemented and tested), **partial**,
**future** (needs a component that does not exist yet), **accepted** (known
residual risk).

### T1: Malicious files exploiting parsers

* **Threat:** crafted content triggers memory corruption or logic bugs in
  file parsers.
* **Current:** partial. Our own code is safe Rust (`unsafe_code = "forbid"`).
  File content is parsed only by YARA-X's modules (PE, ELF, Mach-O, .NET,
  LNK, DEX), which are Rust. Only the modules we list are compiled in.
  Detector panics are isolated per call and the per-worker state is rebuilt
  afterwards. The `yara-scan` fuzz target drives all enabled format modules
  with arbitrary bytes (initial campaign: ~104k inputs over 7 minutes, no crashes).
* **Residual:** YARA-X and wasmtime are large dependencies whose own
  `unsafe` code we do not audit. A parser bug runs in the scanning process
  with the user's privileges.
* **Future:** a sandboxed parser process (seccomp/landlock, AppContainer)
  once the service exists.

### T2: Archives and decompression bombs

* **Current:** mitigated by scope. Archives are not opened, so an archive
  counts as one opaque file. This is also a *detection gap*
  ([known limitations](../known-limitations.md)).
* **Future:** limits on total expanded bytes, expansion ratio, entry count,
  nesting depth and time. Extract to memory or a private temp dir, never by
  following entry paths (zip-slip).

### T3: Path traversal

* **Current:** mitigated. The engine only reads paths produced by directory
  enumeration under canonicalised roots; it never builds paths from file
  contents. Excludes use component-wise matching (`/skip` does not exclude
  `/skipnot`; this is tested).
* **Future:** quarantine restore and archive extraction must validate target
  paths ([quarantine.md](quarantine.md)).

### T4: Symlink and reparse-point attacks

* **Threat:** a link inside a scanned tree points at `/etc/shadow` or a
  device, leaks content, or causes loops. A file is swapped for a link
  between enumeration and open (TOCTOU).
* **Current:** mitigated.
  * Default policy `skip`: links are not followed and are reported as
    skipped.
  * Files are opened with `O_NOFOLLOW` (Linux) or
    `FILE_FLAG_OPEN_REPARSE_POINT` (Windows), so a link swapped in after
    enumeration is not followed. This is tested.
  * `follow` policy uses walkdir's loop detection; loops become issues (tested).
    The report warns that followed links may leave the scan roots.
  * Only the final path component is protected. A *directory* swapped for a
    link mid-scan can redirect a later open. That is harmless for a read-only
    scanner running as the user, but **it is not acceptable for privileged
    remediation**, which must use `openat2(RESOLVE_NO_SYMLINKS)` or
    handle-relative operations.

### T5: FIFOs, devices and special files

* **Threat:** opening a FIFO blocks forever; reading `/dev/zero` never ends;
  reading a tty has side effects.
* **Current:** mitigated. Non-regular entries are skipped. Opens use
  `O_NONBLOCK | O_NOCTTY`, and the type is re-checked with `fstat` on the
  handle. `/proc` and `/sys` are excluded by default on Linux. FIFO handling
  is tested.

### T6: Malicious rule and signature files

* **Current:** mitigated for the hash database. 256 MiB cap, strict schema,
  validation of every field, rejection of control and bidi characters,
  duplicate detection, all-or-nothing loading. The parser is fuzzed
  (8.3M executions without a crash in the initial run). An invalid database
  aborts the scan instead of silently reducing coverage.
* **Current (YARA rules):** mitigated. `include` disabled (it would let a
  rule read arbitrary files), slow patterns and unknown/invalid `aw_*`
  metadata rejected, size and rule-count caps, strict regex syntax, scan
  timeouts and match caps, compiled-rule files not accepted.
* **Current (authenticity):** mitigated. Content must be signed by a trusted
  minisign key unless `--allow-unsigned` is given. Verification happens
  before parsing, and invalid signatures are always fatal. Reports record
  the signer and warn about unsigned content.
* **Residual:** a *validly signed* old database is accepted (no rollback
  protection), and a malicious *trusted* signer can still cause false
  positives. The damage is limited because automatic remediation only acts
  on confirmed malware hash matches, re-checks the hash, and never touches
  system directories.

### T7: Compromised update sources

* **Current:** partial. There is no update mechanism, but content
  signatures are verified against user-pinned keys (T6).
* **Future:** rollback and freeze protection, key rotation, and never
  executing downloaded code ([update-security.md](update-security.md)).

### T8: Unauthorised GUI or CLI-to-service requests

* **Current:** not applicable, because there is no service or IPC.
* **Future:** local-only transport (Unix socket / named pipe) with OS-level
  peer authentication and an explicit authorisation matrix; no TCP
  listener ([privilege-model.md](privilege-model.md)).

### T9: Privilege escalation through the product

* **Current:** mitigated by design. The CLI runs with the invoking user's
  privileges and has no setuid, service or elevation path. Reports written
  with `--output` go via a temp file plus atomic rename (mode 0600 on Unix), so
  an existing symlink at the destination is replaced rather than written
  through.
* **Future:** the service is the only privileged component; see the
  privilege model.

### T10: Quarantine tampering and remediation attacks

* **Threats:** tricking remediation into deleting or moving the wrong file
  (symlink swaps, `..`, hard links, TOCTOU); reading or executing quarantined
  malware; restoring over an existing file or into an attacker-writable
  directory; corrupting state through crashes; forging quarantine IDs to
  reach other files.
* **Current (Linux):** mitigated, with each point tested:
  * `openat2(RESOLVE_NO_SYMLINKS)` on every path, handle-relative open and
    unlink, and removal only if the name still refers to the copied inode.
  * Hard-linked files are refused.
  * The expected hash is re-checked before anything changes.
  * The store is 0700, owned by the user, never opened through a link, and
    locked with `flock`.
  * Content is XOR-encoded with a random key, so it is inert.
  * Restore never overwrites (`RENAME_NOREPLACE`/`link`), refuses group- or
    world-writable directories, and strips setuid/setgid.
  * IDs are parsed strictly (no path syntax).
  * Journal-based crash recovery, tested by fault injection at every step.
* **Residual:** the inode-check-to-unlink race (limited to one name in a
  directory the attacker can already modify); no privilege separation yet;
  Windows has no quarantine. See [quarantine.md](quarantine.md#not-guaranteed).

### T11: Malicious configuration changes

* **Current:** partial. `ScanConfig` is validated and deserialises with
  `deny_unknown_fields`. Configuration comes only from CLI arguments today.
* **Future:** service configuration is root/SYSTEM-owned. Changes go through
  the authorised IPC and are audit-logged. Unsafe values (e.g. disabling
  scanning of a path) are logged prominently.

### T12: Resource exhaustion

* **Current:** mitigated.
  * Bounded worker count (1-64, default ≤ 8).
  * Bounded work and result channels (memory is independent of tree size).
  * Per-file size limit, enforced from the handle **and** during reading,
    so a file growing mid-read is caught.
  * Depth limit.
  * Recorded findings, skips and issues are capped; the rest are only counted.
  * Streaming hash with a 64 KiB buffer.
  * Cancellation checked per file and per chunk.
  * Measured: ~46k files / 660 MiB scanned with 4 MB peak RSS.
  * Per-file time limit (default 60 s), checked between read chunks, before
    each detector, and inside YARA-X.
  * Content buffered for YARA only up to `max_content_size` (64 MiB), so
    worst-case buffer memory is bounded by `workers × 64 MiB`.
* **Partial:** a single blocking `read(2)` on a hung network or FUSE
  filesystem cannot be interrupted, so it can stall a worker beyond the limit.
  There is no whole-scan time budget.

### T13: False positives and unsafe remediation

* **Current:** mitigated.
  * Remediation happens only when the user asks for it (`scan --quarantine`
    or `quarantine add`). The automatic policy accepts only confirmed
    exact-hash malware matches outside protected system directories; YARA,
    heuristic, suspicious and test findings are marked `not_eligible`.
  * Quarantine is always reversible until an explicit
    `quarantine delete --yes`.
  * YARA rules cannot claim `confirmed` confidence.

### T14: Compromised host visibility (rootkits)

* **Accepted:** a scanner running inside a compromised OS sees what the
  kernel shows it. Kernel rootkits can hide files and processes from 0.1.0
  completely. **Future:** cross-view checks raise the attacker's cost but
  cannot defeat a determined kernel-level adversary. Offline scanning from
  trusted media is the real mitigation. The product must say this and not
  claim otherwise.

### T15: Tampering with logs or detection evidence

* **Current:** partial.
  * Scan reports are written atomically but are ordinary user-owned files.
  * Remediation actions go to a hash-chained audit log that detects edits,
    removals and reordering; the store refuses to open when the chain is
    broken.
  * An attacker able to rewrite the whole log can forge a consistent chain.
* **Future:** anchor the head hash externally (syslog / Windows Event Log /
  remote collector); service-owned log.

### T16: Output injection via hostile names

* **Threat:** a file named with ANSI/OSC escape sequences rewrites the
  terminal, spoofs output or sets the window title. Bidi overrides disguise
  `invoice‮fdp.exe`. Non-UTF-8 names break JSON generation.
* **Current:** mitigated. All untrusted strings are escaped before terminal
  output (C0/C1 controls, DEL, bidi controls). Paths serialise losslessly via
  `ObservedPath.raw_hex`. Tested end-to-end with a hostile file name.

## Assumptions

* The Rust toolchain, the standard library and audited dependencies are
  trustworthy (cargo-deny and RustSec checks in CI).
* The user who invokes the CLI is not the adversary.
* The OS kernel is not compromised. When it is, see T14.
