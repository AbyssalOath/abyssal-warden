# Scanning

```sh
abyssal-warden scan [OPTIONS] <PATH>...
```

Without `--signatures` or `--yara`, files are enumerated and hashed but
**not evaluated for threats**. The CLI warns about this and the report says
so.

Detection content must be **signed** by a key you trust (`--trusted-key`),
unless you pass `--allow-unsigned`. See
[signatures.md](../detection/signatures.md#signing).

## Options

| Option | Default | Meaning |
|---|---|---|
| `-s, --signatures FILE` | none | Hash signature database; repeatable. An invalid or unverifiable database aborts the scan |
| `-y, --yara PATH` | none | YARA rule file or directory of `*.yar`/`*.yara`; repeatable ([yara.md](../detection/yara.md)) |
| `--trusted-key FILE` | none | minisign public key whose signatures are accepted; repeatable |
| `--allow-unsigned` | off | Accept content files that have no `.minisig` (a bad signature is still an error) |
| `--max-content-size SIZE` | `64M` | Largest file YARA inspects; larger files are hashed only and listed as `content not inspected` |
| `--file-timeout SECS` | `60` | Time limit per file (YARA uses whole seconds) |
| `--quarantine` | off | After the scan, quarantine files with confirmed malware hash matches (Linux; [remediation](remediation.md)) |
| `--quarantine-store DIR` | per-user default | Store for `--quarantine` |
| `--format human\|json` | `human` | Output format |
| `-o, --output FILE` | stdout | Write the report to a file (atomically; mode 0600 on Unix) |
| `--follow-symlinks` | off | Follow links below the scan paths. May leave the scan paths |
| `--max-file-size SIZE` | `512M` | Skip larger files (`K`/`M`/`G`/`T` = binary multiples) |
| `--max-depth N` | `256` | Maximum directory depth below each path |
| `--threads N` | CPUs, max 8 | Worker threads (1-64) |
| `--exclude PATH` | none | Exclude a path and everything below it; repeatable |
| `--no-default-excludes` | off | Linux: also scan `/proc` and `/sys` |
| `--one-file-system` | off | Do not cross into other filesystems |
| `--no-progress` | off | Hide the progress line (it is shown only on a terminal) |
| `--show-skipped` | off | List skipped entries in human output |

Ctrl-C cancels the scan and prints the partial report. A second Ctrl-C exits
immediately.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, no findings, every entry processed |
| 1 | At least one finding (of any kind, including test indicators). With `--quarantine`, check each finding's `remediation_status` |
| 2 | Usage error, invalid database, or fatal error |
| 3 | No findings, but some entries could not be scanned (see "Issues") |
| 130 | Cancelled |

## Reading a report

* **Findings**: each has a severity, a kind (`known indicator`, …), a
  confidence, the file and its SHA-256, the rule and database that matched,
  the evidence, and an explanation. "Recommended" actions are **not
  performed**, except that `--quarantine` acts on confirmed malware hash
  matches ([remediation](remediation.md)).
* **Skipped by policy**: entries deliberately not scanned (symlinks,
  non-regular files, over the size limit, excluded, depth limit), and files
  hashed but not content-inspected by YARA (`content not inspected`). These
  do not make a scan incomplete.
* **Issues**: entries that should have been scanned but could not be
  (permission denied, I/O errors, loops, detector failures, per-file
  timeouts). They mean coverage is incomplete.
* **Warnings**: statements about what the report does and does not mean.

"No findings" means no file matched the loaded signatures. It does not mean
the system is clean.

## JSON report

`--format json` emits a `ScanReport` with `schema_version: 1`. The schema is
defined by the types in `crates/core/src/report.rs` and
`crates/core/src/finding.rs`. Consumers should ignore unknown fields and
tolerate new enum values. Paths are objects:

```json
{ "text": "/home/u/evil�name", "raw_hex": "2f686f6d652f..." }
```

`raw_hex` is present only when the name is not valid Unicode. It holds the
exact bytes (Unix) or UTF-16LE code units (Windows).

## Other commands

```sh
abyssal-warden hash FILE...                                   # SHA-256, sha256sum-style output
abyssal-warden signatures validate --trusted-key K.pub FILE   # check a database and its signature
abyssal-warden yara validate --trusted-key K.pub PATH...      # compile and check rules
abyssal-warden quarantine ...                                 # see remediation.md
```
