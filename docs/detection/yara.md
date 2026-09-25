# YARA rules (YARA-X)

Decision record: [ADR-0005](../architecture/decisions/0005-yara-engine.md).
Implementation: `crates/yara/src/lib.rs`. Tests: `crates/yara/tests/yara.rs`.

**Status: implemented** for on-demand scans, on every platform the engine
builds for.

## Purpose, inputs and outputs

* **Purpose:** match file content against YARA rules.
* **Input:** the file bytes supplied by the scanner (`FileObservation::content`),
  up to `max_content_size` (default 64 MiB). Larger files are not
  YARA-scanned and are reported as `content_not_inspected`.
* **Output:** one `Finding` per matching rule, with evidence listing up to 8
  pattern matches (`$id at offset 0x…, N bytes`).

## Usage

```sh
abyssal-warden scan --trusted-key project.pub --yara rules/ /path
abyssal-warden yara validate --trusted-key project.pub rules/
```

`--yara` accepts files or directories. In a directory, `*.yar` and `*.yara`
are taken (non-recursive, sorted); symbolic links are ignored. Each file gets
its own namespace (`<stem>_<n>`), so identical rule names in different files
don't collide. Rule files must be signed (`FILE.minisig`, see
[signatures.md](signatures.md#signing)) unless `--allow-unsigned` is given.

## Rule metadata conventions

A rule's meaning comes from optional `aw_*` metadata, validated when the
rules are loaded. Unknown `aw_*` keys and invalid values reject the whole
rule set.

| Key | Values | Default |
|---|---|---|
| `aw_kind` | `known_indicator`, `suspicious`, `heuristic`, `informational` | `suspicious` |
| `aw_confidence` | `low`, `medium`, `high` (`confirmed` is refused: a pattern match does not prove identity) | `medium` |
| `aw_severity` | `info` … `critical` | `medium` |
| `aw_category` | `malware`, `potentially_unwanted`, `test_indicator`, `unknown` | `unknown` |
| `aw_name` | display name, ≤ 256 bytes, no control/bidi characters | rule identifier |
| `aw_rule_version` | integer ≥ 1 | none |
| `description` | standard YARA metadata; shown only if it contains no control/bidi characters | - |

Recommended action: `quarantine` only for `known_indicator` + `malware` +
confidence `high`; `none` for test indicators and informational rules;
otherwise `review`. YARA findings are **never** quarantined automatically,
because only `confirmed` exact-hash matches are
([ADR-0008](../architecture/decisions/0008-quarantine-store.md)).

## Hardening and limits

| Control | Setting |
|---|---|
| `include` statements | disabled (YARA-X enables them by default) |
| Slow patterns | rejected (`error_on_slow_pattern`); e.g. one-byte patterns |
| Regex syntax | strict (no relaxed legacy syntax) |
| Total rule source | 64 MiB; 200,000 rules |
| Rule files per directory | 10,000 |
| Per-file timeout | remaining per-file budget, rounded **up to whole seconds** (YARA-X checks timeouts on a 1-second heartbeat) |
| Matches per pattern | 1,000 |
| Timeout / scan error | recorded as a `detector_failed` issue; the scan continues |

## Supported features

Only the features in this table are claimed. It lists what the test suite
exercises; other YARA-X features probably work but are **not claimed**
until tested.

| Feature | Tested |
|---|---|
| Text strings, hex strings, `any of them`, condition-only rules | yes |
| Metadata mapping (`aw_*`, `description`) | yes |
| Modules compile: pe, elf, macho, dotnet, dex, lnk, hash, math, string, time | yes (import compiles; module logic is YARA-X's and fuzzed via the `yara-scan` target) |
| Excluded modules rejected (cuckoo, vt, console, magic, …) | yes (cuckoo) |
| Timeout on pathological conditions | yes (O(n²) loop, 256 KiB input) |
| Includes rejected; slow patterns rejected | yes |

**Not supported:** compiled-rule files (`yarac` output, or YARA-X
serialised rules; deserialising untrusted compiled rules is a large attack
surface), external variables, process-memory scanning.

## Performance

Measured with `cargo run --release -p warden-yara --example scanner_cost`
(500 rules, 4 KiB input, one thread):

| Operation | Time |
|---|---|
| Create a YARA-X scanner | ~226 µs |
| Scan with a reused scanner | ~4.5 µs |

Creating a scanner per file would have made setup the dominant cost, so the
detector keeps one scanner per scan worker (`Detector::worker`,
[ADR-0006](../architecture/decisions/0006-content-access-and-time-limits.md)).

## Engine choice

| | **YARA-X** (chosen) | libyara via `yara` crate | boreal |
|---|---|---|---|
| Implementation | Rust rewrite by YARA's maintainers | C via FFI | Independent Rust |
| Licence | BSD-3-Clause | BSD-3-Clause | MIT / Apache-2.0 |
| Memory safety | Safe Rust; conditions run in wasmtime | C parsers and modules | Safe Rust |
| Maintenance | Active; YARA's successor | Maintenance mode | Active, smaller team |
| Build | ~180 crates incl. wasmtime | C toolchain + libyara | Lighter |

boreal remains a candidate for differential testing.

## Testing

`crates/yara/tests/yara.rs` covers detection end-to-end through the scan
engine, metadata semantics, every rejection rule (each checked to fail for
the intended reason), module availability, the content limit, and the
timeout. The `yara-scan` fuzz target feeds arbitrary bytes through the
detector with rules importing every enabled binary-format module.
