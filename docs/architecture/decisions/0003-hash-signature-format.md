# ADR-0003: Hash signature database format v1

* **Status:** Accepted
* **Date:** 2026-09-24

## Context

The first detection provider matches exact SHA-256 hashes. Databases will
eventually arrive through an update channel, so the format must be treated
as untrusted input, versioned, and extensible toward family and pattern
signatures without a premature schema.

## Options considered

| Option | For | Against |
|---|---|---|
| JSON | Human-readable, diff-able, serde_json is mature and fuzzed, already a dependency | Larger and slower to parse than binary for millions of entries |
| TOML | Readable | Poor fit for large arrays; an extra parser |
| Plain text (`hash name` per line) | Tiny, fast | No room for metadata, versioning or classification |
| Binary / SQLite | Fast and compact for large sets | Opaque to review; SQLite adds a C dependency and a big parser surface |
| ClamAV `.hdb`/`.hsb` | Existing ecosystem | Format is ClamAV's; its databases have their own licence terms; less metadata |

## Decision

JSON with a mandatory header (`format` = `abyssal-warden.hash-signatures`,
`format_version` = 1), a `database` metadata object (including a `license`
field for the *data*), and a `signatures` array. Parsing is:

1. size-capped (256 MiB) before reading;
2. two-phase: the header is checked first, so a newer version reports
   "unsupported version" rather than "unknown field";
3. strict: `deny_unknown_fields` at every level;
4. fully validated: ID charset and length, text length limits, rejection of
   control and bidi characters, `rule_version >= 1`, no duplicate IDs, no
   duplicate hashes (an ambiguous verdict is refused);
5. all-or-nothing: an invalid entry rejects the whole database.

The full specification is in [signatures.md](../../detection/signatures.md).

## Consequences

* Adding optional fields requires a new `format_version`. This is intended:
  old engines must not silently ignore semantics they don't understand.
* JSON parse time and memory for very large sets (millions of hashes) is
  not yet measured. A compact binary format may be added as
  `format_version` 2 or as a separate format ID, with benchmarks.
* Databases are **not signed** yet. Loading an attacker-supplied database
  can at worst cause false positives/negatives, because the engine never acts
  on findings. Signing becomes mandatory before any automatic update or
  remediation exists ([update-security.md](../../security/update-security.md)).
