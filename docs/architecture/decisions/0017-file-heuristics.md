# ADR-0017: File heuristics

* **Status:** Accepted
* **Date:** 2026-09-25

## Context

Exact hashes and YARA rules only find what someone has described. The
heuristics design (docs/detection/heuristics.md) listed name, PE, ELF,
script and location heuristics, under the rules that they are explainable,
measured on clean files, never confirmed, and never remediated
automatically. PE and ELF parsing is untrusted-input parsing.

## Decision

1. **A separate crate, `warden-heuristics`**, implementing one `Detector`
   (id `heuristics`) that needs file content. It depends on `warden-core`,
   `object`, `regex` and `memchr`.
2. **Parser: `object`** (read-only features, `elf` and `pe`). It is
   maintained by the gimli-rs project, used by the Rust toolchain and
   `backtrace`, parses without copying, returns errors rather than
   panicking by design, and was already in the dependency tree through
   YARA-X, so it adds no new code. `goblin` was the alternative; it has
   had more panic-on-malformed-input bugs and would be a new dependency.
   Both are fuzzed through our `heuristics` target.
3. **One command-pattern table** (`warden_heuristics::patterns`), shared with
   `warden-system`, which maps pattern kinds to its own `AW-SYS` rules. A
   fix to a pattern applies to both.
4. **Opt-in** (`--heuristics`). The measured clean hit rate is 0.07 per
   10,000 files on 549,615 Linux files, but PE rules could not be measured
   (no Windows corpus). Enabling heuristics by default will be decided per
   rule after a Windows measurement with the included `corpus_eval` tool.
5. **Findings stay reviewable**: `heuristic`/`suspicious`, `low`/`medium`
   confidence, action `review`, concrete evidence, and a combination rule
   (AW-HEU-099) when three or more independent rules match.

## Consequences

* Unknown droppers, packed binaries, disguised executables and malicious
  scripts can be surfaced without signatures, at a measured false-positive
  cost.
* Heuristic findings affect the exit status (1) like any finding, but never
  the quarantine policy.
* `warden-system` now depends on `warden-heuristics` (for the pattern
  table only).
