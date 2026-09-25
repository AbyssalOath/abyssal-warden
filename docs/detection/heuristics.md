# Heuristic analysis

**Status: design. No heuristics are implemented.** Abyssal Warden 0.1.0
produces no `heuristic` or `suspicious` findings.

## Principles

* Heuristic findings are `kind = heuristic` or `suspicious`, with
  `confidence` of `low` or `medium` (rarely `high`). They are never labelled
  as confirmed malware.
* Each heuristic has a documented rationale, known false-positive sources,
  and a measured false-positive rate on a clean corpus
  ([testing.md](testing.md)) before it is enabled by default.
* The evidence lists the concrete observations (for example "section `.text`
  entropy 7.92; imports `VirtualAllocEx`, `WriteProcessMemory`"), so a human
  can verify it.
* Heuristics never trigger automatic remediation.
* Heuristics are separate detectors, so they can be enabled, disabled and
  versioned individually.

## Candidate heuristics, in rough order

1. **Format/extension mismatch**: executable magic (`MZ`, `\x7fELF`) with a
   document or image extension; double extensions; bidi overrides in names.
2. **PE structure anomalies**: sections both writable and executable, entry
   point outside code sections, high-entropy sections that suggest packing,
   invalid or missing Authenticode on files in system locations.
3. **ELF anomalies**: stripped binaries in unusual locations, writable
   executable segments, `DT_RPATH` to world-writable directories.
4. **Location and context**: executables in temp or download directories
   with recent mtime; scripts with obfuscation markers.

Parsers for items 2 and 3 are untrusted-input parsers. They must be fuzzed
and must be memory-safe crates (candidates: `goblin`, `object`), evaluated
before adoption.
