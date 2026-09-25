# Detection pipeline

Decision record: [ADR-0002](decisions/0002-detection-interface.md).

## Purpose

This pipeline evaluates each scanned object with a set of independent
detection providers and records every conclusion as an explainable,
structured `Finding`. It avoids a single opaque score.

## Inputs and outputs

* **Input to a detector:** a `FileObservation`, which holds the path, the
  SHA-256 of the bytes actually read, `FileMetadata` taken from the open
  handle (size, mtime, Unix mode), the content (if any detector asked for it
  and the file is within `max_content_size`), and the per-file deadline.
* **Output:** `Result<Vec<Finding>, DetectorError>`. Zero or more findings, or
  an error that the scanner records as a `detector_failed` issue.

## The `Detector` contract

```rust
pub trait Detector: Send + Sync {
    fn info(&self) -> DetectorInfo;   // id, version, database name/version/size/signer
    fn requirements(&self) -> DetectorRequirements { .. }   // content: bool
    fn inspect_file(&self, file: &FileObservation<'_>) -> Result<Vec<Finding>, DetectorError>;
    fn worker(&self) -> Box<dyn DetectorWorker + '_> { .. } // per-thread state
}

pub struct FileObservation<'a> {
    pub path: &'a Path,
    pub sha256: &'a Sha256Digest,
    pub metadata: &'a FileMetadata,
    pub content: Option<&'a [u8]>,   // the exact bytes hashed, if requested and ≤ limit
    pub deadline: Instant,           // per-file time budget
}
```

Implementations must:

1. **Never modify the host.** They must not execute, move, delete or write
   the target. Remediation is a separate subsystem.
2. **Be bounded.** Work must be proportional to input size and within
   configured limits, and must stop once `deadline` passes. Content is
   attacker-controlled.
3. **Be thread-safe.** One instance is shared by all workers.
4. **Explain themselves.** Every finding needs evidence and an explanation a
   human can verify.

Panics are caught per detector call (`catch_unwind`), so one faulty detector
cannot abort a scan or suppress other detectors. The release profile keeps
`panic = "unwind"` for this reason.

## Finding semantics

| Field | Meaning |
|---|---|
| `kind` | `known_indicator` (matched a curated indicator), `suspicious`, `heuristic`, `informational` |
| `confidence` | How strongly the evidence supports the conclusion about **this target** (below) |
| `severity` | Impact if true: `info` … `critical` |
| `category` | What the indicator describes: `malware`, `potentially_unwanted`, `test_indicator`, `unknown` |
| `source` | Detector id/version, rule id/version, database name/version |
| `evidence[]` | Machine-typed evidence items, each with a human summary |
| `explanation` | Plain-language reasoning, including its caveats |
| `recommended_action` | `none`, `review` or `quarantine`. **Never performed automatically.** |
| `remediation_status` | Currently always `not_attempted` |

Confidence levels:

* `confirmed`: deterministic match against a curated indicator (exact
  cryptographic hash). It confirms that the file *is* the indicator. Whether
  the indicator is correctly labelled depends on the database; explanations
  say so.
* `high`: strong structural match, such as a well-tested YARA rule on
  specific byte patterns. Not yet produced.
* `medium` / `low`: heuristic or contextual evidence. Not yet produced. Such
  findings must never trigger automatic destructive action.

Unsupported or incomplete checks are not findings. They appear as `issues`,
`skipped` entries, `truncated` counters and `warnings` in the report, so a
reader can tell "nothing found" from "not checked".

## Current providers

| Provider | Detector id | Kind produced | Doc |
|---|---|---|---|
| Exact SHA-256 signatures | `hash-signatures` | `known_indicator` / `confirmed` | [signatures.md](../detection/signatures.md) |
| YARA rules (YARA-X) | `yara-x` | per rule metadata; never `confirmed` | [yara.md](../detection/yara.md) |
| File heuristics (`--heuristics`) | `heuristics` | `heuristic` / `suspicious`, `low` or `medium` | [heuristics.md](../detection/heuristics.md) |

## Content access, per-worker state and time limits

Decision record: [ADR-0006](decisions/0006-content-access-and-time-limits.md).

* **Read once.** The scanner reads each file exactly once. The same bytes
  are hashed and, when a detector declares `requirements().content`, kept in
  a per-worker buffer and shared read-only with every detector. No memory
  mapping (it would need `unsafe`, and truncation during the scan raises
  SIGBUS).
* **Bounded.** Content is kept only for files ≤ `max_content_size` (default
  64 MiB). Worst case is `workers × max_content_size`; buffers shrink to
  8 MiB between files. Larger files are still hashed and hash-matched;
  content detectors are skipped and a `content_not_inspected` entry records
  the gap.
* **Per-worker state.** `Detector::worker()` is called once per scan thread
  (and again after a panic). YARA uses it to reuse one YARA-X scanner; about
  50× cheaper than creating one per file.
* **Time limit.** `file_timeout_ms` (default 60 s) becomes the observation's
  deadline. Reading stops between chunks once it passes (`timeout` issue);
  remaining detectors are skipped and named (`timeout` issue); YARA-X gets
  the remaining time as its scan timeout.

## Testing approach

* Unit tests per provider (`crates/engine/src/signatures.rs`).
* Integration tests with synthetic fixtures (`crates/engine/tests/scan.rs`),
  including faulty and panicking detectors.
* Fuzzing of every parser that consumes untrusted rule/database input
  (`fuzz/`).
