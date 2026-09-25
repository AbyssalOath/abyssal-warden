# ADR-0006: Content access, per-worker detector state, per-file time limit

* **Status:** Accepted (amends ADR-0002); thread model and stall handling amended by [ADR-0009](0009-stall-watchdog.md)
* **Date:** 2026-09-24

## Context

Content detectors (YARA now, format parsers later) need the file's bytes.
ADR-0002 deferred the design until the first real content detector existed.
The YARA integration also showed that some detectors need expensive
per-thread state. Finally, a hostile or stalled file must not be able to
hold a worker indefinitely.

## Decision

**Read once, bounded, shared.**
* `Detector::requirements()` declares `content: bool`.
* The scanner reads each file exactly once. It hashes the bytes and, if any
  detector needs content and the file is at most `max_content_size`
  (default 64 MiB), keeps them in a per-worker buffer. Every detector sees
  the same bytes as `FileObservation::content: Option<&[u8]>`.
* Files over the limit are still hashed and hash-matched. Content detectors
  are not called for them, and the report records a `content_not_inspected`
  skip for each, so the gap is visible.
* No memory mapping: it needs `unsafe` (forbidden workspace-wide) and a file
  truncated during the scan can crash the process (SIGBUS). Worst-case
  buffer memory is `workers × max_content_size`. Buffers are shrunk to 8 MiB
  between files.

**Per-worker detector state.**
* `Detector::worker(&self) -> Box<dyn DetectorWorker + '_>` is called once
  per worker thread per scan, and again after a panic. The worker may borrow
  the detector (each scan thread holds the detector through an `Arc`), so
  this needs no `unsafe`. The default forwards to `inspect_file`, so stateless detectors are
  unaffected.

**Per-file time limit.**
* `file_timeout_ms` (default 60 s) sets `FileObservation::deadline`.
* It is enforced cooperatively: between read chunks (the file becomes a
  `timeout` issue and is not evaluated), before each detector (remaining
  detectors are skipped and named in a `timeout` issue), and inside
  detectors that honour the deadline (YARA passes it to YARA-X).

## Consequences

* A single blocking `read(2)` on a hung network or FUSE filesystem cannot be
  interrupted and can exceed the limit. [ADR-0009](0009-stall-watchdog.md)
  adds a watchdog that abandons such workers so the scan still finishes.
* A detector that ignores the deadline can overrun it. The contract in
  `detector.rs` requires honouring it.
