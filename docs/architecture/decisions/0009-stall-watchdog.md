# ADR-0009: Stall watchdog, whole-scan time limit and detached scan threads

* **Status:** Accepted (amends ADR-0006)
* **Date:** 2026-09-25

## Context

ADR-0006's per-file time limit is cooperative. Two cases escape it:

* a `read(2)` blocked in the kernel on a hung network or FUSE filesystem,
  which no user-space code can interrupt;
* a detector that ignores `FileObservation::deadline`.

With scoped threads (`std::thread::scope`), `Scanner::scan` could not return
until every thread had exited, so a single stuck file hung the whole scan.
There was also no limit on total scan time.

## Options

| Option | Result |
|---|---|
| Keep scoped threads; document | Scans can hang indefinitely |
| Kill the stuck thread | Not possible in safe Rust (or safely at all: it may hold locks) |
| Scan each file in a child process | Real isolation, but a large redesign and per-file process cost; better done with the service |
| **Detached threads, abandon stuck workers** | Scan always finishes; the stuck thread lives on harmlessly until its call returns or the process exits |

## Decision

* Walker and workers are ordinary threads that share state through `Arc`.
  Detectors are held as `Arc<dyn Detector>`. `Detector::worker` still borrows
  the detector, from the thread's own `Arc`, so still no `unsafe`.
* The caller's thread coordinates. It receives results with a 50 ms tick,
  and on each tick:
  * applies the **whole-scan time limit** (`scan_timeout_ms`, CLI
    `--scan-timeout`), stopping the scan with status `time_limit_reached`;
  * propagates user cancellation to an internal stop token;
  * runs the **watchdog**: a worker still on the same file more than
    `file_timeout + 2 s` after starting it is abandoned. The file is reported
    as a `timeout` issue, the worker is detached, and a replacement is
    started (at most `workers` replacements per scan). An abandoned worker
    exits instead of taking more work once its stuck call returns.
* Termination is by explicit exit messages (a drop guard sends one even if
  the thread panics), not by channel disconnection, because an abandoned
  thread still holds a sender.
* Queued-versus-taken counters make sure work never silently disappears. If
  every worker stalled before the queue drained, the scan reports
  `time_limit_reached` and an issue stating how many files were never
  scanned.
* The walker queues work with `try_send` plus the stop token, so it cannot
  block forever on a queue that no worker drains.

## Consequences

* Every scan finishes, and every file is accounted for as scanned, skipped,
  or an issue.
* An abandoned thread keeps its resources (content buffer up to
  `max_content_size`, one file descriptor) until its blocked call returns or
  the process exits. The report warns when this happens. Capping
  replacements bounds the total.
* The grace period (2 s) covers YARA-X's one-second timeout granularity.
* True isolation of hostile inputs (killable per-file processes) remains
  future work, together with the service (Phase 7).
