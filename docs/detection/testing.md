# Detection evaluation methodology

This document defines how detection quality will be measured. **No detection
rate has been measured or is claimed for Abyssal Warden.** Unit and
integration tests prove that the mechanisms work on synthetic fixtures; they
say nothing about real-world protection.

## Rules for any published claim

A detection or false-positive figure may be published only together with:

1. the exact engine version, detector versions and database versions;
2. the test population: source, collection dates, size, file-type mix, and
   how "malicious" and "clean" labels were established;
3. the configuration (limits, enabled detectors);
4. the metric definitions below;
5. known biases (e.g. a hash database evaluated on the same feed it was built
   from will score near 100% and mean nothing).

## Metrics

| Metric | Definition |
|---|---|
| Detection rate | Malicious samples with ≥1 finding of `kind ∈ {known_indicator, suspicious, heuristic}` ÷ malicious samples scanned. Reported per kind and per confidence level |
| False-positive rate | Clean files with any such finding ÷ clean files scanned. Reported per detector |
| Coverage | Files actually scanned ÷ files present (skips and issues reduce it) |
| Throughput | Bytes/s and files/s, warm and cold cache, stating the storage type |
| Memory | Peak RSS (`/usr/bin/time -v` or equivalent) |
| CPU | CPU seconds per GB scanned |
| Detection latency | For on-access (future): time from file creation to finding |
| Remediation success | For quarantine (future): items quarantined and verified ÷ attempted; restore round-trip success |

## Corpora

* **Clean corpus:** fresh installations of supported Windows and Linux
  versions and common application sets, hashed and version-recorded. Every
  default-enabled detector is measured against it.
* **Malicious corpus:** only from sources whose terms permit research use,
  handled only in isolated, disposable VMs without network egress. Samples
  are **never** committed to this repository or stored on CI runners.
  Evaluation results record sample hashes, not samples.
* **Temporal split:** when measuring any detector built from a feed, evaluate
  on samples first seen *after* the detector's content was frozen.

## Current evidence

| Area | Evidence |
|---|---|
| Hash matching correctness | Unit and integration tests with synthetic indicators |
| Traversal and hardening | Integration tests (symlinks, loops, FIFOs, permissions, hostile names, limits) |
| Parser robustness | Fuzzing with ASan, 2026-09-24, no crashes: signature DB parser 8.3M + 8.1M executions (2 × 60s); digest parser 56M / 60s; audit-log verifier 8.8M / 90s; YARA-X with all enabled format modules ~104k inputs / 7 min |
| YARA scanner reuse | 500 rules, 4 KiB input: create ~226 µs vs scan ~4.5 µs (`crates/yara/examples/scanner_cost.rs`) |
| Throughput and memory | Informal, `/usr/share`, 46,423 files / 659 MiB, warm cache, NVMe, 8 workers: hash only 0.95s / 4 MB peak RSS; hash + YARA (content buffered) 1.12s / 72 MB peak RSS |
| Real-world detection rate | **Not measured** |
