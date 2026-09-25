# ADR-0015: Linux persistence inventory and integrity checks

* **Status:** Accepted
* **Date:** 2026-09-25

## Context

File scanning finds known-bad content. It does not answer "what on this
system starts automatically?" or "is the running system lying to me?".
Those are the questions persistence enumeration and rootkit checks answer.
They are also the prerequisite for persistence cleanup. The design must stay
honest: a kernel rootkit controls every view a process inside the OS can
read.

## Decision

1. **A separate crate, `warden-system`**, depending only on `warden-core`.
   It returns a `SystemReport` (schema v1) with check results, findings, the
   full persistence inventory and issues. The CLI command is `system-check`.
   It is not a `Detector`, because it inspects configuration and kernel
   state rather than individual files.
2. **Inventory everything, flag little.** Every persistence entry is listed
   (systemd units and timers, cron and anacron, `ld.so.preload`, shell
   startup files, environment files, XDG autostart, SSH `authorized_keys`,
   PAM, `rc.local`, udev). Findings come from a small catalogue of
   documented rules (`AW-SYS-001` and up,
   [system-checks.md](../../detection/system-checks.md)). Heuristic
   findings never have `confirmed` confidence and never trigger remediation.
3. **Reads confined to the inspected root.** Every configuration file is
   opened with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` relative
   to a handle on the root. With `--root` pointing at a mounted image, the
   image's absolute symlinks resolve inside the image and cannot reach the
   host. Reads are bounded (1 MiB), non-blocking and only of regular files.
   Paths in the report are the *logical* paths inside the inspected system.
4. **Kernel and process checks only on the running system**: loaded-module
   cross-view (`/proc/modules` against `/sys/module/*/initstate`, confirmed
   by a second read), taint flags, a hidden-PID sweep (every PID up to
   `pid_max` probed directly and compared with the `/proc` listing, threads
   excluded, candidates re-confirmed against a fresh listing), and deleted
   executables in writable locations (including `memfd`). Offline, they are
   reported as `skipped`, never as clean.
5. **Package verification through the package manager.** `rpm -V` or
   `dpkg --verify` are run from fixed absolute paths with an empty
   environment, `LC_ALL=C`, a timeout, bounded output and (for rpm)
   `--noscripts --nodeps`, so no package script runs. By default only the
   packages that own critical binaries and libraries, and the programs
   persistence entries start, are verified; `--verify-all-packages` does
   everything. Only digest changes to non-configuration files are reported.
   Reimplementing rpm and dpkg database parsing in Rust was rejected: it is
   large, and it would not make the database itself more trustworthy.
6. **Correlation with content detection.** With detection content given,
   the executables that persistence entries start are resolved inside the
   root and scanned with the normal engine, and a hit produces
   `AW-SYS-016` on the persistence entry. The scan is included in the report
   (`referenced_files`).
7. **Secrets are not copied.** Environment values in systemd units and
   environment files often hold tokens. Only dynamic-loader variables
   (`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`) are recorded; other lines
   appear only when a rule matches them. Commands (cron lines, `ExecStart`)
   are recorded as they are, so reports can still contain sensitive command
   lines and should be handled accordingly.
8. **Exit status:** 1 if a non-informational finding exists, 3 if any check
   was partial, failed or unsupported (or an issue was recorded), 0 only for
   complete, clean runs.

## Consequences

* Every Linux persistence location in the list has an inventory, and the
  suspicious patterns that matter most (download-and-run, reverse shells,
  temp-directory programs, preload injection, writable root-run programs,
  PAM backdoors) are flagged.
* A clean result is explicitly not proof of absence. The report always says
  so, and the recommended trustworthy check is offline (`--root`) from
  known-good media.
* Running unprivileged gives partial coverage, which the checks report.
* Package verification trusts the inspected system's package database and
  the host's rpm or dpkg binary.
* Windows persistence (Run keys, services, scheduled tasks, WMI) remains
  planned (Phase 8).
