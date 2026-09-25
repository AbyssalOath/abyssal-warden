# ADR-0014: Allow-list, audit anchoring, and stopping running malware

* **Status:** Accepted (extends ADR-0008)
* **Date:** 2026-09-25

## Context

Known limitations of the quarantine subsystem:

1. A restored file is detected, and possibly re-quarantined, by the next scan.
2. The audit log is tamper-evident only against partial edits: someone who
   can write the store can rewrite the whole chain.
3. Quarantining a running program leaves it running.

## Decision

1. **Allow-list by exact SHA-256**, stored as `allowlist.json` in the
   private store and written atomically. A restore adds the file's hash
   unless `--no-allow` is given. Scans mark matching findings
   `remediation_status: allowed`: they are **still reported**, never hidden,
   but excluded from automatic quarantine and from exit status 1. Managed
   with `quarantine allowlist list|remove`; every change is audit-logged.
   `scan --no-allowlist` ignores it.
2. **External anchor for the audit chain.** After each audit entry is
   written, `seq`, the entry's SHA-256, the action and the outcome are sent
   to syslog (`/dev/log`, `authpriv.notice`, tag `abyssal-warden`; journald
   listens there). Unprivileged users cannot delete or rewrite system
   journal entries, so a rewritten local chain no longer matches its
   anchors. `quarantine verify-log` prints the head to compare. Only fixed
   ASCII fields are sent (no paths or names), which prevents log injection
   and keeps file names out of the system log. Failure to anchor is a
   warning, not an error (the store still works where syslog is absent).
   `ABYSSAL_WARDEN_SYSLOG_SOCKET` redirects anchors (empty value: off); the
   library takes an explicit `AnchorTarget`.
3. **Processes using the file.** Before moving it, the store finds
   processes that map the exact file (device and inode in
   `/proc/<pid>/maps`: executables and shared libraries, including after
   deletion). They are always recorded in the item's notes. With
   `--kill-processes` they are paused (SIGSTOP) before the move and killed
   (SIGKILL) only after the file is safely stored. A guard resumes them
   (SIGCONT) if the quarantine fails for any reason, including panics.

## Consequences

* Restoring a false positive "sticks", while staying visible in reports.
* Anchoring detects rewrites only if someone compares with the journal;
  automated comparison needs a privileged component (the service, Phase 7).
  A root attacker can still tamper with both.
* Scripts run by an interpreter are not found (the script is read, not
  mapped). Processes of other users are invisible without root. A process
  started between the check and the move is not stopped. Persistence
  cleanup is separate (Phase 5).
