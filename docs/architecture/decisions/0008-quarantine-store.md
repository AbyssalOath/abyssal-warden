# ADR-0008: Quarantine store and remediation safety model

* **Status:** Accepted
* **Date:** 2026-09-24

## Context

`docs/security/quarantine.md` set the safety model to be in place before any
destructive code was written. This records the implementation decisions and
where they differ from that design.

## Decision

* **New crate `warden-remediation`**, the only code allowed to move or
  delete files. The engine does not depend on it.
* **Linux only for now.** The implementation relies on `openat2`
  (`RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, Linux ≥ 5.6),
  `renameat2(RENAME_NOREPLACE)` and handle-relative `unlinkat`, through
  `rustix`'s safe wrappers. Other platforms return `Unsupported` rather than
  get a weaker implementation. Windows needs a DACL-hardened store and
  by-handle operations (future work).
* **Per-item record = journal entry.** States: `pending → quarantined →
  restored | deleted`, or `rolled_back | failed`. Records are replaced
  atomically (temp file, fsync, rename, fsync directory).
* **Sequence:** copy to `<id>.data.tmp` → fsync → re-read and verify →
  compare with the expected hash → write `pending` record → rename to
  `<id>.data` → confirm same inode → `unlinkat` original → fsync →
  `quarantined`. This differs from the design doc by writing the record
  *after* the copy, so a crash before that point leaves only a stray temp
  file, which is deleted on the next open. Every crash point is covered by a
  fault-injection test.
* **Encoding:** 8-byte header plus XOR with a random 32-byte per-item key.
  This makes the file inert, not secret.
* **Automatic remediation policy** (`scan --quarantine`): only
  `known_indicator` + `confirmed` + `malware` + recommended `quarantine`,
  with the hash from the finding required to match at quarantine time, and
  never under protected system directories. Everything else is marked
  `not_eligible` with a reason.
* **Restore** requires `--yes`, never overwrites, refuses group- or
  world-writable directories and directories owned by other users, and
  drops setuid/setgid bits.
* **Audit log:** hash-chained JSON Lines. The store refuses to open if the
  chain is broken.
* **Hard-linked files are refused**, because removing one name would leave
  the content reachable through the others.

## Consequences

* The store is per effective user (`~/.local/share/...` for users,
  `/var/lib/abyssal-warden/quarantine` for root). A user can quarantine only
  files they can delete. There is no privilege separation until the
  service exists.
* The audit chain detects edits, deletions and reordering. It does not stop
  someone who can rewrite the whole file; that needs an external anchor.
* Running processes are not stopped, and persistence entries that
  reference a quarantined file are not cleaned up.
