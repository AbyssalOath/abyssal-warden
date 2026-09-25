# Quarantine and remediation

**Status: implemented on Linux** (`crates/remediation`,
[ADR-0008](../architecture/decisions/0008-quarantine-store.md)). **Not
available on Windows or other platforms**: the store returns "not supported"
there.

## Purpose, inputs, outputs

* **Purpose:** make a detected file inert and inaccessible without
  destroying it. Every action is reversible (except explicit deletion),
  auditable and crash-safe.
* **Inputs:** a `QuarantineRequest` (absolute path, expected SHA-256,
  reason, size limit), or a finding that meets the automatic policy.
* **Outputs:** a `QuarantineRecord`, an audit-log entry, and, for
  `scan --quarantine`, the finding's `remediation_status` /
  `remediation_detail`.

## Store

| | Location | Protection |
|---|---|---|
| root | `/var/lib/abyssal-warden/quarantine` | created 0700, must be owned by the effective user with no group/other access, never opened through a symlink |
| other users | `$XDG_DATA_HOME/abyssal-warden/quarantine` (or `~/.local/share/...`) | same checks |

`--store DIR` overrides the location. An exclusive `flock` stops two
processes from using the store at once.

```text
<store>/.lock
<store>/audit.log            hash-chained JSON Lines
<store>/items/<id>.json      record + journal state (0600)
<store>/items/<id>.data      "AWQDATA1" + content XOR a random 32-byte key (0600)
```

IDs are 128-bit random hex values. User-supplied IDs are parsed strictly,
so an ID can never be a path.

## Quarantine

```mermaid
sequenceDiagram
    participant S as Store
    participant D as Parent dir (pinned fd)
    S->>D: openat2(parent, RESOLVE_NO_SYMLINKS)
    S->>D: openat(name, O_NOFOLLOW|O_NONBLOCK); fstat: regular, size, nlink == 1
    S->>S: copy encoded to <id>.data.tmp, fsync, re-read + verify hash
    S->>S: compare with expected hash (else: discard copy, nothing changed)
    S->>S: write record "pending" (atomic)
    S->>S: rename to <id>.data, fsync items/
    S->>D: statat(name): same dev/inode? then unlinkat(name); fsync dir
    S->>S: record "quarantined"; audit "ok"
```

Refused, with nothing changed: relative paths or paths with `..`; any
symbolic link in any path component; non-regular files; files over the size
limit; files with more than one hard link; files inside the store; files
under protected system directories (`/bin`, `/boot`, `/dev`, `/etc`,
`/lib*`, `/proc`, `/sbin`, `/sys`, `/usr`, `/var/lib/dpkg`, `/var/lib/rpm`)
unless `--allow-protected` is given for a manual quarantine; content that no
longer matches the expected hash.

## Recovery

Each item's record is its journal entry. Opening the store replays
unfinished (`pending`) items:

| Found on open | Action | Resulting state |
|---|---|---|
| Original still present (same inode) | discard the copy | `rolled_back` |
| Original gone, copy verifies | keep the copy | `quarantined` |
| Original gone, no verified copy | record the loss | `failed` |
| Stray `*.data.tmp` without a record, stray record temps | delete | - |

A crash at each step (after the pending record, after the copy is
committed, after the original is removed) is simulated by fault-injection
tests.

## Restore and delete

* `quarantine restore ID --yes [--to DIR]`: writes to a temporary name,
  verifies the hash, sets the mode (without setuid/setgid), sets the owner if
  running as root, fsyncs, then `renameat2(RENAME_NOREPLACE)` (falling back
  to `link(2)`, which also never replaces). Refuses if the target exists; if
  the directory is missing, reached through a symlink, group/world-writable,
  owned by another user, or inside the store.
* `quarantine delete ID --yes`: removes the content and keeps the record
  (`deleted`) for the audit trail.

## Automatic remediation policy

`scan --quarantine` acts only on findings that are **all** of:
`known_indicator`, confidence `confirmed`, category `malware`, recommended
action `quarantine`, and a file target with a hash (in practice: an exact
match in a hash database), and not under a protected directory. The
quarantine re-checks the hash, so a file that changed after the scan is left
alone. All other findings are marked `not_eligible` with the reason. YARA,
heuristic and test-indicator findings are never remediated automatically.

## Audit log

Each line holds `seq`, time, the acting uid, action, item, path, hash,
outcome, detail and `prev` (SHA-256 of the previous line).
`quarantine verify-log` checks the chain, and the store **refuses to open**
if it is broken.

## Guarantees

* No data loss on crash: the original is removed only after a verified,
  fsynced copy and a committed journal entry exist.
* No symlink following anywhere in the path, and removal only of the inode
  that was copied.
* Restore never overwrites and never writes into a directory other users can
  write to.
* Every operation and every failure is in the audit log.

## Not guaranteed

* **Running processes** keep executing; quarantine does not kill them.
* **Persistence** (services, cron, autostart entries) that references the
  file is not cleaned up.
* **Rootkit-protected or locked files** may not be removable.
* A narrow race remains between the inode check and `unlinkat`: an attacker
  who can write the parent directory could swap the name in that instant.
  Only a name in that same directory is affected, one the attacker could
  already delete. Kernel `protected_hardlinks` stops hard-linking other
  users' files into place.
* The audit chain does not stop someone who can rewrite the whole file (no
  external anchor yet).
* Stored content is only XOR-encoded (inert, not encrypted).
* No privilege separation: the CLI acts with the invoking user's rights until
  the service exists.
* Restored files are not added to an allow-list and will be detected again
  by the next scan.
