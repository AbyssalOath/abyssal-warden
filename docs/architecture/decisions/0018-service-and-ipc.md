# ADR-0018: Service, local IPC and privilege separation (Linux)

* **Status:** Accepted
* **Date:** 2026-09-25
* **Implements:** [privilege-model.md](../../security/privilege-model.md),
  with the changes recorded below.

## Context

Phase 7 of the work plan: a background service with scheduled scans and
persistent history, authenticated local IPC, and privilege separation. The
known limitations it addresses:
* scans that hang in the kernel cannot be killed;
* nothing compares the quarantine audit log with the system log;
* unprivileged runs cannot see everything;
* parsers of untrusted content run with the invoking user's privileges.

The workspace forbids `unsafe` code.

## Decision

1. **Three pieces.** `warden-ipc`: a pure protocol with framing,
   validation and the authorisation matrix. `warden-service`: the daemon
   library. `abyssal-wardend`: the daemon binary, shipped in the CLI
   package next to `abyssal-warden`, whose `service` subcommand is the
   client.
2. **Transport:** a Unix stream socket (default
   `/run/abyssal-warden/wardend.sock`, mode 0666, or 0660 with
   `socket_group`). The peer is identified by the kernel with `SO_PEERCRED`
   when it connects. There is no network listener.
3. **Protocol:** 4-byte big-endian length plus JSON, versioned. Requests
   are limited to 64 KiB (checked before allocation), unknown operations
   and fields are rejected (every operation is a struct variant so serde
   enforces `deny_unknown_fields`), and there are 30-second I/O timeouts,
   at most 64 connections and 1,000 requests per connection. Paths must
   be absolute UTF-8 without NUL.
4. **Authorisation** (`warden_ipc::policy`, checked on every request after
   validation):
   * Anyone may ping, see status, start scans, and list, read or cancel
     **their own** jobs.
   * Administrators may also run system checks, quarantine, restore,
     delete, start schedules, verify the audit log, and see all jobs.
   * Jobs owned by someone else are reported as not found.
   * **Administrators** are root, users listed in `admin_users`, and
     members of `admin_group` (read from `/etc/group`, including primary
     groups).
   * *Change from the design:* polkit is not used yet. It needs a D-Bus
     client and an authentication agent, and a socket client has neither;
     group-based authorisation is what polkit's own default rules do for
     local administrators.
5. **Privilege separation without unsafe code.** Every scan and system
   check runs in a separate `abyssal-warden` child process started through
   util-linux `setpriv`:
   * **Administrator and scheduled jobs** run as the dedicated
     `abyssal-warden` account. They keep only `CAP_DAC_READ_SEARCH` (plus
     `CAP_SYS_PTRACE` for system checks) in the ambient, inheritable and
     bounding sets, with `no_new_privs` and no supplementary groups. They
     can read everything and write nothing they do not own.
   * **Jobs requested by other users** run as that user, with their groups
     and no capabilities, so the kernel enforces that they scan only what
     they could read themselves.
   * Children have their own process group, a minimal environment, `/` as
     working directory, bounded output (256 MiB) and a deadline; cancelling
     or timing out kills the whole group.
   * Allow-listing and quarantine happen in the service after it has read
     the report, never in the child. The child receives
     `--no-allowlist` and never `--quarantine`.
   * *Change from the design:* seccomp/landlock sandboxes for the parsers
     are not added yet; the capability and identity drop is the boundary.
   * Setting capabilities across a uid change needs `prctl`/`capset`, which
     is `unsafe` from Rust. `setpriv` performs exactly this and is present
     wherever systemd is. The drop is verified by a test in a user
     namespace with subordinate ids: the child can read another uid's 0600
     file only with the capability, and cannot write it.
6. **Jobs and history:** a bounded queue (default 32) and 1 to 8 workers.
   Summaries and reports are stored as 0600 files in 0700 directories owned
   by the service, pruned to `history_limit`. Jobs interrupted by a
   shutdown are marked failed on restart.
7. **Schedules** (UTC): every N hours, or every N days at `HH:MM`. A run
   missed while the machine was off runs once at start, never repeatedly.
8. **Audit comparison:**
   * The service periodically, and on request, verifies the quarantine
     chain and compares it with the anchors journald attributes to its own
     uid (`_UID`, supplied by the kernel).
   * Anchors now carry a chain identifier (`chain=`, the first entry's hash
     prefix), so anchors from other stores are not confused with this one.
   * Audit entries record `on_behalf_of` (the IPC caller) next to the
     actor.
9. **Configuration** (`/etc/abyssal-warden/service.json`) must be
   root-owned and not group- or world-writable when the service runs as
   root; the same applies to the scanner binary. Unknown fields are
   rejected.
10. **Windows is deferred** to Phase 8. Named-pipe DACLs and client-token
    identification need Win32 security calls (`unsafe`). The protocol and
    policy are platform-neutral and will be reused.

## Consequences

* Scheduled and on-request scans run with read-only privileges; a
  compromised parser in a child cannot modify the system or the store.
* A hung scan is killed at its deadline instead of leaking a thread.
* Tampering with the quarantine audit log is detected automatically and
  logged, unless the attacker is root on the running system.
* The service needs util-linux `setpriv`, a `abyssal-warden` account and
  (for `socket_group`/`admin_group`) the groups in
  `packaging/linux/abyssal-warden.sysusers`.
* In development mode (not root) the service runs jobs with its own
  identity and refuses to scan on behalf of other users.
