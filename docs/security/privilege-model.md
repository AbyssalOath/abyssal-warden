# Privilege model

**Status: implemented on Linux** ([ADR-0018](../architecture/decisions/0018-service-and-ipc.md),
[user guide](../user/service.md)); Windows follows in Phase 8. Where the
implementation differs from the original design, this document states the
implemented behaviour and the ADR records why.

## Principles

1. **Least privilege per process.** The GUI and CLI never run elevated for
   normal use. Only the service may hold elevated rights, and it drops what it
   does not need (Linux: capabilities rather than full root where feasible,
   systemd sandboxing; Windows: a dedicated service SID with only the rights
   it needs).
2. **Detection runs with the least privilege that can read the target.**
   Scanning a user's own files does not need the service.
3. **Privileged actions are requests, not commands.** Clients ask; the
   service authenticates the peer, authorises the action against policy,
   validates every argument, then acts and audit-logs.
4. **No network listener.** There is no TCP/HTTP API on localhost or
   anywhere else.

## Transport and authentication

| Platform | Transport | Peer authentication |
|---|---|---|
| Linux (implemented) | Unix stream socket `/run/abyssal-warden/wardend.sock`, 0666 (or 0660 with `socket_group`); every request is authorised | `SO_PEERCRED` (uid) captured by the kernel at connect |
| Windows (Phase 8) | Named pipe with an explicit DACL (SYSTEM, Administrators, Interactive Users: connect), `PIPE_REJECT_REMOTE_CLIENTS` | Client token via `ImpersonateNamedPipeClient` / `GetNamedPipeClientProcessId` |

Messages use the versioned, size-limited schema in `warden-ipc`. The
service rejects unknown request types, unknown fields, oversized messages
and malformed arguments, and closes idle connections.

## Authorisation matrix

| Action | Unprivileged local user | Administrator / root |
|---|---|---|
| Scan paths | allowed; the scan runs **as the caller**, so it reads only what they can | allowed; runs as the scanner account (reads everything) |
| View, fetch reports of, cancel jobs | own jobs only (others' are "not found") | all |
| Quarantine automatically after a scan | denied | allowed, audit-logged with the requester |
| List, restore, delete quarantined items | denied | allowed, audit-logged with the requester (delete needs `--yes` in the CLI) |
| System check, start a schedule, verify the audit log | denied | allowed |
| Change schedules, policy | only by editing the root-owned configuration | same |
| Trigger database update | planned (updater) | planned |

Administrators are root, `admin_users` and members of `admin_group`
(`/etc/group`). polkit is not used yet (see ADR-0018). On Windows,
membership of Administrators will be checked on the client token. The GUI
never elevates itself.

## Service hardening

* Linux systemd unit (`packaging/linux/abyssal-wardend.service`,
  implemented): `NoNewPrivileges=yes`, `ProtectSystem=full`, kernel
  protections, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`,
  `SystemCallFilter=@system-service`, `CapabilityBoundingSet` limited to
  reading, quarantine, identity switching, killing and process inspection.
  *Changed from the design:* `ProtectSystem=strict` and `PrivateTmp` would
  hide or freeze the files the scanner must see and quarantine; the
  quarantine policy already never touches `/usr`, `/boot` or `/etc`, which
  `ProtectSystem=full` makes read-only.
* Windows: service SID type restricted, no `SeDebugPrivilege` unless process
  scanning needs it (documented when it does). Protected-process
  registration requires Microsoft programmes (see
  [windows.md](../platform/windows.md)).
* **Implemented (Linux):** parsers run in a lower-privileged child process
  (the scanner account with only `CAP_DAC_READ_SEARCH`, or the requesting
  user with no capabilities, `no_new_privs`, via `setpriv`); the privileged
  parent only reads the report and performs remediation.
  Planned: seccomp/landlock inside the child; AppContainer on Windows.

## Testing

* Every request type against both roles (the authorisation matrix unit
  test); unknown operations, unknown fields, wrong versions, invalid
  arguments and oversized frames against a running daemon.
* The `ipc-decode` fuzz target (decoding, validation, authorisation).
* A running daemon refuses quarantine, restore, delete, system checks,
  schedules and audit verification to non-administrators, and runs their
  scans with their own identity.
* The privilege drop itself is verified in a user namespace (see ADR-0018).
