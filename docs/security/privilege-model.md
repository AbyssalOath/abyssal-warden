# Privilege model

**Status: design.** Only the unprivileged CLI exists. This document defines
the rules the service, IPC and GUI must follow when they are built. An ADR is
recorded before implementation.

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

## Transport and authentication (planned)

| Platform | Transport | Peer authentication |
|---|---|---|
| Linux | Unix domain socket in `/run/abyssal-warden/`, directory 0750 root:`abyssal-warden` | `SO_PEERCRED` (uid/gid/pid) checked on every connection |
| Windows | Named pipe with an explicit DACL (SYSTEM, Administrators, Interactive Users: connect), `PIPE_REJECT_REMOTE_CLIENTS` | Client token via `ImpersonateNamedPipeClient` / `GetNamedPipeClientProcessId` |

Messages use a versioned, size-limited schema (`warden-ipc`, planned). The
service rejects unknown request types, oversized messages and malformed
fields, and closes idle connections.

## Authorisation matrix (planned)

| Action | Unprivileged local user | Administrator / root |
|---|---|---|
| Scan paths the caller can read | allowed (in-process, no service needed) | allowed |
| Ask the service to scan paths the caller cannot read | denied | allowed |
| View own scan history | allowed | allowed |
| View all scan history, audit log | denied | allowed |
| Quarantine a file | denied, unless policy allows users to quarantine files they own | allowed, audit-logged |
| Restore from quarantine | denied | allowed, with confirmation, audit-logged |
| Permanently delete | denied | allowed, with confirmation, audit-logged |
| Change schedules, exclusions, policy | denied | allowed, audit-logged |
| Trigger database update | allowed (the update itself is verified) | allowed |

On Linux, administrator actions are authorised with polkit. On Windows,
membership of Administrators is checked on the client token. The GUI never
elevates itself.

## Service hardening checklist (planned)

* Linux systemd unit: `NoNewPrivileges=yes`, `ProtectSystem=strict` with
  explicit `ReadWritePaths` for state and quarantine, `PrivateTmp=yes`,
  `ProtectKernelModules=yes`, `RestrictAddressFamilies=AF_UNIX`,
  `SystemCallFilter=@system-service`, `CapabilityBoundingSet` limited to what
  scanning and remediation need (e.g. `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`).
* Windows: service SID type restricted, no `SeDebugPrivilege` unless process
  scanning needs it (documented when it does). Protected-process
  registration requires Microsoft programmes (see
  [windows.md](../platform/windows.md)).
* Scanning parsers may run in a lower-privileged child process
  (seccomp/landlock on Linux, AppContainer on Windows), with the privileged
  parent doing only file-handle brokering and remediation.

## Testing requirements (when implemented)

* Every IPC request type: unauthenticated, unauthorised and malformed variants
  are rejected (unit and integration tests).
* Fuzzing of the IPC decoder.
* Tests that a non-admin client cannot trigger quarantine, restore, delete or
  policy changes.
