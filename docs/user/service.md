# The service (`abyssal-wardend`, Linux)

The service runs scheduled and on-request scans and system checks in the
background, keeps their history, and lets administrators manage the
quarantine store, all over a local socket. Scans run in separate processes
with reduced privileges. Design: [ADR-0018](../architecture/decisions/0018-service-and-ipc.md),
[privilege model](../security/privilege-model.md).

## Install

```sh
install -m 0755 abyssal-warden abyssal-wardend /usr/bin/
install -m 0644 packaging/linux/abyssal-wardend.service /etc/systemd/system/
install -m 0644 packaging/linux/abyssal-warden.sysusers /usr/lib/sysusers.d/abyssal-warden.conf
systemd-sysusers                       # creates the abyssal-warden account and admin group
install -d -m 0755 /etc/abyssal-warden
install -m 0644 packaging/linux/service.json /etc/abyssal-warden/service.json
systemctl daemon-reload && systemctl enable --now abyssal-wardend
usermod -aG abyssal-warden-admin alice # make alice an administrator
```

Requirements: Linux 5.6 or later, systemd, util-linux `setpriv`.

## Using it

```sh
abyssal-warden service status
abyssal-warden service scan ~/Downloads --heuristics --wait   # runs with your own permissions
sudo abyssal-warden service scan /srv --quarantine --wait     # administrator: scanner account
abyssal-warden service jobs
abyssal-warden service report <JOB-ID> [--format json]
abyssal-warden service cancel <JOB-ID>
abyssal-warden service schedules
abyssal-warden service run-schedule daily-home      # administrators
abyssal-warden service system-check --wait          # administrators
abyssal-warden service quarantine list|restore ID|delete ID --yes
abyssal-warden service verify-audit                 # administrators
```

`--wait` prints the finished report and exits like a local `scan` or
`system-check` (0, 1, 2, 3, 130). Without it the job ID is printed. Use
`--socket PATH` or `ABYSSAL_WARDEN_SOCKET` for a non-default socket.

## Who may do what

| Action | Any local user | Administrator |
|---|---|---|
| Status, list schedules | yes | yes |
| Scan paths | yes, **as themselves** | yes, as the scanner account (reads everything) |
| See, fetch reports of, cancel jobs | their own | all |
| Scan with `--quarantine`, system check, run a schedule | no | yes |
| Quarantine list, restore, delete; audit verification | no | yes |

Administrators are root, `admin_users` and members of `admin_group`.
Denied requests are logged.

## Configuration

`/etc/abyssal-warden/service.json` (root-owned, not group- or
world-writable; unknown fields are refused):

| Field | Default | Meaning |
|---|---|---|
| `socket` | `/run/abyssal-warden/wardend.sock` | Socket path (at most 107 bytes) |
| `socket_group` | none (0666) | Only this group may connect (0660) |
| `state_dir` | `/var/lib/abyssal-warden/service` | Job history and reports (0700) |
| `quarantine_store` | `/var/lib/abyssal-warden/quarantine` | Store for quarantine operations |
| `admin_users`, `admin_group` | none | Administrators besides root |
| `scanner_user` | `abyssal-warden` | Account privileged jobs run as |
| `scanner_binary` | next to `abyssal-wardend` | Must be root-owned |
| `content`, `keyrings` | none | Signed content bundles and extra keyrings for every job (the system keyring is always used) |
| `max_concurrent_jobs` | 1 | 1 to 8 |
| `max_queued_jobs` | 32 | Further requests are refused as busy |
| `job_timeout_minutes` | 240 | Jobs are killed after this plus one minute |
| `history_limit` | 200 | Finished jobs kept |
| `audit_check_hours` | 24 | Audit log comparison interval (0: on request only) |
| `schedules` | none | See below |

A schedule: `name`, `kind` (`scan` or `system_check`), `paths` (scans),
`every_hours`, optional `at_utc` (`HH:MM`; `every_hours` must then be a
multiple of 24), `heuristics`, `quarantine` (scans). Times are UTC. A run
missed while the machine was off starts once when the service starts.

## Hardening

The unit (`packaging/linux/abyssal-wardend.service`):
* limits the service to the capabilities it needs;
* sets `NoNewPrivileges`, `ProtectSystem=full`, kernel protections, a
  system-call filter and `AF_UNIX`/`AF_NETLINK` only.

`ProtectHome` and `PrivateTmp` are deliberately not used, because the
scanner must see the real `/home` and `/tmp`. Scanner children run:
* as the unprivileged `abyssal-warden` account with only
  `CAP_DAC_READ_SEARCH`, or
* as the requesting user with no capabilities.

## Logs

`journalctl -u abyssal-wardend` shows starts and ends of jobs, denied
requests, quarantine actions and audit check results. An audit check
failure is logged as `AUDIT LOG CHECK FAILED`.
