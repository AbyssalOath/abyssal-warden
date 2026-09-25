# Linux

## Current support (0.1.0)

| Capability | Status |
|---|---|
| On-demand scanning, hashing, hash signatures | Implemented and tested (developed on Fedora 42, kernel 6.19, x86_64) |
| Hardened open | `openat2(RESOLVE_NO_SYMLINKS)` under `skip` (before Linux 5.6: opened relative to the scan root with `cap-std`, never leaving it), `O_NONBLOCK`, `O_NOCTTY`, `O_CLOEXEC`, `O_NOATIME` when permitted; type and size re-checked with `fstat` |
| Default excludes | `/proc`, `/sys`. Dropped automatically if you ask to scan inside them; disable with `--no-default-excludes` |
| Non-UTF-8 file names | Preserved losslessly (`raw_hex`), escaped on the terminal |
| `--one-file-system` | Stays on the device of each root (useful for `/` to skip network and pseudo filesystems) |
| YARA rules | Implemented ([yara.md](../detection/yara.md)) |
| Quarantine / restore / delete | Implemented ([quarantine.md](../security/quarantine.md)); needs Linux ≥ 5.6 (`openat2`) |
| Everything below | Not implemented |

Notes:

* Files are opened with `O_NOATIME` when allowed (the scanning user owns the
  file, or has `CAP_FOWNER`, e.g. root), so scanning leaves access times
  unchanged. Other files are read normally, and their atime may be updated
  according to the mount options (`relatime` updates it at most once a day,
  or when it is older than the modification time).
* Files are opened with `openat2(RESOLVE_NO_SYMLINKS)` (Linux ≥ 5.6), so no
  symbolic link is followed in any path component under the default policy.
* Scanning as an unprivileged user covers only readable files. Unreadable
  entries are reported as `permission_denied` issues, and the CLI exits with
  code 3.
* `/dev/shm` and `/run` are **not** excluded, because they are common malware
  staging locations. Device nodes there are skipped as non-regular files.
* SELinux and AppArmor denials surface as `permission_denied` issues even when
  running as root. A future service policy module must grant read access
  explicitly.
* In containers, a scan sees the container's mount namespace, not the host's.

## Planned integrations and their mechanisms

| Capability | Mechanism | Constraints |
|---|---|---|
| Service and scheduling | **Implemented:** `abyssal-wardend` with a hardened systemd unit and internal schedules ([service.md](../user/service.md)) | Non-systemd init (OpenRC, runit) untested |
| IPC | **Implemented:** Unix socket with `SO_PEERCRED`; administrators by user list or group | polkit planned |
| ELF analysis | Memory-safe parser (`goblin` / `object`), fuzzed | |
| Package integrity | **Implemented:** `rpm -V` / `dpkg --verify` of critical and referenced files ([system-checks.md](../detection/system-checks.md)) | Package databases can be tampered with by root-level attackers; this only raises the cost |
| Persistence inspection | **Implemented** (`system-check`): systemd units and timers (system and user), cron (`/etc/crontab`, `/etc/cron.*`, `/var/spool/cron`), `/etc/ld.so.preload`, shell profiles, `/etc/rc.local`, XDG autostart, udev rules, PAM modules, SSH `authorized_keys` | Read-only enumeration; each check reports unsupported or limited status |
| Kernel module inspection | **Implemented:** `/proc/modules` vs `/sys/module` cross-view and taint flags (unsigned-module taint included) | A kernel rootkit controls both views |
| Hidden process detection | **Implemented:** every PID up to `pid_max` probed directly against the `/proc` listing; deleted executables in writable locations | Same limitation |
| On-access scanning and blocking | **fanotify** permission events (`FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM`) | Needs `CAP_SYS_ADMIN`; a slow scanner stalls every opener system-wide, so strict timeouts and fail-open/fail-closed policy are required; mount or filesystem marks |
| Telemetry | eBPF (tracepoints, LSM BPF where `CONFIG_BPF_LSM` and `lsm=bpf` are enabled) | Kernel-version dependent; BPF programs must use a GPL-compatible licence (see ADR-0004) |
| Integrity | IMA/EVM measurement logs, where the kernel has them enabled | Not enabled by default on most distributions |

`inotify` is **not** real-time protection. It cannot block, does not scale
to whole filesystems, and loses events on overflow. Any watcher-based feature
must be described as post-hoc.

## Limits of in-OS detection

A root-level or kernel-level attacker can hide files, processes and modules
from every user-space view. Offline scanning (booting trusted media and
scanning the unmounted root filesystem) is the planned mitigation.
