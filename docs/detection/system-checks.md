# System checks: persistence inventory and integrity rules

Decision records: [ADR-0015](../architecture/decisions/0015-system-checks.md),
[ADR-0016](../architecture/decisions/0016-package-trust-self-integrity-windows.md).
Implementation: `crates/system`; CLI `abyssal-warden system-check`
([user guide](../user/system-check.md)). Linux and Windows (live system).

## Linux checks

| Check ID | What it examines | Live only |
|---|---|---|
| `persistence.systemd` | `.service`/`.timer` units and drop-ins in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, `/lib` `systemd/system` and `systemd/user`, and each user's `~/.config/systemd/user`; enabled = linked from a `*.wants`/`*.requires` directory | no |
| `persistence.cron` | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron{,/crontabs}/*`, `/etc/anacrontab`, `/etc/cron.{hourly,daily,weekly,monthly}/*` | no |
| `persistence.ld_preload` | `/etc/ld.so.preload` | no |
| `persistence.shell_profiles` | `/etc/profile`, `/etc/profile.d/*`, bash, zsh and fish system files; users' `.profile`, `.bashrc`, `.zshrc`, `.xprofile` and similar | no |
| `persistence.environment` | `/etc/environment`, `/etc/environment.d`, `pam_env.conf`, `~/.pam_environment`, `~/.config/environment.d` | no |
| `persistence.xdg_autostart` | `/etc/xdg/autostart/*.desktop`, `~/.config/autostart/*.desktop` | no |
| `persistence.ssh_authorized_keys` | `~/.ssh/authorized_keys{,2}` for root and login users; forced `command=` options; unusual `AuthorizedKeysFile`/`AuthorizedKeysCommand` in `sshd_config` | no |
| `persistence.pam` | `/etc/pam.d/*`, `/etc/pam.conf` | no |
| `persistence.rc_local` | `/etc/rc.local`, `/etc/rc.d/rc.local` | no |
| `persistence.udev` | `RUN`, `PROGRAM`, `IMPORT{program}` in udev rules (`RUN{builtin}` ignored) | no |
| `persistence.sysv_init` | `/etc/init.d/*`, `/etc/rc.d/init.d/*`; enabled = an `S##` link in runlevels 2 to 5 | no |
| `persistence.at_jobs` | `/var/spool/at/*`, `/var/spool/cron/atjobs/*` (the submitter's environment in each job is searched, never copied) | no |
| `persistence.systemd_generators` | `system-generators`, `user-generators` and the environment generators in `/etc`, `/run`, `/usr/local/lib`, `/usr/lib`, `/lib` `systemd` | no |
| `persistence.kernel_modules` | `modules-load.d` and `/etc/modules` (modules loaded at boot); `modprobe.d` `install`/`remove` commands | no |
| `persistence.motd` | `/etc/update-motd.d/*` (run as root at login) | no |
| `persistence.ssh_rc` | `/etc/ssh/sshrc`, `~/.ssh/rc` (run at every SSH login) | no |
| `persistence.initramfs_hooks` | `/etc/initramfs-tools/hooks`, `/etc/initramfs-tools/scripts`, `/etc/dracut.conf{,.d}` | no |
| `persistence.boot_loader` | `/etc/grub.d/*` | no |
| `boot.integrity` | Secure Boot state, kernel lockdown mode and module signature enforcement (live); running and configured kernel command lines (`/proc/cmdline`, `/etc/default/grub`, `/etc/kernel/cmdline`, `/boot/loader/entries`); ownership and permissions of everything under `/boot` | partly |
| `processes.self_integrity` | libraries mapped into the scanner's own process (`/proc/self/maps`) against the ones it links | yes |
| `kernel.modules` | `/proc/modules` against `/sys/module/*/initstate` | yes |
| `kernel.ebpf` | loaded eBPF programs: `bpftool -j prog show` as root, otherwise programs held open by processes (`/proc/*/fdinfo`); objects pinned in `/sys/fs/bpf`. Inventory only | yes |
| `kernel.taint` | `/proc/sys/kernel/tainted` | yes |
| `processes.hidden` | every PID up to `pid_max` against the `/proc` listing | yes |
| `processes.deleted_executables` | `/proc/*/exe` of every process | yes |
| `packages.verify` | critical binaries and libraries plus every program a persistence entry starts, hashed by Abyssal Warden and compared with the package database (see below) | no |

Users inspected: root, users with a login shell, and UIDs 1000 to 65533,
from the inspected system's `/etc/passwd`. Unprivileged runs inspect only the
current user and report the affected checks as `partial`.

### Package verification and what it trusts

Abyssal Warden reads and hashes every file itself, so a trojaned `rpm` or
`dpkg`, or a user-mode rootkit hooking file reads in that process, cannot
make a modified file look clean.

* **dpkg**: `/var/lib/dpkg/info/*.list` and `*.md5sums` are parsed directly.
  No dpkg program runs, so a Debian-family image can be checked from any
  host. Merged-`/usr` spellings (`/bin/ls` and `/usr/bin/ls`) are matched.
* **rpm**: the database is queried with the host's `/usr/bin/rpm -q --qf`
  (fixed path, empty environment, timeout, no scripts, `--root` for images)
  for each file's recorded digest (MD5, SHA-224/256/384/512), and the file
  is hashed here. Configuration and ghost files are skipped.

What remains trusted: the package **database**, which root on the inspected
system can rewrite, and for rpm the host's `rpm` program's reading of it.
Checking from trusted media (`--root`) removes the second; comparing against
the distribution's signed repository metadata would remove the first and is
planned.

## Windows checks

Live system only (`--root` is refused on Windows). Registry values are read
with the `winreg` crate; files are read with a 1 MiB limit; nothing is
executed.

| Check ID | What it examines |
|---|---|
| `persistence.registry_run` | `Run`, `RunOnce`, `RunServices`, `RunServicesOnce`, `Policies\Explorer\Run` (and `WOW6432Node`) in HKLM and every loaded user hive (HKU) |
| `persistence.winlogon` | Winlogon `Shell`, `Userinit`, `Taskman`, `AppSetup`; `AppInit_DLLs` with `LoadAppInit_DLLs`; Image File Execution Options `Debugger`; SilentProcessExit `MonitorProcess` |
| `persistence.services` | services and drivers set to boot, system or automatic start: `ImagePath` (normalised) and `Parameters\ServiceDll`, with the account they run as |
| `persistence.scheduled_tasks` | task definitions in `%SystemRoot%\System32\Tasks` (UTF-16 XML): `Exec` actions, COM handlers, `Enabled`, `Hidden`, principal |
| `persistence.startup_folders` | the all-users and each profile's Startup folder; scripts are searched line by line, shortcuts are listed (targets not resolved yet) |
| `persistence.wmi`, `kernel.drivers`, `processes.hidden`, `packages.verify` | reported as `unsupported` (not implemented on Windows yet) |

Command patterns and rules are shared with Linux where they apply
(download-and-run, encoded commands, reverse shells, temporary locations),
plus the Windows rules AW-SYS-020 to 025.

## Rules

All rules have `rule_version` 1 and detector `system-checks`. None has
`confirmed` confidence, and none triggers remediation.

| ID | Name | Kind / severity / confidence | Known false positives |
|---|---|---|---|
| AW-SYS-001 | Persistence runs a file from a temporary directory (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm`, `/dev/mqueue`) | suspicious / high / medium | Installers that schedule cleanup jobs in `/tmp` |
| AW-SYS-002 | Persistence downloads and runs code (`curl`/`wget` piped to a shell or interpreter, or download then `chmod +x`) | suspicious / high / medium | Self-updating tools configured by the admin |
| AW-SYS-003 | Reverse shell (`/dev/tcp`, `nc -e`, `socat exec:`, `sh -i >&`, `mkfifo`+`nc`, interpreter socket plus exec code) | suspicious / critical / medium | Deliberate remote-support setups |
| AW-SYS-004 | Decodes and runs an encoded payload (`base64 -d \| sh`, `eval` of decoded data) | suspicious / high / medium | Rare in legitimate configuration |
| AW-SYS-005 | `LD_PRELOAD`/`LD_AUDIT` set by a persistence entry | suspicious / high / medium | Performance tools (jemalloc, tcmalloc), accessibility shims |
| AW-SYS-006 | `/etc/ld.so.preload` lists a library | suspicious / high / medium | Some security products and memory allocators |
| AW-SYS-007 | A system entry (runs as root) starts a file that non-root users can modify: not owned by root, group-writable with a non-root group, world-writable, or in such a directory (sticky directories excepted) | suspicious / high / medium | Software installed into a user-owned `/opt` directory, a real privilege-escalation risk anyway |
| AW-SYS-008 | The file defining an entry is writable by others (system: not root-owned or group/world-writable; user: world-writable or owned by another non-root user) | suspicious / medium / high | Misconfigured but benign permissions |
| AW-SYS-009 | Starts a hidden (dot) file or a file in a hidden directory, except common tool directories (`.local`, `.cargo`, `.nvm`, ...) | heuristic / medium / low | User tools in other dot-directories |
| AW-SYS-010 | PAM loads a module by absolute path outside the system `security` directories | suspicious / high / medium | Third-party PAM modules installed to `/opt` |
| AW-SYS-011 | Kernel module present in one of `/proc/modules` and `/sys/module` but not the other, on two reads | suspicious / critical / medium | None known; module load races are filtered by the second read |
| AW-SYS-012 | Kernel taint shows a force-loaded (F) or force-unloaded (R) module | suspicious / medium / low | Admins forcing out-of-date drivers |
| AW-SYS-013 | A process answers at `/proc/PID` but is missing from the `/proc` listing (threads excluded, confirmed twice) | suspicious / critical / medium | Processes in another PID namespace are not affected; none known |
| AW-SYS-014 | A process runs a deleted executable that was in a temporary, home or hidden location, or a `memfd` | suspicious / high / medium | Programs run from a build directory then rebuilt; container runtimes that re-execute themselves from `memfd` (runc) |
| AW-SYS-015 | A non-configuration file's content differs from the digest in the package database | suspicious / high / medium | Prelink, local rebuilds, manual hotfixes |
| AW-SYS-016 | Persistence starts a file that a content detector flagged | suspicious / critical / high | As the underlying detection |
| AW-SYS-017 | PAM runs an external program with `pam_exec` | heuristic / low / low | Legitimate notification or home-directory scripts |
| AW-SYS-018 | Kernel tainted by proprietary (P), out-of-tree (O) or unsigned (E) modules | informational / info / high | Expected with vendor graphics or virtualisation drivers; does not affect the exit status |
| AW-SYS-019 | A shared library the scanner does not link is mapped into its own process (preload, `LD_AUDIT`, `memfd`) | suspicious / critical / medium | Deliberate `LD_PRELOAD` by the user (the evidence says so); profilers and sanitizers |
| AW-SYS-020 | Windows system program used to run script or remote code (`mshta` with URL/script, `rundll32 javascript:`, `regsvr32 /i:http` or `scrobj.dll`, `wmic process call create`, `wscript`/`cscript` on a URL or user/temp path) | suspicious / high / medium | Some legacy logon scripts |
| AW-SYS-021 | Image File Execution Options `Debugger` or SilentProcessExit `MonitorProcess` registered | suspicious / high / medium | Debugging tools, Process Explorer replacing Task Manager |
| AW-SYS-022 | Winlogon `Shell`/`Userinit` differ from the defaults, or `Taskman`/`AppSetup` set | suspicious / high / medium | Kiosk shells, some OEM tools |
| AW-SYS-023 | `AppInit_DLLs` set and `LoadAppInit_DLLs` = 1 | suspicious / high / medium | Old accessibility or input tools |
| AW-SYS-024 | A service or task running with system privileges starts a program under `C:\Users` or `C:\ProgramData` | heuristic / medium / low | Vendor updaters installed in ProgramData |
| AW-SYS-025 | Scheduled task marked `Hidden` | heuristic / low / low | Some vendor maintenance tasks |
| AW-SYS-027 | Secure Boot is disabled | informational / info / high | Self-built or older systems; does not affect the exit status |
| AW-SYS-028 | Running or configured kernel command line weakens security: `selinux=0`, `enforcing=0`, `apparmor=0`, `security=none`, `audit=0`, `module.sig_enforce=0`, `ima_appraise=off`, `rd.break`, `systemd.debug_shell`, non-standard `init=`/`rdinit=` | suspicious / medium / medium | Admin troubleshooting left in place |
| AW-SYS-029 | A file or directory under `/boot` is not owned by root or is group/world-writable | suspicious / high / high | None known on a correctly installed system |

Command patterns are case-insensitive regular expressions with a size
limit, applied to at most 8 KiB per line. They live in
`crates/heuristics/src/patterns.rs` (shared with the script heuristics) and
are tested in `crates/system/src/heuristics.rs` with positive and negative
cases.

## What the checks cannot do

* **A kernel rootkit can defeat every in-OS check.** It can hide modules
  from both views, hide processes from direct probes, and serve clean file
  contents. A clean live result reduces suspicion, but it does not rule
  out compromise. For assurance, boot trusted media and run
  `system-check --root /mnt/suspect` (plus `scan`) on the unmounted disk.
* Package verification trusts the package database (and, for rpm, the host's
  `rpm` reading it); see above.
* The self-integrity check catches injected libraries, not a rootkit that
  also hides its mapping from `/proc/self/maps` (a kernel rootkit can).
* The hidden-process sweep does not see processes hidden from direct
  `/proc/PID` access as well, and it depends on the kernel.
* eBPF programs are listed, not judged; without `bpftool` and root,
  programs attached without a holding process are not seen.
* Boot checks do not verify firmware, the boot loader binary or initramfs
  contents against a measurement (TPM event log); kernels and boot loader
  files owned by packages are covered by package verification.
* Not inventoried yet (Linux): git hooks, desktop-environment-specific
  startup, `binfmt_misc`, `/etc/rc.d/rc.local`-style distribution variants.
* Windows: live system only; WMI event subscriptions, COM hijacks,
  shortcut targets, drivers, hidden processes and Authenticode are not
  checked yet; users who are not logged on are not inspected (their hives
  are not loaded).
* Command heuristics look at text, not at what scripts they call. A benign
  line that runs a malicious script is caught only by scanning that script
  (`AW-SYS-016`, with detection content) or through AW-SYS-001, 007 or 009.

## Testing

Unit tests cover every parser (units, crontab lines, desktop files,
`authorized_keys` options, PAM lines, udev rules, modprobe commands, rpm
query output, dpkg `md5sums`, `/proc/modules`, taint bits, kernel command
lines, bpftool JSON, fdinfo, `/proc/self/maps`, Windows task XML in UTF-16,
image paths, environment expansion, Winlogon defaults), the command patterns (positive and
negative), root confinement (absolute and `..` symlinks stay inside the
image), the hidden-PID confirmation logic, and the tool runner's timeout.
The `system-parsers` fuzz target runs every parser and pattern on arbitrary
input. Integration tests build fake root trees with planted persistence, and a
benign tree that must produce no heuristic findings. CLI tests cover
correlation with a signed hash database, sanitised output and the rule that
environment values are not reported. Tests never modify the real system.
Live Linux checks are exercised by read-only tests (`/proc` listing, our own
mappings, a CLI run with a harmless library preloaded to prove AW-SYS-019).
Native dpkg verification is tested on a fake root with a planted modified
binary. The live Windows layer is compiled and linted here and runs against
the CI machine's registry in the Windows CI job.
