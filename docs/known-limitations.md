# Known limitations

Abyssal Warden is in early development. It is **not** a replacement for an
established anti-malware product, and nothing here should be read as a claim
of protection.

These are being worked through in phases; see the
[work plan](../ROADMAP.md#known-limitations-work-plan).

## Detection

* **No real signatures or rules ship with the project.** Without content you
  provide, scans detect nothing (the CLI warns about this).
* File detection is exact SHA-256 matching, YARA rules and optional
  structural heuristics (`--heuristics`). No behavioural, emulation or
  memory scanning.
* Heuristics are measured on Linux files only (0.07 hits per 10,000 clean
  files); the PE rules have not been measured on a Windows corpus and are
  low confidence. They are off by default.
* YARA scans only files up to `--max-content-size` (default 64 MiB); larger
  files are hash-checked only (reported as `content not inspected`).
* YARA support covers the features listed in
  [yara.md](detection/yara.md#supported-features); some modules are
  deliberately excluded, and includes, slow patterns and compiled rules are
  refused.
* **Only ZIP archives are unpacked** (including JAR, APK, Office documents
  and self-extracting ZIP executables), and only stored, deflate and
  deflate64 entries. 7z, RAR, tar/gzip, CAB, ISO, MSI and other formats,
  encrypted members, and other ZIP compression methods are not inspected
  (reported, not silently skipped). Archives larger than
  `--max-content-size` are hashed but not expanded. See
  [archives.md](detection/archives.md).
* No detection-rate evaluation has been performed
  ([methodology](detection/testing.md)).

## Content trust

* Signed content bundles have rollback, expiry and revocation protection,
  but individually signed files (`--signatures`/`--yara`) do not.
* **No project signing key exists yet**, so there is no official content to
  trust ([procedure](security/content-trust.md#project-signing-key-procedure)).
* A fresh machine accepts any valid, unexpired release at or above the floor
  in its keyring; how recent that floor is depends on how recent the
  installed release is. There is no online freshness check (needs TUF).
* The example key in `examples/keys/` is a test key and must never be
  trusted outside testing.

## Protection and remediation

* No real-time or on-access protection; nothing is blocked.
* Quarantine is **Linux only**. It never removes persistence. Stopping running
  processes (`--kill-processes`) misses interpreted scripts and, without
  root, other users' processes.
* The audit log is compared with the system log automatically only by the
  service; root can alter both.
* Quarantine never removes persistence entries; `system-check` only reports
  them.

## System checks

See [system-checks.md](detection/system-checks.md#what-the-checks-cannot-do).

* **A kernel rootkit can defeat every in-OS check** (module cross-view,
  hidden processes, file contents). A clean live result is not proof of a
  clean system; inspect offline from trusted media for assurance.
* Package verification hashes files itself, but still trusts the package
  database (which root can rewrite) and, for rpm, the host's `rpm` reading
  it. Comparing against the distribution's signed repository metadata is
  planned.
* eBPF programs are inventoried, not judged. Boot checks cover Secure Boot,
  lockdown, command lines and `/boot` permissions, not firmware or
  measured-boot (TPM) verification.
* Unprivileged runs see only the current user's files and processes. This
  is an operating-system permission boundary; run as root, or ask an
  administrator to run it through the service.
* Windows: live system only; Run keys, Winlogon, AppInit_DLLs, IFEO,
  services, scheduled tasks and Startup folders are checked. WMI
  subscriptions, COM hijacks, shortcut targets, drivers and hidden processes
  are not. The Windows checks have only run in CI so far.

## Scanning behaviour

* A read blocked in the kernel on a hung network or FUSE filesystem cannot be
  interrupted. The scan still finishes (the watchdog abandons the stuck worker
  and reports the file), but the abandoned thread keeps its buffer and file
  descriptor until the read returns or the process exits. Scans run by the
  service are separate processes and are killed at their deadline; direct
  CLI scans keep this limitation.
* Files that change during a scan are hashed as read. A file that grows past
  the size limit mid-read is skipped.
* With `--follow-symlinks`, scanned files may lie outside the given roots.
* On Windows and on Linux kernels older than 5.6, a link that stays *inside*
  a scan root can redirect a read to another file in the same root (links
  leading outside a root are always refused). Linux 5.6+ refuses all links.
* Scanning updates atime of files the scanning user does not own (unless
  running as root or the filesystem is mounted `noatime`).
* Windows: locked system files cannot be read; the test suite has not yet
  been run on Windows outside CI.

## Operational

* The service (scheduling, history, IPC) is **Linux only**; administrator
  authorisation is by group, not polkit; parser children have no
  seccomp/landlock sandbox yet. Any local user can queue scans up to the
  queue limit unless `socket_group` is set.
* No GUI, update mechanism or signed releases.
* Scan reports are not signed.
* Rust 1.93 or later is required (bound by YARA-X); checked in CI.
