# Windows

## Current support (0.1.0)

| Capability | Status |
|---|---|
| On-demand scanning, hashing, hash signatures | Implemented. Compiles and passes Clippy for `x86_64-pc-windows-gnu`. CI runs the test suite on `windows-latest` (MSVC) |
| Hardened open | Under the `skip` policy, files are opened relative to a handle on their scan root (`cap-std`), one component at a time; nothing can resolve outside the root, and a final-component symlink or junction is opened as itself and skipped ([ADR-0010](../architecture/decisions/0010-root-relative-opens.md)) |
| Duplicate files (`--follow-symlinks`) | De-duplicated by volume serial number and file index (`GetFileInformationByHandle`) |
| Paths | Roots are canonicalised to verbatim form (`\\?\C:\...`), which appears in reports. Non-Unicode (unpaired-surrogate) names are preserved as UTF-16LE hex in `raw_hex` |
| Default excludes | None |
| YARA rules | Implemented; compiles and passes Clippy for Windows (YARA-X supports Windows), not yet run there |
| Quarantine | **Not supported**: returns "not supported". Needs a DACL-hardened store under `%ProgramData%` and by-handle move/delete (`FILE_FLAG_OPEN_REPARSE_POINT`, `SetFileInformationByHandle`) |
| System check (`system-check`) | Implemented for the live system: Run keys, Winlogon, AppInit_DLLs, Image File Execution Options, services and drivers, scheduled tasks, Startup folders ([system-checks.md](../detection/system-checks.md#windows-checks)). Rules unit-tested on every platform; the registry and file layer runs in Windows CI |
| Everything below | Not implemented |

**Not verified yet:** the test suite has not been *run* on Windows by the
maintainers; the first CI run on `windows-latest` is the first execution.
Unix-specific tests (symlinks, FIFOs, permissions) are `cfg(unix)`, and
Windows-specific equivalents (junctions, ACL denial, locked files) still need
to be written.

Known behaviour: files locked for exclusive access by another process (e.g.
`pagefile.sys`, registry hives, some running executables' data) fail to open
and appear as `io` or `permission_denied` issues. Reading them needs the
Volume Shadow Copy Service or raw-volume access (future, privileged).

## Planned integrations and their mechanisms

| Capability | Supported mechanism | Constraints |
|---|---|---|
| Service | Service Control Manager (`windows-service` crate to be evaluated) | Service account: a virtual account / service SID with minimal rights |
| Secure GUI↔service IPC | Named pipe with explicit DACL, `PIPE_REJECT_REMOTE_CLIENTS`, client token checks | See [privilege model](../security/privilege-model.md) |
| PE analysis | Memory-safe parser crate (`goblin` / `object` to be evaluated), fuzzed | Untrusted input |
| Signature trust | `WinVerifyTrust` for Authenticode, catalog signatures | Reduces false positives on signed OS files; a signature is not proof of benign |
| Persistence inspection | Run/RunOnce keys, services, scheduled tasks (Task Scheduler API or `%SystemRoot%\System32\Tasks`), Winlogon, IFEO, AppInit_DLLs, WMI event subscriptions, startup folders | Read-only enumeration first; each check reports "unsupported" when it cannot run (e.g. without admin) |
| Script scanning | AMSI provider registration | A COM provider DLL loaded into other processes, so a high bar for code quality |
| Process telemetry | ETW | The Microsoft-Windows-Threat-Intelligence provider needs an antimalware protected process (PPL), which needs an ELAM driver signed through Microsoft's programme |
| On-access scanning and blocking | File system **minifilter** driver (Filter Manager) | Kernel driver: must be Microsoft-signed (attestation or WHQL, which needs an EV certificate); needs an allocated altitude; C/C++ (or experimental Rust `windows-drivers-rs`); a bug causes a system crash |
| Early boot protection | ELAM driver | Microsoft Virus Initiative membership required |
| Security Center integration | WSC registration | Restricted to MVI members; without it Windows Defender stays the registered AV |

`ReadDirectoryChangesW` (directory watching) is **not** real-time protection:
it reports changes after they happen, can overflow, and cannot block
execution. It may be used for "scan new downloads soon after they appear",
and must be described as that.

## Limits of user-mode detection

Kernel-mode rootkits and bootkits can hide from all user-mode enumeration.
Offline scanning from trusted media (WinPE-based or Linux-based, reading
NTFS) is the planned mitigation. It will be documented as the only reliable
option for those threats.
