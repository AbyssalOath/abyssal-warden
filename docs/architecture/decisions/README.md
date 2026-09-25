# Architecture decision records

Each significant, hard-to-reverse decision gets a numbered record. Records
are never deleted. A reversed decision gets a new record that supersedes the
old one, and the old record's status is updated to point to it.

Template: context → options considered → decision → consequences.

| # | Title | Status |
|---|---|---|
| [0001](0001-workspace-structure.md) | Workspace structure | Accepted |
| [0002](0002-detection-interface.md) | Detection interface and finding model | Accepted (amended by 0006) |
| [0003](0003-hash-signature-format.md) | Hash signature database format v1 | Accepted |
| [0004](0004-project-license.md) | Project licence: AGPL-3.0-only | Accepted |
| [0005](0005-yara-engine.md) | YARA engine: YARA-X | Accepted |
| [0006](0006-content-access-and-time-limits.md) | Content access, per-worker state, per-file time limit | Accepted |
| [0007](0007-content-signing.md) | Signed detection content (minisign) | Accepted |
| [0008](0008-quarantine-store.md) | Quarantine store and remediation safety model | Accepted |
| [0009](0009-stall-watchdog.md) | Stall watchdog, whole-scan time limit, detached scan threads | Accepted |
| [0010](0010-root-relative-opens.md) | Root-relative file opens (cap-std) and cross-platform file IDs | Accepted |
| [0011](0011-archive-scanning.md) | Archive scanning (ZIP) | Accepted |
| [0012](0012-content-bundles.md) | Signed content bundles, keyrings, rollback protection | Accepted (amended by 0013) |
| [0013](0013-threshold-floors-revocation.md) | Threshold signatures, sequence floors, revocation carried by content | Accepted |
| [0014](0014-remediation-completeness.md) | Allow-list, audit anchoring, stopping running malware | Accepted |
| [0015](0015-system-checks.md) | Linux persistence inventory and integrity checks | Accepted |
| [0016](0016-package-trust-self-integrity-windows.md) | Package trust, scanner self-integrity, Windows persistence | Accepted |
| [0017](0017-file-heuristics.md) | File heuristics | Accepted |
| [0018](0018-service-and-ipc.md) | Service, local IPC and privilege separation (Linux) | Accepted |

Pending decisions, each to be recorded before its implementation starts:

* IPC transport and authorisation ([design notes](../../security/privilege-model.md))
* GUI framework ([evaluation](../gui.md))
* Automatic update mechanism (TUF) ([design notes](../../security/update-security.md))
* Windows quarantine store
