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

Pending decisions, each to be recorded before its implementation starts:

* IPC transport and authorisation ([design notes](../../security/privilege-model.md))
* GUI framework ([evaluation](../gui.md))
* Update mechanism: rollback/freeze protection, TUF ([design notes](../../security/update-security.md))
* Project signing-key management
* Windows quarantine store
