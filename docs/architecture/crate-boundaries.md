# Crate boundaries

Decision record: [ADR-0001](decisions/0001-workspace-structure.md).

A crate boundary is created only when it serves one of these purposes:
isolating a heavy or risky dependency, enforcing a privilege or trust
boundary, or giving a component that other components consume a stable
interface. Matching a diagram is not a reason.

## Current crates

```text
warden-cli ─┬─► warden-engine ──────┐
            ├─► warden-yara ────────┼─► warden-core
            └─► warden-remediation ─┘
```

The engine, YARA provider and remediation crates depend only on
`warden-core`, not on each other. The CLI composes them.

### `warden-core` (library)

* **Contains:** `ScanConfig`/`ScanLimits`/`SymlinkPolicy`, `Finding` and its
  enums, `ScanReport`, `ObservedPath`, `Sha256Digest`, `Detector` trait,
  `CancellationToken`.
* **Dependencies:** serde, thiserror, time, uuid. No I/O and no platform code.
* **Why separate:** it is the vocabulary shared by every current and future
  component (engine, detectors, service, IPC, GUI). Third-party detector
  crates depend only on it, not on the engine's traversal dependencies.

### `warden-engine` (library)

* **Contains:** `Scanner` (traversal and orchestration), hardened single-read
  I/O with content buffering and deadlines, the hash signature database and
  its detector, minisign verification (`trust`).
* **Dependencies:** warden-core, walkdir, sha2, serde_json, minisign-verify,
  libc (Unix only).
* **Why the hash detector lives here:** it is small, has no heavy
  dependencies, and it is the reference implementation of `Detector`.
  Splitting it out would add a crate without isolating anything.

### `warden-cli` (binary `abyssal-warden`)

* **Contains:** argument parsing, verified content loading, progress
  display, report rendering and sanitisation, exit codes, Ctrl-C handling,
  quarantine commands.
* **Dependencies:** warden-core, warden-engine, warden-yara,
  warden-remediation, clap, ctrlc, serde, serde_json, tempfile, time.

### `warden-yara` (library)

* **Contains:** `YaraDetector` (compile, metadata validation, per-worker
  YARA-X scanner).
* **Dependencies:** warden-core, yara-x (explicit module list), sha2.
* **Why separate:** isolates the ~180-crate YARA-X/wasmtime tree
  ([ADR-0005](decisions/0005-yara-engine.md)). The engine does not depend on
  it; the CLI composes them.

### `warden-remediation` (library)

* **Contains:** `QuarantineStore` (Linux), records/journal, audit log,
  automatic-remediation policy.
* **Dependencies:** warden-core, rustix (Linux), getrandom, serde_json, sha2.
* **Why separate:** it is the only code allowed to move or delete files
  ([ADR-0008](decisions/0008-quarantine-store.md)). Nothing in the detection
  path depends on it.

## Planned crates and the reason for each

| Crate | Boundary reason |
|---|---|
| `warden-service` | Process boundary: the long-running, possibly privileged process. |
| `warden-ipc` | Shared, versioned request/response schema for the service, CLI and GUI. |
| `warden-platform-windows` / `-linux` | Isolates OS-specific dependencies (`windows` crate, etc.) and unsafe FFI, if needed, away from the `unsafe`-forbidden core. |
| `warden-gui` | Keeps GUI dependencies out of everything else. |

## Rules

1. `warden-core` must not gain I/O, threads or platform-specific dependencies.
2. Nothing in the detection path may depend on remediation.
3. `unsafe_code = "forbid"` is workspace-wide. A future crate that needs FFI
   gets a crate-local exception, with every `unsafe` block documenting its
   safety invariants.
4. All crates are `publish = false` until the licence is decided and the API
   is stable. The **JSON report** is the compatibility contract, not the Rust
   API.
