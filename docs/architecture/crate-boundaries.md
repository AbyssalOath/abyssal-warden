# Crate boundaries

Decision record: [ADR-0001](decisions/0001-workspace-structure.md).

A crate boundary is created only when it serves one of these purposes:
isolating a heavy or risky dependency, enforcing a privilege or trust
boundary, or giving a component that other components consume a stable
interface. Matching a diagram is not a reason.

## Current crates

```text
warden-cli ─┬─► warden-engine ───────────────┐
            ├─► warden-yara ─────────────────┤
            ├─► warden-heuristics ───────────┤
            ├─► warden-remediation ──────────┼─► warden-core
            └─► warden-system ─► (heuristics)┘
```

The engine, YARA, heuristics and remediation crates depend only on
`warden-core`, not on each other. `warden-system` also uses the heuristics
crate's command-pattern table. The CLI composes them.

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
  warden-remediation, warden-system, clap, ctrlc, serde, serde_json, tempfile, time.

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

### `warden-ipc` (library)

* **Contains:** the service protocol, framing, validation and the
  authorisation policy.
* **Dependencies:** serde, serde_json, thiserror, time, uuid.
* **Why separate:** client and server (and future GUI and Windows service)
  share one definition of the trust boundary; it is pure and fuzzed.

### `warden-service` (library; binary `abyssal-wardend` in warden-cli)

* **Contains:** the Linux daemon: socket server, jobs, schedules, history,
  child processes with reduced privileges, audit comparison.
* **Dependencies:** warden-core, warden-ipc, warden-remediation, serde_json,
  tempfile, time, uuid; rustix and ctrlc (Linux).
* **Why separate:** it is the only long-running privileged component
  ([ADR-0018](decisions/0018-service-and-ipc.md)). It never parses scanned
  content itself; it runs `abyssal-warden` children.

### `warden-heuristics` (library)

* **Contains:** the `heuristics` detector (names, PE, ELF, scripts,
  location) and the shared command-pattern table.
* **Dependencies:** warden-core, object (read-only ELF/PE), regex, memchr,
  time.
* **Why separate:** it holds the untrusted binary parser and can be
  enabled, versioned and fuzzed on its own
  ([ADR-0017](decisions/0017-file-heuristics.md)).

### `warden-system` (library)

* **Contains:** persistence inventory, `AW-SYS-*` rules, kernel, process
  and package checks (Linux), root-confined reads.
* **Dependencies:** warden-core, warden-heuristics (patterns), md-5, sha2,
  serde_json, thiserror, time; rustix and libc (Linux); winreg (Windows).
* **Why separate:** it inspects system state rather than files, runs
  external tools (rpm/dpkg), and will need different privileges in the
  service. It stays read-only
  ([ADR-0015](decisions/0015-system-checks.md)).

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
