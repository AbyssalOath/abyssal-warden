# Development setup

## Toolchain

* Rust **stable**, edition 2024. Developed with rustc 1.97.1. The minimum
  supported version is not yet defined.
* The first build compiles YARA-X and wasmtime (~180 crates, about a minute
  on 16 cores).
* Quarantine tests need Linux ≥ 5.6 (`openat2`).
* Components: `rustfmt`, `clippy`.
* Optional:
  * `nightly` toolchain, for fuzzing
  * `cargo-deny` (`cargo install cargo-deny --locked`): licence, advisory and
    source policy (`deny.toml`)
  * `cargo-audit`: RustSec advisories
  * `cargo-fuzz` (`cargo install cargo-fuzz --locked`)
* Windows cross-check from Linux: `rustup target add x86_64-pc-windows-gnu`.
  `cargo check` and `cargo clippy` work without a linker. Building or running
  tests needs a MinGW toolchain or a Windows machine.

## Layout

```text
crates/core         warden-core: types, Detector traits (no I/O)
crates/engine       warden-engine: scanner, hardened I/O, hash signatures, signature verification
crates/yara         warden-yara: YARA-X provider
crates/remediation  warden-remediation: quarantine store (Linux)
crates/cli          warden-cli: `abyssal-warden` binary
examples/           synthetic signature DB, YARA rule, test public key (+ .minisig)
fuzz/            cargo-fuzz harnesses (separate workspace, nightly)
docs/            documentation (start at docs/README.md)
```

## Required checks (identical to CI)

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS=-D\ warnings cargo doc --workspace --no-deps
cargo deny check                     # if installed
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
```

## Running

```sh
cargo run -p warden-cli -- scan --signatures examples/signatures/synthetic-test-indicators.json <path>
cargo run -p warden-cli -- --help
```
