# Development setup

## Toolchain

* Rust, edition 2024. The toolchain is **pinned** in `rust-toolchain.toml`
  (currently 1.98.0); rustup selects it automatically inside the repository,
  and CI uses the same version, so a new Rust release cannot break the
  build. To upgrade: bump the file and the `toolchain:` lines in
  `.github/workflows/ci.yml`, then fix any new Clippy lints.
* Minimum supported version: **1.93** (`rust-version` in `Cargo.toml`, bound
  by YARA-X), checked by the `msrv` CI job with `cargo +1.93.0`.
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
