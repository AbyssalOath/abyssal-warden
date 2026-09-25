# Installation

There are no binary releases yet. Build from source:

```sh
# Requires Rust stable (https://rustup.rs)
git clone <repository-url> abyssal-warden
cd abyssal-warden
cargo build --release --locked
./target/release/abyssal-warden --help
```

The binary is self-contained. It does not install services, drivers or
scheduled tasks, and it does not need administrator rights. Run it as a
normal user to scan files that user can read.

Before relying on it, read the [known limitations](../known-limitations.md).
It is not a replacement for an established anti-malware product.
