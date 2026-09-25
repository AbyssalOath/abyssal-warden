# ADR-0004: Project licence

* **Status:** Accepted: **AGPL-3.0-only** (decided by the project owner)
* **Date:** proposed 2026-09-24; accepted 2026-09-24

## Context

Abyssal Warden is meant to be free, open-source, transparent and auditable
security software for Windows and Linux. The licence affects:

* whether others may ship modified or proprietary versions;
* which third-party code we can incorporate;
* future kernel components.

Current dependencies are all permissive (MIT, Apache-2.0, Unicode-3.0, Zlib,
Unlicense options; checked with `cargo license` and enforced by
`deny.toml`), so they constrain nothing. Future constraints:

* **YARA-X** is BSD-3-Clause, compatible with every option below.
* **libclamav** is GPL-2.0-only. Linking it in-process is only possible for
  a GPL-2.0-compatible project, which rules out Apache-2.0 and GPL-3.0.
  Talking to `clamd` over a socket avoids this.
* **Linux kernel modules** must be GPL-2.0-compatible to use GPL-only kernel
  symbols. **eBPF programs** that use GPL-only helpers must declare a
  GPL-compatible licence. The convention is to dual-license those components
  separately (e.g. "Dual BSD/GPL"), whatever the main project licence is.
* **Detection content** (signatures, rules) should carry its own licence
  per database. The format has a `license` field for this.

## Options

| Licence | Effect on derivatives | Patent grant | Notes |
|---|---|---|---|
| **Apache-2.0** | Anyone may ship proprietary modified versions | Yes, with retaliation clause | Common in Rust; easiest to adopt and integrate; compatible with GPL-3.0 downstream |
| MIT OR Apache-2.0 | Same as Apache-2.0 | Apache path only | Rust-ecosystem default; maximises reuse of our crates |
| MPL-2.0 | Modified *files* must remain open; can be combined into proprietary products | Yes | Middle ground; GPL-compatible |
| GPL-3.0-or-later | Distributed modifications must be released under GPL | Yes | Stops closed forks (e.g. rebranded "scareware" built on our engine); may put off some integrators; incompatible with GPL-2.0-only code (libclamav) |
| GPL-2.0-or-later | As above | No explicit grant | Would allow linking libclamav; older licence |

## Recommendation (at proposal time; superseded by the decision below)

**Apache-2.0** for the code, unless preventing closed-source derivatives is
a primary goal. In that case, **GPL-3.0-or-later**.

Reasoning: the project's value depends on being auditable and widely
reviewed and reused, for example by incident responders embedding the engine
in their own tooling. Apache-2.0 maximises that and provides an explicit
patent grant. The main risk is proprietary rebranding. A licence cannot fully
stop bad actors; trademark policy on the name "Abyssal Warden" and signed
official releases address impersonation more directly.

Whichever is chosen:

* Keep kernel/eBPF components in separate crates with their own
  GPL-compatible dual licence.
* License project-authored detection content separately (e.g. CC0 or
  CC-BY-4.0). The synthetic test database is marked CC0-1.0.
* Add `LICENSE` (and `NOTICE` for Apache-2.0), set `license` in
  `[workspace.package]`, and require `Signed-off-by` (DCO) on contributions.

## Decision

The project owner chose the **GNU Affero General Public License v3.0** and
added the licence text as `LICENSE`. Every workspace crate declares
`license = "AGPL-3.0-only"`.

"Only" rather than "or later" was chosen as the reversible default: the
owner can widen the grant to "or any later version" at any time, but a
grant of "or later" cannot be withdrawn for versions already released. If
"or later" is intended, change the `license` field in the root `Cargo.toml`
and add the standard notice to the README.

## Consequences of AGPL-3.0

* Anyone who distributes a modified version, **or offers it to users over a
  network** (e.g. a hosted scanning service), must publish their changes
  under the AGPL. This is stronger than the GPL-3.0 option in the table
  above, and it directly addresses closed forks, including "scan as a
  service" offerings.
* Dependencies: all current dependencies (MIT, Apache-2.0 including the
  LLVM exception, BSD-2/3-Clause, Zlib, ISC, Unicode-3.0, Unlicense) are
  compatible with AGPL-3.0; `deny.toml` enforces the allow-list.
* **GPL-2.0-only code (e.g. libclamav) cannot be linked.** Integration with
  ClamAV, if ever wanted, must be out of process (clamd).
* Linux kernel and eBPF components still need a GPL-2.0-compatible licence
  and will be dual-licensed separately, as described above.
* Detection content keeps its own licence per database (`database.license`).
* Contributions: adopt a DCO (`Signed-off-by`) before accepting external
  patches, so the licence history stays clear.
