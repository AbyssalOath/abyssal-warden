# GUI framework evaluation

**Status: proposal.** No GUI exists yet. The CLI and scanner API take
priority, and this decision is finalised as ADR-0005 when GUI work begins.

## Constraints from the security model

* The GUI runs **unprivileged** and performs no privileged operation itself.
  It sends requests to the service over authenticated IPC
  ([privilege model](../security/privilege-model.md)).
* The GUI displays **attacker-controlled strings** (file names, and rule text
  from third-party databases). Rendering them must not be able to execute
  code or trigger actions.
* It must work on Windows and on Linux (X11 and Wayland).
* It needs accessibility (screen readers, keyboard navigation).

## Options

| Criterion | egui / eframe | Tauri 2 |
|---|---|---|
| Language | Rust only | Rust back end, HTML/CSS/JS front end in a system webview |
| Rendering untrusted text | Text is drawn as glyphs; there is no markup or script interpretation | Webview. An XSS bug (e.g. unsafe `innerHTML` with a file name) becomes script execution, which can call exposed Tauri commands |
| Attack surface | Rust GUI stack plus graphics driver | Rust plus webview engine (WebView2 / WebKitGTK), plus the JS dependency tree |
| Supply chain | Cargo only | Cargo plus npm ecosystem |
| Platform dependencies | OpenGL/wgpu | WebView2 runtime on Windows; WebKitGTK on Linux, whose security update cadence varies by distribution |
| Accessibility | AccessKit integration; functional but less mature than native or web | Inherits webview accessibility; generally mature |
| Look and feel, UI development speed | Functional, non-native; immediate-mode layout | Rich, flexible, familiar web tooling |
| Binary size | Small | Small (uses system webview) |
| Permission model | N/A (no script layer) | Capability/permission system restricts which commands the front end may invoke |

## Provisional recommendation: egui (eframe)

For a security product whose main UI job is showing hostile strings and
sending a handful of authorised requests, removing the script layer entirely
counts for more than Tauri's richer UI. egui keeps the whole stack in Rust
and in one supply chain.

Risks we accept, and their mitigations:

* **Accessibility is weaker.** We will test with NVDA/Narrator and Orca
  before release, and keep every GUI function also available in the CLI.
* **Less polished appearance.** Acceptable for this product.

We would reconsider Tauri if egui's accessibility turns out insufficient in
testing. In that case: a strict CSP, no `innerHTML`, a minimal command
allow-list via capabilities, and the same rule that the GUI holds no
privilege.

## Required GUI features (when built)

Quick, full and custom scan; progress and cancellation; detection details
(all `Finding` fields, sanitised); quarantine management through the service;
scan history; schedule settings; update status; system status that states
current limitations. Unsupported options are hidden, not shown disabled with
implied functionality.
