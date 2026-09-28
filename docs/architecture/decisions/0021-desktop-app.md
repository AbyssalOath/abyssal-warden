# ADR-0021: Desktop app (egui, standalone or through the service)

* **Status:** Accepted
* **Date:** 2026-09-28

## Context

The command line covers every function, but most people expect an app.
The GUI evaluation ([gui.md](../gui.md)) recommended egui over a webview
toolkit because the app's main job is showing attacker-controlled text
(file names, rule metadata). It also assumed the app would talk only to the
service, which would make the app useless until the service is installed.

## Decision

1. **egui (eframe 0.35) with the OpenGL renderer (glow)**, not wgpu: a
   much smaller dependency tree. AccessKit is enabled for screen readers.
   The native folder picker is `rfd` using the XDG desktop portal on Linux
   (no GTK build dependency).
2. **Two modes.**
   * *Standalone* (no service): the app runs the `abyssal-warden` program
     next to it as a child process, as the current user: `scan --format
     json --progress-json`, `update --format json`. Hostile files are never
     parsed in the app process, and content verification is exactly the
     CLI's.
   * *Service*: when `abyssal-wardend` answers, scans go to it over the
     authenticated endpoint (ADR-0018), and the Quarantine and schedule
     functions are enabled. The user can switch scans back to standalone.
   The app holds no privilege in either mode.
3. **Untrusted text is escaped before display** (the core
   `escape_unsafe_chars`), drawn as plain glyphs, never as links or markup,
   and shortened in lists. A headless test renders every page with a
   hostile file name (right-to-left override, terminal escape) and asserts
   that no control or bidi character is drawn.
4. **Destructive actions need confirmation** (restore, delete), and paths
   are passed to the scanner after `--`.
5. **The project keyring is built into the programs** (`keys/keyring.json`
   at build time) and the official update channel is the default source,
   so the app works without setup. `--no-builtin-keyring` turns the
   built-in keys off; the system keyring still applies on top, and its
   revocations win.
6. **`scan --progress-json`**: counts only (never paths) as JSON lines on
   stderr, for front ends.

## Consequences

* The app is usable right after download, without the service.
* egui embeds its default fonts (Hack, Noto Emoji, Ubuntu Light; OFL-1.1,
  Ubuntu Font Licence, MIT). The licences allow embedding when each copy
  carries the licence text: `licenses/third-party/egui-fonts/` ships with
  every build, and `deny.toml` allows those licences for that crate only.
* A changed project key needs a new program release (as before: keys are
  never learned from content).
* Service scans show no live counts (the protocol has no progress
  messages yet).
* Not yet: quarantine management in standalone mode, notifications, a tray
  icon, scan history in the app, and an accessibility test with screen
  readers (planned before a release).
