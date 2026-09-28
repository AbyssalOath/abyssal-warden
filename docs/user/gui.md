# The desktop app

`abyssal-warden-gui` is the desktop app for Linux and Windows. Design:
[ADR-0021](../architecture/decisions/0021-desktop-app.md).

**Status:** first version. Every function is also in the command line
(`abyssal-warden`), which remains the reference.

Keep `abyssal-warden-gui` and `abyssal-warden` in the same folder: the app
runs the scanner program next to it (or finds it on `PATH`).

## Two modes

| | Standalone (no service) | With the service (`abyssal-wardend`) |
|---|---|---|
| Scans run as | you, with your permissions | the service's scanner account, or you (see [service](service.md)) |
| Live progress | file, byte and finding counts | "running" only |
| Detection content | yours, from **Detection content** | the service's (its `content` and `update` schedules) |
| Quarantine page | not available (use `abyssal-warden quarantine`) | list, restore, delete (administrators) |

The app looks for the service when it starts (**Status** shows the result;
**Check again** retries). When it is found, scans go through it unless you
untick **Run scans through the service**.

## Pages

* **Status:** the mode, and what the product can and cannot do.
* **Scan:** add folders (Downloads, Home, **Choose folder…**, or type a
  path), choose heuristics and archive scanning, **Start scan**. **Cancel**
  stops the scanner.
* **Results:** a summary, findings sorted by severity, and every detail of
  the selected finding (evidence, rule, database, explanation). **Copy
  SHA-256** and **Copy location** put the values on the clipboard.
  Warnings and scanner messages are listed below.
* **Detection content:** **Check for updates now** downloads the latest
  signed content for your account from the official channel
  ([updates](updates.md)). With the service, its update schedules are
  listed with **Run now**.
* **Quarantine** (service): quarantined files with **Restore…** and
  **Delete…**, each confirmed first. A restored file is allow-listed.

## Safety notes

* File names and rule texts are shown with control and direction
  characters escaped (for example `invoice\u{202e}fdp.exe`), so a name
  cannot disguise itself or trigger anything.
* The app has no privileges. It never quarantines on its own; findings
  are reported for you to act on.
* The scanner runs in a separate process: a hostile file is never parsed
  inside the app.

## Linux menu entry

`packaging/linux/abyssal-warden.desktop` and the icon
(`assets/icons/abyssal-warden-256.png`, installed as `abyssal-warden.png`
in an icon theme directory) add the app to desktop menus; the test-build
README has per-user install commands.

## Not yet

Notifications, a tray icon, scan history in the app, standalone
quarantine management, live progress for service scans, and a screen
reader test (NVDA, Narrator, Orca) before the first release.
