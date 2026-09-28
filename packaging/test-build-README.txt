Abyssal Warden - TEST BUILD
===========================

This is an unsigned test build from CI, not a release. It is in early
development and must not be relied on to protect a system.

Keep all files together in one folder: the app runs the abyssal-warden
program that sits next to it.

Contents
  abyssal-warden-gui(.exe)  the desktop app
  abyssal-warden(.exe)    the scanner and all commands (the app uses it)
  abyssal-wardend(.exe)   the background service (optional)
  keyring.json            the project's trusted public keys (also built
                          into the programs; here for reference)
  abyssal-warden.png      the app icon
  abyssal-warden.desktop  Linux menu entry (see step 5)
  demo/                   a harmless synthetic test bundle (test key only)
  SHA256SUMS              checksums of the programs and keyring

The app: double-click abyssal-warden-gui.exe (Windows) or run
./abyssal-warden-gui (Linux). Without the background service it works
standalone: scans run as you. The steps below use the command line.

On Windows, replace ./abyssal-warden with .\abyssal-warden.exe below.

1. Check the download
   Linux:    sha256sum -c SHA256SUMS
   Windows:  Get-FileHash .\abyssal-warden.exe   (compare with SHA256SUMS)
   Linux only: chmod +x abyssal-warden abyssal-wardend abyssal-warden-gui

2. See a detection, safely
   Never download real malware to test with. The demo bundle detects two
   harmless marker strings:

   Linux:
     mkdir -p /tmp/aw-demo
     printf 'ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR\n' > /tmp/aw-demo/indicator.txt
     printf 'ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER\n' > /tmp/aw-demo/marker.txt
     ./abyssal-warden scan --keyring demo/keys/keyring.json --content demo/bundle \
         --content-state /tmp/aw-demo-state.json /tmp/aw-demo

   Windows (PowerShell):
     mkdir $env:TEMP\aw-demo
     Set-Content $env:TEMP\aw-demo\indicator.txt 'ABYSSAL-WARDEN-SYNTHETIC-TEST-INDICATOR'
     Set-Content $env:TEMP\aw-demo\marker.txt 'ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER'
     .\abyssal-warden.exe scan --keyring demo\keys\keyring.json --content demo\bundle `
         --content-state $env:TEMP\aw-demo-state.json $env:TEMP\aw-demo

   Expect two findings and exit code 1.

3. Real detection content (once a content release is published)
   The project's keys and update channel are built in:
     ./abyssal-warden update
     ./abyssal-warden scan --installed ~/Downloads
   (In the app: Detection content > Check for updates now.)

4. Other things to try
     ./abyssal-warden system-check              (Linux: persistence and integrity;
                                                  Windows: persistence, run as Administrator
                                                  for full coverage)
     ./abyssal-warden scan --heuristics ~/Downloads
     ./abyssal-warden --help                     (every command has --help)

5. Linux menu entry (optional)
     mkdir -p ~/.local/bin ~/.local/share/applications ~/.local/share/icons/hicolor/256x256/apps
     cp abyssal-warden abyssal-warden-gui ~/.local/bin/
     cp abyssal-warden.png ~/.local/share/icons/hicolor/256x256/apps/
     cp abyssal-warden.desktop ~/.local/share/applications/

Please report problems, false positives and confusing output as issues:
https://github.com/AbyssalOath/abyssal-warden/issues
