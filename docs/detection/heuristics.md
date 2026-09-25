# Heuristic analysis

Decision record: [ADR-0017](../architecture/decisions/0017-file-heuristics.md).
Implementation: `crates/heuristics` (detector id `heuristics`). Enable with
`scan --heuristics` (and `system-check --heuristics` for the programs that
persistence entries start). The persistence rules of `system-check` are
listed separately in [system-checks.md](system-checks.md); they share this
crate's command patterns.

## Principles

* Heuristic findings are `kind = heuristic` or `suspicious`, with
  `confidence` of `low` or `medium`. They are never labelled as confirmed
  malware, always recommend `review`, and never trigger automatic
  remediation (the quarantine policy rejects them).
* Each heuristic has a documented rationale, known false-positive sources,
  and a measured hit rate on a clean corpus (below).
* The evidence lists the concrete observation (for example "writable and
  executable: .text", "remote thread injection: imports VirtualAllocEx,
  WriteProcessMemory, CreateRemoteThread", "line 12: curl -s ... | bash"),
  so a person can verify it.
* Heuristics are a separate detector, versioned in every report, and off
  unless requested.

## What is analysed

Every file whose content the scanner reads (up to `--max-content-size`),
including archive members:

* **Names**: the file name (for archive members, the member's name).
* **PE and ELF structure**, parsed read-only with the `object` crate.
* **Scripts**: files with a `#!` line or a script extension (`.sh`, `.py`,
  `.pl`, `.rb`, `.php`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, ...)
  and text content. Comment lines are skipped. At most 50,000 lines, 8 KiB
  per line.
* **Location**: executables under `/tmp`, `/var/tmp`, `/dev/shm` or Windows
  temporary and public folders (files on disk only).

## Rules

All rules have `rule_version` 1. "Clean hits" are from the measurement
below.

| ID | Name | Kind / severity / confidence | Known false positives | Clean hits |
|---|---|---|---|---|
| AW-HEU-001 | Executable content (PE, ELF, Mach-O) with a document, image, archive or media extension | suspicious / high / medium | Oddly named tools (Fedora's `whois.md` led to dropping `.md`) | 0 |
| AW-HEU-002 | Double extension (`invoice.pdf.exe`) or spaces padding the name before an executable extension | suspicious / medium / medium | Rare | 0 |
| AW-HEU-003 | Bidirectional control characters in the name | suspicious / high / medium | Right-to-left language names using explicit marks | 0 |
| AW-HEU-010 | PE section writable and executable | heuristic / medium / low | Packed or protected commercial software, some JIT hosts | n/m |
| AW-HEU-011 | PE entry point outside executable sections | heuristic / medium / low | Packed software | n/m |
| AW-HEU-012 | Known packer section names (UPX, ASPack, MPRESS, Petite, Themida, WinLicense, VMProtect, Enigma, NsPack, PECompact, ...) | heuristic / low / medium | Legitimately packed tools and games | n/m |
| AW-HEU-013 | Executable sections with entropy ≥ 7.2 bits/byte and ≤ 10 imports (not UEFI images) | heuristic / low / low | Packed software; installers | 0 (3 before UEFI images were exempted: kernel EFI stubs) |
| AW-HEU-014 | Complete import set for remote-thread injection or process hollowing | heuristic / medium / low | Debuggers, security and accessibility tools | n/m |
| AW-HEU-015 | A complete PE image after the last section (outside the signature area) | heuristic / medium / low | Installers and self-extractors that carry raw executables | n/m |
| AW-HEU-016 | MZ/PE signatures present but the headers do not parse | heuristic / low / low | Truncated downloads, corrupt files | n/m |
| AW-HEU-020 | ELF `PT_LOAD` segment writable and executable | heuristic / medium / low | Very old binaries, some JIT runtimes | 0 |
| AW-HEU-021 | ELF requests an executable stack | heuristic / low / low | Old or hand-written assembly | 0 |
| AW-HEU-022 | ELF executable with the UPX header (`UPX!` in the first KiB) | heuristic / medium / medium | Deliberately packed tools | 0 (3 before the check was restricted to the header: object files containing the marker as a constant) |
| AW-HEU-023 | ELF executable without any section headers | heuristic / low / low | Some embedded or size-optimised binaries | 0 |
| AW-HEU-024 | RPATH/RUNPATH with an empty entry, `.`, a relative path (not `$ORIGIN`) or a temporary directory | suspicious / medium / medium | Build-tree binaries not meant for installation | 0 |
| AW-HEU-025 | ELF entry point outside executable segments | heuristic / medium / low | None known | 0 |
| AW-HEU-026 | Program interpreter not a standard `ld*.so`, relative, or in a temporary directory | suspicious / medium / medium | Custom toolchains | 0 |
| AW-HEU-030 | Script downloads and runs code | heuristic / medium / low | Installers, and text that *shows* install commands (help strings, web pages) | 3 |
| AW-HEU-031 | Script opens a reverse shell | suspicious / high / medium | Penetration-testing tools | 0 (20 before interpreter one-liners were required to pass inline code: minified syntax highlighters) |
| AW-HEU-032 | Script decodes and runs an encoded payload | suspicious / medium / low | Self-extracting installers | 0 |
| AW-HEU-033 | Script uses mshta, rundll32, regsvr32, wmic or wscript to run remote or script code | suspicious / medium / low | Legacy logon scripts | 0 |
| AW-HEU-034 | Script sets `LD_PRELOAD`/`LD_AUDIT` | heuristic / low / low | Tracing tools (`sotruss`), test harnesses | 1 |
| AW-HEU-035 | Shell, PowerShell, batch or VBScript file with a base64 run of 4 KiB or more | heuristic / low / low | Self-extracting shell installers | 0 |
| AW-HEU-040 | Executable in a temporary or shared-memory directory | heuristic / low / low | Build output and installers unpacking to `/tmp` | not measured (corpus has none) |
| AW-HEU-099 | Three or more of the above on one file | suspicious / medium / medium | As the underlying rules | 0 |

n/m: not measured; see below.

## Measured hit rates

Clean corpus, 2026-09-25, on a Fedora 42 development machine (`/usr`,
`/opt`, `~/.cargo`, `~/.rustup`, and project trees including build output):
**549,615 files**, of which 135,053 ELF, 10,900 scripts and 11 PE files.

* **4 hits in total (0.07 per 10,000 files)**, all explained: three
  AW-HEU-030 (a help string in `fpaste` and a web page showing an install
  command), one AW-HEU-034 (`sotruss`, which exists to set `LD_AUDIT`).
* ELF structure rules: 0 hits on 135,053 ELF files.
* The measurement found and fixed three rule defects before release (noted
  in the table).
* **PE rules are not measured**: the corpus has only 11 PE files. They are
  shipped with `low` confidence (except known packer names) and must be
  measured on a Windows installation before any of them is enabled by
  default.

Reproduce or extend the measurement:

```sh
cargo run --release -p warden-heuristics --example corpus_eval -- /usr /opt
# On Windows (PE rules):
cargo run --release -p warden-heuristics --example corpus_eval -- C:\Windows\System32 "C:\Program Files"
```

The tool prints each rule's hit count, rate per 10,000 files and example
paths. Detection-rate evaluation on malicious samples follows
[testing.md](testing.md) and has not been done yet.

## Limits

* Heuristics describe structure and text, not behaviour. A clean result
  means none of these patterns is present.
* Text patterns can be defeated by trivial obfuscation, and match text
  that only *mentions* a command.
* Delay-load imports and imports resolved at run time (`GetProcAddress`)
  are not seen by AW-HEU-014.
* Authenticode signatures are noted in evidence but not verified.
* Mach-O files are recognised (AW-HEU-001) but not analysed.
