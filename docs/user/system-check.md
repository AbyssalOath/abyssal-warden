# System check (Linux and Windows)

`abyssal-warden system-check` lists everything that starts automatically on
a Linux system, flags suspicious entries, and checks the running kernel,
processes and packages for signs of tampering. It changes nothing.

```sh
sudo abyssal-warden system-check                      # running system
sudo abyssal-warden system-check --content /usr/share/abyssal-warden/content
sudo abyssal-warden system-check --root /mnt/suspect  # offline disk image
abyssal-warden system-check --format json -o report.json
abyssal-warden.exe system-check                        # Windows, elevated prompt
```

Run it as root (Linux) or from an elevated prompt (Windows). Otherwise other
users' files, root's crontab and most processes cannot be read, and the
affected checks are reported as `PARTIAL`. That is an operating-system
permission boundary, not something the tool can work around.

On Windows, only the running system can be inspected, and some checks
(WMI subscriptions, drivers, hidden processes, signatures) are reported as
`unsupported`, so the exit status is 3 when nothing is found.

## Options

| Option | Effect |
|---|---|
| `--root DIR` | Inspect a mounted system instead of `/`. Symbolic links resolve inside `DIR`. Kernel and process checks are skipped. |
| `--content DIR`, `-s FILE`, `-y PATH` (and the trust options of `scan`) | Also scan the programs that persistence entries start. Detections are linked to the entry (`AW-SYS-016`). |
| `--no-referenced-scan` | Do not scan referenced programs, even with content. |
| `--no-hidden-processes` | Skip the PID sweep (a few seconds). |
| `--no-packages` | Skip package verification (Linux). Files are hashed by Abyssal Warden; dpkg databases are read directly, rpm is only asked for recorded digests. |
| `--verify-all-packages` | Verify every package, not only critical and referenced files. This can take minutes. |
| `--package-timeout SECS` | Time limit per package-manager run (default 300). |
| `--show-inventory` | List every persistence entry in the human output. |
| `--format json`, `-o FILE` | As for `scan`. The JSON schema is `SystemReport` v1. |

## Reading the result

* **Checks**: one line per check, with its status: `ok`, `PARTIAL` (could
  not see everything; see the detail), `skipped`, `unsupported` or `FAILED`.
* **Findings**: rules `AW-SYS-001` to `AW-SYS-029`, described with their
  false positives in [system-checks.md](../detection/system-checks.md).
  Each finding names the defining file and the entry. Review them yourself.
  Nothing is removed automatically.
* **Informational**: context such as kernel taint from vendor drivers. It
  does not affect the exit status.
* **Persistence inventory**: counts by mechanism. `--show-inventory` or the
  JSON report gives every entry, with the command and executable.

The report can contain command lines from crontabs and units, which may
include sensitive arguments. Environment values are not copied, apart
from dynamic-loader variables.

## Exit status

| Code | Meaning |
|---|---|
| 0 | All checks completed, nothing to review |
| 1 | At least one non-informational finding |
| 2 | Usage or fatal error (e.g. the root cannot be opened) |
| 3 | No findings, but some check was partial, failed or unsupported |
| 130 | Cancelled |

## Limits

A kernel-level rootkit can hide from every check that runs inside the
system it controls. Treat a clean live result as "nothing found", not
"clean". For assurance, boot trusted media, mount the suspect disk
read-only, and run `system-check --root` and `scan` against it. See
[system-checks.md](../detection/system-checks.md#what-the-checks-cannot-do).
