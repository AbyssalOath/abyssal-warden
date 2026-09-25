# Remediation

**Linux only.** On other platforms the quarantine commands report that they
are not supported. Design and guarantees:
[docs/security/quarantine.md](../security/quarantine.md).

Quarantine moves a file into a private store, encoded so it cannot run, and
removes the original, only after the stored copy has been verified. It is
reversible until you delete the item.

## After a scan

```sh
abyssal-warden scan --trusted-key project.pub -s db.json --quarantine /home
```

Only findings that are **exact hash matches against a database entry
categorised as malware** are quarantined automatically, and never files under
system directories (`/usr`, `/etc`, `/boot`, …). YARA, heuristic and test
findings are left in place and marked `not eligible`, with the reason, in the
report. The file's hash is checked again at quarantine time, so a file that
changed after the scan is not touched.

## Manually

```sh
abyssal-warden quarantine add /home/u/Downloads/invoice.exe [--sha256 HEX] [--note TEXT]
abyssal-warden quarantine list
abyssal-warden quarantine show ID
abyssal-warden quarantine restore ID --yes [--to DIR]
abyssal-warden quarantine delete ID --yes
abyssal-warden quarantine verify-log
```

* Paths must be absolute and contain no symbolic links. Files with more than
  one hard link are refused. `--allow-protected` is needed for files under
  system directories; use it only if you are certain.
* **Restore** never overwrites an existing file. It refuses directories that
  other users can write to, and does not restore setuid/setgid bits. As a
  normal user it cannot restore the original owner.
* **Delete** is permanent. The record stays for the audit trail.
* The store is `~/.local/share/abyssal-warden/quarantine` for normal users
  and `/var/lib/abyssal-warden/quarantine` for root (`--store DIR` to
  override). You can only quarantine files you are allowed to delete.

## What quarantine does not do

It does not stop a running process, remove persistence (services, cron,
autostart) that points to the file, or clean up anything else the malware
changed. Removing one file rarely removes a compromise; use your
incident-response procedures.
