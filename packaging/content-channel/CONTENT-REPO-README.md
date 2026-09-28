# Abyssal Warden detection content

Signed detection content for [Abyssal Warden](https://github.com/AbyssalOath/abyssal-warden).
This repository holds no code of the scanner. Each **release** is one
content bundle; the latest release is what clients install:

```sh
abyssal-warden update --source https://github.com/AbyssalOath/abyssal-warden-content/releases/latest/download/
```

## What is in a bundle

Content converted from openly licensed feeds, pinned by commit and listed
with their licences in each release's `SOURCES.md`:

* [ESET malware-ioc](https://github.com/eset/malware-ioc) (BSD-2-Clause):
  sample hashes and YARA rules from ESET research.
* [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules)
  (MIT).

Rules and hashes that match known-clean files are removed before release.
Detection rates have not been measured; see the main project's
documentation before relying on this content.

## How it is protected

* Every bundle manifest is signed offline with a content key.
* `timestamp.json` is re-signed twice a day by this repository's workflow
  with a separate timestamp key. It can only confirm which bundle is
  current; it cannot change content. Clients refuse stale, replayed or
  mismatched timestamps.
* Clients trust only the keys in the keyring shipped with the software
  (`keys/keyring.json` here, for reference):

| Key ID | Role |
|---|---|
| `E38F08952E4891C4` | content (signs releases) |
| `4102DBFF6CC818E7` | content (standby) |
| `9E95EAD8F3B83A9D` | content (standby) |
| `D6307A0B86E9900B` | timestamp (online) |
| `0146DC1FDAF84B3D` | timestamp (offline backup) |

Details: [content trust](https://github.com/AbyssalOath/abyssal-warden/blob/main/docs/security/content-trust.md)
and [updates](https://github.com/AbyssalOath/abyssal-warden/blob/main/docs/user/updates.md).

## Reporting problems

False positives or a suspected key compromise: open an issue in the
[main repository](https://github.com/AbyssalOath/abyssal-warden), or
follow its security policy for anything sensitive.
