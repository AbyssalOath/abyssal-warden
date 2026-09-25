# Hash signature databases

Decision record: [ADR-0003](../architecture/decisions/0003-hash-signature-format.md).
Implementation: `crates/engine/src/signatures.rs`.

## What it detects

Files whose SHA-256 is **exactly** equal to a signature's `sha256`. A match
proves the file is byte-for-byte identical to the indicator. Changing a single
byte defeats it, so exact-hash matching is a baseline that complements, but
does not replace, pattern and behavioural detection.

## Format (version 1)

```json
{
  "format": "abyssal-warden.hash-signatures",
  "format_version": 1,
  "database": {
    "name": "example-db",
    "version": "2026.09.24.1",
    "description": "optional, ≤ 4096 bytes, newlines allowed",
    "license": "optional, the licence of this data, e.g. CC0-1.0"
  },
  "signatures": [
    {
      "id": "AW-TEST-0001",
      "name": "AbyssalWarden.Test.SyntheticIndicator",
      "sha256": "26d11a0d2767bb969011c61c58953c5d89035f8c2ca524efcafe3a9c92461eae",
      "category": "test_indicator",
      "severity": "info",
      "rule_version": 1,
      "description": "optional",
      "remediation": "optional guidance shown to the user"
    }
  ]
}
```

| Field | Rules |
|---|---|
| `format` | Must equal `abyssal-warden.hash-signatures` |
| `format_version` | Must equal `1`; others are rejected with "unsupported version" |
| `database.name` | 1-256 bytes, no control/bidi characters |
| `database.version` | 1-64 bytes, no control/bidi characters. Used in reports; will be used for rollback protection |
| `signatures[].id` | 1-128 characters from `[A-Za-z0-9._:-]`; unique within the database |
| `signatures[].name` | 1-256 bytes, no control/bidi characters |
| `signatures[].sha256` | 64 hex characters (either case); unique within the database |
| `signatures[].category` | `malware`, `potentially_unwanted`, `test_indicator`, `unknown` |
| `signatures[].severity` | `info`, `low`, `medium`, `high`, `critical` |
| `signatures[].rule_version` | Integer ≥ 1; bump it when the entry's meaning changes |
| `description`, `remediation` | Optional, ≤ 4096 bytes; newlines and tabs allowed, other controls rejected |

Global limits: file ≤ 256 MiB, ≤ 2,000,000 signatures. Unknown fields
anywhere cause rejection. Any invalid entry rejects the whole database.

## Resulting finding

* `kind = known_indicator`, `confidence = confirmed`
* `severity` and `category` come from the signature
* `recommended_action`: `quarantine` for `malware`, `none` for
  `test_indicator`, `review` otherwise. This is advisory only.
* `source` records detector version, `rule_id`, `rule_version`, and database
  name and version
* evidence `exact_sha256_match`

## Creating and validating a database

```sh
abyssal-warden hash suspicious.bin           # prints the SHA-256
abyssal-warden signatures validate my-db.json
```

## Content policy

* The repository ships **only synthetic test indicators**
  (`examples/signatures/`). They match harmless files created for testing.
* Do not add third-party hash lists without confirming that their licence
  permits redistribution. Record that licence in `database.license`.
* Hash lists of real malware are welcome as *separate* databases whose
  provenance is documented. Never commit the samples themselves.

## Signing

Decision record: [ADR-0007](../architecture/decisions/0007-content-signing.md).

Databases and YARA rule files are signed with
[minisign](https://jedisct1.github.io/minisign/) (Ed25519). The signature
for `db.json` is `db.json.minisig`, next to it.

```sh
minisign -G -p project.pub -s project.key          # once; keep the secret key offline
minisign -S -s project.key -m db.json -t "db.json 2026.09.24.1"
abyssal-warden signatures validate --trusted-key project.pub db.json
```

* By default, `scan`, `signatures validate` and `yara validate` refuse
  content that is not signed by a key given with `--trusted-key`.
* `--allow-unsigned` accepts files that have **no** signature file. A
  signature that is present but fails verification is always an error.
* Only prehashed signatures (minisign's default) are accepted.
* Verification happens before parsing. The verifying key ID appears in the
  report as `detectors[].database.signer`; reports warn about unsigned
  content.
* The example content is signed with a throwaway test key
  (`examples/keys/synthetic-test.pub`, key ID `4B646D33D8084FE3`). Its secret
  key was discarded. **Never trust this key outside testing.** Editing an
  example file invalidates its signature.

**Not provided yet:** rollback protection (an older, validly signed
database is accepted), expiry, key rotation. See
[update-security.md](../security/update-security.md).
