# Content trust: bundles, keyrings, rollback and expiry

Decision records: [ADR-0012](../architecture/decisions/0012-content-bundles.md),
[ADR-0013](../architecture/decisions/0013-threshold-floors-revocation.md).
Implementation: `crates/engine/src/bundle.rs`, `content_state.rs`,
`trust.rs`; CLI `crates/cli/src/content.rs`, `content_cmd.rs`.

Detection content (hash databases, YARA rules) decides what is reported and,
with `--quarantine`, what is moved off disk. This document covers how the
scanner decides which content to trust, and how the project must manage its
signing keys.

## What is protected

| Threat | Protection |
|---|---|
| Forged or modified content | minisign (Ed25519) signature over the manifest, which pins every file by size and SHA-256 |
| **Rollback** to an older, validly signed release (e.g. one missing new detections) | Strictly increasing `sequence`, recorded per bundle name in a local state file; older sequences are refused |
| **Equivocation** (two different releases with the same sequence) | The recorded manifest hash must match for an equal sequence |
| **Freeze** (serving a stale but valid bundle indefinitely) | Every manifest has `expires`; expired bundles are refused unless `--allow-expired` is given, and the report warns 7 days before expiry |
| **Mix-and-match** (old rules with a new database) | One manifest pins all files of a bundle together |
| Compromised or retired signing key | Keyring with `revoked` flags and `not_before`/`not_after` windows; **revocations carried by accepted manifests** (`revoke_keys`) |
| One stolen key publishing content | **Threshold signatures**: the keyring can require N distinct signers |
| Old release accepted on a **fresh machine** (no rollback record yet) | **Sequence floors** in the keyring shipped with each release |
| Bundle files that escape the bundle directory (symlinks, `..`) | Paths are validated, files are opened relative to the bundle directory (cap-std), links are not followed |

Per-file signed content (`--signatures FILE`, `--yara PATH` with
`FILE.minisig`) is still supported, but has **no** rollback or expiry
protection; the report says so.

## Bundle format

```text
bundle/
  manifest.json            what is signed
  manifest.json.minisig    minisign signature of manifest.json
  manifest.json.minisig.2  optional further signatures (up to .16)
  signatures/*.json        hash databases
  rules/*.yar              YARA rules
```

```json
{
  "format": "abyssal-warden.content-manifest",
  "format_version": 1,
  "name": "abyssal-warden-official",
  "sequence": 2026092501,
  "issued": "2026-09-25T00:00:00Z",
  "expires": "2026-10-25T00:00:00Z",
  "files": [
    { "path": "rules/family.yar", "kind": "yara_rules", "size": 1234, "sha256": "..." },
    { "path": "signatures/main.json", "kind": "hash_database", "size": 5678, "sha256": "..." }
  ],
  "revoke_keys": ["70EF691BC71E4DD9"]
}
```

`revoke_keys` is optional (up to 64 key IDs; add with
`content manifest --revoke-key ID`).

Rules: `name` is `[A-Za-z0-9._-]{1,128}`; `sequence` ≥ 1; `expires` after
`issued`; 1 to 10,000 files; paths are relative, `/`-separated, with no `.`,
`..`, backslashes, colons, control or bidi characters, and no duplicates; each
file ≤ 256 MiB. Unknown fields are rejected. Files in the directory that the
manifest does not list are ignored.

## Load sequence

1. Read `manifest.json` (≤ 1 MiB) and verify every signature file present
   (`.minisig`, `.minisig.2` … `.16`) at the current time. Count **distinct**
   trusted keys that are valid now and not revoked (by the keyring or by a
   revocation recorded from an earlier manifest). Fewer than the keyring's
   threshold (default 1) is refused, with the reason for each signature.
2. Parse and validate the manifest.
3. Refuse it if expired (unless `--allow-expired`).
4. Check rollback: refuse a sequence below the recorded one **or below the
   keyring's floor for that bundle name**, or an equal sequence with a
   different manifest hash.
5. Read each listed file relative to the bundle directory and check its size
   and SHA-256.
6. Parse the content (hash databases, YARA rules).
7. Only when **every** bundle has loaded: record the accepted sequences and
   the keys the manifests revoke in the state file (atomic write, exclusive
   lock). Revocations also apply at once to later bundles in the same run,
   and to individually signed files in later runs.

`content verify` performs steps 1 to 6 and records nothing.

## Keyrings

```json
{
  "format": "abyssal-warden.keyring",
  "format_version": 1,
  "policy": { "threshold": 2 },
  "bundles": [ { "name": "abyssal-warden-official", "min_sequence": 2026092501 } ],
  "keys": [
    { "id": "70EF691BC71E4DD9", "public_key": "RW...", "description": "...",
      "not_before": "2026-09-25T00:00:00Z", "not_after": "2028-09-25T00:00:00Z",
      "revoked": false }
  ]
}
```

* `id` must match the public key (checked).
* `policy.threshold` (1 to 16): distinct signers a bundle manifest needs.
  With more than 1, individually signed files are refused. Several keyrings:
  the highest threshold wins.
* `bundles[].min_sequence`: the lowest acceptable sequence for that bundle,
  set to the current release when the keyring is published. It protects
  fresh installations. Several keyrings: the highest floor wins.
* The **system keyring** (`/etc/abyssal-warden/keyring.json`; Windows
  `%ProgramData%\AbyssalWarden\keyring.json`) is always loaded when present,
  so its revocations also apply to keys given with `--trusted-key`.
* Keys are never learned from content. A compromised key could otherwise add
  keys that outlive its own revocation. Keyrings change only through the
  channel that installs the software (package, release).

## State file

| Where | Path |
|---|---|
| root (Linux) | `/var/lib/abyssal-warden/content-state.json` |
| other Unix users | `$XDG_STATE_HOME/abyssal-warden/content-state.json` (default `~/.local/state/...`) |
| Windows | `%LOCALAPPDATA%\AbyssalWarden\content-state.json` |

Override with `--content-state FILE`. The file is 0600 in a 0700 directory
(Unix), written atomically under a lock. If it is unreadable the scanner
**fails closed**: deleting it is an explicit, visible reset of rollback
protection.

## Project signing-key procedure

**Status: no project key exists yet.** The example content in `examples/`
is signed with a throwaway test key (`70EF691BC71E4DD9`) whose secret was
discarded. It must never be trusted outside testing. Before the first real
content release, the project owner performs the following.

### Tools

Sign with a dedicated tool, not with Abyssal Warden. The scanner never
handles secret keys, so a scanner bug cannot leak one.

* **`rsign2`** (Rust implementation of minisign; `cargo install rsign2`):
  recommended, consistent with the project's Rust-first approach.
* `minisign` (C, the reference implementation): equivalent and compatible.

### 1. Generate keys (offline)

On offline machines, generate **three** keys held by **different
maintainers**: two for signing each release (threshold 2), and one standby
for rotation and compromise recovery. Protect every secret key with a
strong password. (With a single maintainer, use two keys and threshold 1,
and move to threshold 2 as soon as there is a second key holder.)

```sh
rsign generate -p aw-content-2026A.pub -s aw-content-2026A.key -c "Abyssal Warden content 2026A"
rsign generate -p aw-content-2026B.pub -s aw-content-2026B.key -c "Abyssal Warden content 2026B"
rsign generate -p aw-content-2026C.pub -s aw-content-2026C.key -c "Abyssal Warden content 2026C (standby)"
```

* Store each secret key on separate offline media, with separate backups in
  different physical locations. Ideally different maintainers hold A and B.
* Never put a secret key in CI, a repository, or an online machine.

### 2. Publish

* Commit both **public** keys to `keys/` in the repository.
* Build the keyring with all keys valid (so rotation needs no keyring
  change), `not_after` about two years out, `policy.threshold` 2, and a
  `bundles` floor equal to the latest release's sequence. Update the floor
  in every software release.
* Ship the keyring with releases and packages as
  `/etc/abyssal-warden/keyring.json`.
* Publish the key IDs out of band too (release notes, website, signed tag),
  so users can cross-check.

### 3. Sign each content release

1. Build the bundle directory and run
   `abyssal-warden content manifest DIR --name abyssal-warden-official --sequence N --expires-in 30`.
   Use date-based sequences (`YYYYMMDDNN`) so they always increase.
2. Move `manifest.json` (only the manifest: it pins every file by hash) to the
   signing machine. Review it: name, sequence higher than the last release,
   expiry, file list.
3. Each signer signs, into a separate file:
   `rsign sign -s aw-content-2026A.key -t "abyssal-warden-official N" manifest.json`
   then `rsign sign -s aw-content-2026B.key -t "abyssal-warden-official N" -x manifest.json.minisig.2 manifest.json`.
4. Return `manifest.json.minisig`, run `content verify` with the release
   keyring, and publish.
5. Publish a new release before the old one expires. Clients warn during the
   last 7 days.

### 4. Planned rotation

Sign new releases with the standby key B. Ship a keyring update that gives A
a `not_after` a few weeks ahead (covering clients that update slowly). Then
generate a new standby key C and add it in the same or a later keyring update.

### 5. Key compromise

1. Publish the next bundle immediately, signed by the remaining keys (the
   standby key replaces the compromised one), with
   `content manifest ... --revoke-key <COMPROMISED_ID>` and a sequence higher
   than anything the attacker might have signed. Every client that accepts
   it records the revocation. This is the fast path, and rollback protection
   keeps clients from going back.
2. Ship a keyring update with the key `"revoked": true` and the standby key
   promoted, with a security advisory (covers fresh installations).
3. Generate a new standby key.

Limitations: a client that never receives a newer bundle only learns of the
revocation from a keyring update. There is no online freshness check (that
needs TUF's timestamp role; see [update-security.md](update-security.md)).

## Testing

Engine unit tests cover keyring parsing, revocation, validity windows, and
revocation overriding `--trusted-key`; bundle loading; same-size and
different-size tampering; untrusted and unsigned manifests; expiry; paths
escaping the bundle; manifest rules; rollback, equivocation, persistence,
corrupt state and permissions. CLI tests run the whole flow with the real
`content manifest` command and freshly signed bundles.
