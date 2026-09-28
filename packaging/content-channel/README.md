# Content channel kit (GitHub Releases)

Files for the **content repository**, a separate repository whose releases
hold only signed content bundles (for example
`AbyssalOath/abyssal-warden-content`). Clients use:

```text
https://github.com/AbyssalOath/abyssal-warden-content/releases/latest/download/
```

A separate repository keeps software releases from ever becoming the
"latest" content release. Design: [ADR-0020](../../docs/architecture/decisions/0020-content-updates.md);
keys: [content-trust.md](../../docs/security/content-trust.md#project-signing-key-procedure).

| File | Purpose |
|---|---|
| `.github/workflows/refresh-timestamp.yml` | Re-signs `timestamp.json` on the latest release twice a day |
| `scripts/refresh_timestamp.py` | Writes `timestamp.json` from a release's `manifest.json` (standard library only) |

## Keys

| Key | Role | Password | Where it lives |
|---|---|---|---|
| Content A | `content` | yes | offline |
| Content B (standby) | `content` | yes | offline, separate media |
| Timestamp online | `timestamp` | **no** | only in the `TIMESTAMP_SECRET_KEY` secret |
| Timestamp backup | `timestamp` | yes | offline |

Generate them as described in content-trust.md. All four go into the
keyring shipped with the software from the first release:

```json
{
  "format": "abyssal-warden.keyring",
  "format_version": 1,
  "policy": { "threshold": 1 },
  "keys": [
    { "id": "<A>", "public_key": "<A>", "roles": ["content"], "description": "content A" },
    { "id": "<B>", "public_key": "<B>", "roles": ["content"], "description": "content B (standby)" },
    { "id": "<T1>", "public_key": "<T1>", "roles": ["timestamp"], "description": "timestamp (online)" },
    { "id": "<T2>", "public_key": "<T2>", "roles": ["timestamp"], "description": "timestamp (backup)" }
  ]
}
```

Generate the entries rather than copying IDs by hand:

```sh
abyssal-warden content key-entry --role content aw-content-2026A.pub aw-content-2026B.pub
abyssal-warden content key-entry --role timestamp timestamp-online.pub timestamp-backup.pub
```

Keyrings whose IDs do not match their keys are refused.

## Repository setup

1. Create the repository (public, so clients can download without a token).
   Turn on 2FA for every account with write access; keep collaborators to
   a minimum. Protect the default branch (no force pushes, reviews if there
   is more than one maintainer).
2. Copy this kit into it: `.github/workflows/refresh-timestamp.yml`,
   `scripts/refresh_timestamp.py` and `CONTENT-REPO-README.md` (as
   `README.md`). Add `keys/timestamp-signing.pub` (the **online** timestamp
   public key; the workflow checks every signature against it) and, for
   reference, the other public keys and `keys/keyring.json`. Until the
   first release exists, scheduled runs finish with a notice and do
   nothing.
3. Settings > Environments > New environment `timestamp-signing`:
   deployment branches **Selected branches: the default branch only**. Add
   the secret `TIMESTAMP_SECRET_KEY` with the full contents of
   `timestamp-online.key`, then delete that file.
4. Settings > Actions > General: allow **only actions created by GitHub**
   (the workflow uses none; this stops a future edit from adding one), and
   leave fork pull request workflows without secrets (the default).

## Publishing a content release

On your machine, with the content key:

```sh
# Build the bundle from the pinned feeds (fetch, convert, vet, drop what
# matches clean files, licences, flat manifest). Signing comes next.
packaging/content-channel/scripts/build-bundle.sh --sequence 2026100101 --out bundle
rsign sign -s aw-content-2026A.key -t "abyssal-warden-official 2026100101" bundle/manifest.json
abyssal-warden content verify bundle --keyring keyring.json

# Upload as a draft, so clients never see a release without a timestamp.
gh release create 2026100101 --repo AbyssalOath/abyssal-warden-content --draft \
  --title "Content 2026100101" bundle/*
# Stamp the draft, then publish it as the latest release.
gh workflow run refresh-timestamp.yml --repo AbyssalOath/abyssal-warden-content -f tag=2026100101
gh run watch --repo AbyssalOath/abyssal-warden-content
gh release edit 2026100101 --repo AbyssalOath/abyssal-warden-content --draft=false --latest
```

Publish a new bundle before the current one expires (30 days above): the
bundle expiry, signed offline, is what limits how long a stolen timestamp
key could hold clients on old content.

## Keeping it running

* A failed run emails the account that last changed the workflow. Two days
  of failures still leave a valid timestamp; after 72 hours clients report
  the channel as expired and keep their installed content.
* GitHub disables scheduled workflows in public repositories after 60 days
  without repository activity. Publishing content regularly (at least
  monthly, which the 30-day expiry already requires) with a commit to the
  repository keeps it active; if it is ever disabled, re-enable it under
  Actions and run it by hand.
* During an upload there is a moment when the release's files do not match;
  a client that updates at that moment refuses them and succeeds next time.

## If the online key leaks

Follow "Online timestamp key leaked" in content-trust.md: delete the secret,
publish a bundle that revokes the online key, stamped by hand with the
backup key. Clients that install it stop trusting the leaked key without a
software update.
