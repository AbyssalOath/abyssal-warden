# Content updates

`abyssal-warden update` downloads the latest signed content bundle from an
update source, verifies it completely and installs it. Scans use installed
bundles with `--installed`. Design:
[ADR-0020](../architecture/decisions/0020-content-updates.md); trust model:
[content-trust.md](../security/content-trust.md).

**Status:** the mechanism is implemented and tested. **The project does not
publish an update channel yet**: there is no official URL and no project
keys. Until there is, use it with your own signed bundles or a mirror.

## Updating

```sh
abyssal-warden update --source https://updates.example.org/abyssal-warden
abyssal-warden scan --installed /home
```

| Option | Default | Meaning |
|---|---|---|
| `--source URL\|DIR` | `$ABYSSAL_WARDEN_UPDATE_SOURCE`, else the official channel | An `https://` URL or a local directory (offline mirror). `http://` is refused |
| `--content-dir DIR` | see below | Where bundles are installed, one subdirectory per bundle name |
| `--content-state FILE` | as for scans | Rollback and freshness records |
| `--keyring FILE`, `--trusted-key FILE` | built-in project keyring and system keyring | Trusted keys. The keyring must give a key the `timestamp` role |
| `--allow-expired` | off | Accept an expired timestamp or bundle (offline mirrors only; stale content misses new threats) |
| `--format human\|json` | `human` | Output format |

Default content directory: `/var/lib/abyssal-warden/content` as root;
`$XDG_DATA_HOME/abyssal-warden/content` (default `~/.local/share/...`) for
other users; `%ProgramData%\AbyssalWarden\Content` (elevated) or
`%LOCALAPPDATA%\AbyssalWarden\Content` on Windows.

`scan --installed` and `system-check --installed` load every bundle in the
content directory (`--content-dir` to choose another). They fail if nothing
is installed, rather than silently scanning without content.

Exit status: 0 when the bundle was installed or is already current, 2 on any
error. On error the installed bundle is unchanged.

## What is checked

In order, before anything is installed:

1. `timestamp.json` is signed by a key with the **timestamp** role, has not
   expired, is not older than one seen before, and does not name an older
   bundle than the installed one.
2. `manifest.json` has exactly the size and SHA-256 the timestamp names.
3. Every file is downloaded into a private staging directory with its size
   and SHA-256 checked.
4. The staged bundle is verified exactly as a scan would verify it: content
   key signatures and threshold, key validity and revocation, expiry,
   rollback, and all content parsed and compiled.
5. It is swapped into place atomically; an interrupted swap is recovered on
   the next run.

HTTPS uses the operating system's certificate store, at most 3 redirects, a
30-second connect timeout and a 15-minute limit per request. Every download
has a size limit. TLS is not what makes content trustworthy; signatures are.

## In the service

Set `update_source` in `service.json` and add a schedule of kind `update`
([service.md](service.md#configuration)):

```json
{
  "update_source": "https://updates.example.org/abyssal-warden",
  "schedules": [
    { "name": "content", "kind": "update", "every_hours": 6 },
    { "name": "daily-home", "paths": ["/home"], "every_hours": 24, "at_utc": "03:30" }
  ]
}
```

The packaged systemd unit allows no IP networking. For an `https://`
source, allow it with a drop-in (a local-directory mirror needs nothing):

```sh
sudo systemctl edit abyssal-wardend
# [Service]
# RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
sudo systemctl restart abyssal-wardend
```

The update runs as the scanner account with no capabilities, into that
account's service state directory. Scans and system checks the service runs
as the scanner account then use the installed bundles automatically. Scans
run as the requesting user do not (they use `content` only).

## Publishing

Layout of an update source (a static directory or web root):

```text
timestamp.json            timestamp.json.minisig
manifest.json             manifest.json.minisig   (manifest.json.minisig.2, ... for thresholds)
<content files listed in manifest.json>
```

Steps, with content keys offline and the timestamp key where the publishing
job runs:

```sh
# 1. Build content (see docs/detection/content-sources.md for feeds).
abyssal-warden content import-hashes feed.sha256 -o bundle/feed.json \
  --db-name feed --db-version 2026-09-28 --detection-name Feed.Malware \
  --id-prefix FEED --license "BSD-2-Clause (source ...)"
abyssal-warden content import-yara upstream-rules/ -o bundle/rules
cp upstream-LICENSE bundle/LICENSE-feed.txt

# 2. Manifest, signed offline with the content key(s).
abyssal-warden content manifest bundle --name official --sequence 2026092801
rsign sign -s content.key bundle/manifest.json

# 3. Timestamp, signed with the timestamp key. Repeat this step (with a
#    higher --version) well before it expires, even when content is unchanged.
abyssal-warden content timestamp bundle --version 1 --expires-in 72
rsign sign -s timestamp.key bundle/timestamp.json
```

The keyring shipped to clients lists the timestamp key with
`"roles": ["timestamp"]` ([content-trust.md](../security/content-trust.md#keyrings)).

### On GitHub Releases

A ready-made kit for the content repository (scheduled timestamp refresh
workflow, setup steps, release commands) is in
[`packaging/content-channel/`](../../packaging/content-channel/README.md).

The project channel will use GitHub Releases of a repository that holds
only content, so its "latest" release is always the current bundle:

```text
https://github.com/<owner>/<content-repo>/releases/latest/download/
```

Clients follow two redirects (to the tagged release, then to GitHub's asset
host), within the limit of three. A missing optional file (a further
threshold signature) is a normal 404.

* Release assets cannot have paths, so bundles must be **flat**: put every
  file at the top of the bundle directory (`import-yara -o bundle`) and
  build the manifest with `content manifest --flat`, which refuses
  subdirectories.
* Upload every bundle file, `manifest.json` and its signatures, and
  `timestamp.json` with its signature, to one release.
* Refresh the timestamp before it expires even when content is unchanged:
  `content timestamp` with a higher `--version`, sign, then
  `gh release upload <tag> timestamp.json timestamp.json.minisig --clobber`.
* A client that runs while a release is being uploaded may see files that do
  not match; it refuses them and succeeds on its next run.
