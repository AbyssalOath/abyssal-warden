# Third-party detection content: sources and licences

**Status:** the official bundle will contain **ESET malware-ioc** and
**ReversingLabs YARA rules** (owner decision, 2026-09-28); Neo23x0
signature-base is noted for later. The build pipeline exists and has been
run locally; **nothing is published yet**
([ADR-0020](../architecture/decisions/0020-content-updates.md)).

Rules for every source:

* The licence is read **before** anything is imported, and recorded in the
  content itself (`database.license` for hash databases; rule metadata and a
  licence file for YARA).
* Every bundle carries the licence and notice files of its sources
  (`LICENSE*`, `NOTICE*`, `*.txt`, `*.md` are included as notice files by
  `content manifest`).
* Nothing is imported whose licence forbids redistribution or needs terms
  this project cannot meet. When in doubt, a source is left out.
* Content is re-checked on every import: licences change.

Reviewed in September 2026. This is an engineering summary, not legal
advice; re-read each licence before relying on it.

## Summary

| Source | Content | Licence | Decision |
|---|---|---|---|
| [ESET malware-ioc](https://github.com/eset/malware-ioc) | SHA-1/SHA-256 IOCs and YARA rules from ESET research | BSD-2-Clause | **Shipped**, with the copyright notice and licence in the bundle |
| [ReversingLabs YARA rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | YARA rules for malware families | MIT | **Shipped**, with the copyright notice and licence in the bundle |
| [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) | YARA rules and IOCs | Detection Rule License 1.1 | **Later**: usable with conditions (rule author and reference attribution in match output, which is implemented; the licence link; no rules that need external variables). Deferred because it is large and broad, so its false-positive rate should be measured on a Windows clean corpus first |
| [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) | SHA-256 hashes of samples | Fair-use terms; API needs an auth key; commercial use needs a subscription; derivative works need consent | **Not redistributed.** Users may import it locally with their own key |
| [Elastic protections-artifacts](https://github.com/elastic/protections-artifacts) | YARA and behaviour rules | Elastic License 2.0 | **Excluded**: not an open-source licence, restrictions incompatible with AGPL redistribution |
| [YARA Forge](https://github.com/YARAHQ/yara-forge) | Aggregated rule packages | Mixed (one per upstream source) | **Skipped**: use the upstream sources directly, each with its own licence |

## Detection Rule License (DRL 1.1) compliance

The DRL requires that anyone using the rules gets the author attribution
and a reference to the licence **in the output** of matches. Abyssal
Warden keeps the `author`, `reference` and `license` metadata of every YARA
rule and adds them to each finding's evidence
(`Rule author: ...; reference: ...; licence: ...`). The bundle includes
the licence text. Rules whose metadata was stripped are not imported.

signature-base contains rules that use YARA **external variables**
(`filename`, `filepath`, `extension`, `filetype`, `owner`), which this
project does not define. They fail to compile and `content import-yara`
skips them with the reason; they can also be listed in an `--exclude` file.

## MalwareBazaar locally

The terms do not allow redistributing MalwareBazaar data in our bundles.
A user who accepts those terms can convert an export they downloaded with
their own auth key into a local, self-signed database:

```sh
abyssal-warden content import-hashes full_sha256.txt -o bazaar.json \
  --db-name malwarebazaar-local --db-version 2026-09-28 \
  --detection-name MalwareBazaar.Sample --id-prefix MB \
  --license "abuse.ch MalwareBazaar terms; local use only"
```

and sign it with a key they trust (`--trusted-key`), as for any local
database ([signatures.md](signatures.md#signing)).

## Importing

`content import-hashes` reads SHA-256 lists (one digest per line, optionally
followed by a file name as `sha256sum` prints it; `#` comments allowed),
de-duplicates them and writes a hash database. Lines that are not SHA-256
are counted and skipped. The result is validated with the scanner's own
loader before it is written.

`content import-yara` compiles each rule file on its own under this
project's restrictions (explicit module list, no `include`, no slow
patterns, valid metadata) and copies the files that pass. The rest are
reported with the reason, so one bad file does not stop a whole feed.

Both take `--clean-corpus DIR` (repeatable; links inside are followed):
hashes that match a clean file are dropped, and so is every rule file with
a rule that matches one. `import-hashes --name-by-directory` names
detections after each list's directory (`ESET.blacklotus`);
`import-yara --prefix` keeps feeds apart in a flat bundle.

Accepted content then goes through the normal release steps: `content
manifest`, the offline signatures, `content timestamp` and the timestamp
signature ([updates](../user/updates.md#publishing)).

## Building the official bundle

`packaging/content-channel/scripts/build-bundle.sh` builds it from the
feeds pinned (by full commit) in `packaging/content-channel/feeds.lock`:

1. fetch each feed at exactly its pinned commit;
2. import ESET's `samples.sha256` lists, one detection name per campaign;
3. import and vet ESET's and ReversingLabs' YARA files (`eset-`, `rl-`
   prefixes);
4. drop anything that matches the clean corpus (default: `/usr/bin`,
   `/usr/lib64`, `/usr/lib`);
5. add both licences and `SOURCES.md` (feeds, commits, what was left out);
6. write a flat manifest. Signing is done afterwards, offline.

A pin is updated only after reviewing the upstream changes and re-reading
the licence.

**ESET campaigns that list clean files are left out.** ESET's reports
sometimes mark files in a campaign as clean (abused legitimate programs,
third-party tools). Most such files are not in the hash lists, but where
one is, the report gives only its SHA-1, so its SHA-256 cannot be removed
by itself. The script skips the whole campaign and names it in
`SOURCES.md`. At the pinned commit this is `amavaldo` (13 hashes, 5 of
them clean programs such as `gup.exe` and `ctfmon.exe`).

**Trial build (2026-09-28, pinned commits above):** 6,100 ESET hashes, 24
ESET and 310 ReversingLabs rule files; every rule file passed vetting;
nothing matched 10,538 clean files (this machine's `/usr/bin`,
`/usr/lib64` and 128 Windows DLL/EXE files found on it). Loaded as a
signed bundle, it scanned 1,665 files in 2.6 s, using about 690 MB of
memory (mostly the compiled rules).

Limits of that check:

* The clean corpus is Linux files plus a handful of Windows files, while
  most of these rules target Windows. Their false-positive rate on
  Windows is **unmeasured**.
* Third-party rules have no `aw_*` metadata, so their findings are
  reported as `suspicious`, medium confidence and severity, category
  `unknown` (never automatically quarantined). ESET hash matches are
  `malware`, high severity, and are eligible for `--quarantine`.
* No detection rate has been measured ([testing.md](testing.md)). Until
  it is, no claim about detection coverage is made.

## Not yet done

* A Windows clean corpus for the false-positive check.
* Mapping upstream rule metadata (for example ReversingLabs' category and
  malware type) to findings.
* Running the pipeline on a schedule; today it is run by hand before each
  release.
