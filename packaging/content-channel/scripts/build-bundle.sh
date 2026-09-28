#!/usr/bin/env bash
# Build the official content bundle from the pinned feeds in feeds.lock:
# fetch each feed at its exact commit, convert and vet it, drop anything that
# matches known-clean files, add licences and a sources list, and write a
# flat manifest. Signing is NOT done here: sign manifest.json afterwards with
# the offline content key (packaging/content-channel/README.md).
#
# Usage: build-bundle.sh --sequence N --out DIR [--clean-corpus DIR]...
#        [--aw PATH-TO-abyssal-warden] [--expires-in DAYS]
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
lock="$here/feeds.lock"
aw=abyssal-warden
sequence=""
out=""
expires=30
corpus=()

while [ $# -gt 0 ]; do
  case "$1" in
    --sequence) sequence=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --clean-corpus) corpus+=("$2"); shift 2 ;;
    --aw) aw=$2; shift 2 ;;
    --expires-in) expires=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$sequence" =~ ^[0-9]{1,19}$ ]] || { echo "--sequence N is required (e.g. $(date -u +%Y%m%d)01)" >&2; exit 2; }
[ -n "$out" ] || { echo "--out DIR is required" >&2; exit 2; }
if [ -e "$out" ] && [ -n "$(ls -A "$out")" ]; then
  echo "$out is not empty" >&2; exit 2
fi
if [ ${#corpus[@]} -eq 0 ]; then
  for d in /usr/bin /usr/lib64 /usr/lib; do [ -d "$d" ] && corpus+=("$d"); done
  echo "clean corpus (default): ${corpus[*]}"
fi
corpus_args=()
for d in "${corpus[@]}"; do corpus_args+=(--clean-corpus "$d"); done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

# Fetch every pinned feed at its exact commit.
declare -A src commit
while read -r name url rev; do
  [ -z "$name" ] || [ "${name:0:1}" = "#" ] && continue
  [[ "$rev" =~ ^[0-9a-f]{40}$ ]] || { echo "$name: pin must be a full commit" >&2; exit 2; }
  echo "fetching $name at $rev"
  git init -q "$work/$name"
  git -C "$work/$name" fetch -q --depth 1 "$url" "$rev"
  git -C "$work/$name" -c advice.detachedHead=false checkout -q FETCH_HEAD
  [ "$(git -C "$work/$name" rev-parse HEAD)" = "$rev" ] || { echo "$name: commit mismatch" >&2; exit 1; }
  src[$name]=$url; commit[$name]=$rev
done < "$lock"

eset=$work/eset-malware-ioc
rl=$work/reversinglabs-yara-rules
eset_rev=${commit[eset-malware-ioc]}
rl_rev=${commit[reversinglabs-yara-rules]}

# ESET hash lists, one detection name per campaign directory. A campaign
# whose report marks any listed file as clean ("Clean file", "clean",
# "Legitimate App") is skipped whole: those rows give only SHA-1, so the
# matching SHA-256 cannot be removed on its own.
lists=()
skipped_campaigns=()
mapfile -t all_lists < <(find "$eset" -name samples.sha256 | sort)
for list in "${all_lists[@]}"; do
  dir=$(dirname "$list")
  readme=$dir/README.adoc
  clean_listed=""
  if [ -f "$readme" ]; then
    mapfile -t marked < <(grep -iE '\|[[:space:]]*(clean file|clean|legitimate app)[[:space:]]*\|' "$readme" \
               | grep -oE '[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32}' || true)
    for h in "${marked[@]}"; do
      if grep -qi "$h" "$dir"/samples.* 2>/dev/null; then clean_listed=$h; break; fi
    done
  fi
  if [ -n "$clean_listed" ]; then
    skipped_campaigns+=("$(basename "$dir") (lists $clean_listed, which ESET marks clean)")
  else
    lists+=("$list")
  fi
done
"$aw" content import-hashes "${lists[@]}" -o "$out/eset-hashes.json" \
  --db-name eset-malware-ioc --db-version "${eset_rev:0:12}" \
  --detection-name ESET --id-prefix ESET --name-by-directory \
  --license "BSD-2-Clause; ESET malware-ioc ${eset_rev:0:12}; see LICENSE-eset-malware-ioc.txt" \
  --description "Sample hashes from ESET research publications" \
  "${corpus_args[@]}"

# YARA rules from both feeds, vetted one file at a time.
"$aw" content import-yara "$eset" -o "$out" --prefix eset- "${corpus_args[@]}"
"$aw" content import-yara "$rl/yara" -o "$out" --prefix rl- "${corpus_args[@]}"

# Licences and provenance travel with the content.
cp "$eset/LICENSE" "$out/LICENSE-eset-malware-ioc.txt"
cp "$rl/LICENSE" "$out/LICENSE-reversinglabs-yara-rules.txt"
{
  echo "# Sources of this bundle"
  echo
  echo "Built $(date -u +%Y-%m-%dT%H:%M:%SZ), sequence $sequence."
  echo
  echo "| Feed | Commit | Licence |"
  echo "|---|---|---|"
  echo "| ${src[eset-malware-ioc]} | $eset_rev | BSD-2-Clause (LICENSE-eset-malware-ioc.txt) |"
  echo "| ${src[reversinglabs-yara-rules]} | $rl_rev | MIT (LICENSE-reversinglabs-yara-rules.txt) |"
  echo
  echo "Converted and vetted by Abyssal Warden; rules or hashes that matched"
  echo "known-clean files were removed. Upstream authors are not responsible"
  echo "for this conversion."
  if [ ${#skipped_campaigns[@]} -gt 0 ]; then
    echo
    echo "ESET campaigns left out:"
    for c in "${skipped_campaigns[@]}"; do echo "- $c"; done
  fi
} > "$out/SOURCES.md"

"$aw" content manifest "$out" --flat --name abyssal-warden-official \
  --sequence "$sequence" --expires-in "$expires"
echo
[ ${#skipped_campaigns[@]} -eq 0 ] || printf 'skipped ESET campaign: %s\n' "${skipped_campaigns[@]}"
echo "done. Review $out/SOURCES.md, then sign $out/manifest.json with the content key."
