#!/usr/bin/env python3
"""Write timestamp.json for an Abyssal Warden content release.

Runs in the content repository's scheduled workflow, next to the timestamp
signing key, so it uses only the Python standard library (no build, no
downloaded packages). The format must match
crates/engine/src/freshness.rs; the client re-checks everything.

The version is max(previous version + 1, current Unix time), so it always
increases, even if the previous timestamp is missing.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

FORMAT = "abyssal-warden.content-timestamp"
MAX_LIFETIME_HOURS = 31 * 24
MAX_MANIFEST_BYTES = 1024 * 1024  # bundle.rs MAX_MANIFEST_BYTES
NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def rfc3339(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def previous_version(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0
    try:
        with open(path, "rb") as f:
            v = json.load(f).get("version", 0)
    except (OSError, ValueError, AttributeError):
        return 0
    return v if isinstance(v, int) and v >= 0 else 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", required=True)
    p.add_argument("--previous", help="timestamp.json currently published (optional)")
    p.add_argument("--expires-in-hours", type=int, default=72)
    p.add_argument("--out", required=True)
    a = p.parse_args()

    if not 1 <= a.expires_in_hours <= MAX_LIFETIME_HOURS:
        fail(f"--expires-in-hours must be 1 to {MAX_LIFETIME_HOURS}")
    with open(a.manifest, "rb") as f:
        data = f.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        fail("manifest too large")
    try:
        manifest = json.loads(data)
    except ValueError as e:
        fail(f"manifest is not JSON: {e}")
    if manifest.get("format") != "abyssal-warden.content-manifest":
        fail("not an Abyssal Warden content manifest")
    name, sequence = manifest.get("name"), manifest.get("sequence")
    if not isinstance(name, str) or not NAME.match(name):
        fail("manifest name is invalid")
    if not isinstance(sequence, int) or sequence < 1:
        fail("manifest sequence is invalid")

    now = datetime.now(timezone.utc).replace(microsecond=0)
    ts = {
        "format": FORMAT,
        "format_version": 1,
        "version": max(previous_version(a.previous) + 1, int(time.time())),
        "bundle": name,
        "sequence": sequence,
        "manifest_sha256": hashlib.sha256(data).hexdigest(),
        "manifest_size": len(data),
        "issued": rfc3339(now),
        "expires": rfc3339(now + timedelta(hours=a.expires_in_hours)),
    }
    out_dir = os.path.dirname(os.path.abspath(a.out))
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".timestamp-")
    with os.fdopen(fd, "w") as f:
        json.dump(ts, f, indent=2)
        f.write("\n")
    os.replace(tmp, a.out)
    print(f"wrote {a.out}: bundle {name} sequence {sequence}, version {ts['version']}, expires {ts['expires']}")


if __name__ == "__main__":
    main()
