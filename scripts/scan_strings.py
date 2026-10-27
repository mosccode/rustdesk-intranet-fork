#!/usr/bin/env python3
"""Scan a built artifact for strings that must not be in an intranet-only build.

Checks both ASCII and UTF-16LE encodings. ``FAIL`` patterns are vendor domains
that the acceptance criteria require to be absent; ``INFO`` patterns are module
names or public addresses reported for the record (some, such as the pinned
option name ``relay-fallback-delay``, are expected).

Usage:
    python scripts/scan_strings.py <file-or-dir> [...]
"""
import hashlib
import os
import sys

FAIL = [
    "rustdesk.com",
    "rustdesk.cn",
    "api.rustdesk.com",
    "hbbs.rustdesk.com",
    "telegram.org",
    "googleapis.com",
    "gstatic.com",
    "nip.io",
]

INFO = [
    "rendezvous",
    "relay",
    "reqwest",
    "tungstenite",
    "updater",
    "telegram",
    "8.8.8.8",
    "1.1.1.1",
    "2001:4860",
    "github.com/rustdesk",
]

SKIP_EXT = {".pdb", ".lib", ".exp", ".ilk", ".obj", ".zip", ".png", ".ico"}


def iter_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, names in os.walk(path):
                for name in names:
                    if os.path.splitext(name)[1].lower() in SKIP_EXT:
                        continue
                    yield os.path.join(root, name)
        elif os.path.isfile(path):
            yield path
        else:
            raise SystemExit(f"not found: {path}")


def encodings(needle):
    yield "ascii", needle.encode("ascii")
    yield "utf16", needle.encode("utf-16le")


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    failed = False
    files = list(iter_files(argv))
    for path in files:
        data = open(path, "rb").read()
        digest = hashlib.sha256(data).hexdigest()
        print(f"\n== {path}  ({len(data)} bytes, sha256 {digest})")
        for name, needles in (("FAIL", FAIL), ("INFO", INFO)):
            for needle in needles:
                hits = []
                for enc, pat in encodings(needle):
                    count = data.count(pat)
                    if count:
                        hits.append(f"{enc}={count}")
                if hits:
                    mark = "FAIL" if name == "FAIL" else "info"
                    print(f"  [{mark}] {needle}: {', '.join(hits)}")
                    if name == "FAIL":
                        failed = True
    print("\nRESULT:", "FAIL - vendor string found" if failed else "PASS - no vendor domains")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
