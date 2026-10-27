#!/usr/bin/env python3
"""Extract exact package/version/hash metadata from a Debian Packages file.

Use only with metadata fetched from the repository snapshot pinned in
`docs/debian13/arm64-target.json`. The tool does not download or trust unpinned
repository metadata on its own.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def parse_stanzas(text: str):
    stanza: dict[str, str] = {}
    current_key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if stanza:
                yield stanza
                stanza = {}
                current_key = None
            continue
        if line[0].isspace() and current_key is not None:
            stanza[current_key] += "\n" + line[1:]
            continue
        if ":" not in line:
            raise ValueError(f"malformed Packages line: {line!r}")
        key, value = line.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"empty Packages key: {line!r}")
        current_key = key
        stanza[key] = value.lstrip()
    if stanza:
        yield stanza


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", required=True, type=Path, help="uncompressed Packages index from the pinned snapshot")
    parser.add_argument("--package", default="hello")
    parser.add_argument("--arch", default="arm64")
    parser.add_argument("--version", help="require an exact version when the index contains more than one match")
    args = parser.parse_args()

    try:
        text = args.packages.read_text(encoding="utf-8")
        stanzas = list(parse_stanzas(text))
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"package-pin: FAIL: {exc}", file=sys.stderr)
        return 1

    matches = [
        stanza
        for stanza in stanzas
        if stanza.get("Package") == args.package
        and stanza.get("Architecture") in {args.arch, "all"}
        and (args.version is None or stanza.get("Version") == args.version)
    ]
    if not matches:
        print("package-pin: FAIL: no matching package in supplied pinned index", file=sys.stderr)
        return 1
    if len(matches) != 1:
        versions = sorted({stanza.get("Version", "<missing>") for stanza in matches})
        print(
            "package-pin: FAIL: multiple matches; rerun with --version: " + ", ".join(versions),
            file=sys.stderr,
        )
        return 1

    stanza = matches[0]
    required = ["Package", "Version", "Architecture", "Filename", "Size", "SHA256"]
    missing = [key for key in required if not stanza.get(key)]
    if missing:
        print(f"package-pin: FAIL: missing required metadata: {', '.join(missing)}", file=sys.stderr)
        return 1

    try:
        size = int(stanza["Size"])
    except ValueError:
        print(f"package-pin: FAIL: invalid Size: {stanza['Size']!r}", file=sys.stderr)
        return 1

    result = {
        "schema_version": 1,
        "package": stanza["Package"],
        "version": stanza["Version"],
        "architecture": stanza["Architecture"],
        "filename": stanza["Filename"],
        "size_bytes": size,
        "sha256": stanza["SHA256"],
        "sha512": stanza.get("SHA512"),
        "source_policy": "Packages metadata must originate from the exact snapshot pinned in docs/debian13/arm64-target.json",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
