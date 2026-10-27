#!/usr/bin/env python3
"""Generate a Deb822 apt source file from the pinned Debian ARM64 target manifest.

This helper does not run apt. It only renders exact snapshot sources from
`docs/debian13/arm64-target.json`, failing closed if an unpinned/floating URL is
encountered.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TARGET = ROOT / "docs/debian13/arm64-target.json"
DEFAULT_KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")


class SourceError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SourceError(message)


def load_target(path: Path) -> dict:
    try:
        target = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceError(f"cannot read target manifest: {exc}") from exc
    require(isinstance(target, dict), "target manifest must be an object")
    require(target.get("schema_version") == 1, "target schema_version must be 1")
    require(target.get("target_id") == "debian-13-trixie-arm64-20260712-2537", "unexpected target_id")
    require(target.get("distribution") == "Debian", "target distribution must be Debian")
    require(target.get("release") == "13", "target release must be Debian 13")
    require(target.get("architecture") == "arm64", "target architecture must be arm64")
    return target


def render_sources(target: dict, keyring: Path) -> str:
    repositories = target.get("repositories")
    require(isinstance(repositories, list) and repositories, "target repositories must be a non-empty array")
    blocks: list[str] = []
    seen_names: set[str] = set()
    for repo in repositories:
        require(isinstance(repo, dict), "repository entries must be objects")
        name = repo.get("name")
        url = repo.get("base_url")
        snapshot = repo.get("snapshot")
        suite = repo.get("suite")
        components = repo.get("components")
        require(isinstance(name, str) and name and name not in seen_names, "repository names must be unique and non-empty")
        seen_names.add(name)
        require(isinstance(url, str) and url.startswith("https://snapshot.debian.org/archive/"), f"{name}: URL must use snapshot.debian.org")
        require(isinstance(snapshot, str) and snapshot and snapshot in url, f"{name}: snapshot timestamp must appear in URL")
        require("/latest/" not in url, f"{name}: floating latest URL is forbidden")
        require(isinstance(suite, str) and suite, f"{name}: suite must be non-empty")
        require(isinstance(components, list) and components and all(isinstance(item, str) and item for item in components), f"{name}: components must be non-empty strings")
        blocks.append(
            "\n".join(
                [
                    "Types: deb",
                    f"URIs: {url}",
                    f"Suites: {suite}",
                    "Components: " + " ".join(components),
                    f"Signed-By: {keyring}",
                    "Check-Valid-Until: no",
                ]
            )
        )
    return "\n\n".join(blocks) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--keyring", type=Path, default=DEFAULT_KEYRING)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    out = args.out.expanduser().resolve()
    if out.exists():
        print(f"snapshot-sources: FAIL: refusing to overwrite existing output: {out}", file=sys.stderr)
        return 1
    try:
        target = load_target(args.target.expanduser().resolve())
        rendered = render_sources(target, args.keyring)
    except SourceError as exc:
        print(f"snapshot-sources: FAIL: {exc}", file=sys.stderr)
        return 1

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    print(json.dumps({"status":"PASS","target_id":target["target_id"],"output":str(out),"repositories":len(target["repositories"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
