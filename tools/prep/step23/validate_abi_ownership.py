#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

VALID_STEPS = set(range(23, 36))
VALID_ERRNOS = {"ENOEXEC", "EINVAL", "EAFNOSUPPORT", "ENOSYS", "ENOTTY"}


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "tests/prep/step23/abi_ownership_matrix.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("surfaces"), list):
        raise SystemExit("invalid Step23 matrix schema")
    required = set(data.get("required_surface_ids", []))
    seen: set[str] = set()
    owners: dict[str, str] = {}
    for item in data["surfaces"]:
        sid = item.get("id")
        if not sid or sid in seen:
            raise SystemExit(f"duplicate/missing surface id: {sid!r}")
        seen.add(sid)
        step = item.get("canonical_step")
        owner = item.get("canonical_owner")
        if step not in VALID_STEPS or not isinstance(owner, str) or not owner.strip():
            raise SystemExit(f"{sid}: invalid canonical owner/step")
        if item.get("duplicate_allowed") is not False:
            raise SystemExit(f"{sid}: duplicate authority must remain forbidden")
        errno = item.get("unsupported_errno")
        if errno not in VALID_ERRNOS:
            raise SystemExit(f"{sid}: unsupported behavior must name a Linux-compatible errno")
        owners[sid] = owner
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step23 surfaces: {missing}")
    if not required:
        raise SystemExit("Step23 required_surface_ids must be non-empty")
    print(f"STEP23_PREP_OK surfaces={len(seen)}")


if __name__ == "__main__":
    main()
