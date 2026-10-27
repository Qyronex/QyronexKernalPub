#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ALLOWED_PERMS = {"r", "w"}


def evaluate(case: dict) -> str:
    if not case.get("stream_assigned", False):
        return "reject"
    if case.get("domain_id") != case.get("frame_domain_id"):
        return "reject"
    if case.get("frame_generation") != case.get("expected_generation"):
        return "reject"
    if case.get("frame_revoked", False):
        return "reject"
    op = case.get("operation")
    if op == "reuse":
        return "accept" if case.get("invalidated_before_reuse") is True else "reject"
    if op != "map":
        return "reject"
    page_size = case.get("page_size")
    iova = case.get("iova")
    length = case.get("length")
    frame_size = case.get("frame_size")
    if not all(isinstance(v, int) and v > 0 for v in (page_size, length, frame_size)):
        return "reject"
    if not isinstance(iova, int) or iova < 0 or iova % page_size != 0 or length % page_size != 0:
        return "reject"
    if length > frame_size:
        return "reject"
    perms = set(case.get("perms", []))
    if not perms or not perms <= ALLOWED_PERMS:
        return "reject"
    return "accept"


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "tests/prep/step19/iommu_dma_cases.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("cases"), list):
        raise SystemExit("invalid Step19 corpus schema")
    seen = set()
    for case in data["cases"]:
        cid = case.get("id")
        if not cid or cid in seen:
            raise SystemExit(f"duplicate/missing case id: {cid!r}")
        seen.add(cid)
        actual = evaluate(case)
        if actual != case.get("expected"):
            raise SystemExit(f"{cid}: expected {case.get('expected')} got {actual}")
    required = {"map-rw-valid","map-ro-valid","unassigned-stream","foreign-domain","stale-generation","revoked-frame","misaligned-iova","oversized-map","execute-permission","reuse-without-invalidate","reuse-after-invalidate"}
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step19 cases: {missing}")
    print(f"STEP19_PREP_OK cases={len(seen)}")


if __name__ == "__main__":
    main()
