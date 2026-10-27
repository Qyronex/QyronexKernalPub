#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

SUPPORTED = {"VERSION_1", "BLK_F_FLUSH", "BLK_F_RO"}
OPS = {"read", "write", "flush"}


def power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def evaluate(case: dict) -> str:
    q = case["queue_size"]
    if not isinstance(q, int) or not power_of_two(q) or q > 32768:
        return "reject"
    features = set(case["features"])
    if "VERSION_1" not in features or not features <= SUPPORTED:
        return "reject"
    op = case["op"]
    if op not in OPS:
        return "reject"
    if op == "write" and "BLK_F_RO" in features:
        return "reject"
    if op == "flush" and "BLK_F_FLUSH" not in features:
        return "reject"
    if case["buffer_revoked"] or case["buffer_generation"] != case["expected_generation"]:
        return "reject"

    descriptors = case["descriptors"]
    head = case["head"]
    if not descriptors or len(descriptors) > q or not isinstance(head, int):
        return "reject"
    seen: set[int] = set()
    index: int | None = head
    for _ in range(q):
        if index is None:
            return "accept"
        if index < 0 or index >= len(descriptors) or index in seen:
            return "reject"
        seen.add(index)
        nxt = descriptors[index].get("next")
        if nxt is not None and not isinstance(nxt, int):
            return "reject"
        index = nxt
    return "reject"


def main() -> None:
    path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parents[3]
        / "tests/prep/step20/virtio_block_cases.json"
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("cases"), list):
        raise SystemExit("invalid Step20 corpus schema")
    seen = set()
    for case in data["cases"]:
        cid = case.get("id")
        if not cid or cid in seen:
            raise SystemExit(f"duplicate/missing case id: {cid!r}")
        seen.add(cid)
        actual = evaluate(case)
        if actual != case.get("expected"):
            raise SystemExit(f"{cid}: expected {case.get('expected')} got {actual}")
    required = {
        "read-ok",
        "write-ok",
        "flush-ok",
        "descriptor-cycle",
        "descriptor-oob",
        "queue-not-power-two",
        "missing-version1",
        "unknown-feature",
        "write-on-readonly",
        "flush-without-feature",
        "stale-buffer-generation",
        "revoked-buffer",
    }
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step20 cases: {missing}")
    print(f"STEP20_PREP_OK cases={len(seen)}")


if __name__ == "__main__":
    main()
