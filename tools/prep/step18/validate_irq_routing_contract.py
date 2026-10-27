#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def evaluate(case: dict) -> str:
    mode = case.get("mode")
    vectors = case.get("vectors")
    if mode not in {"msi", "msix"} or not isinstance(vectors, int) or not (1 <= vectors <= 2048):
        return "reject"
    if case.get("requested_endpoint") != case.get("assigned_endpoint"):
        return "reject"
    if case.get("target_cpu") not in case.get("allowed_cpus", []):
        return "reject"
    if not case.get("platform_has_its", False):
        return "reject"
    threshold = case.get("storm_threshold")
    count = case.get("storm_count")
    if not isinstance(threshold, int) or threshold <= 0 or not isinstance(count, int) or count < 0:
        return "reject"
    if count > threshold and not case.get("masked", False):
        return "reject"
    if mode == "msix":
        table_bytes = case.get("table_bytes")
        table_bar_bytes = case.get("table_bar_bytes")
        pba_bytes = case.get("pba_bytes")
        pba_bar_bytes = case.get("pba_bar_bytes")
        required_table = vectors * 16
        required_pba = ((vectors + 63) // 64) * 8
        if not all(isinstance(v, int) and v >= 0 for v in (table_bytes, table_bar_bytes, pba_bytes, pba_bar_bytes)):
            return "reject"
        if table_bytes < required_table or table_bytes > table_bar_bytes:
            return "reject"
        if pba_bytes < required_pba or pba_bytes > pba_bar_bytes:
            return "reject"
    return "accept"


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "tests/prep/step18/irq_routing_cases.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("cases"), list):
        raise SystemExit("invalid Step18 corpus schema")
    seen = set()
    for case in data["cases"]:
        cid = case.get("id")
        if not cid or cid in seen:
            raise SystemExit(f"duplicate/missing case id: {cid!r}")
        seen.add(cid)
        actual = evaluate(case)
        if actual != case.get("expected"):
            raise SystemExit(f"{cid}: expected {case.get('expected')} got {actual}")
    required = {"msi-valid","msix-valid","zero-vectors","too-many-vectors","table-oob","pba-oob","foreign-endpoint","foreign-affinity","missing-its","storm-unmasked"}
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step18 cases: {missing}")
    print(f"STEP18_PREP_OK cases={len(seen)}")


if __name__ == "__main__":
    main()
