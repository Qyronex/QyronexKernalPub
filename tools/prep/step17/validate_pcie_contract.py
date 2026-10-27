#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

MAX_U64 = (1 << 64) - 1


def power_of_two(value: int) -> bool:
    return isinstance(value, int) and value > 0 and value & (value - 1) == 0


def valid_cap_offset(value: int) -> bool:
    return isinstance(value, int) and (value == 0 or 0x40 <= value <= 0xFC and value % 4 == 0)


def evaluate(case: dict) -> str:
    start, end, bus = case["bus_start"], case["bus_end"], case["bus"]
    device, function = case["device"], case["function"]
    if not all(isinstance(v, int) for v in (start, end, bus, device, function)):
        return "reject"
    if start < 0 or end > 255 or start > end or not (start <= bus <= end):
        return "reject"
    if not (0 <= device <= 31 and 0 <= function <= 7):
        return "reject"
    if case.get("owner") != "kernel":
        return "reject"

    cap_ptr = case.get("cap_ptr", 0)
    if not valid_cap_offset(cap_ptr):
        return "reject"
    caps = case.get("caps", {})
    seen: set[int] = set()
    cursor = cap_ptr
    for _ in range(48):
        if cursor == 0:
            break
        if cursor in seen or not valid_cap_offset(cursor):
            return "reject"
        seen.add(cursor)
        cap = caps.get(str(cursor))
        if not isinstance(cap, dict) or not isinstance(cap.get("id"), int):
            return "reject"
        nxt = cap.get("next", 0)
        if not valid_cap_offset(nxt):
            return "reject"
        cursor = nxt
    else:
        return "reject"

    for bar in case.get("bars", []):
        base, size = bar.get("base"), bar.get("size")
        if not isinstance(base, int) or not power_of_two(size) or size < 16:
            return "reject"
        if base < 0 or base > MAX_U64 or base % size != 0:
            return "reject"
        if base + size - 1 > MAX_U64:
            return "reject"
    return "accept"


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "tests/prep/step17/pcie_discovery_cases.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("cases"), list):
        raise SystemExit("invalid Step17 corpus schema")
    seen = set()
    for case in data["cases"]:
        cid = case.get("id")
        if not cid or cid in seen:
            raise SystemExit(f"duplicate/missing case id: {cid!r}")
        seen.add(cid)
        actual = evaluate(case)
        if actual != case.get("expected"):
            raise SystemExit(f"{cid}: expected {case.get('expected')} got {actual}")
    required = {"valid-single-function","valid-multifunction","bus-out-of-range","device-out-of-range","capability-loop","capability-misaligned","bar-size-not-power-two","bar-misaligned","bar-overflow","predelegated-authority"}
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step17 cases: {missing}")
    print(f"STEP17_PREP_OK cases={len(seen)}")


if __name__ == "__main__":
    main()
