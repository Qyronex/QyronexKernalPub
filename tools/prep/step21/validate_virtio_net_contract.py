#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

SUPPORTED = {"VERSION_1", "NET_F_MAC", "CSUM", "GUEST_CSUM"}
VALID_L3 = {"arp", "ipv4", "ipv6"}
VALID_L4 = {"udp", "tcp"}


def power_of_two(value: int) -> bool:
    return isinstance(value, int) and value > 0 and value & (value - 1) == 0


def evaluate(case: dict) -> str:
    q = case.get("queue_size")
    if not power_of_two(q) or q > 32768:
        return "reject"
    features = set(case.get("features", []))
    if "VERSION_1" not in features or not features <= SUPPORTED:
        return "reject"
    if case.get("direction") not in {"rx", "tx"}:
        return "reject"
    if not case.get("dma_assigned", False):
        return "reject"
    if case.get("buffer_revoked", False) or case.get("buffer_generation") != case.get("expected_generation"):
        return "reject"
    packet_len, mtu = case.get("packet_len"), case.get("mtu")
    if not isinstance(packet_len, int) or not isinstance(mtu, int) or mtu <= 0:
        return "reject"
    if packet_len < 14 or packet_len > mtu + 14:
        return "reject"
    l3, l4 = case.get("l3"), case.get("l4")
    if l3 not in VALID_L3:
        return "reject"
    if l3 == "arp":
        if l4 is not None:
            return "reject"
    elif l4 not in VALID_L4:
        return "reject"

    descriptors = case.get("descriptors", [])
    head = case.get("head")
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
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "tests/prep/step21/virtio_net_cases.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or not isinstance(data.get("cases"), list):
        raise SystemExit("invalid Step21 corpus schema")
    seen = set()
    for case in data["cases"]:
        cid = case.get("id")
        if not cid or cid in seen:
            raise SystemExit(f"duplicate/missing case id: {cid!r}")
        seen.add(cid)
        actual = evaluate(case)
        if actual != case.get("expected"):
            raise SystemExit(f"{cid}: expected {case.get('expected')} got {actual}")
    required = {"arp-tx-valid","ipv4-udp-tx-valid","ipv4-tcp-rx-valid","ipv6-udp-valid","queue-not-power-two","missing-version1","unknown-feature","descriptor-cycle","descriptor-oob","stale-buffer-generation","revoked-buffer","dma-unassigned","mtu-exceeded","invalid-l4"}
    missing = sorted(required - seen)
    if missing:
        raise SystemExit(f"missing required Step21 cases: {missing}")
    print(f"STEP21_PREP_OK cases={len(seen)}")


if __name__ == "__main__":
    main()
