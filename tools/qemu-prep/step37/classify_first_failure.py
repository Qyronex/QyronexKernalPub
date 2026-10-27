#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROUTING = ROOT / "tests/qemu-prep/step37/first_failure_routing.json"


def classify(event: dict[str, object], routing: dict[str, object]) -> dict[str, object]:
    if event.get("schema") != "kernal-step37-first-failure-v1":
        raise ValueError("unexpected first-failure event schema")
    failure_class = event.get("failure_class")
    if not isinstance(failure_class, str) or not failure_class:
        raise ValueError("failure_class must be a non-empty string")
    mandatory = event.get("mandatory")
    if mandatory is not True:
        raise ValueError("only deterministic mandatory failures belong in the Step37 first-failure path")
    evidence = event.get("evidence")
    if not isinstance(evidence, dict) or not evidence.get("artifact") or not evidence.get("sha256"):
        raise ValueError("first-failure event requires artifact + sha256 evidence")

    routes = routing.get("routes", {})
    future = routing.get("future_step_conflicts", {})
    if failure_class in routes:
        route = routes[failure_class]
        return {
            "schema": "kernal-step37-first-failure-route-v1",
            "state": "ROUTED_TO_EXISTING_OWNER",
            "failure_class": failure_class,
            "owner_step": route["owner_step"],
            "canonical_area": route["area"],
            "operation": event.get("operation"),
            "detail": event.get("detail"),
            "evidence": evidence,
            "action": "Reproduce the reference behavior in the named canonical owner only, update compatibility evidence, then rerun the same Step37 boot. Do not add systemd/unit special cases.",
        }
    if failure_class in future:
        return {
            "schema": "kernal-step37-first-failure-route-v1",
            "state": "ROADMAP_DEPENDENCY_CONFLICT",
            "failure_class": failure_class,
            "future_owner_step": future[failure_class],
            "operation": event.get("operation"),
            "detail": event.get("detail"),
            "evidence": evidence,
            "action": "Stop Step37 promotion and resolve the roadmap dependency explicitly. Do not pull a future-step implementation forward silently.",
        }
    return {
        "schema": "kernal-step37-first-failure-route-v1",
        "state": "UNCLASSIFIED_STOP",
        "failure_class": failure_class,
        "operation": event.get("operation"),
        "detail": event.get("detail"),
        "evidence": evidence,
        "action": "Stop and classify the missing contract before source work. Unknown failures must never become fake-success or catch-all systemd compatibility paths.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        event = json.loads(args.event.read_text(encoding="utf-8"))
        routing = json.loads(ROUTING.read_text(encoding="utf-8"))
        result = classify(event, routing)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, KeyError) as exc:
        print(f"step37-first-failure: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        if args.out.exists():
            print(f"step37-first-failure: FAIL: refusing to overwrite {args.out}", file=sys.stderr)
            return 1
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"step37-first-failure: PASS: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
