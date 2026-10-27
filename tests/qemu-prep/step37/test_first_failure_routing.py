#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/qemu-prep/step37/classify_first_failure.py"
ROUTING_PATH = ROOT / "tests/qemu-prep/step37/first_failure_routing.json"
SPEC = importlib.util.spec_from_file_location("step37_failure", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ROUTING = json.loads(ROUTING_PATH.read_text(encoding="utf-8"))


def event(failure_class: str, *, mandatory: bool = True) -> dict[str, object]:
    return {
        "schema": "kernal-step37-first-failure-v1",
        "failure_class": failure_class,
        "mandatory": mandatory,
        "operation": "example",
        "detail": "deterministic first failure",
        "evidence": {"artifact": "serial.log", "sha256": "a" * 64},
    }


class Step37FirstFailureRoutingTest(unittest.TestCase):
    def test_routes_known_failure_to_smallest_existing_owner(self) -> None:
        result = MODULE.classify(event("eventfd"), ROUTING)
        self.assertEqual(result["state"], "ROUTED_TO_EXISTING_OWNER")
        self.assertEqual(result["owner_step"], 35)
        self.assertIn("Do not add systemd/unit special cases", result["action"])

    def test_future_step_requirement_is_dependency_conflict(self) -> None:
        result = MODULE.classify(event("udev"), ROUTING)
        self.assertEqual(result["state"], "ROADMAP_DEPENDENCY_CONFLICT")
        self.assertEqual(result["future_owner_step"], 38)

    def test_unknown_failure_stops_instead_of_fake_success(self) -> None:
        result = MODULE.classify(event("mystery_kernel_contract"), ROUTING)
        self.assertEqual(result["state"], "UNCLASSIFIED_STOP")
        self.assertIn("never become fake-success", result["action"])

    def test_non_mandatory_failure_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "mandatory failures"):
            MODULE.classify(event("network", mandatory=False), ROUTING)

    def test_every_pre_step37_route_points_backward(self) -> None:
        for route in ROUTING["routes"].values():
            self.assertLessEqual(route["owner_step"], 36)


if __name__ == "__main__":
    unittest.main()
