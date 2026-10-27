#!/usr/bin/env python3
"""Statically validate the staged expanded Debian reference case manifest.

Unlike the canonical collector's runtime validation, this checker does not
require Debian executables to exist on the host. It validates only repository
metadata relationships and therefore can run on a development Mac/CI host.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGET = ROOT / "docs/debian13/arm64-target.json"
DEFAULT_MATRIX = ROOT / "docs/debian13/compatibility-matrix.json"
DEFAULT_CASES = ROOT / "tests/qemu-prep/reference-cases-expanded.json"
CASE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


class CaseValidationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CaseValidationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CaseValidationError(f"cannot read JSON {path}: {exc}") from exc
    require(isinstance(value, dict), f"top-level JSON value must be an object: {path}")
    return value


def component_programs(matrix: dict[str, Any], target_id: str) -> dict[str, str]:
    require(matrix.get("schema_version") == 1, "compatibility matrix schema_version must be 1")
    require(matrix.get("target_id") == target_id, "compatibility matrix target_id mismatch")
    entries = matrix.get("components")
    require(isinstance(entries, list) and entries, "compatibility matrix components must be non-empty")
    result: dict[str, str] = {}
    for entry in entries:
        require(isinstance(entry, dict), "compatibility matrix component must be an object")
        component_id = entry.get("id")
        program = entry.get("program")
        require(isinstance(component_id, str) and component_id and component_id not in result, "component ids must be unique non-empty strings")
        require(isinstance(program, str) and program.startswith("/"), f"{component_id}: program must be an absolute path")
        result[component_id] = program
    return result


def validate_cases(document: dict[str, Any], target_id: str, programs: dict[str, str]) -> None:
    require(document.get("schema_version") == 1, "expanded cases schema_version must be 1")
    require(document.get("target_id") == target_id, "expanded cases target_id mismatch")
    cases = document.get("cases")
    require(isinstance(cases, list) and cases, "expanded cases must be a non-empty array")

    seen: set[str] = set()
    covered: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), "expanded case entry must be an object")
        case_id = case.get("id")
        component = case.get("component")
        argv = case.get("argv")
        require(isinstance(case_id, str) and CASE_ID.fullmatch(case_id) is not None, "expanded case id must use only A-Za-z0-9._-")
        require(case_id not in seen, f"duplicate expanded case id: {case_id}")
        seen.add(case_id)
        require(isinstance(component, str) and component in programs, f"{case_id}: unknown compatibility-matrix component {component!r}")
        covered.add(component)
        require(isinstance(argv, list) and argv and all(isinstance(arg, str) and "\x00" not in arg for arg in argv), f"{case_id}: argv must be a non-empty string array without NUL")
        require(argv[0] == programs[component], f"{case_id}: argv[0] must match compatibility-matrix program {programs[component]}")

    missing = sorted(set(programs) - covered)
    require(not missing, "expanded cases must retain coverage for every compatibility-matrix component: " + ",".join(missing))

    excluded = document.get("excluded_from_this_manifest")
    require(isinstance(excluded, list) and excluded and all(isinstance(item, str) and item for item in excluded), "expanded cases must document intentionally excluded scenario classes")


def validate(target_path: Path, matrix_path: Path, cases_path: Path) -> None:
    target = load_json(target_path)
    target_id = target.get("target_id")
    require(isinstance(target_id, str) and target_id, "target_id must be present")
    programs = component_programs(load_json(matrix_path), target_id)
    validate_cases(load_json(cases_path), target_id, programs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    args = parser.parse_args()
    try:
        validate(args.target, args.matrix, args.cases)
    except CaseValidationError as exc:
        print(f"qemu-prep-expanded-cases: FAIL: {exc}", file=sys.stderr)
        return 1
    print("qemu-prep-expanded-cases: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
