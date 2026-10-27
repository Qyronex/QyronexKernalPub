#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

FORBIDDEN_CRITICAL_UNITS = {
    "dbus.service",
    "systemd-journald.service",
    "systemd-udevd.service",
    "systemd-logind.service",
    "systemd-remount-fs.service",
}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def parse_kv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in read_text(path).splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def status(path: Path) -> int | None:
    text = read_text(path).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise ValueError(f"invalid status file {path}: {text!r}") from exc


def safe_unit(unit: str) -> str:
    return unit.translate(str.maketrans({"/": "_", "@": "_", ".": "_", "-": "_"}))


def package_identity(directory: Path, unit: str) -> dict[str, str] | None:
    safe = safe_unit(unit)
    text = read_text(directory / "services" / f"{safe}.package.stdout").strip()
    if not text:
        return None
    fields = text.split("\t")
    if len(fields) != 3:
        return None
    return {"package": fields[0], "version": fields[1], "architecture": fields[2]}


def service_record(directory: Path, unit: str) -> dict[str, object]:
    safe = safe_unit(unit)
    props = parse_kv(directory / "services" / f"{safe}.stdout")
    pkg = package_identity(directory, unit)
    eligible = all(
        [
            props.get("LoadState") == "loaded",
            props.get("ActiveState") == "active",
            props.get("CanStart") == "yes",
            props.get("CanStop") == "yes",
            props.get("RefuseManualStart") != "yes",
            props.get("RefuseManualStop") != "yes",
            bool(props.get("FragmentPath")),
            pkg is not None,
            unit not in FORBIDDEN_CRITICAL_UNITS,
        ]
    )
    reasons: list[str] = []
    if unit in FORBIDDEN_CRITICAL_UNITS:
        reasons.append("critical-unit-excluded")
    for key, expected in (("LoadState", "loaded"), ("ActiveState", "active"), ("CanStart", "yes"), ("CanStop", "yes")):
        if props.get(key) != expected:
            reasons.append(f"{key}={props.get(key, 'missing')}")
    if props.get("RefuseManualStart") == "yes":
        reasons.append("manual-start-refused")
    if props.get("RefuseManualStop") == "yes":
        reasons.append("manual-stop-refused")
    if not props.get("FragmentPath"):
        reasons.append("fragment-missing")
    if pkg is None:
        reasons.append("package-identity-missing")
    return {
        "unit": unit,
        "eligible": eligible,
        "reasons": reasons,
        "properties": props,
        "package": pkg,
    }


def classify(directory: Path, selected: list[str]) -> dict[str, object]:
    identity = parse_kv(directory / "identity.txt")
    required = {"schema", "arch", "pid1_comm", "pid1_exe", "source_commit", "target_id", "target_sha256", "failure_probe_requested"}
    missing = sorted(required - identity.keys())
    if missing:
        raise ValueError(f"missing identity fields: {missing}")
    if identity["schema"] != "2":
        raise ValueError("unsupported Step37 reference schema")
    if identity["arch"] not in {"aarch64", "arm64"}:
        raise ValueError("reference is not AArch64")
    if identity["pid1_comm"] != "systemd" or not identity["pid1_exe"].endswith("/systemd"):
        raise ValueError("reference PID1 identity is not systemd")
    if not re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"]):
        raise ValueError("source_commit must be a full lowercase Git SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", identity["target_sha256"]):
        raise ValueError("target_sha256 must be lowercase SHA-256")

    candidates = [line.strip() for line in read_text(directory / "service-candidates.txt").splitlines() if line.strip()]
    records = {unit: service_record(directory, unit) for unit in candidates}
    eligible = sorted(unit for unit, record in records.items() if record["eligible"])

    if selected:
        if len(selected) != 3 or len(set(selected)) != 3:
            raise ValueError("Step37 frozen service set must contain exactly three unique units")
        unknown = sorted(set(selected) - set(records))
        if unknown:
            raise ValueError(f"selected services were not reference candidates: {unknown}")
        ineligible = [unit for unit in selected if not records[unit]["eligible"]]
        if ineligible:
            raise ValueError(f"selected services are not eligible ordinary services: {ineligible}")
        selection_state = "FROZEN_THREE_SERVICES"
    else:
        selection_state = "SELECTION_REQUIRED"

    failure_requested = identity["failure_probe_requested"] == "1"
    failure = {
        "requested": failure_requested,
        "run_status": status(directory / "failure-probe-run.status") if failure_requested else None,
        "diagnostic_status": status(directory / "failure-probe-status.status") if failure_requested else None,
        "journal_status": status(directory / "failure-probe-journal.status") if failure_requested else None,
        "reset_status": status(directory / "failure-probe-reset.status") if failure_requested else None,
    }
    if failure_requested and failure["run_status"] == 0:
        raise ValueError("intentional failure probe returned success")
    if failure_requested and failure["reset_status"] != 0:
        raise ValueError("failed-service reset did not complete")

    hash_manifest = directory / "SHA256SUMS"
    hash_text = read_text(hash_manifest)
    return {
        "schema": "kernal-step37-debian13-pid1-reference-v1",
        "provenance": identity,
        "manager": {
            "is_system_running_status": status(directory / "systemctl-is-system-running.status"),
            "is_system_running": read_text(directory / "systemctl-is-system-running.stdout").strip(),
            "default_target": read_text(directory / "systemctl-get-default.stdout").strip(),
            "failed_units": read_text(directory / "systemctl-list-failed.stdout").splitlines(),
        },
        "boot_order_evidence": {
            "default_target_dependencies_present": bool(read_text(directory / "default-target-dependencies.stdout")),
            "critical_chain_present": bool(read_text(directory / "systemd-analyze-critical-chain.stdout")),
            "default_target_critical_chain_present": bool(read_text(directory / "systemd-analyze-critical-chain-default.stdout")),
        },
        "services": {
            "candidates": records,
            "eligible_ordinary_services": eligible,
            "selection_state": selection_state,
            "frozen_three": selected,
        },
        "failure_diagnostics": failure,
        "raw_evidence_manifest_sha256": hashlib.sha256(hash_text.encode("utf-8")).hexdigest() if hash_text else None,
        "runtime_rule": "Use the exact frozen service/package identities and first mandatory boot failures; never add process-name or unit-name kernel special cases.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--service", action="append", default=[])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = classify(args.input.expanduser().resolve(), args.service)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"step37-pid1-classifier: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        out = args.out.expanduser().resolve()
        if out.exists():
            print(f"step37-pid1-classifier: FAIL: refusing to overwrite {out}", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"step37-pid1-classifier: PASS: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
