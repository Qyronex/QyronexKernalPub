#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

NAMESPACE_PROPERTIES = {
    "PrivateTmp": "mnt",
    "PrivateDevices": "mnt",
    "PrivateMounts": "mnt",
    "ProtectSystem": "mnt",
    "ProtectHome": "mnt",
    "PrivateNetwork": "net",
    "PrivateUsers": "user",
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


def parse_proc_status(path: Path) -> dict[str, str]:
    wanted = {
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    }
    values: dict[str, str] = {}
    for raw in read_text(path).splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        if key in wanted:
            values[key] = value.strip()
    return values


def parse_security_probe(text: str) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    pattern = re.compile(r"^INFO security\.([A-Za-z0-9_]+) state=([A-Za-z0-9_-]+)(?: (.*))?$")
    for raw in text.splitlines():
        match = pattern.match(raw.strip())
        if not match:
            continue
        name, state, tail = match.groups()
        fields: dict[str, object] = {"state": state}
        if tail:
            for token in tail.split():
                if "=" not in token:
                    continue
                key, value = token.split("=", 1)
                if key in {"errno", "value"} and value.lstrip("-").isdigit():
                    fields[key] = int(value)
                else:
                    fields[key] = value
        result[name] = fields
    return result


def parse_unit_properties(directory: Path) -> dict[str, dict[str, str]]:
    units: dict[str, dict[str, str]] = {}
    for unit in read_text(directory / "selected-units.txt").splitlines():
        unit = unit.strip()
        if not unit:
            continue
        safe = unit.translate(str.maketrans({".": "_", "@": "_", "/": "_", "-": "_"}))
        units[unit] = parse_kv(directory / f"unit-{safe}.stdout")
    return units


def infer_namespaces(units: dict[str, dict[str, str]]) -> dict[str, list[str]]:
    per_unit: dict[str, list[str]] = {}
    for unit, props in units.items():
        required: set[str] = set()
        for prop, namespace in NAMESPACE_PROPERTIES.items():
            value = props.get(prop, "")
            if prop in {"ProtectSystem", "ProtectHome"}:
                enabled = value not in {"", "no", "false", "0"}
            else:
                enabled = value.lower() in {"yes", "true", "1"}
            if enabled:
                required.add(namespace)
        restrict = props.get("RestrictNamespaces", "").strip()
        if restrict:
            # Preserve systemd's exact textual policy as evidence. It can be a
            # boolean or a space-separated namespace allow/deny expression.
            required.add("policy:RestrictNamespaces")
        per_unit[unit] = sorted(required)
    return per_unit


def read_root_controllers(directory: Path) -> list[str]:
    text = read_text(directory / "_sys_fs_cgroup_cgroup.controllers.txt")
    return sorted(set(text.split()))


def enforcement_summary(directory: Path, requested: bool) -> dict[str, object]:
    if not requested:
        return {"requested": False, "state": "SKIPPED"}
    statuses = {
        name: parse_kv_status(directory / f"enforcement-{name}.status")
        for name in ("pids", "cpu", "memory")
    }
    pids_text = read_text(directory / "enforcement-pids.stdout")
    cpu_text = read_text(directory / "enforcement-cpu.stdout")
    memory_text = read_text(directory / "enforcement-memory.stdout")
    return {
        "requested": True,
        "statuses": statuses,
        "pids_observed": statuses["pids"] == 0 and "PASS pids.enforcement" in pids_text,
        "cpu_throttling_observed": statuses["cpu"] == 0 and "PASS cpu.throttling" in cpu_text,
        "memory_process_survived": "FAIL memory.enforcement-process-survived" in memory_text,
        "memory_run_nonzero": statuses["memory"] is not None and statuses["memory"] != 0,
    }


def parse_kv_status(path: Path) -> int | None:
    text = read_text(path).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise ValueError(f"invalid status file {path}: {text!r}") from exc


def classify(directory: Path) -> dict[str, object]:
    identity = parse_kv(directory / "identity.txt")
    required = {"schema", "arch", "pid1", "kernel", "source_commit", "target_id", "target_sha256", "enforcement_requested"}
    missing = sorted(required - identity.keys())
    if missing:
        raise ValueError(f"missing identity fields: {missing}")
    if identity["schema"] != "2":
        raise ValueError(f"unsupported Step36 reference schema: {identity['schema']!r}")
    if identity["arch"] not in {"aarch64", "arm64"}:
        raise ValueError(f"reference is not AArch64: {identity['arch']!r}")
    if identity["pid1"] != "systemd":
        raise ValueError("reference PID1 is not systemd")
    if not re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"]):
        raise ValueError("source_commit must be a full lowercase Git SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", identity["target_sha256"]):
        raise ValueError("target_sha256 must be lowercase SHA-256")

    security_status = parse_kv_status(directory / "security-api-probe.status")
    if security_status != 0:
        raise ValueError(f"security API probe did not pass: status={security_status}")
    security_text = read_text(directory / "security-api-probe.stdout")
    if "PASS step36.security-api-probe.complete" not in security_text:
        raise ValueError("security API probe completion marker missing")

    units = parse_unit_properties(directory)
    namespaces = infer_namespaces(units)
    proc1 = parse_proc_status(directory / "proc-1-status.txt")
    controllers = read_root_controllers(directory)
    enforcement_requested = identity["enforcement_requested"] == "1"
    enforcement = enforcement_summary(directory, enforcement_requested)

    security = parse_security_probe(security_text)
    required_security_probes = {
        "prctl_get_securebits",
        "prctl_get_no_new_privs",
        "prctl_get_seccomp",
        "prctl_capbset_read_sys_admin",
        "seccomp_get_action_avail",
        "keyctl_get_process_keyring",
        "audit_netlink_socket",
        "bpf_prog_get_next_id",
    }
    missing_security = sorted(required_security_probes - security.keys())
    if missing_security:
        raise ValueError(f"missing security probe observations: {missing_security}")

    return {
        "schema": "kernal-step36-debian13-systemd-feature-reference-v1",
        "provenance": identity,
        "cgroup_v2": {
            "root_controllers": controllers,
            "pid1_membership": read_text(directory / "proc-1-cgroup.txt").strip(),
            "selected_unit_properties": units,
            "enforcement": enforcement,
        },
        "namespace_requirements": {
            "inferred_from_selected_unit_properties": namespaces,
            "rule": "Re-run with the exact Step37 service set before PREP_READY; inferred namespaces are requirements input, not a second namespace authority model.",
        },
        "linux_security_view": {
            "pid1_status": proc1,
            "probe_results": security,
            "rule": "Linux capabilities/securebits/security API visibility never grants Kernal object capabilities; optional calls retain explicit fallback/error behavior until target-proven mandatory.",
        },
        "runtime_rule": "Implement only target-observed cgroup/namespace/security contracts through canonical Process/scheduler/VM/VFS/network/credential owners.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = classify(args.input.expanduser().resolve())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"step36-feature-classifier: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        out = args.out.expanduser().resolve()
        if out.exists():
            print(f"step36-feature-classifier: FAIL: refusing to overwrite {out}", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"step36-feature-classifier: PASS: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
