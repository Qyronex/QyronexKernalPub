#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HOTPLUG_POLICY = ROOT / "tests/qemu-prep/step38/hotplug_policy.json"


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


def parse_status(path: Path) -> int | None:
    text = read_text(path).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise ValueError(f"invalid status file {path}: {text!r}") from exc


def property_keys(path: Path) -> list[str]:
    keys: set[str] = set()
    for raw in read_text(path).splitlines():
        if "=" in raw:
            key = raw.split("=", 1)[0].strip()
            if key and re.fullmatch(r"[A-Za-z0-9_]+", key):
                keys.add(key)
    return sorted(keys)


def node_stat(path: Path) -> dict[str, str] | None:
    text = read_text(path).strip()
    if not text or text == "absent":
        return None
    result: dict[str, str] = {}
    for token in text.split():
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value
    return result


def classify(directory: Path) -> dict[str, object]:
    identity = parse_kv(directory / "identity.txt")
    required = {"schema", "arch", "pid1", "source_commit", "target_id", "target_sha256", "transport_profile", "udev_test_requested"}
    missing = sorted(required - identity.keys())
    if missing:
        raise ValueError(f"missing identity fields: {missing}")
    if identity["schema"] != "2":
        raise ValueError("unsupported Step38 reference schema")
    if identity["arch"] not in {"aarch64", "arm64"}:
        raise ValueError("reference is not AArch64")
    if identity["pid1"] != "systemd":
        raise ValueError("reference PID1 is not systemd")
    if not re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"]):
        raise ValueError("source_commit must be full lowercase Git SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", identity["target_sha256"]):
        raise ValueError("target_sha256 must be lowercase SHA-256")

    policy = json.loads(HOTPLUG_POLICY.read_text(encoding="utf-8"))
    profiles = policy["profiles"]
    profile_name = identity["transport_profile"]
    if profile_name not in profiles:
        raise ValueError(f"transport profile absent from hotplug policy: {profile_name}")
    profile = profiles[profile_name]

    service = parse_kv(directory / "udev-service.stdout")
    if service.get("LoadState") != "loaded" or service.get("ActiveState") != "active":
        raise ValueError(f"systemd-udevd is not loaded+active: {service}")

    selected = parse_kv(directory / "selected.txt")
    root_properties: dict[str, str] = {}
    for candidate in sorted((directory / "devices").glob("root-*.stdout")):
        if "attribute-walk" not in candidate.name:
            root_properties = parse_kv(candidate)
            if root_properties:
                break
    net_properties = parse_kv(directory / "devices/net-properties.stdout")

    tty_properties: dict[str, dict[str, str]] = {}
    for path in sorted((directory / "devices").glob("tty*-properties.stdout")):
        name = path.name.split("-properties.stdout", 1)[0]
        tty_properties[name] = parse_kv(path)

    uevent_fields = {
        "root": property_keys(directory / "devices/root-uevent.txt"),
        "net": property_keys(directory / "devices/net-uevent.txt"),
    }
    for path in sorted((directory / "devices").glob("tty*-uevent.txt")):
        uevent_fields[path.name.removesuffix("-uevent.txt")] = property_keys(path)

    nodes: dict[str, object] = {}
    for stat_file in sorted((directory / "devices").glob("*.stat")):
        nodes[stat_file.name.removesuffix(".stat")] = node_stat(stat_file)

    udev_tests: dict[str, object] = {}
    if identity["udev_test_requested"] == "1":
        for status_file in sorted(directory.glob("udev-test-*.status")):
            name = status_file.name.removesuffix(".status")
            stdout = directory / f"{name}.stdout"
            stderr = directory / f"{name}.stderr"
            text = read_text(stdout) + read_text(stderr)
            udev_tests[name] = {
                "status": parse_status(status_file),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "observed_property_keys": sorted(
                    set(re.findall(r"(?m)^([A-Za-z0-9_]+)=", text))
                ),
            }
        if not udev_tests:
            raise ValueError("udev test was requested but no udev-test status files exist")

    raw_manifest = read_text(directory / "SHA256SUMS")
    return {
        "schema": "kernal-step38-debian13-udev-reference-v1",
        "provenance": identity,
        "udev": {
            "service": service,
            "package": read_text(directory / "udev-package.stdout").strip(),
            "boot_journal_present": bool(read_text(directory / "udev-journal-boot.stdout")),
            "export_db_present": bool(read_text(directory / "udevadm-info-export-db.stdout")),
            "tests": udev_tests,
        },
        "selected_devices": {
            "root_source": selected.get("root_source"),
            "net_iface": selected.get("net_iface"),
            "root_property_keys": sorted(root_properties.keys()),
            "net_property_keys": sorted(net_properties.keys()),
            "tty_property_keys": {name: sorted(props.keys()) for name, props in tty_properties.items()},
            "uevent_fields": uevent_fields,
            "device_nodes": nodes,
        },
        "hotplug_claim": {
            "profile": profile_name,
            "transport": profile["transport"],
            "block": profile["block_hotplug_claimed"],
            "network": profile["network_hotplug_claimed"],
            "console": profile["console_hotplug_claimed"],
            "required_lifecycle": profile["required_udev_lifecycle"],
            "requires_separate_live_hotplug_evidence": bool(profile["block_hotplug_claimed"] or profile["network_hotplug_claimed"] or profile["console_hotplug_claimed"]),
        },
        "raw_evidence_manifest_sha256": hashlib.sha256(raw_manifest.encode("utf-8")).hexdigest() if raw_manifest else None,
        "runtime_rule": "Project only canonical device facts into sysfs/uevent/device nodes. Reference visibility never creates a second hardware/IRQ/DMA authority.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = classify(args.input.expanduser().resolve())
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"step38-udev-classifier: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        out = args.out.expanduser().resolve()
        if out.exists():
            print(f"step38-udev-classifier: FAIL: refusing to overwrite {out}", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"step38-udev-classifier: PASS: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
