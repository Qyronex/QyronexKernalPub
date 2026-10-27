#!/usr/bin/env python3
"""Classify Step-34 read-only network reference output into integration inputs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TARGET_ID = "debian-13-trixie-arm64-20260712-2537"


def read_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def parse_selected(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in read_optional(path).splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def parse_systemd_show(directory: Path, unit_key: str) -> dict[str, str]:
    path = directory / f"unit-{unit_key}.stdout"
    values: dict[str, str] = {}
    for raw in read_optional(path).splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            values[key] = value
    return values


def classify_manager(directory: Path) -> dict:
    candidates = {
        "systemd-networkd": parse_systemd_show(directory, "systemd-networkd_service"),
        "NetworkManager": parse_systemd_show(directory, "NetworkManager_service"),
        "ifupdown/networking.service": parse_systemd_show(directory, "networking_service"),
        "systemd-resolved": parse_systemd_show(directory, "systemd-resolved_service"),
    }
    active = [name for name, values in candidates.items() if values.get("ActiveState") == "active"]
    return {"active": active, "details": candidates}


def extract_default_route(directory: Path) -> str | None:
    text = read_optional(directory / "ip-route4.stdout")
    for line in text.splitlines():
        if line.startswith("default "):
            return line
    return None


def classify(directory: Path) -> dict:
    selected = parse_selected(directory / "selection.txt")
    iface = selected.get("default_iface", "")
    if not iface:
        raise ValueError("default_iface missing from collector output")

    manager = classify_manager(directory)
    resolv_target = read_optional(directory / "resolv-conf-symlink.txt") or None
    resolv_text = read_optional(directory / "resolv-conf.txt")
    nameservers = []
    for line in resolv_text.splitlines():
        match = re.match(r"\s*nameserver\s+(\S+)", line)
        if match:
            nameservers.append(match.group(1))

    route = extract_default_route(directory)
    if "systemd-networkd" in manager["active"]:
        configuration_path = "SYSTEMD_NETWORKD_OBSERVED"
    elif "NetworkManager" in manager["active"]:
        configuration_path = "NETWORKMANAGER_OBSERVED"
    elif "ifupdown/networking.service" in manager["active"]:
        configuration_path = "IFUPDOWN_OBSERVED"
    else:
        configuration_path = "MANAGER_UNRESOLVED_REVIEW_REQUIRED"

    return {
        "schema_version": 1,
        "step": 34,
        "target_id": TARGET_ID,
        "reference_network": {
            "default_iface": iface,
            "default_route": route,
            "sysfs_path": read_optional(directory / "default-iface-sysfs-path.txt") or None,
            "mac": read_optional(directory / "default-iface-address.txt") or None,
            "mtu": read_optional(directory / "default-iface-mtu.txt") or None,
            "operstate": read_optional(directory / "default-iface-operstate.txt") or None,
        },
        "manager_classification": configuration_path,
        "manager_state": manager,
        "resolver": {
            "resolv_conf_symlink": resolv_target,
            "nameservers": nameservers,
        },
        "first_qemu_integration_rule": "Implement only the static/DHCP/interface-control semantics proven necessary by the selected pinned Debian reference profile; do not add a second network-manager-specific kernel path.",
        "qemu_user_network_target": {
            "guest_visible_host": "10.0.2.2",
            "guest_visible_dns": "10.0.2.3",
            "guest_to_host_tcp_port": 18081,
            "guest_to_host_udp_port": 18082,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = classify(args.input.expanduser().resolve())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"step34-network-classifier: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        out = args.out.expanduser().resolve()
        if out.exists():
            print(f"step34-network-classifier: FAIL: refusing to overwrite {out}", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"step34-network-classifier: PASS: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
