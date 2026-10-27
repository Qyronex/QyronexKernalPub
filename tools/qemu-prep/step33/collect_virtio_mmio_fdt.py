#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "docs/debian13/arm64-target.json"


def read_u32(path: Path, default: int | None = None) -> int:
    if not path.is_file():
        if default is None:
            raise ValueError(f"missing required property: {path}")
        return default
    raw = path.read_bytes()
    if len(raw) != 4:
        raise ValueError(f"property {path} must contain one big-endian u32")
    return struct.unpack(">I", raw)[0]


def read_cells(path: Path) -> list[int]:
    raw = path.read_bytes()
    if len(raw) == 0 or len(raw) % 4 != 0:
        raise ValueError(f"property {path} has invalid cell length {len(raw)}")
    return list(struct.unpack(f">{len(raw) // 4}I", raw))


def cells_to_int(cells: list[int]) -> int:
    value = 0
    for cell in cells:
        value = (value << 32) | cell
    return value


def read_strings(path: Path) -> list[str]:
    raw = path.read_bytes()
    return [part.decode("ascii") for part in raw.split(b"\0") if part]


def decode_reg(node: Path) -> list[dict[str, int]]:
    parent = node.parent
    address_cells = read_u32(parent / "#address-cells", default=2)
    size_cells = read_u32(parent / "#size-cells", default=1)
    if address_cells < 1 or address_cells > 4 or size_cells < 1 or size_cells > 4:
        raise ValueError(
            f"unsupported address/size cell geometry at {parent}: {address_cells}/{size_cells}"
        )
    cells = read_cells(node / "reg")
    stride = address_cells + size_cells
    if len(cells) % stride != 0:
        raise ValueError(f"truncated reg property at {node}")
    ranges: list[dict[str, int]] = []
    for offset in range(0, len(cells), stride):
        base = cells_to_int(cells[offset : offset + address_cells])
        size = cells_to_int(cells[offset + address_cells : offset + stride])
        if size == 0:
            raise ValueError(f"zero-length MMIO range at {node}")
        if base + size > 1 << 64:
            raise ValueError(f"overflowing MMIO range at {node}")
        ranges.append({"base": base, "size": size})
    return ranges


def scan_fdt(device_tree_root: Path) -> list[dict[str, object]]:
    if not device_tree_root.is_dir():
        raise ValueError(f"device-tree root missing: {device_tree_root}")
    nodes: list[dict[str, object]] = []
    for compatible_path in sorted(device_tree_root.rglob("compatible")):
        compatible = read_strings(compatible_path)
        if "virtio,mmio" not in compatible:
            continue
        node = compatible_path.parent
        reg_path = node / "reg"
        irq_path = node / "interrupts"
        if not reg_path.is_file() or not irq_path.is_file():
            raise ValueError(f"VirtIO-MMIO node lacks reg/interrupts: {node}")
        relative = "/" + str(node.relative_to(device_tree_root))
        status = "okay"
        if (node / "status").is_file():
            values = read_strings(node / "status")
            status = values[0] if values else ""
        nodes.append(
            {
                "path": relative,
                "compatible": compatible,
                "status": status,
                "reg": decode_reg(node),
                "interrupt_cells": read_cells(irq_path),
            }
        )
    if not nodes:
        raise ValueError("no virtio,mmio nodes found in reference FDT")
    return nodes


def parse_hex_int(text: str) -> int:
    return int(text.strip(), 0)


def scan_virtio_sysfs(sysfs_root: Path) -> list[dict[str, object]]:
    if not sysfs_root.is_dir():
        raise ValueError(f"VirtIO sysfs root missing: {sysfs_root}")
    devices: list[dict[str, object]] = []
    for entry in sorted(sysfs_root.glob("virtio*")):
        device_file = entry / "device"
        if not device_file.is_file():
            continue
        device_id = parse_hex_int(device_file.read_text(encoding="ascii"))
        vendor_id = None
        if (entry / "vendor").is_file():
            vendor_id = parse_hex_int((entry / "vendor").read_text(encoding="ascii"))
        driver = None
        if (entry / "driver").exists():
            driver = Path(os.path.realpath(entry / "driver")).name
        parent = Path(os.path.realpath(entry / "device" / "..")) if (entry / "device" / "..").exists() else None
        devices.append(
            {
                "name": entry.name,
                "device_id": device_id,
                "vendor_id": vendor_id,
                "driver": driver,
                "sysfs_path": str(entry.resolve()),
                "parent_name": parent.name if parent else None,
            }
        )
    if not devices:
        raise ValueError("no VirtIO devices found in sysfs")
    return devices


def collect(device_tree_root: Path, sysfs_root: Path) -> dict[str, object]:
    nodes = scan_fdt(device_tree_root)
    devices = scan_virtio_sysfs(sysfs_root)
    block_devices = [device for device in devices if device["device_id"] == 2]
    return {
        "schema": "kernal-step33-virtio-mmio-reference-v1",
        "fdt": {
            "source": str(device_tree_root),
            "virtio_mmio_nodes": nodes,
            "hardcoded_address_required": False,
        },
        "virtio": {
            "sysfs_source": str(sysfs_root),
            "devices": devices,
            "block_device_count": len(block_devices),
        },
    }


def require_reference_environment() -> dict[str, str]:
    machine = platform.machine()
    if machine not in {"aarch64", "arm64"}:
        raise ValueError(f"reference collector requires AArch64, found {machine}")
    os_release = Path("/etc/os-release")
    if not os_release.is_file():
        raise ValueError("/etc/os-release missing")
    values: dict[str, str] = {}
    for raw in os_release.read_text(encoding="utf-8").splitlines():
        if "=" not in raw or raw.startswith("#"):
            continue
        key, value = raw.split("=", 1)
        values[key] = value.strip().strip('"').strip("'")
    if values.get("ID") != "debian" or values.get("VERSION_ID", "").split(".", 1)[0] != "13":
        raise ValueError("reference collector requires Debian 13")
    if values.get("VERSION_CODENAME") not in {None, "trixie"}:
        raise ValueError("reference collector requires Debian 13/Trixie")
    return {
        "architecture": machine,
        "os_id": values.get("ID", ""),
        "os_version_id": values.get("VERSION_ID", ""),
        "kernel_release": platform.release(),
    }


def exact_source_commit() -> str:
    commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"], text=True
    ).strip()
    if len(commit) != 40 or any(ch not in "0123456789abcdef" for ch in commit):
        raise ValueError(f"invalid source commit identity: {commit!r}")
    return commit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-tree-root", type=Path, default=Path("/proc/device-tree"))
    parser.add_argument("--virtio-sysfs-root", type=Path, default=Path("/sys/bus/virtio/devices"))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        env = require_reference_environment()
        result = collect(args.device_tree_root, args.virtio_sysfs_root)
        target_raw = TARGET.read_bytes()
        target = json.loads(target_raw)
        result["provenance"] = {
            **env,
            "source_commit": exact_source_commit(),
            "target_id": target["target_id"],
            "target_sha256": hashlib.sha256(target_raw).hexdigest(),
        }
        if result["virtio"]["block_device_count"] < 1:
            raise ValueError("reference profile exposes no VirtIO block device (device id 2)")
        if args.out.exists():
            raise ValueError(f"refusing to overwrite existing output: {args.out}")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, KeyError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        print(f"step33-fdt-reference: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "STEP33_VIRTIO_MMIO_FDT_REFERENCE_OK "
        f"source_commit={result['provenance']['source_commit']} "
        f"nodes={len(result['fdt']['virtio_mmio_nodes'])} "
        f"block_devices={result['virtio']['block_device_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
