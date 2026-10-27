#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
"""Build the bounded Step-29 initramfs from the accepted Step-28 BusyBox pin."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

MAX_INITRAMFS_BYTES = 16 * 1024 * 1024
DEFAULT_PROOF_MANIFEST = Path("tests/step29/path-fd-proof.json")
DEFAULT_OUTPUT = Path("target/step29/busybox-initramfs.cpio")
STEP28_BUILDER = Path("tools/step28/build-busybox-initramfs.py")
PROOF_FIELDS = {
    "schema_version",
    "target_id",
    "busybox_manifest",
    "busybox_path",
    "regression_argv0",
    "directory_argv0",
    "fixture_path",
    "fixture_target_path",
    "fixture_symlink_target",
    "directory_symlink_path",
    "directory_symlink_target",
    "fixture_format",
    "fixture_size_bytes",
    "fixture_sha256",
    "qemu_guest_address",
    "required_regression_semantics",
    "required_directory_semantics",
}
FIXED_PROOF_VALUES = {
    "schema_version": 2,
    "target_id": "debian-13-trixie-arm64-20260712-2537",
    "busybox_manifest": "tests/step28/busybox-static-arm64.json",
    "busybox_path": "bin/busybox",
    "regression_argv0": "date",
    "directory_argv0": "ls",
    "fixture_path": "etc/localtime",
    "fixture_target_path": "usr/share/zoneinfo/UTC",
    "fixture_symlink_target": "../usr/share/zoneinfo/UTC",
    "directory_symlink_path": "proof-link",
    "directory_symlink_target": "etc",
    "fixture_format": "TZif-v1-UTC",
    "fixture_size_bytes": 54,
    "fixture_sha256": "fa6b1c0d5279a53bc0a9b565bc322c541c1bbf223d90db518ea634512342b3ab",
    "qemu_guest_address": "0x48000000",
}
REQUIRED_REGRESSION_SEMANTICS = [
    "openat-readonly",
    "symlink-follow",
    "positive-read",
    "fstat-or-newfstatat",
    "close",
]
REQUIRED_DIRECTORY_SEMANTICS = [
    "open-directory",
    "getdents64-positive",
    "symlink-dirent",
    "close",
]


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_step28_builder(root: Path):
    path = root / STEP28_BUILDER
    if not path.is_file():
        fail(f"accepted Step-28 builder is missing: {path}")
    spec = importlib.util.spec_from_file_location("kernal_step28_builder", path)
    if spec is None or spec.loader is None:
        fail(f"cannot load accepted Step-28 builder: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_proof_manifest(path: Path) -> dict[str, object]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        fail("Step-29 proof manifest root must be a JSON object")
    missing = sorted(PROOF_FIELDS.difference(manifest))
    unexpected = sorted(set(manifest).difference(PROOF_FIELDS))
    if missing:
        fail(f"Step-29 proof manifest is missing fields: {', '.join(missing)}")
    if unexpected:
        fail(f"Step-29 proof manifest has unexpected fields: {', '.join(unexpected)}")
    for field, expected in FIXED_PROOF_VALUES.items():
        if manifest[field] != expected:
            fail(
                f"Step-29 proof manifest {field} must be {expected!r}, "
                f"got {manifest[field]!r}"
            )
    if manifest["required_regression_semantics"] != REQUIRED_REGRESSION_SEMANTICS:
        fail("Step-29 regression semantics do not match the proof contract")
    if manifest["required_directory_semantics"] != REQUIRED_DIRECTORY_SEMANTICS:
        fail("Step-29 directory semantics do not match the proof contract")
    return manifest


def utc_tzif() -> bytes:
    """Return the manifest-pinned minimal TZif v1 file describing UTC with no transitions."""
    header = bytearray(b"TZif\0" + b"\0" * 15)
    # ttisgmtcnt, ttisstdcnt, leapcnt, timecnt, typecnt, charcnt
    header.extend(struct.pack(">6I", 0, 0, 0, 0, 1, 4))
    if len(header) != 44:
        fail("internal TZif header length error")
    # ttinfo: gmtoff=0, isdst=0, abbreviation index=0; abbreviation table="UTC\0".
    return bytes(header) + struct.pack(">lBB", 0, 0, 0) + b"UTC\0"


def verify_fixture(proof: dict[str, object], fixture: bytes) -> None:
    expected_size = int(proof["fixture_size_bytes"])
    if len(fixture) != expected_size:
        fail(f"Step-29 fixture size mismatch: got {len(fixture)}, expected {expected_size}")
    actual = sha256_bytes(fixture)
    expected = str(proof["fixture_sha256"])
    if actual != expected:
        fail(f"Step-29 fixture SHA-256 mismatch: got {actual}, expected {expected}")


def build_initramfs(step28, proof: dict[str, object], busybox: bytes, fixture: bytes) -> bytes:
    output = bytearray()
    entries = [
        (1, ".", 0o040755, b""),
        (2, "bin", 0o040755, b""),
        (3, "etc", 0o040755, b""),
        (4, "usr", 0o040755, b""),
        (5, "usr/share", 0o040755, b""),
        (6, "usr/share/zoneinfo", 0o040755, b""),
        (7, str(proof["busybox_path"]), 0o100755, busybox),
        (8, str(proof["fixture_target_path"]), 0o100644, fixture),
        (
            9,
            str(proof["fixture_path"]),
            0o120777,
            str(proof["fixture_symlink_target"]).encode("ascii"),
        ),
        (
            10,
            str(proof["directory_symlink_path"]),
            0o120777,
            str(proof["directory_symlink_target"]).encode("ascii"),
        ),
        (11, step28.CPIO_TRAILER, 0, b""),
    ]
    for inode, path, mode, data in entries:
        step28.newc_entry(output, inode, path, mode, data)
    while len(output) % 512:
        output.append(0)
    if not output or len(output) > MAX_INITRAMFS_BYTES:
        fail(f"Step-29 initramfs size is outside policy: {len(output)} bytes")
    return bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof-manifest", type=Path, default=DEFAULT_PROOF_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    proof_path = (
        args.proof_manifest
        if args.proof_manifest.is_absolute()
        else root / args.proof_manifest
    )
    proof = load_proof_manifest(proof_path)

    step28 = load_step28_builder(root)
    busybox_manifest_path = root / str(proof["busybox_manifest"])
    busybox_manifest = step28.load_manifest(busybox_manifest_path)
    package = step28.fetch_package(root, busybox_manifest)
    busybox = step28.extract_member(package, str(busybox_manifest["package_member"]))
    step28.validate_static_aarch64_elf(busybox)

    fixture = utc_tzif()
    verify_fixture(proof, fixture)
    initramfs = build_initramfs(step28, proof, busybox, fixture)
    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(initramfs)
    print(
        "Step-29 dual-proof initramfs built: "
        f"{output} bytes={len(initramfs)} busybox_sha256={step28.sha256_bytes(busybox)} "
        f"fixture_sha256={sha256_bytes(fixture)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
