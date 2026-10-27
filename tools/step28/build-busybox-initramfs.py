#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
"""Build the bounded Step-28 initramfs from the pinned Debian ARM64 busybox-static package."""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import urllib.request

AR_MAGIC = b"!<arch>\n"
AR_HEADER_BYTES = 60
CPIO_HEADER_BYTES = 110
CPIO_TRAILER = "TRAILER!!!"
MAX_PACKAGE_BYTES = 16 * 1024 * 1024
MAX_BUSYBOX_BYTES = 8 * 1024 * 1024
PT_LOAD = 1
PT_INTERP = 3
EM_AARCH64 = 183

STEP28_MANIFEST_FIELDS = {
    "schema_version",
    "target_id",
    "package",
    "version",
    "architecture",
    "artifact",
    "immutable_url",
    "size_bytes",
    "sha256",
    "package_member",
    "initramfs_path",
    "proof_argv0",
    "qemu_guest_address",
}
STEP28_FIXED_MANIFEST_VALUES = {
    "schema_version": 1,
    "target_id": "debian-13-trixie-arm64-20260712-2537",
    "package": "busybox-static",
    "architecture": "arm64",
    "package_member": "usr/bin/busybox",
    "initramfs_path": "bin/busybox",
    "proof_argv0": "true",
    "qemu_guest_address": "0x48000000",
}


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: Path) -> dict[str, object]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        fail("Step-28 manifest root must be a JSON object")

    keys = set(manifest)
    missing = sorted(STEP28_MANIFEST_FIELDS.difference(keys))
    if missing:
        fail(f"Step-28 manifest is missing fields: {', '.join(missing)}")
    unexpected = sorted(keys.difference(STEP28_MANIFEST_FIELDS))
    if unexpected:
        fail(f"Step-28 manifest has unexpected fields: {', '.join(unexpected)}")

    for field, expected in STEP28_FIXED_MANIFEST_VALUES.items():
        actual = manifest[field]
        if actual != expected:
            fail(f"Step-28 manifest {field} must be {expected!r}, got {actual!r}")

    version = manifest["version"]
    if not isinstance(version, str) or not version:
        fail("Step-28 BusyBox package version must be a non-empty string")
    artifact = manifest["artifact"]
    if not isinstance(artifact, str) or not artifact.endswith("_arm64.deb"):
        fail("Step-28 BusyBox artifact must name an ARM64 Debian package")
    url = manifest["immutable_url"]
    if not isinstance(url, str) or not url.startswith(
        "https://snapshot.debian.org/archive/debian/20260712T000000Z/"
    ):
        fail("Step-28 BusyBox URL must use the pinned 2026-07-12 Debian snapshot")
    if not url.endswith(f"/{artifact}"):
        fail("Step-28 BusyBox URL artifact does not match the manifest artifact")

    digest = manifest["sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        fail("Step-28 BusyBox package SHA-256 is malformed")
    size = manifest["size_bytes"]
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_PACKAGE_BYTES:
        fail("Step-28 BusyBox package size is outside the bounded policy")
    return manifest


def verify_package(data: bytes, manifest: dict[str, object]) -> None:
    expected_size = int(manifest["size_bytes"])
    if len(data) != expected_size:
        fail(f"BusyBox package size mismatch: got {len(data)}, expected {expected_size}")
    actual = sha256_bytes(data)
    expected = str(manifest["sha256"])
    if actual != expected:
        fail(f"BusyBox package SHA-256 mismatch: got {actual}, expected {expected}")


def fetch_package(root: Path, manifest: dict[str, object]) -> bytes:
    override = os.environ.get("KERNAL_STEP28_BUSYBOX_DEB")
    if override:
        source = Path(override).expanduser()
        data = source.read_bytes()
        verify_package(data, manifest)
        return data

    cache_root = Path(
        os.environ.get("KERNAL_STEP28_CACHE", "~/.cache/kernal/step28")
    ).expanduser()
    cache_root.mkdir(parents=True, exist_ok=True)
    artifact = str(manifest["artifact"])
    cache_path = cache_root / artifact
    if cache_path.is_file():
        data = cache_path.read_bytes()
        verify_package(data, manifest)
        return data

    url = str(manifest["immutable_url"])
    if not url.startswith("https://snapshot.debian.org/archive/debian/"):
        fail("Step-28 BusyBox URL must use the pinned Debian snapshot archive")

    request = urllib.request.Request(url, headers={"User-Agent": "kernal-step28/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(MAX_PACKAGE_BYTES + 1)
    if len(data) > MAX_PACKAGE_BYTES:
        fail("downloaded BusyBox package exceeds the Step-28 size bound")
    verify_package(data, manifest)

    with tempfile.NamedTemporaryFile(dir=cache_root, delete=False) as temporary:
        temporary.write(data)
        temporary_path = Path(temporary.name)
    temporary_path.replace(cache_path)
    return data


def ar_members(data: bytes) -> dict[str, bytes]:
    if not data.startswith(AR_MAGIC):
        fail("Debian package is missing the ar global header")
    offset = len(AR_MAGIC)
    members: dict[str, bytes] = {}
    while offset < len(data):
        end = offset + AR_HEADER_BYTES
        if end > len(data):
            fail("truncated ar member header")
        header = data[offset:end]
        if header[58:60] != b"`\n":
            fail("invalid ar member trailer")
        raw_name = header[0:16].decode("ascii", "strict").strip()
        if raw_name.endswith("/"):
            raw_name = raw_name[:-1]
        try:
            size = int(header[48:58].decode("ascii", "strict").strip(), 10)
        except ValueError as error:
            raise RuntimeError("invalid ar member size") from error
        if size < 0 or size > MAX_PACKAGE_BYTES:
            fail("ar member size is outside the Step-28 bound")
        payload_start = end
        payload_end = payload_start + size
        if payload_end > len(data):
            fail("truncated ar member payload")
        if not raw_name or raw_name in members:
            fail("empty or duplicate ar member name")
        members[raw_name] = data[payload_start:payload_end]
        offset = payload_end + (size & 1)
    if offset != len(data):
        fail("ar package has invalid alignment")
    return members


def decompress_data_tar(members: dict[str, bytes]) -> bytes:
    candidates = [name for name in members if name.startswith("data.tar")]
    if len(candidates) != 1:
        fail("Debian package must contain exactly one data.tar member")
    name = candidates[0]
    payload = members[name]
    if name == "data.tar":
        return payload
    if name == "data.tar.xz":
        return lzma.decompress(payload)
    if name == "data.tar.gz":
        return gzip.decompress(payload)
    if name == "data.tar.bz2":
        return bz2.decompress(payload)
    fail(f"unsupported Debian data archive compression: {name}")


def extract_member(package: bytes, member_path: str) -> bytes:
    data_tar = decompress_data_tar(ar_members(package))
    wanted = member_path.removeprefix("./").lstrip("/")
    with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:") as archive:
        matches = []
        for member in archive.getmembers():
            normalized = member.name.removeprefix("./").lstrip("/")
            if normalized == wanted:
                matches.append(member)
        if len(matches) != 1:
            fail(f"Debian data archive must contain exactly one {wanted}")
        member = matches[0]
        if not member.isfile():
            fail(f"Debian package member {wanted} is not a regular file")
        if member.size <= 0 or member.size > MAX_BUSYBOX_BYTES:
            fail("BusyBox executable size is outside the Step-28 bound")
        file_object = archive.extractfile(member)
        if file_object is None:
            fail(f"could not read Debian package member {wanted}")
        data = file_object.read(MAX_BUSYBOX_BYTES + 1)
        if len(data) != member.size:
            fail("BusyBox member length does not match tar metadata")
        return data


def validate_static_aarch64_elf(data: bytes) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        fail("BusyBox payload is not an ELF image")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        fail("BusyBox must be ELF64 little-endian version 1")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_AARCH64:
        fail(f"BusyBox ELF machine is {machine}, expected AArch64 ({EM_AARCH64})")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize = struct.unpack_from("<H", data, 54)[0]
    phnum = struct.unpack_from("<H", data, 56)[0]
    if phnum == 0 or phentsize < 56:
        fail("BusyBox ELF has no valid program-header table")
    table_bytes = phentsize * phnum
    if phoff > len(data) or table_bytes > len(data) - phoff:
        fail("BusyBox ELF program-header table is out of bounds")

    load_segments = 0
    for index in range(phnum):
        header = phoff + index * phentsize
        segment_type = struct.unpack_from("<I", data, header)[0]
        if segment_type == PT_INTERP:
            fail("BusyBox proof requires a static ELF without PT_INTERP")
        if segment_type == PT_LOAD:
            load_segments += 1
    if load_segments == 0:
        fail("BusyBox ELF contains no PT_LOAD segment")


def align4(output: bytearray) -> None:
    while len(output) % 4:
        output.append(0)


def newc_entry(output: bytearray, ino: int, path: str, mode: int, payload: bytes) -> None:
    encoded_path = path.encode("utf-8")
    if b"\x00" in encoded_path or not encoded_path:
        fail("invalid Step-28 initramfs path")
    fields = [
        ino,
        mode,
        0,
        0,
        1,
        0,
        len(payload),
        0,
        0,
        0,
        0,
        len(encoded_path) + 1,
        0,
    ]
    header = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    if len(header) != CPIO_HEADER_BYTES:
        fail("internal CPIO header length error")
    output.extend(header)
    output.extend(encoded_path)
    output.append(0)
    align4(output)
    output.extend(payload)
    align4(output)


def build_initramfs(busybox: bytes, path: str) -> bytes:
    if path != "bin/busybox":
        fail("Step-28 proof path is fixed to bin/busybox")
    output = bytearray()
    newc_entry(output, 1, ".", 0o040755, b"")
    newc_entry(output, 2, "bin", 0o040755, b"")
    newc_entry(output, 3, path, 0o100755, busybox)
    newc_entry(output, 4, CPIO_TRAILER, 0, b"")
    while len(output) % 512:
        output.append(0)
    return bytes(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/step28/busybox-static-arm64.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/step28/busybox-initramfs.cpio"),
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    manifest_path = args.manifest if args.manifest.is_absolute() else root / args.manifest
    output_path = args.output if args.output.is_absolute() else root / args.output
    manifest = load_manifest(manifest_path)
    package = fetch_package(root, manifest)
    busybox = extract_member(package, str(manifest["package_member"]))
    validate_static_aarch64_elf(busybox)
    initramfs = build_initramfs(busybox, str(manifest["initramfs_path"]))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(initramfs)
    print(f"step28 package_sha256={sha256_bytes(package)}")
    print(f"step28 busybox_sha256={sha256_bytes(busybox)}")
    print(f"step28 initramfs_sha256={sha256_bytes(initramfs)}")
    print(f"step28 initramfs_bytes={len(initramfs)}")
    print(f"step28 output={output_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"step28 builder: {error}", file=sys.stderr)
        raise SystemExit(1)
