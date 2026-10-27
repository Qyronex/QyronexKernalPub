#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

REQUIRED_INPUTS = {
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "linker-script",
    "native-c",
    "native-header",
    "assembly",
    "Dockerfile",
    "Makefile",
}
REQUIRED_SURFACES = {"elf64", "bootinfo", "acpi", "fdt", "cpio"}
REQUIRED_RULES = {
    "github-actions-pinned-by-sha",
    "no-cargo-git-dependency-without-revision",
    "unsafe-inventory",
    "assembly-inventory",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def identity(samples: list[dict]) -> str:
    canonical = "".join(
        f"{entry['path']}\0{entry['sha256']}\n"
        for entry in sorted(samples, key=lambda entry: entry["path"])
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def main() -> None:
    path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path(__file__).resolve().parents[3]
        / "tests/prep/step25/security_targets.json"
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1:
        raise SystemExit("invalid Step25 corpus schema")

    inputs = set(data.get("required_repro_inputs", []))
    if not REQUIRED_INPUTS <= inputs:
        raise SystemExit(f"missing reproducibility inputs: {sorted(REQUIRED_INPUTS - inputs)}")

    surfaces = data.get("fuzz_surfaces", [])
    names = {entry.get("name") for entry in surfaces}
    if not REQUIRED_SURFACES <= names:
        raise SystemExit(f"missing fuzz surfaces: {sorted(REQUIRED_SURFACES - names)}")
    for entry in surfaces:
        if entry.get("category") != "parser" or not entry.get("path"):
            raise SystemExit(f"invalid fuzz surface: {entry!r}")

    rules = set(data.get("supply_chain_rules", []))
    if not REQUIRED_RULES <= rules:
        raise SystemExit(f"missing supply-chain rules: {sorted(REQUIRED_RULES - rules)}")

    samples = data.get("identity_samples", [])
    if not samples or len({entry.get('path') for entry in samples}) != len(samples):
        raise SystemExit("identity samples must have unique paths")
    for entry in samples:
        if not HEX64.fullmatch(entry.get("sha256", "")):
            raise SystemExit(f"invalid sha256 sample: {entry!r}")

    baseline = identity(samples)
    mutated = [dict(entry) for entry in samples]
    mutated[0]["sha256"] = "d" * 64
    if identity(mutated) == baseline:
        raise SystemExit("reproducibility identity failed mutation sensitivity")
    if identity(list(reversed(samples))) != baseline:
        raise SystemExit("reproducibility identity must be path-order stable")

    print(f"STEP25_PREP_OK fuzz_surfaces={len(names)} repro_identity={baseline[:16]}")


if __name__ == "__main__":
    main()
