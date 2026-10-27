#!/usr/bin/env python3
"""Collect Debian 13 ARM64 reference observations and a normalized requirement inventory.

Run this only inside the pinned Debian reference environment. The collector refuses another
release/architecture, validates probe components against the compatibility matrix, hashes program
output, and reduces strace data to reviewable requirement categories. Raw traces, PIDs, addresses and
timing data are never persisted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TARGET = ROOT / "docs/debian13/arm64-target.json"
DEFAULT_MATRIX = ROOT / "docs/debian13/compatibility-matrix.json"
DEFAULT_CASES = ROOT / "tests/debian13/reference-cases.json"
DEFAULT_OBSERVATION = Path("reference-debian.json")
DEFAULT_INVENTORY = Path("reference-syscalls.json")
CASE_ID = re.compile(r"^[A-Za-z0-9._-]+$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
# With `strace -f -o`, child lines may start with either `1234 ` or `[pid 1234] ` depending on
# strace/version/options. The syscall name itself and selected normalized arguments are retained.
SYSCALL = re.compile(
    r"^(?:(?:\[pid\s+\d+\]|\d+)\s+)?([A-Za-z_][A-Za-z0-9_]*)\("
)
RESULT_DELIMITER = re.compile(r"\)\s+=\s")
QUOTED = re.compile(r'"((?:\\.|[^"\\])*)"')
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.+|:-]+$")
NETWORK_SYSCALLS = {
    "accept",
    "accept4",
    "bind",
    "connect",
    "getpeername",
    "getsockname",
    "getsockopt",
    "listen",
    "recvfrom",
    "recvmmsg",
    "recvmsg",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setsockopt",
    "shutdown",
    "socket",
    "socketpair",
}
# Only arguments that the Linux ABI defines as path operands are retained as path requirements.
# This deliberately excludes arbitrary quoted payloads from write/send/logging syscalls.
PATH_ARGUMENT_POSITIONS: dict[str, tuple[int, ...]] = {
    "access": (0,),
    "chdir": (0,),
    "chmod": (0,),
    "chown": (0,),
    "chroot": (0,),
    "execve": (0,),
    "execveat": (1,),
    "faccessat": (1,),
    "faccessat2": (1,),
    "fchmodat": (1,),
    "fchownat": (1,),
    "link": (0, 1),
    "linkat": (1, 3),
    "lchown": (0,),
    "lstat": (0,),
    "mkdir": (0,),
    "mkdirat": (1,),
    "mknod": (0,),
    "mknodat": (1,),
    "mount": (0, 1),
    "move_mount": (1, 3),
    "name_to_handle_at": (1,),
    "newfstatat": (1,),
    "open": (0,),
    "openat": (1,),
    "openat2": (1,),
    "open_tree": (1,),
    "pivot_root": (0, 1),
    "readlink": (0,),
    "readlinkat": (1,),
    "rename": (0, 1),
    "renameat": (1, 3),
    "renameat2": (1, 3),
    "rmdir": (0,),
    "stat": (0,),
    "statfs": (0,),
    "statx": (1,),
    "symlink": (0, 1),
    "symlinkat": (0, 2),
    "truncate": (0,),
    "umount": (0,),
    "umount2": (0,),
    "unlink": (0,),
    "unlinkat": (1,),
    "utimensat": (1,),
}
UNIX_SOCKET_ADDRESS_SYSCALLS = {"bind", "connect", "sendto", "recvfrom"}
REQUIREMENT_KEYS = (
    "syscalls",
    "ioctl_requests",
    "paths",
    "proc_paths",
    "sys_paths",
    "dev_paths",
    "filesystem_paths",
    "socket_families",
    "socket_types",
    "socket_protocols",
    "network_syscalls",
)


class CollectionError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CollectionError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CollectionError(f"cannot read JSON {path}: {error}") from error
    require(isinstance(value, dict), f"top-level JSON value must be an object: {path}")
    return value


def parse_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise CollectionError(f"cannot read {path}: {error}") from error
    values: dict[str, str] = {}
    for raw in lines:
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def clean_environment() -> dict[str, str]:
    return {
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }


def validate_environment(target: dict[str, Any]) -> dict[str, str]:
    require(target.get("architecture") == "arm64", "collector target must be arm64")
    machine = platform.machine().lower()
    require(machine in {"aarch64", "arm64"}, f"reference machine must be ARM64, got {machine}")

    release = parse_os_release()
    require(release.get("ID") == "debian", "reference environment must be Debian")
    require(
        release.get("VERSION_ID", "").split(".", 1)[0] == "13",
        f"reference VERSION_ID must be Debian 13, got {release.get('VERSION_ID')!r}",
    )
    require(
        release.get("VERSION_CODENAME") == "trixie",
        f"reference codename must be trixie, got {release.get('VERSION_CODENAME')!r}",
    )

    dpkg = shutil.which("dpkg")
    require(dpkg is not None, "dpkg is required in the reference environment")
    arch = subprocess.run(
        [dpkg, "--print-architecture"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=clean_environment(),
    ).stdout.strip()
    require(arch == "arm64", f"dpkg architecture must be arm64, got {arch}")

    strace = shutil.which("strace")
    require(strace is not None, "strace is required; prepare the pinned reference packages first")
    return {
        "machine": machine,
        "kernel_release": platform.release(),
        "version_id": release.get("VERSION_ID", ""),
        "version_codename": release.get("VERSION_CODENAME", ""),
        "dpkg_architecture": arch,
        "strace": strace,
    }


def matrix_components(matrix: dict[str, Any], target_id: str) -> dict[str, str]:
    require(matrix.get("schema_version") == 1, "matrix schema_version must be 1")
    require(matrix.get("target_id") == target_id, "matrix target_id mismatch")
    entries = matrix.get("components")
    require(isinstance(entries, list), "matrix components must be an array")
    result: dict[str, str] = {}
    for entry in entries:
        require(isinstance(entry, dict), "matrix component must be an object")
        component_id = entry.get("id")
        program = entry.get("program")
        require(
            isinstance(component_id, str) and component_id and component_id not in result,
            "matrix component ids must be unique non-empty strings",
        )
        require(
            isinstance(program, str) and Path(program).is_absolute(),
            f"{component_id}: matrix program must be an absolute path",
        )
        result[component_id] = program
    return result


def validate_cases(
    document: dict[str, Any], target_id: str, allowed_components: dict[str, str]
) -> list[dict[str, Any]]:
    require(document.get("schema_version") == 1, "case manifest schema_version must be 1")
    require(document.get("target_id") == target_id, "case manifest target_id mismatch")
    cases = document.get("cases")
    require(isinstance(cases, list) and cases, "case manifest must contain cases")
    seen: set[str] = set()
    covered: set[str] = set()
    validated: list[dict[str, Any]] = []
    for case in cases:
        require(isinstance(case, dict), "case entry must be an object")
        case_id = case.get("id")
        component = case.get("component")
        argv = case.get("argv")
        require(
            isinstance(case_id, str)
            and CASE_ID.fullmatch(case_id) is not None
            and case_id not in seen,
            "case ids must be unique and use only A-Za-z0-9._-",
        )
        seen.add(case_id)
        require(
            isinstance(component, str) and component in allowed_components,
            f"{case_id}: component must exist in compatibility matrix",
        )
        covered.add(component)
        require(
            isinstance(argv, list)
            and argv
            and all(isinstance(arg, str) and "\x00" not in arg for arg in argv),
            f"{case_id}: argv must be a non-empty string array",
        )
        expected_program = allowed_components[component]
        require(
            argv[0] == expected_program,
            f"{case_id}: program must match compatibility matrix: {expected_program}",
        )
        program = Path(argv[0])
        require(program.is_absolute(), f"{case_id}: program path must be absolute")
        require(
            program.is_file() and os.access(program, os.X_OK),
            f"{case_id}: program is missing or not executable: {program}",
        )
        validated.append({"id": case_id, "component": component, "argv": argv})
    missing = sorted(set(allowed_components) - covered)
    require(not missing, f"reference cases do not cover matrix components: {','.join(missing)}")
    return validated


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def trace_call(raw: str) -> tuple[str, str | None] | None:
    """Return a syscall name and complete argument text when available.

    strace aligns short calls with arbitrary whitespace before `=`, so result parsing must accept
    any amount of alignment whitespace. An unfinished `-f` call still contributes its syscall name;
    argument-specific requirements are extracted only from complete call lines.
    """
    line = raw.strip()
    match = SYSCALL.match(line)
    if match is None:
        return None
    name = match.group(1)
    args_and_result = line[match.end() :]
    delimiter = RESULT_DELIMITER.search(args_and_result)
    if delimiter is None:
        return name, None
    return name, args_and_result[: delimiter.start()]


def split_top_level_args(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote = False
    escaped = False
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def safe_token(value: str) -> str | None:
    token = value.strip()
    if not token or len(token) > 128 or SAFE_TOKEN.fullmatch(token) is None:
        return None
    return token


def quoted_strings(value: str) -> list[str]:
    return [match.group(1) for match in QUOTED.finditer(value)]


def path_operands(name: str, args: list[str], args_text: str) -> list[str]:
    result: list[str] = []
    for position in PATH_ARGUMENT_POSITIONS.get(name, ()):
        if position >= len(args):
            continue
        result.extend(quoted_strings(args[position]))
    if name in UNIX_SOCKET_ADDRESS_SYSCALLS and "sun_path=" in args_text:
        result.extend(quoted_strings(args_text))
    return [path for path in result if path and len(path) <= 4096 and "\x00" not in path]


def empty_requirements() -> dict[str, list[str]]:
    return {key: [] for key in REQUIREMENT_KEYS}


def parse_requirements(trace: str) -> dict[str, list[str]]:
    values: dict[str, set[str]] = {key: set() for key in REQUIREMENT_KEYS}
    for raw in trace.splitlines():
        call = trace_call(raw)
        if call is None:
            continue
        name, args_text = call
        values["syscalls"].add(name)
        if args_text is None:
            continue
        args = split_top_level_args(args_text)

        values["paths"].update(path_operands(name, args, args_text))

        if name == "ioctl" and len(args) >= 2:
            request = safe_token(args[1])
            if request is not None:
                values["ioctl_requests"].add(request)

        if name == "socket" and len(args) >= 3:
            for key, raw_value in zip(
                ("socket_families", "socket_types", "socket_protocols"), args[:3]
            ):
                token = safe_token(raw_value)
                if token is not None:
                    values[key].add(token)

        if name in NETWORK_SYSCALLS:
            values["network_syscalls"].add(name)

    for path in values["paths"]:
        if path == "/proc" or path.startswith("/proc/"):
            values["proc_paths"].add(path)
        elif path == "/sys" or path.startswith("/sys/"):
            values["sys_paths"].add(path)
        elif path == "/dev" or path.startswith("/dev/"):
            values["dev_paths"].add(path)
        else:
            values["filesystem_paths"].add(path)

    return {key: sorted(values[key]) for key in REQUIREMENT_KEYS}


def aggregate_requirements(cases: list[dict[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {key: set() for key in REQUIREMENT_KEYS}
    for case in cases:
        requirements = case.get("requirements")
        require(isinstance(requirements, dict), "inventory case requirements must be an object")
        for key in REQUIREMENT_KEYS:
            entries = requirements.get(key)
            require(
                isinstance(entries, list) and all(isinstance(entry, str) for entry in entries),
                f"inventory requirement {key} must be a string array",
            )
            result[key].update(entries)
    return {key: sorted(result[key]) for key in REQUIREMENT_KEYS}


def evidence_provenance(target: dict[str, Any], source_commit: str) -> dict[str, Any]:
    require(HEX40.fullmatch(source_commit) is not None, "source_commit must be a 40-char lowercase git SHA")
    rootfs = target.get("rootfs")
    require(isinstance(rootfs, dict), "target rootfs must be an object")
    artifact = rootfs.get("artifact")
    size_bytes = rootfs.get("size_bytes")
    sha256_value = rootfs.get("sha256")
    sha512_value = rootfs.get("sha512")
    require(isinstance(artifact, str) and artifact, "rootfs artifact is required for provenance")
    require(isinstance(size_bytes, int) and size_bytes > 0, "rootfs size is required for provenance")
    require(
        isinstance(sha256_value, str) and HEX64.fullmatch(sha256_value) is not None,
        "rootfs sha256 is invalid for provenance",
    )
    require(
        isinstance(sha512_value, str) and HEX128.fullmatch(sha512_value) is not None,
        "rootfs sha512 is invalid for provenance",
    )
    return {
        "source_commit": source_commit,
        "rootfs": {
            "artifact": artifact,
            "size_bytes": size_bytes,
            "sha256": sha256_value,
            "sha512": sha512_value,
        },
    }


def signal_name(returncode: int) -> str | None:
    if returncode >= 0:
        return None
    number = -returncode
    try:
        return signal.Signals(number).name
    except ValueError:
        return f"SIG{number}"


def collect_case(
    case: dict[str, Any], strace: str, timeout_seconds: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="kernal-debian13-oracle-") as directory:
        trace_path = Path(directory) / "trace.txt"
        command = [
            strace,
            "-f",
            "-qq",
            "-s",
            "0",
            "-o",
            str(trace_path),
            "--",
            *case["argv"],
        ]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
                env=clean_environment(),
                cwd="/tmp",
            )
        except subprocess.TimeoutExpired as error:
            raise CollectionError(f"{case['id']}: timed out after {timeout_seconds}s") from error
        try:
            trace = trace_path.read_text(encoding="utf-8", errors="strict")
        except OSError as error:
            raise CollectionError(f"{case['id']}: cannot read strace output: {error}") from error

    requirements = parse_requirements(trace)
    require(requirements["syscalls"], f"{case['id']}: strace produced no syscall inventory")
    observed = {
        "id": case["id"],
        "outcome": {
            "return_value": None,
            "errno": None,
            "signal": signal_name(completed.returncode),
            "exit_status": completed.returncode if completed.returncode >= 0 else None,
            "stdout_sha256": sha256(completed.stdout),
            "stderr_sha256": sha256(completed.stderr),
            "file_metadata": None,
            "socket_behavior": None,
        },
    }
    inventory = {
        "id": case["id"],
        "component": case["component"],
        "argv": case["argv"],
        # Keep the original field for existing consumers while the richer normalized schema is adopted.
        "syscalls": requirements["syscalls"],
        "requirements": requirements,
    }
    return observed, inventory


def package_versions() -> dict[str, str]:
    packages = [
        "apt",
        "busybox",
        "dash",
        "dbus",
        "dpkg",
        "iproute2",
        "libc6",
        "strace",
        "systemd",
        "udev",
    ]
    result: dict[str, str] = {}
    for package in packages:
        completed = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=clean_environment(),
        )
        require(
            completed.returncode == 0,
            f"required reference package is not installed: {package}",
        )
        version = completed.stdout.strip()
        require(version, f"reference package has empty version: {package}")
        result[package] = version
    return result


def dump(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n",
        encoding="utf-8",
    )


def collect(args: argparse.Namespace) -> None:
    target = load_json(args.target)
    require(target.get("schema_version") == 1, "target schema_version must be 1")
    target_id = target.get("target_id")
    require(isinstance(target_id, str) and target_id, "target_id is required")
    provenance = evidence_provenance(target, args.source_commit)
    environment = validate_environment(target)
    components = matrix_components(load_json(args.matrix), target_id)
    cases = validate_cases(load_json(args.cases), target_id, components)
    versions = package_versions()
    strace = environment["strace"]

    observations: list[dict[str, Any]] = []
    inventories: list[dict[str, Any]] = []
    for case in cases:
        observed, inventory = collect_case(case, strace, args.timeout)
        observations.append(observed)
        inventories.append(inventory)

    dump(
        args.observation,
        {
            "schema_version": 1,
            "target_id": target_id,
            "environment": "reference-debian",
            "provenance": provenance,
            "cases": observations,
        },
    )
    dump(
        args.inventory,
        {
            "schema_version": 1,
            "target_id": target_id,
            "environment": "reference-debian",
            "provenance": provenance,
            "host": environment,
            "packages": versions,
            "requirements": aggregate_requirements(inventories),
            "cases": inventories,
        },
    )
    print(f"collected {len(cases)} Debian ARM64 reference cases")
    print(f"observation: {args.observation}")
    print(f"requirement inventory: {args.inventory}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--observation", type=Path, default=DEFAULT_OBSERVATION)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--timeout", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        print("debian13-reference: timeout must be positive", file=sys.stderr)
        return 2
    try:
        collect(args)
    except (CollectionError, OSError, subprocess.SubprocessError) as error:
        print(f"debian13-reference: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
