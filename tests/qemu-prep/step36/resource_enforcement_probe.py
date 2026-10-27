#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import os
import signal
import sys
import time
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")


def self_cgroup() -> Path:
    for raw in Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines():
        parts = raw.split(":", 2)
        if len(parts) == 3 and parts[0] == "0":
            relative = parts[2].lstrip("/")
            return CGROUP_ROOT / relative
    raise RuntimeError("unified cgroup-v2 self path not found")


def read_int(path: Path) -> int:
    text = path.read_text(encoding="utf-8").strip()
    if text == "max":
        return -1
    return int(text)


def read_stat(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        fields = raw.split()
        if len(fields) == 2:
            try:
                values[fields[0]] = int(fields[1])
            except ValueError:
                pass
    return values


def probe_pids() -> int:
    group = self_cgroup()
    limit = read_int(group / "pids.max")
    if limit < 1 or limit > 128:
        print(f"FAIL pids.limit-not-bounded value={limit}", file=sys.stderr)
        return 1
    gate_r, gate_w = os.pipe()
    children: list[int] = []
    failure_errno: int | None = None
    try:
        for _ in range(limit + 16):
            try:
                pid = os.fork()
            except OSError as exc:
                failure_errno = exc.errno
                break
            if pid == 0:
                os.close(gate_w)
                try:
                    os.read(gate_r, 1)
                finally:
                    os._exit(0)
            children.append(pid)
        if failure_errno not in {errno.EAGAIN, errno.ENOMEM}:
            print(
                f"FAIL pids.enforcement children={len(children)} errno={failure_errno}",
                file=sys.stderr,
            )
            return 1
        print(
            f"PASS pids.enforcement limit={limit} children_before_failure={len(children)} errno={failure_errno}"
        )
        return 0
    finally:
        os.close(gate_r)
        os.close(gate_w)
        for pid in children:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for pid in children:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def probe_cpu() -> int:
    group = self_cgroup()
    cpu_max = (group / "cpu.max").read_text(encoding="utf-8").strip()
    quota_text, period_text = cpu_max.split()
    if quota_text == "max":
        print("FAIL cpu.quota-unbounded", file=sys.stderr)
        return 1
    quota = int(quota_text)
    period = int(period_text)
    if quota <= 0 or period <= 0 or quota >= period:
        print(f"FAIL cpu.quota-not-restrictive quota={quota} period={period}", file=sys.stderr)
        return 1
    before = read_stat(group / "cpu.stat")
    deadline = time.monotonic() + 1.5
    value = 1
    while time.monotonic() < deadline:
        value = (value * 1103515245 + 12345) & 0x7FFFFFFF
    after = read_stat(group / "cpu.stat")
    before_count = before.get("nr_throttled", 0)
    after_count = after.get("nr_throttled", 0)
    if after_count <= before_count:
        print(
            f"FAIL cpu.throttling-not-observed before={before_count} after={after_count} value={value}",
            file=sys.stderr,
        )
        return 1
    print(
        f"PASS cpu.throttling quota={quota} period={period} nr_throttled_before={before_count} nr_throttled_after={after_count}"
    )
    return 0


def probe_memory_survivor(megabytes: int) -> int:
    group = self_cgroup()
    limit = read_int(group / "memory.max")
    print(f"INFO memory.limit={limit} requested_megabytes={megabytes}")
    # This mode is intentionally expected to be killed by cgroup memory
    # enforcement when systemd-run gives it a smaller MemoryMax. If it returns
    # successfully the caller must treat that as an enforcement failure.
    payload = bytearray(megabytes * 1024 * 1024)
    for offset in range(0, len(payload), 4096):
        payload[offset] = 1
    print("FAIL memory.enforcement-process-survived")
    return 42


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("pids", "cpu", "memory"))
    parser.add_argument("--megabytes", type=int, default=96)
    args = parser.parse_args()
    try:
        if args.mode == "pids":
            return probe_pids()
        if args.mode == "cpu":
            return probe_cpu()
        return probe_memory_survivor(args.megabytes)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"FAIL resource-probe mode={args.mode} error={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
