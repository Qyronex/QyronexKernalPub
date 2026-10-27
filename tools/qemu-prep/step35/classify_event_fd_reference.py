#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

TRACE_SYSCALLS = {
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "eventfd2",
    "timerfd_create",
    "timerfd_settime",
    "signalfd4",
    "inotify_init1",
    "inotify_add_watch",
    "memfd_create",
    "pidfd_open",
    "pidfd_send_signal",
    "close_range",
}

REQUIRED_PROBE_MARKERS = (
    "PASS epoll.level.first-ready",
    "PASS epoll.level.remains-ready",
    "PASS epoll.level.clears-after-drain",
    "PASS epoll.edge.first-transition",
    "PASS epoll.edge.no-repeat-without-transition",
    "PASS epoll.edge.new-transition",
    "PASS epoll.oneshot.first-ready",
    "PASS epoll.oneshot.disabled-after-delivery",
    "PASS epoll.oneshot.rearm",
    "PASS epoll.reuse.old-watch-not-redirected",
    "PASS eventfd.empty-nonblock-eagain",
    "PASS eventfd.epoll-ready",
    "PASS eventfd.read-counter",
    "PASS timerfd.expiration-ready",
    "PASS timerfd.expiration-count",
    "PASS signalfd.masked-delivery",
    "PASS inotify.create-move-delete",
    "PASS memfd.get-seals",
    "PASS memfd.grow-sealed-eperm",
    "PASS close-range.closed-fd",
    "PASS step35.event-fd-probe.complete",
)


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
        raise ValueError(f"invalid status in {path}: {text!r}") from exc


def syscall_inventory(text: str) -> list[str]:
    observed: set[str] = set()
    pattern = re.compile(r"^(?:\[pid\s+\d+\]\s+|\d+\s+)?([A-Za-z0-9_]+)\(")
    for raw in text.splitlines():
        match = pattern.match(raw.strip())
        if match and match.group(1) in TRACE_SYSCALLS:
            observed.add(match.group(1))
    return sorted(observed)


def classify(directory: Path) -> dict[str, object]:
    identity = parse_kv(directory / "identity.txt")
    required_identity = {"schema", "arch", "kernel", "source_commit", "target_id", "target_sha256"}
    missing = sorted(required_identity - identity.keys())
    if missing:
        raise ValueError(f"missing identity fields: {missing}")
    if identity["schema"] != "1":
        raise ValueError("unsupported Step35 reference schema")
    if identity["arch"] not in {"aarch64", "arm64"}:
        raise ValueError(f"reference is not AArch64: {identity['arch']!r}")
    if not re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"]):
        raise ValueError("source_commit must be full lowercase Git SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", identity["target_sha256"]):
        raise ValueError("target_sha256 must be lowercase SHA-256")

    probe_status = parse_status(directory / "event-fd-probe.status")
    if probe_status != 0:
        raise ValueError(f"event-fd probe did not pass: status={probe_status}")
    probe = read_text(directory / "event-fd-probe.stdout")
    missing_markers = [marker for marker in REQUIRED_PROBE_MARKERS if marker not in probe]
    if missing_markers:
        raise ValueError(f"event-fd probe missing markers: {missing_markers}")

    pidfd_supported = "INFO pidfd.open supported=1" in probe
    if pidfd_supported:
        for marker in (
            "PASS pidfd.release-child",
            "PASS pidfd.exit-readiness",
            "PASS pidfd.child-exit-zero",
        ):
            if marker not in probe:
                raise ValueError(f"pidfd support claimed without marker: {marker}")

    traces: dict[str, object] = {}
    for name, filename in (
        ("probe", "event-fd-probe.strace"),
        ("systemctl", "systemctl-event-api.strace"),
        ("busctl", "busctl-event-api.strace"),
    ):
        path = directory / filename
        text = read_text(path)
        traces[name] = {
            "present": bool(text),
            "syscalls": syscall_inventory(text),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None,
        }

    consumer_required = sorted(
        set(traces["systemctl"]["syscalls"]) | set(traces["busctl"]["syscalls"])
    )
    return {
        "schema": "kernal-step35-debian13-event-fd-reference-v1",
        "provenance": identity,
        "probe": {
            "status": probe_status,
            "pass_markers": [line[5:] for line in probe.splitlines() if line.startswith("PASS ")],
            "pidfd_open_supported": pidfd_supported,
            "errno_contracts": {
                "eventfd_empty_nonblock": "EAGAIN",
                "memfd_grow_after_grow_seal": "EPERM",
                "close_range_closed_fd": "EBADF",
            },
            "readiness_contracts": [
                "epoll_level_repeats_until_drain",
                "epoll_edge_requires_new_transition",
                "epoll_oneshot_requires_rearm",
                "closed_fd_number_reuse_does_not_redirect_old_watch",
                "eventfd_readiness_clears_after_counter_read",
                "timerfd_becomes_readable_after_expiration",
                "pidfd_becomes_readable_on_child_exit_if_supported",
            ],
        },
        "strace": traces,
        "observed_consumer_required_syscalls": consumer_required,
        "consumer_trace_complete": bool(traces["systemctl"]["present"] and traces["busctl"]["present"]),
        "runtime_rule": "Implement only the observed Debian consumer subset plus the explicit probe semantics; absence from one trace is not proof that a syscall is globally unnecessary.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = classify(args.input.expanduser().resolve())
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"step35-event-fd-classifier: FAIL: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        out = args.out.expanduser().resolve()
        if out.exists():
            print(f"step35-event-fd-classifier: FAIL: refusing to overwrite {out}", file=sys.stderr)
            return 1
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"step35-event-fd-classifier: PASS: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
