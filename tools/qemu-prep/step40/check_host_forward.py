#!/usr/bin/env python3
"""Check the Step-40 host->guest TCP server through QEMU hostfwd."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--request", default="KERNAL_STEP40_HOST_PING\n")
    parser.add_argument("--expect", default="KERNAL_STEP40_TCP_OK")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    if args.attempts < 1:
        parser.error("attempts must be >= 1")
    if args.timeout <= 0 or args.delay < 0:
        parser.error("timeout must be > 0 and delay >= 0")

    last_error = None
    for attempt in range(1, args.attempts + 1):
        started = time.monotonic()
        try:
            with socket.create_connection((args.host, args.port), timeout=args.timeout) as connection:
                connection.settimeout(args.timeout)
                connection.sendall(args.request.encode("utf-8"))
                reply = connection.recv(4096)
            decoded = reply.decode("utf-8", errors="replace")
            if args.expect not in decoded:
                last_error = f"expected token {args.expect!r} not present in reply {decoded!r}"
            else:
                print(
                    json.dumps(
                        {
                            "status": "PASS",
                            "check_id": "host-reachable-tcp",
                            "host": args.host,
                            "port": args.port,
                            "attempt": attempt,
                            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                            "expected_token": args.expect,
                            "reply": decoded,
                        },
                        sort_keys=True,
                    )
                )
                return 0
        except OSError as exc:
            last_error = str(exc)
        if attempt < args.attempts:
            time.sleep(args.delay)

    print(
        json.dumps(
            {
                "status": "FAIL",
                "check_id": "host-reachable-tcp",
                "host": args.host,
                "port": args.port,
                "attempts": args.attempts,
                "error": last_error,
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
