#!/usr/bin/env python3
"""Run deterministic host-local TCP/UDP endpoints for Step-34 QEMU tests.

Default binding is loopback-only. If the selected QEMU user-network setup cannot
reach loopback through its host alias, an operator may explicitly select another
bind address and must record it in acceptance evidence.
"""

from __future__ import annotations

import argparse
import json
import signal
import socket
import threading
import time

STOP = threading.Event()
TCP_REPLY = b"KERNAL_TCP_OK\n"
UDP_PREFIX = b"KERNAL_UDP_OK:"


def tcp_worker(bind: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind, port))
        server.listen(16)
        server.settimeout(0.5)
        while not STOP.is_set():
            try:
                client, peer = server.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(2.0)
                try:
                    payload = client.recv(4096)
                except socket.timeout:
                    payload = b""
                client.sendall(TCP_REPLY)
                print(json.dumps({"event": "tcp", "peer": peer[0], "peer_port": peer[1], "request_len": len(payload)}), flush=True)


def udp_worker(bind: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((bind, port))
        server.settimeout(0.5)
        while not STOP.is_set():
            try:
                payload, peer = server.recvfrom(4096)
            except socket.timeout:
                continue
            reply = UDP_PREFIX + payload[:256]
            server.sendto(reply, peer)
            print(json.dumps({"event": "udp", "peer": peer[0], "peer_port": peer[1], "request_len": len(payload)}), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=18081)
    parser.add_argument("--udp-port", type=int, default=18082)
    args = parser.parse_args()

    if not 1 <= args.tcp_port <= 65535 or not 1 <= args.udp_port <= 65535:
        parser.error("ports must be in 1..65535")
    if args.tcp_port == args.udp_port:
        parser.error("TCP and UDP ports must differ for unambiguous evidence")

    def stop_handler(_signum, _frame):
        STOP.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    threads = [
        threading.Thread(target=tcp_worker, args=(args.bind, args.tcp_port), name="tcp-endpoint", daemon=True),
        threading.Thread(target=udp_worker, args=(args.bind, args.udp_port), name="udp-endpoint", daemon=True),
    ]
    for thread in threads:
        thread.start()

    print(
        json.dumps(
            {
                "status": "READY",
                "bind": args.bind,
                "tcp_port": args.tcp_port,
                "udp_port": args.udp_port,
                "tcp_reply": TCP_REPLY.decode().strip(),
                "udp_reply_prefix": UDP_PREFIX.decode(),
            },
            sort_keys=True,
        ),
        flush=True,
    )

    try:
        while not STOP.is_set():
            if not all(thread.is_alive() for thread in threads):
                STOP.set()
                return 1
            time.sleep(0.2)
    finally:
        STOP.set()
        for thread in threads:
            thread.join(timeout=1.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
