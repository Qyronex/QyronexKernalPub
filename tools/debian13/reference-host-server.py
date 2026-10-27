#!/usr/bin/env python3
"""Loopback-only transfer server for the Debian 13 ARM64 reference QEMU guest.

It serves cloud-init metadata/user-data plus one exact git archive and accepts only the bounded
reference evidence files declared by the canonical host runner. A random URL token is required for uploads, request sizes are bounded, and no
arbitrary path writes are permitted.
"""

from __future__ import annotations

import argparse
import http.server
import os
import secrets
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_UPLOADS = {
    "reference-debian.json",
    "reference-syscalls.json",
    "kernal-step32-tty-reference.raw",
    "kernal-step32-tty-reference.json",
}
ALLOWED_DOWNLOADS = {"meta-data", "user-data", "repo.tar.gz"}


class ReferenceHandler(http.server.BaseHTTPRequestHandler):
    server_version = "KernalDebianReference/1"

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write("reference-host: " + (format % args) + "\n")

    @property
    def root(self) -> Path:
        return self.server.root  # type: ignore[attr-defined]

    @property
    def token(self) -> str:
        return self.server.token  # type: ignore[attr-defined]

    @property
    def output(self) -> Path:
        return self.server.output  # type: ignore[attr-defined]

    def safe_name(self) -> str:
        path = urlsplit(self.path).path
        return path.rsplit("/", 1)[-1]

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        name = self.safe_name()
        if path != f"/{name}" or name not in ALLOWED_DOWNLOADS:
            self.send_error(404)
            return
        source = self.root / name
        if not source.is_file():
            self.send_error(404)
            return
        data = source.read_bytes()
        content_type = "application/gzip" if name.endswith(".gz") else "text/plain; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        prefix = f"/upload/{self.token}/"
        if not path.startswith(prefix):
            self.send_error(403)
            return
        name = path[len(prefix) :]
        if "/" in name or name not in ALLOWED_UPLOADS:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_error(411)
            return
        if length < 1 or length > MAX_UPLOAD_BYTES:
            self.send_error(413)
            return
        data = self.rfile.read(length)
        if len(data) != length:
            self.send_error(400)
            return
        try:
            data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            self.send_error(400)
            return
        self.output.mkdir(parents=True, exist_ok=True)
        temporary = self.output / f".{name}.part"
        destination = self.output / name
        temporary.write_bytes(data)
        os.replace(temporary, destination)
        self.send_response(204)
        self.end_headers()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--token", default=secrets.token_hex(24))
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--port-file", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.root.is_dir():
        raise SystemExit(f"server root does not exist: {args.root}")
    if not args.token or "/" in args.token:
        raise SystemExit("upload token is invalid")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), ReferenceHandler)
    server.root = args.root  # type: ignore[attr-defined]
    server.output = args.output  # type: ignore[attr-defined]
    server.token = args.token  # type: ignore[attr-defined]
    args.port_file.write_text(str(server.server_port) + "\n", encoding="ascii")
    print(f"reference-host: listening on 127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
