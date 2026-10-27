#!/usr/bin/env python3
import re
import sys
from pathlib import Path

if len(sys.argv) != 3:
    print("usage: classify_result.py <exit-code> <log-file>", file=sys.stderr)
    raise SystemExit(64)

exit_code = int(sys.argv[1])
text = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")

infra_patterns = [
    r"AArch64 musl compiler not found",
    r"not an AArch64 musl toolchain",
    r"can't find crate for [`']core",
    r"aarch64-unknown-none-softfloat.*(?:missing|not installed|unusable)",
    r"No space left on device",
    r"\bENOSPC\b",
    r"qemu-system-aarch64: command not found",
]
compile_patterns = [
    r"error\[E\d+\]",
    r"could not compile",
    r"error: aborting due to",
    r"clippy.*(?:error|failed)",
]
runtime_patterns = [
    r"KERNAL/ARM64:",
    r"qemu-system-aarch64",
    r"panic",
    r"exception",
    r"timeout",
    r"marker.*(?:missing|not found)",
]

if exit_code == 0:
    print("PASS")
    raise SystemExit(0)
if any(re.search(p, text, re.I | re.S) for p in infra_patterns):
    print("INFRA")
    raise SystemExit(10)
if any(re.search(p, text, re.I | re.S) for p in compile_patterns):
    print("COMPILE")
    raise SystemExit(20)
if any(re.search(p, text, re.I | re.S) for p in runtime_patterns):
    print("RUNTIME")
    raise SystemExit(30)
print("UNKNOWN")
raise SystemExit(40)
