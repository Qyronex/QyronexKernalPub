#!/usr/bin/env python3
"""Validate the Step 32 Debian reference transport handoff contract.

This is PREP-only validation. It pins the archive payload, exact source-SHA
handoff, guest invocation and returned evidence shape without modifying the
shared Debian launcher or claiming runtime/reference execution.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "tests/qemu-prep/step32/reference_transport_contract.json"
TARGET = ROOT / "docs/debian13/arm64-target.json"
COLLECTOR = ROOT / "tools/qemu-prep/step32/collect_tty_reference.sh"
NORMALIZER = ROOT / "tools/qemu-prep/step32/normalize_tty_reference.py"
VERIFIER = ROOT / "tools/qemu-prep/step32/verify_tty_reference_evidence.py"

EXPECTED_ARCHIVE_PATHS = [
    "docs/debian13/arm64-target.json",
    "tests/qemu-prep/step32/pty_probe.c",
    "tools/qemu-prep/step32/build_run_pty_probe.sh",
    "tools/qemu-prep/step32/collect_tty_reference.sh",
    "tools/qemu-prep/step32/normalize_tty_reference.py",
]
EXPECTED_ENVIRONMENT = {
    "KERNAL_STEP32_SOURCE_COMMIT": "<exact-40-hex-source-sha>",
    "KERNAL_STEP32_REFERENCE_OUT": "/tmp/kernal-step32-tty-reference.raw",
    "KERNAL_STEP32_REFERENCE_JSON": "/tmp/kernal-step32-tty-reference.json",
}
EXPECTED_PROVENANCE = {
    "schema",
    "collected_at",
    "os_id",
    "os_version_id",
    "architecture",
    "kernel_release",
    "source_commit",
    "target_sha256",
    "raw_sha256",
    "compiler",
}


def fail(message: str) -> int:
    print(f"step32-reference-transport: FAIL: {message}", file=sys.stderr)
    return 1


def load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    try:
        contract = load_object(CONTRACT)
        target = load_object(TARGET)

        require(contract.get("schema") == "kernal-step32-reference-transport-v1", "invalid contract schema")
        require(contract.get("step") == 32, "contract step must be 32")
        require(contract.get("state") == "PREP_IN_PROGRESS", "transport contract must remain PREP_IN_PROGRESS")
        require(contract.get("runtime_authority") == "none", "transport PREP must not claim runtime authority")
        require(contract.get("archive_mode") == "git-archive-no-dotgit", "archive mode must pin the no-.git guest")
        require(contract.get("target_id") == target.get("target_id"), "contract target_id does not match pinned target")
        require(target.get("architecture") == "arm64", "pinned target must remain arm64")
        require(contract.get("architecture") == "arm64", "transport architecture must remain arm64")

        paths = contract.get("archive_required_paths")
        require(paths == EXPECTED_ARCHIVE_PATHS, "archive payload path set/order drifted")
        for relative in EXPECTED_ARCHIVE_PATHS:
            path = ROOT / relative
            require(path.is_file() and path.stat().st_size > 0, f"required archive input missing/empty: {relative}")
            require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, f"unsafe archive path: {relative}")
            if relative != "docs/debian13/arm64-target.json":
                require(
                    relative.startswith(("docs/debian13/qemu-prep/step32/", "tools/qemu-prep/step32/", "tests/qemu-prep/step32/")),
                    f"Step32 transport input escaped the declared PREP scope: {relative}",
                )

        source = contract.get("source_commit")
        require(isinstance(source, dict), "source_commit contract must be an object")
        require(source.get("environment") == "KERNAL_STEP32_SOURCE_COMMIT", "source commit environment drifted")
        require(source.get("format") == "full-lowercase-40-hex", "source commit format drifted")
        require(source.get("required") is True, "source commit handoff must be required")
        require(source.get("guest_git_metadata_required") is False, "git archive guest must not require .git metadata")

        guest = contract.get("guest_invocation")
        require(isinstance(guest, dict), "guest_invocation must be an object")
        require(guest.get("working_directory") == "archive-root", "guest working directory drifted")
        require(
            guest.get("argv") == ["bash", "tools/qemu-prep/step32/collect_tty_reference.sh"],
            "guest collector invocation drifted",
        )
        require(guest.get("environment") == EXPECTED_ENVIRONMENT, "guest environment handoff drifted")

        returned = contract.get("return_artifacts")
        require(
            returned
            == [
                {"kind": "raw", "path": EXPECTED_ENVIRONMENT["KERNAL_STEP32_REFERENCE_OUT"]},
                {"kind": "normalized", "path": EXPECTED_ENVIRONMENT["KERNAL_STEP32_REFERENCE_JSON"]},
            ],
            "returned raw/normalized artifact contract drifted",
        )

        host_verification = contract.get("host_verification")
        require(isinstance(host_verification, dict), "host_verification must be an object")
        require(
            host_verification.get("argv")
            == [
                "python3",
                "-B",
                "tools/qemu-prep/step32/verify_tty_reference_evidence.py",
                "<returned-raw-artifact>",
                "<returned-normalized-artifact>",
                "<exact-40-hex-source-sha>",
            ],
            "host evidence verifier argv drifted",
        )
        require(
            host_verification.get("success_marker") == "STEP32_REFERENCE_EVIDENCE_OK",
            "host evidence verifier success marker drifted",
        )
        require(host_verification.get("required") is True, "host evidence verification must remain required")
        require(VERIFIER.is_file() and VERIFIER.stat().st_size > 0, "host evidence verifier missing/empty")

        normalized = contract.get("normalized_evidence")
        require(isinstance(normalized, dict), "normalized_evidence must be an object")
        require(
            normalized.get("schema") == "kernal-step32-debian13-tty-reference-v1",
            "normalized evidence schema drifted",
        )
        sections = normalized.get("required_sections")
        require(
            isinstance(sections, list)
            and set(sections) == {"provenance", "termios", "winsize", "devices", "entropy", "pty"},
            "normalized evidence section contract drifted",
        )
        fields = normalized.get("required_provenance_fields")
        require(
            isinstance(fields, list) and set(fields) == EXPECTED_PROVENANCE,
            "normalized provenance fields drifted",
        )

        collector = COLLECTOR.read_text(encoding="utf-8")
        for fragment in (
            "KERNAL_STEP32_SOURCE_COMMIT",
            "KERNAL_STEP32_REFERENCE_OUT",
            "KERNAL_STEP32_REFERENCE_JSON",
            "explicit source commit does not match checked-out HEAD",
            "source commit identity must be a full 40-character lowercase git SHA",
        ):
            require(fragment in collector, f"collector no longer implements transport contract fragment: {fragment}")

        normalizer = NORMALIZER.read_text(encoding="utf-8")
        require(
            '"schema": "kernal-step32-debian13-tty-reference-v1"' in normalizer,
            "normalizer evidence schema drifted",
        )
        for key in ("raw_sha256", "source_commit", "target_sha256", "devices", "entropy", "pty"):
            require(f'"{key}"' in normalizer, f"normalizer no longer emits required field/section: {key}")

        verifier = VERIFIER.read_text(encoding="utf-8")
        for fragment in (
            "normalized == recomputed",
            "provenance.get(\"source_commit\") == expected_source_commit",
            "provenance.get(\"target_sha256\") == target_sha256",
            "provenance.get(\"raw_sha256\") == raw_sha256",
            "STEP32_REFERENCE_EVIDENCE_OK",
        ):
            require(fragment in verifier, f"host evidence verifier contract drifted: {fragment}")

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return fail(str(exc))

    print(
        "STEP32_REFERENCE_TRANSPORT_CONTRACT_OK "
        "target=debian-13-trixie-arm64-20260712-2537 archive_inputs=5 return_artifacts=2 host_verifier=required"
    )
    print("step32-reference-transport: NOTE: contract validation only; real pinned Debian guest evidence is still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
