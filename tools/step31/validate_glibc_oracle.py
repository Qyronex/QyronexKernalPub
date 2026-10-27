#!/usr/bin/env python3
"""Validate the bounded Step-31 Debian 13 ARM64 dynamic-glibc oracle contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "docs/debian13/step31/glibc-oracle.json"
TARGET_PATH = ROOT / "docs/debian13/arm64-target.json"
CASES_PATH = ROOT / "tests/debian13/reference-cases.json"
SYSCALL_EVIDENCE_PATH = ROOT / "tests/debian13/evidence/reference-syscalls.json"

EXPECTED_AUXV = {
    "AT_PHDR": 3,
    "AT_PHENT": 4,
    "AT_PHNUM": 5,
    "AT_PAGESZ": 6,
    "AT_BASE": 7,
    "AT_ENTRY": 9,
    "AT_UID": 11,
    "AT_EUID": 12,
    "AT_GID": 13,
    "AT_EGID": 14,
    "AT_SECURE": 23,
    "AT_RANDOM": 25,
    "AT_EXECFN": 31,
}

EXPECTED_SOURCE_PATHS = {
    "reference_cases": "tests/debian13/reference-cases.json",
    "reference_syscalls": "tests/debian13/evidence/reference-syscalls.json",
    "target_manifest": "docs/debian13/arm64-target.json",
}

EXPECTED_INTERPRETER_CONTRACT = {
    "exactly_one_pt_interp_when_dynamic_interpreter_is_declared",
    "bounded_file_range",
    "nul_terminated_without_trailing_payload",
    "no_embedded_nul_path_ambiguity",
    "path_is_observed_only_during_prep",
    "runtime_resolution_is_deferred_to_step31_integration",
}

EXPECTED_ELF_IMAGE_TYPES = {"ET_EXEC", "ET_DYN"}
EXPECTED_ELF_METADATA = {
    "load_bias",
    "program_header_virtual_address",
    "program_header_entry_size",
    "program_header_entry_count",
    "entry_point",
    "interpreter_path",
}
EXPECTED_ELF_WX_POLICY = (
    "reject_any_effective_page_permission_union_containing_write_and_execute_after_"
    "page_alignment_rounding_and_overlapping_pt_loads"
)
EXPECTED_AT_BASE_SEMANTICS = "interpreter_load_bias_for_dynamic_processes_zero_when_no_interpreter"
EXPECTED_TLS = {
    "register": "TPIDR_EL0",
    "initial_thread": "dynamic_loader_may_establish_userspace_tls_before_transferring_to_program",
    "clone_tls": "clone_tls_value_must_be_generation_owned_by_the_new_thread_context",
    "context_switch": "restore_only_the_selected_live_thread_generation",
    "stale_generation": "fail_closed",
}

CRITICAL_REQUIRED_SYSCALLS = {
    "futex",
    "getrandom",
    "mmap",
    "mprotect",
    "munmap",
    "set_robust_list",
    "set_tid_address",
}


def fail(message: str) -> None:
    raise ValueError(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot load {path.relative_to(ROOT)}: {exc}")


def objects(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def find_id(value: Any, case_id: str) -> dict[str, Any] | None:
    for item in objects(value):
        if item.get("id") == case_id:
            return item
    return None


def require_unique_strings(
    values: Any,
    field: str,
    *,
    allow_empty: bool = False,
) -> set[str]:
    if (
        not isinstance(values, list)
        or (not values and not allow_empty)
        or not all(isinstance(v, str) for v in values)
    ):
        qualifier = "a string list" if allow_empty else "a non-empty string list"
        fail(f"{field} must be {qualifier}")
    result = set(values)
    if len(result) != len(values):
        fail(f"{field} contains duplicates")
    return result


def validate() -> dict[str, Any]:
    contract = load_json(CONTRACT_PATH)
    target = load_json(TARGET_PATH)
    cases = load_json(CASES_PATH)
    syscall_evidence = load_json(SYSCALL_EVIDENCE_PATH)

    if contract.get("schema_version") != 1:
        fail("unsupported Step-31 oracle schema_version")
    if contract.get("architecture") != "arm64" or target.get("architecture") != "arm64":
        fail("Step-31 oracle must remain ARM64-only")
    if contract.get("target_id") != target.get("target_id"):
        fail("Step-31 target_id drifted from the canonical Debian target")
    for label, document in (("reference cases", cases), ("syscall evidence", syscall_evidence)):
        if not isinstance(document, dict) or document.get("target_id") != contract.get("target_id"):
            fail(f"{label} target_id drifted from the Step-31 contract")

    rootfs = target.get("rootfs", {})
    immutable_url = rootfs.get("immutable_url")
    if not isinstance(immutable_url, str) or "/latest/" in immutable_url:
        fail("Debian rootfs must use an immutable non-latest URL")
    if not rootfs.get("sha512") or not rootfs.get("sha256") or not rootfs.get("size_bytes"):
        fail("Debian rootfs integrity pin is incomplete")

    evidence_provenance = syscall_evidence.get("provenance")
    if not isinstance(evidence_provenance, dict):
        fail("syscall evidence provenance must be an object")
    if set(evidence_provenance) != {"source_commit", "rootfs"}:
        fail("syscall evidence provenance fields must be exactly source_commit and rootfs")
    source_commit = evidence_provenance.get("source_commit")
    if (
        not isinstance(source_commit, str)
        or len(source_commit) != 40
        or any(char not in "0123456789abcdef" for char in source_commit)
    ):
        fail("syscall evidence source_commit must be a 40-char lowercase git SHA")
    expected_evidence_rootfs = {
        key: rootfs.get(key)
        for key in ("artifact", "size_bytes", "sha256", "sha512")
    }
    if evidence_provenance.get("rootfs") != expected_evidence_rootfs:
        fail("syscall evidence rootfs provenance drifted from the canonical Debian target")

    source_policy = contract.get("source_policy", {})
    if source_policy.get("reuse_existing_debian13_oracle") is not True:
        fail("Step-31 must reuse the existing Debian 13 oracle")
    if source_policy.get("allow_patched_debian_binaries") is not False:
        fail("patched Debian binaries are forbidden")
    for field, expected in EXPECTED_SOURCE_PATHS.items():
        if source_policy.get(field) != expected:
            fail(f"source_policy.{field} must remain pinned to {expected}")

    interp = contract.get("interpreter", {})
    interp_path = interp.get("pt_interp")
    case_id = interp.get("reference_case_id")
    if interp_path != "/lib/ld-linux-aarch64.so.1":
        fail("unexpected AArch64 PT_INTERP path")
    if not isinstance(case_id, str):
        fail("missing glibc-loader reference case id")
    interpreter_contract = require_unique_strings(interp.get("contract"), "interpreter.contract")
    if interpreter_contract != EXPECTED_INTERPRETER_CONTRACT:
        fail(
            "PT_INTERP contract drift: "
            f"expected {sorted(EXPECTED_INTERPRETER_CONTRACT)}, got {sorted(interpreter_contract)}"
        )
    case = find_id(cases, case_id)
    if case is None:
        fail(f"reference case {case_id!r} is absent")
    argv = case.get("argv")
    if not isinstance(argv, list) or not argv or argv[0] != interp_path:
        fail("canonical glibc-loader case no longer executes the pinned interpreter")
    if find_id(syscall_evidence, case_id) is None:
        fail("glibc-loader case is absent from reference syscall evidence")

    elf = contract.get("elf", {})
    image_types = require_unique_strings(elf.get("accepted_image_types"), "elf.accepted_image_types")
    if image_types != EXPECTED_ELF_IMAGE_TYPES:
        fail(f"ELF image type contract drift: expected {sorted(EXPECTED_ELF_IMAGE_TYPES)}, got {sorted(image_types)}")
    if elf.get("wx_policy") != EXPECTED_ELF_WX_POLICY:
        fail("ELF W^X policy drifted from the effective-page permission-union contract")
    elf_metadata = require_unique_strings(elf.get("required_metadata"), "elf.required_metadata")
    if elf_metadata != EXPECTED_ELF_METADATA:
        fail(f"ELF metadata contract drift: expected {sorted(EXPECTED_ELF_METADATA)}, got {sorted(elf_metadata)}")

    auxv = contract.get("auxv", {})
    auxv_entries = auxv.get("required")
    if not isinstance(auxv_entries, list):
        fail("auxv.required must be a list")
    actual_auxv: dict[str, int] = {}
    for entry in auxv_entries:
        if not isinstance(entry, dict):
            fail("auxv entry must be an object")
        name = entry.get("name")
        number = entry.get("number")
        if not isinstance(name, str) or not isinstance(number, int):
            fail("auxv entry requires string name and integer number")
        if name in actual_auxv:
            fail(f"duplicate auxv entry {name}")
        actual_auxv[name] = number
    if actual_auxv != EXPECTED_AUXV:
        fail(f"auxv contract drift: expected {EXPECTED_AUXV}, got {actual_auxv}")
    if auxv.get("at_base_semantics") != EXPECTED_AT_BASE_SEMANTICS:
        fail("AT_BASE semantics drifted from the dynamic-interpreter load-bias contract")

    at_random = auxv.get("at_random", {})
    if at_random.get("bytes") != 16 or at_random.get("fresh_per_successful_exec") is not True:
        fail("AT_RANDOM must provide 16 fresh bytes per successful exec")
    if at_random.get("all_zero_forbidden") is not True:
        fail("AT_RANDOM may not permit an all-zero payload")
    if at_random.get("userspace_pointer_must_be_readable") is not True:
        fail("AT_RANDOM must point to readable userspace storage")

    tls = contract.get("tls", {})
    for field, expected in EXPECTED_TLS.items():
        if tls.get(field) != expected:
            fail(f"tls.{field} drifted from the pinned AArch64 TLS ownership contract")

    pthread_required = require_unique_strings(
        contract.get("pthread", {}).get("required_kernel_contracts"),
        "pthread.required_kernel_contracts",
    )
    for required in {
        "set_tid_address",
        "set_robust_list",
        "futex_wait_wake",
        "thread_exit_clear_tid_and_wake",
    }:
        if required not in pthread_required:
            fail(f"missing pthread bootstrap contract {required}")

    syscall_contract = contract.get("syscalls", {})
    reference_case_ids = require_unique_strings(
        syscall_contract.get("reference_case_ids"),
        "syscalls.reference_case_ids",
    )
    required_syscalls = require_unique_strings(
        syscall_contract.get("required_for_reference_bootstrap"),
        "syscalls.required_for_reference_bootstrap",
    )
    declared_unobserved = require_unique_strings(
        syscall_contract.get("required_but_unobserved_in_reference_cases"),
        "syscalls.required_but_unobserved_in_reference_cases",
        allow_empty=True,
    )
    optional_syscalls = require_unique_strings(
        syscall_contract.get("optional_with_enosys_fallback"),
        "syscalls.optional_with_enosys_fallback",
    )

    overlap = required_syscalls & optional_syscalls
    if overlap:
        fail(f"syscall classification overlap: {sorted(overlap)}")
    if not declared_unobserved <= required_syscalls:
        fail("declared unobserved syscalls must remain a subset of required syscalls")
    for required in CRITICAL_REQUIRED_SYSCALLS:
        if required not in required_syscalls:
            fail(f"missing required glibc bootstrap syscall {required}")
    if "rseq" not in optional_syscalls:
        fail("rseq fallback policy must be explicit")

    observed_syscalls: set[str] = set()
    for reference_case_id in reference_case_ids:
        if find_id(cases, reference_case_id) is None:
            fail(f"syscall reference case {reference_case_id!r} is absent from canonical cases")
        evidence_case = find_id(syscall_evidence, reference_case_id)
        if evidence_case is None:
            fail(f"syscall reference case {reference_case_id!r} has no pinned evidence")
        observed_syscalls.update(
            require_unique_strings(
                evidence_case.get("syscalls"),
                f"syscall evidence for {reference_case_id}",
            )
        )

    missing_required = required_syscalls - observed_syscalls
    if missing_required != declared_unobserved:
        fail(
            "required bootstrap evidence gap drift: "
            f"declared {sorted(declared_unobserved)}, observed gap {sorted(missing_required)}"
        )
    missing_optional = optional_syscalls - observed_syscalls
    if missing_optional:
        fail(f"optional fallback syscalls lack pinned probe evidence: {sorted(missing_optional)}")

    policy = syscall_contract.get("policy", {})
    if policy.get("unknown_required_syscall") != "fail_closed_and_report_oracle_delta":
        fail("unknown required syscalls must fail closed and report oracle drift")
    if policy.get("optional_syscall") != "ENOSYS_only_when_glibc_has_a_defined_fallback":
        fail("optional syscall fallback must remain explicit ENOSYS-only")
    if policy.get("fake_success") is not False or policy.get("process_name_special_cases") is not False:
        fail("fake success and process-name special cases are forbidden")

    boundary = contract.get("acceptance_boundary", {})
    if boundary.get("prep_is_milestone_acceptance") is not False:
        fail("Step-31 PREP may not claim milestone acceptance")
    if boundary.get("step31_final_integration_requires_step30_accepted_and_merged") is not True:
        fail("Step-31 final integration must stay blocked on Step 30")
    if boundary.get("final_step31_evidence_must_use_one_exact_frozen_sha") is not True:
        fail("final Step-31 evidence must stay tied to one exact frozen SHA")

    return {
        "status": "ok",
        "target_id": contract["target_id"],
        "interpreter": interp_path,
        "reference_case": case_id,
        "evidence_source_commit": source_commit,
        "syscall_reference_cases": len(reference_case_ids),
        "observed_syscalls": len(observed_syscalls),
        "auxv_entries": len(actual_auxv),
        "required_syscalls": len(required_syscalls),
        "declared_unobserved_required_syscalls": len(declared_unobserved),
        "optional_syscalls": len(optional_syscalls),
    }


def main() -> int:
    try:
        result = validate()
    except ValueError as exc:
        print(f"step31 glibc oracle invalid: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
