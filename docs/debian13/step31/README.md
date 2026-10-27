# Step 31 Debian 13 ARM64 dynamic-glibc oracle prep

This directory records the bounded Step-31 preparation contract that may run while Step 30.7 closes. It does not grant ownership of the shared runtime and it is not Step-31 milestone acceptance evidence.

## Pinned reference

The oracle reuses the repository's existing Debian 13 ARM64 target manifest and evidence corpus. The pinned target is `debian-13-trixie-arm64-20260712-2537`; no `latest` image, locally patched Debian binary, or process-name compatibility path is permitted.

The canonical interpreter observation is the existing `component.glibc-loader.help` case using:

`/lib/ld-linux-aarch64.so.1 --help`

`glibc-oracle.json` adds the Step-31-specific contract around that evidence. It does not create another rootfs, collector, ELF loader, VFS resolver, address-space owner, or syscall oracle.

## Contract surface

The prep contract pins:

- bounded, unambiguous `PT_INTERP` observation for the AArch64 glibc loader;
- ET_EXEC/ET_DYN metadata required by the later runtime composition;
- fail-closed W^X at effective page granularity: after page alignment/rounding and across overlapping `PT_LOAD` mappings, no page permission union may contain both WRITE and EXECUTE;
- the auxv entries required to compose the main executable and interpreter, including `AT_BASE` and a 16-byte fresh `AT_RANDOM` payload;
- generation-owned `TPIDR_EL0`/clone-TLS expectations;
- pthread bootstrap dependencies (`set_tid_address`, robust-list, futex, clear-tid wake);
- required versus optional syscall behavior without fake-success fallbacks.

The current three syscall reference cases exercise every syscall declared in `required_for_reference_bootstrap`, including `futex`, so `required_but_unobserved_in_reference_cases` is intentionally empty. The validator requires exact equality between the actual missing-required set and that declaration: any future required syscall that is not observed fails closed until the evidence or contract is updated, and any stale non-empty gap declaration also fails once the pinned evidence covers it. Final pthread/futex runtime proof remains part of Step-31 integration after Step 30.7.

The runtime owner must still perform interpreter path resolution, mapping, load-bias selection, final auxv construction, TLS handoff, and syscall integration after Step 30.7 is accepted and merged.

## Validation

Run:

```text
python3 tools/step31/validate_glibc_oracle.py
```

The validator fails closed if the Step-31 contract drifts from the pinned Debian target, if the canonical glibc-loader case disappears or changes path, if the effective page-level W^X policy is weakened, if auxv numbers are inconsistent, if required and optional syscall classifications overlap, if observed syscall evidence drifts from the explicitly declared evidence gap, or if the policy permits patched binaries/fake success.

The lane's required frozen-SHA gate sequence remains:

`fmt-check -> workspace-test -> strict clippy -> arm-build`

Passing those PREP gates only proves that this bounded preparation branch is internally consistent. Final Step-31 QEMU acceptance is released only after Step 30.7 is accepted and merged and the integrator reconciles the prep lanes onto that accepted source.
