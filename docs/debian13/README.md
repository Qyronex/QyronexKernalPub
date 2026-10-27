# Debian 13 ARM64 compatibility oracle

This directory is the machine-reviewed compatibility boundary for the first Debian 13 ARM64 server target. The public compatibility roadmap is tracked in `DEBIAN_13_COMPATIBILITY_ROADMAP.md`; the active runtime target is AArch64.

## Pinned target

`arm64-target.json` pins one immutable Debian 13 (Trixie) ARM64 cloud image and exact Debian snapshot repository timestamps. The image is **not** stored in Git.

Pinned image:

- build: `20260712-2537`
- artifact: `debian-13-generic-arm64-20260712-2537.qcow2`
- Debian-published SHA-512: `3be884e19878b307a5916eb59be17efb7f1a5ec8290f2253345640f0a8740082fd40cfb7a7940b56cca0a76289ecd448507011cfd1b17472c9998d90f44b5c2c`
- independently derived and pinned SHA-256: `7e556159a995fa4634e2ea52228ec7a4226193e2d1a87e2c7158e4c6d53ed5fe`

The image URL and Debian `SHA512SUMS` manifest URL are versioned. `/latest/` is forbidden. The SHA-256 is an independent local pin over the artifact that already matched Debian's published SHA-512; the oracle does not invent or depend on a second Debian cloud checksum-manifest URL. Replacing the build, repository timestamp or any cryptographic identity requires a new `target_id`; do not silently retarget an accepted ID.

Fetch into the external cache. The fetcher requires the artifact's entry in Debian's versioned `SHA512SUMS` to equal the repository pin, then recomputes the exact byte size, SHA-512 and independently pinned SHA-256 locally:

```bash
bash tools/debian13/fetch-pinned-arm64.sh
```

The default cache is `~/.cache/kernal/debian13`. Override it with `KERNAL_DEBIAN13_CACHE`. Downloaded Debian images and package/rootfs payloads must stay out of Git history.

## Validate manifests and host tooling

```bash
python3 tools/debian13/oracle.py validate
python3 -m unittest discover -s tests/debian13 -p 'test_*.py' -v
bash -n \
  tools/debian13/fetch-pinned-arm64.sh \
  tools/debian13/prepare-reference.sh \
  tools/debian13/run-reference-qemu-macos.sh
```

Validation rejects unversioned image URLs, malformed hashes, non-ARM64 targets, floating repository URLs, missing/duplicate representative Debian components, invalid trace states, unknown compatibility states and proven rows without evidence. The regression suite also protects the Apple-Silicon host launcher from Bash-4-only helpers so it remains runnable by the macOS system `/bin/bash`.

## Compatibility states

The machine-readable matrix uses only:

- `SUPPORTED_PROVEN` — executable evidence exists for the exact semantic contract;
- `SUPPORTED_UNVERIFIED` — an implementation exists but the pinned Debian corpus has not proved it;
- `PARTIAL` — only a narrower subset is implemented/proven;
- `ENOSYS_UNSUPPORTED` — unsupported behavior is explicit and an expected Linux error is recorded;
- `NOT_REQUIRED` — the pinned target corpus proved the operation unnecessary for the bounded milestone.

An unknown operation defaults to `ENOSYS_UNSUPPORTED` / `ENOSYS`. The matrix must never use optimistic success as a placeholder.

## Reference corpus: real Debian execution only

`tests/debian13/reference-cases.json` contains bounded probes for every representative component plus deterministic functional probes for `/proc`, `/sys`, `/dev`, ordinary filesystem paths, a TTY ioctl attempt and iproute2's loopback/netlink path. These probes discover requirements; they do not authorize Step-28+ implementation.

The corpus must be collected **inside the verified Debian 13 ARM64 reference guest**, never synthesized on macOS and never copied from documentation.

### Automated Apple-Silicon reference guest

On an Apple-Silicon Mac with Homebrew QEMU installed, the canonical collection path is:

```bash
bash tools/debian13/run-reference-qemu-macos.sh
```

The host launcher:

1. requires macOS/arm64 and a clean exact-source worktree;
2. records the full 40-character source commit before collection;
3. downloads only the pinned image into the external cache, verifies Debian's versioned SHA-512 manifest entry, then rechecks the exact local byte size plus pinned SHA-512 and independently derived SHA-256;
4. creates a temporary copy-on-write qcow2 overlay, locates the AArch64 EDK2 firmware shipped with QEMU, and exposes only the exact `docs/debian13`, `tests/debian13` and `tools/debian13` subtree to the guest through the bounded NoCloud transfer path — no `.git`, credentials or unrelated working-tree data;
5. boots the verified Debian 13 ARM64 guest with QEMU/HVF;
6. runs `prepare-reference.sh` and `collect-reference.py` inside that guest;
7. retrieves the two evidence files and rejects them unless both name the exact source commit and exact pinned rootfs artifact/size/hashes used for the run.

The image cache defaults to `~/.cache/kernal/debian13`. Evidence output defaults to `tests/debian13/evidence` and can be redirected with `KERNAL_DEBIAN13_REFERENCE_OUTPUT`. The default runtime budget is intentionally bounded to 35 minutes total: 600 seconds for the pinned image fetch, 1200 seconds for the QEMU guest collection, and 300 seconds of outer-watchdog reserve. Override those with `KERNAL_DEBIAN13_REFERENCE_FETCH_TIMEOUT_SECONDS`, `KERNAL_DEBIAN13_REFERENCE_TIMEOUT_SECONDS`, and `KERNAL_DEBIAN13_REFERENCE_TOTAL_TIMEOUT_SECONDS`. Progress is reported every 60 seconds by default and can be adjusted with `KERNAL_DEBIAN13_REFERENCE_PROGRESS_INTERVAL_SECONDS` (minimum 15 seconds). Persistent host/QEMU/server diagnostics are written under `~/.cache/kernal/debian13/logs/<run-id>/` by default; redirect them with `KERNAL_DEBIAN13_REFERENCE_LOG_DIR`.

The automation is transport only: the evidence remains valid only for the exact target ID, pinned rootfs identity and exact source head whose bounded subtree was archived into the guest.

### Manual guest fallback

If the automated host launcher is unavailable, boot a copy-on-write instance of the verified image, place the bounded repository checkout in the guest, and pass the exact full source SHA explicitly:

```bash
SOURCE_COMMIT=$(git rev-parse HEAD)
sudo bash tools/debian13/prepare-reference.sh
python3 tools/debian13/collect-reference.py \
  --source-commit "$SOURCE_COMMIT" \
  --observation reference-debian.json \
  --inventory reference-syscalls.json
```

`prepare-reference.sh` refuses non-Debian-13/non-arm64 guests, ignores all pre-existing apt sources, and uses only the exact Debian/debian-security snapshot URLs from `arm64-target.json`. Signed Debian archive metadata is required through the system archive keyring. It installs only the bounded probe packages and `strace`.

`collect-reference.py` independently rechecks Debian 13/Trixie/arm64 and `dpkg --print-architecture=arm64`, requires all probe executables, validates every component against the matrix, runs each probe under a fixed locale/timezone/PATH, hashes stdout/stderr, records exit/signal state and exact installed package versions, and reduces raw strace output to normalized, reviewable requirement categories. PID/address/timing data and raw trace logs are deliberately discarded.

The generated inventory keeps `syscalls` for existing consumers and also records explicit per-case and aggregate categories:

- syscall names;
- ioctl request names/numbers visible in strace;
- all absolute paths plus `/proc`, `/sys`, `/dev` and ordinary filesystem subsets;
- socket families, types and protocols;
- networking-related syscall names.

Every category is present as an array even when nothing was observed; absence is never silently conflated with an empty observation. Both evidence documents also carry exact source/rootfs provenance.

The two generated files are evidence candidates:

- `reference-debian.json` — externally observable outcomes used by the semantic comparator;
- `reference-syscalls.json` — package/reference provenance plus normalized requirement discovery.

A schema or probe change invalidates older generated evidence. Re-run the pinned guest collector on the new exact head before treating the branch as acceptance-ready. Do not change a component's reviewed trace state merely because a collector exists; trace-state promotion still requires a real reviewed corpus from the pinned guest.

## Observation comparison

Reference Debian/Linux and Kernal use the same bounded outcome fields: return value, errno, signal, process exit status, stdout/stderr SHA-256 digests, file metadata and socket behavior. Adding another observable requires an oracle schema change rather than an ad-hoc parser.

Compare collected reference and Kernal observations with:

```bash
python3 tools/debian13/oracle.py compare reference-debian.json kernal.json --output report.json
```

The reference document must identify `environment=reference-debian`; the Kernal document must identify `environment=kernal`. Swapping them fails validation. The command returns non-zero when a case is missing or any observed value differs. A known compatibility gap therefore remains visible until implementation and evidence agree; the comparator does not auto-forgive `ENOSYS`.

## Requirement inventory

The generated inventory is requirement input, not an implementation request by itself. For every observed syscall/ioctl/proc/sys/device/filesystem/network dependency:

1. map it to an existing Kernal owner if one exists;
2. keep already-proven Step-15/16 semantics rather than recreating them;
3. classify unsupported operations explicitly;
4. implement compatibility work in dependency order according to `DEBIAN_13_COMPATIBILITY_ROADMAP.md`.

Keep compatibility-oracle tooling separate from kernel runtime implementation.

## Security / provenance rules

- Never execute or mount a downloaded rootfs before Debian's pinned SHA-512 manifest entry, exact size and both local digests verify.
- Require signed Debian `InRelease` metadata from exact snapshot URLs when packages are retrieved.
- Bind evidence to the exact source commit and pinned rootfs artifact/size/hashes.
- Never use package/process names to special-case Kernal behavior.
- Never commit downloaded Debian images, packages or raw trace logs.
- Keep unsupported operations explicit and fail closed.
- Do not weaken W^X, null-page, capability, memory ownership, IRQ/DMA or lifecycle invariants for Debian compatibility.
