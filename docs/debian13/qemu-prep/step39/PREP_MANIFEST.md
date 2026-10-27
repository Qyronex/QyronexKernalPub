# PREP manifest — Step 39

Status: `PREP_IN_PROGRESS`

## Runtime target

Close the Debian 13 ARM64 package-manager contracts required for ordinary `dpkg`/`apt` operation on the pinned QEMU server profile.

## Dependency release condition

Runtime integration starts only after Step 38 is accepted and explicitly released.

## Prepared artifacts

- `tests/qemu-prep/step39/package_transaction_plan.json` — dpkg configure, apt update/install/remove and failure-injection plan on disposable overlays.
- `tools/qemu-prep/step39/pin_package.py` — extracts exact package/version/file/size/hash metadata from a `Packages` index obtained from the pinned Debian snapshot.
- `tools/qemu-prep/create_verified_overlay.py` — ensures every package transaction runs on a verified COW copy, never the pinned base.
- Existing `dpkg --version` / `apt-get --version` traces supply shallow library/path/syscall requirements but are explicitly not transaction evidence.

## Still to collect before PREP_READY

- exact `hello` (or owner-selected ordinary package) version, architecture, file and hash from the pinned snapshot;
- full reference `dpkg --configure -a`, `apt-get update`, install and remove traces;
- actual flock/fcntl lock behavior and contention;
- exact fsync/fdatasync/syncfs/rename/truncate/mmap requirements observed during real transactions;
- xattr/ACL and certificate/time/entropy requirements only where observed;
- failure-injection outcomes defining the selected filesystem's real durability boundary.

## Prep focus

- pin one package configure/install/remove/update corpus;
- reference traces for flock/fcntl locking and contention;
- fsync/fdatasync/syncfs + rename/truncate durability expectations;
- mmap/truncate interaction probes;
- ownership/mode/timestamp/xattr/ACL subset actually used by the corpus;
- shebang/interpreter execution probes;
- apt transport prerequisites for clock, entropy, DNS, TCP and certificate handling;
- failure-injection cases around dpkg database updates.

## Canonical owners to consume

Canonical FD/OFD locking state, VFS/filesystem durability owner, VM/mmap owner, Step-30 exec, Step-31 dynamic loader, Step-34 network, time and entropy owners.

## Forbidden duplicates

No package-specific kernel exceptions, second locking database, fake durability acknowledgements, second executable resolver, or apt-specific network path.

## Integration landing order

1. package-manager trace oracle;
2. advisory/file locking;
3. durability contracts;
4. metadata/xattr/ACL subset actually observed;
5. interpreter/shebang closure;
6. apt transport prerequisites;
7. failure injection;
8. dpkg/apt QEMU acceptance.

## Acceptance probes

`dpkg --configure` on documented package set; `apt update` against pinned snapshot; install/remove one exact ordinary package; lock contention; consistent dpkg database after selected process-failure cases.

## Handoff freshness

Stale if pinned Debian repository/package set, VFS/filesystem durability, FD/OFD, VM, exec/loader, network, time or entropy interfaces change incompatibly.