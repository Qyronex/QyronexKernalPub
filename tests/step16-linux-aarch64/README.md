# Step 16 unchanged Linux AArch64 program proof

Step 16 deliberately does **not** introduce a new Kernal-specific userspace program. It reuses the
already accepted unchanged Linux/POSIX fixture at:

`tests/step15-linux-aarch64/pthread_minimum.c`

That source remains an ordinary static-musl program with no inline `svc`, Kernal ABI shim, custom
startup assembly, or bare-metal runtime. Keeping one source file prevents Step 16 from silently
forking a weaker test artifact after Step 15 has already accepted the real libc/pthread path.

The reproducible userspace build remains:

```sh
aarch64-linux-musl-gcc -O2 -static -pthread -std=c11 -Wall -Wextra -Werror \
  -o pthread_minimum tests/step15-linux-aarch64/pthread_minimum.c
```

The canonical Step-16 proof command is:

```sh
cargo run --locked -p xtask --bin arm-qemu-step16
```

It performs independent 1-, 2- and 4-vCPU AArch64 QEMU boots through the same protected initrd,
canonical Linux ELF loader, Process/AddressSpace, EL0/SVC, VM, pthread/futex, write and exit owners
accepted in Step 15. Every boot must exit normally, contain exactly one unchanged userspace success
marker:

```text
KERNAL/S15: unchanged musl pthread minimum passed
```

and additionally prove the normal production path. Stable ownership/teardown diagnostics for initial
Linux leader publication, TTBR0 activation, validated `write(64)` return, final Linux TTBR0
deactivation, proof-carrying `exit_group(0)` finalization and full Linux Process teardown must each
appear exactly once. Normal VM progress through `brk(0)` and anonymous `mmap` must be observed at
least once; ordinary libc is allowed to issue those syscalls more than once.

The Step-15 marker is intentionally retained because changing it would modify the accepted userspace
program merely to rename a milestone. Step 16 is a stronger proof of the same unchanged artifact, not
a new program.
