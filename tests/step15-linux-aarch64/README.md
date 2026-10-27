# Step 15 Linux AArch64 musl acceptance fixture

`pthread_minimum.c` is intentionally an ordinary Linux/POSIX libc program. It contains no inline
syscalls, Kernal-specific ABI shims, custom startup assembly, or bare-metal runtime. The acceptance
artifact must be built as a static AArch64 Linux executable against musl and loaded through the
normal Linux ELF/initial-stack path.

A representative build command is:

```sh
aarch64-linux-musl-gcc -O2 -static -pthread -std=c11 -Wall -Wextra -Werror \
  -o pthread_minimum pthread_minimum.c
```

The test deliberately sets the pthread guard size to zero. This keeps Step 15 scoped to the accepted
minimum VM contract and avoids turning `mprotect` into an accidental prerequisite of the verifier.
The program still exercises libc `brk`, anonymous `mmap`/`munmap`, `clock_gettime`, one joinable
`pthread_create`, generation-distinct TLS state, and `pthread_join`/futex synchronization. Normal
musl startup/thread machinery remains unchanged, including its own clone/TLS/TID/clear-child-tid
behavior.

Acceptance is valid only when QEMU boots the Kernal AArch64 image, the kernel loads this Linux/musl
ELF through the production loader, the process exits with status 0, and the console contains exactly
this success marker from the userspace program:

```text
KERNAL/S15: unchanged musl pthread minimum passed
```

Do not replace this fixture with direct `svc` instructions, a freestanding `aarch64-unknown-none`
program, or a kernel-internal simulation of pthread behavior. Such probes are useful unit/integration
tests but do not satisfy the Step-15 unchanged-musl acceptance requirement.
