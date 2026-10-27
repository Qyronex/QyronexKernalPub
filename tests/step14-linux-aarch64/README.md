# Step 14 unchanged Linux arm64 proof programs

These sources use only the public Linux arm64 syscall ABI: syscall number in `x8`, arguments and return value in `x0..x5`, and `svc #0`. They contain no Kernal-specific userspace ABI, capability handle, native syscall number, or private kernel entry instruction.

`src/main.rs` checks the Step-14 bootstrap surface in one single-thread Linux process:

- `getpid` (172) returns a positive ID;
- `gettid` (178) returns the same ID for the process leader;
- an unsupported syscall returns `-ENOSYS`;
- `write` (64) writes fixed messages to fd 1 and fd 2 and returns the exact byte counts;
- `exit_group` (94) terminates with status 0 and does not return.

`src/exit.rs` is a second single-thread Linux process whose only operation is `exit` (93) with status 0. This keeps the two non-returning exit paths independently observable.

Both are linked as fixed static AArch64 ELF64 executables at a normal user virtual address. The protected ARM build script compiles them with the same pinned Rust toolchain and `aarch64-unknown-none-softfloat` code generator used for the accepted Step-12 ELF artifact. After building, the produced ELF bytes are embedded unchanged into the QEMU proof; the kernel must adapt to the Linux ABI, not the programs to Kernal.
