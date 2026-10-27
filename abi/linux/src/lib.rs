// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod step29_fs;
pub use step29_fs::{
    FsCall, OPEN_HOW_V0_SIZE, OPENAT2_KNOWN_RESOLVE_MASK, OPENAT2_STEP29_SUPPORTED_RESOLVE_MASK,
    validate_open_how_v0_size, validate_openat2_resolve,
};

mod step30;
pub use step30::{
    KillSelector, SignalNumber, Step30RuntimeCall, TgkillTarget, Wait4Selector, WaitIdType,
    WaitOptions, decode_kill_selector, decode_signal_number, decode_tgkill_target,
    decode_wait4_options, decode_wait4_selector, decode_waitid_options, decode_waitid_type,
};

/// Linux exposes at most six direct syscall argument registers on the supported 64-bit ABIs.
pub const MAX_SYSCALL_ARGS: usize = 6;

/// Linux reserves return values in `-1..=-4095` for errno results.
pub const MAX_ERRNO: u16 = 4095;

/// Consume the low 32 bits of a raw syscall register as Linux `unsigned int`.
pub const fn linux_unsigned_int(raw: u64) -> u32 {
    raw as u32
}

/// Consume the low 32 bits of a raw syscall register and reinterpret them as Linux `int`.
pub const fn linux_signed_int(raw: u64) -> i32 {
    raw as u32 as i32
}

/// Reinterpret a full raw syscall register as Linux signed 64-bit `off_t`.
pub const fn linux_signed_off_t(raw: u64) -> i64 {
    raw as i64
}

/// Preserve the full raw register for Linux pointer/`size_t`/`unsigned long` arguments.
pub const fn linux_u64(raw: u64) -> u64 {
    raw
}

/// Architecture-neutral Linux syscall request.
///
/// Architecture adapters own the register convention and syscall-number table. Common syscall
/// implementations consume this value instead of depending on an AArch64/x86 trap frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallRequest {
    pub number: u64,
    pub args: [u64; MAX_SYSCALL_ARGS],
}

impl SyscallRequest {
    pub const fn new(number: u64, args: [u64; MAX_SYSCALL_ARGS]) -> Self {
        Self { number, args }
    }
}

/// Architecture-neutral Step-14 bootstrap operation selected by an architecture syscall-number
/// adapter.
///
/// This type deliberately carries only Linux-visible scalar arguments. It contains no process,
/// capability, usercopy, console or scheduler authority. Architecture adapters map their syscall
/// numbers to these operations; common semantics execute them through an explicit runtime context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapCall {
    Write {
        fd: u64,
        user_buffer: u64,
        count: u64,
    },
    Exit {
        status: u64,
    },
    ExitGroup {
        status: u64,
    },
    GetPid,
    GetTid,
}

/// Architecture-neutral Linux minimum-runtime operation selected by an architecture syscall-number
/// adapter.
///
/// The variants intentionally preserve only the raw Linux-visible scalar arguments. They do not
/// validate VM policy, dereference user pointers, read clocks, mutate futex queues, create threads
/// or install TLS. Those semantics require the explicit Process/AddressSpace/scheduler/runtime
/// authority owned by later common handlers. Keeping this type authority-free lets every
/// architecture reuse the same semantic implementations without depending on a trap frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimumRuntimeCall {
    Mmap {
        address: u64,
        length: u64,
        protection: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    },
    Munmap {
        address: u64,
        length: u64,
    },
    Mprotect {
        address: u64,
        length: u64,
        protection: u64,
    },
    Brk {
        address: u64,
    },
    ClockGettime {
        clock_id: u64,
        user_timespec: u64,
    },
    Futex {
        user_address: u64,
        operation: u64,
        value: u64,
        timeout_or_val2: u64,
        user_address2: u64,
        value3: u64,
    },
    Clone {
        flags: u64,
        child_stack: u64,
        parent_tid: u64,
        tls: u64,
        child_tid: u64,
    },
}

/// Architecture-neutral Step-29 path/file-descriptor operation accepted by the existing path/VFS
/// runtime.
///
/// This surface is intentionally kept stable. New FD-I/O calls live in [`FdIoCall`] so extending
/// the ABI does not invalidate exhaustive matches in the already accepted Step-29 path handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathFdCall {
    OpenAt {
        dirfd: u64,
        user_path: u64,
        flags: u64,
        mode: u64,
    },
    Close {
        fd: u64,
    },
    Getdents64 {
        fd: u64,
        user_buffer: u64,
        count: u64,
    },
    Read {
        fd: u64,
        user_buffer: u64,
        count: u64,
    },
    Fstat {
        fd: u64,
        user_stat: u64,
    },
    Newfstatat {
        dirfd: u64,
        user_path: u64,
        user_stat: u64,
        flags: u64,
    },
}

/// Architecture-neutral Step-29 descriptor-I/O extension selected independently from [`PathFdCall`].
///
/// Variants preserve raw Linux-visible register bits only. This type has no descriptor lookup,
/// usercopy, pipe, scheduler, signal or filesystem authority; those semantics belong to the later
/// integration owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdIoCall {
    Dup {
        oldfd: u64,
    },
    Dup3 {
        oldfd: u64,
        newfd: u64,
        flags: u64,
    },
    Fcntl {
        fd: u64,
        cmd: u64,
        arg: u64,
    },
    Pipe2 {
        user_pipefd: u64,
        flags: u64,
    },
    Lseek {
        fd: u64,
        offset: u64,
        whence: u64,
    },
    Pread64 {
        fd: u64,
        user_buffer: u64,
        count: u64,
        offset: u64,
    },
}

/// Positive Linux errno identifier.
///
/// Keeping errno positive internally makes the sign conversion explicit at the ABI return
/// boundary and prevents accidental double-negation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Errno(u16);

impl Errno {
    pub const EPERM: Self = Self(1);
    pub const ENOENT: Self = Self(2);
    pub const ESRCH: Self = Self(3);
    pub const EINTR: Self = Self(4);
    pub const EIO: Self = Self(5);
    pub const E2BIG: Self = Self(7);
    pub const ENOEXEC: Self = Self(8);
    pub const EBADF: Self = Self(9);
    pub const ECHILD: Self = Self(10);
    pub const EAGAIN: Self = Self(11);
    pub const ENOMEM: Self = Self(12);
    pub const EACCES: Self = Self(13);
    pub const EFAULT: Self = Self(14);
    pub const EBUSY: Self = Self(16);
    pub const EEXIST: Self = Self(17);
    pub const ENOTDIR: Self = Self(20);
    pub const EISDIR: Self = Self(21);
    pub const EINVAL: Self = Self(22);
    pub const ENFILE: Self = Self(23);
    pub const EMFILE: Self = Self(24);
    pub const ENOSPC: Self = Self(28);
    pub const ESPIPE: Self = Self(29);
    pub const EROFS: Self = Self(30);
    pub const EPIPE: Self = Self(32);
    pub const ENAMETOOLONG: Self = Self(36);
    pub const ENOSYS: Self = Self(38);
    pub const ELOOP: Self = Self(40);
    pub const EOVERFLOW: Self = Self(75);

    pub const fn new(value: u16) -> Option<Self> {
        if value == 0 || value > MAX_ERRNO {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Encoded Linux syscall result to be written to the architecture-defined result register.
///
/// The `-1..=-4095` range is reserved for errno. Successful construction rejects that range so a
/// common handler cannot accidentally manufacture an errno-looking result while bypassing
/// [`Errno`]. Negative values below the reserved window remain representable for Linux interfaces
/// whose successful return domain is signed.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallReturn(i64);

impl SyscallReturn {
    pub const fn success(value: i64) -> Option<Self> {
        if value < 0 && value >= -(MAX_ERRNO as i64) {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn error(errno: Errno) -> Self {
        Self(-(errno.get() as i64))
    }

    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Returns the exact two's-complement register representation used by 64-bit Linux ABIs.
    pub const fn as_u64_bits(self) -> u64 {
        self.0 as u64
    }
}

/// Canonical fallback for a syscall number with no implemented common semantic handler.
pub const fn unsupported(_request: SyscallRequest) -> SyscallReturn {
    SyscallReturn::error(Errno::ENOSYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_preserves_number_and_six_arguments() {
        let request = SyscallRequest::new(172, [1, 2, 3, 4, 5, 6]);
        assert_eq!(request.number, 172);
        assert_eq!(request.args, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn bootstrap_operations_preserve_raw_linux_arguments_without_authority() {
        let write = BootstrapCall::Write {
            fd: 2,
            user_buffer: u64::MAX - 7,
            count: u64::MAX,
        };
        match write {
            BootstrapCall::Write {
                fd,
                user_buffer,
                count,
            } => {
                assert_eq!(fd, 2);
                assert_eq!(user_buffer, u64::MAX - 7);
                assert_eq!(count, u64::MAX);
            }
            _ => panic!("write operation changed variant"),
        }

        let exit = BootstrapCall::ExitGroup { status: 0x1234 };
        assert!(matches!(exit, BootstrapCall::ExitGroup { status: 0x1234 }));
    }

    #[test]
    fn minimum_runtime_operations_preserve_raw_linux_arguments_without_authority() {
        let mmap = MinimumRuntimeCall::Mmap {
            address: 1,
            length: 2,
            protection: 3,
            flags: 4,
            fd: 5,
            offset: 6,
        };
        assert_eq!(
            mmap,
            MinimumRuntimeCall::Mmap {
                address: 1,
                length: 2,
                protection: 3,
                flags: 4,
                fd: 5,
                offset: 6,
            }
        );

        let mprotect = MinimumRuntimeCall::Mprotect {
            address: 7,
            length: 8,
            protection: 9,
        };
        assert_eq!(
            mprotect,
            MinimumRuntimeCall::Mprotect {
                address: 7,
                length: 8,
                protection: 9,
            }
        );

        let futex = MinimumRuntimeCall::Futex {
            user_address: u64::MAX,
            operation: u64::MAX - 1,
            value: u64::MAX - 2,
            timeout_or_val2: u64::MAX - 3,
            user_address2: u64::MAX - 4,
            value3: u64::MAX - 5,
        };
        assert!(matches!(
            futex,
            MinimumRuntimeCall::Futex {
                user_address: u64::MAX,
                operation,
                value,
                timeout_or_val2,
                user_address2,
                value3,
            } if operation == u64::MAX - 1
                && value == u64::MAX - 2
                && timeout_or_val2 == u64::MAX - 3
                && user_address2 == u64::MAX - 4
                && value3 == u64::MAX - 5
        ));

        let clone = MinimumRuntimeCall::Clone {
            flags: 10,
            child_stack: 11,
            parent_tid: 12,
            tls: 13,
            child_tid: 14,
        };
        assert_eq!(
            clone,
            MinimumRuntimeCall::Clone {
                flags: 10,
                child_stack: 11,
                parent_tid: 12,
                tls: 13,
                child_tid: 14,
            }
        );
    }

    #[test]
    fn path_fd_operations_preserve_raw_linux_arguments_without_authority() {
        assert_eq!(
            PathFdCall::OpenAt {
                dirfd: (-100_i64) as u64,
                user_path: 0x1000,
                flags: 0x80000,
                mode: 0o644,
            },
            PathFdCall::OpenAt {
                dirfd: (-100_i64) as u64,
                user_path: 0x1000,
                flags: 0x80000,
                mode: 0o644,
            }
        );
        assert_eq!(
            PathFdCall::Getdents64 {
                fd: 3,
                user_buffer: 0x1800,
                count: 8192,
            },
            PathFdCall::Getdents64 {
                fd: 3,
                user_buffer: 0x1800,
                count: 8192,
            }
        );
        assert!(matches!(
            PathFdCall::Read {
                fd: 3,
                user_buffer: 0x2000,
                count: 4096,
            },
            PathFdCall::Read { fd: 3, .. }
        ));
        assert!(matches!(
            PathFdCall::Newfstatat {
                dirfd: (-100_i64) as u64,
                user_path: 0x3000,
                user_stat: 0x4000,
                flags: 0,
            },
            PathFdCall::Newfstatat { flags: 0, .. }
        ));
    }

    #[test]
    fn errno_range_rejects_zero_and_values_outside_linux_error_window() {
        assert_eq!(Errno::new(0), None);
        assert_eq!(Errno::new(1), Some(Errno::EPERM));
        assert_eq!(Errno::new(Errno::ENOENT.get()), Some(Errno::ENOENT));
        assert_eq!(Errno::new(Errno::EINTR.get()), Some(Errno::EINTR));
        assert_eq!(Errno::new(Errno::EBADF.get()), Some(Errno::EBADF));
        assert_eq!(Errno::new(Errno::EAGAIN.get()), Some(Errno::EAGAIN));
        assert_eq!(Errno::new(Errno::EFAULT.get()), Some(Errno::EFAULT));
        assert_eq!(
            Errno::new(Errno::ENAMETOOLONG.get()),
            Some(Errno::ENAMETOOLONG)
        );
        assert_eq!(Errno::new(MAX_ERRNO), Some(Errno(MAX_ERRNO)));
        assert_eq!(Errno::new(MAX_ERRNO + 1), None);
    }

    #[test]
    fn errno_is_encoded_once_and_preserves_register_bits() {
        let interrupted = SyscallReturn::error(Errno::EINTR);
        let retry = SyscallReturn::error(Errno::EAGAIN);
        let invalid = SyscallReturn::error(Errno::EINVAL);
        let unsupported = SyscallReturn::error(Errno::ENOSYS);
        assert_eq!(interrupted.raw(), -4);
        assert_eq!(retry.raw(), -11);
        assert_eq!(invalid.raw(), -22);
        assert_eq!(unsupported.raw(), -38);
        assert_eq!(unsupported.as_u64_bits(), (-38_i64) as u64);
    }

    #[test]
    fn unknown_syscall_fails_closed_with_enosys() {
        let request = SyscallRequest::new(u64::MAX, [u64::MAX; MAX_SYSCALL_ARGS]);
        assert_eq!(unsupported(request), SyscallReturn::error(Errno::ENOSYS));
    }

    #[test]
    fn success_cannot_bypass_the_reserved_errno_window() {
        assert_eq!(SyscallReturn::success(0).unwrap().raw(), 0);
        assert_eq!(SyscallReturn::success(1234).unwrap().raw(), 1234);
        assert_eq!(SyscallReturn::success(-1), None);
        assert_eq!(SyscallReturn::success(-(MAX_ERRNO as i64)), None);
        assert_eq!(
            SyscallReturn::success(-(MAX_ERRNO as i64) - 1)
                .unwrap()
                .raw(),
            -(MAX_ERRNO as i64) - 1
        );
    }
}
