// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod signal_entry;
pub use signal_entry::*;
mod signal_frame;
pub use signal_frame::*;
mod signal_frame_minimal;
pub use signal_frame_minimal::*;
mod signal_siginfo;
pub use signal_siginfo::*;

mod step29_fs;
pub use step29_fs::{classify_fs, fs_nr};

mod step30;
pub use step30::{
    KERNEL_SIGACTION_BYTES, KERNEL_SIGSET_BYTES, KernelSigaction, SigmaskHow,
    classify_step30_runtime, decode_sigmask_how, nr as step30_nr, valid_rt_sigset_size,
};

mod waitid_siginfo;
pub use waitid_siginfo::{KERNEL_SIGINFO_BYTES, WaitIdSiginfo};

use kernal_linux_abi::{
    BootstrapCall, FdIoCall, MAX_SYSCALL_ARGS, MinimumRuntimeCall, PathFdCall, SyscallRequest,
    SyscallReturn,
};

/// Linux arm64 uses x8 for the syscall number, x0..x5 for arguments and x0 for the result.
pub const SYSCALL_NUMBER_REGISTER: usize = 8;
pub const RESULT_REGISTER: usize = 0;

/// Stable Linux arm64 syscall-number anchors used by ABI tests and the immediate successor steps.
/// Declaring a number here does not claim semantic syscall support.
pub mod nr {
    pub const DUP: u64 = 23;
    pub const DUP3: u64 = 24;
    pub const FCNTL: u64 = 25;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const PIPE2: u64 = 59;
    pub const GETDENTS64: u64 = 61;
    pub const LSEEK: u64 = 62;
    pub const READ: u64 = 63;
    pub const WRITE: u64 = 64;
    pub const PREAD64: u64 = 67;
    pub const NEWFSTATAT: u64 = 79;
    pub const FSTAT: u64 = 80;
    pub const EXIT: u64 = 93;
    pub const EXIT_GROUP: u64 = 94;
    pub const FUTEX: u64 = 98;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const GETPID: u64 = 172;
    pub const GETTID: u64 = 178;
    pub const BRK: u64 = 214;
    pub const MUNMAP: u64 = 215;
    pub const CLONE: u64 = 220;
    pub const EXECVE: u64 = 221;
    pub const MMAP: u64 = 222;
    pub const MPROTECT: u64 = 226;
}

/// Decode only the Linux arm64 register convention from an already captured EL0 register frame.
/// SVC/ESR classification remains owned by the accepted Step-9 AArch64 exception transport.
pub fn decode_registers(registers: &[u64; 31]) -> SyscallRequest {
    let mut args = [0; MAX_SYSCALL_ARGS];
    args.copy_from_slice(&registers[..MAX_SYSCALL_ARGS]);
    SyscallRequest::new(registers[SYSCALL_NUMBER_REGISTER], args)
}

/// Classifies only the Step-14 Linux arm64 bootstrap syscall-number set.
///
/// Unknown numbers deliberately return `None`; callers retain the original [`SyscallRequest`] and
/// must route it through the shared common `unsupported() -> -ENOSYS` fallback. This adapter owns
/// only arm64 number/argument mapping and contains no I/O, identity or lifecycle semantics.
pub fn classify_bootstrap(request: SyscallRequest) -> Option<BootstrapCall> {
    match request.number {
        nr::WRITE => Some(BootstrapCall::Write {
            fd: request.args[0],
            user_buffer: request.args[1],
            count: request.args[2],
        }),
        nr::EXIT => Some(BootstrapCall::Exit {
            status: request.args[0],
        }),
        nr::EXIT_GROUP => Some(BootstrapCall::ExitGroup {
            status: request.args[0],
        }),
        nr::GETPID => Some(BootstrapCall::GetPid),
        nr::GETTID => Some(BootstrapCall::GetTid),
        _ => None,
    }
}

/// Classifies the Linux arm64 minimum memory/time/thread syscall-number set into the common,
/// authority-free scalar call contract.
///
/// This function performs no validation and no privileged operation. VM flags, user pointers,
/// clock IDs, futex operations and clone flags remain raw Linux-visible values for common semantic
/// handlers to validate using the current Process/AddressSpace/scheduler/runtime authority.
pub fn classify_minimum_runtime(request: SyscallRequest) -> Option<MinimumRuntimeCall> {
    match request.number {
        nr::MMAP => Some(MinimumRuntimeCall::Mmap {
            address: request.args[0],
            length: request.args[1],
            protection: request.args[2],
            flags: request.args[3],
            fd: request.args[4],
            offset: request.args[5],
        }),
        nr::MUNMAP => Some(MinimumRuntimeCall::Munmap {
            address: request.args[0],
            length: request.args[1],
        }),
        nr::MPROTECT => Some(MinimumRuntimeCall::Mprotect {
            address: request.args[0],
            length: request.args[1],
            protection: request.args[2],
        }),
        nr::BRK => Some(MinimumRuntimeCall::Brk {
            address: request.args[0],
        }),
        nr::CLOCK_GETTIME => Some(MinimumRuntimeCall::ClockGettime {
            clock_id: request.args[0],
            user_timespec: request.args[1],
        }),
        nr::FUTEX => Some(MinimumRuntimeCall::Futex {
            user_address: request.args[0],
            operation: request.args[1],
            value: request.args[2],
            timeout_or_val2: request.args[3],
            user_address2: request.args[4],
            value3: request.args[5],
        }),
        nr::CLONE => Some(MinimumRuntimeCall::Clone {
            flags: request.args[0],
            child_stack: request.args[1],
            parent_tid: request.args[2],
            tls: request.args[3],
            child_tid: request.args[4],
        }),
        _ => None,
    }
}

/// Classifies only the accepted Step-29 Linux arm64 path/file-descriptor syscall-number set.
///
/// Keeping this classifier stable preserves the already accepted exhaustive path/VFS runtime.
pub fn classify_path_fd(request: SyscallRequest) -> Option<PathFdCall> {
    match request.number {
        nr::OPENAT => Some(PathFdCall::OpenAt {
            dirfd: request.args[0],
            user_path: request.args[1],
            flags: request.args[2],
            mode: request.args[3],
        }),
        nr::CLOSE => Some(PathFdCall::Close {
            fd: request.args[0],
        }),
        nr::GETDENTS64 => Some(PathFdCall::Getdents64 {
            fd: request.args[0],
            user_buffer: request.args[1],
            count: request.args[2],
        }),
        nr::READ => Some(PathFdCall::Read {
            fd: request.args[0],
            user_buffer: request.args[1],
            count: request.args[2],
        }),
        nr::FSTAT => Some(PathFdCall::Fstat {
            fd: request.args[0],
            user_stat: request.args[1],
        }),
        nr::NEWFSTATAT => Some(PathFdCall::Newfstatat {
            dirfd: request.args[0],
            user_path: request.args[1],
            user_stat: request.args[2],
            flags: request.args[3],
        }),
        _ => None,
    }
}

/// Classifies the Step-29 descriptor-I/O extension without changing the accepted path classifier.
///
/// Raw register bits are preserved exactly. Width/sign interpretation and all descriptor, pipe,
/// usercopy, scheduler and signal semantics remain outside this authority-free adapter.
pub fn classify_fd_io(request: SyscallRequest) -> Option<FdIoCall> {
    match request.number {
        nr::DUP => Some(FdIoCall::Dup {
            oldfd: request.args[0],
        }),
        nr::DUP3 => Some(FdIoCall::Dup3 {
            oldfd: request.args[0],
            newfd: request.args[1],
            flags: request.args[2],
        }),
        nr::FCNTL => Some(FdIoCall::Fcntl {
            fd: request.args[0],
            cmd: request.args[1],
            arg: request.args[2],
        }),
        nr::PIPE2 => Some(FdIoCall::Pipe2 {
            user_pipefd: request.args[0],
            flags: request.args[1],
        }),
        nr::LSEEK => Some(FdIoCall::Lseek {
            fd: request.args[0],
            offset: request.args[1],
            whence: request.args[2],
        }),
        nr::PREAD64 => Some(FdIoCall::Pread64 {
            fd: request.args[0],
            user_buffer: request.args[1],
            count: request.args[2],
            offset: request.args[3],
        }),
        _ => None,
    }
}

/// Write an already encoded common Linux result to x0 without changing any other user register.
pub fn write_result(registers: &mut [u64; 31], result: SyscallReturn) {
    registers[RESULT_REGISTER] = result.as_u64_bits();
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_abi::{Errno, unsupported};

    #[test]
    fn arm64_number_anchors_match_linux() {
        assert_eq!(nr::DUP, 23);
        assert_eq!(nr::DUP3, 24);
        assert_eq!(nr::FCNTL, 25);
        assert_eq!(nr::OPENAT, 56);
        assert_eq!(nr::CLOSE, 57);
        assert_eq!(nr::PIPE2, 59);
        assert_eq!(nr::GETDENTS64, 61);
        assert_eq!(nr::LSEEK, 62);
        assert_eq!(nr::READ, 63);
        assert_eq!(nr::WRITE, 64);
        assert_eq!(nr::PREAD64, 67);
        assert_eq!(nr::NEWFSTATAT, 79);
        assert_eq!(nr::FSTAT, 80);
        assert_eq!(nr::EXIT, 93);
        assert_eq!(nr::EXIT_GROUP, 94);
        assert_eq!(nr::FUTEX, 98);
        assert_eq!(nr::CLOCK_GETTIME, 113);
        assert_eq!(nr::GETPID, 172);
        assert_eq!(nr::GETTID, 178);
        assert_eq!(nr::BRK, 214);
        assert_eq!(nr::MUNMAP, 215);
        assert_eq!(nr::CLONE, 220);
        assert_eq!(nr::MMAP, 222);
        assert_eq!(nr::MPROTECT, 226);
    }

    #[test]
    fn x8_and_x0_through_x5_decode_into_common_request_without_mutation() {
        let mut registers = [0u64; 31];
        registers[SYSCALL_NUMBER_REGISTER] = nr::WRITE;
        for (index, value) in registers[..MAX_SYSCALL_ARGS].iter_mut().enumerate() {
            *value = 0x1000 + index as u64;
        }
        registers[6] = 0xaaaa;
        registers[7] = 0xbbbb;
        registers[9] = 0xcccc;

        let before = registers;
        let request = decode_registers(&registers);

        assert_eq!(
            request,
            SyscallRequest::new(nr::WRITE, [0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005],)
        );
        assert_eq!(registers, before);
    }

    #[test]
    fn step14_numbers_map_to_common_operations_without_semantics() {
        assert_eq!(
            classify_bootstrap(SyscallRequest::new(
                nr::WRITE,
                [2, 0x1234, u64::MAX, 4, 5, 6],
            )),
            Some(BootstrapCall::Write {
                fd: 2,
                user_buffer: 0x1234,
                count: u64::MAX,
            })
        );
        assert_eq!(
            classify_bootstrap(SyscallRequest::new(nr::EXIT, [0x1234, 2, 3, 4, 5, 6])),
            Some(BootstrapCall::Exit { status: 0x1234 })
        );
        assert_eq!(
            classify_bootstrap(SyscallRequest::new(nr::EXIT_GROUP, [0xabcd, 2, 3, 4, 5, 6],)),
            Some(BootstrapCall::ExitGroup { status: 0xabcd })
        );
        assert_eq!(
            classify_bootstrap(SyscallRequest::new(
                nr::GETPID,
                [u64::MAX; MAX_SYSCALL_ARGS],
            )),
            Some(BootstrapCall::GetPid)
        );
        assert_eq!(
            classify_bootstrap(SyscallRequest::new(
                nr::GETTID,
                [u64::MAX; MAX_SYSCALL_ARGS],
            )),
            Some(BootstrapCall::GetTid)
        );
    }

    #[test]
    fn step15_numbers_preserve_raw_arm64_argument_order_without_semantics() {
        assert_eq!(
            classify_minimum_runtime(SyscallRequest::new(nr::MMAP, [1, 2, 3, 4, 5, 6])),
            Some(MinimumRuntimeCall::Mmap {
                address: 1,
                length: 2,
                protection: 3,
                flags: 4,
                fd: 5,
                offset: 6,
            })
        );
        assert_eq!(
            classify_minimum_runtime(SyscallRequest::new(nr::MUNMAP, [11, 12, 13, 14, 15, 16])),
            Some(MinimumRuntimeCall::Munmap {
                address: 11,
                length: 12,
            })
        );
        assert_eq!(
            classify_minimum_runtime(SyscallRequest::new(nr::MPROTECT, [17, 18, 19, 20, 21, 22])),
            Some(MinimumRuntimeCall::Mprotect {
                address: 17,
                length: 18,
                protection: 19,
            })
        );
        assert_eq!(
            classify_minimum_runtime(SyscallRequest::new(nr::BRK, [21, 22, 23, 24, 25, 26])),
            Some(MinimumRuntimeCall::Brk { address: 21 })
        );
        assert_eq!(
            classify_minimum_runtime(SyscallRequest::new(
                nr::CLOCK_GETTIME,
                [31, 32, 33, 34, 35, 36],
            )),
            Some(MinimumRuntimeCall::ClockGettime {
                clock_id: 31,
                user_timespec: 32,
            })
        );
        assert_eq!(
            classify_minimum_runtime(SyscallRequest::new(nr::FUTEX, [41, 42, 43, 44, 45, 46])),
            Some(MinimumRuntimeCall::Futex {
                user_address: 41,
                operation: 42,
                value: 43,
                timeout_or_val2: 44,
                user_address2: 45,
                value3: 46,
            })
        );
        assert_eq!(
            classify_minimum_runtime(SyscallRequest::new(nr::CLONE, [51, 52, 53, 54, 55, 56])),
            Some(MinimumRuntimeCall::Clone {
                flags: 51,
                child_stack: 52,
                parent_tid: 53,
                tls: 54,
                child_tid: 55,
            })
        );
    }

    #[test]
    fn step29_numbers_preserve_raw_path_fd_arguments_without_semantics() {
        let at_fdcwd = (-100_i64) as u64;
        assert_eq!(
            classify_path_fd(SyscallRequest::new(
                nr::OPENAT,
                [at_fdcwd, 0x1000, 0x80000, 0o644, 5, 6],
            )),
            Some(PathFdCall::OpenAt {
                dirfd: at_fdcwd,
                user_path: 0x1000,
                flags: 0x80000,
                mode: 0o644,
            })
        );
        assert_eq!(
            classify_path_fd(SyscallRequest::new(nr::CLOSE, [3, 2, 3, 4, 5, 6])),
            Some(PathFdCall::Close { fd: 3 })
        );
        assert_eq!(
            classify_path_fd(SyscallRequest::new(
                nr::GETDENTS64,
                [3, 0x1800, 8192, 4, 5, 6]
            )),
            Some(PathFdCall::Getdents64 {
                fd: 3,
                user_buffer: 0x1800,
                count: 8192,
            })
        );
        assert_eq!(
            classify_path_fd(SyscallRequest::new(nr::READ, [3, 0x2000, 4096, 4, 5, 6])),
            Some(PathFdCall::Read {
                fd: 3,
                user_buffer: 0x2000,
                count: 4096,
            })
        );
        assert_eq!(
            classify_path_fd(SyscallRequest::new(nr::FSTAT, [3, 0x3000, 3, 4, 5, 6])),
            Some(PathFdCall::Fstat {
                fd: 3,
                user_stat: 0x3000,
            })
        );
        assert_eq!(
            classify_path_fd(SyscallRequest::new(
                nr::NEWFSTATAT,
                [at_fdcwd, 0x4000, 0x5000, 0x100, 5, 6],
            )),
            Some(PathFdCall::Newfstatat {
                dirfd: at_fdcwd,
                user_path: 0x4000,
                user_stat: 0x5000,
                flags: 0x100,
            })
        );
    }

    #[test]
    fn classifiers_are_disjoint_and_unknown_numbers_remain_for_enosys() {
        let step14 = SyscallRequest::new(nr::WRITE, [u64::MAX; MAX_SYSCALL_ARGS]);
        assert!(classify_bootstrap(step14).is_some());
        assert_eq!(classify_minimum_runtime(step14), None);
        assert_eq!(classify_path_fd(step14), None);
        assert_eq!(classify_fd_io(step14), None);

        let step15 = SyscallRequest::new(nr::MMAP, [u64::MAX; MAX_SYSCALL_ARGS]);
        assert_eq!(classify_bootstrap(step15), None);
        assert!(classify_minimum_runtime(step15).is_some());
        assert_eq!(classify_path_fd(step15), None);
        assert_eq!(classify_fd_io(step15), None);

        let path = SyscallRequest::new(nr::OPENAT, [u64::MAX; MAX_SYSCALL_ARGS]);
        assert_eq!(classify_bootstrap(path), None);
        assert_eq!(classify_minimum_runtime(path), None);
        assert!(classify_path_fd(path).is_some());
        assert_eq!(classify_fd_io(path), None);

        let fd_io = SyscallRequest::new(nr::DUP3, [u64::MAX; MAX_SYSCALL_ARGS]);
        assert_eq!(classify_bootstrap(fd_io), None);
        assert_eq!(classify_minimum_runtime(fd_io), None);
        assert_eq!(classify_path_fd(fd_io), None);
        assert!(classify_fd_io(fd_io).is_some());

        let hostile = SyscallRequest::new(u64::MAX, [u64::MAX; MAX_SYSCALL_ARGS]);
        assert_eq!(classify_bootstrap(hostile), None);
        assert_eq!(classify_minimum_runtime(hostile), None);
        assert_eq!(classify_path_fd(hostile), None);
        assert_eq!(classify_fd_io(hostile), None);
        assert_eq!(unsupported(hostile), SyscallReturn::error(Errno::ENOSYS));
    }

    #[test]
    fn negative_enosys_writeback_changes_only_x0() {
        let mut registers = core::array::from_fn(|index| 0x100 + index as u64);
        let before = registers;
        write_result(&mut registers, SyscallReturn::error(Errno::ENOSYS));

        assert_eq!(registers[0], (-38_i64) as u64);
        assert_eq!(&registers[1..], &before[1..]);
    }
}
