// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod time;

use core::num::NonZeroU32;
use kernal_linux_abi::{BootstrapCall, Errno, SyscallReturn};

const MAX_LINUX_TASK_ID: u32 = i32::MAX as u32;

/// The two bootstrap descriptors Step 14 exposes as kernel-owned diagnostic output sinks.
///
/// This is intentionally not a general file-descriptor table. Broader VFS/file semantics belong to
/// later roadmap steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFd {
    Stdout,
    Stderr,
}

impl OutputFd {
    pub const fn from_raw(fd: u64) -> Option<Self> {
        match fd {
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            _ => None,
        }
    }

    pub const fn raw(self) -> u64 {
        match self {
            Self::Stdout => 1,
            Self::Stderr => 2,
        }
    }
}

/// Lifecycle breadth requested by a Linux exit syscall.
///
/// The common dispatcher never destroys scheduler/process objects itself. Architecture/runtime code
/// must translate this intent through Kernal's existing thread exit -> teardown -> reap -> process
/// release ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitScope {
    Thread,
    ThreadGroup,
}

/// Non-returning lifecycle request emitted by `exit`/`exit_group` semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitRequest {
    pub scope: ExitScope,
    pub status: u8,
}

/// Result of one Step-14 bootstrap operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    Return(SyscallReturn),
    Exit(ExitRequest),
}

/// Runtime services required by the architecture-independent Step-14 semantics.
///
/// Implementations own all privileged details: validating/copying the user range, PAN windows,
/// output serialization and allocation of Linux-visible PID/TID values. The IDs are identifiers,
/// not capabilities. The semantic boundary still validates that they fit Linux's positive signed
/// 32-bit task-ID range before returning them to userspace.
pub trait BootstrapContext {
    fn write(&mut self, fd: OutputFd, user_buffer: u64, count: u64) -> Result<u64, Errno>;

    fn pid(&self) -> NonZeroU32;

    fn tid(&self) -> NonZeroU32;
}

/// Executes one architecture-neutral Step-14 bootstrap operation.
///
/// Unsupported syscall-number selection is deliberately outside this function: architecture ABI
/// adapters either classify a request into [`BootstrapCall`] or leave it to the shared `-ENOSYS`
/// fallback. Exit operations return a lifecycle intent instead of bypassing Kernal's process/thread
/// teardown machinery.
pub fn dispatch<C: BootstrapContext + ?Sized>(
    call: BootstrapCall,
    context: &mut C,
) -> DispatchOutcome {
    match call {
        BootstrapCall::Write {
            fd,
            user_buffer,
            count,
        } => dispatch_write(fd, user_buffer, count, context),
        BootstrapCall::Exit { status } => DispatchOutcome::Exit(ExitRequest {
            scope: ExitScope::Thread,
            status: status as u8,
        }),
        BootstrapCall::ExitGroup { status } => DispatchOutcome::Exit(ExitRequest {
            scope: ExitScope::ThreadGroup,
            status: status as u8,
        }),
        BootstrapCall::GetPid => DispatchOutcome::Return(success_task_id(context.pid())),
        BootstrapCall::GetTid => DispatchOutcome::Return(success_task_id(context.tid())),
    }
}

fn dispatch_write<C: BootstrapContext + ?Sized>(
    fd: u64,
    user_buffer: u64,
    count: u64,
    context: &mut C,
) -> DispatchOutcome {
    let fd = match OutputFd::from_raw(fd) {
        Some(fd) => fd,
        None => return DispatchOutcome::Return(SyscallReturn::error(Errno::EBADF)),
    };

    if count == 0 {
        return DispatchOutcome::Return(SyscallReturn::success(0).unwrap());
    }

    match context.write(fd, user_buffer, count) {
        Ok(written) if written <= count => DispatchOutcome::Return(success_u64(written)),
        Ok(_) => DispatchOutcome::Return(SyscallReturn::error(Errno::EINVAL)),
        Err(errno) => DispatchOutcome::Return(SyscallReturn::error(errno)),
    }
}

fn success_task_id(value: NonZeroU32) -> SyscallReturn {
    if value.get() > MAX_LINUX_TASK_ID {
        return SyscallReturn::error(Errno::EINVAL);
    }
    success_u64(value.get() as u64)
}

fn success_u64(value: u64) -> SyscallReturn {
    match i64::try_from(value).ok().and_then(SyscallReturn::success) {
        Some(result) => result,
        None => SyscallReturn::error(Errno::EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockContext {
        pid: NonZeroU32,
        tid: NonZeroU32,
        write_result: Result<u64, Errno>,
        writes: usize,
        last_write: Option<(OutputFd, u64, u64)>,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                pid: NonZeroU32::new(17).unwrap(),
                tid: NonZeroU32::new(23).unwrap(),
                write_result: Ok(0),
                writes: 0,
                last_write: None,
            }
        }
    }

    impl BootstrapContext for MockContext {
        fn write(&mut self, fd: OutputFd, user_buffer: u64, count: u64) -> Result<u64, Errno> {
            self.writes += 1;
            self.last_write = Some((fd, user_buffer, count));
            self.write_result
        }

        fn pid(&self) -> NonZeroU32 {
            self.pid
        }

        fn tid(&self) -> NonZeroU32 {
            self.tid
        }
    }

    #[test]
    fn stdout_and_stderr_route_without_creating_a_general_fd_table() {
        let mut context = MockContext::new();
        context.write_result = Ok(5);

        assert_eq!(
            dispatch(
                BootstrapCall::Write {
                    fd: 1,
                    user_buffer: 0x4000,
                    count: 5,
                },
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::success(5).unwrap())
        );
        assert_eq!(context.last_write, Some((OutputFd::Stdout, 0x4000, 5)));

        context.write_result = Ok(3);
        assert_eq!(
            dispatch(
                BootstrapCall::Write {
                    fd: 2,
                    user_buffer: 0x5000,
                    count: 3,
                },
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::success(3).unwrap())
        );
        assert_eq!(context.last_write, Some((OutputFd::Stderr, 0x5000, 3)));
    }

    #[test]
    fn invalid_fd_fails_before_runtime_output_or_usercopy() {
        let mut context = MockContext::new();
        assert_eq!(
            dispatch(
                BootstrapCall::Write {
                    fd: u64::MAX,
                    user_buffer: u64::MAX,
                    count: u64::MAX,
                },
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::error(Errno::EBADF))
        );
        assert_eq!(context.writes, 0);
        assert_eq!(context.last_write, None);
    }

    #[test]
    fn zero_length_write_does_not_touch_runtime_or_user_pointer() {
        let mut context = MockContext::new();
        context.write_result = Err(Errno::EFAULT);

        assert_eq!(
            dispatch(
                BootstrapCall::Write {
                    fd: 1,
                    user_buffer: u64::MAX,
                    count: 0,
                },
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::success(0).unwrap())
        );
        assert_eq!(context.writes, 0);
        assert_eq!(context.last_write, None);
    }

    #[test]
    fn write_propagates_runtime_errno_without_double_negation() {
        let mut context = MockContext::new();
        context.write_result = Err(Errno::EFAULT);
        assert_eq!(
            dispatch(
                BootstrapCall::Write {
                    fd: 1,
                    user_buffer: u64::MAX,
                    count: 4,
                },
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::error(Errno::EFAULT))
        );
    }

    #[test]
    fn write_rejects_backend_overreporting_and_unrepresentable_success() {
        let mut context = MockContext::new();
        context.write_result = Ok(4);
        assert_eq!(
            dispatch(
                BootstrapCall::Write {
                    fd: 1,
                    user_buffer: 0x6000,
                    count: 3,
                },
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::error(Errno::EINVAL))
        );

        context.write_result = Ok((i64::MAX as u64) + 1);
        assert_eq!(
            dispatch(
                BootstrapCall::Write {
                    fd: 2,
                    user_buffer: 0x7000,
                    count: u64::MAX,
                },
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::error(Errno::EINVAL))
        );
    }

    #[test]
    fn getpid_and_gettid_return_only_linux_visible_scalar_ids() {
        let mut context = MockContext::new();
        assert_eq!(
            dispatch(BootstrapCall::GetPid, &mut context),
            DispatchOutcome::Return(SyscallReturn::success(17).unwrap())
        );
        assert_eq!(
            dispatch(BootstrapCall::GetTid, &mut context),
            DispatchOutcome::Return(SyscallReturn::success(23).unwrap())
        );
    }

    #[test]
    fn getpid_and_gettid_enforce_positive_signed_32_bit_task_ids() {
        let mut context = MockContext::new();
        context.pid = NonZeroU32::new(MAX_LINUX_TASK_ID).unwrap();
        context.tid = NonZeroU32::new(MAX_LINUX_TASK_ID).unwrap();
        let maximum = SyscallReturn::success(MAX_LINUX_TASK_ID as i64).unwrap();
        assert_eq!(
            dispatch(BootstrapCall::GetPid, &mut context),
            DispatchOutcome::Return(maximum)
        );
        assert_eq!(
            dispatch(BootstrapCall::GetTid, &mut context),
            DispatchOutcome::Return(maximum)
        );

        let outside = NonZeroU32::new(MAX_LINUX_TASK_ID + 1).unwrap();
        context.pid = outside;
        context.tid = outside;
        assert_eq!(
            dispatch(BootstrapCall::GetPid, &mut context),
            DispatchOutcome::Return(SyscallReturn::error(Errno::EINVAL))
        );
        assert_eq!(
            dispatch(BootstrapCall::GetTid, &mut context),
            DispatchOutcome::Return(SyscallReturn::error(Errno::EINVAL))
        );
    }

    #[test]
    fn exit_operations_emit_lifecycle_intent_and_linux_low_byte_status() {
        let mut context = MockContext::new();
        assert_eq!(
            dispatch(BootstrapCall::Exit { status: 0x1234 }, &mut context,),
            DispatchOutcome::Exit(ExitRequest {
                scope: ExitScope::Thread,
                status: 0x34,
            })
        );
        assert_eq!(
            dispatch(BootstrapCall::ExitGroup { status: 0x01ff }, &mut context,),
            DispatchOutcome::Exit(ExitRequest {
                scope: ExitScope::ThreadGroup,
                status: 0xff,
            })
        );
    }
}
