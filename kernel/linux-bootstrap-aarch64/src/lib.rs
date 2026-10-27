// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod time;

use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::{
    classify_bootstrap, classify_minimum_runtime, classify_step30_runtime,
};
use kernal_linux_abi::{
    MinimumRuntimeCall, Step30RuntimeCall, SyscallRequest, SyscallReturn, unsupported,
};
use kernal_linux_bootstrap::{BootstrapContext, DispatchOutcome, ExitRequest, dispatch};
use kernal_process_aarch64::{ActiveProcess, Error as ActiveProcessError};
use kernal_syscall_entry_aarch64::{
    ActiveProcessHandle, DecodedProcessSyscall, Error as EntryError, apply_linux_return,
    decode_process_syscall,
};

/// Result of handling one Linux arm64 SVC through the accepted Step-9/13 transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapOutcome {
    /// A normal Linux result is present in the saved frame; the existing ERET path may resume EL0.
    Returned,
    /// `exit`/`exit_group` must continue through the existing non-returning scheduler lifecycle.
    Exit(ExitRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The accepted Step-13 syscall-entry/return boundary rejected the frame or process state.
    Entry(EntryError),
    /// The process ceased to be the exact current process before a non-returning exit was handed off.
    ActiveProcess(ActiveProcessError),
    /// This Linux-only adapter was invoked for a Native-personality process.
    NativePersonality,
}

impl From<EntryError> for Error {
    fn from(value: EntryError) -> Self {
        Self::Entry(value)
    }
}

/// Result returned by a privileged Step-15 minimum-runtime handler.
///
/// Most minimum calls are synchronous and return an ordinary [`SyscallReturn`]. Blocking calls are
/// different: FUTEX_WAIT may validate/write the saved x0 result before switching the current thread
/// away, and clone integration may similarly need to finish frame-visible state inside its owner
/// transaction. `FrameCommitted` tells the common trap dispatcher that the supplied ExceptionFrame
/// is already final and that it must not re-run the old entry-generation validation afterward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimumDispatchOutcome {
    Return(SyscallReturn),
    FrameCommitted,
}

/// Unified request-level outcome for the Step-14 + Step-15 Linux arm64 composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step15DispatchOutcome {
    Return(SyscallReturn),
    Exit(ExitRequest),
    FrameCommitted,
}

/// Privileged handler boundary for one already-classified Step-15 minimum runtime operation.
///
/// Implementations own all Process/AddressSpace/VM/futex/scheduler/clone authority. This dispatcher
/// supplies only the scalar [`MinimumRuntimeCall`] plus the saved exception frame. A handler that may
/// context-switch must commit any Linux-visible return state itself and return
/// [`MinimumDispatchOutcome::FrameCommitted`]; it must never expect the outer dispatcher to reuse the
/// pre-switch [`ActiveProcess`] witness after resumption.
pub trait MinimumRuntimeContext {
    type Error;

    fn dispatch_minimum(
        &mut self,
        call: MinimumRuntimeCall,
        frame: &mut ExceptionFrame,
    ) -> Result<MinimumDispatchOutcome, Self::Error>;
}

/// Errors from the Step-15-capable trap composition.
#[derive(Debug, Eq, PartialEq)]
pub enum Step15Error<E> {
    Base(Error),
    Minimum(E),
}

impl<E> From<Error> for Step15Error<E> {
    fn from(value: Error) -> Self {
        Self::Base(value)
    }
}

/// Result returned by the final Step-30 process-runtime integration owner.
///
/// Synchronous operations return an ordinary Linux scalar result. Operations such as wait, exec or
/// signal-frame return may legitimately switch generations or replace the process image; those paths
/// must commit their final frame state inside the authoritative owner transaction and return
/// `FrameCommitted` so this transport never reuses a stale entry-generation witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step30RuntimeDispatchOutcome {
    Return(SyscallReturn),
    FrameCommitted,
}

/// Privileged boundary for one already-classified architecture-neutral Step-30 runtime call.
///
/// The classifier supplies raw Linux-visible scalars only. Implementations must resolve every
/// Process/Thread/PID/TID/VFS/FD/AddressSpace/scheduler capability through the canonical owners and
/// may not retain shorter-lived references across a context switch.
pub trait Step30RuntimeContext {
    type Error;

    fn dispatch_step30(
        &mut self,
        call: Step30RuntimeCall,
        frame: &mut ExceptionFrame,
    ) -> Result<Step30RuntimeDispatchOutcome, Self::Error>;
}

/// Unified request-level outcome after enabling the final Step-30 process-runtime surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step30DispatchOutcome {
    Return(SyscallReturn),
    Exit(ExitRequest),
    FrameCommitted,
}

/// Errors from the final Step-30-capable trap composition.
#[derive(Debug, Eq, PartialEq)]
pub enum Step30Error<ME, SE> {
    Base(Error),
    Minimum(ME),
    Runtime(SE),
}

/// Dispatches one Step-14 Linux arm64 syscall from the accepted lower-EL exception frame.
///
/// This compatibility path deliberately retains the exact Step-14 surface. Minimum-runtime calls are
/// still returned as `-ENOSYS` here; callers that enable Step 15 must use
/// [`dispatch_linux_syscall_step15`] instead.
///
/// The function deliberately owns no exception vector, process model, usercopy implementation,
/// console, PID namespace or scheduler lifecycle. It composes the already-accepted boundaries:
///
/// 1. Step 13 proves that `current` is the exact process generation that trapped this frame and
///    decodes x8/x0..x5 through the existing SVC path.
/// 2. The arm64 ABI adapter classifies only the Step-14 syscall-number set.
/// 3. Common Step-14 semantics execute through the caller-supplied [`BootstrapContext`].
/// 4. Returning operations use the existing Step-13 validated Linux writeback path.
/// 5. Exit operations never write a return value or authorize ERET. The exact process/switch
///    generation is revalidated immediately before the lifecycle intent is handed to runtime code.
///
/// # Runtime context contract
///
/// The supplied [`BootstrapContext`] must be scheduler-neutral and non-blocking while this
/// synchronous lower-EL handler owns `current`: it must not context-switch, replace the active
/// process/address space, or otherwise invalidate the trapped switch generation. In particular,
/// Step-14 `write` may emit bytes before the final `apply_linux_return` revalidation, so its
/// usercopy/console backend must remain bounded and non-scheduling. Exit scheduling happens only
/// after this function returns [`TrapOutcome::Exit`].
pub fn dispatch_linux_syscall<
    C: BootstrapContext + ?Sized,
    const CAPS: usize,
    const VMAS: usize,
>(
    current: &ActiveProcess<'_, CAPS, VMAS>,
    frame: &mut ExceptionFrame,
    context: &mut C,
) -> Result<TrapOutcome, Error> {
    let request = match decode_process_syscall(current, frame)? {
        DecodedProcessSyscall::Linux(request) => request,
        DecodedProcessSyscall::Native(_) => return Err(Error::NativePersonality),
    };

    match dispatch_bootstrap_request(request, context) {
        DispatchOutcome::Return(result) => {
            apply_linux_return(current, frame, result)?;
            Ok(TrapOutcome::Returned)
        }
        DispatchOutcome::Exit(request) => {
            current
                .validate_entry_switch_generation(frame.entry_switch_generation())
                .map_err(Error::ActiveProcess)?;
            Ok(TrapOutcome::Exit(request))
        }
    }
}

/// Dispatches the combined Step-14 + Step-15 Linux arm64 syscall surface.
///
/// The Step-14 path is unchanged. Step-15 syscall numbers are classified through the single common
/// [`MinimumRuntimeCall`] contract and delegated to `minimum`. Synchronous minimum calls return a
/// scalar result which is written through the accepted Step-13 boundary here. A blocking handler may
/// instead return [`MinimumDispatchOutcome::FrameCommitted`]; in that case this function performs no
/// further process/frame validation because a legitimate switch away and back has necessarily made
/// the original entry-switch generation stale.
///
/// Unlike the Step-14 compatibility entry, this function receives an [`ActiveProcessHandle`] rather
/// than a retained [`ActiveProcess`]. Decode and synchronous writeback each reacquire a fresh witness;
/// no Process/address-space Rust reference is live while `minimum.dispatch_minimum()` may block.
/// `bootstrap` and `minimum` must be per-trap/static-provider values and may not transitively retain
/// shorter-lived owner references across a switch.
pub fn dispatch_linux_syscall_step15<
    C: BootstrapContext + ?Sized + 'static,
    M: MinimumRuntimeContext + ?Sized + 'static,
    const CAPS: usize,
    const VMAS: usize,
>(
    current: ActiveProcessHandle<CAPS, VMAS>,
    frame: &mut ExceptionFrame,
    bootstrap: &mut C,
    minimum: &mut M,
) -> Result<TrapOutcome, Step15Error<M::Error>> {
    let decoded = current
        .with_current(|active| decode_process_syscall(active, frame))
        .map_err(|error| Step15Error::Base(Error::ActiveProcess(error)))?;
    let request = match decoded.map_err(|error| Step15Error::Base(Error::Entry(error)))? {
        DecodedProcessSyscall::Linux(request) => request,
        DecodedProcessSyscall::Native(_) => {
            return Err(Step15Error::Base(Error::NativePersonality));
        }
    };

    let outcome = {
        let mut handle_minimum = |call| minimum.dispatch_minimum(call, frame);
        dispatch_step15_request(request, bootstrap, &mut handle_minimum)
            .map_err(Step15Error::Minimum)?
    };

    match outcome {
        Step15DispatchOutcome::Return(result) => {
            current
                .with_current(|active| apply_linux_return(active, frame, result))
                .map_err(|error| Step15Error::Base(Error::ActiveProcess(error)))?
                .map_err(|error| Step15Error::Base(Error::Entry(error)))?;
            Ok(TrapOutcome::Returned)
        }
        Step15DispatchOutcome::Exit(request) => {
            let entry_switch_generation = frame.entry_switch_generation();
            current
                .with_current(|active| {
                    active.validate_entry_switch_generation(entry_switch_generation)
                })
                .map_err(|error| Step15Error::Base(Error::ActiveProcess(error)))?
                .map_err(|error| Step15Error::Base(Error::ActiveProcess(error)))?;
            Ok(TrapOutcome::Exit(request))
        }
        Step15DispatchOutcome::FrameCommitted => Ok(TrapOutcome::Returned),
    }
}

/// Dispatches the Step-14 + Step-15 + Step-30 Linux arm64 surface without retaining process
/// references across privileged runtime callbacks.
///
/// Classification order is intentionally stable: accepted bootstrap calls win first, accepted
/// minimum-runtime calls second, and the new Step-30 process-runtime surface third. Synchronous
/// results are written only after reacquiring the exact current process witness. A callback that may
/// block, switch or replace the image must commit its frame itself and return `FrameCommitted`.
pub fn dispatch_linux_syscall_step30<
    C: BootstrapContext + ?Sized + 'static,
    M: MinimumRuntimeContext + ?Sized + 'static,
    S: Step30RuntimeContext + ?Sized + 'static,
    const CAPS: usize,
    const VMAS: usize,
>(
    current: ActiveProcessHandle<CAPS, VMAS>,
    frame: &mut ExceptionFrame,
    bootstrap: &mut C,
    minimum: &mut M,
    step30: &mut S,
) -> Result<TrapOutcome, Step30Error<M::Error, S::Error>> {
    let decoded = current
        .with_current(|active| decode_process_syscall(active, frame))
        .map_err(|error| Step30Error::Base(Error::ActiveProcess(error)))?;
    let request = match decoded.map_err(|error| Step30Error::Base(Error::Entry(error)))? {
        DecodedProcessSyscall::Linux(request) => request,
        DecodedProcessSyscall::Native(_) => {
            return Err(Step30Error::Base(Error::NativePersonality));
        }
    };

    let outcome = if let Some(call) = classify_bootstrap(request) {
        match dispatch(call, bootstrap) {
            DispatchOutcome::Return(result) => Step30DispatchOutcome::Return(result),
            DispatchOutcome::Exit(request) => Step30DispatchOutcome::Exit(request),
        }
    } else if let Some(call) = classify_minimum_runtime(request) {
        match minimum
            .dispatch_minimum(call, frame)
            .map_err(Step30Error::Minimum)?
        {
            MinimumDispatchOutcome::Return(result) => Step30DispatchOutcome::Return(result),
            MinimumDispatchOutcome::FrameCommitted => Step30DispatchOutcome::FrameCommitted,
        }
    } else if let Some(call) = classify_step30_runtime(request) {
        match step30
            .dispatch_step30(call, frame)
            .map_err(Step30Error::Runtime)?
        {
            Step30RuntimeDispatchOutcome::Return(result) => Step30DispatchOutcome::Return(result),
            Step30RuntimeDispatchOutcome::FrameCommitted => Step30DispatchOutcome::FrameCommitted,
        }
    } else {
        Step30DispatchOutcome::Return(unsupported(request))
    };

    match outcome {
        Step30DispatchOutcome::Return(result) => {
            current
                .with_current(|active| apply_linux_return(active, frame, result))
                .map_err(|error| Step30Error::Base(Error::ActiveProcess(error)))?
                .map_err(|error| Step30Error::Base(Error::Entry(error)))?;
            Ok(TrapOutcome::Returned)
        }
        Step30DispatchOutcome::Exit(request) => {
            let entry_switch_generation = frame.entry_switch_generation();
            current
                .with_current(|active| {
                    active.validate_entry_switch_generation(entry_switch_generation)
                })
                .map_err(|error| Step30Error::Base(Error::ActiveProcess(error)))?
                .map_err(|error| Step30Error::Base(Error::ActiveProcess(error)))?;
            Ok(TrapOutcome::Exit(request))
        }
        Step30DispatchOutcome::FrameCommitted => Ok(TrapOutcome::Returned),
    }
}

/// Applies only the arm64 Step-14 number mapping plus architecture-neutral bootstrap semantics.
///
/// Keeping this helper free of trap/process state makes the ABI/semantic composition deterministic
/// and host-testable. Unknown numbers retain the original request and use the common `-ENOSYS`
/// fallback; they never reach a privileged runtime callback.
pub fn dispatch_bootstrap_request<C: BootstrapContext + ?Sized>(
    request: SyscallRequest,
    context: &mut C,
) -> DispatchOutcome {
    match classify_bootstrap(request) {
        Some(call) => dispatch(call, context),
        None => DispatchOutcome::Return(unsupported(request)),
    }
}

/// Host-testable Step-14 + Step-15 request composition without trap/process authority.
///
/// Bootstrap classification always has first priority, preserving the accepted Step-14 behavior.
/// The classifiers are intentionally disjoint, but keeping that ordering explicit prevents a future
/// minimum-runtime expansion from silently stealing an older syscall. Unknown requests retain the
/// canonical common `-ENOSYS` fallback and never invoke `minimum`.
pub fn dispatch_step15_request<C, F, E>(
    request: SyscallRequest,
    bootstrap: &mut C,
    mut minimum: F,
) -> Result<Step15DispatchOutcome, E>
where
    C: BootstrapContext + ?Sized,
    F: FnMut(MinimumRuntimeCall) -> Result<MinimumDispatchOutcome, E>,
{
    if let Some(call) = classify_bootstrap(request) {
        return Ok(match dispatch(call, bootstrap) {
            DispatchOutcome::Return(result) => Step15DispatchOutcome::Return(result),
            DispatchOutcome::Exit(request) => Step15DispatchOutcome::Exit(request),
        });
    }

    if let Some(call) = classify_minimum_runtime(request) {
        return minimum(call).map(|outcome| match outcome {
            MinimumDispatchOutcome::Return(result) => Step15DispatchOutcome::Return(result),
            MinimumDispatchOutcome::FrameCommitted => Step15DispatchOutcome::FrameCommitted,
        });
    }

    Ok(Step15DispatchOutcome::Return(unsupported(request)))
}

/// Host-testable request composition for the final Step-30 process-runtime surface.
///
/// This helper carries no trap, process or usercopy authority. It makes dispatch precedence explicit
/// and lets the semantic integration owner prove that unknown requests never reach privileged hooks.
pub fn dispatch_step30_request<C, FM, FS, E>(
    request: SyscallRequest,
    bootstrap: &mut C,
    mut minimum: FM,
    mut step30: FS,
) -> Result<Step30DispatchOutcome, E>
where
    C: BootstrapContext + ?Sized,
    FM: FnMut(MinimumRuntimeCall) -> Result<MinimumDispatchOutcome, E>,
    FS: FnMut(Step30RuntimeCall) -> Result<Step30RuntimeDispatchOutcome, E>,
{
    if let Some(call) = classify_bootstrap(request) {
        return Ok(match dispatch(call, bootstrap) {
            DispatchOutcome::Return(result) => Step30DispatchOutcome::Return(result),
            DispatchOutcome::Exit(request) => Step30DispatchOutcome::Exit(request),
        });
    }

    if let Some(call) = classify_minimum_runtime(request) {
        return minimum(call).map(|outcome| match outcome {
            MinimumDispatchOutcome::Return(result) => Step30DispatchOutcome::Return(result),
            MinimumDispatchOutcome::FrameCommitted => Step30DispatchOutcome::FrameCommitted,
        });
    }

    if let Some(call) = classify_step30_runtime(request) {
        return step30(call).map(|outcome| match outcome {
            Step30RuntimeDispatchOutcome::Return(result) => Step30DispatchOutcome::Return(result),
            Step30RuntimeDispatchOutcome::FrameCommitted => Step30DispatchOutcome::FrameCommitted,
        });
    }

    Ok(Step30DispatchOutcome::Return(unsupported(request)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU32;
    use kernal_linux_aarch64_abi::{nr, step30_nr};
    use kernal_linux_abi::{Errno, SyscallReturn};
    use kernal_linux_bootstrap::{ExitScope, OutputFd};

    struct MockContext {
        pid: NonZeroU32,
        tid: NonZeroU32,
        writes: usize,
        write_result: Result<u64, Errno>,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                pid: NonZeroU32::new(41).unwrap(),
                tid: NonZeroU32::new(43).unwrap(),
                writes: 0,
                write_result: Ok(0),
            }
        }
    }

    impl BootstrapContext for MockContext {
        fn write(&mut self, _fd: OutputFd, _user_buffer: u64, _count: u64) -> Result<u64, Errno> {
            self.writes += 1;
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
    fn bootstrap_only_path_keeps_minimum_and_unknown_syscalls_on_enosys() {
        let mut context = MockContext::new();
        for request in [
            SyscallRequest::new(nr::MMAP, [u64::MAX; 6]),
            SyscallRequest::new(u64::MAX, [u64::MAX; 6]),
        ] {
            assert_eq!(
                dispatch_bootstrap_request(request, &mut context),
                DispatchOutcome::Return(SyscallReturn::error(Errno::ENOSYS))
            );
        }
        assert_eq!(context.writes, 0);
    }

    #[test]
    fn arm64_getpid_and_gettid_use_only_common_scalar_context() {
        let mut context = MockContext::new();
        assert_eq!(
            dispatch_bootstrap_request(SyscallRequest::new(nr::GETPID, [0; 6]), &mut context),
            DispatchOutcome::Return(SyscallReturn::success(41).unwrap())
        );
        assert_eq!(
            dispatch_bootstrap_request(SyscallRequest::new(nr::GETTID, [0; 6]), &mut context),
            DispatchOutcome::Return(SyscallReturn::success(43).unwrap())
        );
    }

    #[test]
    fn arm64_write_routes_through_common_context_once() {
        let mut context = MockContext::new();
        context.write_result = Ok(7);
        assert_eq!(
            dispatch_bootstrap_request(
                SyscallRequest::new(nr::WRITE, [2, 0x4000, 7, 0, 0, 0]),
                &mut context,
            ),
            DispatchOutcome::Return(SyscallReturn::success(7).unwrap())
        );
        assert_eq!(context.writes, 1);
    }

    #[test]
    fn exit_and_exit_group_remain_non_returning_lifecycle_intents() {
        let mut context = MockContext::new();
        assert_eq!(
            dispatch_bootstrap_request(
                SyscallRequest::new(nr::EXIT, [0x1234, 0, 0, 0, 0, 0]),
                &mut context,
            ),
            DispatchOutcome::Exit(ExitRequest {
                scope: ExitScope::Thread,
                status: 0x34,
            })
        );
        assert_eq!(
            dispatch_bootstrap_request(
                SyscallRequest::new(nr::EXIT_GROUP, [0x01ff, 0, 0, 0, 0, 0]),
                &mut context,
            ),
            DispatchOutcome::Exit(ExitRequest {
                scope: ExitScope::ThreadGroup,
                status: 0xff,
            })
        );
        assert_eq!(context.writes, 0);
    }

    #[test]
    fn step15_preserves_bootstrap_priority_without_calling_minimum_handler() {
        let mut context = MockContext::new();
        let mut minimum_calls = 0usize;
        let result = dispatch_step15_request(
            SyscallRequest::new(nr::GETPID, [u64::MAX; 6]),
            &mut context,
            |_call| {
                minimum_calls += 1;
                Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted)
            },
        )
        .unwrap();

        assert_eq!(
            result,
            Step15DispatchOutcome::Return(SyscallReturn::success(41).unwrap())
        );
        assert_eq!(minimum_calls, 0);
    }

    #[test]
    fn minimum_runtime_request_reaches_one_common_scalar_hook() {
        let mut context = MockContext::new();
        let request = SyscallRequest::new(nr::MMAP, [1, 2, 3, 4, 5, 6]);
        let mut minimum_calls = 0usize;
        let result = dispatch_step15_request(request, &mut context, |call| {
            minimum_calls += 1;
            assert_eq!(
                call,
                MinimumRuntimeCall::Mmap {
                    address: 1,
                    length: 2,
                    protection: 3,
                    flags: 4,
                    fd: 5,
                    offset: 6,
                }
            );
            Ok::<_, ()>(MinimumDispatchOutcome::Return(
                SyscallReturn::success(0x1234).unwrap(),
            ))
        })
        .unwrap();

        assert_eq!(
            result,
            Step15DispatchOutcome::Return(SyscallReturn::success(0x1234).unwrap())
        );
        assert_eq!(minimum_calls, 1);
        assert_eq!(context.writes, 0);
    }

    #[test]
    fn blocking_minimum_handler_can_commit_frame_without_outer_writeback() {
        let mut context = MockContext::new();
        let request = SyscallRequest::new(nr::FUTEX, [0x4000, 128, 7, 0, 0, 0]);
        let result = dispatch_step15_request(request, &mut context, |call| {
            assert!(matches!(call, MinimumRuntimeCall::Futex { .. }));
            Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted)
        })
        .unwrap();

        assert_eq!(result, Step15DispatchOutcome::FrameCommitted);
    }

    #[test]
    fn unknown_step15_request_never_reaches_minimum_handler() {
        let mut context = MockContext::new();
        let mut minimum_calls = 0usize;
        let result = dispatch_step15_request(
            SyscallRequest::new(u64::MAX, [u64::MAX; 6]),
            &mut context,
            |_call| {
                minimum_calls += 1;
                Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted)
            },
        )
        .unwrap();

        assert_eq!(
            result,
            Step15DispatchOutcome::Return(SyscallReturn::error(Errno::ENOSYS))
        );
        assert_eq!(minimum_calls, 0);
    }

    #[test]
    fn old_step15_dispatch_keeps_step30_only_syscalls_on_enosys() {
        let mut context = MockContext::new();
        let mut minimum_calls = 0usize;
        let result = dispatch_step15_request(
            SyscallRequest::new(step30_nr::SET_ROBUST_LIST, [0x4000, 24, 0, 0, 0, 0]),
            &mut context,
            |_call| {
                minimum_calls += 1;
                Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted)
            },
        )
        .unwrap();

        assert_eq!(
            result,
            Step15DispatchOutcome::Return(SyscallReturn::error(Errno::ENOSYS))
        );
        assert_eq!(minimum_calls, 0);
        assert_eq!(context.writes, 0);
    }

    #[test]
    fn step30_preserves_bootstrap_and_minimum_priority() {
        let mut context = MockContext::new();
        let mut minimum_calls = 0usize;
        let mut step30_calls = 0usize;

        let bootstrap = dispatch_step30_request(
            SyscallRequest::new(nr::GETPID, [u64::MAX; 6]),
            &mut context,
            |_call| {
                minimum_calls += 1;
                Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted)
            },
            |_call| {
                step30_calls += 1;
                Ok::<_, ()>(Step30RuntimeDispatchOutcome::FrameCommitted)
            },
        )
        .unwrap();
        assert_eq!(
            bootstrap,
            Step30DispatchOutcome::Return(SyscallReturn::success(41).unwrap())
        );
        assert_eq!(minimum_calls, 0);
        assert_eq!(step30_calls, 0);

        let minimum = dispatch_step30_request(
            SyscallRequest::new(nr::MMAP, [1, 2, 3, 4, 5, 6]),
            &mut context,
            |call| {
                minimum_calls += 1;
                assert!(matches!(call, MinimumRuntimeCall::Mmap { .. }));
                Ok::<_, ()>(MinimumDispatchOutcome::Return(
                    SyscallReturn::success(0x55).unwrap(),
                ))
            },
            |_call| {
                step30_calls += 1;
                Ok::<_, ()>(Step30RuntimeDispatchOutcome::FrameCommitted)
            },
        )
        .unwrap();
        assert_eq!(
            minimum,
            Step30DispatchOutcome::Return(SyscallReturn::success(0x55).unwrap())
        );
        assert_eq!(minimum_calls, 1);
        assert_eq!(step30_calls, 0);
    }

    #[test]
    fn step30_runtime_request_reaches_exactly_one_scalar_hook() {
        let mut context = MockContext::new();
        let mut minimum_calls = 0usize;
        let mut step30_calls = 0usize;
        let result = dispatch_step30_request(
            SyscallRequest::new(step30_nr::SET_ROBUST_LIST, [0x4000, 24, 0, 0, 0, 0]),
            &mut context,
            |_call| {
                minimum_calls += 1;
                Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted)
            },
            |call| {
                step30_calls += 1;
                assert_eq!(
                    call,
                    Step30RuntimeCall::SetRobustList {
                        head: 0x4000,
                        len: 24,
                    }
                );
                Ok::<_, ()>(Step30RuntimeDispatchOutcome::Return(
                    SyscallReturn::success(0).unwrap(),
                ))
            },
        )
        .unwrap();

        assert_eq!(
            result,
            Step30DispatchOutcome::Return(SyscallReturn::success(0).unwrap())
        );
        assert_eq!(minimum_calls, 0);
        assert_eq!(step30_calls, 1);
    }

    #[test]
    fn blocking_step30_handler_can_commit_frame_without_outer_writeback() {
        let mut context = MockContext::new();
        let result = dispatch_step30_request(
            SyscallRequest::new(step30_nr::WAIT4, [u64::MAX, 0x8000, 0, 0, 0, 0]),
            &mut context,
            |_call| Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted),
            |call| {
                assert!(matches!(call, Step30RuntimeCall::Wait4 { .. }));
                Ok::<_, ()>(Step30RuntimeDispatchOutcome::FrameCommitted)
            },
        )
        .unwrap();

        assert_eq!(result, Step30DispatchOutcome::FrameCommitted);
    }

    #[test]
    fn unknown_step30_request_never_reaches_privileged_handlers() {
        let mut context = MockContext::new();
        let mut minimum_calls = 0usize;
        let mut step30_calls = 0usize;
        let result = dispatch_step30_request(
            SyscallRequest::new(u64::MAX, [u64::MAX; 6]),
            &mut context,
            |_call| {
                minimum_calls += 1;
                Ok::<_, ()>(MinimumDispatchOutcome::FrameCommitted)
            },
            |_call| {
                step30_calls += 1;
                Ok::<_, ()>(Step30RuntimeDispatchOutcome::FrameCommitted)
            },
        )
        .unwrap();

        assert_eq!(
            result,
            Step30DispatchOutcome::Return(SyscallReturn::error(Errno::ENOSYS))
        );
        assert_eq!(minimum_calls, 0);
        assert_eq!(step30_calls, 0);
    }
}
