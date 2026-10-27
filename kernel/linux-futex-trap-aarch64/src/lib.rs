// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ptr::NonNull;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_futex::Error as FutexError;
use kernal_linux_abi::{Errno, MinimumRuntimeCall, SyscallReturn};
use kernal_linux_futex::{MinimumFutexCall, decode_minimum};
use kernal_linux_futex_aarch64::{FutexAccessError, read_private_word};
use kernal_linux_futex_runtime::{
    CancelError, InterruptError, SerializedFutexTable, WaitDecision, WaitError, WakeError,
};
use kernal_process::Process;
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessAddressSpaceError};
use kernal_scheduler_cpu::{CpuSchedulerCell, Error as SchedulerError};
use kernal_scheduler_smp::GlobalThreadId;
use kernal_syscall_entry_aarch64::{Error as EntryError, apply_linux_return};

/// Result of one private-futex trap composition when the caller opts into Step-30 signal awareness.
///
/// `SignalInterrupted` carries only the exact scheduler generation whose canonical FutexTable
/// interruption marker is still retained on resume. This crate deliberately does not decide EINTR,
/// SA_RESTART, handler delivery or fatal signal policy and does not consume that marker; those remain
/// Core/SignalTable ownership and must commit before the exact futex interruption is consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    Complete,
    SignalInterrupted(GlobalThreadId),
}

/// Fatal/runtime failures from the Step-15 AArch64 private-futex trap composition.
///
/// Normal Linux request errors are written to the trapped frame and return `Ok(())`; this enum is
/// reserved for privileged ownership, scheduler, futex-state or wake-delivery failures that must not
/// be disguised as a recoverable userspace errno.
#[derive(Debug, Eq, PartialEq)]
pub enum Error<E> {
    NotFutexCall,
    Entry(EntryError),
    ProcessAddressSpace(ProcessAddressSpaceError),
    Scheduler(SchedulerError),
    Access(FutexAccessError),
    Wait(WaitError<FutexAccessError>),
    Cancel(CancelError),
    Interrupt(InterruptError),
    Wake(WakeError<E>),
    Invariant,
}

fn require_complete<E>(outcome: DispatchOutcome) -> Result<(), Error<E>> {
    match outcome {
        DispatchOutcome::Complete => Ok(()),
        DispatchOutcome::SignalInterrupted(_) => Err(Error::Invariant),
    }
}

/// Executes one already-classified Step-15 private futex call through the accepted AArch64 owners.
///
/// This reference-based compatibility entry delegates to [`dispatch_private_futex_raw`]. It remains
/// useful for bootstrap callers which can keep every referent exclusively stable for the entire call.
/// A normal multi-threaded runtime should use the raw-owner entry directly: a successful FUTEX_WAIT
/// may suspend this function's stack frame while another thread legitimately mutates the same Process
/// or address-space owner, which is incompatible with retaining Rust references across the switch.
///
/// # Safety
/// In addition to the scheduler/quiescence requirements documented on
/// [`dispatch_private_futex_raw`], the caller must guarantee that `process`, `address_space`, and
/// `frame` are not mutably aliased until this function returns, including while FUTEX_WAIT is blocked.
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch_private_futex<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: &Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    frame: &mut ExceptionFrame,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    call: MinimumRuntimeCall,
    deliver: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), Error<E>> {
    // SAFETY: the stronger reference-stability contract above implies the raw-owner contract below.
    let outcome = unsafe {
        dispatch_private_futex_raw_signal_aware(
            NonNull::from(process),
            NonNull::from(address_space),
            NonNull::from(frame),
            scheduler,
            futexes,
            call,
            deliver,
        )
    }?;
    require_complete(outcome)
}

/// Executes one Step-15 private futex call without retaining Process/address-space references across
/// a blocking scheduler switch.
///
/// This compatibility entry remains intentionally signal-unaware. If an Interrupted marker is ever
/// observed, it fails closed rather than silently returning the staged Linux success. Step-30 Core
/// must use [`dispatch_private_futex_raw_signal_aware`] so canonical SignalTable policy can consume the
/// returned exact generation.
///
/// # Safety
/// Same owner/quiescence requirements as [`dispatch_private_futex_raw_signal_aware`].
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch_private_futex_raw<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    frame: NonNull<ExceptionFrame>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    call: MinimumRuntimeCall,
    deliver: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), Error<E>> {
    let outcome = unsafe {
        dispatch_private_futex_raw_signal_aware(
            process,
            address_space,
            frame,
            scheduler,
            futexes,
            call,
            deliver,
        )
    }?;
    require_complete(outcome)
}

/// Executes one Step-30 signal-aware private futex call without retaining Process/address-space
/// references across a blocking scheduler switch.
///
/// This is the production composition boundary for a multi-threaded Process. Every user-memory or
/// Linux-frame operation materializes short-lived references from the raw owner handles, completes
/// synchronously, and drops those references before `bootstrap_block_current_and_switch` can suspend
/// the current kernel stack. FUTEX_WAKE likewise creates its owner references only around the
/// nonblocking key read and final result writeback. The function therefore does not reserve a shared
/// Rust borrow of the Process or address-space owner while a different thread runs.
///
/// The adapter deliberately owns no second queue, scheduler, signal policy or usercopy mechanism. It
/// composes the existing minimum futex policy, generation-bound AArch64 userword access, serialized
/// FutexTable, exact-generation scheduler transitions and Step-13 Linux result boundary.
///
/// FUTEX_WAIT still stages Linux success (`x0=0`) before switching. If the exact resumed generation
/// owns a retained signal interruption, [`DispatchOutcome::SignalInterrupted`] is returned while the
/// canonical marker remains owned by the FutexTable. Core must replace the staged success through its
/// prepared-signal EINTR/SA_RESTART/fatal transaction and only then consume that exact marker. A
/// normal wake returns [`DispatchOutcome::Complete`].
///
/// # Safety
/// `process`, `address_space`, and `frame` must remain allocated at stable addresses until this call
/// returns. They must identify the exact trapped thread's current Process/TTBR0 binding and exception
/// frame whenever this function materializes a reference from them. No conflicting reference may be
/// live during those short synchronous windows. Between those windows, including while FUTEX_WAIT is
/// blocked, other owner-serialized threads may access the same Process/address-space through their
/// canonical paths.
///
/// The caller must execute on the scheduler owner CPU/PE with local IRQ delivery masked,
/// `irq_depth=0`, `preempt_count=0`, migration suppressed and the current process/address-space
/// binding stable from compare through either successful block/switch or cancellation. `futexes` must
/// be the canonical serialized private table. `deliver` must route every consumed exact
/// [`GlobalThreadId`] through the existing local/remote scheduler owner path without silently dropping
/// it and must not retain references to any owner that may be needed while FUTEX_WAIT is suspended.
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch_private_futex_raw_signal_aware<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    frame: NonNull<ExceptionFrame>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    call: MinimumRuntimeCall,
    deliver: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<DispatchOutcome, Error<E>> {
    // SAFETY: delegated caller contract is exactly the shared implementation contract below.
    unsafe {
        dispatch_private_futex_raw_inner(
            process,
            address_space,
            frame,
            scheduler,
            futexes,
            call,
            None,
            deliver,
        )
    }
}

/// Signal-aware AArch64 private-futex call with exact destination address-space activation composed
/// into every committed scheduler switch.
///
/// The callback receives only the exact selected scheduler generation and its opaque generation-bound
/// ContextTable token. It must resolve canonical Process/address-space authority and either activate
/// that destination or fail closed/non-returning. Futex ownership and wake routing stay unchanged.
///
/// # Safety
/// Same requirements as [`dispatch_private_futex_raw_signal_aware`]. In addition,
/// `activate_destination` must not re-enter this scheduler and must not return after failing to
/// activate the exact selected generation.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch_private_futex_raw_with_destination_address_space_signal_aware<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    frame: NonNull<ExceptionFrame>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    call: MinimumRuntimeCall,
    activate_destination: fn(GlobalThreadId, u64),
    deliver: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<DispatchOutcome, Error<E>> {
    // SAFETY: delegated caller contract plus the stricter destination activation contract above.
    unsafe {
        dispatch_private_futex_raw_inner(
            process,
            address_space,
            frame,
            scheduler,
            futexes,
            call,
            Some(activate_destination),
            deliver,
        )
    }
}

/// Compatibility destination-address-space entry. It fails closed if a signal-owned FUTEX_WAIT resume
/// reaches a caller which has not opted into the Step-30 signal handoff.
///
/// # Safety
/// Same requirements as [`dispatch_private_futex_raw_with_destination_address_space_signal_aware`].
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn dispatch_private_futex_raw_with_destination_address_space<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    frame: NonNull<ExceptionFrame>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    call: MinimumRuntimeCall,
    activate_destination: fn(GlobalThreadId, u64),
    deliver: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), Error<E>> {
    let outcome = unsafe {
        dispatch_private_futex_raw_with_destination_address_space_signal_aware(
            process,
            address_space,
            frame,
            scheduler,
            futexes,
            call,
            activate_destination,
            deliver,
        )
    }?;
    require_complete(outcome)
}

#[allow(clippy::too_many_arguments)]
unsafe fn dispatch_private_futex_raw_inner<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    frame: NonNull<ExceptionFrame>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    call: MinimumRuntimeCall,
    activate_destination: Option<fn(GlobalThreadId, u64)>,
    deliver: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<DispatchOutcome, Error<E>> {
    let (user_address, operation, value, timeout_or_val2) = match call {
        MinimumRuntimeCall::Futex {
            user_address,
            operation,
            value,
            timeout_or_val2,
            ..
        } => (user_address, operation, value, timeout_or_val2),
        _ => return Err(Error::NotFutexCall),
    };

    let operation = match decode_minimum(operation, value, timeout_or_val2) {
        Ok(operation) => operation,
        Err(errno) => {
            // SAFETY: this synchronous result window is covered by the raw-owner contract.
            unsafe { write_errno_raw(process, address_space, frame, errno) }?;
            return Ok(DispatchOutcome::Complete);
        }
    };

    match operation {
        MinimumFutexCall::WaitPrivate { expected } => {
            // SAFETY: delegated owner/quiescence contract from this function.
            let current =
                unsafe { scheduler.bootstrap_current_global_thread() }.map_err(Error::Scheduler)?;
            // SAFETY: the closure creates Process/address-space references only for the synchronous
            // atomic userword observation. They are gone before compare_prepare_commit returns and
            // before any scheduler transition is attempted.
            let decision = unsafe {
                futexes.compare_prepare_commit(current, expected, || {
                    read_private_word(process.as_ref(), address_space.as_ref(), user_address)
                        .map(|word| (word.key, word.value))
                })
            };

            match decision {
                Ok(WaitDecision::ValueMismatch) => {
                    // SAFETY: synchronous writeback window under the raw-owner contract.
                    unsafe { write_errno_raw(process, address_space, frame, Errno::EAGAIN) }?;
                    Ok(DispatchOutcome::Complete)
                }
                Ok(WaitDecision::Sleep) => {
                    // Commit the provisional Linux-visible return before any scheduler switch. It is
                    // authoritative only for a normal wake; SignalInterrupted requires Core to
                    // replace it through canonical signal delivery before EL0 return.
                    let success = success_value::<E>(0)?;
                    // SAFETY: synchronous writeback window under the raw-owner contract.
                    if let Err(write_error) =
                        unsafe { write_result_raw(process, address_space, frame, success) }
                    {
                        // The waiter is committed but the thread is still Running. Best-effort exact
                        // cancellation contains ordinary state. A signal-owned Interrupted record is
                        // deliberately non-cancellable and remains fail-closed evidence.
                        // SAFETY: delegated owner/quiescence contract is still held pre-switch.
                        return match unsafe { futexes.cancel_wait(current) } {
                            Ok(_) => Err(write_error),
                            Err(cancel_error) => Err(Error::Cancel(cancel_error)),
                        };
                    }

                    // No Process, address-space, frame or wake-router reference is live here. Only raw
                    // pointer values remain on the suspended stack if this operation switches.
                    // SAFETY: delegated owner/quiescence contract remains held from commit to block.
                    let switched = match activate_destination {
                        Some(activate_destination) => {
                            #[cfg(all(target_arch = "aarch64", target_os = "none"))]
                            {
                                // SAFETY: delegated owner/quiescence contract remains held; the
                                // callback must activate the exact selected generation or never return.
                                unsafe {
                                    scheduler
                                        .bootstrap_block_current_and_switch_with_destination_address_space(
                                            current,
                                            activate_destination,
                                        )
                                }
                            }
                            #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
                            {
                                let _ = activate_destination;
                                Err(SchedulerError::Invariant)
                            }
                        }
                        // SAFETY: compatibility path retains the accepted pre-Step-30 switch behavior.
                        None => unsafe { scheduler.bootstrap_block_current_and_switch(current) },
                    };
                    match switched {
                        Ok(resumed) if resumed == current => {
                            // SAFETY: the exact generation is current again in the same IRQ-masked
                            // owner window. Observe only; Core must commit signal policy before the
                            // retained futex interruption can be consumed.
                            if unsafe { futexes.interruption_pending(current) }
                                .map_err(Error::Interrupt)?
                            {
                                Ok(DispatchOutcome::SignalInterrupted(current))
                            } else {
                                Ok(DispatchOutcome::Complete)
                            }
                        }
                        Ok(_) => Err(Error::Invariant),
                        Err(SchedulerError::NoRunnableThread) => {
                            // This error is documented pre-switch: current remains Running. A signal
                            // may have claimed the committed waiter even though no peer could run;
                            // observe that exact reason before ordinary block-failure cancellation.
                            // SAFETY: exact current generation still owns this failed block path.
                            if unsafe { futexes.interruption_pending(current) }
                                .map_err(Error::Interrupt)?
                            {
                                return Ok(DispatchOutcome::SignalInterrupted(current));
                            }
                            // A racing normal WAKE may instead have consumed the committed waiter.
                            // SAFETY: exact current generation still owns this failed block path.
                            match unsafe { futexes.cancel_wait(current) } {
                                Ok(false) => Ok(DispatchOutcome::Complete),
                                Ok(true) => Err(Error::Scheduler(SchedulerError::NoRunnableThread)),
                                Err(error) => Err(Error::Cancel(error)),
                            }
                        }
                        Err(block_error) => {
                            // Some scheduler errors can be observed only after a switch and resume.
                            // Cancellation is containment only and cannot turn the original privileged
                            // scheduler failure into Linux success.
                            // SAFETY: delegated owner contract applies to the resumed generation.
                            let _ = unsafe { futexes.cancel_wait(current) };
                            Err(Error::Scheduler(block_error))
                        }
                    }
                }
                Err(WaitError::Observe(FutexAccessError::Errno(errno))) => {
                    // SAFETY: synchronous writeback window under the raw-owner contract.
                    unsafe { write_errno_raw(process, address_space, frame, errno) }?;
                    Ok(DispatchOutcome::Complete)
                }
                Err(WaitError::Observe(error)) => Err(Error::Access(error)),
                Err(WaitError::Futex(error)) => match recoverable_wait_errno(error) {
                    Some(errno) => {
                        // SAFETY: synchronous writeback window under the raw-owner contract.
                        unsafe { write_errno_raw(process, address_space, frame, errno) }?;
                        Ok(DispatchOutcome::Complete)
                    }
                    None => Err(Error::Wait(WaitError::Futex(error))),
                },
                Err(error) => Err(Error::Wait(error)),
            }
        }
        MinimumFutexCall::WakePrivate { maximum } => {
            // SAFETY: references exist only for this synchronous key/userword read.
            let word = match unsafe {
                read_private_word(process.as_ref(), address_space.as_ref(), user_address)
            } {
                Ok(word) => word,
                Err(FutexAccessError::Errno(errno)) => {
                    // SAFETY: synchronous writeback window under the raw-owner contract.
                    unsafe { write_errno_raw(process, address_space, frame, errno) }?;
                    return Ok(DispatchOutcome::Complete);
                }
                Err(error) => return Err(Error::Access(error)),
            };

            // SAFETY: delegated non-reentrant runtime contract; delivery failures remain fatal after
            // waiter consumption and are never converted to Linux errno.
            let report =
                unsafe { futexes.wake_with(word.key, maximum, deliver) }.map_err(Error::Wake)?;
            let value = i64::try_from(report.woken).map_err(|_| Error::Invariant)?;
            let result = SyscallReturn::success(value).ok_or(Error::Invariant)?;
            // SAFETY: synchronous final writeback window under the raw-owner contract.
            unsafe { write_result_raw(process, address_space, frame, result) }?;
            Ok(DispatchOutcome::Complete)
        }
    }
}

const fn recoverable_wait_errno(error: FutexError) -> Option<Errno> {
    match error {
        FutexError::Capacity => Some(Errno::EAGAIN),
        FutexError::Unaligned => Some(Errno::EINVAL),
        FutexError::DuplicateWaiter
        | FutexError::WaiterNotFound
        | FutexError::InvalidWaiterState
        | FutexError::QueueCorrupt => None,
    }
}

unsafe fn write_errno_raw<const CAPS: usize, const VMAS: usize, E>(
    process: NonNull<Process<CAPS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    frame: NonNull<ExceptionFrame>,
    errno: Errno,
) -> Result<(), Error<E>> {
    // SAFETY: delegated raw-owner contract covers this short synchronous writeback window.
    unsafe { write_result_raw(process, address_space, frame, SyscallReturn::error(errno)) }
}

unsafe fn write_result_raw<const CAPS: usize, const VMAS: usize, E>(
    process: NonNull<Process<CAPS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    mut frame: NonNull<ExceptionFrame>,
    result: SyscallReturn,
) -> Result<(), Error<E>> {
    // SAFETY: delegated raw-owner contract guarantees these referents are valid and non-conflicting
    // for this helper call. No reference escapes the call.
    unsafe {
        write_result(
            process.as_ref(),
            address_space.as_ref(),
            frame.as_mut(),
            result,
        )
    }
}

fn write_result<const CAPS: usize, const VMAS: usize, E>(
    process: &Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    frame: &mut ExceptionFrame,
    result: SyscallReturn,
) -> Result<(), Error<E>> {
    // Create a fresh current-process witness only for this synchronous writeback. It never survives a
    // potentially blocking scheduler transition.
    let active = address_space
        .current_owner(process)
        .map_err(Error::ProcessAddressSpace)?;
    apply_linux_return(&active, frame, result).map_err(Error::Entry)
}

fn success_value<E>(value: i64) -> Result<SyscallReturn, Error<E>> {
    SyscallReturn::success(value).ok_or(Error::Invariant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_helper_never_manufactures_errno_window_values() {
        assert_eq!(success_value::<()>(0).unwrap().raw(), 0);
        assert_eq!(success_value::<()>(7).unwrap().raw(), 7);
        assert_eq!(success_value::<()>(-1), Err(Error::Invariant));
    }

    #[test]
    fn wait_capacity_and_alignment_are_recoverable_but_corruption_is_not() {
        assert_eq!(
            recoverable_wait_errno(FutexError::Capacity),
            Some(Errno::EAGAIN)
        );
        assert_eq!(
            recoverable_wait_errno(FutexError::Unaligned),
            Some(Errno::EINVAL)
        );
        for error in [
            FutexError::DuplicateWaiter,
            FutexError::WaiterNotFound,
            FutexError::InvalidWaiterState,
            FutexError::QueueCorrupt,
        ] {
            assert_eq!(recoverable_wait_errno(error), None);
        }
    }

    #[test]
    fn non_futex_call_is_rejected_before_runtime_authority_is_needed() {
        let call = MinimumRuntimeCall::Brk { address: 0 };
        assert!(!matches!(call, MinimumRuntimeCall::Futex { .. }));
    }
}
