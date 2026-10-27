// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::{
    Aarch64FpsimdContext, Aarch64RtSignalFramePrefix, Aarch64SignalFrameRecord,
    Aarch64SignalHandlerEntry, Aarch64SignalIntegerContext, Aarch64SignalStack, FRAME_RECORD_BYTES,
    MinimalAarch64RtSignalFrame, RT_SIGFRAME_BYTES, SenderSignalSiginfo,
    place_minimal_signal_frame,
};
use kernal_linux_abi::{Errno, SyscallReturn};
use kernal_linux_signal::{
    DefaultAction, Delivery, Error as SignalError, PreparedSignalDelivery, SA_RESTART, SA_SIGINFO,
    SignalProvenance,
};
use kernal_linux_wait::{WaitInterruptOutcome, WaitSignalCommitOutcome, WaitSleepReceipt};
use kernal_scheduler_smp::{GlobalThreadId, JobControlCommand};
use kernal_user_elf_runtime_aarch64::AARCH64_LINUX_RT_SIGRETURN_TRAMPOLINE;
use kernal_user_entry_aarch64::El0ReturnState;

const SS_DISABLE: i32 = 2;
const SIGSEGV: u8 = 11;
const USER_FRAME_BYTES: usize = RT_SIGFRAME_BYTES + FRAME_RECORD_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterruptedWaitContext {
    ReturnEintr,
    Restart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterruptedWaitSignalCommit {
    ChildWon,
    SignalStale,
    SignalCommitted(Delivery),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterruptedWaitDelivery {
    Reobserve,
    SignalFrameCommitted,
}

/// Final Core action after the private-futex owner's retained signal-interruption marker is resolved.
///
/// `Restarted` means canonical SignalTable policy decided that the syscall must retry and the exact
/// retained futex marker was consumed before the trapped syscall PC was rewound. `SignalFrameCommitted`
/// means one exact PreparedSignal committed, the matching futex marker was then consumed, and its
/// handler frame was installed. The ordinary return hook must not deliver a second signal during the
/// same exception return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterruptedFutexDelivery {
    Restarted,
    SignalFrameCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalWaitInterruptRoute {
    None,
    Wake(GlobalThreadId),
    Futex(GlobalThreadId),
}

struct PreparedHandlerFrame {
    entry: Aarch64SignalHandlerEntry,
    expected: Delivery,
}

enum HandlerFramePreparation {
    BadUserState(&'static str),
    Ready(PreparedHandlerFrame),
}

fn terminate_bad_handler_frame(reason: &str) -> ! {
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 30 signal frame bad user state -> SIGSEGV: ");
        serial.write_str(reason);
        serial.write_str("\n");
    }

    // The exact PreparedSignal receipt has already been revalidated and committed before this helper
    // is entered. Reuse the exact generation-bound signaled exit lifecycle instead of returning to a
    // task whose selected handler/restorer/frame cannot be published. A forced SIGSEGV uses its
    // ordinary core-dump wait bit.
    super::exit::handle_fatal_signal(SIGSEGV, true)
}

fn handler_frame_copy_fault_is_user(error: kernal_usercopy::Error) -> bool {
    matches!(
        error,
        kernal_usercopy::Error::NullGuard
            | kernal_usercopy::Error::OutsideUserRange
            | kernal_usercopy::Error::Overflow
            | kernal_usercopy::Error::Fault
    )
}

/// Builds the userspace context that a signal handler must later restore for an interrupted wait.
///
/// AArch64 exception entry records `ELR_EL1` after the trapping SVC instruction. Linux-visible EINTR
/// therefore keeps that continuation PC and replaces only x0 in the saved signal context. SA_RESTART
/// re-executes the original SVC by moving the saved PC back exactly one fixed-width AArch64
/// instruction. The restart state is validated through the canonical EL0 return-state owner before it
/// can be embedded in a signal frame. This helper mutates only a copy; the live exception frame stays
/// untouched until the normal prepared-signal transaction commits.
pub(super) fn interrupted_wait_snapshot(
    frame: &ExceptionFrame,
    context: InterruptedWaitContext,
) -> Result<ExceptionFrame, ()> {
    let mut snapshot = *frame;
    match context {
        InterruptedWaitContext::ReturnEintr => {
            snapshot.x[0] = SyscallReturn::error(Errno::EINTR).as_u64_bits();
        }
        InterruptedWaitContext::Restart => {
            let restart_pc = snapshot.elr_el1.checked_sub(4).ok_or(())?;
            let validated = El0ReturnState::new(restart_pc, snapshot.spsr_el1, snapshot.sp_el0)
                .map_err(|_| ())?;
            snapshot.elr_el1 = validated.return_pc();
            snapshot.spsr_el1 = validated.spsr_el1();
            snapshot.sp_el0 = validated.user_sp();
        }
    }
    Ok(snapshot)
}

fn exact_wait_route(
    outcome: WaitInterruptOutcome,
    expected: GlobalThreadId,
) -> Result<SignalWaitInterruptRoute, ()> {
    match outcome {
        WaitInterruptOutcome::Wake(thread) if thread == expected => {
            Ok(SignalWaitInterruptRoute::Wake(thread))
        }
        WaitInterruptOutcome::Wake(_) => Err(()),
        WaitInterruptOutcome::NotWaiting => Ok(SignalWaitInterruptRoute::Futex(expected)),
        WaitInterruptOutcome::InterruptedNoWake
        | WaitInterruptOutcome::AlreadyInterrupted
        | WaitInterruptOutcome::ChildNotified => Ok(SignalWaitInterruptRoute::None),
    }
}

fn finish_wait_interrupt_route(
    route: SignalWaitInterruptRoute,
) -> Result<Option<GlobalThreadId>, ()> {
    match route {
        SignalWaitInterruptRoute::None => Ok(None),
        SignalWaitInterruptRoute::Wake(thread) => Ok(Some(thread)),
        SignalWaitInterruptRoute::Futex(target) => {
            // SAFETY: callers enter from the signal-send SVC while the current PE retains its
            // IRQ-masked scheduler owner window. The exact target was selected by the canonical
            // SignalTable/LinuxIdentity policy and all RuntimeCell borrows ended before this call.
            let route =
                unsafe { super::futex::interrupt_wait_after_signal(target) }.map_err(|_| ())?;
            match route {
                super::futex::SignalInterruptRoute::NotWaiting
                | super::futex::SignalInterruptRoute::Retained
                | super::futex::SignalInterruptRoute::AlreadyInterrupted => Ok(None),
                super::futex::SignalInterruptRoute::Wake(thread) if thread == target => {
                    Ok(Some(thread))
                }
                super::futex::SignalInterruptRoute::Wake(_) => Err(()),
            }
        }
    }
}

/// After a process-directed signal queue commit, marks at most one exact blocking-owner registration
/// as interrupted and returns only an exact scheduler wake obligation.
///
/// Target choice is the canonical next-delivery policy from SignalTable/LinuxIdentity. WaitTable is
/// authoritative when it owns the exact generation. Only `WaitInterruptOutcome::NotWaiting` falls
/// through after the RuntimeCell borrow ends to the sole private-futex owner. This prevents a signal
/// from waking/counting two blocking owners and keeps normal FUTEX_WAKE disjoint from signal-owned
/// interruption.
pub(super) fn interrupt_process_wait_after_signal(
    pid: NonZeroU32,
) -> Result<Option<GlobalThreadId>, ()> {
    let route = super::runtime::with_linux_runtime(|state| {
        let Some((target, _policy)) = state.process_signal_wait_interrupt_target(pid)? else {
            return Ok::<_, super::runtime::Error>(SignalWaitInterruptRoute::None);
        };
        let outcome = state.interrupt_wait_for_signal(target)?;
        exact_wait_route(outcome, target).map_err(|_| super::runtime::Error::InvalidState)
    })
    .map_err(|_| ())?
    .map_err(|_| ())?;
    finish_wait_interrupt_route(route)
}

/// After an exact thread-directed signal queue commit, marks only that exact generation's canonical
/// blocking owner when its actual next signal delivery interrupts the syscall.
pub(super) fn interrupt_thread_wait_after_signal(
    target: GlobalThreadId,
) -> Result<Option<GlobalThreadId>, ()> {
    let route = super::runtime::with_linux_runtime(|state| {
        if state
            .signal_syscall_interruption_for_thread(target)?
            .is_none()
        {
            return Ok::<_, super::runtime::Error>(SignalWaitInterruptRoute::None);
        }
        let outcome = state.interrupt_wait_for_signal(target)?;
        exact_wait_route(outcome, target).map_err(|_| super::runtime::Error::InvalidState)
    })
    .map_err(|_| ())?
    .map_err(|_| ())?;
    finish_wait_interrupt_route(route)
}

/// Routes only an exact scheduler wake obligation returned by a canonical blocking owner.
///
/// All RuntimeCell/FutexTable borrows have already ended before this function is entered. A local
/// target is made ready only through this PE's canonical scheduler owner. A remote target is published
/// through the existing remote-wake mailbox before its owner PE receives the reschedule SGI. Any
/// failure after the SignalTable/blocking-owner commit is an internal fail-closed error and is never
/// converted into a Linux errno.
pub(super) fn route_exact_wait_wake_after_signal(wake: Option<GlobalThreadId>) -> Result<(), ()> {
    let Some(target) = wake else {
        return Ok(());
    };
    let current_cpu = super::super::current_cpu_index();
    let target_cpu = usize::from(target.cpu.0);
    let target_scheduler = super::super::CPU_SCHEDULERS.get(target_cpu).ok_or(())?;
    if target_cpu == current_cpu {
        // SAFETY: the signal-send SVC retains this PE's IRQ-masked scheduler owner window and the
        // target generation came only from an exact canonical blocking-owner wake obligation.
        unsafe { target_scheduler.bootstrap_wake_local_exact(target) }.map_err(|_| ())
    } else {
        super::remote_wake_with_reschedule(target_scheduler, target).map_err(|_| ())
    }
}

/// Completes the post-queue process-directed wait interruption without retaining runtime owners
/// across scheduler mutation.
pub(super) fn interrupt_and_wake_process_wait_after_signal(pid: NonZeroU32) -> Result<(), ()> {
    let wake = interrupt_process_wait_after_signal(pid)?;
    route_exact_wait_wake_after_signal(wake)
}

/// Completes the post-queue thread-directed wait interruption for one exact scheduler generation.
pub(super) fn interrupt_and_wake_thread_wait_after_signal(
    target: GlobalThreadId,
) -> Result<(), ()> {
    let wake = interrupt_thread_wait_after_signal(target)?;
    route_exact_wait_wake_after_signal(wake)
}

/// Commits a prepared signal and consumes its exact interrupted-wait marker under one RuntimeCell
/// borrow after every fallible signal-frame step has completed.
///
/// Child exit remains authoritative: `Notified` is consumed first as `ChildWon` and the prepared
/// signal stays pending. Only an exact retained `Interrupted` receipt may consume the prepared signal.
/// Because SignalTable commit and WaitTable interruption consumption occur under the same serialized
/// runtime borrow, no other thread can steal a process-pending signal between those two commits.
/// If the prepared signal became stale before this borrow, consume only the exact retained Wait
/// interruption and return `SignalStale` so the caller can reobserve/reblock instead of fabricating
/// EINTR/restart from stale signal authority.
pub(super) fn commit_interrupted_wait_signal(
    current: GlobalThreadId,
    receipt: WaitSleepReceipt,
    prepared: PreparedSignalDelivery,
) -> Result<InterruptedWaitSignalCommit, ()> {
    if receipt.thread() != current {
        return Err(());
    }

    super::runtime::with_linux_runtime(move |state| {
        match state.commit_wait_sleep_signal_aware(&receipt)? {
            WaitSignalCommitOutcome::AlreadyWoken => {
                return Ok::<_, super::runtime::Error>(InterruptedWaitSignalCommit::ChildWon);
            }
            WaitSignalCommitOutcome::Sleep => {
                // This helper is valid only after signal-side Interrupted commit. If a caller reaches
                // it from Prepared state, undo the compatibility mutation and fail closed.
                let _ = state.cancel_wait_sleep(receipt)?;
                return Err(super::runtime::Error::InvalidState);
            }
            WaitSignalCommitOutcome::Interrupted => {}
        }

        // Sample the resumed TTBR0 generation only while the sole RuntimeCell is held. This closes
        // the observation/revalidation window between scheduler resume and signal-owner commit.
        let resumed_switch_generation = kernal_process_aarch64::current_user_switch_generation()
            .ok_or(super::runtime::Error::InvalidState)?;
        let committed = match state.with_current_signal_delivery(
            current,
            resumed_switch_generation,
            |process, _address_space, _objects, identities, signals| {
                signals.commit_prepared_delivery(identities, process, current, prepared)
            },
        )? {
            Ok(committed) => committed,
            Err(SignalError::PreparedDeliveryStale) => {
                if !state.consume_interrupted_wait_for_signal(receipt)? {
                    return Err(super::runtime::Error::InvalidState);
                }
                return Ok(InterruptedWaitSignalCommit::SignalStale);
            }
            Err(error) => return Err(super::runtime::Error::Signal(error)),
        };

        if !state.consume_interrupted_wait_for_signal(receipt)? {
            // RuntimeCell serialization makes this unreachable after the Interrupted observation
            // above; treat any future semantic widening as an invariant rather than duplicating a
            // signal delivery after child notification.
            return Err(super::runtime::Error::InvalidState);
        }
        Ok(InterruptedWaitSignalCommit::SignalCommitted(committed))
    })
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn consume_interrupted_wait_for_reobserve(receipt: WaitSleepReceipt) -> Result<(), ()> {
    super::runtime::with_linux_runtime(|state| state.consume_interrupted_wait_for_signal(receipt))
        .map_err(|_| ())?
        .map_err(|_| ())?;
    Ok(())
}

fn prepare_handler_frame(
    snapshot: &ExceptionFrame,
    current: GlobalThreadId,
    switch_generation: u64,
    prepared: &PreparedSignalDelivery,
) -> Result<Option<HandlerFramePreparation>, ()> {
    let Delivery::Handler {
        signal,
        handler,
        previous_mask,
        effective_mask,
    } = prepared.delivery()
    else {
        return Ok(None);
    };

    let restorer = handler
        .restorer()
        .unwrap_or(AARCH64_LINUX_RT_SIGRETURN_TRAMPOLINE);
    if handler.entry() & 3 != 0 || restorer & 3 != 0 {
        return Ok(Some(HandlerFramePreparation::BadUserState(
            "misaligned handler/restorer",
        )));
    }

    let entry_points_executable = super::runtime::with_linux_runtime(|state| {
        state.with_current_signal_delivery(
            current,
            switch_generation,
            |process, address_space, objects, _identities, _signals| {
                let mut handler_executable = false;
                let mut restorer_executable = false;
                for index in 0..super::runtime::STEP15_RUNTIME_VMAS {
                    let Some(vma) = address_space
                        .user_vma_at(process, objects, process.address_space_handle(), index)
                        .map_err(|_| ())?
                    else {
                        break;
                    };
                    let end = vma.end().ok_or(())?;
                    if vma.start <= handler.entry() && handler.entry() < end {
                        handler_executable = vma.perms.executable();
                    }
                    if vma.start <= restorer && restorer < end {
                        restorer_executable = vma.perms.executable();
                    }
                    if handler_executable && restorer_executable {
                        break;
                    }
                }
                Ok::<bool, ()>(handler_executable && restorer_executable)
            },
        )
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())?;
    if !entry_points_executable {
        return Ok(Some(HandlerFramePreparation::BadUserState(
            "handler/restorer mapping is not executable",
        )));
    }

    let siginfo = match prepared.provenance() {
        SignalProvenance::User {
            sender_pid,
            sender_uid,
        } => SenderSignalSiginfo::process_directed(signal.number(), sender_pid, sender_uid),
        SignalProvenance::Tkill {
            sender_pid,
            sender_uid,
        } => SenderSignalSiginfo::thread_directed(signal.number(), sender_pid, sender_uid),
        SignalProvenance::Kernel => SenderSignalSiginfo::kernel_directed(signal.number()),
        SignalProvenance::Child(child) => match child.code() {
            kernal_linux_signal::ChildSignalCode::Exited => {
                Some(SenderSignalSiginfo::child_exited(
                    child.child_pid(),
                    child.child_uid(),
                    child.status(),
                ))
            }
            kernal_linux_signal::ChildSignalCode::Killed => SenderSignalSiginfo::child_signaled(
                child.child_pid(),
                child.child_uid(),
                child.status(),
                false,
            ),
            kernal_linux_signal::ChildSignalCode::Dumped => SenderSignalSiginfo::child_signaled(
                child.child_pid(),
                child.child_uid(),
                child.status(),
                true,
            ),
            kernal_linux_signal::ChildSignalCode::Stopped => SenderSignalSiginfo::child_stopped(
                child.child_pid(),
                child.child_uid(),
                child.status(),
            ),
            kernal_linux_signal::ChildSignalCode::Continued => Some(
                SenderSignalSiginfo::child_continued(child.child_pid(), child.child_uid()),
            ),
        },
    };
    let Some(siginfo) = siginfo else {
        return Err(());
    };

    let placement = match place_minimal_signal_frame(snapshot.sp_el0) {
        Ok(placement) => placement,
        Err(_) => {
            return Ok(Some(HandlerFramePreparation::BadUserState(
                "signal stack underflow",
            )));
        }
    };
    match kernal_usercopy::UserRange::new(placement.frame_base(), USER_FRAME_BYTES) {
        Ok(_) => {}
        Err(kernal_usercopy::Error::TooLarge) => return Err(()),
        Err(_) => {
            return Ok(Some(HandlerFramePreparation::BadUserState(
                "signal frame outside userspace",
            )));
        }
    }

    let frame_writable = super::runtime::with_linux_runtime(|state| {
        state.with_current_signal_delivery(
            current,
            switch_generation,
            |process, address_space, objects, _identities, _signals| {
                let frame_start = placement.frame_base();
                let frame_end = frame_start.checked_add(USER_FRAME_BYTES as u64).ok_or(())?;
                let mut cursor = frame_start;
                for index in 0..super::runtime::STEP15_RUNTIME_VMAS {
                    let Some(vma) = address_space
                        .user_vma_at(process, objects, process.address_space_handle(), index)
                        .map_err(|_| ())?
                    else {
                        break;
                    };
                    let vma_end = vma.end().ok_or(())?;
                    if cursor < vma.start {
                        break;
                    }
                    if cursor >= vma_end {
                        continue;
                    }
                    if !vma.perms.writable() {
                        return Ok::<bool, ()>(false);
                    }
                    cursor = core::cmp::min(frame_end, vma_end);
                    if cursor == frame_end {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
        )
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())?;
    if !frame_writable {
        return Ok(Some(HandlerFramePreparation::BadUserState(
            "signal frame mapping is not fully writable",
        )));
    }

    let integer = Aarch64SignalIntegerContext::new(
        0,
        snapshot.x,
        snapshot.sp_el0,
        snapshot.elr_el1,
        snapshot.spsr_el1,
    );
    let prefix = Aarch64RtSignalFramePrefix::new(
        siginfo.into_bytes(),
        0,
        0,
        Aarch64SignalStack::new(0, SS_DISABLE, 0),
        previous_mask.bits(),
        integer,
    );
    // SAFETY: this path is the exact current EL0 generation's synchronous return path. It captures
    // architecture state only and neither switches nor publishes scheduler state.
    let fpsimd = unsafe { kernal_context_aarch64::capture_current_el0_fpsimd() };
    let minimal = MinimalAarch64RtSignalFrame::new(
        prefix,
        Aarch64FpsimdContext::new(fpsimd.fpsr(), fpsimd.fpcr(), *fpsimd.vregs()),
    );
    let mut bytes = [0u8; USER_FRAME_BYTES];
    if minimal
        .encode_into(&mut bytes[..RT_SIGFRAME_BYTES])
        .is_err()
    {
        return Err(());
    }
    let record = Aarch64SignalFrameRecord::new(snapshot.x[29], snapshot.x[30]).to_ne_bytes();
    bytes[RT_SIGFRAME_BYTES..].copy_from_slice(&record);
    if let Err(error) = kernal_usercopy_aarch64::copy_to_user(placement.frame_base(), &bytes) {
        if handler_frame_copy_fault_is_user(error) {
            return Ok(Some(HandlerFramePreparation::BadUserState(
                "signal frame usercopy fault",
            )));
        }
        return Err(());
    }

    let siginfo_arguments = handler.flags() & SA_SIGINFO != 0;
    let entry = Aarch64SignalHandlerEntry::new(
        signal.number(),
        handler.entry(),
        restorer,
        placement,
        siginfo_arguments,
    )
    .map_err(|_| ())?;

    Ok(Some(HandlerFramePreparation::Ready(PreparedHandlerFrame {
        entry,
        expected: Delivery::Handler {
            signal,
            handler,
            previous_mask,
            effective_mask,
        },
    })))
}

/// Completes one exact signal-interrupted blocking wait after the scheduler generation is current.
///
/// Handler frame construction and usercopy remain non-destructive with respect to canonical signal
/// and wait ownership. Only after every fallible frame step succeeds or classifies bad user state does
/// `commit_interrupted_wait_signal` atomically resolve ChildWon/SignalStale versus this exact signal.
/// A still-current BadUserState is then forced to SIGSEGV; stale signal authority never kills this
/// thread. A ready frame is applied only after the same linear commit.
pub(super) fn deliver_interrupted_wait(
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
    receipt: WaitSleepReceipt,
) -> Result<InterruptedWaitDelivery, ()> {
    if receipt.thread() != current {
        return Err(());
    }
    let (resumed_switch_generation, prepared) = super::runtime::with_linux_runtime(|state| {
        // Couple the fresh generation sample to the RuntimeCell owner that immediately consumes it.
        let resumed_switch_generation = kernal_process_aarch64::current_user_switch_generation()
            .ok_or(super::runtime::Error::InvalidState)?;
        let prepared = state.with_current_signal_delivery(
            current,
            resumed_switch_generation,
            |process, _address_space, _objects, identities, signals| {
                signals.prepare_delivery_for_thread(identities, process, current)
            },
        )?;
        Ok::<_, super::runtime::Error>((resumed_switch_generation, prepared))
    })
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let prepared = prepared.map_err(|_| ())?;

    let Some(prepared) = prepared else {
        consume_interrupted_wait_for_reobserve(receipt)?;
        return Ok(InterruptedWaitDelivery::Reobserve);
    };

    match prepared.delivery() {
        Delivery::Default {
            action: DefaultAction::Ignore,
            ..
        } => match commit_interrupted_wait_signal(current, receipt, prepared)? {
            InterruptedWaitSignalCommit::ChildWon | InterruptedWaitSignalCommit::SignalStale => {
                Ok(InterruptedWaitDelivery::Reobserve)
            }
            InterruptedWaitSignalCommit::SignalCommitted(Delivery::Default {
                action: DefaultAction::Ignore,
                ..
            }) => Ok(InterruptedWaitDelivery::Reobserve),
            InterruptedWaitSignalCommit::SignalCommitted(_) => Err(()),
        },
        Delivery::Default {
            signal,
            action: DefaultAction::Terminate { core_dump },
        } => match commit_interrupted_wait_signal(current, receipt, prepared)? {
            InterruptedWaitSignalCommit::ChildWon | InterruptedWaitSignalCommit::SignalStale => {
                Ok(InterruptedWaitDelivery::Reobserve)
            }
            InterruptedWaitSignalCommit::SignalCommitted(committed)
                if committed
                    == (Delivery::Default {
                        signal,
                        action: DefaultAction::Terminate { core_dump },
                    }) =>
            {
                super::exit::handle_fatal_signal(signal.number(), core_dump)
            }
            InterruptedWaitSignalCommit::SignalCommitted(_) => fail_closed_after_signal_commit(
                "KERNAL/ARM64: Step 30 interrupted fatal signal changed after commit\n",
            ),
        },
        Delivery::Default { .. } => {
            // Stop/Continue do not interrupt this syscall. If disposition changed after the queue-side
            // interruption observation, release only the exact Wait marker and leave the signal pending
            // for the dedicated job-control owner.
            consume_interrupted_wait_for_reobserve(receipt)?;
            Ok(InterruptedWaitDelivery::Reobserve)
        }
        Delivery::Handler { handler, .. } => {
            let expected = prepared.delivery();
            let context = if handler.flags() & SA_RESTART != 0 {
                InterruptedWaitContext::Restart
            } else {
                InterruptedWaitContext::ReturnEintr
            };
            let snapshot = interrupted_wait_snapshot(frame, context)?;
            let Some(frame_preparation) =
                prepare_handler_frame(&snapshot, current, resumed_switch_generation, &prepared)?
            else {
                return Err(());
            };

            match frame_preparation {
                HandlerFramePreparation::BadUserState(reason) => {
                    match commit_interrupted_wait_signal(current, receipt, prepared)? {
                        InterruptedWaitSignalCommit::ChildWon
                        | InterruptedWaitSignalCommit::SignalStale => {
                            Ok(InterruptedWaitDelivery::Reobserve)
                        }
                        InterruptedWaitSignalCommit::SignalCommitted(committed)
                            if committed == expected =>
                        {
                            terminate_bad_handler_frame(reason)
                        }
                        InterruptedWaitSignalCommit::SignalCommitted(_) => {
                            fail_closed_after_signal_commit(
                                "KERNAL/ARM64: Step 30 bad interrupted signal changed after commit\n",
                            )
                        }
                    }
                }
                HandlerFramePreparation::Ready(prepared_frame) => {
                    match commit_interrupted_wait_signal(current, receipt, prepared)? {
                        InterruptedWaitSignalCommit::ChildWon
                        | InterruptedWaitSignalCommit::SignalStale => {
                            Ok(InterruptedWaitDelivery::Reobserve)
                        }
                        InterruptedWaitSignalCommit::SignalCommitted(committed)
                            if committed == prepared_frame.expected =>
                        {
                            prepared_frame.entry.apply(
                                &mut frame.x,
                                &mut frame.sp_el0,
                                &mut frame.elr_el1,
                            );
                            Ok(InterruptedWaitDelivery::SignalFrameCommitted)
                        }
                        InterruptedWaitSignalCommit::SignalCommitted(_) => {
                            fail_closed_after_signal_commit(
                                "KERNAL/ARM64: Step 30 interrupted handler changed after commit\n",
                            )
                        }
                    }
                }
            }
        }
    }
}

fn restart_interrupted_futex(frame: &mut ExceptionFrame) -> Result<InterruptedFutexDelivery, ()> {
    let restarted = interrupted_wait_snapshot(frame, InterruptedWaitContext::Restart)?;
    frame.sp_el0 = restarted.sp_el0;
    frame.elr_el1 = restarted.elr_el1;
    frame.spsr_el1 = restarted.spsr_el1;
    Ok(InterruptedFutexDelivery::Restarted)
}

fn prove_interrupted_futex_marker(current: GlobalThreadId) -> Result<(), ()> {
    // SAFETY: the resumed SVC owns the exact current scheduler generation and local IRQs remain
    // masked. This is observation only; the marker stays retained while SignalTable is revalidated.
    let pending =
        unsafe { super::futex::interruption_pending_after_resume(current) }.map_err(|_| ())?;
    if pending { Ok(()) } else { Err(()) }
}

fn consume_interrupted_futex_marker_for_retry(current: GlobalThreadId) -> Result<(), ()> {
    // SAFETY: this exact generation is current in the resumed IRQ-masked SVC. Canonical signal policy
    // has decided that the prior interruption claim no longer produces this syscall result.
    let consumed =
        unsafe { super::futex::consume_interrupted_after_signal(current) }.map_err(|_| ())?;
    if consumed { Ok(()) } else { Err(()) }
}

fn restart_interrupted_futex_after_retry_resolution(
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
) -> Result<InterruptedFutexDelivery, ()> {
    consume_interrupted_futex_marker_for_retry(current)?;
    restart_interrupted_futex(frame)
}

fn consume_interrupted_futex_marker_after_signal_commit(
    current: GlobalThreadId,
    failure: &'static str,
) {
    // SAFETY: the exact canonical signal receipt has already been revalidated and committed before this helper
    // is entered. The matching futex marker must still exist until this exact post-commit consumption.
    match unsafe { super::futex::consume_interrupted_after_signal(current) } {
        Ok(true) => {}
        Ok(false) | Err(_) => fail_closed_after_signal_commit(failure),
    }
}

fn restart_interrupted_futex_after_signal_commit(
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
) -> InterruptedFutexDelivery {
    consume_interrupted_futex_marker_after_signal_commit(
        current,
        "KERNAL/ARM64: Step 30 futex marker missing after signal commit\n",
    );
    match restart_interrupted_futex(frame) {
        Ok(delivery) => delivery,
        Err(()) => fail_closed_after_signal_commit(
            "KERNAL/ARM64: Step 30 futex restart state invalid after signal commit\n",
        ),
    }
}

fn commit_prepared_current_signal(
    current: GlobalThreadId,
    switch_generation: u64,
    prepared: PreparedSignalDelivery,
) -> Result<Result<Delivery, SignalError>, ()> {
    super::runtime::with_linux_runtime(|state| {
        state.with_current_signal_delivery(
            current,
            switch_generation,
            |process, _address_space, _objects, identities, signals| {
                signals.commit_prepared_delivery(identities, process, current, prepared)
            },
        )
    })
    .map_err(|_| ())?
    .map_err(|_| ())
}

/// Completes one signal-interrupted private FUTEX_WAIT while the exact futex interruption marker is
/// still retained and the resumed generation is current again.
///
/// The caller must first restore x0..x5 from the original SVC-entry request because the futex trap
/// provisionally staged Linux success before sleeping. That restoration is what lets SA_RESTART save
/// the original syscall arguments while the non-restart path replaces only x0 with `-EINTR`.
///
/// SignalTable policy is always revalidated while the marker remains retained. Successful signal
/// commits consume the exact marker only afterwards; no-signal, stale-receipt and non-interrupting
/// default decisions consume it as the explicit retry resolution before rewinding the SVC. Missing or
/// stale marker authority fails closed and provisional futex success is never exposed.
pub(super) fn deliver_interrupted_futex(
    frame: &mut ExceptionFrame,
    current: GlobalThreadId,
) -> Result<InterruptedFutexDelivery, ()> {
    prove_interrupted_futex_marker(current)?;

    let (resumed_switch_generation, prepared) = super::runtime::with_linux_runtime(|state| {
        let resumed_switch_generation = kernal_process_aarch64::current_user_switch_generation()
            .ok_or(super::runtime::Error::InvalidState)?;
        let prepared = state.with_current_signal_delivery(
            current,
            resumed_switch_generation,
            |process, _address_space, _objects, identities, signals| {
                signals.prepare_delivery_for_thread(identities, process, current)
            },
        )?;
        Ok::<_, super::runtime::Error>((resumed_switch_generation, prepared))
    })
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let prepared = prepared.map_err(|_| ())?;

    let Some(prepared) = prepared else {
        return restart_interrupted_futex_after_retry_resolution(frame, current);
    };

    match prepared.delivery() {
        Delivery::Default {
            action: DefaultAction::Ignore,
            ..
        } => match commit_prepared_current_signal(current, resumed_switch_generation, prepared)? {
            Ok(Delivery::Default {
                action: DefaultAction::Ignore,
                ..
            }) => Ok(restart_interrupted_futex_after_signal_commit(
                frame, current,
            )),
            Ok(_) => fail_closed_after_signal_commit(
                "KERNAL/ARM64: Step 30 futex ignored signal changed after commit\n",
            ),
            Err(SignalError::PreparedDeliveryStale) => {
                restart_interrupted_futex_after_retry_resolution(frame, current)
            }
            Err(_) => Err(()),
        },
        Delivery::Default {
            signal,
            action: DefaultAction::Terminate { core_dump },
        } => match commit_prepared_current_signal(current, resumed_switch_generation, prepared)? {
            Ok(committed)
                if committed
                    == (Delivery::Default {
                        signal,
                        action: DefaultAction::Terminate { core_dump },
                    }) =>
            {
                consume_interrupted_futex_marker_after_signal_commit(
                    current,
                    "KERNAL/ARM64: Step 30 futex marker missing after fatal signal commit\n",
                );
                super::exit::handle_fatal_signal(signal.number(), core_dump)
            }
            Ok(_) => fail_closed_after_signal_commit(
                "KERNAL/ARM64: Step 30 futex fatal signal changed after commit\n",
            ),
            Err(SignalError::PreparedDeliveryStale) => {
                restart_interrupted_futex_after_retry_resolution(frame, current)
            }
            Err(_) => Err(()),
        },
        Delivery::Default { .. } => {
            // Stop/Continue are intentionally not consumed here. They did not qualify as syscall
            // interruptions at sender observation time; if disposition changed meanwhile, release
            // the exact retained futex claim, retry FUTEX_WAIT and leave the signal pending for the
            // dedicated job-control return owner.
            restart_interrupted_futex_after_retry_resolution(frame, current)
        }
        Delivery::Handler { handler, .. } => {
            let expected = prepared.delivery();
            let context = if handler.flags() & SA_RESTART != 0 {
                InterruptedWaitContext::Restart
            } else {
                InterruptedWaitContext::ReturnEintr
            };
            let snapshot = interrupted_wait_snapshot(frame, context)?;
            let Some(frame_preparation) =
                prepare_handler_frame(&snapshot, current, resumed_switch_generation, &prepared)?
            else {
                return Err(());
            };

            match frame_preparation {
                HandlerFramePreparation::BadUserState(reason) => {
                    match commit_prepared_current_signal(
                        current,
                        resumed_switch_generation,
                        prepared,
                    )? {
                        Ok(committed) if committed == expected => {
                            consume_interrupted_futex_marker_after_signal_commit(
                                current,
                                "KERNAL/ARM64: Step 30 futex marker missing after bad-frame signal commit\n",
                            );
                            terminate_bad_handler_frame(reason)
                        }
                        Ok(_) => fail_closed_after_signal_commit(
                            "KERNAL/ARM64: Step 30 bad futex signal changed after commit\n",
                        ),
                        Err(SignalError::PreparedDeliveryStale) => {
                            restart_interrupted_futex_after_retry_resolution(frame, current)
                        }
                        Err(_) => Err(()),
                    }
                }
                HandlerFramePreparation::Ready(prepared_frame) => {
                    match commit_prepared_current_signal(
                        current,
                        resumed_switch_generation,
                        prepared,
                    )? {
                        Ok(committed) if committed == prepared_frame.expected => {
                            consume_interrupted_futex_marker_after_signal_commit(
                                current,
                                "KERNAL/ARM64: Step 30 futex marker missing after handler signal commit\n",
                            );
                            prepared_frame.entry.apply(
                                &mut frame.x,
                                &mut frame.sp_el0,
                                &mut frame.elr_el1,
                            );
                            Ok(InterruptedFutexDelivery::SignalFrameCommitted)
                        }
                        Ok(_) => fail_closed_after_signal_commit(
                            "KERNAL/ARM64: Step 30 futex handler changed after commit\n",
                        ),
                        Err(SignalError::PreparedDeliveryStale) => {
                            restart_interrupted_futex_after_retry_resolution(frame, current)
                        }
                        Err(_) => Err(()),
                    }
                }
            }
        }
    }
}

fn fail_closed_after_signal_commit(message: &str) -> ! {
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str(message);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Attempts one pending signal delivery after an already-successful SVC dispatch and before `eret`.
///
/// Prepare is non-destructive with respect to canonical SignalTable state. Every fallible frame
/// construction/usercopy step completes before the exact PreparedSignal receipt is revalidated. Bad
/// user frame state forces SIGSEGV only after that receipt commits; a stale process-directed receipt
/// is ignored for this thread. A ready handler frame becomes live only after its same receipt commits.
pub(super) fn deliver_on_return(frame: &mut ExceptionFrame) -> Result<(), ()> {
    let cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(cpu).ok_or(())?;
    // SAFETY: this hook runs synchronously on the same IRQ-masked SVC owner PE immediately before
    // return to EL0. The scheduler's current generation is therefore the exact trap owner.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;

    let prepared = super::runtime::with_linux_runtime(|state| {
        state.with_current_signal_delivery(
            current,
            frame.entry_switch_generation(),
            |process, _address_space, _objects, identities, signals| {
                signals.prepare_delivery_for_thread(identities, process, current)
            },
        )
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())?;

    let Some(prepared) = prepared else {
        return Ok(());
    };

    match prepared.delivery() {
        Delivery::Default {
            action: DefaultAction::Ignore,
            ..
        } => {
            let committed = super::runtime::with_linux_runtime(|state| {
                state.with_current_signal_delivery(
                    current,
                    frame.entry_switch_generation(),
                    |process, _address_space, _objects, identities, signals| {
                        signals.commit_prepared_delivery(identities, process, current, prepared)
                    },
                )
            })
            .map_err(|_| ())?
            .map_err(|_| ())?
            .map_err(|_| ())?;
            if !matches!(
                committed,
                Delivery::Default {
                    action: DefaultAction::Ignore,
                    ..
                }
            ) {
                fail_closed_after_signal_commit(
                    "KERNAL/ARM64: Step 30 ignored signal delivery changed after commit\n",
                );
            }
            Ok(())
        }
        Delivery::Default {
            signal,
            action: DefaultAction::Terminate { core_dump },
        } => {
            // Fatal default delivery is the one default effect that becomes destructive here. The
            // exact prepared receipt must be consumed before lifecycle state is persisted; after that
            // commit no error path is allowed to return to the terminated EL0 generation.
            let committed = super::runtime::with_linux_runtime(|state| {
                state.with_current_signal_delivery(
                    current,
                    frame.entry_switch_generation(),
                    |process, _address_space, _objects, identities, signals| {
                        signals.commit_prepared_delivery(identities, process, current, prepared)
                    },
                )
            })
            .map_err(|_| ())?
            .map_err(|_| ())?
            .map_err(|_| ())?;
            if committed
                != (Delivery::Default {
                    signal,
                    action: DefaultAction::Terminate { core_dump },
                })
            {
                fail_closed_after_signal_commit(
                    "KERNAL/ARM64: Step 30 fatal signal delivery changed after commit\n",
                );
            }

            super::exit::handle_fatal_signal(signal.number(), core_dump)
        }
        Delivery::Default {
            signal,
            action: DefaultAction::Stop,
        } => {
            let expected = Delivery::Default {
                signal,
                action: DefaultAction::Stop,
            };
            let dispatch = super::runtime::with_linux_runtime(|state| {
                // All fallible target selection occurs before consuming the prepared signal. The
                // exact target batch remains valid through the immediately-following signal commit
                // because RuntimeCell serializes LinuxIdentity and Process membership for this window.
                let pid = state
                    .with_current_process_identity(current, |process, identities| {
                        identities.bound_pid(process)
                    })?
                    .map_err(|_| super::runtime::Error::InvalidState)?;
                let targets = state.job_control_targets_for_pid(pid)?;
                let committed = state.with_current_signal_delivery(
                    current,
                    frame.entry_switch_generation(),
                    |process, _address_space, _objects, identities, signals| {
                        signals.commit_prepared_delivery(identities, process, current, prepared)
                    },
                )?;
                match committed {
                    Err(SignalError::PreparedDeliveryStale) => Ok(None),
                    Err(error) => Err(super::runtime::Error::Signal(error)),
                    Ok(committed) if committed == expected => {
                        let dispatch = super::step30_child_exit::begin_process_job_control_transaction(
                            targets,
                            JobControlCommand::Stop,
                            Some(signal.number()),
                        )
                        .unwrap_or_else(|_| {
                            fail_closed_after_signal_commit(
                                "KERNAL/ARM64: Step 30 stop transaction begin failed after signal commit\n",
                            )
                        });
                        Ok(Some(dispatch))
                    }
                    Ok(_) => fail_closed_after_signal_commit(
                        "KERNAL/ARM64: Step 30 stop delivery changed after signal commit\n",
                    ),
                }
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let Some(dispatch) = dispatch else {
                return Ok(());
            };
            let dispatched = super::step30_child_exit::dispatch_process_job_control(dispatch, cpu)
                .unwrap_or_else(|_| {
                    fail_closed_after_signal_commit(
                        "KERNAL/ARM64: Step 30 stop scheduler dispatch failed after signal commit\n",
                    )
                });
            // SAFETY: this return hook owns the current CPU's IRQ-masked synchronous SVC window. The
            // signal generation and scheduler transaction are already authoritative, so any finish
            // failure is fail-stop rather than a recoverable signal-delivery error.
            if unsafe {
                super::step30_child_exit::finish_process_job_control_dispatch(dispatched, cpu)
            }
            .is_err()
            {
                fail_closed_after_signal_commit(
                    "KERNAL/ARM64: Step 30 stop completion failed after signal commit\n",
                );
            }

            // A Stop of the trapping generation switches this synchronous SVC away and this call
            // returns only after a later SIGCONT makes that exact generation runnable again. The
            // destination activation advances the canonical TTBR0 switch generation, so retain the
            // same exact-frame invariant used by blocking wait/exec resume paths before returning to
            // the common signal/EL0 boundary.
            let resumed =
                unsafe { scheduler.bootstrap_current_global_thread() }.unwrap_or_else(|_| {
                    fail_closed_after_signal_commit(
                        "KERNAL/ARM64: Step 30 stopped SVC resumed without scheduler owner\n",
                    )
                });
            if resumed != current {
                fail_closed_after_signal_commit(
                    "KERNAL/ARM64: Step 30 stopped SVC resumed on wrong generation\n",
                );
            }
            let generation = kernal_process_aarch64::current_user_switch_generation()
                .and_then(core::num::NonZeroU64::new)
                .unwrap_or_else(|| {
                    fail_closed_after_signal_commit(
                        "KERNAL/ARM64: Step 30 stopped SVC resumed without switch generation\n",
                    )
                });
            // SAFETY: resumed == current proves the same exact scheduler generation owns this
            // synchronous frame again, and destination activation already installed its TTBR0.
            unsafe { frame.rebind_entry_switch_generation(generation) };
            Ok(())
        }
        Delivery::Default {
            action: DefaultAction::Continue,
            ..
        } => {
            // SIGCONT's process-wide resume side effect belongs to successful generation at the send
            // path. Return-time default delivery only consumes the pending signal; starting a second
            // Continue transaction here would duplicate scheduler authority and race newer stops.
            let expected = prepared.delivery();
            let committed = super::runtime::with_linux_runtime(|state| {
                state.with_current_signal_delivery(
                    current,
                    frame.entry_switch_generation(),
                    |process, _address_space, _objects, identities, signals| {
                        signals.commit_prepared_delivery(identities, process, current, prepared)
                    },
                )
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            match committed {
                Ok(committed) if committed == expected => Ok(()),
                Ok(_) => fail_closed_after_signal_commit(
                    "KERNAL/ARM64: Step 30 continue delivery changed after signal commit\n",
                ),
                Err(SignalError::PreparedDeliveryStale) => Ok(()),
                Err(_) => Err(()),
            }
        }
        Delivery::Handler { .. } => {
            let expected = prepared.delivery();
            let snapshot = *frame;
            let Some(frame_preparation) = prepare_handler_frame(
                &snapshot,
                current,
                frame.entry_switch_generation(),
                &prepared,
            )?
            else {
                return Err(());
            };

            match frame_preparation {
                HandlerFramePreparation::BadUserState(reason) => {
                    let committed = super::runtime::with_linux_runtime(|state| {
                        state.with_current_signal_delivery(
                            current,
                            frame.entry_switch_generation(),
                            |process, _address_space, _objects, identities, signals| {
                                signals.commit_prepared_delivery(
                                    identities, process, current, prepared,
                                )
                            },
                        )
                    })
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
                    match committed {
                        Ok(committed) if committed == expected => {
                            terminate_bad_handler_frame(reason)
                        }
                        Ok(_) => fail_closed_after_signal_commit(
                            "KERNAL/ARM64: Step 30 bad handler signal changed after commit\n",
                        ),
                        Err(SignalError::PreparedDeliveryStale) => Ok(()),
                        Err(_) => Err(()),
                    }
                }
                HandlerFramePreparation::Ready(prepared_frame) => {
                    let committed = super::runtime::with_linux_runtime(|state| {
                        state.with_current_signal_delivery(
                            current,
                            frame.entry_switch_generation(),
                            |process, _address_space, _objects, identities, signals| {
                                signals.commit_prepared_delivery(
                                    identities, process, current, prepared,
                                )
                            },
                        )
                    })
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
                    match committed {
                        Ok(committed) if committed == prepared_frame.expected => {
                            // All fallible owner/usercopy work is now committed. Only now may the
                            // saved exception frame become the handler entry frame.
                            prepared_frame.entry.apply(
                                &mut frame.x,
                                &mut frame.sp_el0,
                                &mut frame.elr_el1,
                            );
                            Ok(())
                        }
                        Ok(_) => fail_closed_after_signal_commit(
                            "KERNAL/ARM64: Step 30 handler signal delivery changed after commit\n",
                        ),
                        Err(SignalError::PreparedDeliveryStale) => Ok(()),
                        Err(_) => Err(()),
                    }
                }
            }
        }
    }
}
