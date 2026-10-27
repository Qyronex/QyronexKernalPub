// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::{NonZeroU32, NonZeroU64};
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::{
    KERNEL_SIGACTION_BYTES, KernelSigaction, SigmaskHow, WaitIdSiginfo, classify_step30_runtime,
    decode_sigmask_how, valid_rt_sigset_size,
};
use kernal_linux_abi::{
    Errno, KillSelector, SignalNumber, Step30RuntimeCall, SyscallRequest, SyscallReturn,
    Wait4Selector, WaitIdType, decode_kill_selector,
    decode_signal_number as decode_send_signal_number, decode_tgkill_target, decode_wait4_options,
    decode_wait4_selector, decode_waitid_options, decode_waitid_type, linux_signed_int,
    linux_unsigned_int,
};
use kernal_linux_credentials::{
    Error as CredentialError, LinuxCredentials, RobustListRegistration,
};
use kernal_linux_exec::ExecCommitHandoff;
use kernal_linux_fd::ReleasedObject;
use kernal_linux_identity::Error as IdentityError;
use kernal_linux_signal::{
    Disposition, Error as SignalError, MaskHow, SA_RESTORER, SIGCONT, Signal, SignalAction,
    SignalHandler, SignalProvenance, SignalSet,
};
use kernal_linux_wait::{
    Error as WaitError, WaitEventClass, WaitInterests, WaitObservation, WaitOutcome,
    WaitPrepareOutcome, WaitSelector, WaitSignalCommitOutcome, WaitSleepReceipt, WaitStatus,
};
use kernal_scheduler_smp::{GlobalThreadId, JobControlCommand};
use kernal_usercopy::Error as UsercopyError;

const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    NotHandled,
    Return(SyscallReturn),
    /// The Step-30 semantic owner already committed authoritative userspace frame state.
    /// The outer legacy fallback must return without rewriting x0 or restoring the entry frame.
    FrameCommitted,
    /// An interrupted blocking wait already committed a concrete signal handler frame. The outer
    /// return hook must not prepare a second signal during this same kernel-to-user transition.
    SignalFrameCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationError {
    Errno(Errno),
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecPrepareError {
    Linux(Errno),
    Invariant,
}

struct PreparedExecCommit {
    image: super::step30_exec_input::PreparedExecImage,
    cloexec: ExecCommitHandoff<{ super::step29_runtime::STEP29_RUNTIME_FDS }>,
    robust_head: Option<u64>,
    process_id: kernal_capability::ObjectId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoNewPrivsRequest {
    Set,
    Get,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalSendResult {
    UnsupportedTarget,
    MissingTarget,
    PermissionDenied,
    ProbeSuccess,
    Queued(SignalNotifyTargets),
    OwnerError(SignalError),
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignalNotifyTargets {
    threads: [Option<GlobalThreadId>; super::runtime::STEP15_RUNTIME_THREADS],
}

impl SignalNotifyTargets {
    const fn empty() -> Self {
        Self {
            threads: [None; super::runtime::STEP15_RUNTIME_THREADS],
        }
    }

    fn single(thread: GlobalThreadId) -> Self {
        let mut targets = Self::empty();
        targets.threads[0] = Some(thread);
        targets
    }

    fn insert(&mut self, ordinal: usize, thread: GlobalThreadId) -> Result<(), ()> {
        let slot = self.threads.get_mut(ordinal).ok_or(())?;
        if slot.is_some() {
            return Err(());
        }
        *slot = Some(thread);
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.threads.iter().all(Option::is_none)
    }

    fn iter(&self) -> impl Iterator<Item = GlobalThreadId> + '_ {
        self.threads.iter().flatten().copied()
    }

    fn exactly_one(self) -> Result<GlobalThreadId, ()> {
        let mut threads = self.iter();
        let target = threads.next().ok_or(())?;
        if threads.next().is_some() {
            return Err(());
        }
        Ok(target)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignalNotifyPlan {
    cpus: [bool; super::super::MAX_PROOF_CPUS],
}

impl SignalNotifyPlan {
    const fn new() -> Self {
        Self {
            cpus: [false; super::super::MAX_PROOF_CPUS],
        }
    }

    fn include_targets(
        &mut self,
        current_cpu: usize,
        targets: SignalNotifyTargets,
    ) -> Result<(), ()> {
        for thread in targets.iter() {
            let target_cpu = usize::from(thread.cpu.0);
            let notify = self.cpus.get_mut(target_cpu).ok_or(())?;
            if target_cpu != current_cpu {
                *notify = true;
            }
        }
        Ok(())
    }

    fn deliver(self) -> Result<(), ()> {
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            for (target_cpu, notify) in self.cpus.iter().copied().enumerate() {
                if !notify {
                    continue;
                }
                let mpidr = super::super::CPU_MPIDRS
                    .get(target_cpu)
                    .ok_or(())?
                    .load(core::sync::atomic::Ordering::Acquire);
                let affinity = kernal_arch_aarch64::CpuAffinity::from_mpidr(mpidr);
                // SAFETY: this is notification only. No scheduler mailbox or RunQueue state is
                // mutated; the target PE observes the already-committed SignalTable state on its
                // normal lower-EL IRQ return boundary.
                unsafe {
                    kernal_gicv3_aarch64::send_sgi1(
                        kernal_gicv3_aarch64::RESCHEDULE_SGI_DEFAULT,
                        affinity,
                    )
                }
                .map_err(|_| ())?;
            }
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        {
            let _ = self;
        }
        Ok(())
    }
}

fn process_signal_notify_targets<
    const CAPS: usize,
    const ID_PROCESSES: usize,
    const ID_THREADS: usize,
>(
    process: &kernal_process::Process<CAPS>,
    identities: &kernal_linux_identity::LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
) -> Result<SignalNotifyTargets, ()> {
    let mut targets = SignalNotifyTargets::empty();
    for ordinal in 0..super::runtime::STEP15_RUNTIME_THREADS {
        match identities.bound_scheduler_thread_at(process, ordinal) {
            Ok(Some(thread)) => targets.insert(ordinal, thread)?,
            Ok(None) => break,
            Err(_) => return Err(()),
        }
    }
    if targets.is_empty() {
        return Err(());
    }
    Ok(targets)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockingWaitError {
    NoChild,
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockingWaitResolution {
    Outcome(WaitOutcome),
    SignalFrameCommitted,
}

/// Handles the Step-30 runtime calls that are already fully composable from accepted owners.
///
/// Calls whose semantic owner has not yet been wired remain `NotHandled`; the surrounding live trap
/// keeps its existing fallback policy. This module owns no Process/Thread/PID/TID registry and never
/// dereferences a robust-list head during registration.
pub(super) fn handle(request: SyscallRequest, frame: &mut ExceptionFrame) -> Result<Outcome, ()> {
    let Some(call) = classify_step30_runtime(request) else {
        return Ok(Outcome::NotHandled);
    };

    match call {
        Step30RuntimeCall::WaitId {
            which,
            id,
            infop,
            options,
            rusage,
        } => {
            let plan = match waitid_observation_plan(which, id, options, rusage) {
                Ok(Some(plan)) => plan,
                Ok(None) => return Ok(Outcome::NotHandled),
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            // The canonical Wait owner is observed non-destructively first. This keeps a bad siginfo
            // pointer from consuming any terminal or job-control observation and is also WNOWAIT.
            let observed = super::runtime::with_linux_runtime(|state| {
                state.observe_wait_for_scheduler_thread_with_interests(
                    current,
                    plan.selector,
                    plan.nohang,
                    plan.interests,
                )
            })
            .map_err(|_| ())?;
            let outcome = match observed {
                Ok(outcome) => outcome,
                Err(super::runtime::Error::Wait(WaitError::NoChild)) => {
                    return Ok(Outcome::Return(SyscallReturn::error(Errno::ECHILD)));
                }
                Err(_) => return Err(()),
            };
            let resolution =
                match resolve_blocking_wait(outcome, current, plan.selector, plan.interests, frame)
                {
                    Ok(resolution) => resolution,
                    Err(BlockingWaitError::NoChild) => {
                        return Ok(Outcome::Return(SyscallReturn::error(Errno::ECHILD)));
                    }
                    Err(BlockingWaitError::Invariant) => return Err(()),
                };
            let outcome = match resolution {
                BlockingWaitResolution::Outcome(outcome) => outcome,
                BlockingWaitResolution::SignalFrameCommitted => {
                    return Ok(Outcome::SignalFrameCommitted);
                }
            };

            match outcome {
                WaitOutcome::NoHang => {
                    if infop != 0 {
                        let empty = WaitIdSiginfo::empty();
                        if let Err(copy_error) =
                            kernal_usercopy_aarch64::copy_to_user(infop, empty.as_bytes())
                        {
                            return match map_wait_usercopy_error(copy_error) {
                                Ok(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
                                Err(()) => Err(()),
                            };
                        }
                    }
                    Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?))
                }
                // `resolve_blocking_wait` above must consume every blocking observation before this
                // result match. A surviving WouldBlock is an internal transaction failure.
                WaitOutcome::WouldBlock => Err(()),
                WaitOutcome::Ready(observation) => {
                    // Step 30 currently has immutable uid/gid vectors: the initial credentials are
                    // bound once and fork copies them exactly; no setuid/setgid mutation surface exists.
                    // Therefore the waiting parent's real uid is also the observed child's real uid.
                    // If credential mutation is added later this must become an exact child observation.
                    let real_uid = current_credentials()?.ruid();
                    let encoded = encode_waitid_siginfo(
                        observation.pid(),
                        observation.status(),
                        observation.event_class(),
                        real_uid,
                    )?;
                    if infop != 0 {
                        if let Err(copy_error) =
                            kernal_usercopy_aarch64::copy_to_user(infop, encoded.as_bytes())
                        {
                            return match map_wait_usercopy_error(copy_error) {
                                Ok(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
                                Err(()) => Err(()),
                            };
                        }
                    }

                    // WNOWAIT leaves the exact observation visible. Otherwise phase 2 branches by
                    // the owner-provided event class: only terminal Exited reaps Process resources;
                    // Stop/Continue consume just their exact generation-bound job-control record.
                    if !plan.nowait {
                        commit_wait_observation_phase2(current, observation)?;
                    }
                    Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?))
                }
            }
        }
        Step30RuntimeCall::Wait4 {
            pid,
            status,
            options,
            rusage,
        } => {
            let plan = match wait4_observation_plan(pid, options, rusage) {
                Ok(Some(plan)) => plan,
                Ok(None) => return Ok(Outcome::NotHandled),
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            // Phase 1 is deliberately non-destructive even for ordinary wait4. This guarantees that
            // a bad userspace status pointer can return EFAULT without consuming the observation.
            let observed = super::runtime::with_linux_runtime(|state| {
                state.observe_wait_for_scheduler_thread_with_interests(
                    current,
                    plan.selector,
                    plan.nohang,
                    plan.interests,
                )
            })
            .map_err(|_| ())?;
            let outcome = match observed {
                Ok(outcome) => outcome,
                Err(super::runtime::Error::Wait(WaitError::NoChild)) => {
                    return Ok(Outcome::Return(SyscallReturn::error(Errno::ECHILD)));
                }
                Err(_) => return Err(()),
            };
            let resolution =
                match resolve_blocking_wait(outcome, current, plan.selector, plan.interests, frame)
                {
                    Ok(resolution) => resolution,
                    Err(BlockingWaitError::NoChild) => {
                        return Ok(Outcome::Return(SyscallReturn::error(Errno::ECHILD)));
                    }
                    Err(BlockingWaitError::Invariant) => return Err(()),
                };
            let outcome = match resolution {
                BlockingWaitResolution::Outcome(outcome) => outcome,
                BlockingWaitResolution::SignalFrameCommitted => {
                    return Ok(Outcome::SignalFrameCommitted);
                }
            };

            match outcome {
                WaitOutcome::NoHang => Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?)),
                // `resolve_blocking_wait` above must consume every blocking observation before this
                // result match. A surviving WouldBlock is an internal transaction failure.
                WaitOutcome::WouldBlock => Err(()),
                WaitOutcome::Ready(observation) => {
                    if status != 0 {
                        let encoded = u32::from(observation.status().raw()).to_le_bytes();
                        if let Err(copy_error) =
                            kernal_usercopy_aarch64::copy_to_user(status, &encoded)
                        {
                            return match map_wait_usercopy_error(copy_error) {
                                Ok(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
                                Err(()) => Err(()),
                            };
                        }
                    }

                    // Phase 2 occurs only after successful userspace status publication. Terminal
                    // Exited is destructive; Stop/Continue consume only the exact current event.
                    commit_wait_observation_phase2(current, observation)?;
                    Ok(Outcome::Return(
                        SyscallReturn::success(i64::from(observation.pid().get())).ok_or(())?,
                    ))
                }
            }
        }
        Step30RuntimeCall::RtSigreturn => {
            super::sigreturn::restore(frame)?;
            Ok(Outcome::FrameCommitted)
        }
        Step30RuntimeCall::SetTidAddress { tidptr } => {
            let clear_child_tid = if tidptr == 0 { None } else { Some(tidptr) };

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            // The exact scheduler generation is revalidated through the canonical Linux identity
            // owner. The numeric TID is an observation/result only, never mutation authority.
            let tid = super::runtime::with_linux_runtime(|state| {
                state
                    .process_parts_for_scheduler_thread(current)
                    .map(|(_, _, tid)| tid)
                    .map_err(|_| ())
            })
            .map_err(|_| ())??;

            #[cfg(all(target_arch = "aarch64", target_os = "none"))]
            {
                // SAFETY: the same SVC owns the scheduler's quiescent current-thread window. Linux
                // stores tidptr opaquely; the scheduler revalidates Running+Published generation.
                unsafe {
                    scheduler.bootstrap_update_current_clear_child_tid(current, clear_child_tid)
                }
                .map_err(|_| ())?;
            }
            #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
            {
                let _ = clear_child_tid;
                return Err(());
            }

            Ok(Outcome::Return(
                SyscallReturn::success(i64::from(tid.get())).ok_or(())?,
            ))
        }
        Step30RuntimeCall::Getppid => {
            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }
            let parent = super::runtime::with_linux_runtime(|state| {
                state.with_current_process_identity(current, |process, identities| {
                    identities.parent_pid_for(process)
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            Ok(Outcome::Return(encode_getppid(parent)?))
        }
        Step30RuntimeCall::Getuid => Ok(Outcome::Return(credential_scalar(
            current_credentials()?.ruid(),
        )?)),
        Step30RuntimeCall::Geteuid => Ok(Outcome::Return(credential_scalar(
            current_credentials()?.euid(),
        )?)),
        Step30RuntimeCall::Getgid => Ok(Outcome::Return(credential_scalar(
            current_credentials()?.rgid(),
        )?)),
        Step30RuntimeCall::Getegid => Ok(Outcome::Return(credential_scalar(
            current_credentials()?.egid(),
        )?)),
        Step30RuntimeCall::Prctl {
            option,
            arg2,
            arg3,
            arg4,
            arg5,
        } => match decode_prctl_request(option, arg2, arg3, arg4, arg5) {
            Err(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
            Ok(NoNewPrivsRequest::Set) => {
                set_current_no_new_privs()?;
                Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?))
            }
            Ok(NoNewPrivsRequest::Get) => {
                let enabled = current_no_new_privs()?;
                Ok(Outcome::Return(
                    SyscallReturn::success(i64::from(u8::from(enabled))).ok_or(())?,
                ))
            }
        },
        Step30RuntimeCall::Kill { pid, signal } => {
            let selector = decode_kill_selector(pid);
            let signal = match decode_send_signal_number(signal) {
                Ok(signal) => signal,
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };
            let is_sigcont = matches!(
                signal,
                SignalNumber::Signal(number) if number == SIGCONT
            );

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            let sender_credentials = current_credentials()?;
            let sender_pid = current_pid(current)?;
            let sender_session = current_session(current)?;

            // Every scalar target is reselected through the retained Process owner before credentials
            // or SignalTable mutation. `SignalNumber::Probe` performs the same existence/permission
            // checks but never manufactures `Signal::new(0)` and never queues pending state. A real
            // queue success snapshots only exact generation-safe thread observations; notification is
            // routed later, after the LinuxRuntime borrow has ended. For SIGCONT, the process-wide
            // Continue transaction is created immediately after the canonical signal generation while
            // this same RuntimeCell still serializes Process/LinuxIdentity membership.
            let send = |target: NonZeroU32| -> Result<
                (
                    SignalSendResult,
                    Option<super::step30_child_exit::ProcessJobControlDispatch>,
                ),
                (),
            > {
                let result = super::runtime::with_linux_runtime(|state| {
                    let result = state.with_process_signal_target_for_pid(
                        target,
                        |process, target_credentials, identities, signals| {
                            let same_session = match identities.getsid(process) {
                                Ok(session) => session == sender_session,
                                Err(_) => return SignalSendResult::Invariant,
                            };
                            let sigcont_session_exception = matches!(
                                signal,
                                SignalNumber::Signal(number) if number == SIGCONT
                            ) && same_session;
                            if !sender_credentials.may_signal(target_credentials)
                                && !sigcont_session_exception
                            {
                                return SignalSendResult::PermissionDenied;
                            }
                            match signal {
                                SignalNumber::Probe => SignalSendResult::ProbeSuccess,
                                SignalNumber::Signal(number) => {
                                    let signal = Signal::new(number).expect(
                                        "common Step-30 ABI validates nonzero signals through 64",
                                    );
                                    match signals.queue_signal_with_provenance(
                                        process,
                                        signal,
                                        SignalProvenance::User {
                                            sender_pid,
                                            sender_uid: sender_credentials.ruid(),
                                        },
                                    ) {
                                        Ok(()) => {
                                            match process_signal_notify_targets(process, identities)
                                            {
                                                Ok(targets) => SignalSendResult::Queued(targets),
                                                Err(()) => SignalSendResult::Invariant,
                                            }
                                        }
                                        Err(error) => SignalSendResult::OwnerError(error),
                                    }
                                }
                            }
                        },
                    )?;
                    let result = result.unwrap_or(SignalSendResult::MissingTarget);
                    let continue_dispatch = if is_sigcont
                        && matches!(result, SignalSendResult::Queued(_))
                    {
                        let targets = state.job_control_targets_for_pid(target).unwrap_or_else(|_| {
                            fail_closed_after_signal_send_commit(
                                "KERNAL/ARM64: Step 30 SIGCONT target revalidation failed after signal commit\n",
                            )
                        });
                        Some(
                            super::step30_child_exit::begin_process_job_control_transaction(
                                targets,
                                JobControlCommand::Continue,
                                None,
                            )
                            .unwrap_or_else(|_| {
                                fail_closed_after_signal_send_commit(
                                    "KERNAL/ARM64: Step 30 SIGCONT transaction begin failed after signal commit\n",
                                )
                            }),
                        )
                    } else {
                        None
                    };
                    Ok::<_, super::runtime::Error>((result, continue_dispatch))
                })
                .map_err(|_| ())?
                .map_err(|_| ())?;
                Ok(result)
            };

            let finish_continue = |dispatch: Option<
                super::step30_child_exit::ProcessJobControlDispatch,
            >| {
                let Some(dispatch) = dispatch else {
                    return;
                };
                let dispatched =
                    super::step30_child_exit::dispatch_process_job_control(dispatch, current_cpu)
                        .unwrap_or_else(|_| {
                            fail_closed_after_signal_send_commit(
                                "KERNAL/ARM64: Step 30 SIGCONT scheduler dispatch failed after signal commit\n",
                            )
                        });
                // SAFETY: this lower-EL SVC owns the current CPU's IRQ-masked, irq_depth=0,
                // preempt_count=0 synchronous owner window. The signal generation and Continue
                // transaction are already authoritative, so any completion failure is fail-stop.
                if unsafe {
                    super::step30_child_exit::finish_process_job_control_dispatch(
                        dispatched,
                        current_cpu,
                    )
                }
                .is_err()
                {
                    fail_closed_after_signal_send_commit(
                        "KERNAL/ARM64: Step 30 SIGCONT completion failed after signal commit\n",
                    );
                }
            };

            let send_selected = |process_group: Option<NonZeroU32>,
                                 exclude_sender_and_init: bool|
             -> Result<Outcome, ()> {
                let targets = super::runtime::with_linux_runtime(|state| {
                    state.signal_target_pids(process_group)
                })
                .map_err(|_| ())?
                .map_err(|_| ())?;

                let mut delivered = false;
                let mut permission_denied = false;
                let mut pending_capacity = false;
                let mut notifications = SignalNotifyPlan::new();
                for target in targets.iter() {
                    // Linux kill(-1, sig) excludes the caller and PID 1. Group-directed kill(0/-pgid)
                    // deliberately retains both when they are actual members of the selected group.
                    if exclude_sender_and_init && (target == sender_pid || target.get() == 1) {
                        continue;
                    }
                    let (result, continue_dispatch) = send(target)?;
                    match result {
                        SignalSendResult::ProbeSuccess => delivered = true,
                        SignalSendResult::Queued(targets) => {
                            delivered = true;
                            finish_continue(continue_dispatch);
                            super::signal_delivery::interrupt_and_wake_process_wait_after_signal(
                                target,
                            )?;
                            notifications.include_targets(current_cpu, targets)?;
                        }
                        SignalSendResult::MissingTarget => {}
                        SignalSendResult::PermissionDenied => permission_denied = true,
                        SignalSendResult::OwnerError(SignalError::PendingCapacity) => {
                            pending_capacity = true;
                        }
                        SignalSendResult::UnsupportedTarget
                        | SignalSendResult::OwnerError(_)
                        | SignalSendResult::Invariant => return Err(()),
                    }
                }

                if delivered {
                    // Queue commits are already authoritative. SGI routing is a post-commit internal
                    // obligation: failure never rolls a signal back or fabricates a Linux errno.
                    notifications.deliver()?;
                    return Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?));
                }
                if pending_capacity {
                    return Ok(Outcome::Return(SyscallReturn::error(Errno::EAGAIN)));
                }
                if permission_denied {
                    return Ok(Outcome::Return(SyscallReturn::error(Errno::EPERM)));
                }
                Ok(Outcome::Return(SyscallReturn::error(Errno::ESRCH)))
            };

            let outcome = match selector {
                KillSelector::Pid(target) => {
                    let (result, continue_dispatch) = send(target)?;
                    finish_continue(continue_dispatch);
                    if matches!(result, SignalSendResult::Queued(_)) {
                        super::signal_delivery::interrupt_and_wake_process_wait_after_signal(
                            target,
                        )?;
                    }
                    finish_signal_send_result(result, current_cpu)
                }
                KillSelector::SameProcessGroup => {
                    send_selected(Some(current_process_group(current)?), false)
                }
                KillSelector::ProcessGroup(process_group) => {
                    send_selected(Some(process_group), false)
                }
                KillSelector::AllPermitted => send_selected(None, true),
            }?;

            if is_sigcont {
                // A successful Continue dispatch may reschedule away from this synchronous SVC and
                // return only after the original sender generation is current again. Destination
                // activation advances the TTBR0 switch generation, so rebind the retained frame
                // before the common signal/EL0 return path validates it.
                let resumed =
                    unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
                if resumed != current {
                    return Err(());
                }
                let generation = kernal_process_aarch64::current_user_switch_generation()
                    .and_then(NonZeroU64::new)
                    .ok_or(())?;
                // SAFETY: resumed == current proves the original sender generation owns this
                // synchronous frame again and its destination TTBR0 is already active.
                unsafe { frame.rebind_entry_switch_generation(generation) };
            }

            Ok(outcome)
        }
        Step30RuntimeCall::Tgkill { tgid, tid, signal } => {
            let target = match decode_tgkill_target(tgid, tid) {
                Ok(target) => target,
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };
            let signal = match decode_send_signal_number(signal) {
                Ok(signal) => signal,
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };
            let is_sigcont = matches!(
                signal,
                SignalNumber::Signal(number) if number == SIGCONT
            );

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            let sender_credentials = current_credentials()?;
            let sender_pid = current_pid(current)?;
            let sender_session = current_session(current)?;
            let result = super::runtime::with_linux_runtime(|state| {
                let result = state.with_process_signal_target_for_pid(
                    target.tgid(),
                    |process, target_credentials, identities, signals| {
                        let same_session = match identities.getsid(process) {
                            Ok(session) => session == sender_session,
                            Err(_) => return SignalSendResult::Invariant,
                        };
                        let sigcont_session_exception = matches!(
                            signal,
                            SignalNumber::Signal(number) if number == SIGCONT
                        ) && same_session;
                        if !sender_credentials.may_signal(target_credentials)
                            && !sigcont_session_exception
                        {
                            return SignalSendResult::PermissionDenied;
                        }
                        let thread =
                            match identities.scheduler_thread_for_tid(process, target.tid()) {
                                Ok(thread) => thread,
                                Err(IdentityError::ThreadNotBound) => {
                                    return SignalSendResult::MissingTarget;
                                }
                                Err(_) => return SignalSendResult::Invariant,
                            };
                        match identities.bound_tid_for_scheduler_thread(process, thread) {
                            Ok(tid) if tid == target.tid() => {}
                            Ok(_) => return SignalSendResult::Invariant,
                            Err(IdentityError::ThreadNotBound) => {
                                return SignalSendResult::MissingTarget;
                            }
                            Err(_) => return SignalSendResult::Invariant,
                        }
                        match signal {
                            SignalNumber::Probe => SignalSendResult::ProbeSuccess,
                            SignalNumber::Signal(number) => {
                                let signal = Signal::new(number).expect(
                                    "common Step-30 ABI validates nonzero signals through 64",
                                );
                                match signals.queue_thread_signal_with_provenance(
                                    identities,
                                    process,
                                    thread,
                                    signal,
                                    SignalProvenance::Tkill {
                                        sender_pid,
                                        sender_uid: sender_credentials.ruid(),
                                    },
                                ) {
                                    Ok(()) => SignalSendResult::Queued(
                                        SignalNotifyTargets::single(thread),
                                    ),
                                    Err(error) => SignalSendResult::OwnerError(error),
                                }
                            }
                        }
                    },
                )?;
                let result = result.unwrap_or(SignalSendResult::MissingTarget);
                let continue_dispatch = if is_sigcont
                    && matches!(result, SignalSendResult::Queued(_))
                {
                    let targets = state
                        .job_control_targets_for_pid(target.tgid())
                        .unwrap_or_else(|_| {
                            fail_closed_after_signal_send_commit(
                                "KERNAL/ARM64: Step 30 tgkill SIGCONT target revalidation failed after signal commit\n",
                            )
                        });
                    Some(
                        super::step30_child_exit::begin_process_job_control_transaction(
                            targets,
                            JobControlCommand::Continue,
                            None,
                        )
                        .unwrap_or_else(|_| {
                            fail_closed_after_signal_send_commit(
                                "KERNAL/ARM64: Step 30 tgkill SIGCONT transaction begin failed after signal commit\n",
                            )
                        }),
                    )
                } else {
                    None
                };
                Ok::<_, super::runtime::Error>((result, continue_dispatch))
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let (result, continue_dispatch) = result;
            if let Some(dispatch) = continue_dispatch {
                let dispatched =
                    super::step30_child_exit::dispatch_process_job_control(dispatch, current_cpu)
                        .unwrap_or_else(|_| {
                            fail_closed_after_signal_send_commit(
                                "KERNAL/ARM64: Step 30 tgkill SIGCONT scheduler dispatch failed after signal commit\n",
                            )
                        });
                // SAFETY: the same synchronous owner window as above remains active; this is the
                // process-wide resume side effect of the already-committed thread-directed SIGCONT.
                if unsafe {
                    super::step30_child_exit::finish_process_job_control_dispatch(
                        dispatched,
                        current_cpu,
                    )
                }
                .is_err()
                {
                    fail_closed_after_signal_send_commit(
                        "KERNAL/ARM64: Step 30 tgkill SIGCONT completion failed after signal commit\n",
                    );
                }
            }
            if is_sigcont {
                // Thread-directed SIGCONT has the same process-wide Continue side effect and may
                // switch this synchronous sender away before returning from the dispatch.
                let resumed =
                    unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
                if resumed != current {
                    return Err(());
                }
                let generation = kernal_process_aarch64::current_user_switch_generation()
                    .and_then(NonZeroU64::new)
                    .ok_or(())?;
                // SAFETY: resumed == current proves this retained SVC frame belongs to the exact
                // sender generation that is current again after destination activation.
                unsafe { frame.rebind_entry_switch_generation(generation) };
            }
            if let SignalSendResult::Queued(targets) = result {
                let thread = targets.exactly_one()?;
                super::signal_delivery::interrupt_and_wake_thread_wait_after_signal(thread)?;
            }
            finish_signal_send_result(result, current_cpu)
        }
        Step30RuntimeCall::RtSigaction {
            signal,
            action,
            old_action,
            sigset_size,
        } => {
            if !valid_rt_sigset_size(sigset_size) {
                return Ok(Outcome::Return(SyscallReturn::error(Errno::EINVAL)));
            }
            let signal = match decode_rt_sigaction_signal(signal) {
                Ok(signal) => signal,
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };

            let requested = if action == 0 {
                None
            } else {
                if signal.is_unmaskable() {
                    return Ok(Outcome::Return(SyscallReturn::error(Errno::EINVAL)));
                }
                let mut bytes = [0u8; KERNEL_SIGACTION_BYTES];
                if let Err(copy_error) = kernal_usercopy_aarch64::copy_from_user(&mut bytes, action)
                {
                    return match map_signal_usercopy_error(copy_error) {
                        Ok(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
                        Err(()) => Err(()),
                    };
                }
                match decode_sigaction_action(KernelSigaction::from_ne_bytes(bytes)) {
                    Ok(action) => Some(action),
                    Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
                }
            };

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            // Linux copies the new action in before mutation, commits the disposition, and only then
            // writes oldact. Therefore an oldact EFAULT after a successful update must not roll the
            // new disposition back.
            let previous = super::runtime::with_linux_runtime(|state| {
                state.with_current_process_signals(current, |process, _identities, signals| {
                    match requested {
                        Some(action) => signals.set_action(process, signal, action),
                        None => signals.action(process, signal),
                    }
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let previous = match previous {
                Ok(previous) => previous,
                Err(error) => match map_sigaction_owner_error(error) {
                    Ok(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
                    Err(()) => return Err(()),
                },
            };

            if old_action != 0 {
                let encoded = encode_sigaction_action(previous).to_ne_bytes();
                if let Err(copy_error) = kernal_usercopy_aarch64::copy_to_user(old_action, &encoded)
                {
                    return match map_signal_usercopy_error(copy_error) {
                        Ok(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
                        Err(()) => Err(()),
                    };
                }
            }
            Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?))
        }
        Step30RuntimeCall::RtSigprocmask {
            how,
            set,
            old_set,
            sigset_size,
        } => {
            if !valid_rt_sigset_size(sigset_size) {
                return Ok(Outcome::Return(SyscallReturn::error(Errno::EINVAL)));
            }

            // Linux ignores `how` when nset is NULL. If a new mask is supplied it is copied and
            // validated before any SignalTable mutation, including removal of SIGKILL/SIGSTOP bits.
            let requested = if set == 0 {
                None
            } else {
                let how = match decode_sigmask_how(how) {
                    Some(how) => how,
                    None => return Ok(Outcome::Return(SyscallReturn::error(Errno::EINVAL))),
                };
                let mut bytes = [0u8; core::mem::size_of::<u64>()];
                if let Err(copy_error) = kernal_usercopy_aarch64::copy_from_user(&mut bytes, set) {
                    return match map_signal_usercopy_error(copy_error) {
                        Ok(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
                        Err(()) => Err(()),
                    };
                }
                Some((
                    signal_mask_how(how),
                    SignalSet::from_bits(u64::from_ne_bytes(bytes)),
                ))
            };

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            let previous = super::runtime::with_linux_runtime(|state| {
                state.with_current_process_signals(current, |process, identities, signals| {
                    match requested {
                        Some((how, set)) => {
                            signals.update_thread_mask(identities, process, current, how, set)
                        }
                        None => signals.thread_mask(identities, process, current),
                    }
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?
            .map_err(|_| ())?;

            // Linux commits the new mask before writing oset. A later EFAULT therefore reports the
            // userspace copy failure without rolling back the canonical thread mask.
            if old_set != 0 {
                let encoded = previous.bits().to_ne_bytes();
                if let Err(copy_error) = kernal_usercopy_aarch64::copy_to_user(old_set, &encoded) {
                    return match map_signal_usercopy_error(copy_error) {
                        Ok(errno) => Ok(Outcome::Return(SyscallReturn::error(errno))),
                        Err(()) => Err(()),
                    };
                }
            }
            Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?))
        }
        Step30RuntimeCall::Setpgid { pid, pgid } => {
            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }
            let current_pid = super::runtime::with_linux_runtime(|state| {
                state.with_current_process_identity(current, |process, identities| {
                    identities.bound_pid(process)
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let target_pid = match process_target_pid(pid, current_pid) {
                Ok(pid) => pid,
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };
            let result = super::runtime::with_linux_runtime(|state| {
                state.setpgid_for_scheduler_thread(current, target_pid, linux_signed_int(pgid))
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            match result {
                Some(result) => Ok(Outcome::Return(encode_setpgid(result)?)),
                None => Ok(Outcome::Return(SyscallReturn::error(Errno::ESRCH))),
            }
        }
        Step30RuntimeCall::Getpgid { pid } => {
            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }
            let current_pid = super::runtime::with_linux_runtime(|state| {
                state.with_current_process_identity(current, |process, identities| {
                    identities.bound_pid(process)
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let target_pid = match process_target_pid(pid, current_pid) {
                Ok(pid) => pid,
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };
            let group = super::runtime::with_linux_runtime(|state| {
                state.with_process_identity_for_pid(target_pid, |process, identities| {
                    identities.getpgid(process)
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            match group {
                Some(Ok(group)) => Ok(Outcome::Return(
                    SyscallReturn::success(i64::from(group.get())).ok_or(())?,
                )),
                Some(Err(_)) => Err(()),
                None => Ok(Outcome::Return(SyscallReturn::error(Errno::ESRCH))),
            }
        }
        Step30RuntimeCall::Getsid { pid } => {
            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }
            let current_pid = super::runtime::with_linux_runtime(|state| {
                state.with_current_process_identity(current, |process, identities| {
                    identities.bound_pid(process)
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?
            .map_err(|_| ())?;
            let target_pid = match process_target_pid(pid, current_pid) {
                Ok(pid) => pid,
                Err(errno) => return Ok(Outcome::Return(SyscallReturn::error(errno))),
            };
            let session = super::runtime::with_linux_runtime(|state| {
                state.with_process_identity_for_pid(target_pid, |process, identities| {
                    identities.getsid(process)
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            match session {
                Some(Ok(session)) => Ok(Outcome::Return(
                    SyscallReturn::success(i64::from(session.get())).ok_or(())?,
                )),
                Some(Err(_)) => Err(()),
                None => Ok(Outcome::Return(SyscallReturn::error(Errno::ESRCH))),
            }
        }
        Step30RuntimeCall::Setsid => {
            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }
            let session = super::runtime::with_linux_runtime(|state| {
                state.with_current_process_identity(current, |process, identities| {
                    identities.setsid(process)
                })
            })
            .map_err(|_| ())?
            .map_err(|_| ())?;
            Ok(Outcome::Return(encode_setsid(session)?))
        }
        call @ Step30RuntimeCall::Execve { .. } => handle_live_exec(call, frame),
        call @ Step30RuntimeCall::Execveat { .. } => handle_live_exec(call, frame),
        Step30RuntimeCall::SetRobustList { head, len } => {
            let registration = match validate_robust_registration(head, len) {
                Ok(registration) => registration,
                Err(RegistrationError::Errno(errno)) => {
                    return Ok(Outcome::Return(SyscallReturn::error(errno)));
                }
                Err(RegistrationError::Invariant) => return Err(()),
            };

            let current_cpu = super::super::current_cpu_index();
            let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
            // SAFETY: the lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
            let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
            if usize::from(current.cpu.0) != current_cpu {
                return Err(());
            }

            // Revalidate the exact scheduler generation against the canonical Linux identity owner
            // before changing generation-bound robust metadata. The returned scalar TID is ignored:
            // existence of the binding is the proof, not the number itself.
            super::runtime::with_linux_runtime(|state| {
                state
                    .process_parts_for_scheduler_thread(current)
                    .map(|_| ())
                    .map_err(|_| ())
            })
            .map_err(|_| ())??;

            // SAFETY: the same SVC owns the scheduler's quiescent current-thread window. The
            // registration was validated as a Linux userspace range above; the scheduler method
            // revalidates Running+Published generation before mutating ContextTable.
            #[cfg(all(target_arch = "aarch64", target_os = "none"))]
            {
                unsafe {
                    scheduler.bootstrap_update_current_robust_list_head(
                        current,
                        registration.head_address(),
                    )
                }
                .map_err(|_| ())?;
            }
            #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
            {
                // Host builds exercise decode/error policy only. The generation-bound
                // ContextTable mutation bridge exists exclusively on freestanding AArch64.
                return Err(());
            }

            Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?))
        }
        _ => Ok(Outcome::NotHandled),
    }
}

fn map_reversible_exec_error(
    error: super::step30_exec_input::ReversibleExecError,
) -> ExecPrepareError {
    match error {
        super::step30_exec_input::ReversibleExecError::Input(
            super::step30_exec_input::ExecInputError::Linux(errno),
        )
        | super::step30_exec_input::ReversibleExecError::Source(
            super::step30_exec_source::ExecSourceError::Linux(errno),
        )
        | super::step30_exec_input::ReversibleExecError::Stage(
            super::live_vm::ExecStageError::Linux(errno),
        ) => ExecPrepareError::Linux(errno),
        super::step30_exec_input::ReversibleExecError::Input(
            super::step30_exec_input::ExecInputError::Invariant,
        )
        | super::step30_exec_input::ReversibleExecError::Source(
            super::step30_exec_source::ExecSourceError::Invariant,
        )
        | super::step30_exec_input::ReversibleExecError::Stage(
            super::live_vm::ExecStageError::Invariant,
        )
        | super::step30_exec_input::ReversibleExecError::Invariant => ExecPrepareError::Invariant,
    }
}

fn current_exec_scheduler() -> Result<
    (
        usize,
        &'static kernal_scheduler_cpu::CpuSchedulerCell<
            { super::super::SCHEDULER_THREADS_PER_CPU },
            { super::super::REMOTE_WAKE_SLOTS },
        >,
        GlobalThreadId,
    ),
    (),
> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }
    Ok((current_cpu, scheduler, current))
}

fn handle_live_exec(call: Step30RuntimeCall, frame: &mut ExceptionFrame) -> Result<Outcome, ()> {
    let (current_cpu, scheduler, current) = current_exec_scheduler()?;
    if !super::live_vm::exact_current_is_only_bound_process_thread(current)? {
        return Err(());
    }

    // Ordinary Linux errno remains possible only while the old image is authoritative.
    // Successful typed staging commits AT_RANDOM and crosses the final reversible boundary.
    let staged = super::entropy::with_exec_at_random(
        |random| -> Result<super::step30_exec_input::PreparedExecImage, ExecPrepareError> {
            // SAFETY: the synchronous SVC no-switch window owns this complete typed staging call.
            unsafe {
                super::step30_exec_input::stage_exec_image_with_core_frames(call, current, random)
            }
            .map_err(map_reversible_exec_error)
        },
    )
    .map_err(|_| ())?;
    let image = match staged {
        Ok(image) => image,
        Err(ExecPrepareError::Linux(errno)) => {
            return Ok(Outcome::Return(SyscallReturn::error(errno)));
        }
        Err(ExecPrepareError::Invariant) => return Err(()),
    };

    // From successful staging onward every owner failure is invariant/fail-stop. Re-observe
    // the canonical retained Process/TID rather than introducing a second Exec identity owner.
    let (process_id, exiting_tid) = super::runtime::with_linux_runtime(|state| {
        let (process, address_space, tid) = state.process_parts_for_scheduler_thread(current)?;
        address_space
            .current_owner(process)
            .map_err(super::runtime::Error::AddressSpace)?;
        Ok::<_, super::runtime::Error>((process.id(), tid.get()))
    })
    .unwrap_or_else(|_| {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec runtime unavailable after staging\n")
    })
    .unwrap_or_else(|_| {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec identity changed after staging\n")
    });
    if image.process() != process_id {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec process changed after staging\n");
    }

    let (replacement, loaded) = image.into_staged().into_parts();
    let return_state = kernal_user_entry_aarch64::El0ReturnState::new(
        loaded.loaded.entry,
        kernal_user_entry_aarch64::EL0T_SPSR_EL1,
        loaded.loaded.initial_sp,
    )
    .unwrap_or_else(|_| exec_fail_closed("KERNAL/ARM64: Step 30 exec return state invalid\n"));

    let cloexec = prepare_exec_cloexec(current, process_id).unwrap_or_else(|_| {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec CLOEXEC prepare failed\n")
    });

    // SAFETY: exact-current metadata observation under the uninterrupted SVC owner window.
    let robust_head = unsafe { scheduler.bootstrap_current_exec_robust_list_head(current) }
        .unwrap_or_else(|_| exec_fail_closed("KERNAL/ARM64: Step 30 exec robust observe failed\n"));
    if let Some(robust_head) = robust_head {
        let cleanup = super::runtime::with_linux_runtime(|state| {
            state.with_exec_current_owner(current, |process, space, _objects| {
                // SAFETY: the old TTBR0 remains authoritative until the replacement below.
                unsafe {
                    kernal_linux_clone_exit_aarch64::cleanup_robust_list(
                        process,
                        space,
                        robust_head,
                        exiting_tid,
                        current,
                        super::futex::futexes(),
                        |target| unsafe { scheduler.bootstrap_wake_local_exact(target) },
                        |target| {
                            let target_cpu = usize::from(target.cpu.0);
                            if target_cpu == current_cpu {
                                return Err(kernal_scheduler_cpu::Error::WrongOwner);
                            }
                            let target_scheduler = super::super::CPU_SCHEDULERS
                                .get(target_cpu)
                                .ok_or(kernal_scheduler_cpu::Error::WrongOwner)?;
                            super::remote_wake_with_reschedule(target_scheduler, target)
                        },
                    )
                }
            })
        });
        if !matches!(cleanup, Ok(Ok(Ok(())))) {
            exec_fail_closed("KERNAL/ARM64: Step 30 exec robust cleanup failed\n");
        }
    }

    // Point of no return: activate and retain the fresh root.
    let superseded = super::runtime::with_linux_runtime(|state| {
        // SAFETY: the exact current single-thread generation remains owner-held.
        unsafe { state.commit_exec_address_space_replacement(current, replacement) }
    })
    .unwrap_or_else(|_| {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec runtime unavailable at root commit\n")
    })
    .unwrap_or_else(|_| exec_fail_closed("KERNAL/ARM64: Step 30 exec root commit failed\n"));

    let generation = kernal_process_aarch64::current_user_switch_generation()
        .and_then(NonZeroU64::new)
        .unwrap_or_else(|| {
            exec_fail_closed("KERNAL/ARM64: Step 30 exec switch generation missing\n")
        });
    // SAFETY: replacement activation is committed and this trapping frame remains exclusively owned.
    unsafe { frame.rebind_entry_switch_generation(generation) };

    super::runtime::with_linux_runtime(|state| {
        state.replace_process_break_for_exec(current, loaded.initial_break)
    })
    .unwrap_or_else(|_| {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec runtime unavailable at brk commit\n")
    })
    .unwrap_or_else(|_| exec_fail_closed("KERNAL/ARM64: Step 30 exec brk commit failed\n"));

    commit_exec_cloexec(current, process_id, cloexec)
        .unwrap_or_else(|_| exec_fail_closed("KERNAL/ARM64: Step 30 exec CLOEXEC commit failed\n"));
    commit_exec_signal_reset(current)
        .unwrap_or_else(|_| exec_fail_closed("KERNAL/ARM64: Step 30 exec signal reset failed\n"));
    // SAFETY: the exact robust observation was consumed before the root swap; this commits
    // the canonical exec reset of robust/clear_child_tid/TLS and TPIDR_EL0 afterward.
    unsafe { scheduler.bootstrap_commit_current_exec_user_state(current, robust_head) }
        .unwrap_or_else(|_| {
            exec_fail_closed("KERNAL/ARM64: Step 30 exec thread-state reset failed\n")
        });
    commit_exec_identity_marker(current).unwrap_or_else(|_| {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec identity marker failed\n")
    });

    frame.x.fill(0);
    frame.elr_el1 = return_state.return_pc();
    frame.sp_el0 = return_state.user_sp();
    frame.spsr_el1 = return_state.spsr_el1();

    reclaim_exec_superseded(current, superseded).unwrap_or_else(|_| {
        exec_fail_closed("KERNAL/ARM64: Step 30 exec old image reclaim failed\n")
    });

    Ok(Outcome::FrameCommitted)
}
fn prepare_exec_cloexec(
    current: GlobalThreadId,
    process_id: kernal_capability::ObjectId,
) -> Result<ExecCommitHandoff<{ super::step29_runtime::STEP29_RUNTIME_FDS }>, ()> {
    let result = super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _tid) = state.process_parts_for_scheduler_thread(current)?;
        if process.id() != process_id {
            return Err(super::runtime::Error::InvalidState);
        }
        address_space
            .current_owner(process)
            .map_err(super::runtime::Error::AddressSpace)?;
        let prepared = super::step29_runtime::with_process(process_id, |path_runtime| {
            ExecCommitHandoff::prepare(process, path_runtime.fds())
        })
        .map_err(|_| super::runtime::Error::InvalidState)?;
        prepared.map_err(|_| super::runtime::Error::InvalidState)
    });
    match result {
        Ok(Ok(handoff)) => Ok(handoff),
        _ => Err(()),
    }
}

fn consume_exec_released_objects<const N: usize>(
    path_runtime: &mut super::step29_runtime::Step29PathRuntime<'_>,
    released: [Option<ReleasedObject>; N],
) -> Result<(), ()> {
    let (_fds, pipes, overlay) = path_runtime.fd_pipe_overlay_parts();
    for object in released.into_iter().flatten() {
        match object {
            ReleasedObject::Pipe(endpoint) => pipes.close(endpoint).map_err(|_| ())?,
            ReleasedObject::RetainedDirectory(directory) => {
                overlay.release_directory(directory).map_err(|_| ())?;
            }
            ReleasedObject::RetainedReadOnly(logical) => {
                overlay.release_open(logical).map_err(|_| ())?;
            }
            ReleasedObject::WritableRegular(retained) => {
                overlay.release_retained_regular(retained).map_err(|_| ())?;
            }
        }
    }
    Ok(())
}

fn commit_exec_cloexec(
    current: GlobalThreadId,
    process_id: kernal_capability::ObjectId,
    handoff: ExecCommitHandoff<{ super::step29_runtime::STEP29_RUNTIME_FDS }>,
) -> Result<(), ()> {
    let result = super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _tid) = state.process_parts_for_scheduler_thread(current)?;
        if process.id() != process_id {
            return Err(super::runtime::Error::InvalidState);
        }
        address_space
            .current_owner(process)
            .map_err(super::runtime::Error::AddressSpace)?;
        let committed = super::step29_runtime::with_process(process_id, |path_runtime| {
            let released = handoff
                .commit_close_on_exec(process, path_runtime.fds())
                .map_err(|_| ())?;
            consume_exec_released_objects(path_runtime, released)
        })
        .map_err(|_| super::runtime::Error::InvalidState)?;
        committed.map_err(|_| super::runtime::Error::InvalidState)
    });
    match result {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

fn commit_exec_signal_reset(current: GlobalThreadId) -> Result<(), ()> {
    let result = super::runtime::with_linux_runtime(|state| {
        state.with_current_process_signals(current, |process, _identities, signals| {
            signals.reset_caught_handlers_for_exec(process)
        })
    });
    match result {
        Ok(Ok(Ok(()))) => Ok(()),
        _ => Err(()),
    }
}

fn commit_exec_identity_marker(current: GlobalThreadId) -> Result<(), ()> {
    let result = super::runtime::with_linux_runtime(|state| {
        state.with_current_process_identity(current, |process, identities| {
            identities.mark_execed(process)
        })
    });
    match result {
        Ok(Ok(Ok(()))) => Ok(()),
        _ => Err(()),
    }
}

fn reclaim_exec_superseded(
    current: GlobalThreadId,
    mut superseded: kernal_process_aarch64::BoundProcessAddressSpace<
        { super::runtime::STEP15_RUNTIME_VMAS },
    >,
) -> Result<(), ()> {
    // SAFETY: caller retains the same PE-local no-switch table/frame/runtime owner window after root
    // replacement. The superseded binding is no longer reachable by scheduler state.
    let result = unsafe {
        kernal_protected_boot_aarch64::RuntimeTablePool::with_live(|page_tables| {
            super::memory::with_live_frame_pool(|frame_pool| {
                super::runtime::with_linux_runtime(|state| {
                    state.with_exec_current_owner(current, |process, active_space, objects| {
                        let allocator = frame_pool.allocator_mut();
                        // SAFETY: exact live Process, committed active binding and linear superseded
                        // binding are held with exclusive table/frame owners for this transaction.
                        unsafe {
                            superseded.reclaim_superseded_anonymous_user_frames(
                                process,
                                objects,
                                active_space,
                                page_tables,
                                |frame| {
                                    let Ok(range) = kernal_frame_allocator::FrameRange::new(
                                        frame.start_address(),
                                        1,
                                    ) else {
                                        return false;
                                    };
                                    allocator.free(range).is_ok()
                                },
                            )
                        }
                    })
                })
            })
        })
    };
    match result {
        Ok(Ok(Ok(Ok(Ok(_released))))) => Ok(()),
        _ => Err(()),
    }
}

fn exec_fail_closed(message: &str) -> ! {
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str(message);
    }
    loop {
        core::hint::spin_loop();
    }
}

const fn signal_mask_how(how: SigmaskHow) -> MaskHow {
    match how {
        SigmaskHow::Block => MaskHow::Block,
        SigmaskHow::Unblock => MaskHow::Unblock,
        SigmaskHow::SetMask => MaskHow::Set,
    }
}

fn decode_rt_sigaction_signal(raw: u64) -> Result<Signal, Errno> {
    let number = linux_unsigned_int(raw);
    let number = u8::try_from(number).map_err(|_| Errno::EINVAL)?;
    Signal::new(number).ok_or(Errno::EINVAL)
}

fn fail_closed_after_signal_send_commit(message: &str) -> ! {
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str(message);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn finish_signal_send_result(result: SignalSendResult, current_cpu: usize) -> Result<Outcome, ()> {
    match result {
        SignalSendResult::Queued(targets) => {
            let mut notifications = SignalNotifyPlan::new();
            notifications.include_targets(current_cpu, targets)?;
            notifications.deliver()?;
            Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?))
        }
        other => encode_signal_send_result(other),
    }
}

fn encode_signal_send_result(result: SignalSendResult) -> Result<Outcome, ()> {
    match result {
        SignalSendResult::UnsupportedTarget => Ok(Outcome::NotHandled),
        SignalSendResult::MissingTarget => Ok(Outcome::Return(SyscallReturn::error(Errno::ESRCH))),
        SignalSendResult::PermissionDenied => {
            Ok(Outcome::Return(SyscallReturn::error(Errno::EPERM)))
        }
        SignalSendResult::ProbeSuccess => Ok(Outcome::Return(SyscallReturn::success(0).ok_or(())?)),
        // A real queued signal must pass through finish_signal_send_result so post-commit SGI
        // notification cannot be silently skipped.
        SignalSendResult::Queued(_) => Err(()),
        SignalSendResult::OwnerError(SignalError::PendingCapacity) => {
            Ok(Outcome::Return(SyscallReturn::error(Errno::EAGAIN)))
        }
        SignalSendResult::OwnerError(_) | SignalSendResult::Invariant => Err(()),
    }
}

fn decode_sigaction_action(raw: KernelSigaction) -> Result<SignalAction, Errno> {
    let restorer = if raw.flags() & SA_RESTORER != 0 {
        Some(raw.restorer())
    } else {
        None
    };
    let mask = SignalSet::from_bits(raw.mask());
    let disposition = match raw.handler() {
        0 => Disposition::Default,
        1 => Disposition::Ignore,
        entry => SignalHandler::new(entry, restorer, raw.flags(), mask)
            .map(Disposition::Handler)
            .map_err(|_| Errno::EINVAL)?,
    };
    SignalAction::new(disposition, raw.flags(), restorer, mask).map_err(|_| Errno::EINVAL)
}

fn encode_sigaction_action(action: SignalAction) -> KernelSigaction {
    let handler = match action.disposition() {
        Disposition::Default => 0,
        Disposition::Ignore => 1,
        Disposition::Handler(handler) => handler.entry(),
    };
    KernelSigaction::new(
        handler,
        action.flags(),
        action.restorer().unwrap_or(0),
        action.mask().bits(),
    )
}

fn map_sigaction_owner_error(error: SignalError) -> Result<Errno, ()> {
    match error {
        SignalError::UncatchableSignal
        | SignalError::UnsupportedFlags
        | SignalError::InvalidHandler => Ok(Errno::EINVAL),
        _ => Err(()),
    }
}

fn map_signal_usercopy_error(error: UsercopyError) -> Result<Errno, ()> {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::TooLarge
        | UsercopyError::Fault => Ok(Errno::EFAULT),
        UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => Err(()),
    }
}

fn resolve_blocking_wait(
    outcome: WaitOutcome,
    current: kernal_scheduler_smp::GlobalThreadId,
    selector: WaitSelector,
    interests: WaitInterests,
    frame: &mut ExceptionFrame,
) -> Result<BlockingWaitResolution, BlockingWaitError> {
    match outcome {
        WaitOutcome::WouldBlock => block_until_wait_ready(current, selector, interests, frame),
        other => Ok(BlockingWaitResolution::Outcome(other)),
    }
}

fn map_blocking_wait_owner_error(error: super::runtime::Error) -> BlockingWaitError {
    match error {
        super::runtime::Error::Wait(WaitError::NoChild) => BlockingWaitError::NoChild,
        _ => BlockingWaitError::Invariant,
    }
}

fn commit_wait_observation_phase2(
    current: kernal_scheduler_smp::GlobalThreadId,
    observation: WaitObservation,
) -> Result<(), ()> {
    match observation.event_class() {
        WaitEventClass::Exited => commit_wait_reap_with_live_owners(current, observation),
        WaitEventClass::Stopped | WaitEventClass::Continued => {
            let consumed = super::runtime::with_linux_runtime(|state| {
                state.consume_wait_nonterminal_for_scheduler_thread(current, observation)
            })
            .map_err(|_| ())?;
            match consumed {
                Ok(()) => Ok(()),
                // A newer real Stop/Continue transition superseded this truthful phase-1 result
                // after userspace writeback. The newer observation remains owned for the next wait.
                Err(super::runtime::Error::Wait(WaitError::StaleObservation)) => Ok(()),
                Err(_) => Err(()),
            }
        }
    }
}

fn commit_wait_reap_with_live_owners(
    current: kernal_scheduler_smp::GlobalThreadId,
    observation: WaitObservation,
) -> Result<(), ()> {
    #[cfg(feature = "step29-qemu-proof")]
    let child = observation.child();

    // SAFETY: destructive wait runs in the synchronous lower-EL owner window. Acquire the global
    // hierarchy owners in the same order as the accepted live-VM path, and keep every borrow scoped
    // to this non-blocking transaction.
    let frame_result = unsafe {
        kernal_protected_boot_aarch64::RuntimeTablePool::with_live(|page_tables| {
            super::memory::with_live_frame_pool(|pool| {
                super::runtime::with_linux_runtime(|state| {
                    state.commit_wait_reap_reclaiming_frames(
                        current,
                        observation,
                        page_tables,
                        pool.allocator_mut(),
                    )
                })
            })
        })
    }
    .map_err(|_| ())?;

    let runtime_result = frame_result.map_err(|_| ())?;
    let semantic_result = runtime_result.map_err(|_| ())?;
    semantic_result.map_err(|_| ())?;

    // The Process/Wait/AddressSpace commit above is authoritative. Retire the process-local FD view
    // only afterwards so WNOWAIT and failed user-result publication remain non-destructive, while a
    // successful zombie reap cannot strand shared OFD/Pipe/Overlay references behind a dead Process.
    #[cfg(feature = "step29-qemu-proof")]
    super::step29_runtime::retire_process(child).map_err(|_| ())?;

    Ok(())
}

fn cancel_blocking_wait(receipt: WaitSleepReceipt) -> Result<bool, BlockingWaitError> {
    super::runtime::with_linux_runtime(|state| state.cancel_wait_sleep(receipt))
        .map_err(|_| BlockingWaitError::Invariant)?
        .map_err(map_blocking_wait_owner_error)
}

fn prime_wait_signal_interruption(
    current: kernal_scheduler_smp::GlobalThreadId,
) -> Result<(), BlockingWaitError> {
    super::runtime::with_linux_runtime(|state| {
        if state
            .signal_syscall_interruption_for_thread(current)?
            .is_some()
        {
            let _ = state.interrupt_wait_for_signal(current)?;
        }
        Ok::<(), super::runtime::Error>(())
    })
    .map_err(|_| BlockingWaitError::Invariant)?
    .map_err(map_blocking_wait_owner_error)
}

fn deliver_interrupted_wait(
    frame: &mut ExceptionFrame,
    current: kernal_scheduler_smp::GlobalThreadId,
    receipt: WaitSleepReceipt,
) -> Result<Option<BlockingWaitResolution>, BlockingWaitError> {
    match super::signal_delivery::deliver_interrupted_wait(frame, current, receipt)
        .map_err(|_| BlockingWaitError::Invariant)?
    {
        super::signal_delivery::InterruptedWaitDelivery::Reobserve => Ok(None),
        super::signal_delivery::InterruptedWaitDelivery::SignalFrameCommitted => {
            Ok(Some(BlockingWaitResolution::SignalFrameCommitted))
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn block_until_wait_ready(
    current: kernal_scheduler_smp::GlobalThreadId,
    selector: WaitSelector,
    interests: WaitInterests,
    frame: &mut ExceptionFrame,
) -> Result<BlockingWaitResolution, BlockingWaitError> {
    let current_cpu = super::super::current_cpu_index();
    if usize::from(current.cpu.0) != current_cpu {
        return Err(BlockingWaitError::Invariant);
    }
    let scheduler = super::super::CPU_SCHEDULERS
        .get(current_cpu)
        .ok_or(BlockingWaitError::Invariant)?;

    loop {
        let prepared = super::runtime::with_linux_runtime(|state| {
            state.prepare_wait_sleep_for_scheduler_thread_with_interests(
                current, selector, interests,
            )
        })
        .map_err(|_| BlockingWaitError::Invariant)?
        .map_err(map_blocking_wait_owner_error)?;

        let receipt = match prepared {
            WaitPrepareOutcome::Ready(observation) => {
                return Ok(BlockingWaitResolution::Outcome(WaitOutcome::Ready(
                    observation,
                )));
            }
            WaitPrepareOutcome::Sleep(receipt) => receipt,
        };

        // A deliverable signal may already have been pending before this waiter was registered. Mark
        // the exact Prepared waiter under the same canonical Signal/Wait runtime ownership; a
        // concurrent sender may have done so already, which is an idempotent owner outcome.
        prime_wait_signal_interruption(current)?;

        let commit = super::runtime::with_linux_runtime(|state| {
            state.commit_wait_sleep_signal_aware(&receipt)
        })
        .map_err(|_| BlockingWaitError::Invariant)?
        .map_err(map_blocking_wait_owner_error)?;
        match commit {
            WaitSignalCommitOutcome::AlreadyWoken => continue,
            WaitSignalCommitOutcome::Interrupted => {
                if let Some(resolution) = deliver_interrupted_wait(frame, current, receipt)? {
                    return Ok(resolution);
                }
                continue;
            }
            WaitSignalCommitOutcome::Sleep => {}
        }

        // No runtime/Process/WaitTable borrow survives this point. The exact committed waiter is the
        // only owner state spanning the scheduler switch. Destination TTBR0 is activated before the
        // selected generation becomes current.
        // SAFETY: lower-EL SVC retains this PE's IRQ-masked, irq_depth=0, preempt_count=0 owner window.
        let switched = unsafe {
            scheduler.bootstrap_block_current_and_switch_with_destination_address_space(
                current,
                super::activate_step30_scheduler_destination,
            )
        };
        match switched {
            Ok(resumed) if resumed == current => {
                // A blocking syscall may switch away and later resume the same scheduler generation.
                // Destination activation records a fresh TTBR0 switch generation, so the retained
                // exception frame must follow that exact resumed binding before post-resume owners
                // validate it or the common signal-return hook attempts to return to EL0.
                let generation = kernal_process_aarch64::current_user_switch_generation()
                    .and_then(NonZeroU64::new)
                    .ok_or(BlockingWaitError::Invariant)?;
                // SAFETY: `resumed == current` proves the same exact scheduler generation is current
                // again, and this synchronous SVC still owns the retained exception frame exclusively.
                unsafe { frame.rebind_entry_switch_generation(generation) };

                // Consume any exact pending scheduler-exit proof first. A child exit racing a signal
                // interruption must be published before we decide whether Wait Notified or Signal
                // Interrupted is authoritative for this receipt.
                super::drain_step30_pending_exits_before_wait(current_cpu)
                    .map_err(|_| BlockingWaitError::Invariant)?;

                let resumed_wait = super::runtime::with_linux_runtime(|state| {
                    state.commit_wait_sleep_signal_aware(&receipt)
                })
                .map_err(|_| BlockingWaitError::Invariant)?;
                match resumed_wait {
                    Ok(WaitSignalCommitOutcome::AlreadyWoken) => continue,
                    Ok(WaitSignalCommitOutcome::Interrupted) => {
                        if let Some(resolution) = deliver_interrupted_wait(frame, current, receipt)?
                        {
                            return Ok(resolution);
                        }
                        continue;
                    }
                    Ok(WaitSignalCommitOutcome::Sleep) => {
                        return Err(BlockingWaitError::Invariant);
                    }
                    Err(super::runtime::Error::Wait(WaitError::StaleWaiter)) => {
                        // A committed child-exit publication consumes the waiter before routing its
                        // exact wake. Reobserve the canonical child state instead of manufacturing EINTR.
                        continue;
                    }
                    Err(super::runtime::Error::Wait(WaitError::WaiterAlreadyCommitted)) => {
                        // A different exact scheduler wake resumed this generation without changing
                        // Wait owner state. Preserve the previous compatibility containment by
                        // cancelling only this exact committed receipt before re-observation.
                        if !cancel_blocking_wait(receipt)? {
                            return Err(BlockingWaitError::Invariant);
                        }
                        continue;
                    }
                    Err(error) => return Err(map_blocking_wait_owner_error(error)),
                }
            }
            Ok(_) => return Err(BlockingWaitError::Invariant),
            Err(kernal_scheduler_cpu::Error::NoRunnableThread) => {
                // The scheduler documents this as a pre-switch failure: current remains Running. A
                // signal may nevertheless have transitioned the waiter to Interrupted after commit,
                // so inspect the canonical Wait state before using compatibility cancellation.
                let current_wait = super::runtime::with_linux_runtime(|state| {
                    state.commit_wait_sleep_signal_aware(&receipt)
                })
                .map_err(|_| BlockingWaitError::Invariant)?;
                match current_wait {
                    Ok(WaitSignalCommitOutcome::AlreadyWoken) => continue,
                    Ok(WaitSignalCommitOutcome::Interrupted) => {
                        if let Some(resolution) = deliver_interrupted_wait(frame, current, receipt)?
                        {
                            return Ok(resolution);
                        }
                        continue;
                    }
                    Ok(WaitSignalCommitOutcome::Sleep) => {
                        return Err(BlockingWaitError::Invariant);
                    }
                    Err(super::runtime::Error::Wait(WaitError::StaleWaiter)) => continue,
                    Err(super::runtime::Error::Wait(WaitError::WaiterAlreadyCommitted)) => {
                        if cancel_blocking_wait(receipt)? {
                            return Err(BlockingWaitError::Invariant);
                        }
                    }
                    Err(error) => return Err(map_blocking_wait_owner_error(error)),
                }
            }
            Err(_) => {
                let _ = cancel_blocking_wait(receipt);
                return Err(BlockingWaitError::Invariant);
            }
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn block_until_wait_ready(
    _current: kernal_scheduler_smp::GlobalThreadId,
    _selector: WaitSelector,
    _interests: WaitInterests,
    _frame: &mut ExceptionFrame,
) -> Result<BlockingWaitResolution, BlockingWaitError> {
    Err(BlockingWaitError::Invariant)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaitIdObservationPlan {
    selector: WaitSelector,
    nohang: bool,
    nowait: bool,
    interests: WaitInterests,
}

/// Decodes the waitid subset backed by the current WaitTable owner. P_ALL and exact P_PID are
/// supported for exited, stopped and continued child observations. Process-group/PIDFD selection,
/// Linux thread-scope flags and rusage remain unhandled until their canonical owners are composed.
fn waitid_observation_plan(
    raw_type: u64,
    raw_id: u64,
    raw_options: u64,
    rusage: u64,
) -> Result<Option<WaitIdObservationPlan>, Errno> {
    let options = decode_waitid_options(raw_options)?;
    if rusage != 0 || options.linux_thread_scope_bits() != 0 {
        return Ok(None);
    }
    let interests = WaitInterests::new(options.exited(), options.stopped(), options.continued())
        .map_err(|_| Errno::EINVAL)?;

    let selector = match decode_waitid_type(raw_type) {
        Some(WaitIdType::All) => WaitSelector::AnyChild,
        Some(WaitIdType::Pid) => {
            let pid = NonZeroU32::new(linux_unsigned_int(raw_id)).ok_or(Errno::EINVAL)?;
            WaitSelector::Pid(pid)
        }
        Some(WaitIdType::ProcessGroup | WaitIdType::PidFd) => return Ok(None),
        None => return Err(Errno::EINVAL),
    };

    Ok(Some(WaitIdObservationPlan {
        selector,
        nohang: options.nohang(),
        nowait: options.nowait(),
        interests,
    }))
}

fn encode_waitid_siginfo(
    pid: NonZeroU32,
    status: WaitStatus,
    event_class: WaitEventClass,
    real_uid: u32,
) -> Result<WaitIdSiginfo, ()> {
    let raw = status.raw();
    match event_class {
        WaitEventClass::Exited => {
            let signal = (raw & 0x7f) as u8;
            if signal == 0 {
                return Ok(WaitIdSiginfo::exited(pid, real_uid, (raw >> 8) as u8));
            }
            WaitIdSiginfo::signaled(pid, real_uid, signal, raw & 0x80 != 0).ok_or(())
        }
        WaitEventClass::Stopped => {
            WaitIdSiginfo::stopped(pid, real_uid, (raw >> 8) as u8).ok_or(())
        }
        WaitEventClass::Continued => Ok(WaitIdSiginfo::continued(pid, real_uid)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Wait4ObservationPlan {
    selector: WaitSelector,
    nohang: bool,
    interests: WaitInterests,
}

/// Decodes the wait4 subset whose canonical owners are composed. Exit is implicit for wait4;
/// WUNTRACED and WCONTINUED extend the event interests. Process-group/thread-scope/rusage modes stay
/// explicitly unhandled until their remaining selection/resource owners are wired.
fn wait4_observation_plan(
    raw_pid: u64,
    raw_options: u64,
    rusage: u64,
) -> Result<Option<Wait4ObservationPlan>, Errno> {
    let options = decode_wait4_options(raw_options)?;
    if rusage != 0 || options.linux_thread_scope_bits() != 0 {
        return Ok(None);
    }
    let interests = WaitInterests::new(true, options.stopped(), options.continued())
        .map_err(|_| Errno::EINVAL)?;
    let selector = match decode_wait4_selector(raw_pid)? {
        Wait4Selector::AnyChild => WaitSelector::AnyChild,
        Wait4Selector::Pid(pid) => WaitSelector::Pid(pid),
        Wait4Selector::SameProcessGroup | Wait4Selector::ProcessGroup(_) => return Ok(None),
    };
    Ok(Some(Wait4ObservationPlan {
        selector,
        nohang: options.nohang(),
        interests,
    }))
}

fn map_wait_usercopy_error(error: UsercopyError) -> Result<Errno, ()> {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::TooLarge
        | UsercopyError::Fault => Ok(Errno::EFAULT),
        UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => Err(()),
    }
}

fn current_pid(current: kernal_scheduler_smp::GlobalThreadId) -> Result<NonZeroU32, ()> {
    super::runtime::with_linux_runtime(|state| {
        state.with_current_process_identity(current, |process, identities| {
            identities.bound_pid(process)
        })
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn current_process_group(current: kernal_scheduler_smp::GlobalThreadId) -> Result<NonZeroU32, ()> {
    super::runtime::with_linux_runtime(|state| {
        state.with_current_process_identity(current, |process, identities| {
            identities.getpgid(process)
        })
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn current_session(current: kernal_scheduler_smp::GlobalThreadId) -> Result<NonZeroU32, ()> {
    super::runtime::with_linux_runtime(|state| {
        state.with_current_process_identity(current, |process, identities| {
            identities.getsid(process)
        })
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn current_credentials() -> Result<LinuxCredentials, ()> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }
    super::runtime::with_linux_runtime(|state| {
        state.with_current_process_credentials(current, |process, credentials| {
            credentials.credentials(process)
        })
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn set_current_no_new_privs() -> Result<(), ()> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }
    super::runtime::with_linux_runtime(|state| {
        state.with_current_process_credentials(current, |process, credentials| {
            credentials.set_no_new_privs(process, true)
        })
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn current_no_new_privs() -> Result<bool, ()> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }
    super::runtime::with_linux_runtime(|state| {
        state.with_current_process_credentials(current, |process, credentials| {
            credentials.no_new_privs(process)
        })
    })
    .map_err(|_| ())?
    .map_err(|_| ())?
    .map_err(|_| ())
}

fn credential_scalar(value: u32) -> Result<SyscallReturn, ()> {
    SyscallReturn::success(i64::from(value)).ok_or(())
}

fn decode_prctl_request(
    option: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Result<NoNewPrivsRequest, Errno> {
    match decode_no_new_privs_prctl(option, arg2, arg3, arg4, arg5) {
        Ok(Some(request)) => Ok(request),
        Ok(None) => Err(Errno::EINVAL),
        Err(errno) => Err(errno),
    }
}

fn decode_no_new_privs_prctl(
    option: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Result<Option<NoNewPrivsRequest>, Errno> {
    match option {
        PR_SET_NO_NEW_PRIVS => {
            if arg2 != 1 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(Some(NoNewPrivsRequest::Set))
            }
        }
        PR_GET_NO_NEW_PRIVS => {
            if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                Err(Errno::EINVAL)
            } else {
                Ok(Some(NoNewPrivsRequest::Get))
            }
        }
        _ => Ok(None),
    }
}

fn process_target_pid(raw_pid: u64, current_pid: NonZeroU32) -> Result<NonZeroU32, Errno> {
    let pid = linux_signed_int(raw_pid);
    if pid == 0 {
        return Ok(current_pid);
    }
    if pid < 0 {
        return Err(Errno::ESRCH);
    }
    NonZeroU32::new(pid as u32).ok_or(Errno::ESRCH)
}

fn current_process_requested(raw_pid: u64, current_pid: NonZeroU32) -> bool {
    let pid = linux_signed_int(raw_pid);
    pid == 0 || (pid > 0 && pid as u32 == current_pid.get())
}

fn encode_getppid(parent: Result<NonZeroU32, IdentityError>) -> Result<SyscallReturn, ()> {
    match parent {
        Ok(pid) => SyscallReturn::success(i64::from(pid.get())).ok_or(()),
        Err(IdentityError::ParentNotBound) => SyscallReturn::success(0).ok_or(()),
        Err(_) => Err(()),
    }
}

fn encode_setpgid(result: Result<NonZeroU32, IdentityError>) -> Result<SyscallReturn, ()> {
    match result {
        Ok(_) => SyscallReturn::success(0).ok_or(()),
        Err(IdentityError::InvalidProcessGroup) => Ok(SyscallReturn::error(Errno::EINVAL)),
        Err(IdentityError::InvalidProcessGroupTarget) => Ok(SyscallReturn::error(Errno::ESRCH)),
        Err(IdentityError::ChildExeced) => Ok(SyscallReturn::error(Errno::EACCES)),
        Err(
            IdentityError::DifferentSession
            | IdentityError::SessionLeader
            | IdentityError::ProcessGroupNotFound,
        ) => Ok(SyscallReturn::error(Errno::EPERM)),
        Err(_) => Err(()),
    }
}

fn encode_setsid(result: Result<NonZeroU32, IdentityError>) -> Result<SyscallReturn, ()> {
    match result {
        Ok(sid) => SyscallReturn::success(i64::from(sid.get())).ok_or(()),
        Err(IdentityError::ProcessGroupLeader) => Ok(SyscallReturn::error(Errno::EPERM)),
        Err(_) => Err(()),
    }
}

fn validate_robust_registration(
    head: u64,
    len: u64,
) -> Result<RobustListRegistration, RegistrationError> {
    let len = usize::try_from(len).map_err(|_| RegistrationError::Errno(Errno::EINVAL))?;
    match RobustListRegistration::new(head, len) {
        Ok(registration) => Ok(registration),
        Err(CredentialError::InvalidRobustListLength) => {
            Err(RegistrationError::Errno(Errno::EINVAL))
        }
        Err(CredentialError::UserRange(_)) => Err(RegistrationError::Errno(Errno::EFAULT)),
        Err(_) => Err(RegistrationError::Invariant),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_credentials::ROBUST_LIST_HEAD_BYTES;
    use kernal_vm::{USER_MAX_EXCLUSIVE, USER_MIN};

    #[test]
    fn signal_send_result_maps_linux_visible_errors_without_hiding_invariants() {
        assert_eq!(
            encode_signal_send_result(SignalSendResult::MissingTarget)
                .unwrap()
                .raw(),
            -(Errno::ESRCH.get() as i64)
        );
        assert_eq!(
            encode_signal_send_result(SignalSendResult::OwnerError(SignalError::PendingCapacity))
                .unwrap()
                .raw(),
            -(Errno::EAGAIN.get() as i64)
        );
        assert_eq!(
            encode_signal_send_result(SignalSendResult::UnsupportedTarget),
            Ok(Outcome::NotHandled)
        );
        assert_eq!(
            encode_signal_send_result(SignalSendResult::PermissionDenied)
                .unwrap()
                .raw(),
            -(Errno::EPERM.get() as i64)
        );
        assert!(encode_signal_send_result(SignalSendResult::Invariant).is_err());
    }

    #[test]
    fn rt_sigaction_default_ignore_roundtrip_nonzero_metadata() {
        let ignored = KernelSigaction::new(1, kernal_linux_signal::SA_RESTART, 0, 1 << (2 - 1));
        let action = decode_sigaction_action(ignored).unwrap();
        assert_eq!(action.disposition(), Disposition::Ignore);
        assert_eq!(encode_sigaction_action(action), ignored);

        let defaulted = KernelSigaction::new(0, kernal_linux_signal::SA_RESTART, 0, 1 << (3 - 1));
        let action = decode_sigaction_action(defaulted).unwrap();
        assert_eq!(action.disposition(), Disposition::Default);
        assert_eq!(encode_sigaction_action(action), defaulted);
    }

    #[test]
    fn rt_sigaction_decoder_still_rejects_signal_zero() {
        assert_eq!(decode_rt_sigaction_signal(0), Err(Errno::EINVAL));
        assert!(decode_rt_sigaction_signal(1).is_ok());
        assert!(decode_rt_sigaction_signal(64).is_ok());
        assert_eq!(decode_rt_sigaction_signal(65), Err(Errno::EINVAL));
    }

    #[test]
    fn waitid_plan_accepts_all_exact_pid_wnohang_wnowait_and_job_control() {
        assert_eq!(
            waitid_observation_plan(0, u64::MAX, 0x0000_0004, 0),
            Ok(Some(WaitIdObservationPlan {
                selector: WaitSelector::AnyChild,
                nohang: false,
                nowait: false,
                interests: WaitInterests::EXITED,
            }))
        );
        assert_eq!(
            waitid_observation_plan(1, 23, 0x0100_0005, 0),
            Ok(Some(WaitIdObservationPlan {
                selector: WaitSelector::Pid(NonZeroU32::new(23).unwrap()),
                nohang: true,
                nowait: true,
                interests: WaitInterests::EXITED,
            }))
        );
        assert_eq!(
            waitid_observation_plan(0, 0, 0x2, 0),
            Ok(Some(WaitIdObservationPlan {
                selector: WaitSelector::AnyChild,
                nohang: false,
                nowait: false,
                interests: WaitInterests::STOPPED,
            }))
        );
        assert_eq!(
            waitid_observation_plan(0, 0, 0x8, 0),
            Ok(Some(WaitIdObservationPlan {
                selector: WaitSelector::AnyChild,
                nohang: false,
                nowait: false,
                interests: WaitInterests::CONTINUED,
            }))
        );
    }

    #[test]
    fn waitid_plan_rejects_invalid_inputs_and_leaves_unwired_selection_modes_unhandled() {
        assert_eq!(waitid_observation_plan(4, 0, 0x4, 0), Err(Errno::EINVAL));
        assert_eq!(waitid_observation_plan(1, 0, 0x4, 0), Err(Errno::EINVAL));
        assert_eq!(waitid_observation_plan(2, 23, 0x4, 0), Ok(None));
        assert_eq!(waitid_observation_plan(3, 23, 0x4, 0), Ok(None));
        assert_eq!(waitid_observation_plan(0, 0, 0x2000_0004, 0), Ok(None));
        assert_eq!(waitid_observation_plan(0, 0, 0x4, 1), Ok(None));
        assert_eq!(waitid_observation_plan(0, 0, 0, 0), Err(Errno::EINVAL));
    }

    #[test]
    fn waitid_siginfo_maps_event_class_without_guessing_from_raw_status() {
        let pid = NonZeroU32::new(23).unwrap();
        assert_eq!(
            encode_waitid_siginfo(pid, WaitStatus::exited(7), WaitEventClass::Exited, 1000)
                .unwrap(),
            WaitIdSiginfo::exited(pid, 1000, 7)
        );
        assert_eq!(
            encode_waitid_siginfo(
                pid,
                WaitStatus::signaled(15, false).unwrap(),
                WaitEventClass::Exited,
                1000,
            )
            .unwrap(),
            WaitIdSiginfo::signaled(pid, 1000, 15, false).unwrap()
        );
        assert_eq!(
            encode_waitid_siginfo(
                pid,
                WaitStatus::signaled(11, true).unwrap(),
                WaitEventClass::Exited,
                1000,
            )
            .unwrap(),
            WaitIdSiginfo::signaled(pid, 1000, 11, true).unwrap()
        );
        assert_eq!(
            encode_waitid_siginfo(
                pid,
                WaitStatus::stopped(19).unwrap(),
                WaitEventClass::Stopped,
                1000,
            )
            .unwrap(),
            WaitIdSiginfo::stopped(pid, 1000, 19).unwrap()
        );
        assert_eq!(
            encode_waitid_siginfo(
                pid,
                WaitStatus::continued(),
                WaitEventClass::Continued,
                1000,
            )
            .unwrap(),
            WaitIdSiginfo::continued(pid, 1000)
        );
    }

    #[test]
    fn wait4_plan_accepts_exact_pid_any_child_wnohang_and_job_control() {
        assert_eq!(
            wait4_observation_plan(u64::MAX, 0, 0),
            Ok(Some(Wait4ObservationPlan {
                selector: WaitSelector::AnyChild,
                nohang: false,
                interests: WaitInterests::EXITED,
            }))
        );
        assert_eq!(
            wait4_observation_plan(23, 1, 0),
            Ok(Some(Wait4ObservationPlan {
                selector: WaitSelector::Pid(NonZeroU32::new(23).unwrap()),
                nohang: true,
                interests: WaitInterests::EXITED,
            }))
        );
        assert_eq!(
            wait4_observation_plan(u64::MAX, 2, 0),
            Ok(Some(Wait4ObservationPlan {
                selector: WaitSelector::AnyChild,
                nohang: false,
                interests: WaitInterests::new(true, true, false).unwrap(),
            }))
        );
        assert_eq!(
            wait4_observation_plan(u64::MAX, 8, 0),
            Ok(Some(Wait4ObservationPlan {
                selector: WaitSelector::AnyChild,
                nohang: false,
                interests: WaitInterests::new(true, false, true).unwrap(),
            }))
        );
    }

    #[test]
    fn wait4_plan_refuses_unwired_group_thread_and_rusage_modes() {
        assert_eq!(wait4_observation_plan(0, 0, 0), Ok(None));
        assert_eq!(
            wait4_observation_plan((-23i32 as u32) as u64, 0, 0),
            Ok(None)
        );
        assert_eq!(wait4_observation_plan(u64::MAX, 0x2000_0000, 0), Ok(None));
        assert_eq!(wait4_observation_plan(u64::MAX, 0, 1), Ok(None));
        assert_eq!(wait4_observation_plan(u64::MAX, 4, 0), Err(Errno::EINVAL));
    }

    #[test]
    fn wait4_usercopy_faults_map_only_recoverable_user_errors_to_efault() {
        assert_eq!(
            map_wait_usercopy_error(UsercopyError::Fault),
            Ok(Errno::EFAULT)
        );
        assert_eq!(
            map_wait_usercopy_error(UsercopyError::OutsideUserRange),
            Ok(Errno::EFAULT)
        );
        assert_eq!(
            map_wait_usercopy_error(UsercopyError::PanStateLeak),
            Err(())
        );
    }

    #[test]
    fn no_new_privs_prctl_matches_linux_argument_contract() {
        assert_eq!(
            decode_no_new_privs_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
            Ok(Some(NoNewPrivsRequest::Set))
        );
        assert_eq!(
            decode_no_new_privs_prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
            Ok(Some(NoNewPrivsRequest::Get))
        );
        assert_eq!(
            decode_no_new_privs_prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            decode_no_new_privs_prctl(PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            decode_no_new_privs_prctl(PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0),
            Err(Errno::EINVAL)
        );
        assert_eq!(decode_no_new_privs_prctl(0, 0, 0, 0, 0), Ok(None));
        assert_eq!(decode_prctl_request(0, 0, 0, 0, 0), Err(Errno::EINVAL));
    }

    #[test]
    fn process_target_pid_maps_zero_positive_and_negative_linux_inputs() {
        let current = NonZeroU32::new(23).unwrap();
        assert_eq!(process_target_pid(0, current), Ok(current));
        assert_eq!(
            process_target_pid(17, current),
            NonZeroU32::new(17).ok_or(Errno::ESRCH)
        );
        assert_eq!(process_target_pid(u64::MAX, current), Err(Errno::ESRCH));
    }

    #[test]
    fn current_process_selector_accepts_zero_and_exact_pid_only() {
        let current = NonZeroU32::new(23).unwrap();
        assert!(current_process_requested(0, current));
        assert!(current_process_requested(23, current));
        assert!(!current_process_requested(24, current));
        assert!(!current_process_requested(u64::MAX, current));
    }

    #[test]
    fn getppid_maps_only_missing_parent_to_linux_zero() {
        assert_eq!(
            encode_getppid(Err(IdentityError::ParentNotBound))
                .unwrap()
                .raw(),
            0
        );
        assert!(encode_getppid(Err(IdentityError::ProcessNotBound)).is_err());
        assert_eq!(
            encode_getppid(Ok(NonZeroU32::new(17).unwrap()))
                .unwrap()
                .raw(),
            17
        );
    }

    #[test]
    fn setpgid_maps_linux_policy_errors_without_hiding_invariants() {
        assert_eq!(
            encode_setpgid(Ok(NonZeroU32::new(23).unwrap()))
                .unwrap()
                .raw(),
            0
        );
        assert_eq!(
            encode_setpgid(Err(IdentityError::InvalidProcessGroup))
                .unwrap()
                .raw(),
            -(Errno::EINVAL.get() as i64)
        );
        for error in [
            IdentityError::DifferentSession,
            IdentityError::SessionLeader,
            IdentityError::ProcessGroupNotFound,
        ] {
            assert_eq!(
                encode_setpgid(Err(error)).unwrap().raw(),
                -(Errno::EPERM.get() as i64)
            );
        }
        assert!(encode_setpgid(Err(IdentityError::ProcessNotBound)).is_err());
    }

    #[test]
    fn setsid_maps_process_group_leader_to_eperm_and_fails_closed_otherwise() {
        assert_eq!(
            encode_setsid(Err(IdentityError::ProcessGroupLeader))
                .unwrap()
                .raw(),
            -(Errno::EPERM.get() as i64)
        );
        assert!(encode_setsid(Err(IdentityError::ProcessNotBound)).is_err());
        assert_eq!(
            encode_setsid(Ok(NonZeroU32::new(23).unwrap()))
                .unwrap()
                .raw(),
            23
        );
    }

    #[test]
    fn robust_registration_requires_linux_head_size() {
        assert_eq!(
            validate_robust_registration(USER_MIN, (ROBUST_LIST_HEAD_BYTES - 1) as u64),
            Err(RegistrationError::Errno(Errno::EINVAL))
        );
        assert!(validate_robust_registration(USER_MIN, ROBUST_LIST_HEAD_BYTES as u64).is_ok());
    }

    #[test]
    fn robust_registration_rejects_non_user_ranges_without_dereference() {
        assert_eq!(
            validate_robust_registration(0, ROBUST_LIST_HEAD_BYTES as u64),
            Err(RegistrationError::Errno(Errno::EFAULT))
        );
        assert_eq!(
            validate_robust_registration(USER_MAX_EXCLUSIVE, ROBUST_LIST_HEAD_BYTES as u64),
            Err(RegistrationError::Errno(Errno::EFAULT))
        );
    }
}
