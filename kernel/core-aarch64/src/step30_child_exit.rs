// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use kernal_percpu::CpuIndex;
use kernal_scheduler::{JobControlContinueOutcome, JobControlStopOutcome};
use kernal_scheduler_smp::{
    JobControlAppliedOutcome, JobControlCommand, JobControlCompletion, JobControlDrainReport,
    JobControlGeneration, JobControlPendingClaim, JobControlRequest, RemoteJobControlQueue,
};

const PROCESS_JOB_CONTROL_MAILBOX_SLOTS: usize = super::runtime::STEP15_RUNTIME_THREADS;
const _: () = assert!(super::super::MAX_PROOF_CPUS == 4);

/// One bounded Job-Control mailbox per scheduler owner PE.
///
/// Capacity equals the maximum exact scheduler generations on one PE, so one current process-level
/// transaction can address every live local generation without allocating. The same mailbox retains
/// both remote-owner and locally-applied scheduler ACKs until Runtime/Wait/Signal composition accepts
/// them. These queues are transport only: they never own Process/PID identity and never mutate a
/// foreign RunQueue.
static PROCESS_JOB_CONTROL_MAILBOXES: [RemoteJobControlQueue<PROCESS_JOB_CONTROL_MAILBOX_SLOTS>;
    super::super::MAX_PROOF_CPUS] = [
    RemoteJobControlQueue::new(CpuIndex(0)),
    RemoteJobControlQueue::new(CpuIndex(1)),
    RemoteJobControlQueue::new(CpuIndex(2)),
    RemoteJobControlQueue::new(CpuIndex(3)),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessJobControlDispatch {
    targets: super::runtime::ProcessJobControlTargets,
    generation: JobControlGeneration,
    command: JobControlCommand,
}

impl ProcessJobControlDispatch {
    pub(super) const fn targets(self) -> super::runtime::ProcessJobControlTargets {
        self.targets
    }

    pub(super) const fn generation(self) -> JobControlGeneration {
        self.generation
    }

    pub(super) const fn command(self) -> JobControlCommand {
        self.command
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessJobControlDispatchResult {
    request_reschedule: bool,
}

impl ProcessJobControlDispatchResult {
    pub(super) const fn request_reschedule(self) -> bool {
        self.request_reschedule
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessJobControlCompletionProgress {
    /// Completion belongs to a previously issued transaction that has already been superseded or
    /// published. The transport ACK may be released, but it must never trigger Linux-visible state.
    Stale,
    /// This exact completion was retained, but other exact target generations are still outstanding.
    Pending,
    /// Every exact target acknowledged the current transaction. `event=None` means every scheduler
    /// result was a no-op (`AlreadyStopped`/`NotStopped`), so no Wait/SIGCHLD event is truthful.
    Complete {
        targets: super::runtime::ProcessJobControlTargets,
        event: Option<super::runtime::ProcessJobControlEvent>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessJobControlTransaction {
    targets: super::runtime::ProcessJobControlTargets,
    generation: JobControlGeneration,
    command: JobControlCommand,
    stop_signal: Option<u8>,
    outcomes: [Option<JobControlAppliedOutcome>; super::runtime::STEP15_RUNTIME_THREADS],
}

impl ProcessJobControlTransaction {
    fn target_index(self, thread: kernal_scheduler_smp::GlobalThreadId) -> Option<usize> {
        self.targets.iter().position(|target| target == thread)
    }

    fn accepts_outcome(self, outcome: JobControlAppliedOutcome) -> bool {
        match self.command {
            JobControlCommand::Stop => matches!(
                outcome,
                JobControlAppliedOutcome::AlreadyStopped
                    | JobControlAppliedOutcome::Held
                    | JobControlAppliedOutcome::Deschedule
            ),
            JobControlCommand::Continue => matches!(
                outcome,
                JobControlAppliedOutcome::NotStopped
                    | JobControlAppliedOutcome::Continued
                    | JobControlAppliedOutcome::Readied
            ),
        }
    }

    fn real_transition(self) -> bool {
        self.outcomes[..self.targets.len()]
            .iter()
            .flatten()
            .copied()
            .any(JobControlAppliedOutcome::is_real_transition)
    }

    fn event(self) -> Result<Option<super::runtime::ProcessJobControlEvent>, ()> {
        if !self.real_transition() {
            return Ok(None);
        }
        match self.command {
            JobControlCommand::Stop => {
                let signal = self.stop_signal.ok_or(())?;
                Ok(Some(super::runtime::ProcessJobControlEvent::Stopped {
                    signal,
                }))
            }
            JobControlCommand::Continue => {
                if self.stop_signal.is_some() {
                    return Err(());
                }
                Ok(Some(super::runtime::ProcessJobControlEvent::Continued))
            }
        }
    }
}

struct ProcessJobControlTransactionState {
    next_generation: u64,
    transactions: [Option<ProcessJobControlTransaction>; super::runtime::STEP15_RUNTIME_PROCESSES],
}

impl ProcessJobControlTransactionState {
    const fn new() -> Self {
        Self {
            next_generation: 1,
            transactions: [None; super::runtime::STEP15_RUNTIME_PROCESSES],
        }
    }
}

/// Core-only receipt owner for in-flight process-level Job-Control composition.
///
/// This is deliberately not a Process/PID/scheduler registry. Every transaction carries only the
/// exact observations returned by the canonical LinuxIdentity/runtime owner plus scheduler transport
/// generations. Actual Process, Wait, Signal and RunQueue mutation always re-enters their canonical
/// owners. The lock protects only this bounded receipt state; callers must never hold it while
/// entering RuntimeCell, touching a RunQueue, sending an SGI, or waiting for another CPU.
struct ProcessJobControlTransactionCell {
    locked: AtomicBool,
    state: UnsafeCell<ProcessJobControlTransactionState>,
}

// SAFETY: `state` is accessed only after successful acquisition of `locked`; every access releases
// the lock before calling any external owner. No reference into the cell escapes `with_state`.
unsafe impl Sync for ProcessJobControlTransactionCell {}

impl ProcessJobControlTransactionCell {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(ProcessJobControlTransactionState::new()),
        }
    }

    fn with_state<R>(
        &self,
        operation: impl FnOnce(&mut ProcessJobControlTransactionState) -> R,
    ) -> R {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the successful CAS gives this caller exclusive access until the Release store.
        let result = operation(unsafe { &mut *self.state.get() });
        self.locked.store(false, Ordering::Release);
        result
    }
}

static PROCESS_JOB_CONTROL_TRANSACTIONS: ProcessJobControlTransactionCell =
    ProcessJobControlTransactionCell::new();

pub(super) fn process_job_control_mailbox(
    cpu: usize,
) -> Option<&'static RemoteJobControlQueue<PROCESS_JOB_CONTROL_MAILBOX_SLOTS>> {
    PROCESS_JOB_CONTROL_MAILBOXES.get(cpu)
}

/// Begins or supersedes the one current Job-Control transaction for an exact Process generation.
///
/// The caller must obtain `targets` from `Step15LinuxRuntime::job_control_targets_for_pid` and invoke
/// this immediately after the corresponding SignalTable generation commit while still inside that
/// same serialized RuntimeCell transaction. That ordering makes transaction generation order equal
/// canonical signal-generation order, so Stop -> Continue races cannot later publish an older Stop.
/// No scheduler state is changed here.
pub(super) fn begin_process_job_control_transaction(
    targets: super::runtime::ProcessJobControlTargets,
    command: JobControlCommand,
    stop_signal: Option<u8>,
) -> Result<ProcessJobControlDispatch, ()> {
    if targets.is_empty() {
        return Err(());
    }
    match command {
        JobControlCommand::Stop => {
            let signal = stop_signal.ok_or(())?;
            let signal = kernal_linux_signal::Signal::new(signal).ok_or(())?;
            if kernal_linux_signal::default_action(signal)
                != kernal_linux_signal::DefaultAction::Stop
            {
                return Err(());
            }
        }
        JobControlCommand::Continue if stop_signal.is_some() => return Err(()),
        JobControlCommand::Continue => {}
    }

    PROCESS_JOB_CONTROL_TRANSACTIONS.with_state(|state| {
        let generation = JobControlGeneration::new(state.next_generation).ok_or(())?;
        state.next_generation = state.next_generation.checked_add(1).unwrap_or(0);

        let slot = state
            .transactions
            .iter()
            .position(|transaction| {
                transaction
                    .as_ref()
                    .is_some_and(|transaction| transaction.targets.process() == targets.process())
            })
            .or_else(|| state.transactions.iter().position(Option::is_none))
            .ok_or(())?;

        // Replacing an older same-Process receipt is the sole supersession edge. Scheduler mailboxes
        // carry the newer full-width generation and replace old pending/completed evidence for this
        // exact scheduler target; any already-copied older ACK is rejected below.
        state.transactions[slot] = Some(ProcessJobControlTransaction {
            targets,
            generation,
            command,
            stop_signal,
            outcomes: [None; super::runtime::STEP15_RUNTIME_THREADS],
        });

        Ok(ProcessJobControlDispatch {
            targets,
            generation,
            command,
        })
    })
}

fn applied_stop(outcome: JobControlStopOutcome) -> JobControlAppliedOutcome {
    match outcome {
        JobControlStopOutcome::AlreadyStopped => JobControlAppliedOutcome::AlreadyStopped,
        JobControlStopOutcome::Held => JobControlAppliedOutcome::Held,
        JobControlStopOutcome::Deschedule => JobControlAppliedOutcome::Deschedule,
    }
}

fn applied_continue(outcome: JobControlContinueOutcome) -> JobControlAppliedOutcome {
    match outcome {
        JobControlContinueOutcome::NotStopped => JobControlAppliedOutcome::NotStopped,
        JobControlContinueOutcome::Continued => JobControlAppliedOutcome::Continued,
        JobControlContinueOutcome::Readied => JobControlAppliedOutcome::Readied,
    }
}

fn claim_exact_local_job_control_request(
    mailbox: &RemoteJobControlQueue<PROCESS_JOB_CONTROL_MAILBOX_SLOTS>,
    request: JobControlRequest,
) -> Result<JobControlPendingClaim, ()> {
    for _ in 0..PROCESS_JOB_CONTROL_MAILBOX_SLOTS {
        let Some(claim) = mailbox.claim_pending().map_err(|_| ())? else {
            return Err(());
        };
        if claim.request() == request {
            return Ok(claim);
        }
        mailbox.restore_pending(claim).map_err(|_| ())?;
    }
    Err(())
}

/// Applies the current process transaction to exact local scheduler generations and publishes remote
/// requests to their owner-CPU mailboxes before sending RESCHEDULE SGIs.
///
/// Every request, including an owner-local request, is first published into the target PE's sole
/// durable mailbox. For a local target Core claims exactly that pending request before the irreversible
/// RunQueue operation, applies the canonical scheduler owner, then turns the same reserved slot into a
/// durable Completed ACK. Thus local and remote completions survive RuntimeCell contention identically
/// and are consumed only by `service_process_job_control_completions`. No foreign RunQueue is touched.
pub(super) fn dispatch_process_job_control(
    dispatch: ProcessJobControlDispatch,
    current_cpu: usize,
) -> Result<ProcessJobControlDispatchResult, ()> {
    if current_cpu >= super::super::MAX_PROOF_CPUS {
        return Err(());
    }
    let mut request_reschedule = false;

    for target in dispatch.targets().iter() {
        let target_cpu = usize::from(target.cpu.0);
        let target_scheduler = super::super::CPU_SCHEDULERS.get(target_cpu).ok_or(())?;
        let mailbox = process_job_control_mailbox(target_cpu).ok_or(())?;
        let request = JobControlRequest::new(target, dispatch.command(), dispatch.generation());
        // Capacity/supersession validation happens before any local scheduler mutation and publication
        // precedes a remote SGI. A newer transaction may replace older pending/completed evidence for
        // the same exact scheduler generation, but never vice versa.
        mailbox.push(request).map_err(|_| ())?;

        if target_cpu == current_cpu {
            let claim = claim_exact_local_job_control_request(mailbox, request)?;
            // SAFETY: caller is the synchronous IRQ-masked owner of `current_cpu`; target identity
            // came only from the canonical Runtime/LinuxIdentity snapshot retained in `dispatch`.
            // `claim` keeps this exact mailbox request RESERVED until the RunQueue result is durable.
            let scheduler_result = match dispatch.command() {
                JobControlCommand::Stop => {
                    unsafe { target_scheduler.bootstrap_job_control_stop(target) }.map(applied_stop)
                }
                JobControlCommand::Continue => {
                    unsafe { target_scheduler.bootstrap_job_control_continue(target) }
                        .map(applied_continue)
                }
            };
            let outcome = match scheduler_result {
                Ok(outcome) => outcome,
                Err(_) => {
                    // The scheduler owner rejected the mutation before producing completion evidence.
                    // Return the exact RESERVED request to Pending so a fail-stop caller cannot strand
                    // a mailbox slot in a non-retriable reservation state.
                    mailbox.restore_pending(claim).map_err(|_| ())?;
                    return Err(());
                }
            };
            request_reschedule |= matches!(
                outcome,
                JobControlAppliedOutcome::Deschedule | JobControlAppliedOutcome::Readied
            );
            mailbox.complete_pending(claim, outcome).map_err(|_| ())?;
            continue;
        }

        let mpidr = super::super::CPU_MPIDRS
            .get(target_cpu)
            .ok_or(())?
            .load(Ordering::Acquire);
        let affinity = kernal_arch_aarch64::CpuAffinity::from_mpidr(mpidr);
        // SAFETY: the exact request is Release-published in the target owner's atomic mailbox before
        // this notification. A send failure after publication is an internal post-commit invariant.
        unsafe {
            kernal_gicv3_aarch64::send_sgi1(kernal_gicv3_aarch64::RESCHEDULE_SGI_DEFAULT, affinity)
        }
        .map_err(|_| ())?;
    }

    Ok(ProcessJobControlDispatchResult { request_reschedule })
}

/// Drains only the current PE's exact remote Job-Control requests in first-level IRQ context.
///
/// The scheduler owner turns every revalidated request into durable completion evidence. This helper
/// intentionally does not feed the Linux transaction owner and does not ACK the transport; RuntimeCell
/// may be busy on another CPU while this IRQ runs, so completed evidence must survive until the later
/// post-IRQ composition step.
///
/// # Safety
/// Must run from `current_cpu`'s first-level RESCHEDULE SGI handler after `enter_irq()` and before EOI,
/// with the owner contract required by `CpuSchedulerCell::drain_remote_job_control_exact_from_irq`.
pub(super) unsafe fn drain_process_job_control_from_irq(
    current_cpu: usize,
) -> Result<JobControlDrainReport, ()> {
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    let mailbox = process_job_control_mailbox(current_cpu).ok_or(())?;
    // SAFETY: delegated first-level IRQ owner contract; mailbox owner index is statically identical.
    let result = unsafe {
        scheduler
            .drain_remote_job_control_exact_from_irq(mailbox, PROCESS_JOB_CONTROL_MAILBOX_SLOTS)
    }
    .map_err(|_| ())?;
    Ok(result.report())
}

/// Retains one exact owner-CPU scheduler ACK and determines whether the current Process transaction
/// is complete. The transport completion itself remains owned by its RemoteJobControlQueue until Core
/// explicitly acknowledges it after this function succeeds.
///
/// Older generations are returned as `Stale` and may be acknowledged without publication. A future
/// generation, opposite command, foreign target or impossible command/outcome pair fails closed.
/// Completion never directly touches WaitTable or SignalTable; a returned `Complete` must flow through
/// the canonical Runtime publication owner before transport ACK.
pub(super) fn retain_process_job_control_completion(
    completion: JobControlCompletion,
) -> Result<ProcessJobControlCompletionProgress, ()> {
    PROCESS_JOB_CONTROL_TRANSACTIONS.with_state(|state| {
        let matching_slot = state.transactions.iter().position(|transaction| {
            transaction
                .as_ref()
                .is_some_and(|transaction| transaction.target_index(completion.thread()).is_some())
        });

        let Some(slot) = matching_slot else {
            // A completion for an already-issued generation may outlive a transaction after a newer
            // signal superseded it or after final publication but before transport ACK. Anything that
            // has never been issued by this owner is corruption/future evidence.
            if state.next_generation != 0 && completion.generation().get() < state.next_generation {
                return Ok(ProcessJobControlCompletionProgress::Stale);
            }
            return Err(());
        };

        let mut transaction = state.transactions[slot].ok_or(())?;
        if completion.generation() < transaction.generation {
            return Ok(ProcessJobControlCompletionProgress::Stale);
        }
        if completion.generation() > transaction.generation
            || completion.command() != transaction.command
            || !transaction.accepts_outcome(completion.outcome())
        {
            return Err(());
        }

        let target_index = transaction.target_index(completion.thread()).ok_or(())?;
        match transaction.outcomes[target_index] {
            Some(existing) if existing != completion.outcome() => return Err(()),
            Some(_) => {}
            None => transaction.outcomes[target_index] = Some(completion.outcome()),
        }
        state.transactions[slot] = Some(transaction);

        if transaction.outcomes[..transaction.targets.len()]
            .iter()
            .any(Option::is_none)
        {
            return Ok(ProcessJobControlCompletionProgress::Pending);
        }

        let event = transaction.event()?;
        state.transactions[slot] = None;
        Ok(ProcessJobControlCompletionProgress::Complete {
            targets: transaction.targets,
            event,
        })
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessExitNotifyPlan {
    cpus: [bool; super::super::MAX_PROOF_CPUS],
}

impl ProcessExitNotifyPlan {
    const fn new() -> Self {
        Self {
            cpus: [false; super::super::MAX_PROOF_CPUS],
        }
    }

    fn include_targets(
        &mut self,
        current_cpu: usize,
        targets: super::runtime::ProcessExitSignalTargets,
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
                // SAFETY: signal state was already committed under the sole runtime owner. This SGI
                // is notification only and does not publish scheduler runnable state or another
                // signal registry.
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

fn route_process_job_control_publication(
    publication: super::runtime::ProcessJobControlPublication,
    current_cpu: usize,
) -> Result<(), ()> {
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    let scheduler_owner = scheduler.owner().map_err(|_| ())?;
    if usize::from(scheduler_owner.0) != current_cpu {
        return Err(());
    }
    super::wake_wait_exit_batch(current_cpu, scheduler, Some(publication.wakes()))?;
    let mut notifications = ProcessExitNotifyPlan::new();
    notifications.include_targets(current_cpu, publication.signal_targets())?;
    notifications.deliver()
}

/// Retries durable completed local or remote Job-Control evidence after owner scheduler mutation has
/// ended. Each completion is first composed under the sole RuntimeCell. `RuntimeCell::Busy` is not
/// failure: the transport slot remains Completed and unacknowledged, so a later safe point can retry
/// without reapplying the RunQueue operation. When a full process transaction completes, Wait/SIGCHLD
/// publication occurs inside that same RuntimeCell borrow immediately after the receipt is consumed;
/// only routing occurs after the borrow ends. The mailbox ACK is the final step.
///
/// Returns `true` when at least one completion must be retried because RuntimeCell was temporarily
/// busy. Callers should arrange another owner-CPU safe point/RESCHEDULE notification.
pub(super) fn service_process_job_control_completions(current_cpu: usize) -> Result<bool, ()> {
    let mailbox = process_job_control_mailbox(current_cpu).ok_or(())?;
    let completions = mailbox
        .completed_batch(PROCESS_JOB_CONTROL_MAILBOX_SLOTS)
        .map_err(|_| ())?;
    let mut retry = false;

    for completion in completions.iter() {
        let composed = super::runtime::with_linux_runtime(|state| {
            let progress = retain_process_job_control_completion(completion)
                .map_err(|_| super::runtime::Error::InvalidState)?;
            match progress {
                ProcessJobControlCompletionProgress::Stale
                | ProcessJobControlCompletionProgress::Pending => Ok(None),
                ProcessJobControlCompletionProgress::Complete { event: None, .. } => Ok(None),
                ProcessJobControlCompletionProgress::Complete {
                    targets,
                    event: Some(event),
                } => state.publish_process_job_control_completion(targets, event),
            }
        });

        let publication = match composed {
            Err(super::runtime::Error::Busy) => {
                retry = true;
                continue;
            }
            Err(_) => return Err(()),
            Ok(Err(_)) => return Err(()),
            Ok(Ok(publication)) => publication,
        };

        if let Some(publication) = publication {
            route_process_job_control_publication(publication, current_cpu)?;
        }
        mailbox.acknowledge(completion).map_err(|_| ())?;
    }

    Ok(retry)
}

fn request_process_job_control_retry(current_cpu: usize) -> Result<(), ()> {
    let mpidr = super::super::CPU_MPIDRS
        .get(current_cpu)
        .ok_or(())?
        .load(Ordering::Acquire);
    let affinity = kernal_arch_aarch64::CpuAffinity::from_mpidr(mpidr);
    // SAFETY: durable Completed evidence remains in this PE's mailbox. Self-SGI only schedules a
    // later owner safe point and never reapplies scheduler state by itself.
    unsafe {
        kernal_gicv3_aarch64::send_sgi1(kernal_gicv3_aarch64::RESCHEDULE_SGI_DEFAULT, affinity)
    }
    .map_err(|_| ())
}

/// Completes one producer-side Job-Control dispatch after its signal generation has already committed.
///
/// Local Completed evidence is composed immediately through the same Runtime/Wait/Signal path used by
/// remote IRQ ACKs. RuntimeCell contention retains the exact completion and rearms a self-SGI retry.
/// If scheduler state now requires a switch, the only legal transition is the job-control-aware
/// post-owner safe point; a stopped current generation therefore cannot return to EL0 before Continue.
///
/// # Safety
/// Must run on `current_cpu` with local IRQs masked, irq_depth=0, preempt_count=0 and migration
/// suppressed. The caller must treat every error as fail-stop because the signal generation and at
/// least part of the scheduler transaction may already be authoritative.
pub(super) unsafe fn finish_process_job_control_dispatch(
    dispatch: ProcessJobControlDispatchResult,
    current_cpu: usize,
) -> Result<(), ()> {
    if service_process_job_control_completions(current_cpu)? {
        request_process_job_control_retry(current_cpu)?;
    }
    if !dispatch.request_reschedule() {
        return Ok(());
    }
    let scheduler = super::super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    // SAFETY: delegated owner/quiescence contract; the destination callback is the canonical
    // Process/AddressSpace activation owner already used by the architecture IRQ safe point.
    unsafe {
        scheduler.bootstrap_reschedule_with_job_control_destination_address_space(
            super::activate_step30_scheduler_destination,
        )
    }
    .map_err(|_| ())?;
    Ok(())
}

/// Publishes one process-level Linux Stop/Continue observation after Core has already collected real
/// scheduler completion for the exact bounded target generation set.
///
/// This compatibility edge is retained for callers that already own an exact completion receipt by
/// value. New local and remote scheduler dispatch uses the durable per-CPU mailbox and
/// `service_process_job_control_completions` instead.
pub(super) fn complete_process_job_control_after_scheduler(
    targets: super::runtime::ProcessJobControlTargets,
    event: super::runtime::ProcessJobControlEvent,
    current_cpu: usize,
) -> Result<(), ()> {
    let publication = super::runtime::with_linux_runtime(|state| {
        state.publish_process_job_control_completion(targets, event)
    })
    .map_err(|_| ())?
    .map_err(|_| ())?;
    if let Some(publication) = publication {
        route_process_job_control_publication(publication, current_cpu)?;
    }
    Ok(())
}

/// Completes the post-lifecycle Linux parent notification/wait policy after the canonical exit owner
/// has retired the exact child scheduler/LinuxIdentity generation.
///
/// Signal policy is sampled and SIGCHLD is committed under the sole Linux runtime owner. Ordinary
/// children publish a zombie in that same transaction. Auto-reap children leave their retained
/// Process/AddressSpace slot intact until this function re-enters the owners in the canonical global
/// order: live page tables -> physical-frame pool -> Linux runtime. Only then are anonymous frames,
/// child metadata, Wait state and the retained process slot destroyed. The Step-29 path/FD view, when
/// enabled, is retired only after that destructive runtime transaction has completed successfully.
pub(super) fn complete_process_exit_wait_after_lifecycle(
    process_id: kernal_capability::ObjectId,
    completion: kernal_linux_exit_lifecycle::Completion,
    cause: kernal_linux_exit_lifecycle::ExitCause,
    current_cpu: usize,
) -> Result<
    Option<kernal_linux_wait::WaitWakeBatch<{ super::runtime::STEP15_RUNTIME_PROCESSES }>>,
    (),
> {
    let plan = super::runtime::with_linux_runtime(|state| {
        state.prepare_process_exit_wait_plan(process_id, completion, cause)
    })
    .map_err(|_| ())?
    .map_err(|_| ())?;

    // Signal queue commit is already authoritative. Route only notification after the RuntimeCell
    // borrow ends; failure is an internal post-commit invariant and never a Linux errno.
    let mut notifications = ProcessExitNotifyPlan::new();
    notifications.include_targets(current_cpu, plan.signal_targets())?;
    notifications.deliver()?;

    match plan.disposition() {
        super::runtime::ProcessExitWaitDisposition::NoParentPublication => Ok(None),
        super::runtime::ProcessExitWaitDisposition::ZombiePublished(wakes) => Ok(Some(wakes)),
        super::runtime::ProcessExitWaitDisposition::AutoReap(process_id) => {
            // SAFETY: the caller is still in the synchronous IRQ-masked post-switch owner window.
            // RuntimeTablePool and frame-pool wrappers enforce the already accepted global owner
            // order before the Linux runtime is re-entered for the destructive cleanup transaction.
            let frame_result = unsafe {
                kernal_protected_boot_aarch64::RuntimeTablePool::with_live(|page_tables| {
                    super::memory::with_live_frame_pool(|pool| {
                        super::runtime::with_linux_runtime(|state| {
                            state.commit_process_auto_reap_reclaiming_frames(
                                process_id,
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
            let wakes = semantic_result.map_err(|_| ())?;

            // The canonical Process/Wait owners have now irreversibly removed this child. Only at
            // this point may the matching process-local descriptor view drop its references to the
            // still-single canonical OFD pool. Final Pipe/Overlay leases are routed by the existing
            // Step-29 runtime owner; no Core-side FD/OFD registry is introduced here.
            #[cfg(feature = "step29-qemu-proof")]
            super::step29_runtime::retire_process(process_id).map_err(|_| ())?;

            Ok(Some(wakes))
        }
    }
}
