// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kernal_percpu::CpuIndex;
use kernal_scheduler::{
    JobControlContinueOutcome, JobControlStopOutcome, RunQueue, ThreadId, ThreadState,
};

const EMPTY: u64 = u64::MAX;
const JOB_CONTROL_COMMAND_BIT: u64 = 1u64 << 32;
const JOB_CONTROL_LOCAL_ID_MASK: u64 = (1u64 << 32) - 1;
const JOB_CONTROL_SLOT_EMPTY: u64 = 0;
const JOB_CONTROL_SLOT_RESERVED: u64 = 1;
const JOB_CONTROL_SLOT_PENDING: u64 = 2;
const JOB_CONTROL_SLOT_ALREADY_STOPPED: u64 = 3;
const JOB_CONTROL_SLOT_HELD: u64 = 4;
const JOB_CONTROL_SLOT_DESCHEDULE: u64 = 5;
const JOB_CONTROL_SLOT_NOT_STOPPED: u64 = 6;
const JOB_CONTROL_SLOT_CONTINUED: u64 = 7;
const JOB_CONTROL_SLOT_READIED: u64 = 8;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalThreadId {
    pub cpu: CpuIndex,
    pub local: ThreadId,
}

impl GlobalThreadId {
    pub const fn new(cpu: CpuIndex, local: ThreadId) -> Self {
        Self { cpu, local }
    }
}

/// One-shot evidence that an exact scheduler generation is still unpublished clone state.
///
/// A valid token means the canonical scheduler owner observed the exact generation as both
/// `RunQueue::Blocked` and generation-owned `ContextTable::Staged` while holding its quiescent owner
/// window. The token is deliberately neither `Copy` nor `Clone`: process/TID publication code can
/// move it through the clone transaction without reconstructing scheduler authority from scalar IDs.
/// Production code should obtain this proof only from the owner-checked `CpuSchedulerCell` staged
/// attestation path.
pub struct StagedThreadProof {
    thread: GlobalThreadId,
}

impl StagedThreadProof {
    pub const fn thread(&self) -> GlobalThreadId {
        self.thread
    }

    /// Constructs a staged proof after the exact scheduler owner has validated both scheduler and
    /// generation-owned publication state.
    ///
    /// # Safety
    /// The caller must hold exclusive owner authority for `thread.cpu`, must have verified exactly
    /// `thread.local` as `Blocked` in that CPU's canonical RunQueue and `Staged` in its matching
    /// ContextTable, and must keep owner quiescence/state continuity until the proof is handed to the
    /// next clone transaction owner. A foreign, stale, Published or reconstructed identity can
    /// authorize process/TID state for a non-existent unpublished child.
    pub const unsafe fn new_unchecked(thread: GlobalThreadId) -> Self {
        Self { thread }
    }
}

/// Evidence that one exact globally-owned scheduler generation has already completed `reap()`.
///
/// Safe process/object cleanup consumes this token instead of inferring reaping from an arbitrary
/// `RunQueue::state()` result. Production code should obtain it from the owner-checked
/// `CpuSchedulerCell` reap path. Proof-only code may construct it after independently satisfying the
/// same ownership and exact-generation contract.
pub struct ReapedThreadProof {
    thread: GlobalThreadId,
}

impl ReapedThreadProof {
    pub const fn thread(&self) -> GlobalThreadId {
        self.thread
    }

    /// Constructs a proof after an exact scheduler generation has already been reaped from the
    /// RunQueue owned by `thread.cpu`.
    ///
    /// # Safety
    /// The caller must have exclusive owner authority for `thread.cpu` and must have successfully
    /// reaped exactly `thread.local` from that CPU's RunQueue. A proof for a foreign queue, a merely
    /// Exited thread, or a different generation can authorize premature object/capability teardown.
    pub const unsafe fn new_unchecked(thread: GlobalThreadId) -> Self {
        Self { thread }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ZeroCapacity,
    WrongOwner,
    Full,
    InvalidJobControlEncoding,
    StaleJobControlGeneration,
    ConflictingJobControlGeneration,
    StaleJobControlCompletion,
    Scheduler(kernal_scheduler::Error),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrainReport {
    pub observed: usize,
    pub readied: usize,
    pub already_ready: usize,
    pub ignored_running: usize,
    pub stale: usize,
}

/// Bounded MPSC wake mailbox owned by exactly one CPU.
///
/// Producers never mutate a foreign RunQueue. Each queued identity carries the owner CpuIndex as
/// well as the local slot/generation; publishing into the wrong CPU mailbox is rejected before it
/// can alias an identically-numbered local slot.
pub struct RemoteWakeQueue<const N: usize> {
    owner: CpuIndex,
    slots: [AtomicU64; N],
    consumer_hint: AtomicUsize,
}

impl<const N: usize> RemoteWakeQueue<N> {
    pub const fn new(owner: CpuIndex) -> Self {
        Self {
            owner,
            slots: [const { AtomicU64::new(EMPTY) }; N],
            consumer_hint: AtomicUsize::new(0),
        }
    }

    pub const fn owner(&self) -> CpuIndex {
        self.owner
    }

    pub fn push(&self, id: GlobalThreadId) -> Result<(), Error> {
        if N == 0 {
            return Err(Error::ZeroCapacity);
        }
        if id.cpu != self.owner {
            return Err(Error::WrongOwner);
        }

        let packed = pack(id);
        let start = packed as usize % N;
        for offset in 0..N {
            let index = (start + offset) % N;
            match self.slots[index].compare_exchange(
                EMPTY,
                packed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) if observed == packed => return Ok(()),
                Err(_) => {}
            }
        }
        Err(Error::Full)
    }

    pub fn pop(&self) -> Result<Option<GlobalThreadId>, Error> {
        if N == 0 {
            return Err(Error::ZeroCapacity);
        }
        let start = self.consumer_hint.load(Ordering::Relaxed) % N;
        for offset in 0..N {
            let index = (start + offset) % N;
            let value = self.slots[index].swap(EMPTY, Ordering::AcqRel);
            if value != EMPTY {
                self.consumer_hint
                    .store(index.wrapping_add(1), Ordering::Relaxed);
                let id = unpack(value);
                if id.cpu != self.owner {
                    return Err(Error::WrongOwner);
                }
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    pub fn drain_into<const THREADS: usize>(
        &self,
        run_queue: &mut RunQueue<THREADS>,
        maximum: usize,
    ) -> Result<DrainReport, Error> {
        let mut report = DrainReport::default();
        while report.observed < maximum {
            let Some(id) = self.pop()? else {
                break;
            };
            report.observed += 1;
            match run_queue.state(id.local) {
                Ok(ThreadState::Blocked) => {
                    run_queue.make_ready(id.local).map_err(Error::Scheduler)?;
                    report.readied += 1;
                }
                Ok(ThreadState::Ready) => report.already_ready += 1,
                Ok(ThreadState::Running) => report.ignored_running += 1,
                Ok(ThreadState::Free | ThreadState::Exited) | Err(_) => report.stale += 1,
            }
        }
        Ok(report)
    }

    pub fn approximate_len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.load(Ordering::Acquire) != EMPTY)
            .count()
    }
}

/// Desired scheduler hold state for one exact Linux job-control target generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobControlCommand {
    Stop,
    Continue,
}

/// Full-width nonzero process-level Job-Control transaction generation.
///
/// The generation is stored independently from the packed local scheduler identity so a stale
/// completion can never alias a later process transaction merely because a small payload counter
/// wrapped. Allocation is owned by Core/Runtime and must fail closed rather than wrap to zero.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JobControlGeneration(NonZeroU64);

impl JobControlGeneration {
    pub const MAX: u64 = u64::MAX;

    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobControlRequest {
    thread: GlobalThreadId,
    command: JobControlCommand,
    generation: JobControlGeneration,
}

impl JobControlRequest {
    pub const fn new(
        thread: GlobalThreadId,
        command: JobControlCommand,
        generation: JobControlGeneration,
    ) -> Self {
        Self {
            thread,
            command,
            generation,
        }
    }

    pub const fn thread(self) -> GlobalThreadId {
        self.thread
    }

    pub const fn command(self) -> JobControlCommand {
        self.command
    }

    pub const fn generation(self) -> JobControlGeneration {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobControlDrainReport {
    pub observed: usize,
    pub held: usize,
    pub already_stopped: usize,
    pub deschedule: usize,
    pub continued: usize,
    pub readied: usize,
    pub not_stopped: usize,
    pub stale: usize,
}

/// Exact result of applying one successfully revalidated Job-Control request.
///
/// `AlreadyStopped` and `NotStopped` are valid ACKs that may satisfy one expected process target but
/// are not Linux-visible transitions. The remaining outcomes are real scheduler state changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobControlAppliedOutcome {
    AlreadyStopped,
    Held,
    Deschedule,
    NotStopped,
    Continued,
    Readied,
}

impl JobControlAppliedOutcome {
    pub const fn is_real_transition(self) -> bool {
        !matches!(self, Self::AlreadyStopped | Self::NotStopped)
    }
}

/// Exact owner-CPU acknowledgement for one successfully revalidated Job-Control request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobControlCompletion {
    thread: GlobalThreadId,
    command: JobControlCommand,
    generation: JobControlGeneration,
    outcome: JobControlAppliedOutcome,
}

impl JobControlCompletion {
    pub const fn new(request: JobControlRequest, outcome: JobControlAppliedOutcome) -> Self {
        Self {
            thread: request.thread(),
            command: request.command(),
            generation: request.generation(),
            outcome,
        }
    }

    pub const fn thread(self) -> GlobalThreadId {
        self.thread
    }

    pub const fn command(self) -> JobControlCommand {
        self.command
    }

    pub const fn generation(self) -> JobControlGeneration {
        self.generation
    }

    pub const fn outcome(self) -> JobControlAppliedOutcome {
        self.outcome
    }

    pub const fn is_real_transition(self) -> bool {
        self.outcome.is_real_transition()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobControlCompletionBatch<const N: usize> {
    entries: [Option<JobControlCompletion>; N],
    len: usize,
}

impl<const N: usize> JobControlCompletionBatch<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            len: 0,
        }
    }

    pub fn push(&mut self, completion: JobControlCompletion) -> Result<(), Error> {
        let slot = self.entries.get_mut(self.len).ok_or(Error::Full)?;
        *slot = Some(completion);
        self.len += 1;
        Ok(())
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> Option<JobControlCompletion> {
        self.entries.get(index).copied().flatten()
    }

    pub fn iter(&self) -> impl Iterator<Item = JobControlCompletion> + '_ {
        self.entries.iter().flatten().copied()
    }
}

impl<const N: usize> Default for JobControlCompletionBatch<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobControlDrainResult<const N: usize> {
    report: JobControlDrainReport,
    completions: JobControlCompletionBatch<N>,
}

impl<const N: usize> JobControlDrainResult<N> {
    pub const fn new(
        report: JobControlDrainReport,
        completions: JobControlCompletionBatch<N>,
    ) -> Self {
        Self {
            report,
            completions,
        }
    }

    pub const fn report(&self) -> JobControlDrainReport {
        self.report
    }

    pub const fn completions(&self) -> &JobControlCompletionBatch<N> {
        &self.completions
    }
}

struct RemoteJobControlSlot {
    state: AtomicU64,
    payload: AtomicU64,
    transaction: AtomicU64,
}

impl RemoteJobControlSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(JOB_CONTROL_SLOT_EMPTY),
            payload: AtomicU64::new(0),
            transaction: AtomicU64::new(0),
        }
    }
}

/// Linear owner claim for one pending transport entry. It is deliberately not Copy/Clone; the slot
/// remains RESERVED until the scheduler owner records either a durable completion or a discard/retry.
pub struct JobControlPendingClaim {
    slot: usize,
    request: JobControlRequest,
}

impl JobControlPendingClaim {
    pub const fn request(&self) -> JobControlRequest {
        self.request
    }
}

/// Bounded MPSC job-control mailbox owned by exactly one CPU.
///
/// Each slot stores exact local scheduler identity/command and a separate full-width transaction
/// generation behind an explicit state word. Producers serialize on RESERVED, so a request is never
/// observed with the wrong transaction generation. Owner application turns Pending into a durable
/// Completed(outcome) state instead of clearing the slot. Core may retry Runtime acknowledgement as
/// often as needed; only explicit `acknowledge` releases completed transport evidence.
pub struct RemoteJobControlQueue<const N: usize> {
    owner: CpuIndex,
    slots: [RemoteJobControlSlot; N],
    consumer_hint: AtomicUsize,
}

impl<const N: usize> RemoteJobControlQueue<N> {
    pub const fn new(owner: CpuIndex) -> Self {
        Self {
            owner,
            slots: [const { RemoteJobControlSlot::new() }; N],
            consumer_hint: AtomicUsize::new(0),
        }
    }

    pub const fn owner(&self) -> CpuIndex {
        self.owner
    }

    pub fn push(&self, request: JobControlRequest) -> Result<(), Error> {
        if N == 0 {
            return Err(Error::ZeroCapacity);
        }
        if request.thread().cpu != self.owner {
            return Err(Error::WrongOwner);
        }

        let identity = pack_job_control_identity(request.thread().local);
        let payload = pack_job_control_payload(request);
        let start = identity as usize % N;
        for offset in 0..N {
            let index = (start + offset) % N;
            let slot = &self.slots[index];
            loop {
                let state = slot.state.load(Ordering::Acquire);
                if state == JOB_CONTROL_SLOT_RESERVED {
                    core::hint::spin_loop();
                    continue;
                }
                if state == JOB_CONTROL_SLOT_EMPTY {
                    if slot
                        .state
                        .compare_exchange(
                            JOB_CONTROL_SLOT_EMPTY,
                            JOB_CONTROL_SLOT_RESERVED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }
                    slot.payload.store(payload, Ordering::Relaxed);
                    slot.transaction
                        .store(request.generation().get(), Ordering::Relaxed);
                    slot.state
                        .store(JOB_CONTROL_SLOT_PENDING, Ordering::Release);
                    return Ok(());
                }

                if slot
                    .state
                    .compare_exchange(
                        state,
                        JOB_CONTROL_SLOT_RESERVED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                let observed_payload = slot.payload.load(Ordering::Relaxed);
                if packed_job_control_identity(observed_payload) != identity {
                    slot.state.store(state, Ordering::Release);
                    break;
                }
                let observed_generation =
                    JobControlGeneration::new(slot.transaction.load(Ordering::Relaxed))
                        .ok_or(Error::InvalidJobControlEncoding)?;
                let observed_command = unpack_job_control_command(observed_payload);
                if observed_generation > request.generation() {
                    slot.state.store(state, Ordering::Release);
                    return Err(Error::StaleJobControlGeneration);
                }
                if observed_generation == request.generation() {
                    slot.state.store(state, Ordering::Release);
                    if observed_command == request.command() {
                        return Ok(());
                    }
                    return Err(Error::ConflictingJobControlGeneration);
                }

                // A newer process transaction supersedes older pending or completed evidence for this
                // exact scheduler generation. Core rejects any already-copied older ACK by generation.
                slot.payload.store(payload, Ordering::Relaxed);
                slot.transaction
                    .store(request.generation().get(), Ordering::Relaxed);
                slot.state
                    .store(JOB_CONTROL_SLOT_PENDING, Ordering::Release);
                return Ok(());
            }
        }
        Err(Error::Full)
    }

    /// Compatibility destructive pop used only by aggregate callers. Completed durable evidence is
    /// intentionally invisible here and can be removed only through `acknowledge`.
    pub fn pop(&self) -> Result<Option<JobControlRequest>, Error> {
        let Some(claim) = self.claim_pending()? else {
            return Ok(None);
        };
        let request = claim.request();
        self.discard_pending(claim)?;
        Ok(Some(request))
    }

    pub fn claim_pending(&self) -> Result<Option<JobControlPendingClaim>, Error> {
        if N == 0 {
            return Err(Error::ZeroCapacity);
        }
        let start = self.consumer_hint.load(Ordering::Relaxed) % N;
        for offset in 0..N {
            let index = (start + offset) % N;
            let slot = &self.slots[index];
            if slot
                .state
                .compare_exchange(
                    JOB_CONTROL_SLOT_PENDING,
                    JOB_CONTROL_SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            let request = unpack_job_control_payload(
                slot.payload.load(Ordering::Relaxed),
                self.owner,
                slot.transaction.load(Ordering::Relaxed),
            )?;
            self.consumer_hint
                .store(index.wrapping_add(1), Ordering::Relaxed);
            return Ok(Some(JobControlPendingClaim {
                slot: index,
                request,
            }));
        }
        Ok(None)
    }

    pub fn complete_pending(
        &self,
        claim: JobControlPendingClaim,
        outcome: JobControlAppliedOutcome,
    ) -> Result<(), Error> {
        let slot = self
            .slots
            .get(claim.slot)
            .ok_or(Error::InvalidJobControlEncoding)?;
        if slot.state.load(Ordering::Acquire) != JOB_CONTROL_SLOT_RESERVED
            || !slot_matches_request(slot, claim.request)
        {
            return Err(Error::StaleJobControlCompletion);
        }
        slot.state
            .store(job_control_completed_state(outcome), Ordering::Release);
        Ok(())
    }

    pub fn discard_pending(&self, claim: JobControlPendingClaim) -> Result<(), Error> {
        let slot = self
            .slots
            .get(claim.slot)
            .ok_or(Error::InvalidJobControlEncoding)?;
        if slot.state.load(Ordering::Acquire) != JOB_CONTROL_SLOT_RESERVED
            || !slot_matches_request(slot, claim.request)
        {
            return Err(Error::StaleJobControlCompletion);
        }
        slot.state.store(JOB_CONTROL_SLOT_EMPTY, Ordering::Release);
        Ok(())
    }

    pub fn restore_pending(&self, claim: JobControlPendingClaim) -> Result<(), Error> {
        let slot = self
            .slots
            .get(claim.slot)
            .ok_or(Error::InvalidJobControlEncoding)?;
        if slot.state.load(Ordering::Acquire) != JOB_CONTROL_SLOT_RESERVED
            || !slot_matches_request(slot, claim.request)
        {
            return Err(Error::StaleJobControlCompletion);
        }
        slot.state
            .store(JOB_CONTROL_SLOT_PENDING, Ordering::Release);
        Ok(())
    }

    /// Returns currently retained exact ACKs without consuming them. Completed slots are claimed
    /// briefly while their multiword payload is read, then restored to the same completed state.
    pub fn completed_batch(&self, maximum: usize) -> Result<JobControlCompletionBatch<N>, Error> {
        if maximum > N {
            return Err(Error::Full);
        }
        let mut completions = JobControlCompletionBatch::new();
        for slot in &self.slots {
            if completions.len() >= maximum {
                break;
            }
            loop {
                let state = slot.state.load(Ordering::Acquire);
                let Some(outcome) = job_control_outcome_from_state(state) else {
                    break;
                };
                if slot
                    .state
                    .compare_exchange(
                        state,
                        JOB_CONTROL_SLOT_RESERVED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                let request = unpack_job_control_payload(
                    slot.payload.load(Ordering::Relaxed),
                    self.owner,
                    slot.transaction.load(Ordering::Relaxed),
                )?;
                completions.push(JobControlCompletion::new(request, outcome))?;
                slot.state.store(state, Ordering::Release);
                break;
            }
        }
        Ok(completions)
    }

    /// Releases one exact durable ACK after Core/Runtime has accepted it, classified it as superseded,
    /// or otherwise proved it safe to discard. A stale receipt cannot clear newer evidence.
    pub fn acknowledge(&self, completion: JobControlCompletion) -> Result<(), Error> {
        if completion.thread().cpu != self.owner {
            return Err(Error::WrongOwner);
        }
        let identity = pack_job_control_identity(completion.thread().local);
        let start = identity as usize % N;
        let expected_state = job_control_completed_state(completion.outcome());
        for offset in 0..N {
            let index = (start + offset) % N;
            let slot = &self.slots[index];
            let state = slot.state.load(Ordering::Acquire);
            if state != expected_state {
                continue;
            }
            if slot
                .state
                .compare_exchange(
                    expected_state,
                    JOB_CONTROL_SLOT_RESERVED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            let request = unpack_job_control_payload(
                slot.payload.load(Ordering::Relaxed),
                self.owner,
                slot.transaction.load(Ordering::Relaxed),
            )?;
            if JobControlCompletion::new(request, completion.outcome()) == completion {
                slot.state.store(JOB_CONTROL_SLOT_EMPTY, Ordering::Release);
                return Ok(());
            }
            slot.state.store(expected_state, Ordering::Release);
        }
        Err(Error::StaleJobControlCompletion)
    }

    pub fn drain_into<const THREADS: usize>(
        &self,
        run_queue: &mut RunQueue<THREADS>,
        maximum: usize,
    ) -> Result<JobControlDrainReport, Error> {
        let mut report = JobControlDrainReport::default();
        while report.observed < maximum {
            let Some(request) = self.pop()? else {
                break;
            };
            report.observed += 1;
            match request.command() {
                JobControlCommand::Stop => match run_queue.job_control_stop(request.thread().local)
                {
                    Ok(JobControlStopOutcome::AlreadyStopped) => report.already_stopped += 1,
                    Ok(JobControlStopOutcome::Held) => report.held += 1,
                    Ok(JobControlStopOutcome::Deschedule) => report.deschedule += 1,
                    Err(
                        kernal_scheduler::Error::InvalidThread
                        | kernal_scheduler::Error::InvalidState,
                    ) => {
                        report.stale += 1;
                    }
                    Err(error) => return Err(Error::Scheduler(error)),
                },
                JobControlCommand::Continue => {
                    match run_queue.job_control_continue(request.thread().local) {
                        Ok(JobControlContinueOutcome::NotStopped) => report.not_stopped += 1,
                        Ok(JobControlContinueOutcome::Continued) => report.continued += 1,
                        Ok(JobControlContinueOutcome::Readied) => report.readied += 1,
                        Err(
                            kernal_scheduler::Error::InvalidThread
                            | kernal_scheduler::Error::InvalidState,
                        ) => report.stale += 1,
                        Err(error) => return Err(Error::Scheduler(error)),
                    }
                }
            }
        }
        Ok(report)
    }

    /// Applies pending requests exactly once and returns every retained valid ACK, including no-op
    /// outcomes. Stale scheduler generations are discarded without ACK and can never satisfy a Core
    /// process transaction. Completed entries remain durable until `acknowledge`.
    pub fn drain_exact_into<const THREADS: usize>(
        &self,
        run_queue: &mut RunQueue<THREADS>,
        maximum: usize,
    ) -> Result<JobControlDrainResult<N>, Error> {
        if maximum > N {
            return Err(Error::Full);
        }
        let mut report = JobControlDrainReport::default();
        while report.observed < maximum {
            let Some(claim) = self.claim_pending()? else {
                break;
            };
            let request = claim.request();
            report.observed += 1;
            let outcome = match request.command() {
                JobControlCommand::Stop => match run_queue.job_control_stop(request.thread().local)
                {
                    Ok(JobControlStopOutcome::AlreadyStopped) => {
                        report.already_stopped += 1;
                        JobControlAppliedOutcome::AlreadyStopped
                    }
                    Ok(JobControlStopOutcome::Held) => {
                        report.held += 1;
                        JobControlAppliedOutcome::Held
                    }
                    Ok(JobControlStopOutcome::Deschedule) => {
                        report.deschedule += 1;
                        JobControlAppliedOutcome::Deschedule
                    }
                    Err(
                        kernal_scheduler::Error::InvalidThread
                        | kernal_scheduler::Error::InvalidState,
                    ) => {
                        report.stale += 1;
                        self.discard_pending(claim)?;
                        continue;
                    }
                    Err(error) => {
                        self.restore_pending(claim)?;
                        return Err(Error::Scheduler(error));
                    }
                },
                JobControlCommand::Continue => {
                    match run_queue.job_control_continue(request.thread().local) {
                        Ok(JobControlContinueOutcome::NotStopped) => {
                            report.not_stopped += 1;
                            JobControlAppliedOutcome::NotStopped
                        }
                        Ok(JobControlContinueOutcome::Continued) => {
                            report.continued += 1;
                            JobControlAppliedOutcome::Continued
                        }
                        Ok(JobControlContinueOutcome::Readied) => {
                            report.readied += 1;
                            JobControlAppliedOutcome::Readied
                        }
                        Err(
                            kernal_scheduler::Error::InvalidThread
                            | kernal_scheduler::Error::InvalidState,
                        ) => {
                            report.stale += 1;
                            self.discard_pending(claim)?;
                            continue;
                        }
                        Err(error) => {
                            self.restore_pending(claim)?;
                            return Err(Error::Scheduler(error));
                        }
                    }
                }
            };
            self.complete_pending(claim, outcome)?;
        }
        Ok(JobControlDrainResult::new(report, self.completed_batch(N)?))
    }

    pub fn approximate_len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.state.load(Ordering::Acquire) != JOB_CONTROL_SLOT_EMPTY)
            .count()
    }
}

const fn pack(id: GlobalThreadId) -> u64 {
    id.local.slot as u64 | ((id.local.generation as u64) << 16) | ((id.cpu.0 as u64) << 32)
}

const fn unpack(value: u64) -> GlobalThreadId {
    GlobalThreadId {
        cpu: CpuIndex((value >> 32) as u16),
        local: ThreadId {
            slot: value as u16,
            generation: (value >> 16) as u16,
        },
    }
}

const fn pack_job_control_identity(local: ThreadId) -> u64 {
    local.slot as u64 | ((local.generation as u64) << 16)
}

const fn pack_job_control_payload(request: JobControlRequest) -> u64 {
    pack_job_control_identity(request.thread().local)
        | match request.command() {
            JobControlCommand::Stop => 0,
            JobControlCommand::Continue => JOB_CONTROL_COMMAND_BIT,
        }
}

const fn packed_job_control_identity(value: u64) -> u64 {
    value & JOB_CONTROL_LOCAL_ID_MASK
}

const fn unpack_job_control_command(payload: u64) -> JobControlCommand {
    if payload & JOB_CONTROL_COMMAND_BIT == 0 {
        JobControlCommand::Stop
    } else {
        JobControlCommand::Continue
    }
}

fn unpack_job_control_payload(
    payload: u64,
    owner: CpuIndex,
    generation: u64,
) -> Result<JobControlRequest, Error> {
    let generation =
        JobControlGeneration::new(generation).ok_or(Error::InvalidJobControlEncoding)?;
    Ok(JobControlRequest::new(
        GlobalThreadId::new(
            owner,
            ThreadId {
                slot: payload as u16,
                generation: (payload >> 16) as u16,
            },
        ),
        unpack_job_control_command(payload),
        generation,
    ))
}

fn slot_matches_request(slot: &RemoteJobControlSlot, request: JobControlRequest) -> bool {
    slot.payload.load(Ordering::Relaxed) == pack_job_control_payload(request)
        && slot.transaction.load(Ordering::Relaxed) == request.generation().get()
}

const fn job_control_completed_state(outcome: JobControlAppliedOutcome) -> u64 {
    match outcome {
        JobControlAppliedOutcome::AlreadyStopped => JOB_CONTROL_SLOT_ALREADY_STOPPED,
        JobControlAppliedOutcome::Held => JOB_CONTROL_SLOT_HELD,
        JobControlAppliedOutcome::Deschedule => JOB_CONTROL_SLOT_DESCHEDULE,
        JobControlAppliedOutcome::NotStopped => JOB_CONTROL_SLOT_NOT_STOPPED,
        JobControlAppliedOutcome::Continued => JOB_CONTROL_SLOT_CONTINUED,
        JobControlAppliedOutcome::Readied => JOB_CONTROL_SLOT_READIED,
    }
}

const fn job_control_outcome_from_state(state: u64) -> Option<JobControlAppliedOutcome> {
    match state {
        JOB_CONTROL_SLOT_ALREADY_STOPPED => Some(JobControlAppliedOutcome::AlreadyStopped),
        JOB_CONTROL_SLOT_HELD => Some(JobControlAppliedOutcome::Held),
        JOB_CONTROL_SLOT_DESCHEDULE => Some(JobControlAppliedOutcome::Deschedule),
        JOB_CONTROL_SLOT_NOT_STOPPED => Some(JobControlAppliedOutcome::NotStopped),
        JOB_CONTROL_SLOT_CONTINUED => Some(JobControlAppliedOutcome::Continued),
        JOB_CONTROL_SLOT_READIED => Some(JobControlAppliedOutcome::Readied),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(value: u64) -> JobControlGeneration {
        JobControlGeneration::new(value).unwrap()
    }

    #[test]
    fn producer_wakeup_is_applied_only_by_owner_drain() {
        let owner = CpuIndex(2);
        let mailbox = RemoteWakeQueue::<8>::new(owner);
        let mut run_queue = RunQueue::<8>::new();
        let thread = run_queue.create(12).unwrap();
        mailbox.push(GlobalThreadId::new(owner, thread)).unwrap();
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Blocked);
        let report = mailbox.drain_into(&mut run_queue, 8).unwrap();
        assert_eq!(report.readied, 1);
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Ready);
    }

    #[test]
    fn wrong_cpu_mailbox_is_rejected() {
        let mailbox = RemoteWakeQueue::<4>::new(CpuIndex(1));
        let id = GlobalThreadId::new(
            CpuIndex(2),
            ThreadId {
                slot: 1,
                generation: 7,
            },
        );
        assert_eq!(mailbox.push(id), Err(Error::WrongOwner));
    }

    #[test]
    fn visible_duplicate_does_not_consume_capacity() {
        let owner = CpuIndex(1);
        let mailbox = RemoteWakeQueue::<2>::new(owner);
        let id = GlobalThreadId::new(
            owner,
            ThreadId {
                slot: 1,
                generation: 7,
            },
        );
        mailbox.push(id).unwrap();
        mailbox.push(id).unwrap();
        assert_eq!(mailbox.approximate_len(), 1);
    }

    #[test]
    fn concurrent_duplicate_publish_occupies_one_slot() {
        let owner = CpuIndex(1);
        let mailbox = RemoteWakeQueue::<8>::new(owner);
        let id = GlobalThreadId::new(
            owner,
            ThreadId {
                slot: 5,
                generation: 9,
            },
        );

        std::thread::scope(|scope| {
            let mailbox = &mailbox;
            for _ in 0..8 {
                scope.spawn(move || mailbox.push(id).unwrap());
            }
        });

        assert_eq!(mailbox.approximate_len(), 1);
    }

    #[test]
    fn full_queue_fails_without_blocking() {
        let owner = CpuIndex(0);
        let mailbox = RemoteWakeQueue::<2>::new(owner);
        mailbox
            .push(GlobalThreadId::new(
                owner,
                ThreadId {
                    slot: 1,
                    generation: 1,
                },
            ))
            .unwrap();
        mailbox
            .push(GlobalThreadId::new(
                owner,
                ThreadId {
                    slot: 2,
                    generation: 1,
                },
            ))
            .unwrap();
        assert_eq!(
            mailbox.push(GlobalThreadId::new(
                owner,
                ThreadId {
                    slot: 3,
                    generation: 1
                }
            )),
            Err(Error::Full)
        );
    }

    #[test]
    fn running_thread_wakeup_is_ignored_not_requeued() {
        let owner = CpuIndex(3);
        let mailbox = RemoteWakeQueue::<4>::new(owner);
        let mut run_queue = RunQueue::<4>::new();
        let thread = run_queue.create(5).unwrap();
        run_queue.make_ready(thread).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(thread));
        mailbox.push(GlobalThreadId::new(owner, thread)).unwrap();
        let report = mailbox.drain_into(&mut run_queue, 4).unwrap();
        assert_eq!(report.ignored_running, 1);
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Running);
    }

    #[test]
    fn staged_proof_preserves_exact_global_identity() {
        let thread = GlobalThreadId::new(
            CpuIndex(4),
            ThreadId {
                slot: 5,
                generation: 9,
            },
        );
        // SAFETY: unit test models the exact owner-validated Staged+Blocked attestation boundary.
        let proof = unsafe { StagedThreadProof::new_unchecked(thread) };
        assert_eq!(proof.thread(), thread);
    }

    #[test]
    fn reap_proof_preserves_exact_global_identity() {
        let thread = GlobalThreadId::new(
            CpuIndex(4),
            ThreadId {
                slot: 7,
                generation: 11,
            },
        );
        // SAFETY: unit test models the post-reap attestation boundary only.
        let proof = unsafe { ReapedThreadProof::new_unchecked(thread) };
        assert_eq!(proof.thread(), thread);
    }

    #[test]
    fn full_width_job_control_generation_roundtrips() {
        let large = (1u64 << 48) + 17;
        assert_eq!(generation(large).get(), large);
        assert_eq!(JobControlGeneration::new(0), None);
    }

    #[test]
    fn pending_job_control_for_one_generation_coalesces_to_newer_transaction() {
        let owner = CpuIndex(1);
        let mailbox = RemoteJobControlQueue::<1>::new(owner);
        let mut run_queue = RunQueue::<2>::new();
        let thread = run_queue.create(7).unwrap();
        run_queue.make_ready(thread).unwrap();
        let target = GlobalThreadId::new(owner, thread);

        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Stop,
                generation(1),
            ))
            .unwrap();
        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Continue,
                generation(1u64 << 40),
            ))
            .unwrap();
        assert_eq!(mailbox.approximate_len(), 1);

        let request = mailbox.pop().unwrap().unwrap();
        assert_eq!(request.thread(), target);
        assert_eq!(request.command(), JobControlCommand::Continue);
        assert_eq!(request.generation(), generation(1u64 << 40));

        mailbox.push(request).unwrap();
        let report = mailbox.drain_into(&mut run_queue, 1).unwrap();
        assert_eq!(report.observed, 1);
        assert_eq!(report.not_stopped, 1);
        assert!(!run_queue.job_control_stopped(thread).unwrap());
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Ready);
    }

    #[test]
    fn stale_job_control_generation_cannot_replace_newer_completed_evidence() {
        let owner = CpuIndex(1);
        let mailbox = RemoteJobControlQueue::<1>::new(owner);
        let mut run_queue = RunQueue::<2>::new();
        let thread = run_queue.create(7).unwrap();
        let target = GlobalThreadId::new(owner, thread);
        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Stop,
                generation(1u64 << 42),
            ))
            .unwrap();
        let result = mailbox.drain_exact_into(&mut run_queue, 1).unwrap();
        assert_eq!(result.completions().len(), 1);
        assert_eq!(
            mailbox.push(JobControlRequest::new(
                target,
                JobControlCommand::Continue,
                generation((1u64 << 42) - 1),
            )),
            Err(Error::StaleJobControlGeneration)
        );
        assert_eq!(mailbox.completed_batch(1).unwrap().len(), 1);
    }

    #[test]
    fn same_transaction_generation_cannot_name_opposite_commands() {
        let owner = CpuIndex(1);
        let mailbox = RemoteJobControlQueue::<1>::new(owner);
        let thread = GlobalThreadId::new(
            owner,
            ThreadId {
                slot: 1,
                generation: 7,
            },
        );
        mailbox
            .push(JobControlRequest::new(
                thread,
                JobControlCommand::Stop,
                generation(3),
            ))
            .unwrap();
        assert_eq!(
            mailbox.push(JobControlRequest::new(
                thread,
                JobControlCommand::Continue,
                generation(3),
            )),
            Err(Error::ConflictingJobControlGeneration)
        );
    }

    #[test]
    fn exact_drain_retains_noop_and_real_ack_until_explicit_acknowledge() {
        let owner = CpuIndex(2);
        let mailbox = RemoteJobControlQueue::<2>::new(owner);
        let mut run_queue = RunQueue::<2>::new();
        let thread = run_queue.create(9).unwrap();
        let target = GlobalThreadId::new(owner, thread);

        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Stop,
                generation(4),
            ))
            .unwrap();
        let stopped = mailbox.drain_exact_into(&mut run_queue, 1).unwrap();
        let held = stopped.completions().get(0).unwrap();
        assert_eq!(held.outcome(), JobControlAppliedOutcome::Held);
        assert!(held.is_real_transition());

        // Completed evidence is returned again but the RunQueue transition is not applied twice.
        let retry = mailbox.drain_exact_into(&mut run_queue, 1).unwrap();
        assert_eq!(retry.report().observed, 0);
        assert_eq!(retry.completions().get(0), Some(held));
        mailbox.acknowledge(held).unwrap();
        assert!(mailbox.completed_batch(2).unwrap().is_empty());

        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Stop,
                generation(5),
            ))
            .unwrap();
        let duplicate_stop = mailbox.drain_exact_into(&mut run_queue, 1).unwrap();
        assert_eq!(duplicate_stop.report().already_stopped, 1);
        let noop = duplicate_stop.completions().get(0).unwrap();
        assert_eq!(noop.outcome(), JobControlAppliedOutcome::AlreadyStopped);
        assert!(!noop.is_real_transition());
        mailbox.acknowledge(noop).unwrap();

        run_queue.make_ready(thread).unwrap();
        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Continue,
                generation(6),
            ))
            .unwrap();
        let continued = mailbox.drain_exact_into(&mut run_queue, 1).unwrap();
        let completion = continued.completions().get(0).unwrap();
        assert_eq!(completion.outcome(), JobControlAppliedOutcome::Readied);
        assert!(completion.is_real_transition());
    }

    #[test]
    fn newer_transaction_supersedes_unacknowledged_completed_evidence() {
        let owner = CpuIndex(2);
        let mailbox = RemoteJobControlQueue::<1>::new(owner);
        let mut run_queue = RunQueue::<2>::new();
        let thread = run_queue.create(9).unwrap();
        let target = GlobalThreadId::new(owner, thread);
        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Stop,
                generation(10),
            ))
            .unwrap();
        let old = mailbox
            .drain_exact_into(&mut run_queue, 1)
            .unwrap()
            .completions()
            .get(0)
            .unwrap();
        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Continue,
                generation(11),
            ))
            .unwrap();
        assert_eq!(
            mailbox.acknowledge(old),
            Err(Error::StaleJobControlCompletion)
        );
        let current = mailbox.pop().unwrap().unwrap();
        assert_eq!(current.generation(), generation(11));
        assert_eq!(current.command(), JobControlCommand::Continue);
    }

    #[test]
    fn stopped_blocked_generation_remembers_real_wake_until_continue() {
        let owner = CpuIndex(2);
        let mailbox = RemoteJobControlQueue::<2>::new(owner);
        let mut run_queue = RunQueue::<2>::new();
        let thread = run_queue.create(9).unwrap();
        let target = GlobalThreadId::new(owner, thread);

        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Stop,
                generation(1),
            ))
            .unwrap();
        let stopped = mailbox.drain_into(&mut run_queue, 1).unwrap();
        assert_eq!(stopped.held, 1);
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Blocked);

        run_queue.make_ready(thread).unwrap();
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Blocked);

        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Continue,
                generation(2),
            ))
            .unwrap();
        let continued = mailbox.drain_into(&mut run_queue, 1).unwrap();
        assert_eq!(continued.readied, 1);
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Ready);
        assert!(!run_queue.job_control_stopped(thread).unwrap());
    }

    #[test]
    fn stopping_running_generation_reports_required_deschedule() {
        let owner = CpuIndex(3);
        let mailbox = RemoteJobControlQueue::<2>::new(owner);
        let mut run_queue = RunQueue::<2>::new();
        let thread = run_queue.create(11).unwrap();
        run_queue.make_ready(thread).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(thread));
        let target = GlobalThreadId::new(owner, thread);

        mailbox
            .push(JobControlRequest::new(
                target,
                JobControlCommand::Stop,
                generation(1),
            ))
            .unwrap();
        let report = mailbox.drain_into(&mut run_queue, 1).unwrap();
        assert_eq!(report.deschedule, 1);
        assert_eq!(run_queue.state(thread).unwrap(), ThreadState::Ready);
        assert!(run_queue.job_control_stopped(thread).unwrap());
    }
}
