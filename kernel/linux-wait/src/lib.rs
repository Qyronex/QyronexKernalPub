// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Architecture-neutral Linux child-observation and wait owner for Roadmap Step 30.
//!
//! This crate does not own Process objects or Linux PID allocation. It snapshots the exact
//! generation-safe parent/child relation already published by `kernal-linux-identity`, keeps only
//! bounded wait/zombie observation state, and never accepts a scalar PID as relationship authority.

use core::num::NonZeroU32;
use kernal_capability::ObjectId;
use kernal_linux_identity::{Error as IdentityError, LinuxIdentityTable};
use kernal_process::{Personality, Process, ProcessState};
use kernal_scheduler_smp::GlobalThreadId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity(IdentityError),
    Capacity,
    AlreadyTracked,
    ParentMismatch,
    StalePublication,
    AlreadyPublished,
    ChildStillLive,
    ChildNotLive,
    WrongPersonality,
    ParentExited,
    NoChild,
    InvalidSignal,
    InvalidInterests,
    ObservationGenerationExhausted,
    StaleObservation,
    WaiterCapacity,
    AlreadyWaiting,
    StaleWaiter,
    WaiterGenerationExhausted,
    WaiterWakeRequired,
    WaiterAlreadyCommitted,
    WaiterInterrupted,
    WaiterNotInterrupted,
}

impl From<IdentityError> for Error {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

/// Linux wait status encoded independently from any userspace pointer or process authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitStatus {
    raw: u16,
}

impl WaitStatus {
    /// Normal process exit. Linux exposes the low eight exit-status bits in bits 8..15.
    pub const fn exited(code: u8) -> Self {
        Self {
            raw: (code as u16) << 8,
        }
    }

    /// Signal termination status used by the later Step-30 signal integration.
    ///
    /// Defining the representation here does not implement signal delivery. The signal owner must
    /// provide the actual termination cause when 30.5 is integrated.
    pub const fn signaled(signal: u8, core_dumped: bool) -> Result<Self, Error> {
        if signal == 0 || signal > 0x7f {
            return Err(Error::InvalidSignal);
        }
        Ok(Self {
            raw: signal as u16 | if core_dumped { 0x80 } else { 0 },
        })
    }

    /// Linux stopped-child status: WIFSTOPPED requires the low byte 0x7f and WSTOPSIG reads bits 8..15.
    pub const fn stopped(signal: u8) -> Result<Self, Error> {
        if signal == 0 || signal > 0x7f {
            return Err(Error::InvalidSignal);
        }
        Ok(Self {
            raw: ((signal as u16) << 8) | 0x7f,
        })
    }

    /// Linux continued-child status consumed by WIFCONTINUED.
    pub const fn continued() -> Self {
        Self { raw: 0xffff }
    }

    pub const fn raw(self) -> u16 {
        self.raw
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitEventClass {
    Exited,
    Stopped,
    Continued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitInterests {
    bits: u8,
}

impl WaitInterests {
    const EXITED_BIT: u8 = 1 << 0;
    const STOPPED_BIT: u8 = 1 << 1;
    const CONTINUED_BIT: u8 = 1 << 2;

    pub const EXITED: Self = Self {
        bits: Self::EXITED_BIT,
    };
    pub const STOPPED: Self = Self {
        bits: Self::STOPPED_BIT,
    };
    pub const CONTINUED: Self = Self {
        bits: Self::CONTINUED_BIT,
    };
    pub const ALL: Self = Self {
        bits: Self::EXITED_BIT | Self::STOPPED_BIT | Self::CONTINUED_BIT,
    };

    pub const fn new(exited: bool, stopped: bool, continued: bool) -> Result<Self, Error> {
        let bits = if exited { Self::EXITED_BIT } else { 0 }
            | if stopped { Self::STOPPED_BIT } else { 0 }
            | if continued { Self::CONTINUED_BIT } else { 0 };
        if bits == 0 {
            return Err(Error::InvalidInterests);
        }
        Ok(Self { bits })
    }

    pub const fn exited(self) -> bool {
        self.bits & Self::EXITED_BIT != 0
    }

    pub const fn stopped(self) -> bool {
        self.bits & Self::STOPPED_BIT != 0
    }

    pub const fn continued(self) -> bool {
        self.bits & Self::CONTINUED_BIT != 0
    }

    const fn accepts(self, class: WaitEventClass) -> bool {
        match class {
            WaitEventClass::Exited => self.exited(),
            WaitEventClass::Stopped => self.stopped(),
            WaitEventClass::Continued => self.continued(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSelector {
    AnyChild,
    Pid(NonZeroU32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitOptions {
    nohang: bool,
    nowait: bool,
    interests: WaitInterests,
}

impl WaitOptions {
    pub const BLOCKING: Self = Self::new(false, false);
    pub const WNOHANG: Self = Self::new(true, false);

    /// Compatibility constructor: historical callers remain interested in terminal exit only.
    pub const fn new(nohang: bool, nowait: bool) -> Self {
        Self {
            nohang,
            nowait,
            interests: WaitInterests::EXITED,
        }
    }

    pub const fn with_interests(nohang: bool, nowait: bool, interests: WaitInterests) -> Self {
        Self {
            nohang,
            nowait,
            interests,
        }
    }

    pub const fn nohang(self) -> bool {
        self.nohang
    }

    pub const fn nowait(self) -> bool {
        self.nowait
    }

    pub const fn interests(self) -> WaitInterests {
        self.interests
    }

    pub const fn exited(self) -> bool {
        self.interests.exited()
    }

    pub const fn stopped(self) -> bool {
        self.interests.stopped()
    }

    pub const fn continued(self) -> bool {
        self.interests.continued()
    }
}

/// Linux-visible child observation. `child` is an exact historical ObjectId for ABA auditing, not
/// a capability and not a way to recreate Process authority. Nonterminal observations also carry the
/// exact per-child event generation, so phase-2 consumption cannot ABA-match a newer equal status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitObservation {
    child: ObjectId,
    pid: NonZeroU32,
    status: WaitStatus,
    event_class: WaitEventClass,
    event_generation: u64,
}

impl WaitObservation {
    pub const fn child(self) -> ObjectId {
        self.child
    }

    pub const fn pid(self) -> NonZeroU32 {
        self.pid
    }

    pub const fn status(self) -> WaitStatus {
        self.status
    }

    pub const fn event_class(self) -> WaitEventClass {
        self.event_class
    }

    pub const fn event_generation(self) -> u64 {
        self.event_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    Ready(WaitObservation),
    WouldBlock,
    NoHang,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildState {
    Running,
    Zombie(WaitStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingObservation {
    event_class: WaitEventClass,
    status: WaitStatus,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChildRecord {
    parent: ObjectId,
    parent_pid: NonZeroU32,
    child: ObjectId,
    child_pid: NonZeroU32,
    state: ChildState,
    pending_job_control: Option<PendingObservation>,
    terminal_generation: Option<u64>,
    next_observation_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaiterState {
    Prepared,
    Committed,
    /// A deliverable signal won against this exact wait registration. The record stays in the sole
    /// Wait owner until the linear receipt observes/consumes the interruption or a child event wins.
    Interrupted,
    Notified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaiterRecord {
    generation: u64,
    parent: ObjectId,
    selector: WaitSelector,
    interests: WaitInterests,
    thread: GlobalThreadId,
    state: WaiterState,
}

/// Linear receipt for one committed blocking-wait registration.
///
/// The receipt is intentionally not Copy/Clone. Its private slot+generation pair prevents an old
/// cancellation path from removing a waiter that reused the same bounded slot later. The exact event
/// interests are retained as part of the same stale-receipt proof.
#[derive(Debug, Eq, PartialEq)]
pub struct WaitSleepReceipt {
    slot: usize,
    generation: u64,
    parent: ObjectId,
    selector: WaitSelector,
    interests: WaitInterests,
    thread: GlobalThreadId,
}

impl WaitSleepReceipt {
    pub const fn thread(&self) -> GlobalThreadId {
        self.thread
    }

    pub const fn interests(&self) -> WaitInterests {
        self.interests
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum WaitPrepareOutcome {
    Ready(WaitObservation),
    Sleep(WaitSleepReceipt),
}

/// Compatibility result for callers that have not yet opted into signal interruption semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitCommitOutcome {
    Sleep,
    AlreadyWoken,
}

/// Interruption-aware result used by Step-30 Core once signal wake/restart composition is wired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSignalCommitOutcome {
    Sleep,
    AlreadyWoken,
    Interrupted,
}

/// Result of asking the sole Wait owner to interrupt one exact scheduler generation.
///
/// No variant mutates scheduler state. `Wake` is returned only when the exact waiter had already
/// committed its scheduler-block obligation. Prepared interruption is retained in-place so a later
/// interruption-aware commit cannot race past the signal and block. Child notification remains a
/// separate event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitInterruptOutcome {
    NotWaiting,
    InterruptedNoWake,
    Wake(GlobalThreadId),
    AlreadyInterrupted,
    ChildNotified,
}

/// Bounded exact-generation wake batch returned by child publication.
///
/// The wait owner never mutates scheduler state. Core must feed these exact GlobalThreadIds into the
/// existing local/remote scheduler wake owners after publication commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitWakeBatch<const N: usize> {
    threads: [Option<GlobalThreadId>; N],
    len: usize,
}

impl<const N: usize> WaitWakeBatch<N> {
    const fn empty() -> Self {
        Self {
            threads: [None; N],
            len: 0,
        }
    }

    fn push(&mut self, thread: GlobalThreadId) {
        debug_assert!(self.len < N);
        self.threads[self.len] = Some(thread);
        self.len += 1;
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> Option<GlobalThreadId> {
        self.threads.get(index).copied().flatten()
    }

    pub fn iter(&self) -> impl Iterator<Item = GlobalThreadId> + '_ {
        self.threads.iter().flatten().copied()
    }
}

/// Opaque publication token created while both exact Process generations are live.
///
/// It is intentionally not `Copy`/`Clone`. Callers retain it across child teardown and present it
/// back when the exact child has reached `ProcessState::Exited`. A failed early publication may be
/// retried with the same token; after successful publication the table rejects duplicates.
#[derive(Debug, Eq, PartialEq)]
pub struct ChildExitPublication {
    slot: usize,
    parent: ObjectId,
    parent_pid: NonZeroU32,
    child: ObjectId,
    child_pid: NonZeroU32,
}

impl ChildExitPublication {
    /// Exact parent Process generation captured by the sole Wait owner while both sides were live.
    ///
    /// This is observation only. A runtime must reselect and revalidate the retained Process owner
    /// before using it to observe signal policy or mutate any other owner.
    pub const fn parent(&self) -> ObjectId {
        self.parent
    }

    /// Linux PID observation paired with [`Self::parent`] at the same generation-safe snapshot.
    pub const fn parent_pid(&self) -> NonZeroU32 {
        self.parent_pid
    }

    pub const fn child_pid(&self) -> NonZeroU32 {
        self.child_pid
    }
}

/// Bounded wait/zombie owner. This is deliberately not a second PID registry: all scalar IDs and
/// parent relations originate from `LinuxIdentityTable`, while exact ObjectIds remain the matching
/// key after the child identity record is retired. Blocking waiter records contain only exact
/// scheduler generations to wake; they never own scheduler state or manufacture Thread authority.
pub struct WaitTable<const N: usize> {
    children: [Option<ChildRecord>; N],
    waiters: [Option<WaiterRecord>; N],
    next_waiter_generation: u64,
}

impl<const N: usize> WaitTable<N> {
    pub const fn new() -> Self {
        Self {
            children: [None; N],
            waiters: [None; N],
            next_waiter_generation: 1,
        }
    }

    /// Snapshots one exact live parent/child relation before the child can exit.
    pub fn track_child<
        const PROCESSES: usize,
        const THREADS: usize,
        const PARENT_CAPS: usize,
        const CHILD_CAPS: usize,
    >(
        &mut self,
        identities: &mut LinuxIdentityTable<PROCESSES, THREADS>,
        parent: &Process<PARENT_CAPS>,
        child: &Process<CHILD_CAPS>,
    ) -> Result<ChildExitPublication, Error> {
        if !identities.is_child_of(parent, child)? {
            return Err(Error::ParentMismatch);
        }

        let parent_id = parent.id();
        let child_id = child.id();
        if self
            .children
            .iter()
            .flatten()
            .any(|record| record.child == child_id)
        {
            return Err(Error::AlreadyTracked);
        }

        let parent_pid = identities.pid_for(parent)?;
        let child_pid = identities.pid_for(child)?;
        let slot = self
            .children
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.children[slot] = Some(ChildRecord {
            parent: parent_id,
            parent_pid,
            child: child_id,
            child_pid,
            state: ChildState::Running,
            pending_job_control: None,
            terminal_generation: None,
            next_observation_generation: 1,
        });

        Ok(ChildExitPublication {
            slot,
            parent: parent_id,
            parent_pid,
            child: child_id,
            child_pid,
        })
    }

    /// Cancels a not-yet-published child observation, for example when child publication rolls back.
    pub fn cancel_tracking(&mut self, publication: ChildExitPublication) -> Result<(), Error> {
        let record = self.record_for(&publication)?;
        if record.state != ChildState::Running {
            return Err(Error::AlreadyPublished);
        }
        self.children[publication.slot] = None;
        Ok(())
    }

    /// Converts a tracked child into a zombie only when no matching waiter still requires a terminal-liveness transition.
    pub fn publish_exit<const CHILD_CAPS: usize>(
        &mut self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
        status: WaitStatus,
    ) -> Result<(), Error> {
        let record = self.validate_exit_publication(publication, child)?;
        if self.waiters.iter().flatten().any(|waiter| {
            waiter.parent == record.parent
                && selector_matches(waiter.selector, record.child_pid)
                && !matches!(waiter.state, WaiterState::Notified)
        }) {
            return Err(Error::WaiterWakeRequired);
        }
        self.commit_exit_record(publication.slot, record, status)?;
        Ok(())
    }

    /// Completes terminal liveness for every exact matching waiter when a tracked child begins
    /// leaving its scheduler generation. Event interests do not suppress this liveness transition.
    pub fn notify_exit_transition(
        &mut self,
        publication: &ChildExitPublication,
    ) -> Result<WaitWakeBatch<N>, Error> {
        let record = self.record_for(publication)?;
        if record.state != ChildState::Running {
            return Err(Error::AlreadyPublished);
        }
        Ok(self.finish_terminal_waiters(record))
    }

    /// Atomically publishes one zombie and completes terminal liveness for every exact matching waiter.
    pub fn publish_exit_with_wakes<const CHILD_CAPS: usize>(
        &mut self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
        status: WaitStatus,
    ) -> Result<WaitWakeBatch<N>, Error> {
        let record = self.validate_exit_publication(publication, child)?;
        let record = self.commit_exit_record(publication.slot, record, status)?;
        Ok(self.finish_terminal_waiters(record))
    }

    /// Atomically removes one exited child without ever publishing a zombie and completes terminal
    /// liveness for every exact matching waiter.
    pub fn auto_reap_exit_with_wakes<const CHILD_CAPS: usize>(
        &mut self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
    ) -> Result<WaitWakeBatch<N>, Error> {
        let record = self.validate_exit_publication(publication, child)?;
        self.children[publication.slot] = None;
        Ok(self.finish_terminal_waiters(record))
    }

    /// Publishes one real job-control stop observation for a still-live exact child generation.
    /// The child remains Running and no Process/FD/Fs/scheduler authority is mutated here.
    pub fn publish_stopped_with_wakes<const CHILD_CAPS: usize>(
        &mut self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
        signal: u8,
    ) -> Result<WaitWakeBatch<N>, Error> {
        let status = WaitStatus::stopped(signal)?;
        self.publish_nonterminal_with_wakes(publication, child, WaitEventClass::Stopped, status)
    }

    /// Publishes one real job-control continue observation for a still-live exact child generation.
    pub fn publish_continued_with_wakes<const CHILD_CAPS: usize>(
        &mut self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
    ) -> Result<WaitWakeBatch<N>, Error> {
        self.publish_nonterminal_with_wakes(
            publication,
            child,
            WaitEventClass::Continued,
            WaitStatus::continued(),
        )
    }

    /// Re-scans one blocking selector for historical EXITED-only callers.
    pub fn prepare_sleep<const PARENT_CAPS: usize>(
        &mut self,
        parent: &Process<PARENT_CAPS>,
        selector: WaitSelector,
        thread: GlobalThreadId,
    ) -> Result<WaitPrepareOutcome, Error> {
        self.prepare_sleep_with_interests(parent, selector, WaitInterests::EXITED, thread)
    }

    /// Re-scans one blocking selector and persists the exact requested observation classes in both
    /// WaiterRecord and the linear sleep receipt.
    pub fn prepare_sleep_with_interests<const PARENT_CAPS: usize>(
        &mut self,
        parent: &Process<PARENT_CAPS>,
        selector: WaitSelector,
        interests: WaitInterests,
        thread: GlobalThreadId,
    ) -> Result<WaitPrepareOutcome, Error> {
        validate_parent(parent)?;
        let parent_id = parent.id();
        let mut matched_running = false;
        for record in self.children.iter().flatten().copied() {
            if record.parent != parent_id || !selector_matches(selector, record.child_pid) {
                continue;
            }
            if let Some(observation) = observation_for_record(record, interests) {
                return Ok(WaitPrepareOutcome::Ready(observation));
            }
            if record.state == ChildState::Running {
                matched_running = true;
            }
        }
        if !matched_running {
            return Err(Error::NoChild);
        }
        if self
            .waiters
            .iter()
            .flatten()
            .any(|waiter| waiter.thread == thread)
        {
            return Err(Error::AlreadyWaiting);
        }
        let slot = self
            .waiters
            .iter()
            .position(Option::is_none)
            .ok_or(Error::WaiterCapacity)?;
        let generation = self.next_waiter_generation;
        if generation == 0 {
            return Err(Error::WaiterGenerationExhausted);
        }
        self.next_waiter_generation = generation.checked_add(1).unwrap_or(0);
        self.waiters[slot] = Some(WaiterRecord {
            generation,
            parent: parent_id,
            selector,
            interests,
            thread,
            state: WaiterState::Prepared,
        });
        Ok(WaitPrepareOutcome::Sleep(WaitSleepReceipt {
            slot,
            generation,
            parent: parent_id,
            selector,
            interests,
            thread,
        }))
    }

    /// Compatibility commit for callers that do not yet compose signal interruption.
    pub fn commit_sleep(&mut self, receipt: &WaitSleepReceipt) -> Result<WaitCommitOutcome, Error> {
        let current = self.waiter_record_for(receipt)?;
        match current.state {
            WaiterState::Prepared => {
                self.waiters[receipt.slot] = Some(WaiterRecord {
                    state: WaiterState::Committed,
                    ..current
                });
                Ok(WaitCommitOutcome::Sleep)
            }
            WaiterState::Interrupted => Err(Error::WaiterInterrupted),
            WaiterState::Notified => {
                self.waiters[receipt.slot] = None;
                Ok(WaitCommitOutcome::AlreadyWoken)
            }
            WaiterState::Committed => Err(Error::WaiterAlreadyCommitted),
        }
    }

    /// Commits one exact prepared waiter with explicit signal-interruption semantics.
    pub fn commit_sleep_signal_aware(
        &mut self,
        receipt: &WaitSleepReceipt,
    ) -> Result<WaitSignalCommitOutcome, Error> {
        let current = self.waiter_record_for(receipt)?;
        match current.state {
            WaiterState::Prepared => {
                self.waiters[receipt.slot] = Some(WaiterRecord {
                    state: WaiterState::Committed,
                    ..current
                });
                Ok(WaitSignalCommitOutcome::Sleep)
            }
            WaiterState::Interrupted => Ok(WaitSignalCommitOutcome::Interrupted),
            WaiterState::Notified => {
                self.waiters[receipt.slot] = None;
                Ok(WaitSignalCommitOutcome::AlreadyWoken)
            }
            WaiterState::Committed => Err(Error::WaiterAlreadyCommitted),
        }
    }

    /// Cancels one exact waiter before or after scheduler block failure.
    pub fn cancel_sleep(&mut self, receipt: WaitSleepReceipt) -> Result<bool, Error> {
        let Some(current) = self.waiter_record_for_optional(&receipt)? else {
            return Ok(false);
        };
        self.waiters[receipt.slot] = None;
        Ok(!matches!(current.state, WaiterState::Notified))
    }

    /// Marks the exact wait registration for `thread` as signal-interrupted without touching the scheduler.
    pub fn interrupt_sleep_for_thread(
        &mut self,
        thread: GlobalThreadId,
    ) -> Result<WaitInterruptOutcome, Error> {
        let Some(slot) = self
            .waiters
            .iter()
            .position(|entry| entry.is_some_and(|waiter| waiter.thread == thread))
        else {
            return Ok(WaitInterruptOutcome::NotWaiting);
        };
        let current = self.waiters[slot].ok_or(Error::StaleWaiter)?;
        match current.state {
            WaiterState::Prepared => {
                self.waiters[slot] = Some(WaiterRecord {
                    state: WaiterState::Interrupted,
                    ..current
                });
                Ok(WaitInterruptOutcome::InterruptedNoWake)
            }
            WaiterState::Committed => {
                self.waiters[slot] = Some(WaiterRecord {
                    state: WaiterState::Interrupted,
                    ..current
                });
                Ok(WaitInterruptOutcome::Wake(current.thread))
            }
            WaiterState::Interrupted => Ok(WaitInterruptOutcome::AlreadyInterrupted),
            WaiterState::Notified => Ok(WaitInterruptOutcome::ChildNotified),
        }
    }

    /// Consumes the exact retained signal interruption after the caller has revalidated SignalTable.
    pub fn consume_interrupted_sleep(&mut self, receipt: WaitSleepReceipt) -> Result<bool, Error> {
        let current = self.waiter_record_for(&receipt)?;
        match current.state {
            WaiterState::Interrupted => {
                self.waiters[receipt.slot] = None;
                Ok(true)
            }
            WaiterState::Notified => {
                self.waiters[receipt.slot] = None;
                Ok(false)
            }
            WaiterState::Prepared | WaiterState::Committed => Err(Error::WaiterNotInterrupted),
        }
    }

    /// Cancels a scheduler-blocked wait registration by exact global generation.
    pub fn cancel_committed_sleep_for_thread(
        &mut self,
        thread: GlobalThreadId,
    ) -> Result<bool, Error> {
        let Some(slot) = self.waiters.iter().position(|entry| {
            entry.is_some_and(|waiter| {
                waiter.thread == thread && waiter.state == WaiterState::Committed
            })
        }) else {
            return Ok(false);
        };
        self.waiters[slot] = None;
        Ok(true)
    }

    /// Observes or reaps one child belonging to this exact live parent generation.
    ///
    /// Existing callers remain EXITED-only through `WaitOptions::new`; event-aware callers can ask
    /// for Stop/Continue independently. WNOWAIT keeps both terminal and nonterminal observations;
    /// nonterminal destructive compatibility consumption is generation-bound.
    pub fn wait<const PARENT_CAPS: usize>(
        &mut self,
        parent: &Process<PARENT_CAPS>,
        selector: WaitSelector,
        options: WaitOptions,
    ) -> Result<WaitOutcome, Error> {
        validate_parent(parent)?;
        let parent_id = parent.id();
        let mut matched_running = false;

        for slot in 0..N {
            let Some(record) = self.children[slot] else {
                continue;
            };
            if record.parent != parent_id || !selector_matches(selector, record.child_pid) {
                continue;
            }

            if let Some(observation) = observation_for_record(record, options.interests()) {
                if !options.nowait() {
                    match observation.event_class() {
                        WaitEventClass::Exited => self.children[slot] = None,
                        WaitEventClass::Stopped | WaitEventClass::Continued => {
                            self.consume_nonterminal_from_slot(slot, observation)?;
                        }
                    }
                }
                return Ok(WaitOutcome::Ready(observation));
            }
            if record.state == ChildState::Running {
                matched_running = true;
            }
        }

        if !matched_running {
            return Err(Error::NoChild);
        }
        if options.nohang() {
            Ok(WaitOutcome::NoHang)
        } else {
            Ok(WaitOutcome::WouldBlock)
        }
    }

    /// Exact phase-2 edge for a previously observed Stop/Continue event. The observation's private
    /// child/class/generation/status tuple must still name the same pending event; a newer equal-looking
    /// event is never consumed by an older receipt. Callers implementing WNOWAIT simply skip this edge.
    pub fn consume_nonterminal_observation<const PARENT_CAPS: usize>(
        &mut self,
        parent: &Process<PARENT_CAPS>,
        observation: WaitObservation,
    ) -> Result<(), Error> {
        validate_parent(parent)?;
        if observation.event_class() == WaitEventClass::Exited {
            return Err(Error::StaleObservation);
        }
        let slot = self
            .children
            .iter()
            .position(|entry| {
                entry.is_some_and(|record| {
                    record.parent == parent.id() && record.child == observation.child()
                })
            })
            .ok_or(Error::StaleObservation)?;
        self.consume_nonterminal_from_slot(slot, observation)
    }

    fn publish_nonterminal_with_wakes<const CHILD_CAPS: usize>(
        &mut self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
        event_class: WaitEventClass,
        status: WaitStatus,
    ) -> Result<WaitWakeBatch<N>, Error> {
        let mut record = self.validate_live_publication(publication, child)?;
        let generation = allocate_observation_generation(&mut record)?;
        record.pending_job_control = Some(PendingObservation {
            event_class,
            status,
            generation,
        });
        self.children[publication.slot] = Some(record);
        Ok(self.finish_waiters(record, event_class))
    }

    fn consume_nonterminal_from_slot(
        &mut self,
        slot: usize,
        observation: WaitObservation,
    ) -> Result<(), Error> {
        let mut record = self
            .children
            .get(slot)
            .copied()
            .flatten()
            .ok_or(Error::StaleObservation)?;
        let pending = record.pending_job_control.ok_or(Error::StaleObservation)?;
        if pending.event_class != observation.event_class()
            || pending.generation != observation.event_generation()
            || pending.status != observation.status()
        {
            return Err(Error::StaleObservation);
        }
        record.pending_job_control = None;
        self.children[slot] = Some(record);
        Ok(())
    }

    fn finish_terminal_waiters(&mut self, record: ChildRecord) -> WaitWakeBatch<N> {
        let mut wakes = WaitWakeBatch::empty();
        for slot in 0..N {
            let Some(waiter) = self.waiters[slot] else {
                continue;
            };
            if waiter.parent != record.parent
                || !selector_matches(waiter.selector, record.child_pid)
            {
                continue;
            }
            match waiter.state {
                WaiterState::Prepared | WaiterState::Interrupted => {
                    self.waiters[slot] = Some(WaiterRecord {
                        state: WaiterState::Notified,
                        ..waiter
                    });
                }
                WaiterState::Committed => {
                    wakes.push(waiter.thread);
                    self.waiters[slot] = None;
                }
                WaiterState::Notified => {}
            }
        }
        wakes
    }

    fn finish_waiters(
        &mut self,
        record: ChildRecord,
        event_class: WaitEventClass,
    ) -> WaitWakeBatch<N> {
        let mut wakes = WaitWakeBatch::empty();
        for slot in 0..N {
            let Some(waiter) = self.waiters[slot] else {
                continue;
            };
            if waiter.parent != record.parent
                || !waiter.interests.accepts(event_class)
                || !selector_matches(waiter.selector, record.child_pid)
            {
                continue;
            }
            match waiter.state {
                WaiterState::Prepared | WaiterState::Interrupted => {
                    self.waiters[slot] = Some(WaiterRecord {
                        state: WaiterState::Notified,
                        ..waiter
                    });
                }
                WaiterState::Committed => {
                    wakes.push(waiter.thread);
                    self.waiters[slot] = None;
                }
                WaiterState::Notified => {}
            }
        }
        wakes
    }

    fn waiter_record_for(&self, receipt: &WaitSleepReceipt) -> Result<WaiterRecord, Error> {
        self.waiter_record_for_optional(receipt)?
            .ok_or(Error::StaleWaiter)
    }

    fn waiter_record_for_optional(
        &self,
        receipt: &WaitSleepReceipt,
    ) -> Result<Option<WaiterRecord>, Error> {
        let current = self
            .waiters
            .get(receipt.slot)
            .copied()
            .ok_or(Error::StaleWaiter)?;
        let Some(current) = current else {
            return Ok(None);
        };
        if current.generation != receipt.generation
            || current.parent != receipt.parent
            || current.selector != receipt.selector
            || current.interests != receipt.interests
            || current.thread != receipt.thread
        {
            return Err(Error::StaleWaiter);
        }
        Ok(Some(current))
    }

    fn validate_exit_publication<const CHILD_CAPS: usize>(
        &self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
    ) -> Result<ChildRecord, Error> {
        if child.personality() != Personality::Linux {
            return Err(Error::WrongPersonality);
        }
        if child.id() != publication.child {
            return Err(Error::StalePublication);
        }
        if child.state() != ProcessState::Exited {
            return Err(Error::ChildStillLive);
        }
        let record = self.record_for(publication)?;
        if record.state != ChildState::Running {
            return Err(Error::AlreadyPublished);
        }
        Ok(record)
    }

    fn validate_live_publication<const CHILD_CAPS: usize>(
        &self,
        publication: &ChildExitPublication,
        child: &Process<CHILD_CAPS>,
    ) -> Result<ChildRecord, Error> {
        if child.personality() != Personality::Linux {
            return Err(Error::WrongPersonality);
        }
        if child.id() != publication.child {
            return Err(Error::StalePublication);
        }
        if child.state() != ProcessState::Live {
            return Err(Error::ChildNotLive);
        }
        let record = self.record_for(publication)?;
        if record.state != ChildState::Running {
            return Err(Error::AlreadyPublished);
        }
        Ok(record)
    }

    fn commit_exit_record(
        &mut self,
        slot: usize,
        mut record: ChildRecord,
        status: WaitStatus,
    ) -> Result<ChildRecord, Error> {
        let generation = allocate_observation_generation(&mut record)?;
        record.state = ChildState::Zombie(status);
        record.pending_job_control = None;
        record.terminal_generation = Some(generation);
        self.children[slot] = Some(record);
        Ok(record)
    }

    fn record_for(&self, publication: &ChildExitPublication) -> Result<ChildRecord, Error> {
        let record = self
            .children
            .get(publication.slot)
            .and_then(|record| *record)
            .ok_or(Error::StalePublication)?;
        if record.parent != publication.parent
            || record.parent_pid != publication.parent_pid
            || record.child != publication.child
            || record.child_pid != publication.child_pid
        {
            return Err(Error::StalePublication);
        }
        Ok(record)
    }
}

impl<const N: usize> Default for WaitTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn allocate_observation_generation(record: &mut ChildRecord) -> Result<u64, Error> {
    let generation = record.next_observation_generation;
    if generation == 0 {
        return Err(Error::ObservationGenerationExhausted);
    }
    record.next_observation_generation = generation.checked_add(1).unwrap_or(0);
    Ok(generation)
}

fn observation_for_record(
    record: ChildRecord,
    interests: WaitInterests,
) -> Option<WaitObservation> {
    if let ChildState::Zombie(status) = record.state {
        return interests.exited().then_some(WaitObservation {
            child: record.child,
            pid: record.child_pid,
            status,
            event_class: WaitEventClass::Exited,
            event_generation: record.terminal_generation.unwrap_or(u64::MAX),
        });
    }

    let pending = record.pending_job_control?;
    interests
        .accepts(pending.event_class)
        .then_some(WaitObservation {
            child: record.child,
            pid: record.child_pid,
            status: pending.status,
            event_class: pending.event_class,
            event_generation: pending.generation,
        })
}

fn validate_parent<const CAPS: usize>(parent: &Process<CAPS>) -> Result<(), Error> {
    if parent.personality() != Personality::Linux {
        return Err(Error::WrongPersonality);
    }
    if parent.state() != ProcessState::Live {
        return Err(Error::ParentExited);
    }
    Ok(())
}

const fn selector_matches(selector: WaitSelector, pid: NonZeroU32) -> bool {
    match selector {
        WaitSelector::AnyChild => true,
        WaitSelector::Pid(selected) => selected.get() == pid.get(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_object::ObjectTable;
    use kernal_percpu::CpuIndex;
    use kernal_process::ThreadObjectBindings;
    use kernal_scheduler::ThreadId;

    const CPU0: CpuIndex = CpuIndex(0);

    fn global(slot: u16, generation: u16) -> GlobalThreadId {
        GlobalThreadId::new(CPU0, ThreadId { slot, generation })
    }

    #[test]
    fn wait_status_encodes_job_control_exactly() {
        assert_eq!(WaitStatus::stopped(19).unwrap().raw(), (19 << 8) | 0x7f);
        assert_eq!(WaitStatus::continued().raw(), 0xffff);
        assert_eq!(WaitStatus::stopped(0), Err(Error::InvalidSignal));
    }

    #[test]
    fn exited_child_survives_identity_retirement_until_one_shot_reap() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let expected_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<4>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        assert_eq!(publication.parent(), parent.id());
        assert_eq!(
            publication.parent_pid(),
            identities.pid_for(&parent).unwrap()
        );
        assert_eq!(publication.child_pid(), expected_pid);

        let bindings = ThreadObjectBindings::<0>::new();
        child.exit(&mut objects, &bindings).unwrap();
        identities.retire_process(&child).unwrap();
        waits
            .publish_exit(&publication, &child, WaitStatus::exited(7))
            .unwrap();

        let outcome = waits
            .wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING)
            .unwrap();
        let WaitOutcome::Ready(observation) = outcome else {
            panic!("expected reapable child");
        };
        assert_eq!(observation.pid(), expected_pid);
        assert_eq!(observation.event_class(), WaitEventClass::Exited);
        assert_eq!(observation.status().raw(), 7 << 8);
        assert_eq!(
            waits.wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING),
            Err(Error::NoChild)
        );
    }

    #[test]
    fn job_control_observation_tracks_latest_generation_without_capacity() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<4>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let options = WaitOptions::with_interests(false, true, WaitInterests::ALL);

        waits
            .publish_stopped_with_wakes(&publication, &child, 19)
            .unwrap();
        let WaitOutcome::Ready(stopped) = waits
            .wait(&parent, WaitSelector::Pid(child_pid), options)
            .unwrap()
        else {
            panic!("expected stopped observation");
        };
        assert_eq!(stopped.event_class(), WaitEventClass::Stopped);
        assert_eq!(
            waits.wait(&parent, WaitSelector::Pid(child_pid), options),
            Ok(WaitOutcome::Ready(stopped))
        );

        waits
            .publish_continued_with_wakes(&publication, &child)
            .unwrap();
        assert_eq!(
            waits.consume_nonterminal_observation(&parent, stopped),
            Err(Error::StaleObservation)
        );
        let WaitOutcome::Ready(continued) = waits
            .wait(&parent, WaitSelector::Pid(child_pid), options)
            .unwrap()
        else {
            panic!("expected continued observation");
        };
        assert_eq!(continued.event_class(), WaitEventClass::Continued);
        assert!(continued.event_generation() > stopped.event_generation());
        assert_eq!(
            waits.wait(&parent, WaitSelector::Pid(child_pid), options),
            Ok(WaitOutcome::Ready(continued))
        );

        for _ in 0..3 {
            waits
                .publish_stopped_with_wakes(&publication, &child, 19)
                .unwrap();
            waits
                .publish_continued_with_wakes(&publication, &child)
                .unwrap();
        }
        waits
            .publish_stopped_with_wakes(&publication, &child, 20)
            .unwrap();
        let WaitOutcome::Ready(final_stop) = waits
            .wait(&parent, WaitSelector::Pid(child_pid), options)
            .unwrap()
        else {
            panic!("expected final stopped observation");
        };
        assert_eq!(final_stop.event_class(), WaitEventClass::Stopped);
        assert_eq!(final_stop.status().raw(), (20 << 8) | 0x7f);
        assert!(final_stop.event_generation() > continued.event_generation());
        waits
            .consume_nonterminal_observation(&parent, final_stop)
            .unwrap();
        assert_eq!(
            waits.wait(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitOptions::with_interests(true, true, WaitInterests::ALL),
            ),
            Ok(WaitOutcome::NoHang)
        );
    }

    #[test]
    fn zombie_exit_supersedes_current_job_control_observation() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<4>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();

        waits
            .publish_stopped_with_wakes(&publication, &child, 19)
            .unwrap();
        let stopped_options = WaitOptions::with_interests(false, true, WaitInterests::STOPPED);
        let WaitOutcome::Ready(stopped) = waits
            .wait(&parent, WaitSelector::Pid(child_pid), stopped_options)
            .unwrap()
        else {
            panic!("expected stopped observation");
        };

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        waits
            .publish_exit(&publication, &child, WaitStatus::exited(9))
            .unwrap();

        assert_eq!(
            waits.wait(&parent, WaitSelector::Pid(child_pid), stopped_options),
            Err(Error::NoChild)
        );
        assert_eq!(
            waits.consume_nonterminal_observation(&parent, stopped),
            Err(Error::StaleObservation)
        );
        let all_options = WaitOptions::with_interests(false, true, WaitInterests::ALL);
        let WaitOutcome::Ready(exited) = waits
            .wait(&parent, WaitSelector::Pid(child_pid), all_options)
            .unwrap()
        else {
            panic!("expected terminal observation");
        };
        assert_eq!(exited.event_class(), WaitEventClass::Exited);
        assert_eq!(exited.status().raw(), 9 << 8);
        assert!(exited.event_generation() > stopped.event_generation());
    }

    #[test]
    fn event_interest_filters_blocking_waiter_wakes() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<4>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let stop_thread = global(20, 30);
        let exit_thread = global(21, 31);

        let WaitPrepareOutcome::Sleep(stop_receipt) = waits
            .prepare_sleep_with_interests(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitInterests::STOPPED,
                stop_thread,
            )
            .unwrap()
        else {
            panic!("expected stop waiter");
        };
        let WaitPrepareOutcome::Sleep(exit_receipt) = waits
            .prepare_sleep(&parent, WaitSelector::Pid(child_pid), exit_thread)
            .unwrap()
        else {
            panic!("expected exit waiter");
        };
        assert_eq!(
            waits.commit_sleep(&stop_receipt),
            Ok(WaitCommitOutcome::Sleep)
        );
        assert_eq!(
            waits.commit_sleep(&exit_receipt),
            Ok(WaitCommitOutcome::Sleep)
        );

        let wakes = waits
            .publish_stopped_with_wakes(&publication, &child, 19)
            .unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes.get(0), Some(stop_thread));
        assert_eq!(waits.cancel_sleep(stop_receipt), Ok(false));
        assert_eq!(waits.cancel_sleep(exit_receipt), Ok(true));
    }

    #[test]
    fn terminal_exit_wakes_committed_stopped_only_waiter() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(22, 32);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep_with_interests(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitInterests::STOPPED,
                waiter,
            )
            .unwrap()
        else {
            panic!("running child must prepare stopped-only waiter");
        };
        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(0))
            .unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes.get(0), Some(waiter));
        assert_eq!(waits.cancel_sleep(receipt), Ok(false));
    }

    #[test]
    fn terminal_exit_notifies_prepared_stopped_only_waiter() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(23, 33);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep_with_interests(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitInterests::STOPPED,
                waiter,
            )
            .unwrap()
        else {
            panic!("running child must prepare stopped-only waiter");
        };

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(0))
            .unwrap();
        assert!(wakes.is_empty());
        assert_eq!(
            waits.commit_sleep(&receipt),
            Ok(WaitCommitOutcome::AlreadyWoken)
        );
    }

    #[test]
    fn auto_reap_wakes_job_control_only_waiter_and_removes_child() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(24, 34);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep_with_interests(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitInterests::CONTINUED,
                waiter,
            )
            .unwrap()
        else {
            panic!("running child must prepare continued-only waiter");
        };
        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .auto_reap_exit_with_wakes(&publication, &child)
            .unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes.get(0), Some(waiter));
        assert_eq!(
            waits.wait(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitOptions::with_interests(false, true, WaitInterests::CONTINUED),
            ),
            Err(Error::NoChild)
        );
    }

    #[test]
    fn compatibility_publish_refuses_job_control_waiter_that_needs_terminal_liveness() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep_with_interests(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitInterests::STOPPED,
                global(25, 35),
            )
            .unwrap()
        else {
            panic!("running child must prepare stopped-only waiter");
        };
        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        assert_eq!(
            waits.publish_exit(&publication, &child, WaitStatus::exited(0)),
            Err(Error::WaiterWakeRequired)
        );
    }

    #[test]
    fn compatibility_publish_allows_already_notified_job_control_waiter() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep_with_interests(
                &parent,
                WaitSelector::Pid(child_pid),
                WaitInterests::STOPPED,
                global(26, 36),
            )
            .unwrap()
        else {
            panic!("running child must prepare stopped-only waiter");
        };
        assert!(
            waits
                .notify_exit_transition(&publication)
                .unwrap()
                .is_empty()
        );

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        waits
            .publish_exit(&publication, &child, WaitStatus::exited(0))
            .unwrap();
        assert_eq!(
            waits.commit_sleep(&receipt),
            Ok(WaitCommitOutcome::AlreadyWoken)
        );
    }

    #[test]
    fn auto_reap_removes_child_and_preserves_waiter_wake_contract() {
        let mut objects = ObjectTable::<10>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<4>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();

        let prepared_thread = global(14, 20);
        let WaitPrepareOutcome::Sleep(prepared) = waits
            .prepare_sleep(&parent, WaitSelector::Pid(child_pid), prepared_thread)
            .unwrap()
        else {
            panic!("running child must prepare waiter");
        };
        let committed_thread = global(15, 21);
        let WaitPrepareOutcome::Sleep(committed) = waits
            .prepare_sleep(&parent, WaitSelector::Pid(child_pid), committed_thread)
            .unwrap()
        else {
            panic!("running child must prepare waiter");
        };
        assert_eq!(waits.commit_sleep(&committed), Ok(WaitCommitOutcome::Sleep));

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        identities.retire_process(&child).unwrap();
        let wakes = waits
            .auto_reap_exit_with_wakes(&publication, &child)
            .unwrap();

        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes.get(0), Some(committed_thread));
        assert_eq!(
            waits.commit_sleep(&prepared),
            Ok(WaitCommitOutcome::AlreadyWoken)
        );
        assert_eq!(
            waits.wait(&parent, WaitSelector::Pid(child_pid), WaitOptions::BLOCKING),
            Err(Error::NoChild)
        );
    }

    #[test]
    fn running_child_distinguishes_blocking_from_wnohang_without_reaping() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let _publication = waits.track_child(&mut identities, &parent, &child).unwrap();

        assert_eq!(
            waits
                .wait(&parent, WaitSelector::AnyChild, WaitOptions::WNOHANG)
                .unwrap(),
            WaitOutcome::NoHang
        );
        assert_eq!(
            waits
                .wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING)
                .unwrap(),
            WaitOutcome::WouldBlock
        );
    }

    #[test]
    fn wnowait_observes_zombie_without_consuming_it() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let bindings = ThreadObjectBindings::<0>::new();
        child.exit(&mut objects, &bindings).unwrap();
        waits
            .publish_exit(&publication, &child, WaitStatus::exited(0))
            .unwrap();

        let nowait = WaitOptions::new(false, true);
        assert!(matches!(
            waits.wait(&parent, WaitSelector::Pid(child_pid), nowait),
            Ok(WaitOutcome::Ready(_))
        ));
        assert!(matches!(
            waits.wait(&parent, WaitSelector::Pid(child_pid), WaitOptions::BLOCKING),
            Ok(WaitOutcome::Ready(_))
        ));
        assert_eq!(
            waits.wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING),
            Err(Error::NoChild)
        );
    }

    #[test]
    fn live_child_cannot_be_published_as_zombie() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();

        assert_eq!(
            waits.publish_exit(&publication, &child, WaitStatus::exited(1)),
            Err(Error::ChildStillLive)
        );
        waits.cancel_tracking(publication).unwrap();
    }

    #[test]
    fn prepare_after_exit_returns_ready_without_registering_waiter() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        let child_pid = identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        waits
            .publish_exit(&publication, &child, WaitStatus::exited(3))
            .unwrap();

        assert!(matches!(
            waits.prepare_sleep(&parent, WaitSelector::Pid(child_pid), global(1, 1)),
            Ok(WaitPrepareOutcome::Ready(_))
        ));
        assert!(waits.waiters.iter().all(Option::is_none));
    }

    #[test]
    fn exit_transition_notifies_prepared_without_scheduler_wake() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(7, 13);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare waiter");
        };
        let wakes = waits.notify_exit_transition(&publication).unwrap();
        assert!(wakes.is_empty());
        assert_eq!(
            waits.commit_sleep(&receipt),
            Ok(WaitCommitOutcome::AlreadyWoken)
        );
    }

    #[test]
    fn exit_transition_extracts_only_committed_generation() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(8, 14);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare waiter");
        };
        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));
        let wakes = waits.notify_exit_transition(&publication).unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes.get(0), Some(waiter));
    }

    #[test]
    fn commit_before_exit_returns_exact_generation_for_scheduler_wake() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(4, 9);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };
        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));
        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(0))
            .unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes.get(0), Some(waiter));
    }

    #[test]
    fn exit_before_commit_notifies_without_waking_running_parent() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(5, 11);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };
        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(4))
            .unwrap();
        assert!(wakes.is_empty());
        assert_eq!(
            waits.commit_sleep(&receipt),
            Ok(WaitCommitOutcome::AlreadyWoken)
        );
        assert!(matches!(
            waits.wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING),
            Ok(WaitOutcome::Ready(observation)) if observation.status().raw() == 4 << 8
        ));
    }

    #[test]
    fn compatibility_publish_refuses_to_drop_committed_wake() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let receipt = match waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, global(2, 3))
            .unwrap()
        {
            WaitPrepareOutcome::Sleep(receipt) => receipt,
            WaitPrepareOutcome::Ready(_) => panic!("child is still running"),
        };
        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));
        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        assert_eq!(
            waits.publish_exit(&publication, &child, WaitStatus::exited(0)),
            Err(Error::WaiterWakeRequired)
        );
        assert!(matches!(
            waits.wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING),
            Ok(WaitOutcome::WouldBlock)
        ));
    }

    #[test]
    fn committed_waiter_can_be_cancelled_if_scheduler_block_never_commits() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(6, 12);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };

        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));
        assert_eq!(waits.cancel_sleep(receipt), Ok(true));

        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(0))
            .unwrap();
        assert!(wakes.is_empty());
    }

    #[test]
    fn exact_thread_signal_cancel_removes_only_committed_waiter() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let _publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(9, 15);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };

        assert_eq!(waits.cancel_committed_sleep_for_thread(waiter), Ok(false));
        assert_eq!(waits.commit_sleep(&receipt), Ok(WaitCommitOutcome::Sleep));
        assert_eq!(waits.cancel_committed_sleep_for_thread(waiter), Ok(true));
        assert_eq!(waits.cancel_committed_sleep_for_thread(waiter), Ok(false));
        assert_eq!(waits.cancel_sleep(receipt), Ok(false));
    }

    #[test]
    fn signal_interrupt_after_prepare_prevents_later_block_without_scheduler_wake() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let _publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(10, 16);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };

        assert_eq!(
            waits.interrupt_sleep_for_thread(waiter),
            Ok(WaitInterruptOutcome::InterruptedNoWake)
        );
        assert_eq!(
            waits.interrupt_sleep_for_thread(waiter),
            Ok(WaitInterruptOutcome::AlreadyInterrupted)
        );
        assert_eq!(waits.commit_sleep(&receipt), Err(Error::WaiterInterrupted));
        assert_eq!(
            waits.commit_sleep_signal_aware(&receipt),
            Ok(WaitSignalCommitOutcome::Interrupted)
        );
        assert_eq!(waits.consume_interrupted_sleep(receipt), Ok(true));
        assert_eq!(
            waits.interrupt_sleep_for_thread(waiter),
            Ok(WaitInterruptOutcome::NotWaiting)
        );
    }

    #[test]
    fn committed_signal_interrupt_returns_one_exact_wake_generation() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let _publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(11, 17);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };
        assert_eq!(
            waits.commit_sleep_signal_aware(&receipt),
            Ok(WaitSignalCommitOutcome::Sleep)
        );

        assert_eq!(
            waits.interrupt_sleep_for_thread(waiter),
            Ok(WaitInterruptOutcome::Wake(waiter))
        );
        assert_eq!(
            waits.interrupt_sleep_for_thread(waiter),
            Ok(WaitInterruptOutcome::AlreadyInterrupted)
        );
        assert_eq!(waits.consume_interrupted_sleep(receipt), Ok(true));
    }

    #[test]
    fn child_exit_wins_over_prepared_signal_interruption() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(12, 18);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };
        assert_eq!(
            waits.interrupt_sleep_for_thread(waiter),
            Ok(WaitInterruptOutcome::InterruptedNoWake)
        );
        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(6))
            .unwrap();
        assert!(wakes.is_empty());
        assert_eq!(
            waits.commit_sleep_signal_aware(&receipt),
            Ok(WaitSignalCommitOutcome::AlreadyWoken)
        );
        assert!(matches!(
            waits.wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING),
            Ok(WaitOutcome::Ready(observation)) if observation.status().raw() == 6 << 8
        ));
    }

    #[test]
    fn child_exit_wins_over_committed_signal_interruption_without_duplicate_wake() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let waiter = global(13, 19);
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, waiter)
            .unwrap()
        else {
            panic!("running child must prepare blocking waiter");
        };
        assert_eq!(
            waits.commit_sleep_signal_aware(&receipt),
            Ok(WaitSignalCommitOutcome::Sleep)
        );
        assert_eq!(
            waits.interrupt_sleep_for_thread(waiter),
            Ok(WaitInterruptOutcome::Wake(waiter))
        );
        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(8))
            .unwrap();
        assert!(wakes.is_empty());
        assert_eq!(waits.consume_interrupted_sleep(receipt), Ok(false));
        assert!(matches!(
            waits.wait(&parent, WaitSelector::AnyChild, WaitOptions::BLOCKING),
            Ok(WaitOutcome::Ready(observation)) if observation.status().raw() == 8 << 8
        ));
    }

    #[test]
    fn cancel_before_exit_removes_waiter_and_exit_returns_no_wake() {
        let mut objects = ObjectTable::<8>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut child = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child).unwrap();
        let mut waits = WaitTable::<2>::new();
        let publication = waits.track_child(&mut identities, &parent, &child).unwrap();
        let WaitPrepareOutcome::Sleep(receipt) = waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, global(3, 7))
            .unwrap()
        else {
            panic!("child is still running");
        };
        assert_eq!(waits.cancel_sleep(receipt), Ok(true));
        child
            .exit(&mut objects, &ThreadObjectBindings::<0>::new())
            .unwrap();
        let wakes = waits
            .publish_exit_with_wakes(&publication, &child, WaitStatus::exited(0))
            .unwrap();
        assert!(wakes.is_empty());
    }

    #[test]
    fn stale_receipt_cannot_cancel_reused_waiter_slot() {
        let mut objects = ObjectTable::<12>::new();
        let parent = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let child_a = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let child_b = Process::<4>::create_fork_child(&parent, &mut objects).unwrap();
        let mut identities = LinuxIdentityTable::<4, 0>::new();
        identities.bind_child(&parent, &child_a).unwrap();
        identities.bind_child(&parent, &child_b).unwrap();
        let mut waits = WaitTable::<2>::new();
        let _a = waits
            .track_child(&mut identities, &parent, &child_a)
            .unwrap();
        let _b = waits
            .track_child(&mut identities, &parent, &child_b)
            .unwrap();
        let first = match waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, global(1, 1))
            .unwrap()
        {
            WaitPrepareOutcome::Sleep(receipt) => receipt,
            WaitPrepareOutcome::Ready(_) => panic!("children are running"),
        };
        let stale = WaitSleepReceipt {
            slot: first.slot,
            generation: first.generation,
            parent: first.parent,
            selector: first.selector,
            interests: first.interests,
            thread: first.thread,
        };
        assert_eq!(waits.cancel_sleep(first), Ok(true));
        let second = match waits
            .prepare_sleep(&parent, WaitSelector::AnyChild, global(2, 2))
            .unwrap()
        {
            WaitPrepareOutcome::Sleep(receipt) => receipt,
            WaitPrepareOutcome::Ready(_) => panic!("children are running"),
        };
        assert_eq!(stale.slot, second.slot);
        assert_ne!(stale.generation, second.generation);
        assert_eq!(waits.cancel_sleep(stale), Err(Error::StaleWaiter));
        assert_eq!(waits.cancel_sleep(second), Ok(true));
    }
}
