// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Architecture-neutral Linux signal-state owner for Roadmap Step 30.
//!
//! Process-wide dispositions and process-directed pending state are keyed to the exact Process
//! generation. Per-thread masks and thread-directed pending state are keyed to the canonical exact
//! scheduler Thread generation after validation through `kernal-linux-identity`. This crate owns no
//! PID/TID registry, scheduler authority, trap entry, usercopy or AArch64 signal-frame machinery.

mod child_provenance;
pub use child_provenance::{ChildSignalCode, ChildSignalProvenance};

use core::num::{NonZeroU8, NonZeroU32};
use kernal_capability::ObjectId;
use kernal_linux_identity::{Error as IdentityError, LinuxIdentityTable};
use kernal_process::{Personality, Process, ProcessState};
use kernal_scheduler_smp::GlobalThreadId;

pub const MAX_SIGNAL: u8 = 64;
pub const SIGKILL: u8 = 9;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGTTIN: u8 = 21;
pub const SIGTTOU: u8 = 22;

pub const SA_NOCLDSTOP: u64 = 0x0000_0001;
pub const SA_NOCLDWAIT: u64 = 0x0000_0002;
pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;

pub const SUPPORTED_SIGACTION_FLAGS: u64 = SA_NOCLDSTOP
    | SA_NOCLDWAIT
    | SA_SIGINFO
    | SA_RESTORER
    | SA_ONSTACK
    | SA_RESTART
    | SA_NODEFER
    | SA_RESETHAND;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity(IdentityError),
    ProcessCapacity,
    ThreadCapacity,
    PendingCapacity,
    WrongPersonality,
    ProcessExited,
    ProcessStillLive,
    ProcessNotBound,
    ThreadNotBound,
    ChildMismatch,
    AlreadyBound,
    UncatchableSignal,
    UnsupportedFlags,
    InvalidHandler,
    PendingSerialExhausted,
    PreparedDeliveryStale,
}

impl From<IdentityError> for Error {
    fn from(value: IdentityError) -> Self {
        Self::Identity(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Signal(NonZeroU8);

impl Signal {
    pub const fn new(number: u8) -> Option<Self> {
        match NonZeroU8::new(number) {
            Some(number) if number.get() <= MAX_SIGNAL => Some(Self(number)),
            _ => None,
        }
    }

    pub const fn number(self) -> u8 {
        self.0.get()
    }

    pub const fn is_unmaskable(self) -> bool {
        matches!(self.number(), SIGKILL | SIGSTOP)
    }

    pub const fn is_standard(self) -> bool {
        self.number() <= 31
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignalSet(u64);

impl SignalSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits).without_unmaskable()
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, signal: Signal) -> bool {
        self.0 & signal_bit(signal) != 0
    }

    pub const fn with(self, signal: Signal) -> Self {
        if signal.is_unmaskable() {
            self
        } else {
            Self(self.0 | signal_bit(signal))
        }
    }

    pub const fn without(self, signal: Signal) -> Self {
        Self(self.0 & !signal_bit(signal))
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0).without_unmaskable()
    }

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0).without_unmaskable()
    }

    pub const fn without_unmaskable(self) -> Self {
        let kill = Signal::new(SIGKILL).expect("SIGKILL is valid");
        let stop = Signal::new(SIGSTOP).expect("SIGSTOP is valid");
        Self(self.0 & !signal_bit(kill) & !signal_bit(stop))
    }
}

const fn signal_bit(signal: Signal) -> u64 {
    1u64 << (signal.number() - 1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskHow {
    Block,
    Unblock,
    Set,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalHandler {
    entry: u64,
    restorer: Option<u64>,
    flags: u64,
    mask: SignalSet,
}

impl SignalHandler {
    pub fn new(
        entry: u64,
        restorer: Option<u64>,
        flags: u64,
        mask: SignalSet,
    ) -> Result<Self, Error> {
        if entry == 0 || restorer == Some(0) {
            return Err(Error::InvalidHandler);
        }
        if flags & !SUPPORTED_SIGACTION_FLAGS != 0 {
            return Err(Error::UnsupportedFlags);
        }
        let has_restorer_flag = flags & SA_RESTORER != 0;
        if has_restorer_flag != restorer.is_some() {
            return Err(Error::InvalidHandler);
        }
        Ok(Self {
            entry,
            restorer,
            flags,
            mask: mask.without_unmaskable(),
        })
    }

    pub const fn entry(self) -> u64 {
        self.entry
    }

    pub const fn restorer(self) -> Option<u64> {
        self.restorer
    }

    pub const fn flags(self) -> u64 {
        self.flags
    }

    pub const fn mask(self) -> SignalSet {
        self.mask
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Default,
    Ignore,
    Handler(SignalHandler),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalAction {
    disposition: Disposition,
    flags: u64,
    restorer: Option<u64>,
    mask: SignalSet,
}

impl SignalAction {
    pub const fn linux_default() -> Self {
        Self {
            disposition: Disposition::Default,
            flags: 0,
            restorer: None,
            mask: SignalSet::empty(),
        }
    }

    pub fn new(
        disposition: Disposition,
        flags: u64,
        restorer: Option<u64>,
        mask: SignalSet,
    ) -> Result<Self, Error> {
        if flags & !SUPPORTED_SIGACTION_FLAGS != 0 {
            return Err(Error::UnsupportedFlags);
        }
        if restorer == Some(0) || (flags & SA_RESTORER != 0) != restorer.is_some() {
            return Err(Error::InvalidHandler);
        }
        let mask = mask.without_unmaskable();
        if let Disposition::Handler(handler) = disposition
            && (handler.flags() != flags
                || handler.restorer() != restorer
                || handler.mask() != mask)
        {
            return Err(Error::InvalidHandler);
        }
        Ok(Self {
            disposition,
            flags,
            restorer,
            mask,
        })
    }

    pub fn from_disposition(disposition: Disposition) -> Self {
        match disposition {
            Disposition::Handler(handler) => Self {
                disposition,
                flags: handler.flags(),
                restorer: handler.restorer(),
                mask: handler.mask(),
            },
            Disposition::Default | Disposition::Ignore => Self {
                disposition,
                ..Self::linux_default()
            },
        }
    }

    pub const fn disposition(self) -> Disposition {
        self.disposition
    }

    pub const fn flags(self) -> u64 {
        self.flags
    }

    pub const fn restorer(self) -> Option<u64> {
        self.restorer
    }

    pub const fn mask(self) -> SignalSet {
        self.mask
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultAction {
    Ignore,
    Continue,
    Stop,
    Terminate { core_dump: bool },
}

pub const fn default_action(signal: Signal) -> DefaultAction {
    match signal.number() {
        SIGCHLD | 23 | 28 => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Continue,
        SIGSTOP..=SIGTTOU => DefaultAction::Stop,
        3..=8 | 11 | 24 | 25 | 31 => DefaultAction::Terminate { core_dump: true },
        _ => DefaultAction::Terminate { core_dump: false },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalProvenance {
    Kernel,
    Child(ChildSignalProvenance),
    User {
        sender_pid: NonZeroU32,
        sender_uid: u32,
    },
    Tkill {
        sender_pid: NonZeroU32,
        sender_uid: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingSignal {
    signal: Signal,
    provenance: SignalProvenance,
    serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingSource {
    Process,
    Thread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    Default {
        signal: Signal,
        action: DefaultAction,
    },
    Handler {
        signal: Signal,
        handler: SignalHandler,
        previous_mask: SignalSet,
        effective_mask: SignalSet,
    },
}

/// Non-Copy receipt for one exact pending signal selected for delivery but not yet consumed.
///
/// Core may perform all fallible user-frame work after prepare. Only commit is allowed to remove the
/// exact serial, change the thread mask, or apply SA_RESETHAND.
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedSignalDelivery {
    process: ObjectId,
    thread: GlobalThreadId,
    source: PendingSource,
    serial: u64,
    signal: Signal,
    provenance: SignalProvenance,
    expected_action: SignalAction,
    expected_mask: SignalSet,
    delivery: Delivery,
}

impl PreparedSignalDelivery {
    pub const fn delivery(&self) -> Delivery {
        self.delivery
    }

    pub const fn provenance(&self) -> SignalProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingQueue<const N: usize> {
    entries: [Option<PendingSignal>; N],
    next_serial: u64,
}

impl<const N: usize> PendingQueue<N> {
    const fn new() -> Self {
        Self {
            entries: [None; N],
            next_serial: 1,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    fn count(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    #[cfg(test)]
    fn queue(&mut self, signal: Signal) -> Result<(), Error> {
        self.queue_with_provenance(signal, SignalProvenance::Kernel)
    }

    fn preflight_queue(&self, signal: Signal) -> Result<(), Error> {
        if signal.is_standard()
            && self
                .entries
                .iter()
                .flatten()
                .any(|pending| pending.signal == signal)
        {
            return Ok(());
        }
        if self.entries.iter().all(Option::is_some) {
            return Err(Error::PendingCapacity);
        }
        if self.next_serial == 0 {
            return Err(Error::PendingSerialExhausted);
        }
        Ok(())
    }

    fn preflight_queue_after_job_control_cancellation(&self, signal: Signal) -> Result<(), Error> {
        let mut staged = *self;
        let (cancelled, cancelled_len) = job_control_cancelled_numbers(signal);
        for number in cancelled.into_iter().take(cancelled_len) {
            staged.remove_all(Signal::new(number).expect("job-control signal is valid"));
        }
        staged.preflight_queue(signal)
    }

    fn queue_preflighted_with_provenance(&mut self, signal: Signal, provenance: SignalProvenance) {
        if signal.is_standard()
            && self
                .entries
                .iter()
                .flatten()
                .any(|pending| pending.signal == signal)
        {
            return;
        }
        let slot = self
            .entries
            .iter()
            .position(Option::is_none)
            .expect("signal queue preflight guaranteed capacity");
        let serial = self.next_serial;
        assert!(serial != 0, "signal queue preflight guaranteed serial");
        self.next_serial = serial.checked_add(1).unwrap_or(0);
        self.entries[slot] = Some(PendingSignal {
            signal,
            provenance,
            serial,
        });
    }

    #[cfg(test)]
    fn queue_with_provenance(
        &mut self,
        signal: Signal,
        provenance: SignalProvenance,
    ) -> Result<(), Error> {
        self.preflight_queue(signal)?;
        self.queue_preflighted_with_provenance(signal, provenance);
        Ok(())
    }

    fn remove_all(&mut self, signal: Signal) {
        let mut compacted = [None; N];
        let mut next = 0usize;
        for pending in self.entries.iter().flatten().copied() {
            if pending.signal != signal {
                compacted[next] = Some(pending);
                next += 1;
            }
        }
        self.entries = compacted;
    }

    fn next_deliverable_entry(&self, mask: SignalSet) -> Option<(usize, PendingSignal)> {
        let mut best = None;
        for (index, entry) in self.entries.iter().enumerate() {
            let Some(pending) = *entry else {
                continue;
            };
            let signal = pending.signal;
            if !signal.is_unmaskable() && mask.contains(signal) {
                continue;
            }
            match best {
                None => best = Some((index, pending)),
                Some((_, current)) if signal.number() < current.signal.number() => {
                    best = Some((index, pending));
                }
                _ => {}
            }
        }
        best
    }

    #[cfg(test)]
    fn next_deliverable(&self, mask: SignalSet) -> Option<(usize, Signal)> {
        self.next_deliverable_entry(mask)
            .map(|(index, pending)| (index, pending.signal))
    }

    fn take_entry(&mut self, index: usize) -> PendingSignal {
        let pending = self.entries[index].expect("pending index is populated");
        if N > 0 {
            self.entries.copy_within(index + 1..N, index);
            self.entries[N - 1] = None;
        }
        pending
    }

    #[cfg(test)]
    fn take(&mut self, index: usize) -> Signal {
        self.take_entry(index).signal
    }

    fn take_serial(&mut self, serial: u64, signal: Signal) -> Result<PendingSignal, Error> {
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.is_some_and(|pending| pending.serial == serial && pending.signal == signal)
            })
            .ok_or(Error::PreparedDeliveryStale)?;
        Ok(self.take_entry(index))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessSignalRecord<const PENDING: usize> {
    process: ObjectId,
    actions: [SignalAction; MAX_SIGNAL as usize],
    pending: PendingQueue<PENDING>,
}

impl<const PENDING: usize> ProcessSignalRecord<PENDING> {
    const fn new(process: ObjectId) -> Self {
        Self {
            process,
            actions: [SignalAction::linux_default(); MAX_SIGNAL as usize],
            pending: PendingQueue::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadSignalRecord<const PENDING: usize> {
    process: ObjectId,
    thread: GlobalThreadId,
    mask: SignalSet,
    pending: PendingQueue<PENDING>,
}

impl<const PENDING: usize> ThreadSignalRecord<PENDING> {
    const fn new(process: ObjectId, thread: GlobalThreadId, mask: SignalSet) -> Self {
        Self {
            process,
            thread,
            mask: mask.without_unmaskable(),
            pending: PendingQueue::new(),
        }
    }
}

/// Bounded Linux signal policy without a second Process/Thread registry.
///
/// `processes` stores only process-wide signal policy keyed by exact Process ObjectId. `threads`
/// stores only per-thread signal policy keyed by exact [`GlobalThreadId`]. Every public thread
/// operation revalidates that scheduler generation through the canonical [`LinuxIdentityTable`]
/// before observing or mutating signal state. Scalar PID/TID values are never accepted as authority.
pub struct SignalTable<
    const PROCESSES: usize,
    const PENDING: usize,
    const THREADS: usize = PROCESSES,
> {
    processes: [Option<ProcessSignalRecord<PENDING>>; PROCESSES],
    threads: [Option<ThreadSignalRecord<PENDING>>; THREADS],
}

impl<const PROCESSES: usize, const PENDING: usize, const THREADS: usize>
    SignalTable<PROCESSES, PENDING, THREADS>
{
    pub const fn new() -> Self {
        Self {
            processes: [None; PROCESSES],
            threads: [None; THREADS],
        }
    }

    pub fn bind_process<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
    ) -> Result<(), Error> {
        let process_id = live_linux_process(process)?;
        if self.process_record(process_id).is_some() {
            return Ok(());
        }
        let slot = self
            .processes
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ProcessCapacity)?;
        self.processes[slot] = Some(ProcessSignalRecord::new(process_id));
        Ok(())
    }

    pub fn bind_thread<const ID_PROCESSES: usize, const ID_THREADS: usize, const CAPS: usize>(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
        initial_mask: SignalSet,
    ) -> Result<(), Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        if self.process_record(process_id).is_none() {
            return Err(Error::ProcessNotBound);
        }
        if self.thread_record(process_id, thread).is_some() {
            return Ok(());
        }
        let slot = self
            .threads
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ThreadCapacity)?;
        self.threads[slot] = Some(ThreadSignalRecord::new(process_id, thread, initial_mask));
        Ok(())
    }

    pub fn inherit_child<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const PARENT_CAPS: usize,
        const CHILD_CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        parent: &Process<PARENT_CAPS>,
        child: &Process<CHILD_CAPS>,
    ) -> Result<(), Error> {
        let parent_id = live_linux_process(parent)?;
        let child_id = live_linux_process(child)?;
        if !identities.is_child_of(parent, child)? {
            return Err(Error::ChildMismatch);
        }
        let parent_record = self
            .process_record(parent_id)
            .ok_or(Error::ProcessNotBound)?;
        if let Some(existing) = self.process_record(child_id) {
            if existing.actions == parent_record.actions && existing.pending.is_empty() {
                return Ok(());
            }
            return Err(Error::AlreadyBound);
        }
        let slot = self
            .processes
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ProcessCapacity)?;
        let mut record = ProcessSignalRecord::new(child_id);
        record.actions = parent_record.actions;
        self.processes[slot] = Some(record);
        Ok(())
    }

    pub fn inherit_thread_mask<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const PARENT_CAPS: usize,
        const CHILD_CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        parent: &Process<PARENT_CAPS>,
        parent_thread: GlobalThreadId,
        child: &Process<CHILD_CAPS>,
        child_thread: GlobalThreadId,
    ) -> Result<(), Error> {
        let parent_id = exact_bound_thread(identities, parent, parent_thread)?;
        let child_id = exact_bound_thread(identities, child, child_thread)?;
        if !identities.is_child_of(parent, child)? {
            return Err(Error::ChildMismatch);
        }
        let parent_state = self
            .thread_record(parent_id, parent_thread)
            .ok_or(Error::ThreadNotBound)?;
        if let Some(existing) = self.thread_record(child_id, child_thread) {
            return if existing.mask == parent_state.mask && existing.pending.is_empty() {
                Ok(())
            } else {
                Err(Error::AlreadyBound)
            };
        }
        let slot = self
            .threads
            .iter()
            .position(Option::is_none)
            .ok_or(Error::ThreadCapacity)?;
        self.threads[slot] = Some(ThreadSignalRecord::new(
            child_id,
            child_thread,
            parent_state.mask,
        ));
        Ok(())
    }

    pub fn action<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
        signal: Signal,
    ) -> Result<SignalAction, Error> {
        let process_id = live_linux_process(process)?;
        Ok(self
            .process_record(process_id)
            .ok_or(Error::ProcessNotBound)?
            .actions[signal_index(signal)])
    }

    pub fn set_action<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        signal: Signal,
        action: SignalAction,
    ) -> Result<SignalAction, Error> {
        let process_id = live_linux_process(process)?;
        if signal.is_unmaskable() && action.disposition() != Disposition::Default {
            return Err(Error::UncatchableSignal);
        }
        let index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let mut record = self.processes[index].ok_or(Error::ProcessNotBound)?;
        let slot = signal_index(signal);
        let previous = record.actions[slot];
        record.actions[slot] = action;
        if should_discard(action.disposition(), signal) {
            record.pending.remove_all(signal);
            for thread in self.threads.iter_mut().flatten() {
                if thread.process == process_id {
                    thread.pending.remove_all(signal);
                }
            }
        }
        self.processes[index] = Some(record);
        Ok(previous)
    }

    pub fn disposition<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
        signal: Signal,
    ) -> Result<Disposition, Error> {
        self.action(process, signal).map(SignalAction::disposition)
    }

    pub fn set_disposition<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        signal: Signal,
        disposition: Disposition,
    ) -> Result<Disposition, Error> {
        self.set_action(process, signal, SignalAction::from_disposition(disposition))
            .map(SignalAction::disposition)
    }

    pub fn thread_mask<const ID_PROCESSES: usize, const ID_THREADS: usize, const CAPS: usize>(
        &self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
    ) -> Result<SignalSet, Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        self.thread_record(process_id, thread)
            .map(|record| record.mask)
            .ok_or(Error::ThreadNotBound)
    }

    pub fn update_thread_mask<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
        how: MaskHow,
        set: SignalSet,
    ) -> Result<SignalSet, Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        let index = self
            .thread_record_index(process_id, thread)
            .ok_or(Error::ThreadNotBound)?;
        let mut record = self.threads[index].ok_or(Error::ThreadNotBound)?;
        let previous = record.mask;
        record.mask = match how {
            MaskHow::Block => record.mask.union(set),
            MaskHow::Unblock => record.mask.difference(set),
            MaskHow::Set => set.without_unmaskable(),
        };
        self.threads[index] = Some(record);
        Ok(previous)
    }

    fn cancel_job_control_pending(&mut self, process: ObjectId, generated: Signal) {
        let (cancelled, cancelled_len) = job_control_cancelled_numbers(generated);
        if cancelled_len == 0 {
            return;
        }

        if let Some(record) = self
            .processes
            .iter_mut()
            .flatten()
            .find(|record| record.process == process)
        {
            for number in cancelled.into_iter().take(cancelled_len) {
                record
                    .pending
                    .remove_all(Signal::new(number).expect("job-control signal is valid"));
            }
        }
        for thread in self.threads.iter_mut().flatten() {
            if thread.process == process {
                for number in cancelled.into_iter().take(cancelled_len) {
                    thread
                        .pending
                        .remove_all(Signal::new(number).expect("job-control signal is valid"));
                }
            }
        }
    }

    pub fn queue_signal<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        signal: Signal,
    ) -> Result<(), Error> {
        self.queue_signal_with_provenance(process, signal, SignalProvenance::Kernel)
    }

    pub fn queue_signal_with_provenance<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
        signal: Signal,
        provenance: SignalProvenance,
    ) -> Result<(), Error> {
        let process_id = live_linux_process(process)?;
        let index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let record = self.processes[index].ok_or(Error::ProcessNotBound)?;
        if should_discard(record.actions[signal_index(signal)].disposition(), signal) {
            self.cancel_job_control_pending(process_id, signal);
            return Ok(());
        }
        record
            .pending
            .preflight_queue_after_job_control_cancellation(signal)?;
        self.cancel_job_control_pending(process_id, signal);
        let mut record = self.processes[index]
            .expect("validated process signal record survives owner-local cancellation");
        record
            .pending
            .queue_preflighted_with_provenance(signal, provenance);
        self.processes[index] = Some(record);
        Ok(())
    }

    pub fn queue_thread_signal<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
        signal: Signal,
    ) -> Result<(), Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::ProcessNotBound)?;
        if should_discard(
            process_record.actions[signal_index(signal)].disposition(),
            signal,
        ) {
            self.cancel_job_control_pending(process_id, signal);
            return Ok(());
        }
        let index = self
            .thread_record_index(process_id, thread)
            .ok_or(Error::ThreadNotBound)?;
        let record = self.threads[index].ok_or(Error::ThreadNotBound)?;
        record
            .pending
            .preflight_queue_after_job_control_cancellation(signal)?;
        self.cancel_job_control_pending(process_id, signal);
        let mut record = self.threads[index]
            .expect("validated thread signal record survives owner-local cancellation");
        record
            .pending
            .queue_preflighted_with_provenance(signal, SignalProvenance::Kernel);
        self.threads[index] = Some(record);
        Ok(())
    }

    pub fn queue_thread_signal_with_provenance<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
        signal: Signal,
        provenance: SignalProvenance,
    ) -> Result<(), Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::ProcessNotBound)?;
        if should_discard(
            process_record.actions[signal_index(signal)].disposition(),
            signal,
        ) {
            self.cancel_job_control_pending(process_id, signal);
            return Ok(());
        }
        let index = self
            .thread_record_index(process_id, thread)
            .ok_or(Error::ThreadNotBound)?;
        let record = self.threads[index].ok_or(Error::ThreadNotBound)?;
        record
            .pending
            .preflight_queue_after_job_control_cancellation(signal)?;
        self.cancel_job_control_pending(process_id, signal);
        let mut record = self.threads[index]
            .expect("validated thread signal record survives owner-local cancellation");
        record
            .pending
            .queue_preflighted_with_provenance(signal, provenance);
        self.threads[index] = Some(record);
        Ok(())
    }

    pub fn pending_count<const CAPS: usize>(
        &self,
        process: &Process<CAPS>,
    ) -> Result<usize, Error> {
        let process_id = live_linux_process(process)?;
        Ok(self
            .process_record(process_id)
            .ok_or(Error::ProcessNotBound)?
            .pending
            .count())
    }

    pub fn thread_pending_count<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const CAPS: usize,
    >(
        &self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
    ) -> Result<usize, Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        Ok(self
            .thread_record(process_id, thread)
            .ok_or(Error::ThreadNotBound)?
            .pending
            .count())
    }

    pub fn prepare_delivery_for_thread<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const CAPS: usize,
    >(
        &self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
    ) -> Result<Option<PreparedSignalDelivery>, Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        let process_record = self
            .process_record(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let thread_record = self
            .thread_record(process_id, thread)
            .ok_or(Error::ThreadNotBound)?;
        let discardable_thread = thread_record
            .pending
            .entries
            .iter()
            .flatten()
            .copied()
            .find(|pending| {
                should_discard(
                    process_record.actions[signal_index(pending.signal)].disposition(),
                    pending.signal,
                )
            });
        let discardable_process = process_record
            .pending
            .entries
            .iter()
            .flatten()
            .copied()
            .find(|pending| {
                should_discard(
                    process_record.actions[signal_index(pending.signal)].disposition(),
                    pending.signal,
                )
            });
        let discardable = match (discardable_thread, discardable_process) {
            (Some(thread_pending), Some(process_pending)) => {
                if thread_pending.signal.number() <= process_pending.signal.number() {
                    Some((PendingSource::Thread, thread_pending))
                } else {
                    Some((PendingSource::Process, process_pending))
                }
            }
            (Some(pending), None) => Some((PendingSource::Thread, pending)),
            (None, Some(pending)) => Some((PendingSource::Process, pending)),
            (None, None) => None,
        };
        if let Some((source, pending)) = discardable {
            let action = process_record.actions[signal_index(pending.signal)];
            return Ok(Some(PreparedSignalDelivery {
                process: process_id,
                thread,
                source,
                serial: pending.serial,
                signal: pending.signal,
                provenance: pending.provenance,
                expected_action: action,
                expected_mask: thread_record.mask,
                delivery: Delivery::Default {
                    signal: pending.signal,
                    action: DefaultAction::Ignore,
                },
            }));
        }

        let thread_candidate = thread_record
            .pending
            .next_deliverable_entry(thread_record.mask);
        let process_candidate = process_record
            .pending
            .next_deliverable_entry(thread_record.mask);
        let (source, pending) = match (thread_candidate, process_candidate) {
            (None, None) => return Ok(None),
            (Some((_, pending)), None) => (PendingSource::Thread, pending),
            (None, Some((_, pending))) => (PendingSource::Process, pending),
            (Some((_, thread_pending)), Some((_, process_pending))) => {
                if thread_pending.signal.number() <= process_pending.signal.number() {
                    (PendingSource::Thread, thread_pending)
                } else {
                    (PendingSource::Process, process_pending)
                }
            }
        };
        let action = process_record.actions[signal_index(pending.signal)];
        let disposition = action.disposition();
        let delivery = match disposition {
            Disposition::Default => Delivery::Default {
                signal: pending.signal,
                action: default_action(pending.signal),
            },
            Disposition::Ignore => Delivery::Default {
                signal: pending.signal,
                action: DefaultAction::Ignore,
            },
            Disposition::Handler(handler) => {
                let previous_mask = thread_record.mask;
                let mut effective_mask = previous_mask.union(handler.mask());
                if handler.flags() & SA_NODEFER == 0 {
                    effective_mask = effective_mask.with(pending.signal);
                }
                Delivery::Handler {
                    signal: pending.signal,
                    handler,
                    previous_mask,
                    effective_mask,
                }
            }
        };
        Ok(Some(PreparedSignalDelivery {
            process: process_id,
            thread,
            source,
            serial: pending.serial,
            signal: pending.signal,
            provenance: pending.provenance,
            expected_action: action,
            expected_mask: thread_record.mask,
            delivery,
        }))
    }

    pub fn commit_prepared_delivery<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
        prepared: PreparedSignalDelivery,
    ) -> Result<Delivery, Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        if process_id != prepared.process || thread != prepared.thread {
            return Err(Error::PreparedDeliveryStale);
        }
        let process_index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let thread_index = self
            .thread_record_index(process_id, thread)
            .ok_or(Error::ThreadNotBound)?;
        let mut process_record = self.processes[process_index].ok_or(Error::ProcessNotBound)?;
        let mut thread_record = self.threads[thread_index].ok_or(Error::ThreadNotBound)?;
        if thread_record.mask != prepared.expected_mask
            || process_record.actions[signal_index(prepared.signal)] != prepared.expected_action
        {
            return Err(Error::PreparedDeliveryStale);
        }
        let consumed = match prepared.source {
            PendingSource::Process => process_record
                .pending
                .take_serial(prepared.serial, prepared.signal)?,
            PendingSource::Thread => thread_record
                .pending
                .take_serial(prepared.serial, prepared.signal)?,
        };
        if consumed.provenance != prepared.provenance {
            return Err(Error::PreparedDeliveryStale);
        }
        if let Delivery::Handler {
            handler,
            effective_mask,
            ..
        } = prepared.delivery
        {
            thread_record.mask = effective_mask;
            if handler.flags() & SA_RESETHAND != 0 {
                process_record.actions[signal_index(prepared.signal)] =
                    SignalAction::linux_default();
            }
        }
        self.processes[process_index] = Some(process_record);
        self.threads[thread_index] = Some(thread_record);
        Ok(prepared.delivery)
    }

    pub fn next_delivery_for_thread<
        const ID_PROCESSES: usize,
        const ID_THREADS: usize,
        const CAPS: usize,
    >(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
    ) -> Result<Option<Delivery>, Error> {
        loop {
            let Some(prepared) = self.prepare_delivery_for_thread(identities, process, thread)?
            else {
                return Ok(None);
            };
            let delivery = self.commit_prepared_delivery(identities, process, thread, prepared)?;
            if matches!(
                delivery,
                Delivery::Default {
                    action: DefaultAction::Ignore,
                    ..
                }
            ) {
                continue;
            }
            return Ok(Some(delivery));
        }
    }

    pub fn reset_caught_handlers_for_exec<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
    ) -> Result<(), Error> {
        let process_id = live_linux_process(process)?;
        let index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        let mut record = self.processes[index].ok_or(Error::ProcessNotBound)?;
        for action in &mut record.actions {
            if matches!(action.disposition(), Disposition::Handler(_)) {
                *action = SignalAction::linux_default();
            }
        }
        self.processes[index] = Some(record);
        Ok(())
    }

    pub fn retire_thread<const ID_PROCESSES: usize, const ID_THREADS: usize, const CAPS: usize>(
        &mut self,
        identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
        process: &Process<CAPS>,
        thread: GlobalThreadId,
    ) -> Result<(), Error> {
        let process_id = exact_bound_thread(identities, process, thread)?;
        let index = self
            .thread_record_index(process_id, thread)
            .ok_or(Error::ThreadNotBound)?;
        self.threads[index] = None;
        Ok(())
    }

    pub fn retire_process<const CAPS: usize>(
        &mut self,
        process: &Process<CAPS>,
    ) -> Result<(), Error> {
        if process.personality() != Personality::Linux {
            return Err(Error::WrongPersonality);
        }
        if process.state() != ProcessState::Exited {
            return Err(Error::ProcessStillLive);
        }
        let process_id = process.id();
        let index = self
            .process_record_index(process_id)
            .ok_or(Error::ProcessNotBound)?;
        self.processes[index] = None;
        for record in &mut self.threads {
            if record.is_some_and(|record| record.process == process_id) {
                *record = None;
            }
        }
        Ok(())
    }

    fn process_record(&self, process: ObjectId) -> Option<ProcessSignalRecord<PENDING>> {
        self.processes
            .iter()
            .flatten()
            .copied()
            .find(|record| record.process == process)
    }

    fn process_record_index(&self, process: ObjectId) -> Option<usize> {
        self.processes
            .iter()
            .position(|record| record.is_some_and(|record| record.process == process))
    }

    fn thread_record(
        &self,
        process: ObjectId,
        thread: GlobalThreadId,
    ) -> Option<ThreadSignalRecord<PENDING>> {
        self.threads
            .iter()
            .flatten()
            .copied()
            .find(|record| record.process == process && record.thread == thread)
    }

    fn thread_record_index(&self, process: ObjectId, thread: GlobalThreadId) -> Option<usize> {
        self.threads.iter().position(|record| {
            record.is_some_and(|record| record.process == process && record.thread == thread)
        })
    }
}

impl<const PROCESSES: usize, const PENDING: usize, const THREADS: usize> Default
    for SignalTable<PROCESSES, PENDING, THREADS>
{
    fn default() -> Self {
        Self::new()
    }
}

const fn signal_index(signal: Signal) -> usize {
    signal.number() as usize - 1
}

fn job_control_cancelled_numbers(generated: Signal) -> ([u8; 4], usize) {
    match generated.number() {
        SIGCONT => ([SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU], 4),
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => ([SIGCONT, 0, 0, 0], 1),
        _ => ([0; 4], 0),
    }
}

fn should_discard(disposition: Disposition, signal: Signal) -> bool {
    disposition == Disposition::Ignore
        || (disposition == Disposition::Default && default_action(signal) == DefaultAction::Ignore)
}

fn live_linux_process<const CAPS: usize>(process: &Process<CAPS>) -> Result<ObjectId, Error> {
    if process.personality() != Personality::Linux {
        return Err(Error::WrongPersonality);
    }
    if process.state() != ProcessState::Live {
        return Err(Error::ProcessExited);
    }
    Ok(process.id())
}

fn exact_bound_thread<const ID_PROCESSES: usize, const ID_THREADS: usize, const CAPS: usize>(
    identities: &LinuxIdentityTable<ID_PROCESSES, ID_THREADS>,
    process: &Process<CAPS>,
    thread: GlobalThreadId,
) -> Result<ObjectId, Error> {
    let process_id = live_linux_process(process)?;
    identities.bound_tid_for_scheduler_thread(process, thread)?;
    Ok(process_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_object::ObjectTable;
    use kernal_percpu::CpuIndex;
    use kernal_process::ThreadObjectBindings;
    use kernal_scheduler::RunQueue;

    const CPU0: CpuIndex = CpuIndex(0);

    fn signal(number: u8) -> Signal {
        Signal::new(number).unwrap()
    }

    fn one_thread_fixture() -> (
        ObjectTable<8>,
        Process<8>,
        ThreadObjectBindings<2>,
        RunQueue<2>,
        LinuxIdentityTable<2, 2>,
        GlobalThreadId,
    ) {
        let mut objects = ObjectTable::<8>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut bindings = ThreadObjectBindings::<2>::new();
        let mut scheduler = RunQueue::<2>::new();
        let local = scheduler.create(10).unwrap();
        let thread = GlobalThreadId::new(CPU0, local);
        let handle = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, thread)
            .unwrap();
        let mut identities = LinuxIdentityTable::<2, 2>::new();
        identities
            .bind_leader(&process, &objects, &bindings, &scheduler, CPU0, handle)
            .unwrap();
        (objects, process, bindings, scheduler, identities, thread)
    }

    #[test]
    fn default_and_ignore_actions_roundtrip_full_linux_metadata() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut table = SignalTable::<2, 8, 2>::new();
        table.bind_process(&process).unwrap();
        table
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        let sig = signal(2);
        let mask = SignalSet::from_bits(1 << (12 - 1));
        let ignore = SignalAction::new(Disposition::Ignore, SA_RESTART, None, mask).unwrap();
        assert_eq!(
            table.set_action(&process, sig, ignore).unwrap(),
            SignalAction::linux_default()
        );
        assert_eq!(table.action(&process, sig).unwrap(), ignore);

        let default = SignalAction::new(Disposition::Default, SA_RESTART, None, mask).unwrap();
        assert_eq!(table.set_action(&process, sig, default).unwrap(), ignore);
        assert_eq!(table.action(&process, sig).unwrap(), default);
    }

    #[test]
    fn pending_queue_uses_linux_signal_number_priority_and_equal_rt_fifo() {
        let mut pending = PendingQueue::<8>::new();
        pending.queue(signal(40)).unwrap();
        pending.queue(signal(35)).unwrap();
        pending.queue(signal(10)).unwrap();
        pending.queue(signal(35)).unwrap();
        let (index, delivered) = pending.next_deliverable(SignalSet::empty()).unwrap();
        assert_eq!(delivered, signal(10));
        pending.take(index);
        let (index, delivered) = pending.next_deliverable(SignalSet::empty()).unwrap();
        assert_eq!(delivered, signal(35));
        pending.take(index);
        let (_, delivered) = pending.next_deliverable(SignalSet::empty()).unwrap();
        assert_eq!(delivered, signal(35));
    }

    #[test]
    fn standard_coalescing_preserves_first_pending_provenance() {
        let mut pending = PendingQueue::<4>::new();
        let first = SignalProvenance::User {
            sender_pid: NonZeroU32::new(12).unwrap(),
            sender_uid: 1000,
        };
        let second = SignalProvenance::User {
            sender_pid: NonZeroU32::new(13).unwrap(),
            sender_uid: 2000,
        };
        pending.queue_with_provenance(signal(10), first).unwrap();
        pending.queue_with_provenance(signal(10), second).unwrap();
        assert_eq!(pending.count(), 1);
        assert_eq!(
            pending
                .next_deliverable_entry(SignalSet::empty())
                .unwrap()
                .1
                .provenance,
            first
        );
    }

    #[test]
    fn prepare_without_commit_preserves_pending_mask_and_disposition() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        let handler = SignalHandler::new(0x4000, None, SA_RESETHAND, SignalSet::empty()).unwrap();
        signals
            .set_disposition(&process, signal(10), Disposition::Handler(handler))
            .unwrap();
        signals.queue_signal(&process, signal(10)).unwrap();
        let before_pending = signals.pending_count(&process).unwrap();
        let before_mask = signals.thread_mask(&identities, &process, thread).unwrap();
        let before_disposition = signals.disposition(&process, signal(10)).unwrap();
        let prepared = signals
            .prepare_delivery_for_thread(&identities, &process, thread)
            .unwrap()
            .unwrap();
        assert!(matches!(
            prepared.delivery(),
            Delivery::Handler { signal: delivered, .. } if delivered == signal(10)
        ));
        assert_eq!(signals.pending_count(&process).unwrap(), before_pending);
        assert_eq!(
            signals.thread_mask(&identities, &process, thread).unwrap(),
            before_mask
        );
        assert_eq!(
            signals.disposition(&process, signal(10)).unwrap(),
            before_disposition
        );
    }

    #[test]
    fn equal_rt_serial_commit_consumes_only_prepared_instance() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        let first = SignalProvenance::User {
            sender_pid: NonZeroU32::new(21).unwrap(),
            sender_uid: 1,
        };
        let second = SignalProvenance::User {
            sender_pid: NonZeroU32::new(22).unwrap(),
            sender_uid: 2,
        };
        signals
            .queue_signal_with_provenance(&process, signal(35), first)
            .unwrap();
        let prepared = signals
            .prepare_delivery_for_thread(&identities, &process, thread)
            .unwrap()
            .unwrap();
        signals
            .queue_signal_with_provenance(&process, signal(35), second)
            .unwrap();
        signals
            .commit_prepared_delivery(&identities, &process, thread, prepared)
            .unwrap();
        assert_eq!(signals.pending_count(&process).unwrap(), 1);
        assert_eq!(
            signals
                .prepare_delivery_for_thread(&identities, &process, thread)
                .unwrap()
                .unwrap()
                .provenance(),
            second
        );
    }

    #[test]
    fn default_ignored_disposition_uses_the_same_discard_policy() {
        assert!(should_discard(Disposition::Default, signal(SIGCHLD)));
        assert!(should_discard(Disposition::Default, signal(23)));
        assert!(should_discard(Disposition::Default, signal(28)));
        assert!(!should_discard(Disposition::Default, signal(10)));
    }

    #[test]
    fn ignored_signal_discards_existing_process_and_thread_pending_state() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        signals.queue_signal(&process, signal(10)).unwrap();
        signals
            .queue_thread_signal(&identities, &process, thread, signal(10))
            .unwrap();
        signals
            .set_disposition(&process, signal(10), Disposition::Ignore)
            .unwrap();
        assert_eq!(signals.pending_count(&process).unwrap(), 0);
        assert_eq!(
            signals
                .thread_pending_count(&identities, &process, thread)
                .unwrap(),
            0
        );
    }

    #[test]
    fn reset_handler_default_ignore_persists_residual_pending_discard() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        let sigchld = signal(SIGCHLD);
        let handler = SignalHandler::new(0x4000, None, SA_RESETHAND, SignalSet::empty()).unwrap();
        signals
            .set_disposition(&process, sigchld, Disposition::Handler(handler))
            .unwrap();
        signals.queue_signal(&process, sigchld).unwrap();
        signals
            .queue_thread_signal(&identities, &process, thread, sigchld)
            .unwrap();
        assert!(matches!(
            signals
                .next_delivery_for_thread(&identities, &process, thread)
                .unwrap(),
            Some(Delivery::Handler { signal: delivered, .. }) if delivered == sigchld
        ));
        assert_eq!(
            signals.disposition(&process, sigchld).unwrap(),
            Disposition::Default
        );
        assert_eq!(signals.pending_count(&process).unwrap(), 1);
        assert_eq!(
            signals
                .thread_pending_count(&identities, &process, thread)
                .unwrap(),
            0
        );
        assert_eq!(
            signals
                .next_delivery_for_thread(&identities, &process, thread)
                .unwrap(),
            None
        );
        assert_eq!(signals.pending_count(&process).unwrap(), 0);
        assert_eq!(
            signals
                .thread_pending_count(&identities, &process, thread)
                .unwrap(),
            0
        );
    }

    #[test]
    fn ignored_sigcont_clears_process_and_thread_pending_stop_signals() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        signals.queue_signal(&process, signal(SIGSTOP)).unwrap();
        signals
            .queue_thread_signal(&identities, &process, thread, signal(SIGTSTP))
            .unwrap();
        signals
            .set_disposition(&process, signal(SIGCONT), Disposition::Ignore)
            .unwrap();
        signals.queue_signal(&process, signal(SIGCONT)).unwrap();
        assert_eq!(signals.pending_count(&process).unwrap(), 0);
        assert_eq!(
            signals
                .thread_pending_count(&identities, &process, thread)
                .unwrap(),
            0
        );
    }

    #[test]
    fn ignored_stop_generation_clears_process_and_thread_pending_sigcont() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        signals.queue_signal(&process, signal(SIGCONT)).unwrap();
        signals
            .queue_thread_signal(&identities, &process, thread, signal(SIGCONT))
            .unwrap();
        signals
            .set_disposition(&process, signal(SIGTSTP), Disposition::Ignore)
            .unwrap();
        signals
            .queue_thread_signal(&identities, &process, thread, signal(SIGTSTP))
            .unwrap();
        assert_eq!(signals.pending_count(&process).unwrap(), 0);
        assert_eq!(
            signals
                .thread_pending_count(&identities, &process, thread)
                .unwrap(),
            0
        );
    }

    #[test]
    fn caught_stop_generation_clears_pending_sigcont_before_queueing_stop() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        signals.queue_signal(&process, signal(SIGCONT)).unwrap();
        signals
            .queue_thread_signal(&identities, &process, thread, signal(SIGCONT))
            .unwrap();
        let handler = SignalHandler::new(0x5000, None, 0, SignalSet::empty()).unwrap();
        signals
            .set_disposition(&process, signal(SIGTSTP), Disposition::Handler(handler))
            .unwrap();
        signals.queue_signal(&process, signal(SIGTSTP)).unwrap();
        assert_eq!(signals.pending_count(&process).unwrap(), 1);
        assert_eq!(
            signals
                .thread_pending_count(&identities, &process, thread)
                .unwrap(),
            0
        );
        assert!(matches!(
            signals
                .next_delivery_for_thread(&identities, &process, thread)
                .unwrap(),
            Some(Delivery::Handler { signal: delivered, .. }) if delivered == signal(SIGTSTP)
        ));
    }

    #[test]
    fn job_control_preflight_allows_opposite_signal_to_free_target_slot() {
        let mut pending = PendingQueue::<1>::new();
        pending.queue(signal(SIGSTOP)).unwrap();
        assert_eq!(
            pending.preflight_queue_after_job_control_cancellation(signal(SIGCONT)),
            Ok(())
        );
    }

    #[test]
    fn job_control_cancelled_numbers_are_owned_values() {
        let (cancelled, len) = job_control_cancelled_numbers(signal(SIGCONT));
        assert_eq!(&cancelled[..len], &[SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU]);

        let (cancelled, len) = job_control_cancelled_numbers(signal(SIGTSTP));
        assert_eq!(&cancelled[..len], &[SIGCONT]);

        let (cancelled, len) = job_control_cancelled_numbers(signal(2));
        assert_eq!(len, 0);
        assert_eq!(cancelled, [0; 4]);
    }

    #[test]
    fn two_threads_have_independent_masks_and_process_pending_selects_unblocked_thread() {
        let mut objects = ObjectTable::<10>::new();
        let mut process = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let mut bindings = ThreadObjectBindings::<4>::new();
        let mut scheduler = RunQueue::<4>::new();
        let leader_local = scheduler.create(10).unwrap();
        let worker_local = scheduler.create(10).unwrap();
        let leader = GlobalThreadId::new(CPU0, leader_local);
        let worker = GlobalThreadId::new(CPU0, worker_local);
        let leader_handle = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, leader)
            .unwrap();
        let worker_handle = process
            .attach_thread(&mut objects, &mut bindings, &scheduler, CPU0, worker)
            .unwrap();
        let mut identities = LinuxIdentityTable::<2, 4>::new();
        identities
            .bind_leader(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                leader_handle,
            )
            .unwrap();
        identities
            .tid_for(
                &process,
                &objects,
                &bindings,
                &scheduler,
                CPU0,
                worker_handle,
            )
            .unwrap();
        let mut signals = SignalTable::<2, 8, 4>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, leader, SignalSet::empty())
            .unwrap();
        signals
            .bind_thread(&identities, &process, worker, SignalSet::empty())
            .unwrap();
        signals
            .update_thread_mask(
                &identities,
                &process,
                leader,
                MaskHow::Block,
                SignalSet::empty().with(signal(10)),
            )
            .unwrap();
        signals.queue_signal(&process, signal(10)).unwrap();
        assert_eq!(
            signals
                .next_delivery_for_thread(&identities, &process, leader)
                .unwrap(),
            None
        );
        assert!(matches!(
            signals
                .next_delivery_for_thread(&identities, &process, worker)
                .unwrap(),
            Some(Delivery::Default { signal: delivered, .. }) if delivered == signal(10)
        ));
        assert!(
            signals
                .thread_mask(&identities, &process, leader)
                .unwrap()
                .contains(signal(10))
        );
        assert!(
            !signals
                .thread_mask(&identities, &process, worker)
                .unwrap()
                .contains(signal(10))
        );
        signals
            .queue_thread_signal(&identities, &process, leader, signal(12))
            .unwrap();
        assert_eq!(
            signals
                .next_delivery_for_thread(&identities, &process, worker)
                .unwrap(),
            None
        );
        assert_eq!(
            signals
                .thread_pending_count(&identities, &process, leader)
                .unwrap(),
            1
        );
    }

    #[test]
    fn kill_and_stop_are_unmaskable_and_uncatchable() {
        let requested = SignalSet::empty()
            .with(signal(2))
            .with(signal(SIGKILL))
            .with(signal(SIGSTOP));
        assert!(requested.contains(signal(2)));
        assert!(!requested.contains(signal(SIGKILL)));
        assert!(!requested.contains(signal(SIGSTOP)));
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut signals = SignalTable::<2, 4>::new();
        signals.bind_process(&process).unwrap();
        assert_eq!(
            signals.set_disposition(&process, signal(SIGKILL), Disposition::Ignore),
            Err(Error::UncatchableSignal)
        );
        assert_eq!(
            signals.set_disposition(&process, signal(SIGSTOP), Disposition::Ignore),
            Err(Error::UncatchableSignal)
        );
    }

    #[test]
    fn standard_process_pending_coalesces_while_realtime_queues_individually() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut signals = SignalTable::<2, 4>::new();
        signals.bind_process(&process).unwrap();
        signals.queue_signal(&process, signal(10)).unwrap();
        signals.queue_signal(&process, signal(10)).unwrap();
        signals.queue_signal(&process, signal(35)).unwrap();
        signals.queue_signal(&process, signal(35)).unwrap();
        assert_eq!(signals.pending_count(&process).unwrap(), 3);
    }

    #[test]
    fn handler_delivery_changes_only_target_thread_mask_and_resets_process_handler() {
        let (_objects, process, _bindings, _scheduler, identities, thread) = one_thread_fixture();
        let mut signals = SignalTable::<2, 8, 2>::new();
        signals.bind_process(&process).unwrap();
        signals
            .bind_thread(&identities, &process, thread, SignalSet::empty())
            .unwrap();
        let handler = SignalHandler::new(
            0x4000,
            None,
            SA_RESETHAND,
            SignalSet::empty().with(signal(12)),
        )
        .unwrap();
        signals
            .set_disposition(&process, signal(10), Disposition::Handler(handler))
            .unwrap();
        signals
            .queue_thread_signal(&identities, &process, thread, signal(10))
            .unwrap();
        let delivery = signals
            .next_delivery_for_thread(&identities, &process, thread)
            .unwrap()
            .unwrap();
        let Delivery::Handler {
            signal: delivered,
            previous_mask,
            effective_mask,
            ..
        } = delivery
        else {
            panic!("expected handler delivery");
        };
        assert_eq!(delivered, signal(10));
        assert_eq!(previous_mask, SignalSet::empty());
        assert!(effective_mask.contains(signal(10)));
        assert!(effective_mask.contains(signal(12)));
        assert_eq!(
            signals.disposition(&process, signal(10)).unwrap(),
            Disposition::Default
        );
    }

    #[test]
    fn exec_resets_caught_handlers_but_preserves_ignore_and_process_pending() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut signals = SignalTable::<2, 8>::new();
        signals.bind_process(&process).unwrap();
        let handler = SignalHandler::new(0x5000, None, 0, SignalSet::empty()).unwrap();
        signals
            .set_disposition(&process, signal(10), Disposition::Handler(handler))
            .unwrap();
        signals
            .set_disposition(&process, signal(15), Disposition::Ignore)
            .unwrap();
        signals.queue_signal(&process, signal(2)).unwrap();
        signals.reset_caught_handlers_for_exec(&process).unwrap();
        assert_eq!(
            signals.disposition(&process, signal(10)).unwrap(),
            Disposition::Default
        );
        assert_eq!(
            signals.disposition(&process, signal(15)).unwrap(),
            Disposition::Ignore
        );
        assert_eq!(signals.pending_count(&process).unwrap(), 1);
    }

    #[test]
    fn exited_generation_retires_process_and_residual_thread_state() {
        let mut objects = ObjectTable::<4>::new();
        let mut process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut signals = SignalTable::<2, 4>::new();
        signals.bind_process(&process).unwrap();
        let bindings = ThreadObjectBindings::<0>::new();
        process.exit(&mut objects, &bindings).unwrap();
        signals.retire_process(&process).unwrap();
        assert_eq!(signals.process_record(process.id()), None);
    }

    #[test]
    fn default_actions_cover_shell_relevant_stop_continue_and_termination() {
        assert_eq!(default_action(signal(SIGCONT)), DefaultAction::Continue);
        assert_eq!(default_action(signal(SIGSTOP)), DefaultAction::Stop);
        assert_eq!(default_action(signal(SIGCHLD)), DefaultAction::Ignore);
        assert_eq!(
            default_action(signal(11)),
            DefaultAction::Terminate { core_dump: true }
        );
        assert_eq!(
            default_action(signal(15)),
            DefaultAction::Terminate { core_dump: false }
        );
    }
}
