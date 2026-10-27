// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};
use kernal_linux_pipe::PipeId;
use kernal_scheduler_smp::GlobalThreadId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Capacity,
    DuplicateWaiter,
    WaiterNotFound,
    InvalidWaiterState,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WaitCommit {
    Sleep,
    AlreadyWoken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InterruptOutcome {
    NotWaiting,
    Retained,
    WakeRequired,
    AlreadyInterrupted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct NotifyReport {
    pub(super) consumed: usize,
    pub(super) runnable: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaiterState {
    Prepared,
    Committed,
    Notified,
    Interrupted,
}

#[derive(Clone, Copy)]
struct Slot {
    pipe: Option<PipeId>,
    thread: Option<GlobalThreadId>,
    state: WaiterState,
}

impl Slot {
    const EMPTY: Self = Self {
        pipe: None,
        thread: None,
        state: WaiterState::Prepared,
    };

    fn occupied(self) -> bool {
        self.pipe.is_some() || self.thread.is_some()
    }
}

/// Bounded wait owner for blocking pipe reads.
///
/// The owner stores only blocking state. `PipeTable` remains the sole pipe-buffer/lifetime owner and
/// `FdTableSet` remains the sole descriptor/OFD owner. A waiter is bound to the exact generation-rich
/// `PipeId` plus the exact scheduler `GlobalThreadId`; no PID/TID scalar becomes authority.
///
/// The state machine mirrors the already-accepted futex lost-wake contract:
/// Prepared -> Committed before scheduler sleep, normal readiness races Prepared -> Notified,
/// signal interruption races Prepared/Committed -> Interrupted, and an Interrupted record cannot be
/// stolen by a later normal pipe wake.
pub(super) struct PipeWaitTable<const WAITERS: usize> {
    slots: [Slot; WAITERS],
    len: usize,
}

impl<const WAITERS: usize> PipeWaitTable<WAITERS> {
    pub(super) const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; WAITERS],
            len: 0,
        }
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }

    pub(super) fn prepare(&mut self, pipe: PipeId, thread: GlobalThreadId) -> Result<(), Error> {
        self.validate()?;
        if self.find_thread(thread).is_some() {
            return Err(Error::DuplicateWaiter);
        }
        if self.len == WAITERS {
            return Err(Error::Capacity);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.occupied())
            .ok_or(Error::Corrupt)?;
        self.slots[index] = Slot {
            pipe: Some(pipe),
            thread: Some(thread),
            state: WaiterState::Prepared,
        };
        self.len += 1;
        Ok(())
    }

    pub(super) fn commit(&mut self, thread: GlobalThreadId) -> Result<WaitCommit, Error> {
        self.validate()?;
        let index = self.find_thread(thread).ok_or(Error::WaiterNotFound)?;
        match self.slots[index].state {
            WaiterState::Prepared => {
                self.slots[index].state = WaiterState::Committed;
                Ok(WaitCommit::Sleep)
            }
            WaiterState::Notified => {
                self.remove(index)?;
                Ok(WaitCommit::AlreadyWoken)
            }
            WaiterState::Interrupted => Ok(WaitCommit::AlreadyWoken),
            WaiterState::Committed => Err(Error::InvalidWaiterState),
        }
    }

    /// Publishes readiness for at most `maximum` waiters of one exact live pipe generation.
    ///
    /// Prepared waiters are marked Notified and consumed later by their owner without a scheduler
    /// wake. Committed waiters are removed and copied to `output` for exact scheduler delivery.
    /// Interrupted waiters are skipped: signal ownership linearized first and cannot be stolen by a
    /// later data/EOF notification.
    pub(super) fn notify(
        &mut self,
        pipe: PipeId,
        maximum: usize,
        output: &mut [GlobalThreadId],
    ) -> Result<NotifyReport, Error> {
        self.validate()?;
        let limit = core::cmp::min(maximum, output.len());
        if limit == 0 {
            return Ok(NotifyReport::default());
        }
        let mut report = NotifyReport::default();
        let mut index = 0usize;
        while index < WAITERS && report.consumed < limit {
            let slot = self.slots[index];
            if slot.pipe != Some(pipe) {
                index += 1;
                continue;
            }
            match slot.state {
                WaiterState::Prepared => {
                    self.slots[index].state = WaiterState::Notified;
                    report.consumed += 1;
                    index += 1;
                }
                WaiterState::Committed => {
                    let thread = slot.thread.ok_or(Error::Corrupt)?;
                    output[report.runnable] = thread;
                    report.runnable += 1;
                    report.consumed += 1;
                    self.remove(index)?;
                    index += 1;
                }
                WaiterState::Notified | WaiterState::Interrupted => {
                    index += 1;
                }
            }
        }
        Ok(report)
    }

    pub(super) fn interrupt(&mut self, thread: GlobalThreadId) -> Result<InterruptOutcome, Error> {
        self.validate()?;
        let Some(index) = self.find_thread(thread) else {
            return Ok(InterruptOutcome::NotWaiting);
        };
        match self.slots[index].state {
            WaiterState::Prepared => {
                self.slots[index].state = WaiterState::Interrupted;
                Ok(InterruptOutcome::Retained)
            }
            WaiterState::Committed => {
                self.slots[index].state = WaiterState::Interrupted;
                Ok(InterruptOutcome::WakeRequired)
            }
            WaiterState::Interrupted => Ok(InterruptOutcome::AlreadyInterrupted),
            WaiterState::Notified => Ok(InterruptOutcome::NotWaiting),
        }
    }

    pub(super) fn interruption_pending(&self, thread: GlobalThreadId) -> Result<bool, Error> {
        self.validate()?;
        Ok(self
            .find_thread(thread)
            .is_some_and(|index| self.slots[index].state == WaiterState::Interrupted))
    }

    pub(super) fn consume_interrupted(&mut self, thread: GlobalThreadId) -> Result<bool, Error> {
        self.validate()?;
        let Some(index) = self.find_thread(thread) else {
            return Ok(false);
        };
        if self.slots[index].state != WaiterState::Interrupted {
            return Ok(false);
        }
        self.remove(index)?;
        Ok(true)
    }

    pub(super) fn cancel(&mut self, thread: GlobalThreadId) -> Result<bool, Error> {
        self.validate()?;
        let Some(index) = self.find_thread(thread) else {
            return Ok(false);
        };
        if self.slots[index].state == WaiterState::Interrupted {
            return Err(Error::InvalidWaiterState);
        }
        self.remove(index)?;
        Ok(true)
    }

    fn find_thread(&self, thread: GlobalThreadId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.thread == Some(thread))
    }

    fn remove(&mut self, index: usize) -> Result<(), Error> {
        let slot = self.slots.get_mut(index).ok_or(Error::Corrupt)?;
        if !slot.occupied() || self.len == 0 {
            return Err(Error::Corrupt);
        }
        *slot = Slot::EMPTY;
        self.len -= 1;
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        let mut occupied = 0usize;
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.pipe.is_some() != slot.thread.is_some() {
                return Err(Error::Corrupt);
            }
            if !slot.occupied() {
                continue;
            }
            occupied += 1;
            let thread = slot.thread.ok_or(Error::Corrupt)?;
            if self.slots[..index]
                .iter()
                .any(|previous| previous.thread == Some(thread))
            {
                return Err(Error::Corrupt);
            }
        }
        if occupied != self.len || self.len > WAITERS {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}

struct SerializedPipeWaitTable<const WAITERS: usize> {
    locked: AtomicBool,
    table: UnsafeCell<PipeWaitTable<WAITERS>>,
}

// SAFETY: all table access is serialized by `locked`; callers must additionally prevent same-CPU
// interrupt/reentrant entry while a method is active so the spin lock cannot self-deadlock.
unsafe impl<const WAITERS: usize> Sync for SerializedPipeWaitTable<WAITERS> {}

impl<const WAITERS: usize> SerializedPipeWaitTable<WAITERS> {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            table: UnsafeCell::new(PipeWaitTable::new()),
        }
    }

    fn lock(&self) -> Guard<'_, WAITERS> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
        Guard { owner: self }
    }
}

struct Guard<'a, const WAITERS: usize> {
    owner: &'a SerializedPipeWaitTable<WAITERS>,
}

impl<const WAITERS: usize> Guard<'_, WAITERS> {
    fn table_mut(&mut self) -> &mut PipeWaitTable<WAITERS> {
        // SAFETY: this guard owns the unique successful lock acquisition.
        unsafe { &mut *self.owner.table.get() }
    }

    fn table(&self) -> &PipeWaitTable<WAITERS> {
        // SAFETY: this guard owns the unique successful lock acquisition.
        unsafe { &*self.owner.table.get() }
    }
}

impl<const WAITERS: usize> Drop for Guard<'_, WAITERS> {
    fn drop(&mut self) {
        self.owner.locked.store(false, Ordering::Release);
    }
}

pub(super) const STEP30_PIPE_WAITERS: usize = super::runtime::STEP15_RUNTIME_THREADS;
static PIPE_WAITS: SerializedPipeWaitTable<STEP30_PIPE_WAITERS> = SerializedPipeWaitTable::new();

/// Publishes one exact Prepared waiter and releases the PipeWait serializer before returning.
///
/// The caller must re-resolve the original FD/OFD and re-observe the same generation-rich `PipeId`
/// after this function returns. Only a later explicit `commit()` may grant scheduler-sleep authority.
pub(super) unsafe fn prepare(pipe: PipeId, thread: GlobalThreadId) -> Result<(), Error> {
    PIPE_WAITS.lock().table_mut().prepare(pipe, thread)
}

/// Commits one previously Prepared exact waiter immediately before the scheduler block edge.
///
/// `AlreadyWoken` means either readiness won while the caller was revalidating the pipe or a retained
/// signal interruption won; the caller must re-observe the relevant canonical owner and must not sleep.
pub(super) unsafe fn commit(thread: GlobalThreadId) -> Result<WaitCommit, Error> {
    PIPE_WAITS.lock().table_mut().commit(thread)
}

/// Compatibility helper for tests/diagnostics that do not cross a readiness revalidation window.
/// Production blocking reads must use `prepare()` -> FD/OFD/Pipe revalidation -> `commit()` instead.
#[allow(dead_code)]
pub(super) unsafe fn prepare_commit(
    pipe: PipeId,
    thread: GlobalThreadId,
) -> Result<WaitCommit, Error> {
    unsafe { prepare(pipe, thread) }?;
    match unsafe { commit(thread) } {
        Ok(commit) => Ok(commit),
        Err(error) => {
            let _ = unsafe { cancel(thread) };
            Err(error)
        }
    }
}

pub(super) unsafe fn cancel(thread: GlobalThreadId) -> Result<bool, Error> {
    PIPE_WAITS.lock().table_mut().cancel(thread)
}

pub(super) unsafe fn notify_one(
    pipe: PipeId,
) -> Result<(NotifyReport, Option<GlobalThreadId>), Error> {
    let mut output = [None; 1];
    let mut exact = [GlobalThreadId::new(
        kernal_percpu::CpuIndex(0),
        kernal_scheduler::ThreadId {
            slot: 0,
            generation: 0,
        },
    ); 1];
    let report = PIPE_WAITS.lock().table_mut().notify(pipe, 1, &mut exact)?;
    if report.runnable == 1 {
        output[0] = Some(exact[0]);
    }
    Ok((report, output[0]))
}

pub(super) unsafe fn notify_all(
    pipe: PipeId,
) -> Result<([Option<GlobalThreadId>; STEP30_PIPE_WAITERS], NotifyReport), Error> {
    let mut exact = [GlobalThreadId::new(
        kernal_percpu::CpuIndex(0),
        kernal_scheduler::ThreadId {
            slot: 0,
            generation: 0,
        },
    ); STEP30_PIPE_WAITERS];
    let mut out = [None; STEP30_PIPE_WAITERS];
    let report = PIPE_WAITS
        .lock()
        .table_mut()
        .notify(pipe, STEP30_PIPE_WAITERS, &mut exact)?;
    for index in 0..report.runnable {
        out[index] = Some(exact[index]);
    }
    Ok((out, report))
}

pub(super) unsafe fn interrupt(thread: GlobalThreadId) -> Result<InterruptOutcome, Error> {
    PIPE_WAITS.lock().table_mut().interrupt(thread)
}

pub(super) unsafe fn interruption_pending(thread: GlobalThreadId) -> Result<bool, Error> {
    PIPE_WAITS.lock().table().interruption_pending(thread)
}

pub(super) unsafe fn consume_interrupted(thread: GlobalThreadId) -> Result<bool, Error> {
    PIPE_WAITS.lock().table_mut().consume_interrupted(thread)
}
