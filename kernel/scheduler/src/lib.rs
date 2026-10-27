// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const PRIORITY_LEVELS: usize = 64;
const NONE: u16 = u16::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadId {
    pub slot: u16,
    pub generation: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadState {
    Free,
    Ready,
    Running,
    Blocked,
    /// Execution has ended, but stack/context resources still belong to this generation.
    Exited,
}

/// Result of placing one exact scheduler generation under the orthogonal job-control stop hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobControlStopOutcome {
    /// This exact generation was already stopped. No queue state changed.
    AlreadyStopped,
    /// The generation is now held and was not Running at the linearization point.
    Held,
    /// The generation was Running and has been descheduled into a held Ready state. The caller must
    /// complete the normal context-switch boundary before returning to userspace.
    Deschedule,
}

/// Result of clearing one exact scheduler generation's job-control stop hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobControlContinueOutcome {
    /// This exact generation did not carry a stop hold. No scheduler state changed.
    NotStopped,
    /// The hold cleared but no real wake had occurred while stopped, so the underlying state remains
    /// non-runnable (for example a genuinely Blocked futex/wait thread).
    Continued,
    /// The thread was runnable before Stop, or a real wake arrived while stopped, and is now queued.
    Readied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    InvalidThread,
    InvalidPriority,
    InvalidState,
    QueueCorrupt,
}

#[derive(Clone, Copy)]
struct ThreadSlot {
    generation: u16,
    state: ThreadState,
    priority: u8,
    next: u16,
    queued: bool,
    /// Orthogonal POSIX/Linux job-control hold. This never substitutes for the base scheduler state.
    job_control_stopped: bool,
    /// A real wake arrived while a Blocked generation was stopped. The base state remains Blocked
    /// until Continue consumes this bit and publishes Ready exactly once.
    deferred_ready: bool,
}

impl ThreadSlot {
    const EMPTY: Self = Self {
        generation: 1,
        state: ThreadState::Free,
        priority: 0,
        next: NONE,
        queued: false,
        job_control_stopped: false,
        deferred_ready: false,
    };
}

/// Fixed-capacity, allocation-free priority scheduler core.
///
/// Priority 63 is highest and priority 0 is lowest. Each priority level is FIFO.
/// The structure intentionally contains no locks; callers embed one queue per CPU and
/// synchronize migration separately, avoiding a mandatory global scheduler lock.
///
/// Thread destruction is intentionally two-phase. `exit()` moves a thread to `Exited` while its
/// generation remains valid so the owner can tear down context/stack resources. Only `reap()`
/// advances the generation and returns the slot to `Free`. This prevents a new thread from
/// inheriting a virtual stack slot whose old mappings still exist.
///
/// Job-control Stop/Continue is orthogonal to [`ThreadState`]. Stopping a Blocked generation leaves
/// it Blocked. A wake received under the hold records `deferred_ready` without enqueuing; Continue
/// enqueues only when that real wake exists. Thus SIGCONT can never manufacture a futex/wait wake.
pub struct RunQueue<const N: usize> {
    slots: [ThreadSlot; N],
    heads: [u16; PRIORITY_LEVELS],
    tails: [u16; PRIORITY_LEVELS],
    ready_bitmap: u64,
}

impl<const N: usize> Default for RunQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RunQueue<N> {
    pub const fn new() -> Self {
        Self {
            slots: [ThreadSlot::EMPTY; N],
            heads: [NONE; PRIORITY_LEVELS],
            tails: [NONE; PRIORITY_LEVELS],
            ready_bitmap: 0,
        }
    }

    pub fn create(&mut self, priority: u8) -> Result<ThreadId, Error> {
        if priority as usize >= PRIORITY_LEVELS {
            return Err(Error::InvalidPriority);
        }
        if N > NONE as usize {
            return Err(Error::Capacity);
        }
        for (slot, entry) in self.slots.iter_mut().enumerate() {
            // Exited slots are deliberately unavailable until resources are torn down and reap()
            // moves the slot to Free with a new generation.
            if entry.state == ThreadState::Free {
                entry.state = ThreadState::Blocked;
                entry.priority = priority;
                entry.next = NONE;
                entry.queued = false;
                entry.job_control_stopped = false;
                entry.deferred_ready = false;
                return Ok(ThreadId {
                    slot: slot as u16,
                    generation: entry.generation,
                });
            }
        }
        Err(Error::Capacity)
    }

    pub fn make_ready(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.validate_generation(id)?;
        if self.slots[slot].job_control_stopped {
            return match self.slots[slot].state {
                ThreadState::Blocked => {
                    // Preserve the real Blocked reason while remembering that a genuine wake won.
                    self.slots[slot].deferred_ready = true;
                    Ok(())
                }
                ThreadState::Ready if !self.slots[slot].queued => {
                    // It was already runnable before Stop; Continue will re-publish it once.
                    Ok(())
                }
                ThreadState::Ready | ThreadState::Running => Err(Error::QueueCorrupt),
                ThreadState::Free | ThreadState::Exited => Err(Error::InvalidState),
            };
        }
        match self.slots[slot].state {
            ThreadState::Blocked | ThreadState::Running => {}
            ThreadState::Ready if self.slots[slot].queued => return Ok(()),
            _ => return Err(Error::InvalidState),
        }
        let previous_state = self.slots[slot].state;
        self.slots[slot].state = ThreadState::Ready;
        if let Err(error) = self.enqueue(slot) {
            self.slots[slot].state = previous_state;
            return Err(error);
        }
        Ok(())
    }

    pub fn block(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.validate_generation(id)?;
        if self.slots[slot].job_control_stopped {
            return Err(Error::InvalidState);
        }
        match self.slots[slot].state {
            ThreadState::Running => {
                self.slots[slot].state = ThreadState::Blocked;
                Ok(())
            }
            ThreadState::Ready => {
                self.remove_from_ready(slot)?;
                self.slots[slot].state = ThreadState::Blocked;
                Ok(())
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// Applies an orthogonal generation-bound job-control stop hold.
    ///
    /// Ready generations are removed from the run queue but remain logically Ready. Running
    /// generations transition to held Ready and return `Deschedule` so the CPU owner can perform the
    /// existing context switch. Blocked generations remain Blocked. No wake reason is created.
    pub fn job_control_stop(&mut self, id: ThreadId) -> Result<JobControlStopOutcome, Error> {
        let slot = self.validate_generation(id)?;
        if self.slots[slot].job_control_stopped {
            return Ok(JobControlStopOutcome::AlreadyStopped);
        }
        match self.slots[slot].state {
            ThreadState::Ready => {
                if !self.slots[slot].queued {
                    return Err(Error::QueueCorrupt);
                }
                self.remove_from_ready(slot)?;
                self.slots[slot].job_control_stopped = true;
                self.slots[slot].deferred_ready = false;
                Ok(JobControlStopOutcome::Held)
            }
            ThreadState::Running => {
                if self.slots[slot].queued {
                    return Err(Error::QueueCorrupt);
                }
                self.slots[slot].state = ThreadState::Ready;
                self.slots[slot].job_control_stopped = true;
                self.slots[slot].deferred_ready = false;
                Ok(JobControlStopOutcome::Deschedule)
            }
            ThreadState::Blocked => {
                if self.slots[slot].queued {
                    return Err(Error::QueueCorrupt);
                }
                self.slots[slot].job_control_stopped = true;
                self.slots[slot].deferred_ready = false;
                Ok(JobControlStopOutcome::Held)
            }
            ThreadState::Free | ThreadState::Exited => Err(Error::InvalidState),
        }
    }

    /// Clears the job-control hold without manufacturing readiness.
    ///
    /// A held Ready generation is re-enqueued because it was runnable before Stop. A held Blocked
    /// generation is re-enqueued only when `make_ready` recorded a genuine wake while stopped;
    /// otherwise it remains Blocked after Continue.
    pub fn job_control_continue(
        &mut self,
        id: ThreadId,
    ) -> Result<JobControlContinueOutcome, Error> {
        let slot = self.validate_generation(id)?;
        if !self.slots[slot].job_control_stopped {
            return Ok(JobControlContinueOutcome::NotStopped);
        }
        match self.slots[slot].state {
            ThreadState::Ready => {
                if self.slots[slot].queued || self.slots[slot].deferred_ready {
                    return Err(Error::QueueCorrupt);
                }
                self.slots[slot].job_control_stopped = false;
                if let Err(error) = self.enqueue(slot) {
                    self.slots[slot].job_control_stopped = true;
                    return Err(error);
                }
                Ok(JobControlContinueOutcome::Readied)
            }
            ThreadState::Blocked if self.slots[slot].deferred_ready => {
                self.slots[slot].state = ThreadState::Ready;
                self.slots[slot].job_control_stopped = false;
                self.slots[slot].deferred_ready = false;
                if let Err(error) = self.enqueue(slot) {
                    self.slots[slot].state = ThreadState::Blocked;
                    self.slots[slot].job_control_stopped = true;
                    self.slots[slot].deferred_ready = true;
                    return Err(error);
                }
                Ok(JobControlContinueOutcome::Readied)
            }
            ThreadState::Blocked => {
                self.slots[slot].job_control_stopped = false;
                Ok(JobControlContinueOutcome::Continued)
            }
            ThreadState::Running => Err(Error::QueueCorrupt),
            ThreadState::Free | ThreadState::Exited => Err(Error::InvalidState),
        }
    }

    pub fn job_control_stopped(&self, id: ThreadId) -> Result<bool, Error> {
        Ok(self.slots[self.validate_generation(id)?].job_control_stopped)
    }

    /// Marks execution finished but deliberately keeps the generation valid.
    pub fn exit(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.validate_generation(id)?;
        if self.slots[slot].state == ThreadState::Ready {
            if self.slots[slot].queued {
                self.remove_from_ready(slot)?;
            } else if !self.slots[slot].job_control_stopped {
                return Err(Error::QueueCorrupt);
            }
        }
        if matches!(
            self.slots[slot].state,
            ThreadState::Free | ThreadState::Exited
        ) {
            return Err(Error::InvalidState);
        }
        let entry = &mut self.slots[slot];
        entry.state = ThreadState::Exited;
        entry.next = NONE;
        entry.queued = false;
        entry.job_control_stopped = false;
        entry.deferred_ready = false;
        Ok(())
    }

    /// Returns an exited slot to the allocator after all external resources are destroyed.
    ///
    /// This is the only lifecycle transition that advances the generation.
    pub fn reap(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.validate_generation(id)?;
        let entry = &mut self.slots[slot];
        if entry.state != ThreadState::Exited
            || entry.queued
            || entry.job_control_stopped
            || entry.deferred_ready
        {
            return Err(Error::InvalidState);
        }
        entry.generation = next_generation(entry.generation);
        entry.state = ThreadState::Free;
        entry.priority = 0;
        entry.next = NONE;
        entry.queued = false;
        entry.job_control_stopped = false;
        entry.deferred_ready = false;
        Ok(())
    }

    pub fn schedule(&mut self) -> Result<Option<ThreadId>, Error> {
        if self.ready_bitmap == 0 {
            return Ok(None);
        }
        let priority = 63usize - self.ready_bitmap.leading_zeros() as usize;
        let slot = self.dequeue_head(priority)?;
        let entry = &mut self.slots[slot];
        if entry.state != ThreadState::Ready || entry.job_control_stopped || entry.deferred_ready {
            return Err(Error::QueueCorrupt);
        }
        entry.state = ThreadState::Running;
        Ok(Some(ThreadId {
            slot: slot as u16,
            generation: entry.generation,
        }))
    }

    pub fn yield_running(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.validate_generation(id)?;
        if self.slots[slot].state != ThreadState::Running || self.slots[slot].job_control_stopped {
            return Err(Error::InvalidState);
        }
        self.slots[slot].state = ThreadState::Ready;
        if let Err(error) = self.enqueue(slot) {
            self.slots[slot].state = ThreadState::Running;
            return Err(error);
        }
        Ok(())
    }

    pub fn state(&self, id: ThreadId) -> Result<ThreadState, Error> {
        Ok(self.slots[self.validate_generation(id)?].state)
    }

    pub const fn ready_bitmap(&self) -> u64 {
        self.ready_bitmap
    }

    fn validate_generation(&self, id: ThreadId) -> Result<usize, Error> {
        let slot = id.slot as usize;
        let entry = self.slots.get(slot).ok_or(Error::InvalidThread)?;
        if entry.generation != id.generation || entry.state == ThreadState::Free {
            return Err(Error::InvalidThread);
        }
        Ok(slot)
    }

    fn enqueue(&mut self, slot: usize) -> Result<(), Error> {
        if self.slots[slot].queued
            || self.slots[slot].job_control_stopped
            || self.slots[slot].deferred_ready
        {
            return Err(Error::QueueCorrupt);
        }
        let priority = self.slots[slot].priority as usize;
        self.slots[slot].next = NONE;
        let tail = self.tails[priority];
        if tail == NONE {
            if self.heads[priority] != NONE {
                return Err(Error::QueueCorrupt);
            }
            self.heads[priority] = slot as u16;
        } else {
            let tail = tail as usize;
            if tail >= N || !self.slots[tail].queued {
                return Err(Error::QueueCorrupt);
            }
            self.slots[tail].next = slot as u16;
        }
        self.tails[priority] = slot as u16;
        self.slots[slot].queued = true;
        self.ready_bitmap |= 1u64 << priority;
        Ok(())
    }

    fn dequeue_head(&mut self, priority: usize) -> Result<usize, Error> {
        let head = self.heads[priority];
        if head == NONE {
            return Err(Error::QueueCorrupt);
        }
        let slot = head as usize;
        if slot >= N || !self.slots[slot].queued {
            return Err(Error::QueueCorrupt);
        }
        let next = self.slots[slot].next;
        self.heads[priority] = next;
        if next == NONE {
            self.tails[priority] = NONE;
            self.ready_bitmap &= !(1u64 << priority);
        }
        self.slots[slot].next = NONE;
        self.slots[slot].queued = false;
        Ok(slot)
    }

    fn remove_from_ready(&mut self, slot: usize) -> Result<(), Error> {
        if !self.slots[slot].queued {
            return Err(Error::QueueCorrupt);
        }
        let priority = self.slots[slot].priority as usize;
        let mut cursor = self.heads[priority];
        let mut previous = NONE;
        while cursor != NONE {
            let current = cursor as usize;
            if current >= N {
                return Err(Error::QueueCorrupt);
            }
            if current == slot {
                let next = self.slots[current].next;
                if previous == NONE {
                    self.heads[priority] = next;
                } else {
                    self.slots[previous as usize].next = next;
                }
                if self.tails[priority] == cursor {
                    self.tails[priority] = previous;
                }
                if self.heads[priority] == NONE {
                    self.tails[priority] = NONE;
                    self.ready_bitmap &= !(1u64 << priority);
                }
                self.slots[current].next = NONE;
                self.slots[current].queued = false;
                return Ok(());
            }
            previous = cursor;
            cursor = self.slots[current].next;
        }
        Err(Error::QueueCorrupt)
    }
}

const fn next_generation(current: u16) -> u16 {
    let next = current.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_priority_runs_first_and_fifo_within_priority() {
        let mut q = RunQueue::<8>::new();
        let low = q.create(2).unwrap();
        let high_a = q.create(40).unwrap();
        let high_b = q.create(40).unwrap();
        q.make_ready(low).unwrap();
        q.make_ready(high_a).unwrap();
        q.make_ready(high_b).unwrap();
        assert_eq!(q.schedule().unwrap(), Some(high_a));
        assert_eq!(q.schedule().unwrap(), Some(high_b));
        assert_eq!(q.schedule().unwrap(), Some(low));
    }

    #[test]
    fn yield_requeues_at_tail() {
        let mut q = RunQueue::<4>::new();
        let a = q.create(10).unwrap();
        let b = q.create(10).unwrap();
        q.make_ready(a).unwrap();
        q.make_ready(b).unwrap();
        let first = q.schedule().unwrap().unwrap();
        assert_eq!(first, a);
        q.yield_running(first).unwrap();
        assert_eq!(q.schedule().unwrap(), Some(b));
        assert_eq!(q.schedule().unwrap(), Some(a));
    }

    #[test]
    fn block_removes_ready_thread() {
        let mut q = RunQueue::<4>::new();
        let a = q.create(8).unwrap();
        let b = q.create(8).unwrap();
        q.make_ready(a).unwrap();
        q.make_ready(b).unwrap();
        q.block(a).unwrap();
        assert_eq!(q.schedule().unwrap(), Some(b));
        assert_eq!(q.schedule().unwrap(), None);
    }

    #[test]
    fn stopped_blocked_thread_remains_blocked_without_real_wake() {
        let mut q = RunQueue::<2>::new();
        let id = q.create(5).unwrap();
        assert_eq!(q.state(id), Ok(ThreadState::Blocked));
        assert_eq!(q.job_control_stop(id), Ok(JobControlStopOutcome::Held));
        assert_eq!(q.job_control_stopped(id), Ok(true));
        assert_eq!(
            q.job_control_continue(id),
            Ok(JobControlContinueOutcome::Continued)
        );
        assert_eq!(q.state(id), Ok(ThreadState::Blocked));
        assert_eq!(q.job_control_stopped(id), Ok(false));
        assert_eq!(q.schedule().unwrap(), None);
    }

    #[test]
    fn wake_while_stopped_is_deferred_until_continue() {
        let mut q = RunQueue::<2>::new();
        let id = q.create(5).unwrap();
        q.job_control_stop(id).unwrap();
        q.make_ready(id).unwrap();
        assert_eq!(q.state(id), Ok(ThreadState::Blocked));
        assert_eq!(q.schedule().unwrap(), None);
        assert_eq!(
            q.job_control_continue(id),
            Ok(JobControlContinueOutcome::Readied)
        );
        assert_eq!(q.state(id), Ok(ThreadState::Ready));
        assert_eq!(q.schedule().unwrap(), Some(id));
    }

    #[test]
    fn stopping_ready_thread_removes_it_until_continue() {
        let mut q = RunQueue::<3>::new();
        let stopped = q.create(6).unwrap();
        let other = q.create(6).unwrap();
        q.make_ready(stopped).unwrap();
        q.make_ready(other).unwrap();
        assert_eq!(q.job_control_stop(stopped), Ok(JobControlStopOutcome::Held));
        assert_eq!(q.state(stopped), Ok(ThreadState::Ready));
        assert_eq!(q.schedule().unwrap(), Some(other));
        assert_eq!(q.schedule().unwrap(), None);
        assert_eq!(
            q.job_control_continue(stopped),
            Ok(JobControlContinueOutcome::Readied)
        );
        assert_eq!(q.schedule().unwrap(), Some(stopped));
    }

    #[test]
    fn stopping_running_thread_requests_deschedule_and_continue_requeues() {
        let mut q = RunQueue::<2>::new();
        let id = q.create(7).unwrap();
        q.make_ready(id).unwrap();
        assert_eq!(q.schedule().unwrap(), Some(id));
        assert_eq!(
            q.job_control_stop(id),
            Ok(JobControlStopOutcome::Deschedule)
        );
        assert_eq!(q.state(id), Ok(ThreadState::Ready));
        assert_eq!(q.schedule().unwrap(), None);
        assert_eq!(
            q.job_control_continue(id),
            Ok(JobControlContinueOutcome::Readied)
        );
        assert_eq!(q.schedule().unwrap(), Some(id));
    }

    #[test]
    fn duplicate_stop_and_continue_do_not_duplicate_queue_entries() {
        let mut q = RunQueue::<2>::new();
        let id = q.create(7).unwrap();
        q.make_ready(id).unwrap();
        assert_eq!(q.job_control_stop(id), Ok(JobControlStopOutcome::Held));
        assert_eq!(
            q.job_control_stop(id),
            Ok(JobControlStopOutcome::AlreadyStopped)
        );
        assert_eq!(
            q.job_control_continue(id),
            Ok(JobControlContinueOutcome::Readied)
        );
        assert_eq!(
            q.job_control_continue(id),
            Ok(JobControlContinueOutcome::NotStopped)
        );
        assert_eq!(q.schedule().unwrap(), Some(id));
        assert_eq!(q.schedule().unwrap(), None);
    }

    #[test]
    fn exited_slot_cannot_be_reused_before_reap() {
        let mut q = RunQueue::<1>::new();
        let old = q.create(1).unwrap();
        q.make_ready(old).unwrap();
        let running = q.schedule().unwrap().unwrap();
        q.exit(running).unwrap();
        assert_eq!(q.state(old), Ok(ThreadState::Exited));
        assert_eq!(q.create(1), Err(Error::Capacity));
        q.reap(old).unwrap();
        assert_eq!(q.state(old), Err(Error::InvalidThread));
        let new = q.create(1).unwrap();
        assert_ne!(old.generation, new.generation);
        assert_eq!(q.job_control_stopped(new), Ok(false));
    }

    #[test]
    fn stopped_ready_thread_can_exit_without_requeue() {
        let mut q = RunQueue::<1>::new();
        let id = q.create(1).unwrap();
        q.make_ready(id).unwrap();
        q.job_control_stop(id).unwrap();
        q.exit(id).unwrap();
        assert_eq!(q.state(id), Ok(ThreadState::Exited));
        assert_eq!(q.job_control_stopped(id), Ok(false));
        q.reap(id).unwrap();
    }

    #[test]
    fn reap_rejects_live_threads() {
        let mut q = RunQueue::<1>::new();
        let id = q.create(1).unwrap();
        assert_eq!(q.reap(id), Err(Error::InvalidState));
    }

    #[test]
    fn make_ready_rolls_back_state_when_enqueue_detects_corruption() {
        let mut q = RunQueue::<2>::new();
        let id = q.create(9).unwrap();

        q.heads[9] = id.slot;
        assert_eq!(q.make_ready(id), Err(Error::QueueCorrupt));
        assert_eq!(q.state(id), Ok(ThreadState::Blocked));
        assert!(!q.slots[id.slot as usize].queued);
    }

    #[test]
    fn yield_rolls_back_to_running_when_enqueue_detects_corruption() {
        let mut q = RunQueue::<2>::new();
        let id = q.create(11).unwrap();
        q.make_ready(id).unwrap();
        assert_eq!(q.schedule().unwrap(), Some(id));

        q.heads[11] = id.slot;
        assert_eq!(q.yield_running(id), Err(Error::QueueCorrupt));
        assert_eq!(q.state(id), Ok(ThreadState::Running));
        assert!(!q.slots[id.slot as usize].queued);
    }

    #[test]
    fn duplicate_ready_does_not_duplicate_queue_entry() {
        let mut q = RunQueue::<2>::new();
        let a = q.create(12).unwrap();
        q.make_ready(a).unwrap();
        q.make_ready(a).unwrap();
        assert_eq!(q.schedule().unwrap(), Some(a));
        assert_eq!(q.schedule().unwrap(), None);
    }
}
