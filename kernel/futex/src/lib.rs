// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

const NONE: u16 = u16::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexKey {
    pub address_space: u64,
    pub user_address: u64,
}

impl FutexKey {
    pub const fn new(address_space: u64, user_address: u64) -> Result<Self, Error> {
        if user_address & 3 != 0 {
            return Err(Error::Unaligned);
        }
        Ok(Self {
            address_space,
            user_address,
        })
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaiterId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    Unaligned,
    DuplicateWaiter,
    WaiterNotFound,
    InvalidWaiterState,
    QueueCorrupt,
}

/// Result of committing a waiter prepared by [`FutexTable::prepare_wait`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitCommit {
    /// No wake raced with preparation. The owner may now transition the exact current scheduler
    /// generation to Blocked before allowing its wake mailbox to drain or local IRQs to reopen.
    Sleep,
    /// A wake or retained signal interruption raced with preparation. The caller must not block.
    AlreadyWoken,
}

/// Exact owner observation returned by [`FutexTable::interrupt_wait`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptWaitOutcome {
    /// No signal-owned wait exists for this identity. The waiter is absent or a normal wake already
    /// owns the prepared wait through `Notified`.
    NotWaiting,
    /// The waiter was only Prepared. The interruption is retained in-record, but the scheduler
    /// generation has not committed to sleeping and therefore must not be woken.
    Retained,
    /// The waiter was Committed and is now retained as Interrupted. The caller owns exactly one
    /// scheduler-wake obligation for this exact generation.
    WakeRequired,
    /// This exact waiter was already Interrupted. The retained reason remains owned by the first
    /// interruption and no second scheduler wake may be published.
    AlreadyInterrupted,
}

/// Result of the race-safe wake path.
///
/// `woken` is the Linux-visible number of waiters consumed by the wake. `runnable` is the number of
/// exact waiter identities written to the caller-provided output slice and therefore needing an
/// owner-local `make_ready` or existing cross-CPU remote-wake publication. Prepared waiters that
/// raced before block-commit count in `woken` but not `runnable`; their owner observes
/// [`WaitCommit::AlreadyWoken`] and never sleeps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WakeReport {
    pub woken: usize,
    pub runnable: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaiterState {
    /// Legacy/immediate registration or a prepared waiter whose owner has committed to the sleep
    /// transition while keeping local wake-drain closed.
    Committed,
    /// Published under the runtime's futex-table serialization, but the owner has not yet committed
    /// to blocking the current scheduler generation.
    Prepared,
    /// A wake consumed a Prepared waiter. It remains linked only until its owner commits/cancels and
    /// observes that it must not block.
    Notified,
    /// A signal linearized before FUTEX_WAKE for this exact waiter generation. The waiter stays
    /// linked until its resumed owner consumes the interruption reason exactly once. Normal WAKE
    /// must skip this state so it cannot count or steal a signal-owned wait.
    Interrupted,
}

#[derive(Clone, Copy)]
struct WaiterSlot {
    occupied: bool,
    key: FutexKey,
    waiter: WaiterId,
    state: WaiterState,
    next: u16,
}

impl WaiterSlot {
    const EMPTY: Self = Self {
        occupied: false,
        key: FutexKey {
            address_space: 0,
            user_address: 0,
        },
        waiter: WaiterId(0),
        state: WaiterState::Committed,
        next: NONE,
    };
}

/// Hash-bucketed, allocation-free futex waiter table.
///
/// The table intentionally contains no internal lock. A runtime shared by multiple CPUs must
/// serialize mutable table access outside this type. The caller must perform the fault-safe atomic
/// userspace value comparison immediately before [`prepare_wait`](Self::prepare_wait) while keeping
/// the same runtime serialization/owner protocol.
///
/// Step-15 runtimes should use the Prepared -> Committed/Notified handshake rather than the legacy
/// [`wait`](Self::wait) path. This closes the classic lost-wake window without teaching the common
/// futex queue about architecture traps or foreign RunQueue mutation:
///
/// 1. with the current owner unable to drain remote wakes, compare the user word and `prepare_wait`;
/// 2. release/reacquire only the external futex-table serialization as required, then `commit_wait`;
/// 3. `AlreadyWoken` means return without blocking;
/// 4. `Sleep` means transition the exact current scheduler generation to Blocked before reopening
///    local wake-drain/IRQs;
/// 5. WAKE uses `wake_race_safe`; only its `runnable` identities are delivered through the existing
///    owner-local/remote-wake scheduler path.
pub struct FutexTable<const BUCKETS: usize, const WAITERS: usize> {
    slots: [WaiterSlot; WAITERS],
    heads: [u16; BUCKETS],
    tails: [u16; BUCKETS],
    len: usize,
}

impl<const B: usize, const W: usize> Default for FutexTable<B, W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const B: usize, const W: usize> FutexTable<B, W> {
    pub const fn new() -> Self {
        Self {
            slots: [WaiterSlot::EMPTY; W],
            heads: [NONE; B],
            tails: [NONE; B],
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Legacy immediate registration. New blocking runtimes should use `prepare_wait` plus
    /// `commit_wait` so a racing wake cannot be lost before the owner blocks.
    pub fn wait(&mut self, key: FutexKey, waiter: WaiterId) -> Result<(), Error> {
        self.insert_waiter(key, waiter, WaiterState::Committed)
    }

    /// Publishes a waiter before the scheduler block transition.
    ///
    /// A racing `wake_race_safe` marks this exact waiter Notified instead of returning it for a
    /// remote wake while its scheduler state may still be Running. The owner then observes
    /// `AlreadyWoken` from `commit_wait` and does not block.
    pub fn prepare_wait(&mut self, key: FutexKey, waiter: WaiterId) -> Result<(), Error> {
        self.insert_waiter(key, waiter, WaiterState::Prepared)
    }

    /// Commits a previously prepared waiter to the scheduler sleep transition.
    ///
    /// When `Sleep` is returned, the caller must keep owner-local wake draining/IRQs closed until
    /// the exact scheduler generation represented by `waiter` is Blocked. Cross-CPU wake may publish
    /// to the existing owner mailbox during that short window; it cannot be drained too early.
    ///
    /// A retained signal interruption returns `AlreadyWoken` without removing its record. The owner
    /// must not block and must later consume the exact Interrupted marker after canonical signal
    /// revalidation. A normal wake-owned `Notified` record is removed here as before.
    pub fn commit_wait(&mut self, waiter: WaiterId) -> Result<WaitCommit, Error> {
        let index = self.find_waiter(waiter).ok_or(Error::WaiterNotFound)?;
        match self.slots[index].state {
            WaiterState::Prepared => {
                self.slots[index].state = WaiterState::Committed;
                Ok(WaitCommit::Sleep)
            }
            WaiterState::Notified => {
                self.remove_index(index)?;
                Ok(WaitCommit::AlreadyWoken)
            }
            WaiterState::Interrupted => Ok(WaitCommit::AlreadyWoken),
            WaiterState::Committed => Err(Error::InvalidWaiterState),
        }
    }

    /// Removes up to `output.len()` FIFO waiters matching `key` and returns the number woken.
    ///
    /// This legacy method accepts only already-Committed waiters. The matching prefix is validated
    /// before the first mutation, so encountering a Prepared/Notified/Interrupted waiter fails
    /// without removing any earlier waiter or writing partial output.
    pub fn wake(&mut self, key: FutexKey, output: &mut [WaiterId]) -> Result<usize, Error> {
        if B == 0 || output.is_empty() {
            return Ok(0);
        }
        let bucket = bucket_for::<B>(key);
        self.validate_bucket(bucket)?;
        self.validate_legacy_wake_prefix(key, output.len())?;

        let mut cursor = self.heads[bucket];
        let mut previous = NONE;
        let mut count = 0;
        while cursor != NONE && count < output.len() {
            let index = cursor as usize;
            let next = self.slots[index].next;
            if self.slots[index].key == key {
                let waiter = self.slots[index].waiter;
                self.unlink_index(bucket, previous, cursor, next)?;
                output[count] = waiter;
                count += 1;
                cursor = next;
                continue;
            }
            previous = cursor;
            cursor = next;
        }
        self.normalize_empty_bucket(bucket);
        Ok(count)
    }

    /// Race-safe Step-15 wake operation.
    ///
    /// At most `output.len()` matching waiters are consumed in FIFO order. Committed waiters are
    /// removed and copied densely into `output[..report.runnable]` for scheduler wake delivery.
    /// Prepared waiters are marked Notified and count toward `report.woken` but remain linked until
    /// their owner commits, at which point `commit_wait` removes them and returns `AlreadyWoken`.
    /// Already-Notified and signal-owned Interrupted waiters are skipped so a later WAKE cannot
    /// count the same waiter twice or steal a wait whose interruption already linearized.
    pub fn wake_race_safe(
        &mut self,
        key: FutexKey,
        output: &mut [WaiterId],
    ) -> Result<WakeReport, Error> {
        if B == 0 || output.is_empty() {
            return Ok(WakeReport::default());
        }
        let bucket = bucket_for::<B>(key);
        self.validate_bucket(bucket)?;

        let mut cursor = self.heads[bucket];
        let mut previous = NONE;
        let mut report = WakeReport::default();

        while cursor != NONE && report.woken < output.len() {
            let index = cursor as usize;
            let next = self.slots[index].next;
            if self.slots[index].key != key
                || matches!(
                    self.slots[index].state,
                    WaiterState::Notified | WaiterState::Interrupted
                )
            {
                previous = cursor;
                cursor = next;
                continue;
            }

            match self.slots[index].state {
                WaiterState::Prepared => {
                    self.slots[index].state = WaiterState::Notified;
                    report.woken += 1;
                    previous = cursor;
                    cursor = next;
                }
                WaiterState::Committed => {
                    let waiter = self.slots[index].waiter;
                    self.unlink_index(bucket, previous, cursor, next)?;
                    output[report.runnable] = waiter;
                    report.runnable += 1;
                    report.woken += 1;
                    cursor = next;
                }
                WaiterState::Notified | WaiterState::Interrupted => unreachable!(),
            }
        }

        self.normalize_empty_bucket(bucket);
        Ok(report)
    }

    /// Claims the exact waiter generation for signal interruption without owning scheduler state.
    ///
    /// The returned outcome preserves the owner race that linearized:
    /// - Prepared becomes Interrupted and is retained without a scheduler wake obligation;
    /// - Committed becomes Interrupted and grants exactly one scheduler wake obligation;
    /// - Interrupted reports AlreadyInterrupted without granting a second wake;
    /// - an absent waiter or a normal-wake-owned Notified waiter reports NotWaiting.
    pub fn interrupt_wait(&mut self, waiter: WaiterId) -> Result<InterruptWaitOutcome, Error> {
        let Some(index) = self.find_waiter(waiter) else {
            return Ok(InterruptWaitOutcome::NotWaiting);
        };
        match self.slots[index].state {
            WaiterState::Prepared => {
                self.slots[index].state = WaiterState::Interrupted;
                Ok(InterruptWaitOutcome::Retained)
            }
            WaiterState::Committed => {
                self.slots[index].state = WaiterState::Interrupted;
                Ok(InterruptWaitOutcome::WakeRequired)
            }
            WaiterState::Interrupted => Ok(InterruptWaitOutcome::AlreadyInterrupted),
            WaiterState::Notified => Ok(InterruptWaitOutcome::NotWaiting),
        }
    }

    /// Observes whether this exact waiter generation retains a signal-owned interruption.
    ///
    /// Observation never consumes or rewrites the waiter. The owning runtime uses this after a
    /// scheduler resume so canonical SignalTable policy can be revalidated before the exact marker
    /// is consumed for EINTR/SA_RESTART handling. Queue corruption fails closed.
    pub fn interruption_pending(&self, waiter: WaiterId) -> Result<bool, Error> {
        let Some(index) = self.find_waiter(waiter) else {
            return Ok(false);
        };
        let bucket = bucket_for::<B>(self.slots[index].key);
        self.validate_bucket(bucket)?;
        Ok(self.slots[index].state == WaiterState::Interrupted)
    }

    /// Consumes a retained signal-interruption reason for exactly one waiter generation.
    ///
    /// Only Interrupted is removed. Every other exact state, and an absent/stale waiter identity,
    /// returns `Ok(false)` without mutation so resume code cannot fabricate EINTR/SA_RESTART state.
    pub fn consume_interrupted(&mut self, waiter: WaiterId) -> Result<bool, Error> {
        let Some(index) = self.find_waiter(waiter) else {
            return Ok(false);
        };
        if self.slots[index].state != WaiterState::Interrupted {
            return Ok(false);
        }
        self.remove_index(index)?;
        Ok(true)
    }

    /// Cancels an ordinary waiter after the owner abandons its scheduler-block transaction.
    ///
    /// A signal-owned Interrupted record is linearized state, not block-failure cleanup. Preserve it
    /// until `consume_interrupted` after canonical signal revalidation; cancellation fails closed
    /// without mutating the queue instead of erasing EINTR/SA_RESTART ownership.
    pub fn cancel(&mut self, waiter: WaiterId) -> Result<bool, Error> {
        let Some(index) = self.find_waiter(waiter) else {
            return Ok(false);
        };
        if self.slots[index].state == WaiterState::Interrupted {
            return Err(Error::InvalidWaiterState);
        }
        self.remove_index(index)?;
        Ok(true)
    }

    fn insert_waiter(
        &mut self,
        key: FutexKey,
        waiter: WaiterId,
        state: WaiterState,
    ) -> Result<(), Error> {
        if B == 0 || W > NONE as usize {
            return Err(Error::Capacity);
        }
        if self.len > W {
            return Err(Error::QueueCorrupt);
        }
        if self.len == W {
            return Err(Error::Capacity);
        }
        if self.find_waiter(waiter).is_some() {
            return Err(Error::DuplicateWaiter);
        }
        let slot = self
            .slots
            .iter()
            .position(|slot| !slot.occupied)
            .ok_or(Error::QueueCorrupt)?;
        let bucket = bucket_for::<B>(key);
        self.validate_bucket(bucket)?;
        let tail = self.tails[bucket];

        self.slots[slot] = WaiterSlot {
            occupied: true,
            key,
            waiter,
            state,
            next: NONE,
        };
        if tail == NONE {
            self.heads[bucket] = slot as u16;
        } else {
            self.slots[tail as usize].next = slot as u16;
        }
        self.tails[bucket] = slot as u16;
        self.len += 1;
        Ok(())
    }

    fn find_waiter(&self, waiter: WaiterId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.occupied && slot.waiter == waiter)
    }

    fn validate_slot(&self, index: usize) -> Result<(), Error> {
        if index >= W || !self.slots[index].occupied {
            return Err(Error::QueueCorrupt);
        }
        Ok(())
    }

    /// Validates the complete linked-list shape for one bucket before mutation.
    fn validate_bucket(&self, bucket: usize) -> Result<(), Error> {
        if bucket >= B || self.len > W {
            return Err(Error::QueueCorrupt);
        }
        let head = self.heads[bucket];
        let tail = self.tails[bucket];
        if head == NONE {
            return if tail == NONE {
                Ok(())
            } else {
                Err(Error::QueueCorrupt)
            };
        }
        if tail == NONE {
            return Err(Error::QueueCorrupt);
        }

        let mut cursor = head;
        let mut last = NONE;
        let mut visited = 0usize;
        while cursor != NONE {
            if visited >= W {
                return Err(Error::QueueCorrupt);
            }
            let index = cursor as usize;
            self.validate_slot(index)?;
            if bucket_for::<B>(self.slots[index].key) != bucket {
                return Err(Error::QueueCorrupt);
            }
            visited += 1;
            last = cursor;
            cursor = self.slots[index].next;
        }
        if last != tail || visited > self.len {
            return Err(Error::QueueCorrupt);
        }
        Ok(())
    }

    /// Ensures the legacy wake matching prefix contains only Committed waiters before mutation.
    fn validate_legacy_wake_prefix(&self, key: FutexKey, maximum: usize) -> Result<(), Error> {
        let bucket = bucket_for::<B>(key);
        let mut cursor = self.heads[bucket];
        let mut matched = 0usize;
        while cursor != NONE && matched < maximum {
            let index = cursor as usize;
            if self.slots[index].key == key {
                if self.slots[index].state != WaiterState::Committed {
                    return Err(Error::InvalidWaiterState);
                }
                matched += 1;
            }
            cursor = self.slots[index].next;
        }
        Ok(())
    }

    fn remove_index(&mut self, index: usize) -> Result<(), Error> {
        self.validate_slot(index)?;
        let key = self.slots[index].key;
        let bucket = bucket_for::<B>(key);
        self.validate_bucket(bucket)?;
        let mut cursor = self.heads[bucket];
        let mut previous = NONE;

        while cursor != NONE {
            let current = cursor as usize;
            let next = self.slots[current].next;
            if current == index {
                self.unlink_index(bucket, previous, cursor, next)?;
                self.normalize_empty_bucket(bucket);
                return Ok(());
            }
            previous = cursor;
            cursor = next;
        }
        Err(Error::QueueCorrupt)
    }

    fn unlink_index(
        &mut self,
        bucket: usize,
        previous: u16,
        cursor: u16,
        next: u16,
    ) -> Result<(), Error> {
        self.validate_bucket(bucket)?;
        let index = cursor as usize;
        self.validate_slot(index)?;
        if self.slots[index].next != next {
            return Err(Error::QueueCorrupt);
        }
        if previous == NONE {
            if self.heads[bucket] != cursor {
                return Err(Error::QueueCorrupt);
            }
        } else {
            let previous_index = previous as usize;
            self.validate_slot(previous_index)?;
            if self.slots[previous_index].next != cursor {
                return Err(Error::QueueCorrupt);
            }
        }
        if next != NONE {
            self.validate_slot(next as usize)?;
        }
        let new_len = self.len.checked_sub(1).ok_or(Error::QueueCorrupt)?;

        if previous == NONE {
            self.heads[bucket] = next;
        } else {
            self.slots[previous as usize].next = next;
        }
        if self.tails[bucket] == cursor {
            self.tails[bucket] = previous;
        }
        self.slots[index] = WaiterSlot::EMPTY;
        self.len = new_len;
        Ok(())
    }

    fn normalize_empty_bucket(&mut self, bucket: usize) {
        if self.heads[bucket] == NONE {
            self.tails[bucket] = NONE;
        }
    }
}

fn bucket_for<const B: usize>(key: FutexKey) -> usize {
    if B == 0 {
        return 0;
    }
    let mut x = key.user_address ^ key.address_space.rotate_left(17);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    (x as usize) % B
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(space: u64, address: u64) -> FutexKey {
        FutexKey::new(space, address).unwrap()
    }

    #[test]
    fn wake_is_fifo_for_same_futex() {
        let mut table = FutexTable::<8, 8>::new();
        let k = key(1, 0x1000);
        table.wait(k, WaiterId(1)).unwrap();
        table.wait(k, WaiterId(2)).unwrap();
        table.wait(k, WaiterId(3)).unwrap();
        let mut out = [WaiterId(0); 2];
        assert_eq!(table.wake(k, &mut out).unwrap(), 2);
        assert_eq!(out, [WaiterId(1), WaiterId(2)]);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn hash_collisions_do_not_wake_other_keys() {
        let mut table = FutexTable::<1, 8>::new();
        let a = key(1, 0x1000);
        let b = key(1, 0x2000);
        table.wait(a, WaiterId(1)).unwrap();
        table.wait(b, WaiterId(2)).unwrap();
        table.wait(a, WaiterId(3)).unwrap();
        let mut out = [WaiterId(0); 4];
        assert_eq!(table.wake(a, &mut out).unwrap(), 2);
        assert_eq!(&out[..2], &[WaiterId(1), WaiterId(3)]);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn wake_between_prepare_and_commit_is_not_lost() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let waiter = WaiterId(91);
        table.prepare_wait(k, waiter).unwrap();

        let mut out = [WaiterId(0); 1];
        let report = table.wake_race_safe(k, &mut out).unwrap();
        assert_eq!(
            report,
            WakeReport {
                woken: 1,
                runnable: 0
            }
        );
        assert_eq!(table.len(), 1);

        assert_eq!(table.commit_wait(waiter), Ok(WaitCommit::AlreadyWoken));
        assert!(table.is_empty());
    }

    #[test]
    fn committed_wait_is_delivered_to_scheduler_wake_path() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let waiter = WaiterId(92);
        table.prepare_wait(k, waiter).unwrap();
        assert_eq!(table.commit_wait(waiter), Ok(WaitCommit::Sleep));

        let mut out = [WaiterId(0); 1];
        let report = table.wake_race_safe(k, &mut out).unwrap();
        assert_eq!(
            report,
            WakeReport {
                woken: 1,
                runnable: 1
            }
        );
        assert_eq!(out[0], waiter);
        assert!(table.is_empty());
    }

    #[test]
    fn notified_waiter_is_counted_only_once() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let first = WaiterId(1);
        let second = WaiterId(2);
        table.prepare_wait(k, first).unwrap();
        table.prepare_wait(k, second).unwrap();

        let mut one = [WaiterId(0); 1];
        assert_eq!(
            table.wake_race_safe(k, &mut one).unwrap(),
            WakeReport {
                woken: 1,
                runnable: 0,
            }
        );
        assert_eq!(
            table.wake_race_safe(k, &mut one).unwrap(),
            WakeReport {
                woken: 1,
                runnable: 0,
            }
        );
        assert_eq!(table.commit_wait(first), Ok(WaitCommit::AlreadyWoken));
        assert_eq!(table.commit_wait(second), Ok(WaitCommit::AlreadyWoken));
        assert!(table.is_empty());
    }

    #[test]
    fn signal_interrupt_owns_wait_and_normal_wake_skips_it() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let interrupted = WaiterId(11);
        let next = WaiterId(12);
        table.prepare_wait(k, interrupted).unwrap();
        assert_eq!(table.commit_wait(interrupted), Ok(WaitCommit::Sleep));
        table.prepare_wait(k, next).unwrap();
        assert_eq!(table.commit_wait(next), Ok(WaitCommit::Sleep));

        assert_eq!(
            table.interrupt_wait(interrupted),
            Ok(InterruptWaitOutcome::WakeRequired)
        );
        assert_eq!(
            table.interrupt_wait(interrupted),
            Ok(InterruptWaitOutcome::AlreadyInterrupted)
        );
        assert_eq!(table.interruption_pending(interrupted), Ok(true));

        let mut out = [WaiterId(0); 1];
        assert_eq!(
            table.wake_race_safe(k, &mut out).unwrap(),
            WakeReport {
                woken: 1,
                runnable: 1,
            }
        );
        assert_eq!(out[0], next);
        assert_eq!(table.len(), 1);

        assert_eq!(table.consume_interrupted(interrupted), Ok(true));
        assert_eq!(table.interruption_pending(interrupted), Ok(false));
        assert_eq!(table.consume_interrupted(interrupted), Ok(false));
        assert!(table.is_empty());
    }

    #[test]
    fn cancel_cannot_erase_signal_owned_interruption() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let waiter = WaiterId(16);
        table.prepare_wait(k, waiter).unwrap();
        assert_eq!(table.commit_wait(waiter), Ok(WaitCommit::Sleep));
        assert_eq!(
            table.interrupt_wait(waiter),
            Ok(InterruptWaitOutcome::WakeRequired)
        );
        assert_eq!(table.cancel(waiter), Err(Error::InvalidWaiterState));
        assert_eq!(table.len(), 1);

        let mut out = [WaiterId(0); 1];
        assert_eq!(
            table.wake_race_safe(k, &mut out).unwrap(),
            WakeReport {
                woken: 0,
                runnable: 0,
            }
        );
        assert_eq!(table.consume_interrupted(waiter), Ok(true));
        assert_eq!(table.consume_interrupted(waiter), Ok(false));
        assert!(table.is_empty());
    }

    #[test]
    fn prepared_interrupt_is_retained_without_scheduler_wake() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let waiter = WaiterId(14);
        table.prepare_wait(k, waiter).unwrap();
        assert_eq!(
            table.interrupt_wait(waiter),
            Ok(InterruptWaitOutcome::Retained)
        );
        assert_eq!(table.commit_wait(waiter), Ok(WaitCommit::AlreadyWoken));
        assert_eq!(
            table.interrupt_wait(waiter),
            Ok(InterruptWaitOutcome::AlreadyInterrupted)
        );
        assert_eq!(table.interruption_pending(waiter), Ok(true));
        assert_eq!(table.consume_interrupted(waiter), Ok(true));
        assert_eq!(table.interruption_pending(waiter), Ok(false));
        assert!(table.is_empty());
    }

    #[test]
    fn normal_wake_wins_before_signal_without_fabricating_interrupt() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let waiter = WaiterId(13);
        table.prepare_wait(k, waiter).unwrap();
        assert_eq!(table.commit_wait(waiter), Ok(WaitCommit::Sleep));

        let mut out = [WaiterId(0); 1];
        assert_eq!(
            table.wake_race_safe(k, &mut out).unwrap(),
            WakeReport {
                woken: 1,
                runnable: 1,
            }
        );
        assert_eq!(out[0], waiter);
        assert_eq!(
            table.interrupt_wait(waiter),
            Ok(InterruptWaitOutcome::NotWaiting)
        );
        assert_eq!(table.interruption_pending(waiter), Ok(false));
        assert_eq!(table.consume_interrupted(waiter), Ok(false));
    }

    #[test]
    fn notified_prepared_wait_reports_not_waiting_to_signal_owner() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(7, 0x3000);
        let waiter = WaiterId(15);
        table.prepare_wait(k, waiter).unwrap();
        let mut out = [WaiterId(0); 1];
        assert_eq!(
            table.wake_race_safe(k, &mut out).unwrap(),
            WakeReport {
                woken: 1,
                runnable: 0,
            }
        );
        assert_eq!(
            table.interrupt_wait(waiter),
            Ok(InterruptWaitOutcome::NotWaiting)
        );
        assert_eq!(table.commit_wait(waiter), Ok(WaitCommit::AlreadyWoken));
        assert!(table.is_empty());
    }

    #[test]
    fn legacy_wake_fails_closed_before_partial_mutation() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(3, 0x2000);
        table.wait(k, WaiterId(9)).unwrap();
        table.prepare_wait(k, WaiterId(10)).unwrap();
        let mut out = [WaiterId(77); 2];
        assert_eq!(table.wake(k, &mut out), Err(Error::InvalidWaiterState));
        assert_eq!(out, [WaiterId(77); 2]);
        assert_eq!(table.len(), 2);
        assert!(table.cancel(WaiterId(9)).unwrap());
        assert!(table.cancel(WaiterId(10)).unwrap());
    }

    #[test]
    fn cancel_removes_timed_out_waiter() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(9, 0x4000);
        table.wait(k, WaiterId(44)).unwrap();
        assert!(table.cancel(WaiterId(44)).unwrap());
        assert_eq!(table.len(), 0);
        assert!(!table.cancel(WaiterId(44)).unwrap());
    }

    #[test]
    fn cancel_removes_prepared_or_notified_waiter() {
        let mut table = FutexTable::<4, 4>::new();
        let k = key(9, 0x4000);
        table.prepare_wait(k, WaiterId(45)).unwrap();
        assert!(table.cancel(WaiterId(45)).unwrap());
        table.prepare_wait(k, WaiterId(46)).unwrap();
        let mut out = [WaiterId(0); 1];
        assert_eq!(
            table.wake_race_safe(k, &mut out).unwrap(),
            WakeReport {
                woken: 1,
                runnable: 0,
            }
        );
        assert!(table.cancel(WaiterId(46)).unwrap());
        assert!(table.is_empty());
    }

    #[test]
    fn duplicate_waiter_is_rejected() {
        let mut table = FutexTable::<4, 4>::new();
        table.wait(key(1, 0x1000), WaiterId(5)).unwrap();
        assert_eq!(
            table.prepare_wait(key(1, 0x2000), WaiterId(5)),
            Err(Error::DuplicateWaiter)
        );
    }
}
