// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};
pub use kernal_futex::InterruptWaitOutcome;
use kernal_futex::{FutexKey, FutexTable, WaitCommit, WaiterId, WakeReport};
use kernal_percpu::CpuIndex;
use kernal_scheduler::ThreadId;
use kernal_scheduler_smp::GlobalThreadId;

const WAITER_RESERVED_MASK: u64 = 0xffff_0000_0000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    ZeroGeneration,
    ReservedBits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitDecision {
    ValueMismatch,
    Sleep,
}

#[derive(Debug, Eq, PartialEq)]
pub enum WaitError<E> {
    Observe(E),
    Identity(IdentityError),
    Futex(kernal_futex::Error),
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelError {
    Identity(IdentityError),
    Futex(kernal_futex::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptError {
    Identity(IdentityError),
    Futex(kernal_futex::Error),
}

/// Fatal failure after `wake_race_safe` has already consumed one or more committed waiters.
///
/// A caller must not translate this into a recoverable Linux errno and continue. Doing so could
/// leave a consumed waiter permanently blocked. Treat identity or delivery failure as a privileged
/// scheduler/runtime invariant failure.
#[derive(Debug, Eq, PartialEq)]
pub enum WakeError<E> {
    Futex(kernal_futex::Error),
    Identity(IdentityError),
    Delivery(E),
}

/// One externally serialized owner for the existing allocation-free [`FutexTable`].
///
/// The common futex core intentionally contains no lock. Step-15 requires compare + prepare + commit
/// to be one table-serialization transaction, while owner-local IRQ/wake draining remains closed
/// through the subsequent scheduler block. This wrapper supplies only that serialization; it does
/// not own user memory, scheduler state, Linux operation decoding, or a second waiter registry.
pub struct SerializedFutexTable<const BUCKETS: usize, const WAITERS: usize> {
    locked: AtomicBool,
    table: UnsafeCell<FutexTable<BUCKETS, WAITERS>>,
}

// SAFETY: every mutable FutexTable access is reachable only while `locked` is held. Public mutation
// methods are unsafe because callers must additionally prevent same-CPU interrupt/reentrant entry
// while spinning on the lock; cross-CPU contenders are serialized by the atomic acquire/release.
unsafe impl<const B: usize, const W: usize> Sync for SerializedFutexTable<B, W> {}

impl<const B: usize, const W: usize> SerializedFutexTable<B, W> {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            table: UnsafeCell::new(FutexTable::new()),
        }
    }

    /// Atomically performs the Step-15 FUTEX_WAIT compare/prepare/commit table transaction.
    ///
    /// `observe` must perform the architecture's fault-safe atomic user-word read and return the
    /// exact private [`FutexKey`] plus observed u32 value. It runs while the shared futex table lock
    /// is held so a concurrent WAKE cannot pass between compare and waiter publication.
    ///
    /// `Sleep` means the exact generation is committed in the futex table. The caller must keep its
    /// owner-local IRQ/wake-drain window closed and transition that same `current` generation to
    /// Blocked before reopening it. If that scheduler transition fails before blocking, call
    /// [`Self::cancel_wait`] while the same owner remains quiescent.
    ///
    /// The wrapper holds the sole table lock continuously from `prepare_wait` through `commit_wait`.
    /// Therefore the common-core `AlreadyWoken` outcome cannot be caused by a runtime WAKE here, and
    /// a commit error after successful prepare is likewise internal queue/state evidence. Any commit
    /// result other than `Sleep` fails closed as [`WaitError::Invariant`] rather than exposing an
    /// impossible state through the recoverable/common-core Futex error channel.
    ///
    /// # Safety
    /// The caller must prevent same-CPU interrupt/reentrant use of this runtime for the duration of
    /// the call. For FUTEX_WAIT it must also retain the scheduler/address-space owner serialization
    /// required by the supplied `observe` closure and keep wake draining closed until any returned
    /// `Sleep` decision has been consumed by the exact-generation block transition.
    pub unsafe fn compare_prepare_commit<E>(
        &self,
        current: GlobalThreadId,
        expected: u32,
        observe: impl FnOnce() -> Result<(FutexKey, u32), E>,
    ) -> Result<WaitDecision, WaitError<E>> {
        let waiter = encode_waiter(current).map_err(WaitError::Identity)?;
        let mut guard = self.lock();
        let (key, observed) = observe().map_err(WaitError::Observe)?;
        if observed != expected {
            return Ok(WaitDecision::ValueMismatch);
        }

        guard
            .table_mut()
            .prepare_wait(key, waiter)
            .map_err(WaitError::Futex)?;
        match guard.table_mut().commit_wait(waiter) {
            Ok(WaitCommit::Sleep) => Ok(WaitDecision::Sleep),
            Ok(WaitCommit::AlreadyWoken) => Err(WaitError::Invariant),
            Err(_) => {
                // A failed commit is impossible under the runtime's exclusive table transaction.
                // Cancel only as best-effort containment in case the common core retained the waiter;
                // either cancellation outcome remains privileged invariant evidence.
                let _ = guard.table_mut().cancel(waiter);
                Err(WaitError::Invariant)
            }
        }
    }

    /// Cancels the exact generation's prepared/committed waiter after a scheduler block failure.
    ///
    /// `Ok(false)` is meaningful: a concurrent WAKE may already have consumed a committed waiter
    /// after the table lock was released. The owner must then treat the wait as already woken rather
    /// than manufacturing a second registration.
    ///
    /// # Safety
    /// Same non-reentrant futex-runtime requirement as [`Self::compare_prepare_commit`]. The caller
    /// must still own the exact scheduler generation supplied in `current`.
    pub unsafe fn cancel_wait(&self, current: GlobalThreadId) -> Result<bool, CancelError> {
        let waiter = encode_waiter(current).map_err(CancelError::Identity)?;
        let mut guard = self.lock();
        guard.table_mut().cancel(waiter).map_err(CancelError::Futex)
    }

    /// Claims or observes the exact waiter generation for signal interruption.
    ///
    /// The common owner returns a four-way race observation rather than collapsing absence,
    /// pre-block retention, a committed wake obligation and a repeated interruption into one bool.
    /// Only [`InterruptWaitOutcome::WakeRequired`] grants the caller a scheduler-wake obligation.
    /// [`InterruptWaitOutcome::Retained`] means the signal linearized while the waiter was Prepared;
    /// [`InterruptWaitOutcome::AlreadyInterrupted`] retains the first signal owner's claim; and
    /// [`InterruptWaitOutcome::NotWaiting`] means no futex interruption is owned here.
    ///
    /// # Safety
    /// The caller must prevent same-CPU interrupt/reentrant use while this runtime lock may be held
    /// and must wake only the exact `current` generation for `WakeRequired`.
    pub unsafe fn interrupt_wait(
        &self,
        current: GlobalThreadId,
    ) -> Result<InterruptWaitOutcome, InterruptError> {
        let waiter = encode_waiter(current).map_err(InterruptError::Identity)?;
        let mut guard = self.lock();
        guard
            .table_mut()
            .interrupt_wait(waiter)
            .map_err(InterruptError::Futex)
    }

    /// Observes a retained signal interruption for exactly `current` without consuming it.
    ///
    /// This is the resume-side bridge between scheduler wake and canonical SignalTable policy. A
    /// true result means the exact generation still owns an Interrupted futex waiter. The caller may
    /// inspect/commit signal policy and only then call [`Self::consume_interrupted`].
    ///
    /// # Safety
    /// Same non-reentrant futex-runtime requirement as [`Self::interrupt_wait`]. The caller must own
    /// or be resuming the exact scheduler generation supplied in `current`.
    pub unsafe fn interruption_pending(
        &self,
        current: GlobalThreadId,
    ) -> Result<bool, InterruptError> {
        let waiter = encode_waiter(current).map_err(InterruptError::Identity)?;
        let mut guard = self.lock();
        guard
            .table_mut()
            .interruption_pending(waiter)
            .map_err(InterruptError::Futex)
    }

    /// Consumes the retained signal-interruption reason for exactly `current` once.
    ///
    /// Stale or non-waiting generations return `Ok(false)` and cannot consume another generation's
    /// reason. A true result removes only the canonical Interrupted waiter record.
    ///
    /// # Safety
    /// Same non-reentrant futex-runtime requirement as [`Self::interrupt_wait`]. The caller must be
    /// resuming or revalidating the exact scheduler generation supplied in `current`.
    pub unsafe fn consume_interrupted(
        &self,
        current: GlobalThreadId,
    ) -> Result<bool, InterruptError> {
        let waiter = encode_waiter(current).map_err(InterruptError::Identity)?;
        let mut guard = self.lock();
        guard
            .table_mut()
            .consume_interrupted(waiter)
            .map_err(InterruptError::Futex)
    }

    /// Consumes up to `maximum` matching waiters and delivers each committed scheduler identity.
    ///
    /// `compare_prepare_commit` holds this same serializer through prepare and commit, so a runtime
    /// WAKE cannot observe a Prepared waiter. Committed waiters are removed while the table lock is
    /// held, then delivered after the lock is released so scheduler wake publication cannot
    /// recursively contend on this table. Any identity decode or delivery failure after consumption
    /// is fatal runtime evidence and must not be mapped to a normal Linux errno.
    ///
    /// # Safety
    /// The caller must prevent same-CPU interrupt/reentrant use of this runtime while the table lock
    /// may be held. `deliver` must publish the exact generation through the existing owner-local or
    /// remote-wake scheduler mechanism and must not silently drop a consumed waiter.
    pub unsafe fn wake_with<E>(
        &self,
        key: FutexKey,
        maximum: u32,
        mut deliver: impl FnMut(GlobalThreadId) -> Result<(), E>,
    ) -> Result<WakeReport, WakeError<E>> {
        let mut output = [WaiterId(0); W];
        let report = {
            let mut guard = self.lock();
            let limit = core::cmp::min(maximum as usize, W);
            guard
                .table_mut()
                .wake_race_safe(key, &mut output[..limit])
                .map_err(WakeError::Futex)?
        };

        for waiter in output.iter().take(report.runnable).copied() {
            let thread = decode_waiter(waiter).map_err(WakeError::Identity)?;
            deliver(thread).map_err(WakeError::Delivery)?;
        }
        Ok(report)
    }

    fn lock(&self) -> FutexGuard<'_, B, W> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
        FutexGuard { owner: self }
    }

    #[cfg(test)]
    fn len_for_test(&self) -> usize {
        let guard = self.lock();
        guard.table().len()
    }
}

impl<const B: usize, const W: usize> Default for SerializedFutexTable<B, W> {
    fn default() -> Self {
        Self::new()
    }
}

struct FutexGuard<'a, const B: usize, const W: usize> {
    owner: &'a SerializedFutexTable<B, W>,
}

impl<const B: usize, const W: usize> FutexGuard<'_, B, W> {
    #[cfg(test)]
    fn table(&self) -> &FutexTable<B, W> {
        // SAFETY: construction requires successful exclusive acquisition of `owner.locked` and the
        // guard holds that acquisition until Drop.
        unsafe { &*self.owner.table.get() }
    }

    fn table_mut(&mut self) -> &mut FutexTable<B, W> {
        // SAFETY: construction requires successful exclusive acquisition of `owner.locked`; mutable
        // access is tied to the unique guard borrow and no other table reference escapes the guard.
        unsafe { &mut *self.owner.table.get() }
    }
}

impl<const B: usize, const W: usize> Drop for FutexGuard<'_, B, W> {
    fn drop(&mut self) {
        self.owner.locked.store(false, Ordering::Release);
    }
}

fn encode_waiter(thread: GlobalThreadId) -> Result<WaiterId, IdentityError> {
    if thread.local.generation == 0 {
        return Err(IdentityError::ZeroGeneration);
    }
    Ok(WaiterId(
        thread.local.slot as u64
            | ((thread.local.generation as u64) << 16)
            | ((thread.cpu.0 as u64) << 32),
    ))
}

fn decode_waiter(waiter: WaiterId) -> Result<GlobalThreadId, IdentityError> {
    if waiter.0 & WAITER_RESERVED_MASK != 0 {
        return Err(IdentityError::ReservedBits);
    }
    let generation = (waiter.0 >> 16) as u16;
    if generation == 0 {
        return Err(IdentityError::ZeroGeneration);
    }
    Ok(GlobalThreadId::new(
        CpuIndex((waiter.0 >> 32) as u16),
        ThreadId {
            slot: waiter.0 as u16,
            generation,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: FutexKey = FutexKey {
        address_space: 0x1000_0001,
        user_address: 0x0000_0000_0001_2000,
    };

    fn thread(cpu: u16, slot: u16, generation: u16) -> GlobalThreadId {
        GlobalThreadId::new(CpuIndex(cpu), ThreadId { slot, generation })
    }

    #[test]
    fn waiter_identity_round_trips_exact_global_generation() {
        let id = thread(7, 0x1234, 0xabcd);
        let waiter = encode_waiter(id).unwrap();
        assert_eq!(decode_waiter(waiter), Ok(id));
        assert_eq!(waiter.0 >> 48, 0);
    }

    #[test]
    fn zero_generation_and_reserved_bits_are_rejected() {
        assert_eq!(
            encode_waiter(thread(1, 2, 0)),
            Err(IdentityError::ZeroGeneration)
        );
        assert_eq!(
            decode_waiter(WaiterId(1u64 << 63)),
            Err(IdentityError::ReservedBits)
        );
        assert_eq!(
            decode_waiter(WaiterId(0)),
            Err(IdentityError::ZeroGeneration)
        );
    }

    #[test]
    fn mismatch_never_publishes_waiter() {
        let runtime = SerializedFutexTable::<4, 8>::new();
        let current = thread(1, 2, 3);
        let result =
            unsafe { runtime.compare_prepare_commit(current, 9, || Ok::<_, ()>((KEY, 8))) };
        assert_eq!(result, Ok(WaitDecision::ValueMismatch));
        assert_eq!(runtime.len_for_test(), 0);
    }

    #[test]
    fn committed_wait_wakes_exact_scheduler_generation() {
        let runtime = SerializedFutexTable::<4, 8>::new();
        let current = thread(2, 5, 9);
        let wait = unsafe {
            runtime.compare_prepare_commit(current, 0x55aa, || Ok::<_, ()>((KEY, 0x55aa)))
        };
        assert_eq!(wait, Ok(WaitDecision::Sleep));
        assert_eq!(runtime.len_for_test(), 1);

        let mut delivered = None;
        let report = unsafe {
            runtime.wake_with(KEY, 1, |id| {
                delivered = Some(id);
                Ok::<_, ()>(())
            })
        }
        .unwrap();
        assert_eq!(report.woken, 1);
        assert_eq!(report.runnable, 1);
        assert_eq!(delivered, Some(current));
        assert_eq!(runtime.len_for_test(), 0);
    }

    #[test]
    fn signal_interrupt_is_retained_and_consumed_once_for_exact_generation() {
        let runtime = SerializedFutexTable::<4, 8>::new();
        let current = thread(2, 5, 9);
        assert_eq!(
            unsafe {
                runtime.compare_prepare_commit(current, 0x55aa, || Ok::<_, ()>((KEY, 0x55aa)))
            },
            Ok(WaitDecision::Sleep)
        );

        assert_eq!(
            unsafe { runtime.interrupt_wait(current) },
            Ok(InterruptWaitOutcome::WakeRequired)
        );
        assert_eq!(
            unsafe { runtime.interrupt_wait(current) },
            Ok(InterruptWaitOutcome::AlreadyInterrupted)
        );
        assert_eq!(unsafe { runtime.interruption_pending(current) }, Ok(true));

        let mut delivered = None;
        let report = unsafe {
            runtime.wake_with(KEY, 1, |id| {
                delivered = Some(id);
                Ok::<_, ()>(())
            })
        }
        .unwrap();
        assert_eq!(report.woken, 0);
        assert_eq!(report.runnable, 0);
        assert_eq!(delivered, None);
        assert_eq!(runtime.len_for_test(), 1);

        assert_eq!(unsafe { runtime.consume_interrupted(current) }, Ok(true));
        assert_eq!(unsafe { runtime.interruption_pending(current) }, Ok(false));
        assert_eq!(unsafe { runtime.consume_interrupted(current) }, Ok(false));
        assert_eq!(runtime.len_for_test(), 0);
    }

    #[test]
    fn stale_generation_cannot_consume_signal_interruption() {
        let runtime = SerializedFutexTable::<4, 8>::new();
        let current = thread(1, 7, 10);
        let stale = thread(1, 7, 9);
        assert_eq!(
            unsafe { runtime.compare_prepare_commit(current, 7, || Ok::<_, ()>((KEY, 7))) },
            Ok(WaitDecision::Sleep)
        );
        assert_eq!(
            unsafe { runtime.interrupt_wait(current) },
            Ok(InterruptWaitOutcome::WakeRequired)
        );
        assert_eq!(unsafe { runtime.interruption_pending(current) }, Ok(true));
        assert_eq!(unsafe { runtime.interruption_pending(stale) }, Ok(false));
        assert_eq!(
            unsafe { runtime.interrupt_wait(stale) },
            Ok(InterruptWaitOutcome::NotWaiting)
        );
        assert_eq!(unsafe { runtime.consume_interrupted(stale) }, Ok(false));
        assert_eq!(runtime.len_for_test(), 1);
        assert_eq!(unsafe { runtime.consume_interrupted(current) }, Ok(true));
        assert_eq!(runtime.len_for_test(), 0);
    }

    #[test]
    fn normal_wake_wins_before_signal_interrupt() {
        let runtime = SerializedFutexTable::<4, 8>::new();
        let current = thread(1, 8, 11);
        assert_eq!(
            unsafe { runtime.compare_prepare_commit(current, 3, || Ok::<_, ()>((KEY, 3))) },
            Ok(WaitDecision::Sleep)
        );
        let mut delivered = None;
        let report = unsafe {
            runtime.wake_with(KEY, 1, |id| {
                delivered = Some(id);
                Ok::<_, ()>(())
            })
        }
        .unwrap();
        assert_eq!(report.woken, 1);
        assert_eq!(report.runnable, 1);
        assert_eq!(delivered, Some(current));
        assert_eq!(unsafe { runtime.interruption_pending(current) }, Ok(false));
        assert_eq!(
            unsafe { runtime.interrupt_wait(current) },
            Ok(InterruptWaitOutcome::NotWaiting)
        );
        assert_eq!(unsafe { runtime.consume_interrupted(current) }, Ok(false));
    }

    #[test]
    fn cancel_removes_exact_committed_waiter() {
        let runtime = SerializedFutexTable::<4, 8>::new();
        let current = thread(0, 3, 4);
        assert_eq!(
            unsafe { runtime.compare_prepare_commit(current, 7, || Ok::<_, ()>((KEY, 7))) },
            Ok(WaitDecision::Sleep)
        );
        assert_eq!(unsafe { runtime.cancel_wait(current) }, Ok(true));
        assert_eq!(unsafe { runtime.cancel_wait(current) }, Ok(false));
        assert_eq!(runtime.len_for_test(), 0);
    }

    #[test]
    fn wake_delivery_failure_is_fatal_after_waiter_consumption() {
        let runtime = SerializedFutexTable::<4, 8>::new();
        let current = thread(3, 4, 5);
        assert_eq!(
            unsafe { runtime.compare_prepare_commit(current, 1, || Ok::<_, ()>((KEY, 1))) },
            Ok(WaitDecision::Sleep)
        );
        let result = unsafe { runtime.wake_with(KEY, 1, |_id| Err::<(), _>("mailbox-full")) };
        assert_eq!(result, Err(WakeError::Delivery("mailbox-full")));
        assert_eq!(runtime.len_for_test(), 0);

        let report = unsafe { runtime.wake_with(KEY, 1, |_id| Ok::<_, ()>(())) }.unwrap();
        assert_eq!(report.woken, 0);
        assert_eq!(report.runnable, 0);
    }
}
