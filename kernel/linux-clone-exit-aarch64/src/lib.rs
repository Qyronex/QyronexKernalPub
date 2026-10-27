// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::ptr::NonNull;
use kernal_futex::FutexKey;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_linux_futex_runtime::{SerializedFutexTable, WakeError};
use kernal_process::Process;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_process_aarch64::{BoundProcessAddressSpace, current_user_switch_generation};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_cpu::CpuSchedulerCell;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_scheduler_cpu::Error as SchedulerError;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
use kernal_scheduler_smp::GlobalThreadId;

/// Linux CLONE_CHILD_CLEARTID and robust-futex death each wake at most one waiter.
pub const CLEAR_CHILD_TID_WAKE_COUNT: usize = 1;
pub const ROBUST_FUTEX_WAKE_COUNT: usize = 1;

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const CLEAR_CHILD_TID_WAKE_LIMIT: u32 = 1;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const ROBUST_FUTEX_WAKE_LIMIT: u32 = 1;

/// Linux UAPI robust-futex owner word bits.
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
/// Linux bounds robust-list cleanup to prevent a corrupt cyclic list from trapping kernel exit.
pub const ROBUST_LIST_LIMIT: usize = 2048;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const ROBUST_LIST_HEAD_NEXT_OFFSET: u64 = 0;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const ROBUST_LIST_HEAD_FUTEX_OFFSET: u64 = 8;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const ROBUST_LIST_HEAD_PENDING_OFFSET: u64 = 16;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const ROBUST_FUTEX_VALUE_RETRIES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Futex(kernal_futex::Error),
    AddressSpace(kernal_process_aarch64::Error),
    Usercopy(kernal_usercopy::Error),
    AtomicUsercopy(kernal_usercopy_aarch64::AtomicU32CompareExchangeError),
    InvalidRobustTid,
    InvalidRobustList,
    RobustListLimit,
    Overflow,
}

/// Fatal delivery failure after the canonical futex owner has consumed an exact waiter.
///
/// A local target must be delivered synchronously through the current owner scheduler. A foreign
/// target is delegated to the caller's exact owner-mailbox router. Neither failure is recoverable:
/// the futex waiter has already been removed and must not be silently reconstructed or dropped.
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
#[derive(Debug, Eq, PartialEq)]
pub enum WakeDeliveryError<E> {
    Local(SchedulerError),
    Remote(E),
}

/// Fatal errors from Linux thread-exit user cleanup.
///
/// `Clear`, `Robust`, `Wake`, and any scheduler error observed after Running -> Exited are fail-closed
/// runtime evidence. The old Process/TTBR0 binding and kernel stack remain authoritative; callers
/// must never translate these failures into a Linux errno or resume the exited generation at EL0.
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
#[derive(Debug, Eq, PartialEq)]
pub enum ExitError<E> {
    Scheduler(SchedulerError),
    Clear(Error),
    Robust(Error),
    Wake(WakeError<WakeDeliveryError<E>>),
    Invariant,
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
impl<E> From<SchedulerError> for ExitError<E> {
    fn from(value: SchedulerError) -> Self {
        Self::Scheduler(value)
    }
}

/// Derives the process-private futex key for one already generation-owned userspace futex address.
///
/// The scheduler/context owner is responsible for exposing `user_address` only for the exact current
/// Process/Thread generation. This adapter owns no lifecycle registry or scheduler state; it only
/// binds the address to the Process address-space generation used by the accepted private futex table.
pub fn private_futex_key<const CAPS: usize>(
    process: &Process<CAPS>,
    user_address: u64,
) -> Result<FutexKey, Error> {
    FutexKey::new(process.address_space().0, user_address).map_err(Error::Futex)
}

/// Computes Linux robust-futex owner-death replacement for one observed owner word.
///
/// Only a word still owned by `exiting_tid` may be changed. Linux WAITERS is preserved while the TID
/// field is cleared and OWNER_DIED is set. The caller must still perform an atomic compare/exchange
/// against the exact `observed` value before publishing this replacement.
pub const fn robust_owner_died_replacement(observed: u32, exiting_tid: u32) -> Option<u32> {
    if exiting_tid == 0 || exiting_tid > FUTEX_TID_MASK || observed & FUTEX_TID_MASK != exiting_tid
    {
        return None;
    }
    Some((observed & FUTEX_WAITERS) | FUTEX_OWNER_DIED)
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn add_signed_offset(base: u64, offset: i64) -> Result<u64, Error> {
    if offset >= 0 {
        base.checked_add(offset as u64).ok_or(Error::Overflow)
    } else {
        base.checked_sub(offset.unsigned_abs())
            .ok_or(Error::Overflow)
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const fn robust_walk_completed(terminated: bool, next: u64, robust_head: u64) -> bool {
    terminated || next == robust_head
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn validate_current_process<const CAPS: usize, const VMAS: usize>(
    process: &Process<CAPS>,
    space: &BoundProcessAddressSpace<VMAS>,
) -> Result<(), Error> {
    let active = space.current_owner(process).map_err(Error::AddressSpace)?;
    let switch_generation = current_user_switch_generation().ok_or(Error::AddressSpace(
        kernal_process_aarch64::Error::NotCurrentProcess,
    ))?;
    active
        .validate_entry_switch_generation(switch_generation)
        .map_err(Error::AddressSpace)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn read_user_u64(user_address: u64) -> Result<u64, Error> {
    let mut bytes = [0_u8; core::mem::size_of::<u64>()];
    kernal_usercopy_aarch64::copy_from_user(&mut bytes, user_address).map_err(Error::Usercopy)?;
    Ok(u64::from_ne_bytes(bytes))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn read_user_i64(user_address: u64) -> Result<i64, Error> {
    read_user_u64(user_address).map(|value| i64::from_ne_bytes(value.to_ne_bytes()))
}

/// Clears one CLONE_CHILD_CLEARTID word through the accepted AArch64 PAN/fault-safe usercopy path.
///
/// On success the returned key must be passed to the canonical futex WAKE path with
/// [`CLEAR_CHILD_TID_WAKE_COUNT`]. Only after that wake succeeds may the scheduler/context owner mark
/// the exact generation's pending clear-child-tid obligation complete and allow switch/reap/release.
///
/// The exact active TTBR0 switch generation is validated immediately before and after the usercopy
/// window. The post-check is defense-in-depth: the safety contract requires that no address-space
/// switch can occur at all, because a completed userspace zero-store cannot be rolled back after an
/// illegal switch is discovered.
///
/// # Safety
/// The caller must own the exact exiting scheduler generation and its current process/address-space
/// binding. Local IRQ delivery, preemption, migration, and every TTBR0/address-space switch must stay
/// suppressed from the first owner check through the post-store generation validation. `user_address`
/// must be the pending CLONE_CHILD_CLEARTID address owned by that exact generation.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn clear_child_tid<const CAPS: usize, const VMAS: usize>(
    process: &Process<CAPS>,
    space: &BoundProcessAddressSpace<VMAS>,
    user_address: u64,
) -> Result<FutexKey, Error> {
    let key = private_futex_key(process, user_address)?;
    let active = space.current_owner(process).map_err(Error::AddressSpace)?;
    let switch_generation = current_user_switch_generation().ok_or(Error::AddressSpace(
        kernal_process_aarch64::Error::NotCurrentProcess,
    ))?;
    active
        .validate_entry_switch_generation(switch_generation)
        .map_err(Error::AddressSpace)?;

    let store_result = kernal_usercopy_aarch64::copy_to_user(user_address, &0u32.to_ne_bytes())
        .map_err(Error::Usercopy);

    active
        .validate_entry_switch_generation(switch_generation)
        .map_err(Error::AddressSpace)?;
    store_result?;
    Ok(key)
}

/// Walks one exact generation's registered Linux robust list and publishes owner death atomically.
///
/// The list head layout is the 64-bit Linux UAPI `robust_list_head`: `list.next`, signed
/// `futex_offset`, and `list_op_pending`. The main chain is bounded by [`ROBUST_LIST_LIMIT`]. The
/// pending operation entry is skipped in the main walk and processed exactly once afterwards.
///
/// For every entry still owned by `exiting_tid`, the futex word is replaced with
/// `FUTEX_OWNER_DIED | preserved(FUTEX_WAITERS)` using the accepted fault-safe AArch64 user compare/
/// exchange primitive. If WAITERS was present, at most one waiter is consumed from the canonical
/// private futex table and routed through the existing local/remote owners.
///
/// # Safety
/// The caller must own the exact exiting thread generation and keep its Process/TTBR0 binding current,
/// with IRQ delivery, preemption, migration and address-space switching suppressed for the complete
/// walk. `robust_head` must be the head stored for that exact generation by the canonical context
/// owner. Wake callbacks must preserve exact scheduler identities and must not reenter this futex
/// owner on the same CPU.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn cleanup_robust_list<
    const CAPS: usize,
    const VMAS: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: &Process<CAPS>,
    space: &BoundProcessAddressSpace<VMAS>,
    robust_head: u64,
    exiting_tid: u32,
    exiting: GlobalThreadId,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    mut local_wake: impl FnMut(GlobalThreadId) -> Result<(), SchedulerError>,
    mut remote_wake: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), ExitError<E>> {
    if exiting_tid == 0 || exiting_tid > FUTEX_TID_MASK {
        return Err(ExitError::Robust(Error::InvalidRobustTid));
    }
    validate_current_process(process, space).map_err(ExitError::Robust)?;

    let next_address = robust_head
        .checked_add(ROBUST_LIST_HEAD_NEXT_OFFSET)
        .ok_or(ExitError::Robust(Error::Overflow))?;
    let offset_address = robust_head
        .checked_add(ROBUST_LIST_HEAD_FUTEX_OFFSET)
        .ok_or(ExitError::Robust(Error::Overflow))?;
    let pending_address = robust_head
        .checked_add(ROBUST_LIST_HEAD_PENDING_OFFSET)
        .ok_or(ExitError::Robust(Error::Overflow))?;
    let mut next = read_user_u64(next_address).map_err(ExitError::Robust)?;
    let futex_offset = read_user_i64(offset_address).map_err(ExitError::Robust)?;
    let pending = read_user_u64(pending_address).map_err(ExitError::Robust)?;

    let mut terminated = false;
    for _ in 0..ROBUST_LIST_LIMIT {
        if next == robust_head {
            terminated = true;
            break;
        }
        if next == 0 {
            return Err(ExitError::Robust(Error::InvalidRobustList));
        }
        let entry = next;
        next = read_user_u64(entry).map_err(ExitError::Robust)?;
        if entry != pending {
            // SAFETY: delegated caller contract keeps the exact Process/TTBR0 owner current and wake
            // callbacks preserve canonical scheduler ownership throughout this synchronous helper.
            unsafe {
                mark_robust_futex_owner_died(
                    process,
                    entry,
                    futex_offset,
                    exiting_tid,
                    exiting,
                    futexes,
                    &mut local_wake,
                    &mut remote_wake,
                )
            }?;
        }
    }
    if !robust_walk_completed(terminated, next, robust_head) {
        return Err(ExitError::Robust(Error::RobustListLimit));
    }

    if pending != 0 && pending != robust_head {
        // SAFETY: same exact exit-owner contract as the bounded main-list walk above. The pending
        // entry was skipped in that walk, so this is its sole cleanup attempt.
        unsafe {
            mark_robust_futex_owner_died(
                process,
                pending,
                futex_offset,
                exiting_tid,
                exiting,
                futexes,
                &mut local_wake,
                &mut remote_wake,
            )
        }?;
    }

    validate_current_process(process, space).map_err(ExitError::Robust)?;
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
unsafe fn mark_robust_futex_owner_died<
    const CAPS: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: &Process<CAPS>,
    entry: u64,
    futex_offset: i64,
    exiting_tid: u32,
    exiting: GlobalThreadId,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    local_wake: &mut impl FnMut(GlobalThreadId) -> Result<(), SchedulerError>,
    remote_wake: &mut impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), ExitError<E>> {
    let futex_address = add_signed_offset(entry, futex_offset).map_err(ExitError::Robust)?;
    let key = private_futex_key(process, futex_address).map_err(ExitError::Robust)?;
    let mut observed =
        kernal_usercopy_aarch64::load_atomic_u32_from_user(futex_address).map_err(|error| {
            match error {
                kernal_usercopy_aarch64::AtomicU32LoadError::Unaligned => {
                    ExitError::Robust(Error::Futex(kernal_futex::Error::Unaligned))
                }
                kernal_usercopy_aarch64::AtomicU32LoadError::Usercopy(error) => {
                    ExitError::Robust(Error::Usercopy(error))
                }
            }
        })?;

    for _ in 0..ROBUST_FUTEX_VALUE_RETRIES {
        let Some(replacement) = robust_owner_died_replacement(observed, exiting_tid) else {
            return Ok(());
        };
        let result = kernal_usercopy_aarch64::compare_exchange_atomic_u32_in_user(
            futex_address,
            observed,
            replacement,
        )
        .map_err(|error| ExitError::Robust(Error::AtomicUsercopy(error)))?;
        if result.exchanged() {
            if observed & FUTEX_WAITERS != 0 {
                // SAFETY: same owner-quiescent contract as clear-child-tid wake. The canonical futex
                // table consumes at most one exact waiter and the callbacks preserve its identity.
                unsafe {
                    wake_one_private_futex_waiter(
                        futexes,
                        key,
                        ROBUST_FUTEX_WAKE_LIMIT,
                        exiting,
                        local_wake,
                        remote_wake,
                    )
                }
                .map_err(ExitError::Wake)?;
            }
            return Ok(());
        }
        observed = result.observed();
    }

    Err(ExitError::Robust(Error::AtomicUsercopy(
        kernal_usercopy_aarch64::AtomicU32CompareExchangeError::Contended,
    )))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
unsafe fn exit_current_with_clear_child_tid_raw_impl<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    space: NonNull<BoundProcessAddressSpace<VMAS>>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    exiting_tid: u32,
    activate_destination: Option<fn(GlobalThreadId, u64)>,
    mut exit_transition: impl FnMut(GlobalThreadId) -> Result<(), ExitError<E>>,
    mut remote_wake: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), ExitError<E>> {
    {
        // SAFETY: the delegated raw-owner contract guarantees both pointers name the persistent
        // current Process/address-space owners for this synchronous validation window.
        let process = unsafe { process.as_ref() };
        // SAFETY: same delegated stable-owner contract.
        let space = unsafe { space.as_ref() };
        validate_current_process(process, space).map_err(ExitError::Clear)?;
    }

    // SAFETY: delegated caller contract proves scheduler ownership and quiescence.
    let current =
        unsafe { scheduler.bootstrap_current_global_thread() }.map_err(ExitError::Scheduler)?;

    // SAFETY: delegated caller contract is retained continuously through the cleanup closure and
    // final switch. Only raw Process/address-space handles are captured across that switch; Rust
    // references are materialized below solely for the synchronous clear-child-tid window.
    let cleanup = |exited, robust_list_head, clear_child_tid_address| {
        if exited != current {
            return Err(ExitError::Invariant);
        }
        exit_transition(exited)?;
        if let Some(robust_head) = robust_list_head {
            let process_ref = unsafe { process.as_ref() };
            let space_ref = unsafe { space.as_ref() };
            unsafe {
                cleanup_robust_list(
                    process_ref,
                    space_ref,
                    robust_head,
                    exiting_tid,
                    exited,
                    futexes,
                    |target| unsafe { scheduler.bootstrap_wake_local_exact(target) },
                    |target| remote_wake(target),
                )
            }?;
        }
        let Some(user_address) = clear_child_tid_address else {
            return Ok(());
        };

        let key = {
            // SAFETY: scheduler has committed this exact generation Exited but intentionally
            // retained its current Process/TTBR0 binding and old kernel stack. The raw owners
            // remain stable; these references end before wake/successor selection can switch.
            let process = unsafe { process.as_ref() };
            // SAFETY: same delegated stable-owner contract and bounded synchronous window.
            let space = unsafe { space.as_ref() };
            // SAFETY: scheduler/TTBR0 quiescence is retained through this zero-store window.
            unsafe { clear_child_tid(process, space, user_address) }.map_err(ExitError::Clear)?
        };

        // SAFETY: owner-local reentry remains closed. A consumed same-CPU waiter is made
        // Ready synchronously; foreign identities are handed to the caller's owner router.
        unsafe {
            wake_clear_child_tid_waiter(
                futexes,
                key,
                exited,
                |target| {
                    // SAFETY: target is the exact committed waiter on this owner CPU and the
                    // enclosing exit transaction still owns the quiescent scheduler window.
                    unsafe { scheduler.bootstrap_wake_local_exact(target) }
                },
                |target| remote_wake(target),
            )
        }
        .map_err(ExitError::Wake)?;
        Ok(())
    };
    match activate_destination {
        Some(activate_destination) => {
            // SAFETY: delegated owner/quiescence contract is retained continuously through cleanup;
            // the destination callback must activate the exact selected generation or never return.
            unsafe {
                scheduler
                    .bootstrap_exit_current_with_cleanup_and_switch_destination_address_space::<
                        ExitError<E>,
                    >(current, cleanup, activate_destination)
            }
        }
        // SAFETY: compatibility path retains the accepted pre-Step-30 scheduler-switch behavior.
        None => unsafe {
            scheduler
                .bootstrap_exit_current_with_cleanup_and_switch::<ExitError<E>>(current, cleanup)
        },
    }
}

/// Completes one non-returning Linux thread exit using stable raw Process/address-space owners.
///
/// This is the multithreaded runtime entry. Unlike the reference-taking compatibility entry below,
/// it does not require a Rust `Process` or `BoundProcessAddressSpace` reference to remain live on the
/// exiting kernel stack while a successor pthread may mutably borrow the same persistent runtime.
/// References are materialized only inside short synchronous validation/usercopy windows and are
/// ended before wake delivery or the final scheduler switch.
///
/// # Safety
/// `process` and `space` must remain valid, pinned owners for the exact current Process generation
/// through this transaction and any successor execution; they must not be moved or destroyed. The
/// caller must otherwise satisfy the same scheduler/TTBR0/quiescence, futex-owner and remote-wake
/// requirements as [`exit_current_with_clear_child_tid`].
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn exit_current_with_clear_child_tid_raw<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    space: NonNull<BoundProcessAddressSpace<VMAS>>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    exiting_tid: u32,
    remote_wake: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), ExitError<E>> {
    // SAFETY: delegated caller contract is exactly the raw implementation contract above.
    unsafe {
        exit_current_with_clear_child_tid_raw_impl(
            process,
            space,
            scheduler,
            futexes,
            exiting_tid,
            None,
            |_| Ok(()),
            remote_wake,
        )
    }
}

/// Completes one non-returning AArch64 Linux thread exit while activating the exact selected
/// successor Process/address space before the final stack switch.
///
/// Robust-list owner death, clear-child-tid zeroing and canonical futex wakes still complete under
/// the exiting Process/TTBR0. Only after those generation-owned obligations are consumed may the
/// scheduler select a successor and invoke `activate_destination` with that exact generation and its
/// opaque ContextTable address-space token.
///
/// # Safety
/// Same requirements as [`exit_current_with_clear_child_tid_raw`]. `activate_destination` must not
/// re-enter scheduler state and must either activate the exact selected generation or fail
/// closed/non-returning; returning after failed activation would expose a selected successor under
/// the exiting Process TTBR0.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn exit_current_with_clear_child_tid_raw_with_destination_address_space<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    space: NonNull<BoundProcessAddressSpace<VMAS>>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    exiting_tid: u32,
    activate_destination: fn(GlobalThreadId, u64),
    remote_wake: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), ExitError<E>> {
    // SAFETY: delegated raw-owner contract plus the stricter destination activation contract above.
    unsafe {
        exit_current_with_clear_child_tid_raw_impl(
            process,
            space,
            scheduler,
            futexes,
            exiting_tid,
            Some(activate_destination),
            |_| Ok(()),
            remote_wake,
        )
    }
}

/// Completes one destination-aware exit with a post-Exited lifecycle notification hook.
///
/// The hook runs after the exact scheduler generation is Exited and scheduler table borrows have
/// ended, but before robust/clear-child-tid cleanup and before successor selection. Any failure is
/// post-commit and therefore fatal/fail-closed.
///
/// # Safety
/// Same requirements as [`exit_current_with_clear_child_tid_raw_with_destination_address_space`].
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn exit_current_with_clear_child_tid_raw_with_destination_address_space_and_transition<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: NonNull<Process<CAPS>>,
    space: NonNull<BoundProcessAddressSpace<VMAS>>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    exiting_tid: u32,
    activate_destination: fn(GlobalThreadId, u64),
    exit_transition: impl FnMut(GlobalThreadId) -> Result<(), ExitError<E>>,
    remote_wake: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), ExitError<E>> {
    // SAFETY: delegated raw-owner and transition-hook contracts above.
    unsafe {
        exit_current_with_clear_child_tid_raw_impl(
            process,
            space,
            scheduler,
            futexes,
            exiting_tid,
            Some(activate_destination),
            exit_transition,
            remote_wake,
        )
    }
}

/// Completes one non-returning Linux thread exit with generation-owned clear-child-tid semantics.
///
/// The process/address-space binding is checked before the irreversible scheduler transition. The
/// scheduler then marks the exact current generation Exited without first requiring a successor and
/// invokes the cleanup closure while CpuLocal, Process/TTBR0 and the old kernel stack remain bound.
/// If the generation owns a clear-child-tid address, this function performs the accepted fault-safe
/// zero-store, wakes at most one committed private-futex waiter, and routes that exact scheduler
/// identity through the existing owner paths. Same-CPU delivery is synchronous so a blocked pthread
/// joiner can become the first runnable successor; foreign delivery is delegated to `remote_wake`.
///
/// The scheduler consumes the pending clear-child-tid obligation only after zero-store and every
/// required wake delivery succeed. It then selects, validates and switches to the successor. Any
/// failure after Exited is fatal and fail-closed; this function must never return to userspace.
///
/// # Safety
/// The caller must execute on `scheduler`'s owner PE with local IRQ delivery masked, `irq_depth=0`,
/// `preempt_count=0`, migration suppressed and `process`/`space` active as the exact current TTBR0
/// binding. Those conditions must remain true through the final context switch. `futexes` must be the
/// canonical shared private-futex owner used by FUTEX_WAIT. `remote_wake` must route a foreign exact
/// [`GlobalThreadId`] to that target CPU's existing `CpuSchedulerCell::remote_wake` mailbox without
/// blocking, switching address spaces, changing CpuLocal current, or silently dropping the target.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn exit_current_with_clear_child_tid<
    const CAPS: usize,
    const VMAS: usize,
    const THREADS: usize,
    const WAKES: usize,
    const BUCKETS: usize,
    const WAITERS: usize,
    E,
>(
    process: &Process<CAPS>,
    space: &BoundProcessAddressSpace<VMAS>,
    scheduler: &'static CpuSchedulerCell<THREADS, WAKES>,
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    exiting_tid: u32,
    remote_wake: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), ExitError<E>> {
    let process = NonNull::from(process);
    let space = NonNull::from(space);
    // SAFETY: the reference-taking entry establishes stable owners for conversion; neither reference
    // is used after this point, so the non-returning implementation carries only raw handles across
    // successor execution.
    unsafe {
        exit_current_with_clear_child_tid_raw_impl(
            process,
            space,
            scheduler,
            futexes,
            exiting_tid,
            None,
            |_| Ok(()),
            remote_wake,
        )
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn route_woken_thread<E>(
    exiting: GlobalThreadId,
    target: GlobalThreadId,
    local_wake: &mut impl FnMut(GlobalThreadId) -> Result<(), SchedulerError>,
    remote_wake: &mut impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), WakeDeliveryError<E>> {
    if target.cpu == exiting.cpu {
        local_wake(target).map_err(WakeDeliveryError::Local)
    } else {
        remote_wake(target).map_err(WakeDeliveryError::Remote)
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
unsafe fn wake_one_private_futex_waiter<const BUCKETS: usize, const WAITERS: usize, E>(
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    key: FutexKey,
    maximum: u32,
    exiting: GlobalThreadId,
    local_wake: &mut impl FnMut(GlobalThreadId) -> Result<(), SchedulerError>,
    remote_wake: &mut impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), WakeError<WakeDeliveryError<E>>> {
    // SAFETY: delegated caller contract keeps same-CPU futex reentry closed. The delivery callback
    // preserves every consumed exact identity through either synchronous local or owner-mailbox wake.
    let _ = unsafe {
        futexes.wake_with(key, maximum, |target| {
            route_woken_thread(exiting, target, local_wake, remote_wake)
        })
    }?;
    Ok(())
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
unsafe fn wake_clear_child_tid_waiter<const BUCKETS: usize, const WAITERS: usize, E>(
    futexes: &SerializedFutexTable<BUCKETS, WAITERS>,
    key: FutexKey,
    exiting: GlobalThreadId,
    mut local_wake: impl FnMut(GlobalThreadId) -> Result<(), SchedulerError>,
    mut remote_wake: impl FnMut(GlobalThreadId) -> Result<(), E>,
) -> Result<(), WakeError<WakeDeliveryError<E>>> {
    // SAFETY: same canonical private-futex wake contract, specialized to Linux's wake-one
    // CLONE_CHILD_CLEARTID rule.
    unsafe {
        wake_one_private_futex_waiter(
            futexes,
            key,
            CLEAR_CHILD_TID_WAKE_LIMIT,
            exiting,
            &mut local_wake,
            &mut remote_wake,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_futex_runtime::WaitDecision;
    use kernal_object::ObjectTable;
    use kernal_percpu::CpuIndex;
    use kernal_process::Personality;
    use kernal_scheduler::ThreadId;

    const CHILD_TID: u64 = 0x0000_0000_0010_0000;
    const KEY: FutexKey = FutexKey {
        address_space: 0x1000_0001,
        user_address: CHILD_TID,
    };

    fn thread(cpu: u16, slot: u16, generation: u16) -> GlobalThreadId {
        GlobalThreadId::new(CpuIndex(cpu), ThreadId { slot, generation })
    }

    fn commit_waiter(futexes: &SerializedFutexTable<4, 8>, waiter: GlobalThreadId) {
        assert_eq!(
            // SAFETY: tests serialize all access and retain the synthetic exact waiter identity.
            unsafe { futexes.compare_prepare_commit(waiter, 7, || Ok::<_, ()>((KEY, 7))) },
            Ok(WaitDecision::Sleep)
        );
    }

    #[test]
    fn private_key_is_bound_to_exact_process_address_space_generation() {
        let mut objects = ObjectTable::<8>::new();
        let first = Process::<8>::create(&mut objects, Personality::Linux).unwrap();
        let second = Process::<8>::create(&mut objects, Personality::Linux).unwrap();

        let first_key = private_futex_key(&first, CHILD_TID).unwrap();
        let second_key = private_futex_key(&second, CHILD_TID).unwrap();
        assert_eq!(first_key.address_space, first.address_space().0);
        assert_eq!(second_key.address_space, second.address_space().0);
        assert_ne!(first_key.address_space, second.address_space().0);
        assert_eq!(first_key.user_address, CHILD_TID);
        assert_eq!(CLEAR_CHILD_TID_WAKE_COUNT, 1);
        assert_eq!(ROBUST_FUTEX_WAKE_COUNT, 1);
    }

    #[test]
    fn robust_owner_death_requires_exact_tid_and_preserves_only_waiters() {
        let tid = 0x1234;
        assert_eq!(
            robust_owner_died_replacement(tid, tid),
            Some(FUTEX_OWNER_DIED)
        );
        assert_eq!(
            robust_owner_died_replacement(FUTEX_WAITERS | tid, tid),
            Some(FUTEX_WAITERS | FUTEX_OWNER_DIED)
        );
        assert_eq!(
            robust_owner_died_replacement(FUTEX_OWNER_DIED | tid, tid),
            Some(FUTEX_OWNER_DIED)
        );
        assert_eq!(robust_owner_died_replacement(tid + 1, tid), None);
        assert_eq!(robust_owner_died_replacement(tid, 0), None);
        assert_eq!(robust_owner_died_replacement(tid, FUTEX_TID_MASK + 1), None);
    }

    #[test]
    fn robust_walk_exact_limit_accepts_head_and_rejects_over_limit_next() {
        const HEAD: u64 = 0x1000;
        assert_eq!(ROBUST_LIST_LIMIT, 2048);
        assert!(robust_walk_completed(false, HEAD, HEAD));
        assert!(!robust_walk_completed(false, 0x2000, HEAD));
        assert!(robust_walk_completed(true, 0x2000, HEAD));
    }

    #[test]
    fn signed_robust_futex_offset_is_checked_both_directions() {
        assert_eq!(add_signed_offset(0x2000, 24), Ok(0x2018));
        assert_eq!(add_signed_offset(0x2000, -8), Ok(0x1ff8));
        assert_eq!(add_signed_offset(4, -8), Err(Error::Overflow));
        assert_eq!(add_signed_offset(u64::MAX - 3, 8), Err(Error::Overflow));
    }

    #[test]
    fn unaligned_clear_tid_cannot_manufacture_a_futex_key() {
        let mut objects = ObjectTable::<4>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        assert_eq!(
            private_futex_key(&process, CHILD_TID + 2),
            Err(Error::Futex(kernal_futex::Error::Unaligned))
        );
    }

    #[test]
    fn same_cpu_waiter_is_delivered_synchronously_without_remote_mailbox() {
        let futexes = SerializedFutexTable::<4, 8>::new();
        let exiting = thread(2, 1, 5);
        let waiter = thread(2, 3, 9);
        commit_waiter(&futexes, waiter);

        let mut local = None;
        let mut remote_calls = 0usize;
        // SAFETY: the test is single-threaded and supplies exact synthetic delivery owners.
        unsafe {
            wake_clear_child_tid_waiter(
                &futexes,
                KEY,
                exiting,
                |target| {
                    local = Some(target);
                    Ok(())
                },
                |_target| {
                    remote_calls += 1;
                    Ok::<_, ()>(())
                },
            )
        }
        .unwrap();

        assert_eq!(local, Some(waiter));
        assert_eq!(remote_calls, 0);
    }

    #[test]
    fn foreign_waiter_uses_only_the_remote_owner_router() {
        let futexes = SerializedFutexTable::<4, 8>::new();
        let exiting = thread(1, 1, 2);
        let waiter = thread(7, 4, 8);
        commit_waiter(&futexes, waiter);

        let mut local_calls = 0usize;
        let mut remote = None;
        // SAFETY: the test is single-threaded and supplies exact synthetic delivery owners.
        unsafe {
            wake_clear_child_tid_waiter(
                &futexes,
                KEY,
                exiting,
                |_target| {
                    local_calls += 1;
                    Ok(())
                },
                |target| {
                    remote = Some(target);
                    Ok::<_, ()>(())
                },
            )
        }
        .unwrap();

        assert_eq!(local_calls, 0);
        assert_eq!(remote, Some(waiter));
    }

    #[test]
    fn clear_child_tid_wake_consumes_at_most_one_joiner_per_call() {
        let futexes = SerializedFutexTable::<4, 8>::new();
        let exiting = thread(3, 1, 2);
        commit_waiter(&futexes, thread(3, 2, 4));
        commit_waiter(&futexes, thread(3, 3, 5));

        let mut delivered = 0usize;
        for expected in 1..=2 {
            // SAFETY: the test is single-threaded and supplies exact synthetic delivery owners.
            unsafe {
                wake_clear_child_tid_waiter(
                    &futexes,
                    KEY,
                    exiting,
                    |_target| {
                        delivered += 1;
                        Ok(())
                    },
                    |_target| Ok::<_, ()>(()),
                )
            }
            .unwrap();
            assert_eq!(delivered, expected);
        }
    }

    #[test]
    fn generic_private_futex_wake_is_bounded_by_linux_requested_limit() {
        let futexes = SerializedFutexTable::<4, 8>::new();
        let exiting = thread(3, 1, 2);
        commit_waiter(&futexes, thread(3, 2, 4));
        commit_waiter(&futexes, thread(3, 3, 5));
        let mut local = 0usize;
        let mut remote = |_target| Ok::<_, ()>(());
        // SAFETY: single-threaded exact synthetic owner test.
        unsafe {
            wake_one_private_futex_waiter(
                &futexes,
                KEY,
                ROBUST_FUTEX_WAKE_LIMIT,
                exiting,
                &mut |_target| {
                    local += 1;
                    Ok(())
                },
                &mut remote,
            )
        }
        .unwrap();
        assert_eq!(local, 1);
    }

    #[test]
    fn consumed_local_waiter_delivery_failure_remains_fatal() {
        let futexes = SerializedFutexTable::<4, 8>::new();
        let exiting = thread(4, 1, 2);
        let waiter = thread(4, 2, 3);
        commit_waiter(&futexes, waiter);

        // SAFETY: the test is single-threaded and deliberately injects owner delivery failure.
        let result = unsafe {
            wake_clear_child_tid_waiter(
                &futexes,
                KEY,
                exiting,
                |_target| Err(SchedulerError::WrongOwner),
                |_target| Ok::<_, &'static str>(()),
            )
        };
        assert_eq!(
            result,
            Err(WakeError::Delivery(WakeDeliveryError::Local(
                SchedulerError::WrongOwner
            )))
        );

        let mut delivered_again = 0usize;
        // SAFETY: the prior fatal delivery consumed the waiter; this probes that it is not recreated.
        unsafe {
            wake_clear_child_tid_waiter(
                &futexes,
                KEY,
                exiting,
                |_target| {
                    delivered_again += 1;
                    Ok(())
                },
                |_target| Ok::<_, ()>(()),
            )
        }
        .unwrap();
        assert_eq!(delivered_again, 0);
    }

    #[test]
    fn foreign_mailbox_failure_preserves_the_exact_target() {
        let futexes = SerializedFutexTable::<4, 8>::new();
        let exiting = thread(5, 1, 2);
        let waiter = thread(6, 7, 11);
        commit_waiter(&futexes, waiter);

        // SAFETY: the test is single-threaded and deliberately injects remote mailbox failure.
        let result =
            unsafe { wake_clear_child_tid_waiter(&futexes, KEY, exiting, |_target| Ok(()), Err) };
        assert_eq!(
            result,
            Err(WakeError::Delivery(WakeDeliveryError::Remote(waiter)))
        );
    }

    #[test]
    fn scheduler_errors_convert_without_losing_the_original_variant() {
        let error: ExitError<()> = SchedulerError::Busy.into();
        assert_eq!(error, ExitError::Scheduler(SchedulerError::Busy));
    }
}
