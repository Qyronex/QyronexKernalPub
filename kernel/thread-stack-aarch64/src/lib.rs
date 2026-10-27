// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicU64, Ordering};
use kernal_thread_context::{Error as StackError, KernelStack, PAGE_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArena,
    AddressOverflow,
    Exhausted,
    ForeignStack,
    NotAllocated,
    Stack(StackError),
}

impl From<StackError> for Error {
    fn from(value: StackError) -> Self {
        Self::Stack(value)
    }
}

/// Allocation-free ownership for a linker-reserved AArch64 kernel-stack arena.
///
/// This type deliberately owns no page tables and performs no mapping. The architecture boot owner
/// must establish the arena once, with one unmapped guard page followed by a writable, non-executable
/// mapped payload in every slot. The pool prevents concurrent claims of those already-protected
/// slots and returns the canonical [`KernelStack`] metadata consumed by the scheduler.
///
/// Slot occupancy is represented by a single atomic bitmap, so one global pool may be claimed by
/// multiple CPU owners without introducing another scheduler or stack-identity table. Because
/// [`KernelStack`] is a copyable address descriptor and a reused slot has identical geometry,
/// releasing a slot additionally requires external lifecycle ownership; see [`Self::reclaim`].
pub struct StaticStackPool<const N: usize> {
    arena_start: u64,
    arena_end: u64,
    stride: u64,
    mapped_len: u64,
    slot_mask: u64,
    allocated: AtomicU64,
}

impl<const N: usize> StaticStackPool<N> {
    /// Creates a pool over an already protected kernel-stack arena.
    ///
    /// # Safety
    /// The caller must prove for the lifetime of this pool that:
    /// - `[arena_start, arena_end)` is exclusively reserved for these `N` stack slots;
    /// - every slot begins with exactly one unmapped [`PAGE_SIZE`] guard page in every live kernel
    ///   alias;
    /// - the remainder of every slot is mapped writable and non-executable;
    /// - the mappings and slot geometry remain stable until no claimed stack can still execute.
    pub unsafe fn new_protected(
        arena_start: u64,
        arena_end: u64,
        stride: u64,
    ) -> Result<Self, Error> {
        if N == 0
            || N > u64::BITS as usize
            || arena_start == 0
            || arena_start & (PAGE_SIZE - 1) != 0
            || arena_end & (PAGE_SIZE - 1) != 0
            || stride <= PAGE_SIZE
            || stride & (PAGE_SIZE - 1) != 0
        {
            return Err(Error::InvalidArena);
        }

        let count = u64::try_from(N).map_err(|_| Error::AddressOverflow)?;
        let expected_len = count.checked_mul(stride).ok_or(Error::AddressOverflow)?;
        let actual_len = arena_end
            .checked_sub(arena_start)
            .ok_or(Error::InvalidArena)?;
        if actual_len != expected_len {
            return Err(Error::InvalidArena);
        }
        arena_start
            .checked_add(expected_len)
            .filter(|end| *end == arena_end)
            .ok_or(Error::AddressOverflow)?;

        let mapped_len = stride.checked_sub(PAGE_SIZE).ok_or(Error::InvalidArena)?;
        if mapped_len == 0 || mapped_len & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArena);
        }

        let slot_mask = if N == u64::BITS as usize {
            u64::MAX
        } else {
            (1u64 << N) - 1
        };

        Ok(Self {
            arena_start,
            arena_end,
            stride,
            mapped_len,
            slot_mask,
            allocated: AtomicU64::new(0),
        })
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn allocated_count(&self) -> u32 {
        (self.allocated.load(Ordering::Acquire) & self.slot_mask).count_ones()
    }

    /// Claims one exact stack slot, or reports bounded exhaustion without changing ownership.
    pub fn claim(&self) -> Result<KernelStack, Error> {
        let mut current = self.allocated.load(Ordering::Acquire);
        loop {
            let free = (!current) & self.slot_mask;
            if free == 0 {
                return Err(Error::Exhausted);
            }
            let index = free.trailing_zeros() as usize;
            let bit = 1u64 << index;
            match self.allocated.compare_exchange_weak(
                current,
                current | bit,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return match self.stack_for(index) {
                        Ok(stack) => Ok(stack),
                        Err(error) => {
                            self.allocated.fetch_and(!bit, Ordering::AcqRel);
                            Err(error)
                        }
                    };
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Releases one stack slot after its external scheduler/lifecycle owner has surrendered it.
    ///
    /// Geometry checks reject foreign and mutated descriptors, and an already-clear bit reports
    /// [`Error::NotAllocated`]. Geometry alone cannot distinguish a stale descriptor from a later
    /// owner of the same reused slot, because [`KernelStack`] is intentionally copyable and contains
    /// no allocation generation.
    ///
    /// # Safety
    /// The caller must hold the authoritative cancellation/reap result for this exact current stack
    /// allocation and must guarantee that no descriptor retained from an earlier allocation of the
    /// same slot can invoke `reclaim` after the slot is claimed again. The normal Step-15 caller is
    /// the private clone-stack provider immediately after the scheduler returns the exact stack from
    /// staged cancellation or generation-safe reap.
    pub unsafe fn reclaim(&self, stack: KernelStack) -> Result<(), Error> {
        let index = self.index_for(stack)?;
        let bit = 1u64 << index;
        self.allocated
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current & bit != 0).then_some(current & !bit)
            })
            .map(|_| ())
            .map_err(|_| Error::NotAllocated)
    }

    fn stack_for(&self, index: usize) -> Result<KernelStack, Error> {
        if index >= N {
            return Err(Error::ForeignStack);
        }
        let offset = u64::try_from(index)
            .map_err(|_| Error::AddressOverflow)?
            .checked_mul(self.stride)
            .ok_or(Error::AddressOverflow)?;
        let guard_start = self
            .arena_start
            .checked_add(offset)
            .ok_or(Error::AddressOverflow)?;
        let mapped_start = guard_start
            .checked_add(PAGE_SIZE)
            .ok_or(Error::AddressOverflow)?;
        let top = mapped_start
            .checked_add(self.mapped_len)
            .ok_or(Error::AddressOverflow)?;
        if top > self.arena_end {
            return Err(Error::AddressOverflow);
        }
        KernelStack::new(guard_start, mapped_start, self.mapped_len).map_err(Error::Stack)
    }

    fn index_for(&self, stack: KernelStack) -> Result<usize, Error> {
        let offset = stack
            .guard_start
            .checked_sub(self.arena_start)
            .ok_or(Error::ForeignStack)?;
        if offset % self.stride != 0 {
            return Err(Error::ForeignStack);
        }
        let index_u64 = offset / self.stride;
        let index = usize::try_from(index_u64).map_err(|_| Error::ForeignStack)?;
        if index >= N || self.stack_for(index)? != stack {
            return Err(Error::ForeignStack);
        }
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: u64 = 0x0000_0000_8000_0000;
    const STRIDE: u64 = 0x11_000;

    fn pool<const N: usize>() -> StaticStackPool<N> {
        let end = START + N as u64 * STRIDE;
        // SAFETY: tests model an already protected arena; this crate never dereferences the addresses.
        unsafe { StaticStackPool::new_protected(START, end, STRIDE) }.unwrap()
    }

    #[test]
    fn claims_unique_slots_until_bounded_exhaustion() {
        let pool = pool::<4>();
        let first = pool.claim().unwrap();
        let second = pool.claim().unwrap();
        let third = pool.claim().unwrap();
        let fourth = pool.claim().unwrap();

        assert_eq!(first.guard_start, START);
        assert_eq!(first.mapped_start, START + PAGE_SIZE);
        assert_eq!(first.mapped_len, STRIDE - PAGE_SIZE);
        assert_eq!(second.guard_start, START + STRIDE);
        assert_eq!(third.guard_start, START + 2 * STRIDE);
        assert_eq!(fourth.guard_start, START + 3 * STRIDE);
        assert_eq!(pool.allocated_count(), 4);
        assert_eq!(pool.claim(), Err(Error::Exhausted));
    }

    #[test]
    fn exact_reclaim_makes_the_same_slot_available_again() {
        let pool = pool::<2>();
        let first = pool.claim().unwrap();
        let second = pool.claim().unwrap();
        // SAFETY: the test owns the exact first allocation and no reuse has happened yet.
        unsafe { pool.reclaim(first) }.unwrap();
        assert_eq!(pool.allocated_count(), 1);

        let replacement = pool.claim().unwrap();
        assert_eq!(replacement, first);
        assert_eq!(pool.allocated_count(), 2);
        // SAFETY: both descriptors identify the exact current claims and no stale reclaim follows.
        unsafe { pool.reclaim(second) }.unwrap();
        // SAFETY: replacement is the exact current claim for the reused slot.
        unsafe { pool.reclaim(replacement) }.unwrap();
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn foreign_or_mutated_metadata_is_rejected_before_bitmap_release() {
        let pool = pool::<2>();
        let live = pool.claim().unwrap();
        let foreign = KernelStack::new(
            START + 2 * STRIDE,
            START + 2 * STRIDE + PAGE_SIZE,
            STRIDE - PAGE_SIZE,
        )
        .unwrap();
        // SAFETY: this negative test performs no slot reuse and exercises only geometry rejection.
        assert_eq!(unsafe { pool.reclaim(foreign) }, Err(Error::ForeignStack));

        let mutated = KernelStack::new(
            live.guard_start,
            live.mapped_start,
            live.mapped_len - PAGE_SIZE,
        )
        .unwrap();
        // SAFETY: this negative test performs no slot reuse and exercises only geometry rejection.
        assert_eq!(unsafe { pool.reclaim(mutated) }, Err(Error::ForeignStack));
        assert_eq!(pool.allocated_count(), 1);
        // SAFETY: live is still the exact current allocation.
        unsafe { pool.reclaim(live) }.unwrap();
    }

    #[test]
    fn double_reclaim_before_reuse_is_rejected_without_affecting_other_slots() {
        let pool = pool::<2>();
        let first = pool.claim().unwrap();
        let second = pool.claim().unwrap();
        // SAFETY: first is the exact current allocation and no slot reuse occurs in this test.
        unsafe { pool.reclaim(first) }.unwrap();
        // SAFETY: the bit is still clear and has not been reallocated, so this checks NotAllocated.
        assert_eq!(unsafe { pool.reclaim(first) }, Err(Error::NotAllocated));
        assert_eq!(pool.allocated_count(), 1);
        // SAFETY: second is the exact remaining current allocation.
        unsafe { pool.reclaim(second) }.unwrap();
    }

    #[test]
    fn reused_slot_has_identical_descriptor_and_needs_external_owner_proof() {
        let pool = pool::<1>();
        let stale = pool.claim().unwrap();
        // SAFETY: stale currently names the exact first allocation.
        unsafe { pool.reclaim(stale) }.unwrap();
        let current = pool.claim().unwrap();
        assert_eq!(stale, current);
        assert_eq!(pool.allocated_count(), 1);
        // SAFETY: current names the exact active replacement allocation.
        unsafe { pool.reclaim(current) }.unwrap();
    }

    #[test]
    fn constructor_rejects_malformed_or_unbounded_arenas() {
        // SAFETY: addresses are never dereferenced; each call only exercises constructor validation.
        unsafe {
            assert_eq!(
                StaticStackPool::<0>::new_protected(START, START, STRIDE).err(),
                Some(Error::InvalidArena)
            );
            assert_eq!(
                StaticStackPool::<65>::new_protected(START, START + 65 * STRIDE, STRIDE).err(),
                Some(Error::InvalidArena)
            );
            assert_eq!(
                StaticStackPool::<1>::new_protected(0, STRIDE, STRIDE).err(),
                Some(Error::InvalidArena)
            );
            assert_eq!(
                StaticStackPool::<1>::new_protected(START + 1, START + 1 + STRIDE, STRIDE).err(),
                Some(Error::InvalidArena)
            );
            assert_eq!(
                StaticStackPool::<1>::new_protected(START, START + STRIDE - PAGE_SIZE, STRIDE)
                    .err(),
                Some(Error::InvalidArena)
            );
            assert_eq!(
                StaticStackPool::<1>::new_protected(START, START + PAGE_SIZE, PAGE_SIZE).err(),
                Some(Error::InvalidArena)
            );
        }
    }
}
