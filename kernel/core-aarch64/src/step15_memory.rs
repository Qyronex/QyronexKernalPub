// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_frame_allocator::{ExtentAllocator, FrameRange, PAGE_SIZE as FRAME_PAGE_SIZE};
use kernal_memory::ReservationSet;
use kernal_qemu_initrd_aarch64::{QEMU_VIRT_RAM_BASE, QEMU_VIRT_RAM_BYTES};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_protected_boot_aarch64::ProtectedInitrd;

pub const STEP15_RESERVED_RANGES: usize = 2;
pub const STEP15_FRAME_EXTENTS: usize = 8;
pub type Step15FrameAllocator = ExtentAllocator<STEP15_FRAME_EXTENTS>;

const RES_EMPTY: u8 = 0;
const RES_INSTALLING: u8 = 1;
const RES_READY: u8 = 2;
const RES_TAKEN: u8 = 3;

const POOL_EMPTY: u8 = 0;
const POOL_INSTALLING: u8 = 1;
const POOL_READY: u8 = 2;
const POOL_BORROWED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    LowRangeUnavailable,
    AllocatorUnavailable,
    InvalidLowRange,
    InvalidInitrd,
    InvalidRamContract,
    ReservationOutsideRam,
    Reservation(kernal_memory::Error),
    FrameAllocator(kernal_frame_allocator::Error),
    AlreadyPublished,
    Busy,
    AlreadyTaken,
    InvalidState,
}

/// Sole Step-15 QEMU physical-memory owner.
///
/// The live allocator and the exact canonical reservation metadata remain together so the existing
/// Linux ELF loader and later Linux VM runtime can keep their independent reserved-frame checks
/// without reconstructing or weakening Core's ownership exclusions.
pub struct Step15FramePool {
    allocator: Step15FrameAllocator,
    reservations: ReservationSet<STEP15_RESERVED_RANGES>,
}

impl Step15FramePool {
    /// Splits one exclusive pool borrow into the two already-owned resources required by the
    /// canonical loader/VM adapters. The fields are disjoint and neither reference may outlive the
    /// surrounding [`with_live_frame_pool`] operation.
    pub fn split(
        &mut self,
    ) -> (
        &mut Step15FrameAllocator,
        &ReservationSet<STEP15_RESERVED_RANGES>,
    ) {
        (&mut self.allocator, &self.reservations)
    }

    pub fn allocator_mut(&mut self) -> &mut Step15FrameAllocator {
        &mut self.allocator
    }

    pub const fn reservations(&self) -> &ReservationSet<STEP15_RESERVED_RANGES> {
        &self.reservations
    }
}

struct ReservationCell {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<ReservationSet<STEP15_RESERVED_RANGES>>>,
}

// SAFETY: `state` gives one initializer and one move-out consumer. The stored value is never
// borrowed while INSTALLING and cannot be accessed again after TAKEN.
unsafe impl Sync for ReservationCell {}

impl ReservationCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(RES_EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&self, reservations: ReservationSet<STEP15_RESERVED_RANGES>) -> Result<(), Error> {
        match self.state.compare_exchange(
            RES_EMPTY,
            RES_INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(RES_INSTALLING) => return Err(Error::Busy),
            Err(RES_READY) => return Err(Error::AlreadyPublished),
            Err(RES_TAKEN) => return Err(Error::AlreadyTaken),
            Err(_) => return Err(Error::InvalidState),
        }
        // SAFETY: successful EMPTY -> INSTALLING gives this path unique write ownership.
        unsafe { (*self.value.get()).write(reservations) };
        self.state.store(RES_READY, Ordering::Release);
        Ok(())
    }

    fn take(&self) -> Result<ReservationSet<STEP15_RESERVED_RANGES>, Error> {
        match self
            .state
            .compare_exchange(RES_READY, RES_TAKEN, Ordering::AcqRel, Ordering::Acquire)
        {
            // SAFETY: READY proves initialization completed; successful transition gives this call the
            // sole move-out right and TAKEN prevents any later observation.
            Ok(_) => Ok(unsafe { (*self.value.get()).assume_init_read() }),
            Err(RES_EMPTY) => Err(Error::LowRangeUnavailable),
            Err(RES_INSTALLING) => Err(Error::Busy),
            Err(RES_TAKEN) => Err(Error::AlreadyTaken),
            Err(_) => Err(Error::InvalidState),
        }
    }
}

struct FramePoolCell {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<Step15FramePool>>,
}

// SAFETY: installation is one-shot and POOL_READY -> POOL_BORROWED is the only transition that
// exposes mutable pool access. Every borrow is scoped to one synchronous closure and publishes READY
// again before another caller can access the allocator.
unsafe impl Sync for FramePoolCell {}

impl FramePoolCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(POOL_EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&self, pool: Step15FramePool) -> Result<(), Error> {
        match self.state.compare_exchange(
            POOL_EMPTY,
            POOL_INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(POOL_INSTALLING | POOL_READY) => return Err(Error::AlreadyPublished),
            Err(POOL_BORROWED) => return Err(Error::Busy),
            Err(_) => return Err(Error::InvalidState),
        }
        // SAFETY: successful EMPTY -> INSTALLING gives this path unique write ownership.
        unsafe { (*self.value.get()).write(pool) };
        self.state.store(POOL_READY, Ordering::Release);
        Ok(())
    }

    fn with_pool<R>(&self, operation: impl FnOnce(&mut Step15FramePool) -> R) -> Result<R, Error> {
        match self.state.compare_exchange(
            POOL_READY,
            POOL_BORROWED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(POOL_EMPTY | POOL_INSTALLING) => return Err(Error::AllocatorUnavailable),
            Err(POOL_BORROWED) => return Err(Error::Busy),
            Err(_) => return Err(Error::InvalidState),
        }

        // SAFETY: POOL_BORROWED is exclusive mutable ownership and READY proves initialization.
        let pool = unsafe { (&mut *self.value.get()).assume_init_mut() };
        let result = operation(pool);
        self.state.store(POOL_READY, Ordering::Release);
        Ok(result)
    }
}

static STEP15_RESERVATIONS: ReservationCell = ReservationCell::new();
static STEP15_LIVE_FRAME_POOL: FramePoolCell = FramePoolCell::new();

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn publish_frame_reservations(initrd: ProtectedInitrd) -> Result<(), Error> {
    let low = kernal_protected_boot_aarch64::qemu_runtime_reserved_low_range()
        .ok_or(Error::LowRangeUnavailable)?;
    let initrd_len = u64::try_from(initrd.len()).map_err(|_| Error::InvalidInitrd)?;
    let reservations = build_reservations(low.start, low.end, initrd.physical_start(), initrd_len)?;
    STEP15_RESERVATIONS.publish(reservations)
}

/// Consumes Core's exact one-shot reservation set into the sole QEMU proof frame allocator.
///
/// The allocator first owns the complete documented QEMU RAM window and then permanently excludes
/// every page-rounded Core reservation. The same reservation object is retained beside the allocator
/// for the canonical loader's independent preflight. Any failure is fail-closed: the reservation
/// token has already been consumed, so a second less-restricted allocator cannot be constructed.
pub fn initialize_live_frame_allocator() -> Result<(), Error> {
    let reservations = STEP15_RESERVATIONS.take()?;
    let pool = build_live_frame_pool(reservations)?;
    STEP15_LIVE_FRAME_POOL.publish(pool)
}

/// Runs one short operation through the sole live frame allocator and canonical reservation set.
///
/// The pool stays owned by Core across initial ELF loading and later `mmap`/`munmap`/`brk` calls.
/// Concurrent or nested access fails closed instead of manufacturing a second allocator. Callers
/// must not block, context-switch, or retain references derived from `pool` after `operation` returns.
pub fn with_live_frame_pool<R>(
    operation: impl FnOnce(&mut Step15FramePool) -> R,
) -> Result<R, Error> {
    STEP15_LIVE_FRAME_POOL.with_pool(operation)
}

fn build_reservations(
    low_start: u64,
    low_end: u64,
    initrd_start: u64,
    initrd_len: u64,
) -> Result<ReservationSet<STEP15_RESERVED_RANGES>, Error> {
    let low_len = low_end
        .checked_sub(low_start)
        .filter(|length| *length != 0)
        .ok_or(Error::InvalidLowRange)?;
    if initrd_len == 0 {
        return Err(Error::InvalidInitrd);
    }

    let mut reservations = ReservationSet::<STEP15_RESERVED_RANGES>::new();
    reservations
        .reserve(low_start, low_len)
        .map_err(Error::Reservation)?;
    reservations
        .reserve(initrd_start, initrd_len)
        .map_err(Error::Reservation)?;
    Ok(reservations)
}

fn build_live_frame_pool(
    reservations: ReservationSet<STEP15_RESERVED_RANGES>,
) -> Result<Step15FramePool, Error> {
    if QEMU_VIRT_RAM_BASE & (FRAME_PAGE_SIZE - 1) != 0
        || QEMU_VIRT_RAM_BYTES == 0
        || !QEMU_VIRT_RAM_BYTES.is_multiple_of(FRAME_PAGE_SIZE)
    {
        return Err(Error::InvalidRamContract);
    }
    let ram_end = QEMU_VIRT_RAM_BASE
        .checked_add(QEMU_VIRT_RAM_BYTES)
        .ok_or(Error::InvalidRamContract)?;
    let ram_pages = QEMU_VIRT_RAM_BYTES / FRAME_PAGE_SIZE;

    let mut allocator = Step15FrameAllocator::new();
    allocator
        .free(FrameRange::new(QEMU_VIRT_RAM_BASE, ram_pages).map_err(Error::FrameAllocator)?)
        .map_err(Error::FrameAllocator)?;

    for reserved in reservations.ranges().iter().copied() {
        if reserved.start < QEMU_VIRT_RAM_BASE
            || reserved.end > ram_end
            || reserved.start >= reserved.end
            || reserved.start & (FRAME_PAGE_SIZE - 1) != 0
            || reserved.end & (FRAME_PAGE_SIZE - 1) != 0
        {
            return Err(Error::ReservationOutsideRam);
        }
        let pages = (reserved.end - reserved.start) / FRAME_PAGE_SIZE;
        let range = FrameRange::new(reserved.start, pages).map_err(Error::FrameAllocator)?;
        allocator.reserve(range).map_err(Error::FrameAllocator)?;
    }

    Ok(Step15FramePool {
        allocator,
        reservations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_memory::PhysFrame;

    #[test]
    fn low_prefix_and_page_rounded_initrd_are_both_reserved() {
        let reservations =
            build_reservations(0x4000_0000, 0x4080_0000, 0x4800_0123, 0x2000).unwrap();
        assert!(reservations.contains(PhysFrame::from_start_address(0x4000_0000).unwrap()));
        assert!(reservations.contains(PhysFrame::from_start_address(0x407f_f000).unwrap()));
        assert!(!reservations.contains(PhysFrame::from_start_address(0x4080_0000).unwrap()));
        assert!(reservations.contains(PhysFrame::from_start_address(0x4800_0000).unwrap()));
        assert!(reservations.contains(PhysFrame::from_start_address(0x4800_2000).unwrap()));
        assert!(!reservations.contains(PhysFrame::from_start_address(0x4800_3000).unwrap()));
    }

    #[test]
    fn reservation_cell_publishes_and_moves_exactly_once() {
        let cell = ReservationCell::new();
        assert!(matches!(cell.take(), Err(Error::LowRangeUnavailable)));
        let reservations =
            build_reservations(0x4000_0000, 0x4080_0000, 0x4800_0123, 0x2000).unwrap();
        cell.publish(reservations).unwrap();
        let taken = cell.take().unwrap();
        assert!(taken.contains(PhysFrame::from_start_address(0x4000_0000).unwrap()));
        assert!(taken.contains(PhysFrame::from_start_address(0x4800_0000).unwrap()));
        assert!(matches!(cell.take(), Err(Error::AlreadyTaken)));
        let second = build_reservations(0x4000_0000, 0x4080_0000, 0x4900_0000, 0x1000).unwrap();
        assert!(matches!(cell.publish(second), Err(Error::AlreadyTaken)));
    }

    #[test]
    fn live_pool_excludes_reserved_pages_reclaims_normal_frames_and_retains_metadata() {
        let reservations =
            build_reservations(0x4000_0000, 0x4080_0000, 0x4800_0123, 0x2000).unwrap();
        let mut pool = build_live_frame_pool(reservations).unwrap();

        assert_eq!(pool.reservations().len(), 2);
        assert!(
            pool.reservations()
                .contains(PhysFrame::from_start_address(0x4800_0000).unwrap())
        );
        assert_eq!(pool.allocator_mut().reservation_count(), 2);
        assert_eq!(
            pool.allocator_mut()
                .free(FrameRange::new(0x4000_0000, 1).unwrap()),
            Err(kernal_frame_allocator::Error::ReservedRange)
        );
        assert_eq!(
            pool.allocator_mut()
                .free(FrameRange::new(0x4800_0000, 1).unwrap()),
            Err(kernal_frame_allocator::Error::ReservedRange)
        );

        let page = pool.allocator_mut().allocate(1, 1).unwrap();
        assert!(page.start >= 0x4080_0000);
        assert!(page.end().unwrap() <= 0x4800_0000 || page.start >= 0x4800_3000);
        let free_before = pool.allocator_mut().free_pages();
        pool.allocator_mut().free(page).unwrap();
        assert_eq!(pool.allocator_mut().free_pages(), free_before + 1);
    }

    #[test]
    fn frame_pool_cell_serializes_borrows_and_preserves_state() {
        let reservations =
            build_reservations(0x4000_0000, 0x4080_0000, 0x4800_0000, 0x1000).unwrap();
        let pool = build_live_frame_pool(reservations).unwrap();
        let cell = FramePoolCell::new();
        cell.publish(pool).unwrap();

        let free_before = cell
            .with_pool(|pool| {
                assert_eq!(cell.state.load(Ordering::Acquire), POOL_BORROWED);
                assert!(matches!(cell.with_pool(|_| ()), Err(Error::Busy)));
                pool.allocator_mut().free_pages()
            })
            .unwrap();
        let allocated = cell
            .with_pool(|pool| pool.allocator_mut().allocate(1, 1).unwrap())
            .unwrap();
        let free_after = cell
            .with_pool(|pool| pool.allocator_mut().free_pages())
            .unwrap();
        assert_eq!(free_after + 1, free_before);
        cell.with_pool(|pool| pool.allocator_mut().free(allocated).unwrap())
            .unwrap();
        assert_eq!(
            cell.with_pool(|pool| pool.allocator_mut().free_pages())
                .unwrap(),
            free_before
        );
    }

    #[test]
    fn reservation_outside_qemu_ram_fails_closed() {
        let mut reservations = ReservationSet::<STEP15_RESERVED_RANGES>::new();
        reservations
            .reserve(QEMU_VIRT_RAM_BASE - FRAME_PAGE_SIZE, FRAME_PAGE_SIZE)
            .unwrap();
        assert!(matches!(
            build_live_frame_pool(reservations),
            Err(Error::ReservationOutsideRam)
        ));
    }

    #[test]
    fn malformed_ranges_fail_closed() {
        assert!(matches!(
            build_reservations(0x4080_0000, 0x4000_0000, 0x4800_0000, 0x1000),
            Err(Error::InvalidLowRange)
        ));
        assert!(matches!(
            build_reservations(0x4000_0000, 0x4080_0000, 0x4800_0000, 0),
            Err(Error::InvalidInitrd)
        ));
    }
}
