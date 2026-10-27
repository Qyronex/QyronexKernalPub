// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::mem::{MaybeUninit, replace};
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use kernal_page_table_aarch64::Backend;
use kernal_paging::PAGE_SIZE;

use crate::mmu::{BootstrapLayout, Error as MmuError};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static CLAIMED: AtomicBool = AtomicBool::new(false);

const LIVE_EMPTY: u8 = 0;
const LIVE_INSTALLING: u8 = 1;
const LIVE_READY: u8 = 2;
const LIVE_BORROWED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RuntimeNotProtected,
    AlreadyClaimed,
    Mmu(MmuError),
    UsedPageCountOverflow,
    PoolExhausted,
    LiveHandoffTooLate,
    LiveAlreadyInstalled,
    LiveUnavailable,
    LiveBusy,
    LiveInvalidState,
}

impl From<MmuError> for Error {
    fn from(value: MmuError) -> Self {
        Self::Mmu(value)
    }
}

/// BSP-exclusive allocator/view over the unused tail of the linker-reserved AArch64 page-table
/// pool after every PE has retired the temporary TTBR0 regime and the final protection probes pass.
///
/// The whole linker pool already has a writable TTBR1 high alias. This object never recreates a low
/// physical alias: it returns physical table addresses for descriptors while reading, writing and
/// zeroing their contents exclusively through that accepted high alias. Secondary PEs may still be
/// held at the final runtime-release barrier while the BSP uses this pool for one-shot proofs.
pub struct RuntimeTablePool {
    physical_start: u64,
    virtual_start: u64,
    allocation_start: u64,
    next: u64,
    end: u64,
    free_head: u64,
}

impl RuntimeTablePool {
    fn new(layout: BootstrapLayout, used_pages: usize) -> Result<Self, Error> {
        let layout = layout.validate()?;
        let used_pages = u64::try_from(used_pages).map_err(|_| Error::UsedPageCountOverflow)?;
        let used_bytes = used_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::UsedPageCountOverflow)?;
        let next = layout
            .page_tables
            .start
            .checked_add(used_bytes)
            .ok_or(Error::UsedPageCountOverflow)?;
        if next > layout.page_tables.end {
            return Err(Error::PoolExhausted);
        }
        Ok(Self {
            physical_start: layout.page_tables.start,
            virtual_start: layout.high_alias(layout.page_tables.start)?,
            allocation_start: layout.page_tables.end,
            next,
            end: layout.page_tables.end,
            free_head: 0,
        })
    }

    /// Inert replacement left behind after the one-way live-runtime handoff.
    ///
    /// Every [`Backend`] operation fails on this value. It deliberately carries no table-pool
    /// address/cursor, so the construction-window variable cannot remain a second allocator owner.
    const fn retired() -> Self {
        Self {
            physical_start: 0,
            virtual_start: 0,
            allocation_start: 0,
            next: 0,
            end: 0,
            free_head: 0,
        }
    }

    fn table_virtual(&self, table_phys: u64) -> Option<u64> {
        if table_phys & (PAGE_SIZE - 1) != 0 || table_phys < self.physical_start {
            return None;
        }
        let table_end = table_phys.checked_add(PAGE_SIZE)?;
        if table_end > self.end {
            return None;
        }
        let offset = table_phys.checked_sub(self.physical_start)?;
        self.virtual_start.checked_add(offset)
    }

    fn entry_virtual(&self, table_phys: u64, index: usize) -> Option<u64> {
        if index >= 512 {
            return None;
        }
        self.table_virtual(table_phys)?
            .checked_add((index as u64) * core::mem::size_of::<u64>() as u64)
    }

    fn runtime_allocated_table(&self, table_phys: u64) -> bool {
        table_phys & (PAGE_SIZE - 1) == 0
            && table_phys >= self.allocation_start
            && table_phys < self.next
            && table_phys
                .checked_add(PAGE_SIZE)
                .is_some_and(|end| end <= self.next)
    }

    fn allocated_runtime_pages(&self) -> Option<usize> {
        let bytes = self.next.checked_sub(self.allocation_start)?;
        usize::try_from(bytes / PAGE_SIZE).ok()
    }

    fn free_link(&self, table_phys: u64) -> Option<u64> {
        let address = self.entry_virtual(table_phys, 0)?;
        // SAFETY: entry_virtual confines this read to the live TTBR1 alias of one pool page.
        Some(unsafe { read_volatile(address as *const u64) })
    }

    fn free_chain_contains(&self, needle: u64) -> Option<bool> {
        let mut current = self.free_head;
        let limit = self.allocated_runtime_pages()?;
        for _ in 0..limit {
            if current == 0 {
                return Some(false);
            }
            if !self.runtime_allocated_table(current) {
                return None;
            }
            if current == needle {
                return Some(true);
            }
            let next = self.free_link(current)?;
            if next == current || (next != 0 && !self.runtime_allocated_table(next)) {
                return None;
            }
            current = next;
        }
        (current == 0).then_some(false)
    }

    fn free_chain_valid(&self) -> bool {
        self.free_chain_contains(u64::MAX).is_some()
    }

    fn table_is_empty(&self, table_phys: u64) -> bool {
        if !self.runtime_allocated_table(table_phys) {
            return false;
        }
        for index in 0..512 {
            let Some(address) = self.entry_virtual(table_phys, index) else {
                return false;
            };
            // SAFETY: entry_virtual confines this read to one validated pool table page.
            if unsafe { read_volatile(address as *const u64) } != 0 {
                return false;
            }
        }
        true
    }

    /// Validates and recycles one empty runtime-allocated table page for this unique pool owner.
    ///
    /// The unsafe terminal authority stays on [`Backend::release_table`]. This helper performs only
    /// the local ownership/free-chain/emptiness checks after that authority has already been proven by
    /// the caller. Bootstrap-owned pages before `allocation_start`, never-allocated pages at/after
    /// `next`, misaligned/foreign addresses, duplicate releases, corrupted free chains and non-empty
    /// tables are rejected without mutation. Allocation zeroes a recycled page before reuse.
    fn recycle_detached_empty_table(&mut self, table_phys: u64) -> bool {
        if !self.runtime_allocated_table(table_phys) || !self.free_chain_valid() {
            return false;
        }
        match self.free_chain_contains(table_phys) {
            Some(false) => {}
            Some(true) | None => return false,
        }
        if !self.table_is_empty(table_phys) {
            return false;
        }
        let Some(address) = self.entry_virtual(table_phys, 0) else {
            return false;
        };
        // SAFETY: the page was validated as runtime-owned, detached/empty and not already free.
        unsafe { write_volatile(address as *mut u64, self.free_head) };
        self.free_head = table_phys;
        true
    }

    /// Moves this exact construction-window cursor into the unique live-runtime owner.
    ///
    /// On success `self` is replaced by an inert backend, so there is never a second usable cursor.
    ///
    /// # Safety
    /// The caller must satisfy [`handoff_runtime_table_pool`]'s BSP/exclusive-construction contract.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn handoff_to_live(&mut self) -> Result<(), Error> {
        // SAFETY: delegated caller contract is exactly the free handoff primitive's contract.
        unsafe { handoff_runtime_table_pool(self) }
    }

    /// Executes one short operation through the unique live-runtime cursor after final protection.
    ///
    /// # Safety
    /// The caller must satisfy [`with_live_runtime_table_pool`]'s non-switching owner contract.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn with_live<R>(
        operation: impl FnOnce(&mut RuntimeTablePool) -> R,
    ) -> Result<R, Error> {
        // SAFETY: delegated caller contract is exactly the free borrow primitive's contract.
        unsafe { with_live_runtime_table_pool(operation) }
    }
}

impl Backend for RuntimeTablePool {
    fn allocate_zeroed_table(&mut self) -> Option<u64> {
        if self.free_head != 0 {
            if !self.free_chain_valid() {
                return None;
            }
            let physical = self.free_head;
            let next_free = self.free_link(physical)?;
            if next_free == physical || (next_free != 0 && !self.runtime_allocated_table(next_free))
            {
                return None;
            }
            let virtual_address = self.table_virtual(physical)?;
            // SAFETY: physical is a validated detached free-list member in the writable high alias.
            unsafe { write_bytes(virtual_address as *mut u8, 0, PAGE_SIZE as usize) };
            self.free_head = next_free;
            return Some(physical);
        }

        let physical = self.next;
        let next = physical.checked_add(PAGE_SIZE)?;
        if next > self.end {
            return None;
        }
        let virtual_address = self.table_virtual(physical)?;
        // SAFETY: the final TTBR1 regime maps the complete linker-owned table pool writable at the
        // deterministic high alias, and allocation advances monotonically through its unused tail.
        unsafe { write_bytes(virtual_address as *mut u8, 0, PAGE_SIZE as usize) };
        self.next = next;
        Some(physical)
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
        let address = self.entry_virtual(table_phys, index)?;
        // SAFETY: entry_virtual confines the read to the live TTBR1 alias of the table pool.
        Some(unsafe { read_volatile(address as *const u64) })
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
        let Some(address) = self.entry_virtual(table_phys, index) else {
            return false;
        };
        // SAFETY: entry_virtual confines the write to the live writable TTBR1 table-pool alias.
        unsafe { write_volatile(address as *mut u64, value) };
        true
    }

    unsafe fn release_table(&mut self, table_phys: u64) -> bool {
        self.recycle_detached_empty_table(table_phys)
    }
}

/// One-way owner cell for the exact post-proof page-table cursor.
///
/// Installation moves the existing [`RuntimeTablePool`] value; it never reconstructs a cursor from
/// addresses. Later users receive only serialized scoped mutable borrows. The state machine is
/// architecture-neutral so the ownership contract can be host-tested, while the global instance is
/// published only by the real AArch64 runtime.
struct LiveRuntimeTablePoolCell {
    state: AtomicU8,
    pool: UnsafeCell<MaybeUninit<RuntimeTablePool>>,
}

// SAFETY: LIVE_READY -> LIVE_BORROWED is the only path that exposes mutable access. Installation is
// one-shot and publishes the moved value with Release/Acquire ordering before any borrow can succeed.
unsafe impl Sync for LiveRuntimeTablePoolCell {}

impl LiveRuntimeTablePoolCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(LIVE_EMPTY),
            pool: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn install(&self, source: &mut RuntimeTablePool) -> Result<(), Error> {
        // Construction-window ownership has no valid recycle authority. Reject any pre-existing
        // recycle state before the live-cell state machine is touched, so a failed handoff is fully
        // retryable and cannot advance the release floor or strand the cell in INSTALLING.
        if source.free_head != 0 {
            return Err(Error::LiveInvalidState);
        }

        match self.state.compare_exchange(
            LIVE_EMPTY,
            LIVE_INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(LIVE_INSTALLING | LIVE_READY) => return Err(Error::LiveAlreadyInstalled),
            Err(LIVE_BORROWED) => return Err(Error::LiveBusy),
            Err(_) => return Err(Error::LiveInvalidState),
        }

        // Seal the releasable live range only now, after every Step7-14 construction
        // allocation is complete. Pre-live proof tables stay permanently below the floor.
        source.allocation_start = source.next;

        // Move, do not copy, the unique monotonic cursor. The caller's construction-window backend is
        // immediately replaced by a value on which every Backend operation fails.
        let owned = replace(source, RuntimeTablePool::retired());
        // SAFETY: successful EMPTY -> INSTALLING gives this path unique initialization ownership.
        unsafe { (*self.pool.get()).write(owned) };
        self.state.store(LIVE_READY, Ordering::Release);
        Ok(())
    }

    unsafe fn with_pool<R>(
        &self,
        operation: impl FnOnce(&mut RuntimeTablePool) -> R,
    ) -> Result<R, Error> {
        match self.state.compare_exchange(
            LIVE_READY,
            LIVE_BORROWED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(LIVE_EMPTY | LIVE_INSTALLING) => return Err(Error::LiveUnavailable),
            Err(LIVE_BORROWED) => return Err(Error::LiveBusy),
            Err(_) => return Err(Error::LiveInvalidState),
        }

        // SAFETY: LIVE_BORROWED is exclusive mutable ownership and READY proves initialization.
        let pool = unsafe { (&mut *self.pool.get()).assume_init_mut() };
        let result = operation(pool);
        self.state.store(LIVE_READY, Ordering::Release);
        Ok(result)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static LIVE_RUNTIME_TABLE_POOL: LiveRuntimeTablePoolCell = LiveRuntimeTablePoolCell::new();

/// Claims the unused Step-6 page-table pool tail for the BSP Step-7/Step-8 runtime proofs.
///
/// # Safety
/// The caller must be the single BSP owner with interrupts and migration controlled after every PE
/// has retired temporary TTBR0 and the BSP has published the table-pool construction phase. The
/// claim is one-shot because handing out two independent cursors would permit duplicate allocation
/// of the same page-table frame. Secondary PEs remain blocked until the caller dismantles temporary
/// user roots and the runtime publishes its later global release state.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn claim_runtime_table_pool() -> Result<RuntimeTablePool, Error> {
    if !crate::runtime::runtime_table_pool_claim_ready() {
        return Err(Error::RuntimeNotProtected);
    }
    if CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(Error::AlreadyClaimed);
    }
    let state = crate::boot_state();
    RuntimeTablePool::new(state.layout, state.table_pages_used)
}

/// Moves the exact construction-window table cursor into the single live-runtime owner.
///
/// This is intentionally a one-way handoff. On success `source` becomes inert and must not be used as
/// a backend again. The live owner becomes borrowable only after the outer protected-runtime barrier
/// publishes final readiness, so the callback cannot use this API to start live Linux page-table
/// mutation while secondary PEs are still held in the construction rendezvous.
///
/// # Safety
/// The caller must be the IRQ-masked BSP that exclusively owns `source` after every Step-7 through
/// Step-14 construction/proof use is complete. No references into `source` or data borrowed from it may
/// survive this call. This must execute before `enter_runtime_protected_regime()` publishes final
/// runtime readiness and before any live Linux thread can run.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn handoff_runtime_table_pool(source: &mut RuntimeTablePool) -> Result<(), Error> {
    if !crate::runtime::runtime_table_pool_claim_ready() {
        return Err(Error::RuntimeNotProtected);
    }
    if crate::runtime::runtime_protected_regime_ready() {
        return Err(Error::LiveHandoffTooLate);
    }
    LIVE_RUNTIME_TABLE_POOL.install(source)
}

/// Executes one short live-runtime page-table operation through the unique handed-off cursor.
///
/// The borrow exists only for `operation` and concurrent/nested access fails closed as [`Error::LiveBusy`].
/// It is unavailable until the global protected runtime has completed. This is the backend boundary
/// intended for later Linux `mmap`/`munmap`/`brk` calls after the initial process has started.
///
/// # Safety
/// The caller must own the local scheduler/address-space mutation window with IRQ/preemption/migration
/// reentrancy closed. `operation` must not context-switch, block, retain `&mut RuntimeTablePool`, or
/// expose references derived from it after returning. A potentially blocking FUTEX/clone/exit path
/// must end this borrow before changing scheduler state.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn with_live_runtime_table_pool<R>(
    operation: impl FnOnce(&mut RuntimeTablePool) -> R,
) -> Result<R, Error> {
    if !crate::runtime::runtime_protected_regime_ready() {
        return Err(Error::LiveUnavailable);
    }
    // SAFETY: delegated caller contract supplies the non-switching owner window; the cell supplies
    // exclusive mutable access to the moved cursor.
    unsafe { LIVE_RUNTIME_TABLE_POOL.with_pool(operation) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4096))]
    struct TestTablePages([u8; PAGE_SIZE as usize * 4]);

    fn sample_pool(next: u64) -> RuntimeTablePool {
        RuntimeTablePool {
            physical_start: 0x1000,
            virtual_start: 0xffff_0000_0000_1000,
            allocation_start: 0x3000,
            next,
            end: 0x9000,
            free_head: 0,
        }
    }

    fn backed_construction_pool(backing: &mut TestTablePages) -> RuntimeTablePool {
        RuntimeTablePool {
            physical_start: 0x1000,
            virtual_start: backing.0.as_mut_ptr() as u64,
            allocation_start: 0x5000,
            next: 0x2000,
            end: 0x5000,
            free_head: 0,
        }
    }

    #[test]
    fn handoff_moves_cursor_and_retires_source() {
        let cell = LiveRuntimeTablePoolCell::new();
        let mut source = sample_pool(0x4000);

        cell.install(&mut source).unwrap();
        assert_eq!(source.physical_start, 0);
        assert_eq!(source.virtual_start, 0);
        assert_eq!(source.allocation_start, 0);
        assert_eq!(source.next, 0);
        assert_eq!(source.end, 0);
        assert_eq!(source.free_head, 0);
        assert_eq!(source.allocate_zeroed_table(), None);

        let observed = unsafe {
            cell.with_pool(|pool| (pool.allocation_start, pool.next, pool.end, pool.free_head))
        }
        .unwrap();
        assert_eq!(observed, (0x4000, 0x4000, 0x9000, 0));
    }

    #[test]
    fn dirty_recycle_state_rejects_handoff_before_cell_transition() {
        let cell = LiveRuntimeTablePoolCell::new();
        let mut source = sample_pool(0x4000);
        source.free_head = 0x3000;

        assert_eq!(cell.install(&mut source), Err(Error::LiveInvalidState));
        assert_eq!(cell.state.load(Ordering::Acquire), LIVE_EMPTY);
        assert_eq!(source.allocation_start, 0x3000);
        assert_eq!(source.next, 0x4000);
        assert_eq!(source.free_head, 0x3000);
    }

    #[test]
    fn pre_live_table_is_below_release_floor_but_live_tables_reuse() {
        let mut backing = TestTablePages([0; PAGE_SIZE as usize * 4]);
        let cell = LiveRuntimeTablePoolCell::new();
        let mut source = backed_construction_pool(&mut backing);
        let pre_live = source.allocate_zeroed_table().unwrap();
        assert_eq!(pre_live, 0x2000);

        cell.install(&mut source).unwrap();
        let observed = unsafe {
            cell.with_pool(|pool| {
                let pre_live_rejected =
                    unsafe { <RuntimeTablePool as Backend>::release_table(pool, pre_live) };
                let live = pool.allocate_zeroed_table().unwrap();
                let released = unsafe { <RuntimeTablePool as Backend>::release_table(pool, live) };
                let reused = pool.allocate_zeroed_table().unwrap();
                (
                    pool.allocation_start,
                    pre_live_rejected,
                    live,
                    released,
                    reused,
                )
            })
        }
        .unwrap();

        assert_eq!(observed.0, 0x3000);
        assert!(!observed.1);
        assert_eq!(observed.2, 0x3000);
        assert!(observed.3);
        assert_eq!(observed.4, 0x3000);
    }

    #[test]
    fn duplicate_handoff_preserves_second_source() {
        let cell = LiveRuntimeTablePoolCell::new();
        let mut first = sample_pool(0x4000);
        let mut second = sample_pool(0x5000);
        cell.install(&mut first).unwrap();

        assert_eq!(cell.install(&mut second), Err(Error::LiveAlreadyInstalled));
        assert_eq!(second.allocation_start, 0x3000);
        assert_eq!(second.next, 0x5000);
        assert_eq!(second.end, 0x9000);
        assert_eq!(second.free_head, 0);
    }

    #[test]
    fn borrow_requires_install_and_is_serialized() {
        let cell = LiveRuntimeTablePoolCell::new();
        assert_eq!(
            unsafe { cell.with_pool(|_| ()) },
            Err(Error::LiveUnavailable)
        );

        let mut source = sample_pool(0x4000);
        cell.install(&mut source).unwrap();
        let state = &cell.state;
        let result = unsafe {
            cell.with_pool(|_| {
                assert_eq!(state.load(Ordering::Acquire), LIVE_BORROWED);
            })
        };
        assert_eq!(result, Ok(()));
        assert_eq!(cell.state.load(Ordering::Acquire), LIVE_READY);
    }
}
