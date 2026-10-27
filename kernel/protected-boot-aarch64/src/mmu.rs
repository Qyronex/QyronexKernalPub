// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::ptr::{read_volatile, write_bytes, write_volatile};
use kernal_fdt_aarch64::MmioRegion;
#[cfg(target_arch = "aarch64")]
use kernal_page_table_aarch64::invalidate_all_el1;
use kernal_page_table_aarch64::{Backend, Error as PageTableError, Mapper, MemoryType};
use kernal_paging::{page_indexes, MapFlags, PAGE_SIZE};

const MAX_BOOT_MMIO_PAGES: u64 = 16 * 1024;
const MIN_BOOT_TABLE_PAGES: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageRange {
    pub start: u64,
    pub end: u64,
}

impl PageRange {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub fn len(self) -> Result<u64, Error> {
        self.end.checked_sub(self.start).ok_or(Error::InvalidLayout)
    }

    pub fn contains(self, address: u64) -> bool {
        self.start <= address && address < self.end
    }

    fn validate(self) -> Result<(), Error> {
        if self.start >= self.end
            || self.start & (PAGE_SIZE - 1) != 0
            || self.end & (PAGE_SIZE - 1) != 0
        {
            return Err(Error::InvalidLayout);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapLayout {
    pub kernel_phys_base: u64,
    pub kernel_virt_base: u64,
    pub text: PageRange,
    pub rodata: PageRange,
    pub data: PageRange,
    pub bss: PageRange,
    pub boot_guard: PageRange,
    pub secondary_stacks: PageRange,
    pub secondary_stack_stride: u64,
    pub stack_guard_size: u64,
    pub worker_guard: PageRange,
    pub page_tables: PageRange,
}

impl BootstrapLayout {
    pub fn validate(self) -> Result<Self, Error> {
        for range in [
            self.text,
            self.rodata,
            self.data,
            self.bss,
            self.boot_guard,
            self.secondary_stacks,
            self.worker_guard,
            self.page_tables,
        ] {
            range.validate()?;
        }

        if self.kernel_phys_base != self.text.start
            || self.text.end > self.rodata.start
            || self.rodata.end > self.data.start
            || self.data.end > self.bss.start
            || self.secondary_stack_stride == 0
            || self.secondary_stack_stride & (PAGE_SIZE - 1) != 0
            || self.stack_guard_size == 0
            || self.stack_guard_size & (PAGE_SIZE - 1) != 0
            || self.stack_guard_size >= self.secondary_stack_stride
        {
            return Err(Error::InvalidLayout);
        }

        let secondary_len = self.secondary_stacks.len()?;
        if secondary_len % self.secondary_stack_stride != 0 {
            return Err(Error::InvalidLayout);
        }

        for range in [
            self.boot_guard,
            self.secondary_stacks,
            self.worker_guard,
            self.page_tables,
        ] {
            if !contains_range(self.bss, range) {
                return Err(Error::InvalidLayout);
            }
        }

        if ranges_overlap(self.page_tables, self.boot_guard)
            || ranges_overlap(self.page_tables, self.secondary_stacks)
            || ranges_overlap(self.page_tables, self.worker_guard)
        {
            return Err(Error::InvalidLayout);
        }
        for index in 0..self.secondary_stack_count()? {
            if ranges_overlap(self.page_tables, self.secondary_guard(index)?) {
                return Err(Error::InvalidLayout);
            }
        }

        if self.page_tables.len()? < MIN_BOOT_TABLE_PAGES * PAGE_SIZE {
            return Err(Error::PageTablePoolTooSmall);
        }

        page_indexes(self.kernel_virt_base).map_err(PageTableError::from)?;
        let final_kernel_page = self
            .bss
            .end
            .checked_sub(PAGE_SIZE)
            .ok_or(Error::AddressOverflow)?;
        self.high_alias(final_kernel_page)?;
        self.high_alias(self.bss.end)?;

        Ok(self)
    }

    pub fn secondary_stack_count(self) -> Result<usize, Error> {
        let count = self.secondary_stacks.len()? / self.secondary_stack_stride;
        usize::try_from(count).map_err(|_| Error::AddressOverflow)
    }

    pub fn secondary_guard(self, index: usize) -> Result<PageRange, Error> {
        let index = u64::try_from(index).map_err(|_| Error::AddressOverflow)?;
        let offset = index
            .checked_mul(self.secondary_stack_stride)
            .ok_or(Error::AddressOverflow)?;
        let start = self
            .secondary_stacks
            .start
            .checked_add(offset)
            .ok_or(Error::AddressOverflow)?;
        let end = start
            .checked_add(self.stack_guard_size)
            .ok_or(Error::AddressOverflow)?;
        if end > self.secondary_stacks.end {
            return Err(Error::InvalidLayout);
        }
        Ok(PageRange::new(start, end))
    }

    pub fn high_alias(self, physical_address: u64) -> Result<u64, Error> {
        let offset = physical_address
            .checked_sub(self.kernel_phys_base)
            .ok_or(Error::InvalidLayout)?;
        let virtual_address = self
            .kernel_virt_base
            .checked_add(offset)
            .ok_or(Error::AddressOverflow)?;
        page_indexes(virtual_address & !(PAGE_SIZE - 1)).map_err(PageTableError::from)?;
        Ok(virtual_address)
    }

    /// Converts a canonical high-half kernel-image address back to its physical image address. The
    /// conversion is deliberately bounded to `[kernel_phys_base, bss.end)` so high MMIO aliases or
    /// unrelated upper-half addresses cannot be mistaken for firmware physical entry points.
    pub fn physical_from_high_kernel_alias(self, virtual_address: u64) -> Result<u64, Error> {
        let offset = virtual_address
            .checked_sub(self.kernel_virt_base)
            .ok_or(Error::InvalidKernelAlias)?;
        let physical = self
            .kernel_phys_base
            .checked_add(offset)
            .ok_or(Error::AddressOverflow)?;
        if physical < self.kernel_phys_base || physical >= self.bss.end {
            return Err(Error::InvalidKernelAlias);
        }
        Ok(physical)
    }

    /// Returns a physical, 4-byte-aligned `.text` entry suitable for PSCI `CPU_ON`, accepting
    /// either the original physical linker address or its canonical high-half alias.
    pub fn physical_text_entry(self, address: u64) -> Result<u64, Error> {
        let physical = if self.text.contains(address) {
            address
        } else {
            self.physical_from_high_kernel_alias(address)?
        };
        if !self.text.contains(physical) || physical & 3 != 0 {
            return Err(Error::InvalidTextEntry);
        }
        Ok(physical)
    }

    /// Converts a linker-owned physical page range into the corresponding high-half range. This is
    /// used for persisted stack/context metadata after a PE has crossed into TTBR1.
    pub fn high_range(self, physical: PageRange) -> Result<PageRange, Error> {
        physical.validate()?;
        if physical.start < self.kernel_phys_base || physical.end > self.bss.end {
            return Err(Error::InvalidLayout);
        }
        Ok(PageRange::new(
            self.high_alias(physical.start)?,
            self.high_alias(physical.end)?,
        ))
    }

    fn is_guard_page(self, physical_page: u64) -> Result<bool, Error> {
        if self.boot_guard.contains(physical_page) || self.worker_guard.contains(physical_page) {
            return Ok(true);
        }
        for index in 0..self.secondary_stack_count()? {
            if self.secondary_guard(index)?.contains(physical_page) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioAlias {
    pub physical: MmioRegion,
    pub virtual_region: MmioRegion,
}

const EMPTY_MMIO_ALIAS: MmioAlias = MmioAlias {
    physical: MmioRegion { base: 0, size: 0 },
    virtual_region: MmioRegion { base: 0, size: 0 },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    PageTable(PageTableError),
    InvalidLayout,
    AddressOverflow,
    PageTablePoolTooSmall,
    PageTablePoolExhausted,
    InvalidMmioRegion,
    MmioRegionTooLarge,
    GuardMapped,
    IdentityAliasMissing,
    InvalidKernelAlias,
    InvalidTextEntry,
}

impl From<PageTableError> for Error {
    fn from(value: PageTableError) -> Self {
        Self::PageTable(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedBootstrap {
    pub root_table: u64,
    pub table_pages_used: usize,
}

/// Computes deterministic high-half aliases for DTB-discovered MMIO apertures. The aliases begin at
/// the first page after the high-half kernel image and are packed page-by-page, so Step 6 does not
/// invent a second permanent virtual-layout constant. Returned region bases preserve each physical
/// aperture's original in-page offset.
pub fn plan_mmio_aliases<const N: usize>(
    layout: BootstrapLayout,
    mmio_regions: &[MmioRegion; N],
) -> Result<[MmioAlias; N], Error> {
    let layout = layout.validate()?;
    let mut cursor = layout.high_alias(layout.bss.end)?;
    let mut aliases = [EMPTY_MMIO_ALIAS; N];

    for (index, region) in mmio_regions.iter().copied().enumerate() {
        let (alias, next) = plan_mmio_alias_at(cursor, region)?;
        aliases[index] = alias;
        cursor = next;
    }
    Ok(aliases)
}

/// Builds the Step-6 kernel mappings into an already allocated root table.
///
/// Kernel pages receive both their temporary physical identity alias and their canonical high-half
/// alias. The identity alias exists only for the bounded MMU transition and is removed after every
/// PE has moved PC/SP/device access high. Stack guards are skipped in both aliases. Each validated
/// device aperture gets a temporary identity Device-nGnRE mapping plus a deterministic high-half
/// Device alias, allowing TTBR0 to be retired without cutting off PL011/GIC access.
pub fn map_step6_layout<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    layout: BootstrapLayout,
    mmio_regions: &[MmioRegion],
) -> Result<(), Error> {
    let layout = layout.validate()?;

    map_kernel_range(mapper, layout, layout.text, MapFlags::READ.union(MapFlags::EXECUTE))?;
    map_kernel_range(mapper, layout, layout.rodata, MapFlags::READ)?;
    map_kernel_range(mapper, layout, layout.data, MapFlags::WRITE)?;

    let mut page = layout.bss.start;
    while page < layout.bss.end {
        if !layout.is_guard_page(page)? {
            map_kernel_page(mapper, layout, page, MapFlags::WRITE)?;
        }
        page = page.checked_add(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    }

    let mut cursor = layout.high_alias(layout.bss.end)?;
    for region in mmio_regions.iter().copied() {
        let (alias, next) = plan_mmio_alias_at(cursor, region)?;
        map_mmio_region(mapper, alias)?;
        cursor = next;
    }

    verify_guard_holes(mapper, layout)?;
    Ok(())
}

/// Removes every temporary TTBR0 identity leaf created by `map_step6_layout` while retaining the
/// high-half kernel and device mappings. This operation is architecture-neutral so host tests can
/// prove the global table mutation before the AArch64 BSP publishes it with a broadcast TLBI.
pub fn unmap_step6_identity_aliases<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    layout: BootstrapLayout,
    mmio_regions: &[MmioRegion],
) -> Result<(), Error> {
    let layout = layout.validate()?;
    unmap_identity_range(mapper, layout.text)?;
    unmap_identity_range(mapper, layout.rodata)?;
    unmap_identity_range(mapper, layout.data)?;

    let mut page = layout.bss.start;
    while page < layout.bss.end {
        if !layout.is_guard_page(page)? {
            unmap_identity_page(mapper, page)?;
        }
        page = page.checked_add(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    }

    for region in mmio_regions.iter().copied() {
        let (start, end, _) = mmio_page_bounds(region)?;
        let mut page = start;
        while page < end {
            unmap_identity_page(mapper, page)?;
            page = page.checked_add(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
        }
    }
    Ok(())
}

fn map_kernel_range<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    layout: BootstrapLayout,
    range: PageRange,
    flags: MapFlags,
) -> Result<(), Error> {
    let mut page = range.start;
    while page < range.end {
        map_kernel_page(mapper, layout, page, flags)?;
        page = page.checked_add(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    }
    Ok(())
}

fn map_kernel_page<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    layout: BootstrapLayout,
    physical_page: u64,
    flags: MapFlags,
) -> Result<(), Error> {
    mapper.map_page(physical_page, physical_page, flags)?;
    let high = layout.high_alias(physical_page)?;
    if high != physical_page {
        mapper.map_page(high, physical_page, flags)?;
    }
    Ok(())
}

fn map_mmio_region<B: Backend>(mapper: &mut Mapper<'_, B>, alias: MmioAlias) -> Result<(), Error> {
    let (physical_start, physical_end, offset) = mmio_page_bounds(alias.physical)?;
    let virtual_start = alias
        .virtual_region
        .base
        .checked_sub(offset)
        .ok_or(Error::AddressOverflow)?;
    let mapped_len = physical_end
        .checked_sub(physical_start)
        .ok_or(Error::AddressOverflow)?;
    let virtual_end = virtual_start
        .checked_add(mapped_len)
        .ok_or(Error::AddressOverflow)?;
    validate_virtual_page_span(virtual_start, virtual_end)?;

    let mut physical_page = physical_start;
    let mut virtual_page = virtual_start;
    while physical_page < physical_end {
        mapper.map_page_with_type(
            physical_page,
            physical_page,
            MapFlags::WRITE,
            MemoryType::DeviceNgnre,
        )?;
        mapper.map_page_with_type(
            virtual_page,
            physical_page,
            MapFlags::WRITE,
            MemoryType::DeviceNgnre,
        )?;
        physical_page = physical_page
            .checked_add(PAGE_SIZE)
            .ok_or(Error::AddressOverflow)?;
        virtual_page = virtual_page
            .checked_add(PAGE_SIZE)
            .ok_or(Error::AddressOverflow)?;
    }
    Ok(())
}

fn plan_mmio_alias_at(cursor: u64, region: MmioRegion) -> Result<(MmioAlias, u64), Error> {
    let (physical_start, physical_end, offset) = mmio_page_bounds(region)?;
    if cursor & (PAGE_SIZE - 1) != 0 {
        return Err(Error::InvalidLayout);
    }
    let mapped_len = physical_end
        .checked_sub(physical_start)
        .ok_or(Error::AddressOverflow)?;
    let next = cursor
        .checked_add(mapped_len)
        .ok_or(Error::AddressOverflow)?;
    validate_virtual_page_span(cursor, next)?;
    let virtual_base = cursor.checked_add(offset).ok_or(Error::AddressOverflow)?;
    Ok((
        MmioAlias {
            physical: region,
            virtual_region: MmioRegion {
                base: virtual_base,
                size: region.size,
            },
        },
        next,
    ))
}

fn mmio_page_bounds(region: MmioRegion) -> Result<(u64, u64, u64), Error> {
    if region.base == 0 || region.size == 0 {
        return Err(Error::InvalidMmioRegion);
    }
    let start = region.base & !(PAGE_SIZE - 1);
    let offset = region.base.checked_sub(start).ok_or(Error::AddressOverflow)?;
    let raw_end = region
        .base
        .checked_add(region.size)
        .ok_or(Error::AddressOverflow)?;
    let end = raw_end
        .checked_add(PAGE_SIZE - 1)
        .ok_or(Error::AddressOverflow)?
        & !(PAGE_SIZE - 1);
    let pages = end
        .checked_sub(start)
        .ok_or(Error::AddressOverflow)?
        / PAGE_SIZE;
    if pages == 0 || pages > MAX_BOOT_MMIO_PAGES {
        return Err(Error::MmioRegionTooLarge);
    }
    Ok((start, end, offset))
}

fn validate_virtual_page_span(start: u64, end: u64) -> Result<(), Error> {
    if start & (PAGE_SIZE - 1) != 0 || end <= start || end & (PAGE_SIZE - 1) != 0 {
        return Err(Error::InvalidLayout);
    }
    page_indexes(start).map_err(PageTableError::from)?;
    let last = end.checked_sub(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    page_indexes(last).map_err(PageTableError::from)?;
    Ok(())
}

fn unmap_identity_range<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    range: PageRange,
) -> Result<(), Error> {
    let mut page = range.start;
    while page < range.end {
        unmap_identity_page(mapper, page)?;
        page = page.checked_add(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    }
    Ok(())
}

fn unmap_identity_page<B: Backend>(mapper: &mut Mapper<'_, B>, page: u64) -> Result<(), Error> {
    let physical = mapper.unmap_page(page)?;
    if physical != page {
        return Err(Error::IdentityAliasMissing);
    }
    Ok(())
}

pub fn verify_guard_holes<B: Backend>(
    mapper: &Mapper<'_, B>,
    layout: BootstrapLayout,
) -> Result<(), Error> {
    let layout = layout.validate()?;
    verify_unmapped_range(mapper, layout, layout.boot_guard)?;
    verify_unmapped_range(mapper, layout, layout.worker_guard)?;
    for index in 0..layout.secondary_stack_count()? {
        verify_unmapped_range(mapper, layout, layout.secondary_guard(index)?)?;
    }
    Ok(())
}

fn verify_unmapped_range<B: Backend>(
    mapper: &Mapper<'_, B>,
    layout: BootstrapLayout,
    range: PageRange,
) -> Result<(), Error> {
    let mut page = range.start;
    while page < range.end {
        if !matches!(mapper.translate(page), Err(PageTableError::NotMapped)) {
            return Err(Error::GuardMapped);
        }
        let high = layout.high_alias(page)?;
        if !matches!(mapper.translate(high), Err(PageTableError::NotMapped)) {
            return Err(Error::GuardMapped);
        }
        page = page.checked_add(PAGE_SIZE).ok_or(Error::AddressOverflow)?;
    }
    Ok(())
}

const fn contains_range(outer: PageRange, inner: PageRange) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

const fn ranges_overlap(left: PageRange, right: PageRange) -> bool {
    left.start < right.end && right.start < left.end
}

#[cfg(target_arch = "aarch64")]
pub struct PhysicalTablePool {
    start: u64,
    next: u64,
    end: u64,
}

#[cfg(target_arch = "aarch64")]
impl PhysicalTablePool {
    /// # Safety
    /// `range` must be linker-owned, page-aligned RAM that is exclusively reserved for bootstrap
    /// page tables and directly accessible while Stage-1 translation is disabled.
    pub unsafe fn new(range: PageRange) -> Result<Self, Error> {
        range.validate()?;
        if range.len()? < MIN_BOOT_TABLE_PAGES * PAGE_SIZE {
            return Err(Error::PageTablePoolTooSmall);
        }
        Ok(Self {
            start: range.start,
            next: range.start,
            end: range.end,
        })
    }

    pub fn used_pages(&self) -> Result<usize, Error> {
        let bytes = self
            .next
            .checked_sub(self.start)
            .ok_or(Error::AddressOverflow)?;
        usize::try_from(bytes / PAGE_SIZE).map_err(|_| Error::AddressOverflow)
    }

    fn entry_address(&self, table_phys: u64, index: usize) -> Option<u64> {
        if index >= 512 || table_phys & (PAGE_SIZE - 1) != 0 || table_phys < self.start {
            return None;
        }
        let table_end = table_phys.checked_add(PAGE_SIZE)?;
        if table_end > self.end {
            return None;
        }
        table_phys.checked_add((index as u64) * 8)
    }
}

#[cfg(target_arch = "aarch64")]
impl Backend for PhysicalTablePool {
    fn allocate_zeroed_table(&mut self) -> Option<u64> {
        let table = self.next;
        let next = table.checked_add(PAGE_SIZE)?;
        if next > self.end {
            return None;
        }
        // SAFETY: constructor ownership guarantees this page is reserved table RAM, and allocation
        // advances monotonically so no live table is zeroed twice.
        unsafe { write_bytes(table as *mut u8, 0, PAGE_SIZE as usize) };
        self.next = next;
        Some(table)
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
        let address = self.entry_address(table_phys, index)?;
        // SAFETY: entry_address confines the read to the exclusively owned table pool.
        Some(unsafe { read_volatile(address as *const u64) })
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
        let Some(address) = self.entry_address(table_phys, index) else {
            return false;
        };
        // SAFETY: entry_address confines the write to the exclusively owned table pool.
        unsafe { write_volatile(address as *mut u64, value) };
        true
    }
}

#[cfg(target_arch = "aarch64")]
struct HighTableView {
    physical: PageRange,
    virtual_start: u64,
}

#[cfg(target_arch = "aarch64")]
impl HighTableView {
    /// # Safety
    /// The current TTBR1 root must map `layout.page_tables` through `layout.high_alias` as writable
    /// Normal memory. The low identity aliases may already be absent because all table accesses from
    /// this view are performed through the high-half alias.
    unsafe fn new(layout: BootstrapLayout) -> Result<Self, Error> {
        let layout = layout.validate()?;
        Ok(Self {
            physical: layout.page_tables,
            virtual_start: layout.high_alias(layout.page_tables.start)?,
        })
    }

    fn entry_address(&self, table_phys: u64, index: usize) -> Option<u64> {
        if index >= 512 || table_phys & (PAGE_SIZE - 1) != 0 || table_phys < self.physical.start {
            return None;
        }
        let table_end = table_phys.checked_add(PAGE_SIZE)?;
        if table_end > self.physical.end {
            return None;
        }
        let offset = table_phys.checked_sub(self.physical.start)?;
        self.virtual_start
            .checked_add(offset)?
            .checked_add((index as u64) * 8)
    }
}

#[cfg(target_arch = "aarch64")]
impl Backend for HighTableView {
    fn allocate_zeroed_table(&mut self) -> Option<u64> {
        None
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
        let address = self.entry_address(table_phys, index)?;
        // SAFETY: constructor contract keeps the complete page-table pool mapped through TTBR1.
        Some(unsafe { read_volatile(address as *const u64) })
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
        let Some(address) = self.entry_address(table_phys, index) else {
            return false;
        };
        // SAFETY: constructor contract keeps the complete page-table pool writable through TTBR1.
        unsafe { write_volatile(address as *mut u64, value) };
        true
    }
}

/// Materializes a complete Step-6 table set in the linker-owned physical table pool.
///
/// # Safety
/// - Stage-1 translation must still be disabled on the calling PE,
/// - all layout physical ranges must describe the currently loaded kernel image,
/// - `layout.page_tables` must satisfy `PhysicalTablePool::new`,
/// - MMIO regions must come from the already validated platform description.
#[cfg(target_arch = "aarch64")]
pub unsafe fn prepare_step6_tables(
    layout: BootstrapLayout,
    mmio_regions: &[MmioRegion],
) -> Result<PreparedBootstrap, Error> {
    let layout = layout.validate()?;
    // SAFETY: upheld by this function's caller contract and revalidated above.
    let mut backend = unsafe { PhysicalTablePool::new(layout.page_tables)? };
    let root = backend
        .allocate_zeroed_table()
        .ok_or(Error::PageTablePoolExhausted)?;
    {
        let mut mapper = Mapper::new(&mut backend, root)?;
        map_step6_layout(&mut mapper, layout, mmio_regions)?;
    }
    Ok(PreparedBootstrap {
        root_table: root,
        table_pages_used: backend.used_pages()?,
    })
}

/// BSP-owned global phase: removes all shared low aliases through a high-half view of the bootstrap
/// tables and broadcast-invalidates EL1 translations. This function never modifies PE-local TTBR0
/// or TCR state; every PE finalizes those registers separately after this global phase completes.
///
/// # Safety
/// - every expected PE must already execute entirely through TTBR1 high-half aliases and be held at
///   the high-transition barrier with interrupts masked,
/// - `root_table` must be the active shared root created by `prepare_step6_tables`,
/// - all live MMIO pointers on every PE must already use their high-half aliases,
/// - exactly one global owner may execute this operation for a given transition.
#[cfg(target_arch = "aarch64")]
pub unsafe fn remove_step6_low_aliases(
    root_table: u64,
    layout: BootstrapLayout,
    mmio_regions: &[MmioRegion],
) -> Result<(), Error> {
    let layout = layout.validate()?;
    // SAFETY: guaranteed by this function's caller contract.
    let mut backend = unsafe { HighTableView::new(layout)? };
    {
        let mut mapper = Mapper::new(&mut backend, root_table)?;
        unmap_step6_identity_aliases(&mut mapper, layout, mmio_regions)?;
    }
    // SAFETY: the single global owner has published all shared leaf removals while every PE is
    // quiesced high. Broadcast invalidation completes before any PE may finalize TTBR0 locally.
    unsafe { invalidate_all_el1() };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const MOCK_TABLE_BASE: u64 = 0x0100_0000;

    struct MockBackend {
        tables: Vec<[u64; 512]>,
        used: usize,
    }

    impl MockBackend {
        fn new(count: usize) -> Self {
            Self {
                tables: vec![[0; 512]; count],
                used: 0,
            }
        }

        fn table_index(&self, physical: u64) -> Option<usize> {
            let offset = physical.checked_sub(MOCK_TABLE_BASE)?;
            if offset & (PAGE_SIZE - 1) != 0 {
                return None;
            }
            let index = usize::try_from(offset / PAGE_SIZE).ok()?;
            (index < self.tables.len()).then_some(index)
        }
    }

    impl Backend for MockBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            if self.used == self.tables.len() {
                return None;
            }
            let index = self.used;
            self.tables[index] = [0; 512];
            self.used += 1;
            Some(MOCK_TABLE_BASE + index as u64 * PAGE_SIZE)
        }

        fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
            self.tables
                .get(self.table_index(table_phys)?)?
                .get(index)
                .copied()
        }

        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let Some(table) = self.table_index(table_phys) else {
                return false;
            };
            let Some(entry) = self.tables[table].get_mut(index) else {
                return false;
            };
            *entry = value;
            true
        }
    }

    fn layout() -> BootstrapLayout {
        BootstrapLayout {
            kernel_phys_base: 0x4020_0000,
            kernel_virt_base: 0xffff_ffff_8020_0000,
            text: PageRange::new(0x4020_0000, 0x4020_2000),
            rodata: PageRange::new(0x4020_2000, 0x4020_4000),
            data: PageRange::new(0x4020_4000, 0x4020_6000),
            bss: PageRange::new(0x4020_6000, 0x4028_0000),
            boot_guard: PageRange::new(0x4020_6000, 0x4020_7000),
            secondary_stacks: PageRange::new(0x4021_7000, 0x4023_9000),
            secondary_stack_stride: 0x1_1000,
            stack_guard_size: PAGE_SIZE,
            worker_guard: PageRange::new(0x4023_9000, 0x4023_a000),
            page_tables: PageRange::new(0x4024_0000, 0x4026_0000),
        }
    }

    #[test]
    fn maps_identity_and_high_half_while_leaving_guards_absent() {
        let layout = layout().validate().unwrap();
        let mut backend = MockBackend::new(64);
        let root = backend.allocate_zeroed_table().unwrap();
        let mut mapper = Mapper::new(&mut backend, root).unwrap();
        let mmio = [MmioRegion {
            base: 0x0900_0000,
            size: PAGE_SIZE,
        }];
        let aliases = plan_mmio_aliases(layout, &mmio).unwrap();

        map_step6_layout(&mut mapper, layout, &mmio).unwrap();

        assert_eq!(mapper.translate(layout.text.start).unwrap(), layout.text.start);
        assert_eq!(
            mapper
                .translate(layout.high_alias(layout.text.start).unwrap())
                .unwrap(),
            layout.text.start
        );
        assert_eq!(mapper.translate(layout.data.start).unwrap(), layout.data.start);
        assert_eq!(mapper.translate(mmio[0].base).unwrap(), mmio[0].base);
        assert_eq!(
            mapper.translate(aliases[0].virtual_region.base).unwrap(),
            mmio[0].base
        );
        assert_eq!(mapper.translate(0), Err(PageTableError::NullPage));
        verify_guard_holes(&mapper, layout).unwrap();
    }

    #[test]
    fn high_kernel_alias_conversion_is_bounded_and_psci_entry_is_physical() {
        let layout = layout().validate().unwrap();
        let physical_entry = layout.text.start + 0x100;
        let high_entry = layout.high_alias(physical_entry).unwrap();
        assert_eq!(
            layout.physical_from_high_kernel_alias(high_entry).unwrap(),
            physical_entry
        );
        assert_eq!(layout.physical_text_entry(physical_entry).unwrap(), physical_entry);
        assert_eq!(layout.physical_text_entry(high_entry).unwrap(), physical_entry);
        assert_eq!(
            layout.physical_text_entry(layout.high_alias(layout.data.start).unwrap()),
            Err(Error::InvalidTextEntry)
        );
        assert_eq!(
            layout.physical_text_entry(high_entry + 1),
            Err(Error::InvalidTextEntry)
        );
        assert_eq!(
            layout.physical_from_high_kernel_alias(layout.high_alias(layout.bss.end).unwrap()),
            Err(Error::InvalidKernelAlias)
        );
    }

    #[test]
    fn high_range_rebases_persisted_stack_metadata() {
        let layout = layout().validate().unwrap();
        let physical = PageRange::new(0x4020_7000, 0x4020_9000);
        let high = layout.high_range(physical).unwrap();
        assert_eq!(high.start, layout.high_alias(physical.start).unwrap());
        assert_eq!(high.end, layout.high_alias(physical.end).unwrap());
    }

    #[test]
    fn mmio_aliases_follow_kernel_and_preserve_in_page_offsets() {
        let layout = layout().validate().unwrap();
        let regions = [
            MmioRegion {
                base: 0x0900_0123,
                size: 0x1800,
            },
            MmioRegion {
                base: 0x0800_0000,
                size: PAGE_SIZE,
            },
        ];
        let aliases = plan_mmio_aliases(layout, &regions).unwrap();
        let expected_start = layout.high_alias(layout.bss.end).unwrap();
        assert_eq!(aliases[0].virtual_region.base, expected_start + 0x123);
        assert_eq!(aliases[0].virtual_region.size, regions[0].size);
        assert_eq!(aliases[1].virtual_region.base, expected_start + 0x2000);
    }

    #[test]
    fn retiring_identity_aliases_preserves_high_kernel_and_mmio_mappings() {
        let layout = layout().validate().unwrap();
        let mut backend = MockBackend::new(64);
        let root = backend.allocate_zeroed_table().unwrap();
        let mut mapper = Mapper::new(&mut backend, root).unwrap();
        let mmio = [MmioRegion {
            base: 0x0900_0000,
            size: PAGE_SIZE,
        }];
        let aliases = plan_mmio_aliases(layout, &mmio).unwrap();
        map_step6_layout(&mut mapper, layout, &mmio).unwrap();

        unmap_step6_identity_aliases(&mut mapper, layout, &mmio).unwrap();

        assert_eq!(mapper.translate(layout.text.start), Err(PageTableError::NotMapped));
        assert_eq!(mapper.translate(layout.data.start), Err(PageTableError::NotMapped));
        assert_eq!(mapper.translate(mmio[0].base), Err(PageTableError::NotMapped));
        assert_eq!(
            mapper
                .translate(layout.high_alias(layout.text.start).unwrap())
                .unwrap(),
            layout.text.start
        );
        assert_eq!(
            mapper.translate(aliases[0].virtual_region.base).unwrap(),
            mmio[0].base
        );
        verify_guard_holes(&mapper, layout).unwrap();
    }

    #[test]
    fn secondary_guard_pages_are_derived_from_the_linker_stride() {
        let layout = layout().validate().unwrap();
        assert_eq!(layout.secondary_stack_count().unwrap(), 2);
        assert_eq!(
            layout.secondary_guard(0).unwrap(),
            PageRange::new(0x4021_7000, 0x4021_8000)
        );
        assert_eq!(
            layout.secondary_guard(1).unwrap(),
            PageRange::new(0x4022_8000, 0x4022_9000)
        );
    }

    #[test]
    fn rejects_page_table_pool_overlapping_a_guard() {
        let mut layout = layout();
        layout.page_tables = PageRange::new(
            layout.worker_guard.start,
            layout.worker_guard.start + 8 * PAGE_SIZE,
        );
        assert_eq!(layout.validate(), Err(Error::InvalidLayout));
    }

    #[test]
    fn rejects_page_table_pool_overlapping_secondary_stack_payload() {
        let mut layout = layout();
        let payload_start = layout.secondary_stacks.start + layout.stack_guard_size;
        layout.page_tables = PageRange::new(payload_start, payload_start + 8 * PAGE_SIZE);
        assert_eq!(layout.validate(), Err(Error::InvalidLayout));
    }

    #[test]
    fn rejects_unbounded_device_aperture() {
        let layout = layout().validate().unwrap();
        let mut backend = MockBackend::new(64);
        let root = backend.allocate_zeroed_table().unwrap();
        let mut mapper = Mapper::new(&mut backend, root).unwrap();
        let huge = MmioRegion {
            base: 0x0800_0000,
            size: (MAX_BOOT_MMIO_PAGES + 1) * PAGE_SIZE,
        };
        assert_eq!(
            map_step6_layout(&mut mapper, layout, &[huge]),
            Err(Error::MmioRegionTooLarge)
        );
    }
}
