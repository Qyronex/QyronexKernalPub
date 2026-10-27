// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_fdt_aarch64::MmioRegion;
use kernal_paging::PAGE_SIZE;

use crate::mmu::{BootstrapLayout, MmioAlias};

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_HEADER_BYTES: usize = 40;
const MAX_QEMU_DTB_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageSpan {
    start: u64,
    end: u64,
    offset: u64,
}

impl PageSpan {
    fn from_data(start: u64, len: u64) -> Result<Self, AliasPlanError> {
        if len == 0 {
            return Err(AliasPlanError::Empty);
        }
        let data_end = start
            .checked_add(len)
            .ok_or(AliasPlanError::AddressOverflow)?;
        let page_start = start & !(PAGE_SIZE - 1);
        let page_end = data_end
            .checked_add(PAGE_SIZE - 1)
            .ok_or(AliasPlanError::AddressOverflow)?
            & !(PAGE_SIZE - 1);
        if page_start >= page_end {
            return Err(AliasPlanError::InvalidSpan);
        }
        Ok(Self {
            start: page_start,
            end: page_end,
            offset: start
                .checked_sub(page_start)
                .ok_or(AliasPlanError::AddressOverflow)?,
        })
    }

    const fn len(self) -> u64 {
        self.end - self.start
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AliasPlanError {
    Empty,
    AddressOverflow,
    InvalidSpan,
    InvalidLayout,
    MmioPlanMismatch,
}

fn mmio_page_span(region: MmioRegion) -> Result<PageSpan, AliasPlanError> {
    PageSpan::from_data(region.base, region.size)
}

fn alias_base_after_mmio(
    layout: BootstrapLayout,
    aliases: &[MmioAlias],
) -> Result<u64, AliasPlanError> {
    let layout = layout
        .validate()
        .map_err(|_| AliasPlanError::InvalidLayout)?;
    let mut cursor = layout
        .high_alias(layout.bss.end)
        .map_err(|_| AliasPlanError::InvalidLayout)?;

    for alias in aliases.iter().copied() {
        if alias.virtual_region.size != alias.physical.size {
            return Err(AliasPlanError::MmioPlanMismatch);
        }
        let physical = mmio_page_span(alias.physical)?;
        let virtual_start = alias
            .virtual_region
            .base
            .checked_sub(physical.offset)
            .ok_or(AliasPlanError::AddressOverflow)?;
        let virtual_end = virtual_start
            .checked_add(physical.len())
            .ok_or(AliasPlanError::AddressOverflow)?;
        if virtual_start != cursor || virtual_end <= virtual_start {
            return Err(AliasPlanError::MmioPlanMismatch);
        }
        cursor = virtual_end;
    }

    if cursor & (PAGE_SIZE - 1) != 0 || cursor >> 48 != 0xffff {
        return Err(AliasPlanError::InvalidLayout);
    }
    Ok(cursor)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::{ptr::read_volatile, slice::from_raw_parts};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_arch_aarch64::TranslationAccess;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_core_initrd_aarch64::{CoreValidatedInitrd, discover_qemu_initrd};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_fdt::Blob;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_page_table_aarch64::{Backend, Mapper, MemoryType, invalidate_all_el1};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_paging::MapFlags;

/// Fail-closed errors while creating the sole protected, read-only QEMU initrd view.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Debug)]
pub enum ProtectedInitrdError {
    RuntimeNotReady,
    AliasPlan,
    DtbHeader,
    DtbOutsideReservedWindow,
    Dtb(kernal_fdt::Error),
    Provenance(kernal_core_initrd_aarch64::Error),
    PageTable(kernal_page_table_aarch64::Error),
    CleanupFailed,
    TranslationProof,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl From<kernal_page_table_aarch64::Error> for ProtectedInitrdError {
    fn from(value: kernal_page_table_aarch64::Error) -> Self {
        Self::PageTable(value)
    }
}

/// Exact protected mapping of the fully proven QEMU initrd payload.
///
/// Fields are private because this value is mapping provenance, not general page-table authority.
/// `proof` is the single Core owner for FDT structure, DTB/kernel non-overlap, QEMU bounds and
/// canonical ELF parsing. This crate owns only the supervisor-only read-only/NX TTBR1 mapping and its
/// architectural translation probes.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedInitrd {
    proof: CoreValidatedInitrd,
    virtual_start: u64,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl ProtectedInitrd {
    pub const fn physical_start(self) -> u64 {
        self.proof.physical_start()
    }

    pub const fn virtual_start(self) -> u64 {
        self.virtual_start
    }

    pub const fn len(self) -> usize {
        self.proof.len()
    }

    pub const fn proof(self) -> CoreValidatedInitrd {
        self.proof
    }

    /// Borrows the exact mapped payload only for the supplied operation.
    ///
    /// The higher-ranked closure prevents a Rust reference into the permanent boot mapping from
    /// escaping in the return value. Callers may invoke the canonical parser and Linux loader inside
    /// the operation, but cannot retain the borrowed bytes in safe Rust.
    pub fn with_bytes<R>(self, operation: impl for<'a> FnOnce(&'a [u8]) -> R) -> R {
        // SAFETY: only `map_qemu_initrd_high_alias` constructs this value after mapping and probing
        // the complete exact-length range read-only in the permanent final TTBR1 root.
        let bytes = unsafe { from_raw_parts(self.virtual_start as *const u8, self.len()) };
        operation(bytes)
    }

    /// Runs the canonical AArch64 ELF parser over the exact protected byte view without allowing the
    /// borrowed image to escape this mapping scope.
    pub fn validate_aarch64_elf(self) -> Result<(), ProtectedInitrdError> {
        self.with_bytes(|bytes| self.proof.parse_aarch64_elf(bytes).map(|_| ()))
            .map_err(ProtectedInitrdError::Provenance)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_read_only_pages<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    virtual_start: u64,
    physical: PageSpan,
) -> Result<(), ProtectedInitrdError> {
    let mut virtual_page = virtual_start;
    let mut physical_page = physical.start;
    let mut mapped_end = physical.start;

    while physical_page < physical.end {
        if let Err(error) = mapper.map_page_with_type(
            virtual_page,
            physical_page,
            MapFlags::READ,
            MemoryType::NormalWriteBack,
        ) {
            if unmap_read_only_pages(mapper, virtual_start, physical.start, mapped_end).is_err() {
                return Err(ProtectedInitrdError::CleanupFailed);
            }
            return Err(ProtectedInitrdError::PageTable(error));
        }
        physical_page = physical_page
            .checked_add(PAGE_SIZE)
            .ok_or(ProtectedInitrdError::AliasPlan)?;
        virtual_page = virtual_page
            .checked_add(PAGE_SIZE)
            .ok_or(ProtectedInitrdError::AliasPlan)?;
        mapped_end = physical_page;
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn unmap_read_only_pages<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    virtual_start: u64,
    physical_start: u64,
    physical_end: u64,
) -> Result<(), ProtectedInitrdError> {
    let mut virtual_page = virtual_start;
    let mut physical_page = physical_start;
    while physical_page < physical_end {
        let removed = mapper
            .unmap_page(virtual_page)
            .map_err(|_| ProtectedInitrdError::CleanupFailed)?;
        if removed != physical_page {
            return Err(ProtectedInitrdError::CleanupFailed);
        }
        physical_page = physical_page
            .checked_add(PAGE_SIZE)
            .ok_or(ProtectedInitrdError::CleanupFailed)?;
        virtual_page = virtual_page
            .checked_add(PAGE_SIZE)
            .ok_or(ProtectedInitrdError::CleanupFailed)?;
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn invalidate_after_table_mutation() {
    // SAFETY: the public mapping contract holds every secondary PE at the final BSP construction
    // barrier while this sole owner mutates the shared TTBR1 hierarchy.
    unsafe { invalidate_all_el1() };
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn read_be_u32(address: u64) -> Result<u32, ProtectedInitrdError> {
    if address & 3 != 0 {
        return Err(ProtectedInitrdError::DtbHeader);
    }
    // SAFETY: the caller mapped the containing QEMU DTB page read-only immediately before this read.
    Ok(u32::from_be(unsafe {
        read_volatile(address as *const u32)
    }))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn unmap_and_invalidate(
    backend: &mut crate::runtime_table::RuntimeTablePool,
    root_table: u64,
    virtual_start: u64,
    physical: PageSpan,
) -> Result<(), ProtectedInitrdError> {
    let cleanup = {
        let mut mapper = Mapper::new(backend, root_table)?;
        unmap_read_only_pages(&mut mapper, virtual_start, physical.start, physical.end)
    };
    // SAFETY: the caller holds the protected BSP table-mutation contract. Invalidate even when
    // cleanup reports a partial failure, because earlier leaves may already have been cleared.
    unsafe { invalidate_after_table_mutation() };
    cleanup
}

/// Creates the only protected high-half view of the external QEMU initrd.
///
/// The function temporarily maps the QEMU DTB read-only at the first free TTBR1 page after the
/// packed MMIO aliases, reads and validates its exact bounded length, and calls the single
/// `kernal-core-initrd-aarch64` provenance owner while that scoped DTB view is live. The temporary DTB
/// mapping is then removed. The same virtual range is reused for the proven initrd and mapped
/// supervisor-only, read-only and PXN/UXN as Normal-WB memory. No physical or TTBR0 alias is recreated.
///
/// # Safety
/// - Must run in the one-shot protected BSP proof callback after every PE retired TTBR0.
/// - `backend` must be the exact exclusive monotonic RuntimeTablePool cursor supplied by that owner.
/// - Every secondary PE must remain parked with IRQ delivery masked for all shared table mutations
///   and broadcast invalidations.
/// - The returned mapping must not be removed while any `ProtectedInitrd::with_bytes` operation runs.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn map_qemu_initrd_high_alias(
    backend: &mut crate::runtime_table::RuntimeTablePool,
) -> Result<ProtectedInitrd, ProtectedInitrdError> {
    if !crate::runtime::runtime_table_pool_claim_ready() {
        return Err(ProtectedInitrdError::RuntimeNotReady);
    }

    let state = crate::boot_state();
    let alias_base = alias_base_after_mmio(state.layout, &state.mmio_aliases)
        .map_err(|_| ProtectedInitrdError::AliasPlan)?;
    let header_span = PageSpan::from_data(crate::QEMU_VIRT_RAM_BASE, PAGE_SIZE)
        .map_err(|_| ProtectedInitrdError::AliasPlan)?;

    let header_map = {
        let mut mapper = Mapper::new(backend, state.root_table)?;
        map_read_only_pages(&mut mapper, alias_base, header_span)
    };
    // SAFETY: delegated public contract keeps every affected PE quiesced. Invalidation is required
    // after both successful mapping and rollback performed by `map_read_only_pages`.
    unsafe { invalidate_after_table_mutation() };
    header_map?;

    let header = (|| -> Result<usize, ProtectedInitrdError> {
        // SAFETY: the header page is mapped read-only at alias_base above.
        let magic = unsafe { read_be_u32(alias_base) }?;
        // SAFETY: bytes 4..8 are within the same mapped header page.
        let total = unsafe { read_be_u32(alias_base + 4) }? as usize;
        if magic != FDT_MAGIC || !(FDT_HEADER_BYTES..=MAX_QEMU_DTB_BYTES).contains(&total) {
            return Err(ProtectedInitrdError::DtbHeader);
        }
        Ok(total)
    })();

    let total_size = match header {
        Ok(total) => total,
        Err(error) => {
            unmap_and_invalidate(backend, state.root_table, alias_base, header_span)?;
            return Err(error);
        }
    };

    let dtb_span = PageSpan::from_data(crate::QEMU_VIRT_RAM_BASE, total_size as u64)
        .map_err(|_| ProtectedInitrdError::DtbHeader)?;
    if dtb_span.end > state.layout.kernel_phys_base {
        unmap_and_invalidate(backend, state.root_table, alias_base, header_span)?;
        return Err(ProtectedInitrdError::DtbOutsideReservedWindow);
    }

    if dtb_span.end > header_span.end {
        let remainder = PageSpan {
            start: header_span.end,
            end: dtb_span.end,
            offset: 0,
        };
        let remainder_virtual = alias_base
            .checked_add(PAGE_SIZE)
            .ok_or(ProtectedInitrdError::AliasPlan)?;
        let remainder_map = {
            let mut mapper = Mapper::new(backend, state.root_table)?;
            map_read_only_pages(&mut mapper, remainder_virtual, remainder)
        };
        // SAFETY: invalidate after either publication or internal rollback of the remainder leaves.
        unsafe { invalidate_after_table_mutation() };
        if let Err(error) = remainder_map {
            unmap_and_invalidate(backend, state.root_table, alias_base, header_span)?;
            return Err(error);
        }
    }

    let proof_result = (|| -> Result<CoreValidatedInitrd, ProtectedInitrdError> {
        // SAFETY: the complete exact DTB span is mapped read-only and total_size is bounded above.
        let bytes = unsafe { from_raw_parts(alias_base as *const u8, total_size) };
        let blob = Blob::parse(bytes).map_err(ProtectedInitrdError::Dtb)?;
        discover_qemu_initrd(
            &blob,
            crate::QEMU_VIRT_RAM_BASE,
            state.layout.text.start,
            state.layout.bss.end,
        )
        .map_err(ProtectedInitrdError::Provenance)
    })();

    unmap_and_invalidate(backend, state.root_table, alias_base, dtb_span)?;
    let proof = proof_result?;

    let payload_len = u64::try_from(proof.len()).map_err(|_| ProtectedInitrdError::AliasPlan)?;
    let payload = PageSpan::from_data(proof.physical_start(), payload_len)
        .map_err(|_| ProtectedInitrdError::AliasPlan)?;

    let payload_map = {
        let mut mapper = Mapper::new(backend, state.root_table)?;
        map_read_only_pages(&mut mapper, alias_base, payload)
    };
    // SAFETY: invalidate after either publication or internal rollback of the payload leaves.
    unsafe { invalidate_after_table_mutation() };
    payload_map?;

    let virtual_start = alias_base
        .checked_add(payload.offset)
        .ok_or(ProtectedInitrdError::AliasPlan)?;
    let last_offset = payload_len
        .checked_sub(1)
        .ok_or(ProtectedInitrdError::AliasPlan)?;
    let last_virtual = virtual_start
        .checked_add(last_offset)
        .ok_or(ProtectedInitrdError::AliasPlan)?;
    let last_physical = proof
        .physical_start()
        .checked_add(last_offset)
        .ok_or(ProtectedInitrdError::AliasPlan)?;

    let translation_result = {
        let mut mapper = Mapper::new(backend, state.root_table)?;
        let check = match (
            mapper.translate(virtual_start),
            mapper.translate(last_virtual),
        ) {
            (Ok(first), Ok(last)) if first == proof.physical_start() && last == last_physical => {
                Ok(())
            }
            (Err(error), _) | (_, Err(error)) => Err(ProtectedInitrdError::PageTable(error)),
            _ => Err(ProtectedInitrdError::TranslationProof),
        };
        if check.is_err()
            && unmap_read_only_pages(&mut mapper, alias_base, payload.start, payload.end).is_err()
        {
            Err(ProtectedInitrdError::CleanupFailed)
        } else {
            check
        }
    };
    // SAFETY: mapping success and every failure rollback both require a broadcast invalidation.
    unsafe { invalidate_after_table_mutation() };
    translation_result?;

    // SAFETY: the exact shared root is active, all PEs are held, and these probes only test the
    // newly published permissions before any payload bytes are handed to Core.
    let low_read = unsafe {
        kernal_arch_aarch64::probe_el1_translation(proof.physical_start(), TranslationAccess::Read)
    };
    let high_read = unsafe {
        kernal_arch_aarch64::probe_el1_translation(virtual_start, TranslationAccess::Read)
    };
    let high_last_read = unsafe {
        kernal_arch_aarch64::probe_el1_translation(last_virtual, TranslationAccess::Read)
    };
    let high_write = unsafe {
        kernal_arch_aarch64::probe_el1_translation(virtual_start, TranslationAccess::Write)
    };
    if !low_read.faulted()
        || high_read.faulted()
        || high_last_read.faulted()
        || !high_write.faulted()
    {
        unmap_and_invalidate(backend, state.root_table, alias_base, payload)?;
        return Err(ProtectedInitrdError::TranslationProof);
    }

    let protected = ProtectedInitrd {
        proof,
        virtual_start,
    };
    if let Err(error) = protected.validate_aarch64_elf() {
        unmap_and_invalidate(backend, state.root_table, alias_base, payload)?;
        return Err(error);
    }
    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmu::{PageRange, plan_mmio_aliases};

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
    fn alias_begins_immediately_after_the_packed_mmio_plan() {
        let layout = layout().validate().unwrap();
        let physical = [
            MmioRegion {
                base: 0x0900_0123,
                size: 0x1800,
            },
            MmioRegion {
                base: 0x0800_0000,
                size: PAGE_SIZE,
            },
        ];
        let aliases = plan_mmio_aliases(layout, &physical).unwrap();
        let base = alias_base_after_mmio(layout, &aliases).unwrap();
        assert_eq!(
            base,
            layout.high_alias(layout.bss.end).unwrap() + 3 * PAGE_SIZE
        );
    }

    #[test]
    fn page_span_preserves_data_offset_and_checks_overflow() {
        let span = PageSpan::from_data(0x4800_0123, 0x2000).unwrap();
        assert_eq!(span.start, 0x4800_0000);
        assert_eq!(span.end, 0x4800_3000);
        assert_eq!(span.offset, 0x123);
        assert_eq!(
            PageSpan::from_data(0x4800_0000, 0),
            Err(AliasPlanError::Empty)
        );
        assert_eq!(
            PageSpan::from_data(u64::MAX - 7, 16),
            Err(AliasPlanError::AddressOverflow)
        );
    }

    #[test]
    fn alias_plan_rejects_mmio_size_or_cursor_mismatch() {
        let layout = layout().validate().unwrap();
        let physical = [MmioRegion {
            base: 0x0900_0123,
            size: 0x1800,
        }];
        let mut aliases = plan_mmio_aliases(layout, &physical).unwrap();
        aliases[0].virtual_region.size -= 1;
        assert_eq!(
            alias_base_after_mmio(layout, &aliases),
            Err(AliasPlanError::MmioPlanMismatch)
        );
    }
}
