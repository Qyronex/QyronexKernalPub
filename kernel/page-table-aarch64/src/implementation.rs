// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::arch::asm;
use kernal_paging::{MapFlags, PAGE_SIZE, page_indexes};

const VALID: u64 = 1 << 0;
const TABLE_OR_PAGE: u64 = 1 << 1;
const ATTR_INDEX_SHIFT: u32 = 2;
const AP_SHIFT: u32 = 6;
const SH_SHIFT: u32 = 8;
const ACCESS_FLAG: u64 = 1 << 10;
const NOT_GLOBAL: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const HIGH_HALF_PREFIX: u64 = 0xffff_0000_0000_0000;
const HIGH_HALF_MASK: u64 = 0xffff_0000_0000_0000;

const ATTR_NORMAL_WB: u64 = 0;
const ATTR_DEVICE_NGNRE: u64 = 1;
const SH_OUTER: u64 = 0b10;
const SH_INNER: u64 = 0b11;

const MAIR_NORMAL_WB: u64 = 0xff;
const MAIR_DEVICE_NGNRE: u64 = 0x04;

const TCR_T0SZ_48BIT: u64 = 16;
const TCR_EPD0: u64 = 1 << 7;
const TCR_IRGN0_WBWA: u64 = 0b01 << 8;
const TCR_ORGN0_WBWA: u64 = 0b01 << 10;
const TCR_SH0_INNER: u64 = 0b11 << 12;
const TCR_T1SZ_48BIT: u64 = 16 << 16;
const TCR_IRGN1_WBWA: u64 = 0b01 << 24;
const TCR_ORGN1_WBWA: u64 = 0b01 << 26;
const TCR_SH1_INNER: u64 = 0b11 << 28;
const TCR_TG1_4K: u64 = 0b10 << 30;
const TCR_IPS_SHIFT: u32 = 32;

const SCTLR_M: u64 = 1 << 0;
const SCTLR_A: u64 = 1 << 1;
const SCTLR_C: u64 = 1 << 2;
const SCTLR_SA: u64 = 1 << 3;
const SCTLR_SA0: u64 = 1 << 4;
const SCTLR_SED: u64 = 1 << 8;
const SCTLR_EOS: u64 = 1 << 11;
const SCTLR_I: u64 = 1 << 12;
const SCTLR_WXN: u64 = 1 << 19;
const SCTLR_TSCXT: u64 = 1 << 20;
const SCTLR_EIS: u64 = 1 << 22;
const SCTLR_SPAN: u64 = 1 << 23;
const SCTLR_E0E: u64 = 1 << 24;
const SCTLR_EE: u64 = 1 << 25;
const SCTLR_NTLSMD: u64 = 1 << 28;
const SCTLR_LSMAOE: u64 = 1 << 29;

/*
 * AArch64 SCTLR_EL1 reset state is not a kernel policy. Build Step 6 from a known little-endian
 * baseline instead of inheriting firmware/hypervisor controls. These compatibility bits select the
 * backwards-compatible values for fields that were RES1 in earlier Armv8 revisions and are now
 * named controls on newer revisions. Optional EL0 facilities stay disabled until their own step.
 */
const SCTLR_STEP6_COMPAT: u64 =
    SCTLR_SED | SCTLR_EOS | SCTLR_TSCXT | SCTLR_EIS | SCTLR_SPAN | SCTLR_NTLSMD | SCTLR_LSMAOE;
const SCTLR_STEP6_REQUIRED_SET: u64 =
    SCTLR_M | SCTLR_C | SCTLR_SA | SCTLR_SA0 | SCTLR_I | SCTLR_WXN;
const SCTLR_STEP6_REQUIRED_CLEAR: u64 = SCTLR_A | SCTLR_E0E | SCTLR_EE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryType {
    NormalWriteBack,
    DeviceNgnre,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Paging(kernal_paging::Error),
    NullPage,
    BackendFailure,
    InvalidTableAddress,
    InvalidDescriptor,
    AlreadyMapped,
    NotMapped,
    TreeNotEmpty,
    ExecutableDevice,
    Unsupported4KGranule,
    UnsupportedPhysicalAddressRange,
    MmuAlreadyEnabled,
    UnexpectedSctlrState,
    InvalidHighEntry,
    InvalidHighStack,
}

impl From<kernal_paging::Error> for Error {
    fn from(value: kernal_paging::Error) -> Self {
        Self::Paging(value)
    }
}

pub trait Backend {
    fn allocate_zeroed_table(&mut self) -> Option<u64>;
    fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64>;
    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool;

    /// Terminally returns one detached empty table page to the backend owner.
    ///
    /// # Safety
    /// The caller must prove no valid descriptor or active translation can reach
    /// `table_phys`, and that the page belongs to this backend's releasable live set.
    unsafe fn release_table(&mut self, table_phys: u64) -> bool {
        let _ = table_phys;
        false
    }
}

pub fn leaf_descriptor(
    physical_address: u64,
    flags: MapFlags,
    memory_type: MemoryType,
) -> Result<u64, Error> {
    flags.validate()?;
    validate_table_address(physical_address)?;
    if memory_type == MemoryType::DeviceNgnre && flags.executable() {
        return Err(Error::ExecutableDevice);
    }

    let (attr_index, shareability) = match memory_type {
        MemoryType::NormalWriteBack => (ATTR_NORMAL_WB, SH_INNER),
        MemoryType::DeviceNgnre => (ATTR_DEVICE_NGNRE, SH_OUTER),
    };

    let mut descriptor = physical_address
        | VALID
        | TABLE_OR_PAGE
        | ACCESS_FLAG
        | (attr_index << ATTR_INDEX_SHIFT)
        | (shareability << SH_SHIFT);

    if flags.user() {
        // AP=01 => EL1/EL0 RW, AP=11 => EL1/EL0 RO.
        let ap = if flags.writable() { 0b01 } else { 0b11 };
        descriptor |= (ap as u64) << AP_SHIFT;
        descriptor |= NOT_GLOBAL | PXN;
        if !flags.executable() {
            descriptor |= UXN;
        }
    } else {
        // AP=00 => EL1 RW, AP=10 => EL1 RO. EL0 is always blocked for kernel leaves.
        let ap = if flags.writable() { 0b00 } else { 0b10 };
        descriptor |= (ap as u64) << AP_SHIFT;
        descriptor |= UXN;
        if !flags.executable() {
            descriptor |= PXN;
        }
    }

    Ok(descriptor)
}

pub struct Mapper<'a, B: Backend> {
    backend: &'a mut B,
    root: u64,
}

impl<'a, B: Backend> Mapper<'a, B> {
    pub fn new(backend: &'a mut B, root: u64) -> Result<Self, Error> {
        validate_table_address(root)?;
        Ok(Self { backend, root })
    }

    pub const fn root(&self) -> u64 {
        self.root
    }

    pub fn map_page(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        flags: MapFlags,
    ) -> Result<(), Error> {
        self.map_page_with_type(
            virtual_address,
            physical_address,
            flags,
            MemoryType::NormalWriteBack,
        )
    }

    pub fn map_page_with_type(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        flags: MapFlags,
        memory_type: MemoryType,
    ) -> Result<(), Error> {
        if virtual_address == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(virtual_address)?;
        let table = self.ensure_leaf_table_inner(indexes.p4, indexes.p3, indexes.p2)?;
        let current = self
            .backend
            .read_entry(table, indexes.p1)
            .ok_or(Error::BackendFailure)?;
        if current & VALID != 0 {
            return Err(Error::AlreadyMapped);
        }
        let leaf = leaf_descriptor(physical_address, flags, memory_type)?;
        if !self.backend.write_entry(table, indexes.p1, leaf) {
            return Err(Error::BackendFailure);
        }
        Ok(())
    }

    pub fn ensure_leaf_table(&mut self, virtual_address: u64) -> Result<u64, Error> {
        if virtual_address == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(virtual_address)?;
        self.ensure_leaf_table_inner(indexes.p4, indexes.p3, indexes.p2)
    }

    pub fn translate(&self, virtual_address: u64) -> Result<u64, Error> {
        let page = virtual_address & !(PAGE_SIZE - 1);
        let offset = virtual_address & (PAGE_SIZE - 1);
        if page == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(page)?;
        let mut table = self.root;
        for index in [indexes.p4, indexes.p3, indexes.p2] {
            let entry = self
                .backend
                .read_entry(table, index)
                .ok_or(Error::BackendFailure)?;
            if entry & VALID == 0 {
                return Err(Error::NotMapped);
            }
            if entry & TABLE_OR_PAGE == 0 {
                return Err(Error::InvalidDescriptor);
            }
            table = entry & ADDRESS_MASK;
            validate_table_address(table)?;
        }
        let leaf = self
            .backend
            .read_entry(table, indexes.p1)
            .ok_or(Error::BackendFailure)?;
        if leaf & VALID == 0 {
            return Err(Error::NotMapped);
        }
        if leaf & TABLE_OR_PAGE == 0 {
            return Err(Error::InvalidDescriptor);
        }
        (leaf & ADDRESS_MASK)
            .checked_add(offset)
            .ok_or(Error::InvalidTableAddress)
    }

    pub fn unmap_page(&mut self, virtual_address: u64) -> Result<u64, Error> {
        if virtual_address == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(virtual_address)?;
        let mut table = self.root;
        for index in [indexes.p4, indexes.p3, indexes.p2] {
            let entry = self
                .backend
                .read_entry(table, index)
                .ok_or(Error::BackendFailure)?;
            if entry & VALID == 0 {
                return Err(Error::NotMapped);
            }
            if entry & TABLE_OR_PAGE == 0 {
                return Err(Error::InvalidDescriptor);
            }
            table = entry & ADDRESS_MASK;
            validate_table_address(table)?;
        }
        let leaf = self
            .backend
            .read_entry(table, indexes.p1)
            .ok_or(Error::BackendFailure)?;
        if leaf & VALID == 0 {
            return Err(Error::NotMapped);
        }
        if !self.backend.write_entry(table, indexes.p1, 0) {
            return Err(Error::BackendFailure);
        }
        Ok(leaf & ADDRESS_MASK)
    }

    /// Terminally reclaims one already-unreachable empty four-level table tree.
    ///
    /// # Safety
    /// `self.root` must be detached from all active translations for the complete call.
    pub unsafe fn reclaim_empty_tree(&mut self) -> Result<(), Error> {
        self.verify_empty_tree(self.root, 3)?;
        unsafe { self.reclaim_empty_children(self.root, 3)? };
        if !unsafe { self.backend.release_table(self.root) } {
            return Err(Error::BackendFailure);
        }
        Ok(())
    }

    fn verify_empty_tree(&self, table: u64, remaining: u8) -> Result<(), Error> {
        for index in 0..512 {
            let entry = self
                .backend
                .read_entry(table, index)
                .ok_or(Error::BackendFailure)?;
            if entry == 0 {
                continue;
            }
            if entry & VALID == 0 {
                return Err(Error::InvalidDescriptor);
            }
            if remaining == 0 {
                return Err(Error::TreeNotEmpty);
            }
            if entry & TABLE_OR_PAGE == 0 {
                return Err(Error::InvalidDescriptor);
            }
            let child = entry & ADDRESS_MASK;
            validate_table_address(child)?;
            self.verify_empty_tree(child, remaining - 1)?;
        }
        Ok(())
    }

    unsafe fn reclaim_empty_children(&mut self, table: u64, remaining: u8) -> Result<(), Error> {
        if remaining == 0 {
            return Ok(());
        }
        for index in 0..512 {
            let entry = self
                .backend
                .read_entry(table, index)
                .ok_or(Error::BackendFailure)?;
            if entry == 0 {
                continue;
            }
            if entry & VALID == 0 {
                return Err(Error::InvalidDescriptor);
            }
            if entry & TABLE_OR_PAGE == 0 {
                return Err(Error::InvalidDescriptor);
            }
            let child = entry & ADDRESS_MASK;
            validate_table_address(child)?;
            unsafe { self.reclaim_empty_children(child, remaining - 1)? };
            if !self.backend.write_entry(table, index, 0) {
                return Err(Error::BackendFailure);
            }
            if !unsafe { self.backend.release_table(child) } {
                return Err(Error::BackendFailure);
            }
        }
        Ok(())
    }

    fn ensure_leaf_table_inner(&mut self, p4: usize, p3: usize, p2: usize) -> Result<u64, Error> {
        let mut table = self.root;
        for index in [p4, p3, p2] {
            table = self.next_table(table, index)?;
        }
        Ok(table)
    }

    fn next_table(&mut self, table: u64, index: usize) -> Result<u64, Error> {
        let entry = self
            .backend
            .read_entry(table, index)
            .ok_or(Error::BackendFailure)?;
        if entry & VALID != 0 {
            if entry & TABLE_OR_PAGE == 0 {
                return Err(Error::InvalidDescriptor);
            }
            let child = entry & ADDRESS_MASK;
            validate_table_address(child)?;
            return Ok(child);
        }
        let child = self
            .backend
            .allocate_zeroed_table()
            .ok_or(Error::BackendFailure)?;
        validate_table_address(child)?;
        let descriptor = child | VALID | TABLE_OR_PAGE;
        if !self.backend.write_entry(table, index, descriptor) {
            return Err(Error::BackendFailure);
        }
        Ok(child)
    }
}

fn validate_table_address(address: u64) -> Result<(), Error> {
    if address & (PAGE_SIZE - 1) != 0 || address & !ADDRESS_MASK != 0 {
        Err(Error::InvalidTableAddress)
    } else {
        Ok(())
    }
}

const fn high_half_address(address: u64) -> bool {
    address & HIGH_HALF_MASK == HIGH_HALF_PREFIX
}

pub const fn mair_el1_value() -> u64 {
    MAIR_NORMAL_WB | (MAIR_DEVICE_NGNRE << 8)
}

fn tcr_el1_common_value(physical_address_range: u8) -> Result<u64, Error> {
    // Current descriptors encode at most 48-bit physical addresses. Fail closed on FEAT_LPA's
    // 52-bit PARange until the descriptor mask/format is explicitly extended for it.
    if physical_address_range > 5 {
        return Err(Error::UnsupportedPhysicalAddressRange);
    }
    Ok(TCR_T0SZ_48BIT
        | TCR_IRGN0_WBWA
        | TCR_ORGN0_WBWA
        | TCR_SH0_INNER
        | TCR_T1SZ_48BIT
        | TCR_IRGN1_WBWA
        | TCR_ORGN1_WBWA
        | TCR_SH1_INNER
        | TCR_TG1_4K
        | ((physical_address_range as u64) << TCR_IPS_SHIFT))
}

pub fn tcr_el1_value(physical_address_range: u8) -> Result<u64, Error> {
    Ok(tcr_el1_common_value(physical_address_range)? | TCR_EPD0)
}

/// TCR_EL1 value used only while moving the bootstrap PC/SP from the physical lower-half alias to
/// the canonical TTBR1 high-half alias. Both TTBR0 and TTBR1 walks remain enabled during this
/// bounded transition and are expected to point at the same dual-mapped bootstrap table.
pub fn tcr_el1_transition_value(physical_address_range: u8) -> Result<u64, Error> {
    tcr_el1_common_value(physical_address_range)
}

/// Fully specified Step-6 EL1 control value. This is deliberately independent of the incoming
/// SCTLR_EL1 contents so direct-EL1 firmware and EL2->EL1 handoffs converge on the same policy.
pub const fn sctlr_el1_step6_value() -> u64 {
    SCTLR_STEP6_COMPAT | SCTLR_STEP6_REQUIRED_SET
}

const fn sctlr_el1_step6_readback_valid(value: u64) -> bool {
    value & SCTLR_STEP6_REQUIRED_SET == SCTLR_STEP6_REQUIRED_SET
        && value & SCTLR_STEP6_REQUIRED_CLEAR == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1TransitionConfig {
    root_table: u64,
    mair_el1: u64,
    tcr_el1: u64,
    sctlr_el1: u64,
}

impl El1TransitionConfig {
    pub fn for_physical_address_range(
        root_table: u64,
        physical_address_range: u8,
    ) -> Result<Self, Error> {
        validate_table_address(root_table)?;
        Ok(Self {
            root_table,
            mair_el1: mair_el1_value(),
            tcr_el1: tcr_el1_transition_value(physical_address_range)?,
            sctlr_el1: sctlr_el1_step6_value(),
        })
    }

    pub const fn root_table(self) -> u64 {
        self.root_table
    }

    pub const fn mair_el1(self) -> u64 {
        self.mair_el1
    }

    pub const fn tcr_el1(self) -> u64 {
        self.tcr_el1
    }

    pub const fn sctlr_el1(self) -> u64 {
        self.sctlr_el1
    }
}

/// Validates the current EL1/MMU capabilities and returns the complete register image needed by the
/// non-returning low-to-high transition. No translation register is modified here.
#[cfg(target_arch = "aarch64")]
pub fn prepare_el1_transition(root_table: u64) -> Result<El1TransitionConfig, Error> {
    validate_table_address(root_table)?;
    let mmfr0: u64;
    let current_sctlr: u64;
    // SAFETY: both registers are readable at EL1; this function performs no control-state writes.
    unsafe {
        asm!("mrs {value}, ID_AA64MMFR0_EL1", value = out(reg) mmfr0, options(nomem, nostack));
        asm!("mrs {value}, SCTLR_EL1", value = out(reg) current_sctlr, options(nomem, nostack));
    }
    if current_sctlr & SCTLR_M != 0 {
        return Err(Error::MmuAlreadyEnabled);
    }
    let tgran4 = ((mmfr0 >> 28) & 0xf) as u8;
    if tgran4 == 0xf {
        return Err(Error::Unsupported4KGranule);
    }
    El1TransitionConfig::for_physical_address_range(root_table, (mmfr0 & 0xf) as u8)
}

/// Activates the Step-6 dual-walk translation regime and transfers control to a high-half
/// continuation without ever returning through a low-address Rust call frame.
///
/// This is intentionally a one-way ABI boundary: after `SCTLR_EL1.M` becomes visible, the assembly
/// switches SP to `high_stack_top`, places the supplied context in x0/x1, poisons the abandoned
/// frame pointer and LR with zero, and branches directly to `high_entry`. A mistaken return therefore
/// reaches the unmapped null page instead of a stale low alias.
///
/// # Safety
/// - must execute at EL1 with IRQ/FIQ/debug/SError masked and Stage-1 translation disabled,
/// - `config.root_table` must contain valid identity and TTBR1 aliases for the executing code,
/// - `high_entry` must be a mapped executable TTBR1 address and 4-byte aligned,
/// - `high_stack_top` must be a 16-byte-aligned TTBR1 address with mapped writable stack below it,
/// - `argument0`/`argument1` must be valid for the high continuation; any pointer argument must
///   already use its high alias,
/// - the high continuation must never return.
#[cfg(target_arch = "aarch64")]
pub unsafe fn activate_el1_transition_and_branch(
    config: El1TransitionConfig,
    high_stack_top: u64,
    high_entry: u64,
    argument0: u64,
    argument1: u64,
) -> ! {
    if !high_half_address(high_entry) || high_entry & 3 != 0 {
        panic_invalid_transition();
    }
    if !high_half_address(high_stack_top) || high_stack_top & 0xf != 0 {
        panic_invalid_transition();
    }

    let root_table = config.root_table;
    let mair = config.mair_el1;
    let tcr = config.tcr_el1;
    let sctlr = config.sctlr_el1;
    // SAFETY: caller guarantees all low/high mappings and destination invariants above. Every input
    // is pinned to a distinct caller-saved register before x29/x30 are cleared, so the branch target
    // cannot alias LR through allocator choice. The block is noreturn: no abandoned low Rust frame
    // is consumed after SP changes.
    unsafe {
        asm!(
            "msr daifset, #0xf",
            "msr MAIR_EL1, x9",
            "msr TCR_EL1, x10",
            "msr TTBR0_EL1, x8",
            "msr TTBR1_EL1, x8",
            "dsb ish",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            "msr SCTLR_EL1, x11",
            "isb",
            "ic iallu",
            "dsb nsh",
            "isb",
            "mov sp, x12",
            "mov x0, x14",
            "mov x1, x15",
            "mov x29, xzr",
            "mov x30, xzr",
            "br x13",
            in("x8") root_table,
            in("x9") mair,
            in("x10") tcr,
            in("x11") sctlr,
            in("x12") high_stack_top,
            in("x13") high_entry,
            in("x14") argument0,
            in("x15") argument1,
            options(noreturn)
        )
    }
}

#[cfg(target_arch = "aarch64")]
#[cold]
fn panic_invalid_transition() -> ! {
    // This path can only be reached before MMU activation, so a fail-stop loop is safer than trying
    // to enter formatting/panic code whose stack/address assumptions may be in transition.
    loop {
        // SAFETY: WFE is side-effect free for the fail-stop path.
        unsafe { asm!("wfe", options(nomem, nostack)) };
    }
}

/// Finalizes TTBR0 retirement for the **current PE only** after the BSP has globally removed all
/// shared low leaves and completed a broadcast EL1 TLB invalidation. This function never edits page
/// tables and therefore can be called independently by every PE after the global barrier.
///
/// # Safety
/// - current PC, SP and all live runtime pointers must already use TTBR1 high-half mappings,
/// - the shared low leaves must already be absent and globally invalidated,
/// - interrupts must remain masked until this PE publishes its protected state.
#[cfg(target_arch = "aarch64")]
pub unsafe fn finalize_el1_transition_ttbr0() {
    let mut tcr: u64;
    unsafe {
        asm!("mrs {value}, TCR_EL1", value = out(reg) tcr, options(nomem, nostack));
    }
    tcr |= TCR_EPD0;
    unsafe {
        asm!("dsb ish", options(nostack));
        asm!("msr TCR_EL1, {value}", value = in(reg) tcr, options(nomem, nostack));
        asm!("isb", options(nostack));
        asm!("msr TTBR0_EL1, xzr", options(nomem, nostack));
        asm!("isb", options(nostack));
    }
}

/// Invalidates one EL1 stage-1 VA for all ASIDs in the inner-shareable domain.
///
/// # Safety
/// Must execute at EL1 after page-table memory has been updated with the required ownership and
/// break-before-make discipline for the mapping transition being performed.
#[cfg(target_arch = "aarch64")]
pub unsafe fn invalidate_page_el1(virtual_address: u64) {
    let operand = (virtual_address >> 12) & 0x0000_0fff_ffff_ffff;
    unsafe {
        asm!("dsb ishst", options(nostack));
        asm!("tlbi vaae1is, {value}", value = in(reg) operand, options(nostack));
        asm!("dsb ish", "isb", options(nostack));
    }
}

/// Broadcast-invalidates all EL1 stage-1 translations in the inner-shareable domain after a shared
/// page-table mutation. One global owner calls this after publishing the low-leaf removals; every PE
/// subsequently performs its local TTBR0 finalization separately.
///
/// # Safety
/// Caller owns the global page-table transition protocol and all affected PEs are quiesced at the
/// high-half transition barrier.
#[cfg(target_arch = "aarch64")]
pub unsafe fn invalidate_all_el1() {
    unsafe {
        asm!("dsb ishst", options(nostack));
        asm!("tlbi vmalle1is", options(nostack));
        asm!("dsb ish", "isb", options(nostack));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: usize = 24;
    const BASE: u64 = 0x10_0000;

    struct TestBackend {
        tables: [[u64; 512]; TABLES],
        used: usize,
        released: [u64; TABLES],
        released_len: usize,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                tables: [[0; 512]; TABLES],
                used: 1,
                released: [0; TABLES],
                released_len: 0,
            }
        }

        fn index(phys: u64) -> Option<usize> {
            if phys < BASE || (phys - BASE) % PAGE_SIZE != 0 {
                return None;
            }
            let index = ((phys - BASE) / PAGE_SIZE) as usize;
            (index < TABLES).then_some(index)
        }

        fn released(&self) -> &[u64] {
            &self.released[..self.released_len]
        }
    }

    impl Backend for TestBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            if self.used == TABLES {
                return None;
            }
            let index = self.used;
            self.used += 1;
            self.tables[index] = [0; 512];
            Some(BASE + index as u64 * PAGE_SIZE)
        }

        fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
            Some(*self.tables.get(Self::index(table_phys)?)?.get(index)?)
        }

        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let Some(table) = Self::index(table_phys).and_then(|index| self.tables.get_mut(index))
            else {
                return false;
            };
            let Some(entry) = table.get_mut(index) else {
                return false;
            };
            *entry = value;
            true
        }

        unsafe fn release_table(&mut self, table_phys: u64) -> bool {
            let Some(table_index) = Self::index(table_phys) else {
                return false;
            };
            if self.released_len == TABLES
                || !self.tables[table_index].iter().all(|entry| *entry == 0)
                || self.released().contains(&table_phys)
            {
                return false;
            }
            self.released[self.released_len] = table_phys;
            self.released_len += 1;
            true
        }
    }

    #[test]
    fn writable_kernel_page_is_pxn_uxn_and_never_wx() {
        let descriptor =
            leaf_descriptor(0x4000, MapFlags::WRITE, MemoryType::NormalWriteBack).unwrap();
        assert_ne!(descriptor & PXN, 0);
        assert_ne!(descriptor & UXN, 0);
        assert_eq!((descriptor >> AP_SHIFT) & 0b11, 0);
        assert_eq!(
            leaf_descriptor(
                0x4000,
                MapFlags::WRITE.union(MapFlags::EXECUTE),
                MemoryType::NormalWriteBack,
            ),
            Err(Error::Paging(kernal_paging::Error::WritableExecutable))
        );
    }

    #[test]
    fn executable_kernel_text_is_read_only_and_el0_xn() {
        let descriptor =
            leaf_descriptor(0x8000, MapFlags::EXECUTE, MemoryType::NormalWriteBack).unwrap();
        assert_eq!(descriptor & PXN, 0);
        assert_ne!(descriptor & UXN, 0);
        assert_eq!((descriptor >> AP_SHIFT) & 0b11, 0b10);
    }

    #[test]
    fn user_permissions_never_make_page_privileged_executable() {
        let descriptor = leaf_descriptor(
            0x9000,
            MapFlags::USER.union(MapFlags::EXECUTE),
            MemoryType::NormalWriteBack,
        )
        .unwrap();
        assert_ne!(descriptor & PXN, 0);
        assert_eq!(descriptor & UXN, 0);
        assert_eq!((descriptor >> AP_SHIFT) & 0b11, 0b11);
        assert_ne!(descriptor & NOT_GLOBAL, 0);
    }

    #[test]
    fn device_memory_cannot_be_executable() {
        assert_eq!(
            leaf_descriptor(0x1000, MapFlags::EXECUTE, MemoryType::DeviceNgnre),
            Err(Error::ExecutableDevice)
        );
    }

    #[test]
    fn maps_translates_and_unmaps_high_half_page() {
        let mut backend = TestBackend::new();
        let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
        let virtual_address = 0xffff_ffff_8020_0000;
        mapper
            .map_page(virtual_address, 0x40_0000, MapFlags::EXECUTE)
            .unwrap();
        assert_eq!(
            mapper.translate(virtual_address + 0x321).unwrap(),
            0x40_0321
        );
        assert_eq!(mapper.unmap_page(virtual_address).unwrap(), 0x40_0000);
        assert_eq!(mapper.translate(virtual_address), Err(Error::NotMapped));
    }

    #[test]
    fn malformed_nonzero_invalid_descriptor_rejects_without_mutation_or_release() {
        let mut backend = TestBackend::new();
        backend.tables[0][0] = 0x1000;

        let result = {
            let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
            unsafe { mapper.reclaim_empty_tree() }
        };

        assert_eq!(result, Err(Error::InvalidDescriptor));
        assert_eq!(backend.tables[0][0], 0x1000);
        assert!(backend.released().is_empty());
    }

    #[test]
    fn empty_tree_reclaims_children_postorder_and_root_last() {
        let mut backend = TestBackend::new();
        {
            let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
            mapper.ensure_leaf_table(0x4000).unwrap();
            unsafe { mapper.reclaim_empty_tree() }.unwrap();
        }

        assert_eq!(
            backend.released(),
            &[
                BASE + 3 * PAGE_SIZE,
                BASE + 2 * PAGE_SIZE,
                BASE + PAGE_SIZE,
                BASE,
            ]
        );
        assert_eq!(backend.tables[0][0], 0);
        assert_eq!(backend.tables[1][0], 0);
        assert_eq!(backend.tables[2][0], 0);
    }

    #[test]
    fn nonempty_leaf_blocks_all_tree_release() {
        let mut backend = TestBackend::new();
        let result = {
            let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
            mapper
                .map_page(0x4000, 0x40_0000, MapFlags::READ)
                .unwrap();
            unsafe { mapper.reclaim_empty_tree() }
        };

        assert_eq!(result, Err(Error::TreeNotEmpty));
        assert!(backend.released().is_empty());
    }

    #[test]
    fn tcr_uses_4k_granule_high_half_and_disables_ttbr0_walks_initially() {
        let value = tcr_el1_value(5).unwrap();
        assert_ne!(value & TCR_EPD0, 0);
        assert_eq!((value >> 30) & 0b11, 0b10);
        assert_eq!((value >> TCR_IPS_SHIFT) & 0b111, 5);
        assert_eq!(value & 0x3f, 16);
        assert_eq!((value >> 16) & 0x3f, 16);
    }

    #[test]
    fn transition_tcr_differs_only_by_enabling_ttbr0_walks() {
        let final_value = tcr_el1_value(5).unwrap();
        let transition = tcr_el1_transition_value(5).unwrap();
        assert_eq!(transition & TCR_EPD0, 0);
        assert_eq!(final_value, transition | TCR_EPD0);
    }

    #[test]
    fn rejects_52bit_physical_address_range_until_lpa_descriptors_exist() {
        assert_eq!(
            tcr_el1_value(6),
            Err(Error::UnsupportedPhysicalAddressRange)
        );
        assert_eq!(
            tcr_el1_transition_value(6),
            Err(Error::UnsupportedPhysicalAddressRange)
        );
    }

    #[test]
    fn step6_sctlr_policy_is_explicit_little_endian_wxn_and_stack_aligned() {
        let value = sctlr_el1_step6_value();
        assert_eq!(value & SCTLR_STEP6_REQUIRED_SET, SCTLR_STEP6_REQUIRED_SET);
        assert_eq!(value & SCTLR_STEP6_REQUIRED_CLEAR, 0);
        assert_eq!(value & !(SCTLR_STEP6_COMPAT | SCTLR_STEP6_REQUIRED_SET), 0);
        assert!(sctlr_el1_step6_readback_valid(value));
        assert!(!sctlr_el1_step6_readback_valid(value & !SCTLR_WXN));
        assert!(!sctlr_el1_step6_readback_valid(value | SCTLR_EE));
    }

    #[test]
    fn transition_config_contains_only_validated_register_images() {
        let config = El1TransitionConfig::for_physical_address_range(BASE, 5).unwrap();
        assert_eq!(config.root_table(), BASE);
        assert_eq!(config.mair_el1(), mair_el1_value());
        assert_eq!(config.tcr_el1() & TCR_EPD0, 0);
        assert_eq!(config.sctlr_el1(), sctlr_el1_step6_value());
        assert_eq!(
            El1TransitionConfig::for_physical_address_range(BASE + 1, 5),
            Err(Error::InvalidTableAddress)
        );
    }

    #[test]
    fn high_transition_destination_validation_matches_48bit_ttbr1_region() {
        assert!(high_half_address(0xffff_ffff_8020_0000));
        assert!(high_half_address(0xffff_0000_0000_0000));
        assert!(!high_half_address(0x0000_ffff_8020_0000));
    }

    #[test]
    fn mair_reserves_distinct_normal_and_device_attributes() {
        assert_eq!(mair_el1_value() & 0xff, MAIR_NORMAL_WB);
        assert_eq!((mair_el1_value() >> 8) & 0xff, MAIR_DEVICE_NGNRE);
    }
}
