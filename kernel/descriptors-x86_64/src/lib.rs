// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

pub const GDT_ENTRIES: usize = 8;
pub const TSS_LIMIT: u32 = core::mem::size_of::<TaskStateSegment>() as u32 - 1;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selector(pub u16);

impl Selector {
    pub const KERNEL_CODE: Self = Self(1 << 3);
    pub const KERNEL_DATA: Self = Self(2 << 3);
    pub const USER_DATA: Self = Self((3 << 3) | 3);
    pub const USER_CODE: Self = Self((4 << 3) | 3);
    pub const TSS: Self = Self(5 << 3);
    pub const fn bits(self) -> u16 {
        self.0
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TaskStateSegment {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            reserved2: 0,
            reserved3: 0,
            iomap_base: core::mem::size_of::<Self>() as u16,
        }
    }

    pub fn set_ring0_stack(&mut self, top: u64) -> Result<(), Error> {
        validate_stack(top)?;
        self.rsp0 = top;
        Ok(())
    }

    /// IST index is the architectural 1-based IDT value 1..=7.
    pub fn set_ist(&mut self, index: u8, top: u64) -> Result<(), Error> {
        if !(1..=7).contains(&index) {
            return Err(Error::InvalidIst);
        }
        validate_stack(top)?;
        match index {
            1 => self.ist1 = top,
            2 => self.ist2 = top,
            3 => self.ist3 = top,
            4 => self.ist4 = top,
            5 => self.ist5 = top,
            6 => self.ist6 = top,
            7 => self.ist7 = top,
            _ => return Err(Error::InvalidIst),
        }
        Ok(())
    }

    pub fn ring0_stack(&self) -> u64 {
        self.rsp0
    }

    pub fn ist(&self, index: u8) -> Option<u64> {
        match index {
            1 => Some(self.ist1),
            2 => Some(self.ist2),
            3 => Some(self.ist3),
            4 => Some(self.ist4),
            5 => Some(self.ist5),
            6 => Some(self.ist6),
            7 => Some(self.ist7),
            _ => None,
        }
    }
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidIst,
    InvalidStack,
    NonCanonicalBase,
    AlreadyInitialized,
    InitializationInProgress,
}

#[repr(C, align(16))]
pub struct GlobalDescriptorTable {
    entries: [u64; GDT_ENTRIES],
}

impl GlobalDescriptorTable {
    pub const fn new() -> Self {
        let mut entries = [0u64; GDT_ENTRIES];
        entries[0] = 0;
        entries[1] = code_descriptor(0);
        entries[2] = data_descriptor(0);
        entries[3] = data_descriptor(3);
        entries[4] = code_descriptor(3);
        Self { entries }
    }

    pub fn install_tss(&mut self, tss: &'static TaskStateSegment) -> Result<(), Error> {
        let base = tss as *const TaskStateSegment as u64;
        if !is_canonical_48(base) {
            return Err(Error::NonCanonicalBase);
        }
        let descriptor = tss_descriptor(base, TSS_LIMIT);
        self.entries[5] = descriptor.low;
        self.entries[6] = descriptor.high;
        Ok(())
    }

    pub const fn entries(&self) -> &[u64; GDT_ENTRIES] {
        &self.entries
    }
    pub const fn byte_limit(&self) -> u16 {
        (core::mem::size_of::<Self>() - 1) as u16
    }
}

impl Default for GlobalDescriptorTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorConfig {
    pub ring0_stack_top: u64,
    pub double_fault_stack_top: u64,
    pub nmi_stack_top: u64,
    pub machine_check_stack_top: u64,
}

struct DescriptorData {
    tss: TaskStateSegment,
    gdt: GlobalDescriptorTable,
}

impl DescriptorData {
    const fn empty() -> Self {
        Self {
            tss: TaskStateSegment::new(),
            gdt: GlobalDescriptorTable::new(),
        }
    }
}

/// One-shot static storage for one CPU's GDT/TSS. BSP and every AP should own a separate cell.
pub struct DescriptorCell {
    state: AtomicU8,
    data: UnsafeCell<DescriptorData>,
}

// SAFETY: mutation is guarded by the one-shot atomic state machine. After state=2 the data is
// immutable forever, so shared references are race-free.
unsafe impl Sync for DescriptorCell {}

impl DescriptorCell {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            data: UnsafeCell::new(DescriptorData::empty()),
        }
    }

    pub fn prepare(
        &'static self,
        config: DescriptorConfig,
    ) -> Result<PreparedDescriptors<'static>, Error> {
        validate_stack(config.ring0_stack_top)?;
        validate_stack(config.double_fault_stack_top)?;
        validate_stack(config.nmi_stack_top)?;
        validate_stack(config.machine_check_stack_top)?;
        match self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(1) => return Err(Error::InitializationInProgress),
            Err(_) => return Err(Error::AlreadyInitialized),
        }

        // SAFETY: CAS above grants this invocation exclusive initialization ownership.
        let data = unsafe { &mut *self.data.get() };
        if data.tss.set_ring0_stack(config.ring0_stack_top).is_err()
            || data.tss.set_ist(1, config.double_fault_stack_top).is_err()
            || data.tss.set_ist(2, config.nmi_stack_top).is_err()
            || data.tss.set_ist(3, config.machine_check_stack_top).is_err()
        {
            self.state.store(0, Ordering::Release);
            return Err(Error::InvalidStack);
        }
        // SAFETY: data lives inside a static DescriptorCell and will never move.
        let tss: &'static TaskStateSegment = unsafe { &*core::ptr::addr_of!(data.tss) };
        if let Err(error) = data.gdt.install_tss(tss) {
            self.state.store(0, Ordering::Release);
            return Err(error);
        }
        self.state.store(2, Ordering::Release);
        // SAFETY: state=2 freezes initialized storage for the rest of the boot.
        let gdt: &'static GlobalDescriptorTable = unsafe { &*core::ptr::addr_of!(data.gdt) };
        Ok(PreparedDescriptors { gdt, tss })
    }
}

impl Default for DescriptorCell {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PreparedDescriptors<'a> {
    pub gdt: &'a GlobalDescriptorTable,
    pub tss: &'a TaskStateSegment,
}

impl PreparedDescriptors<'static> {
    /// Loads GDT, reloads architectural segment state, and loads TR.
    ///
    /// # Safety
    /// Must execute in x86_64 ring 0 with interrupts disabled or with an already-valid IDT. The
    /// GDT/TSS storage is static, and all configured stack addresses must remain mapped.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn load(self) {
        let pointer = DescriptorTablePointer::for_gdt(self.gdt);
        // SAFETY: caller guarantees ring 0 and static GDT lifetime.
        unsafe { asm!("lgdt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags)) };
        // Reload CS using a far return. Label 2 is chosen to avoid LLVM's 0/1 ambiguity.
        unsafe {
            asm!(
                "push 0x08",
                "lea rax, [rip + 2f]",
                "push rax",
                "retfq",
                "2:",
                out("rax") _,
                options(preserves_flags)
            )
        };
        let data = Selector::KERNEL_DATA.bits();
        // SAFETY: kernel data selector points at a present ring-0 data descriptor.
        unsafe {
            asm!(
                "mov ds, ax", "mov es, ax", "mov ss, ax",
                in("ax") data,
                options(nostack, preserves_flags)
            )
        };
        let tss = Selector::TSS.bits();
        // SAFETY: TSS descriptor was installed in this GDT and points at static initialized data.
        unsafe { asm!("ltr ax", in("ax") tss, options(nostack, preserves_flags)) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemDescriptor {
    pub low: u64,
    pub high: u64,
}

pub const fn code_descriptor(dpl: u8) -> u64 {
    let dpl = (dpl & 0x3) as u64;
    (1u64 << 47) | (dpl << 45) | (1u64 << 44) | (0b1010u64 << 40) | (1u64 << 53)
}

pub const fn data_descriptor(dpl: u8) -> u64 {
    let dpl = (dpl & 0x3) as u64;
    (1u64 << 47) | (dpl << 45) | (1u64 << 44) | (0b0010u64 << 40)
}

pub const fn tss_descriptor(base: u64, limit: u32) -> SystemDescriptor {
    let limit = limit as u64;
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89u64 << 40)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    let high = (base >> 32) & 0xffff_ffff;
    SystemDescriptor { low, high }
}

pub const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

fn validate_stack(top: u64) -> Result<(), Error> {
    if !is_canonical_48(top) || top < 0xffff_8000_0000_0000 || top & 0xf != 0 {
        Err(Error::InvalidStack)
    } else {
        Ok(())
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorTablePointer {
    pub limit: u16,
    pub base: u64,
}

impl DescriptorTablePointer {
    pub fn for_gdt(gdt: &'static GlobalDescriptorTable) -> Self {
        Self {
            limit: gdt.byte_limit(),
            base: gdt as *const GlobalDescriptorTable as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_expected_privilege_levels() {
        assert_eq!(Selector::KERNEL_CODE.bits(), 0x08);
        assert_eq!(Selector::KERNEL_DATA.bits(), 0x10);
        assert_eq!(Selector::USER_DATA.bits(), 0x1b);
        assert_eq!(Selector::USER_CODE.bits(), 0x23);
        assert_eq!(Selector::TSS.bits(), 0x28);
    }

    #[test]
    fn access_bytes_are_code_data_not_system_descriptors() {
        assert_eq!((code_descriptor(0) >> 40) & 0xff, 0x9a);
        assert_eq!((data_descriptor(0) >> 40) & 0xff, 0x92);
        assert_eq!((code_descriptor(3) >> 40) & 0xff, 0xfa);
        assert_eq!((data_descriptor(3) >> 40) & 0xff, 0xf2);
    }

    #[test]
    fn tss_layout_matches_x86_64_architecture() {
        assert_eq!(core::mem::size_of::<TaskStateSegment>(), 104);
        assert_eq!(TSS_LIMIT, 103);
    }

    #[test]
    fn tss_descriptor_round_trips_base_fields() {
        let base = 0xffff_ffff_8123_4000;
        let desc = tss_descriptor(base, TSS_LIMIT);
        let decoded = ((desc.low >> 16) & 0x00ff_ffff)
            | (((desc.low >> 56) & 0xff) << 24)
            | ((desc.high & 0xffff_ffff) << 32);
        assert_eq!(decoded, base);
        assert_eq!((desc.low >> 40) & 0xff, 0x89);
    }

    #[test]
    fn tss_rejects_unaligned_or_user_stack() {
        let mut tss = TaskStateSegment::new();
        assert_eq!(
            tss.set_ist(0, 0xffff_ffff_9000_0000),
            Err(Error::InvalidIst)
        );
        assert_eq!(tss.set_ist(1, 0x7000_0000), Err(Error::InvalidStack));
        assert_eq!(
            tss.set_ist(1, 0xffff_ffff_9000_0008),
            Err(Error::InvalidStack)
        );
        tss.set_ist(1, 0xffff_ffff_9000_0000).unwrap();
        assert_eq!(tss.ist(1), Some(0xffff_ffff_9000_0000));
    }
}
