// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const PAGE_SIZE: u64 = 4096;
pub const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;
pub const BOOT_WINDOW_BASE: u64 = 0xffff_ff80_0000_0000;
pub const BOOTINFO_VIRTUAL: u64 = BOOT_WINDOW_BASE + 0x20_0000;
pub const MEMORY_MAP_VIRTUAL: u64 = BOOT_WINDOW_BASE + 0x21_0000;
pub const STACK_GUARD_VIRTUAL: u64 = BOOT_WINDOW_BASE + 0x40_0000;
pub const STACK_BASE_VIRTUAL: u64 = STACK_GUARD_VIRTUAL + PAGE_SIZE;
pub const DOUBLE_FAULT_GUARD_VIRTUAL: u64 = BOOT_WINDOW_BASE + 0x50_0000;
pub const NMI_GUARD_VIRTUAL: u64 = BOOT_WINDOW_BASE + 0x60_0000;
pub const MACHINE_CHECK_GUARD_VIRTUAL: u64 = BOOT_WINDOW_BASE + 0x70_0000;
pub const DEFAULT_MEMORY_MAP_PAGES: usize = 16;
pub const DEFAULT_STACK_PAGES: usize = 16;
pub const DEFAULT_IST_STACK_PAGES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ZeroPages,
    Overflow,
    Unaligned,
    NonCanonical,
    Overlap,
    EntryOutsideKernelHalf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualRange {
    pub start: u64,
    pub len: u64,
}
impl VirtualRange {
    pub fn new(start: u64, len: u64) -> Result<Self, Error> {
        if len == 0 || start & (PAGE_SIZE - 1) != 0 || len & (PAGE_SIZE - 1) != 0 {
            return Err(Error::Unaligned);
        }
        if !is_canonical_48(start) {
            return Err(Error::NonCanonical);
        }
        let end = start.checked_add(len).ok_or(Error::Overflow)?;
        if !is_canonical_48(end - 1) {
            return Err(Error::NonCanonical);
        }
        Ok(Self { start, len })
    }
    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.len)
    }
    pub fn overlaps(self, other: Self) -> Result<bool, Error> {
        Ok(self.start < other.end().ok_or(Error::Overflow)?
            && other.start < self.end().ok_or(Error::Overflow)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackLayout {
    pub guard: VirtualRange,
    pub mapped: VirtualRange,
    pub initial_rsp: u64,
}
impl StackLayout {
    pub fn new(mapped_pages: usize) -> Result<Self, Error> {
        Self::at(STACK_GUARD_VIRTUAL, mapped_pages, true)
    }

    fn at(guard_start: u64, mapped_pages: usize, sysv_entry: bool) -> Result<Self, Error> {
        if mapped_pages == 0 {
            return Err(Error::ZeroPages);
        }
        let mapped_len = (mapped_pages as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::Overflow)?;
        let guard = VirtualRange::new(guard_start, PAGE_SIZE)?;
        let mapped = VirtualRange::new(guard.end().ok_or(Error::Overflow)?, mapped_len)?;
        let mut initial_rsp = mapped.end().ok_or(Error::Overflow)?;
        if sysv_entry {
            initial_rsp = initial_rsp.checked_sub(8).ok_or(Error::Overflow)?;
        }
        Ok(Self {
            guard,
            mapped,
            initial_rsp,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExceptionStacks {
    pub double_fault: StackLayout,
    pub nmi: StackLayout,
    pub machine_check: StackLayout,
}

impl ExceptionStacks {
    pub fn new(pages: usize) -> Result<Self, Error> {
        let result = Self {
            double_fault: StackLayout::at(DOUBLE_FAULT_GUARD_VIRTUAL, pages, false)?,
            nmi: StackLayout::at(NMI_GUARD_VIRTUAL, pages, false)?,
            machine_check: StackLayout::at(MACHINE_CHECK_GUARD_VIRTUAL, pages, false)?,
        };
        result.validate_disjoint()?;
        Ok(result)
    }

    fn validate_disjoint(self) -> Result<(), Error> {
        let ranges = [
            self.double_fault.guard,
            self.double_fault.mapped,
            self.nmi.guard,
            self.nmi.mapped,
            self.machine_check.guard,
            self.machine_check.mapped,
        ];
        for i in 0..ranges.len() {
            for j in i + 1..ranges.len() {
                if ranges[i].overlaps(ranges[j])? {
                    return Err(Error::Overlap);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffLayout {
    pub bootinfo: VirtualRange,
    pub memory_map: VirtualRange,
    pub stack: StackLayout,
    pub exception_stacks: ExceptionStacks,
}

impl HandoffLayout {
    pub fn new(memory_map_pages: usize, stack_pages: usize) -> Result<Self, Error> {
        if memory_map_pages == 0 {
            return Err(Error::ZeroPages);
        }
        let bootinfo = VirtualRange::new(BOOTINFO_VIRTUAL, PAGE_SIZE)?;
        let memory_map_len = (memory_map_pages as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::Overflow)?;
        let memory_map = VirtualRange::new(MEMORY_MAP_VIRTUAL, memory_map_len)?;
        let stack = StackLayout::new(stack_pages)?;
        let exception_stacks = ExceptionStacks::new(DEFAULT_IST_STACK_PAGES)?;
        let fixed = [bootinfo, memory_map, stack.guard, stack.mapped];
        for range in fixed {
            for ist in [
                exception_stacks.double_fault.guard,
                exception_stacks.double_fault.mapped,
                exception_stacks.nmi.guard,
                exception_stacks.nmi.mapped,
                exception_stacks.machine_check.guard,
                exception_stacks.machine_check.mapped,
            ] {
                if range.overlaps(ist)? {
                    return Err(Error::Overlap);
                }
            }
        }
        if bootinfo.overlaps(memory_map)?
            || bootinfo.overlaps(stack.guard)?
            || bootinfo.overlaps(stack.mapped)?
            || memory_map.overlaps(stack.guard)?
            || memory_map.overlaps(stack.mapped)?
            || stack.guard.overlaps(stack.mapped)?
        {
            return Err(Error::Overlap);
        }
        Ok(Self {
            bootinfo,
            memory_map,
            stack,
            exception_stacks,
        })
    }

    pub fn default_layout() -> Result<Self, Error> {
        Self::new(DEFAULT_MEMORY_MAP_PAGES, DEFAULT_STACK_PAGES)
    }

    pub fn validate_kernel_entry(self, entry: u64) -> Result<(), Error> {
        if !is_canonical_48(entry) || entry < KERNEL_BASE {
            return Err(Error::EntryOutsideKernelHalf);
        }
        Ok(())
    }
}

pub const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_handoff_keeps_guard_page_unmapped_and_sysv_aligned() {
        let layout = HandoffLayout::default_layout().unwrap();
        assert_eq!(layout.stack.guard.end().unwrap(), layout.stack.mapped.start);
        assert_eq!(
            layout.stack.initial_rsp + 8,
            layout.stack.mapped.end().unwrap()
        );
        assert_eq!(layout.stack.initial_rsp & 0xf, 8);
    }

    #[test]
    fn exception_stacks_have_independent_guard_pages() {
        let layout = HandoffLayout::default_layout().unwrap();
        for stack in [
            layout.exception_stacks.double_fault,
            layout.exception_stacks.nmi,
            layout.exception_stacks.machine_check,
        ] {
            assert_eq!(stack.guard.len, PAGE_SIZE);
            assert_eq!(stack.guard.end().unwrap(), stack.mapped.start);
            assert_eq!(stack.initial_rsp, stack.mapped.end().unwrap());
            assert_eq!(stack.initial_rsp & 0xf, 0);
        }
        assert!(
            !layout
                .exception_stacks
                .double_fault
                .mapped
                .overlaps(layout.exception_stacks.nmi.mapped)
                .unwrap()
        );
        assert!(
            !layout
                .exception_stacks
                .nmi
                .mapped
                .overlaps(layout.exception_stacks.machine_check.mapped)
                .unwrap()
        );
    }

    #[test]
    fn boot_regions_are_disjoint() {
        let layout = HandoffLayout::new(8, 32).unwrap();
        assert!(!layout.bootinfo.overlaps(layout.memory_map).unwrap());
        assert!(!layout.memory_map.overlaps(layout.stack.mapped).unwrap());
    }

    #[test]
    fn entry_must_be_high_half() {
        let layout = HandoffLayout::new(1, 4).unwrap();
        assert_eq!(
            layout.validate_kernel_entry(0x20_0000),
            Err(Error::EntryOutsideKernelHalf)
        );
        assert!(layout.validate_kernel_entry(0xffff_ffff_8020_0000).is_ok());
    }
}
