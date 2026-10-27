// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const PAGE_SIZE: u64 = 4096;
pub const PERCPU_REGION_BASE: u64 = 0xffff_ff80_4000_0000;
pub const PERCPU_STRIDE: u64 = 2 * 1024 * 1024;
pub const MAX_CPUS: usize = 256;
pub const KERNEL_STACK_PAGES: usize = 16;
pub const IST_STACK_PAGES: usize = 4;

const KERNEL_GUARD_OFFSET: u64 = 0x00000;
const DOUBLE_FAULT_GUARD_OFFSET: u64 = 0x20000;
const NMI_GUARD_OFFSET: u64 = 0x30000;
const MACHINE_CHECK_GUARD_OFFSET: u64 = 0x40000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CpuOutOfRange,
    Overflow,
    NonCanonical,
    Overlap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    pub start: u64,
    pub len: u64,
}
impl Range {
    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.len)
    }
    pub fn overlaps(self, other: Self) -> Result<bool, Error> {
        Ok(self.start < other.end().ok_or(Error::Overflow)?
            && other.start < self.end().ok_or(Error::Overflow)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardedStack {
    pub guard: Range,
    pub mapped: Range,
    /// Aligned top for TSS RSP/IST entries.
    pub top: u64,
    /// SysV function-entry value for a JMP-based handoff (top - 8).
    pub sysv_entry_rsp: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerCpuLayout {
    pub cpu_index: u16,
    pub region: Range,
    pub kernel_stack: GuardedStack,
    pub double_fault_stack: GuardedStack,
    pub nmi_stack: GuardedStack,
    pub machine_check_stack: GuardedStack,
}

impl PerCpuLayout {
    pub fn for_cpu(cpu_index: usize) -> Result<Self, Error> {
        if cpu_index >= MAX_CPUS {
            return Err(Error::CpuOutOfRange);
        }
        let offset = (cpu_index as u64)
            .checked_mul(PERCPU_STRIDE)
            .ok_or(Error::Overflow)?;
        let base = PERCPU_REGION_BASE
            .checked_add(offset)
            .ok_or(Error::Overflow)?;
        let region = Range {
            start: base,
            len: PERCPU_STRIDE,
        };
        let end = region.end().ok_or(Error::Overflow)?;
        if !is_canonical_48(base) || !is_canonical_48(end - 1) {
            return Err(Error::NonCanonical);
        }

        let layout = Self {
            cpu_index: cpu_index as u16,
            region,
            kernel_stack: guarded_stack(base, KERNEL_GUARD_OFFSET, KERNEL_STACK_PAGES)?,
            double_fault_stack: guarded_stack(base, DOUBLE_FAULT_GUARD_OFFSET, IST_STACK_PAGES)?,
            nmi_stack: guarded_stack(base, NMI_GUARD_OFFSET, IST_STACK_PAGES)?,
            machine_check_stack: guarded_stack(base, MACHINE_CHECK_GUARD_OFFSET, IST_STACK_PAGES)?,
        };
        layout.validate()?;
        Ok(layout)
    }

    fn validate(self) -> Result<(), Error> {
        let ranges = [
            self.kernel_stack.guard,
            self.kernel_stack.mapped,
            self.double_fault_stack.guard,
            self.double_fault_stack.mapped,
            self.nmi_stack.guard,
            self.nmi_stack.mapped,
            self.machine_check_stack.guard,
            self.machine_check_stack.mapped,
        ];
        for range in ranges {
            let end = range.end().ok_or(Error::Overflow)?;
            if range.start < self.region.start || end > self.region.end().ok_or(Error::Overflow)? {
                return Err(Error::Overlap);
            }
        }
        for left in 0..ranges.len() {
            for right in left + 1..ranges.len() {
                if ranges[left].overlaps(ranges[right])? {
                    return Err(Error::Overlap);
                }
            }
        }
        Ok(())
    }
}

fn guarded_stack(region_base: u64, guard_offset: u64, pages: usize) -> Result<GuardedStack, Error> {
    let guard_start = region_base
        .checked_add(guard_offset)
        .ok_or(Error::Overflow)?;
    let mapped_start = guard_start.checked_add(PAGE_SIZE).ok_or(Error::Overflow)?;
    let mapped_len = (pages as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(Error::Overflow)?;
    let mapped_end = mapped_start
        .checked_add(mapped_len)
        .ok_or(Error::Overflow)?;
    if !is_canonical_48(guard_start) || !is_canonical_48(mapped_end - 1) {
        return Err(Error::NonCanonical);
    }
    Ok(GuardedStack {
        guard: Range {
            start: guard_start,
            len: PAGE_SIZE,
        },
        mapped: Range {
            start: mapped_start,
            len: mapped_len,
        },
        top: mapped_end,
        sysv_entry_rsp: mapped_end.checked_sub(8).ok_or(Error::Overflow)?,
    })
}

const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_windows_are_disjoint_and_two_megabyte_aligned() {
        let a = PerCpuLayout::for_cpu(0).unwrap();
        let b = PerCpuLayout::for_cpu(1).unwrap();
        assert_eq!(a.region.start & (PERCPU_STRIDE - 1), 0);
        assert_eq!(b.region.start, a.region.start + PERCPU_STRIDE);
        assert!(!a.region.overlaps(b.region).unwrap());
    }

    #[test]
    fn every_stack_has_guard_and_correct_alignment() {
        let layout = PerCpuLayout::for_cpu(42).unwrap();
        for stack in [
            layout.kernel_stack,
            layout.double_fault_stack,
            layout.nmi_stack,
            layout.machine_check_stack,
        ] {
            assert_eq!(stack.guard.len, PAGE_SIZE);
            assert_eq!(stack.guard.end().unwrap(), stack.mapped.start);
            assert_eq!(stack.top & 0xf, 0);
            assert_eq!(stack.sysv_entry_rsp & 0xf, 8);
        }
    }

    #[test]
    fn maximum_cpu_fits_reserved_region() {
        assert!(PerCpuLayout::for_cpu(MAX_CPUS - 1).is_ok());
        assert_eq!(PerCpuLayout::for_cpu(MAX_CPUS), Err(Error::CpuOutOfRange));
    }
}
