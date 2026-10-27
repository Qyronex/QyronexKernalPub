// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_percpu::CpuIndex;
use kernal_scheduler::ThreadId;
use kernal_thread_context::KernelStack;

pub const PAGE_SIZE: u64 = 4096;
pub const THREAD_STACK_REGION_BASE: u64 = 0xffff_ff90_0000_0000;
pub const CPU_STACK_REGION_STRIDE: u64 = 32 * 1024 * 1024;
pub const THREAD_SLOT_STRIDE: u64 = 128 * 1024;
pub const THREAD_STACK_PAGES: usize = 16;
pub const THREAD_STACK_BYTES: u64 = THREAD_STACK_PAGES as u64 * PAGE_SIZE;
pub const MAX_CPU_STACK_REGIONS: usize = 256;
pub const MAX_THREAD_STACK_SLOTS: usize = (CPU_STACK_REGION_STRIDE / THREAD_SLOT_STRIDE) as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CpuOutOfRange,
    ThreadSlotOutOfRange,
    Overflow,
    NonCanonical,
    Context(kernal_thread_context::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadStackLayout {
    pub cpu: CpuIndex,
    pub thread: ThreadId,
    pub slot_base: u64,
    pub guard_start: u64,
    pub mapped_start: u64,
    pub mapped_len: u64,
    pub top: u64,
    pub sysv_entry_rsp: u64,
}

impl ThreadStackLayout {
    pub fn for_thread(cpu: CpuIndex, thread: ThreadId) -> Result<Self, Error> {
        let cpu_index = cpu.0 as usize;
        if cpu_index >= MAX_CPU_STACK_REGIONS {
            return Err(Error::CpuOutOfRange);
        }
        let slot_index = thread.slot as usize;
        if slot_index >= MAX_THREAD_STACK_SLOTS {
            return Err(Error::ThreadSlotOutOfRange);
        }

        let cpu_offset = (cpu_index as u64)
            .checked_mul(CPU_STACK_REGION_STRIDE)
            .ok_or(Error::Overflow)?;
        let cpu_base = THREAD_STACK_REGION_BASE
            .checked_add(cpu_offset)
            .ok_or(Error::Overflow)?;
        let slot_offset = (slot_index as u64)
            .checked_mul(THREAD_SLOT_STRIDE)
            .ok_or(Error::Overflow)?;
        let slot_base = cpu_base.checked_add(slot_offset).ok_or(Error::Overflow)?;
        let guard_start = slot_base;
        let mapped_start = guard_start.checked_add(PAGE_SIZE).ok_or(Error::Overflow)?;
        let top = mapped_start
            .checked_add(THREAD_STACK_BYTES)
            .ok_or(Error::Overflow)?;
        let slot_end = slot_base
            .checked_add(THREAD_SLOT_STRIDE)
            .ok_or(Error::Overflow)?;
        if top > slot_end {
            return Err(Error::Overflow);
        }
        if !is_canonical_48(slot_base) || !is_canonical_48(slot_end - 1) {
            return Err(Error::NonCanonical);
        }

        Ok(Self {
            cpu,
            thread,
            slot_base,
            guard_start,
            mapped_start,
            mapped_len: THREAD_STACK_BYTES,
            top,
            sysv_entry_rsp: top.checked_sub(8).ok_or(Error::Overflow)?,
        })
    }

    pub fn context_stack(self) -> Result<KernelStack, Error> {
        KernelStack::new(self.guard_start, self.mapped_start, self.mapped_len)
            .map_err(Error::Context)
    }
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
    fn neighboring_threads_get_disjoint_slots_and_guard_pages() {
        let a = ThreadStackLayout::for_thread(
            CpuIndex(0),
            ThreadId {
                slot: 0,
                generation: 1,
            },
        )
        .unwrap();
        let b = ThreadStackLayout::for_thread(
            CpuIndex(0),
            ThreadId {
                slot: 1,
                generation: 1,
            },
        )
        .unwrap();
        assert_eq!(b.slot_base - a.slot_base, THREAD_SLOT_STRIDE);
        assert_eq!(a.guard_start + PAGE_SIZE, a.mapped_start);
        assert!(a.top <= b.slot_base);
        assert_eq!(a.top & 0xf, 0);
        assert_eq!(a.sysv_entry_rsp & 0xf, 8);
    }

    #[test]
    fn cpu_regions_are_disjoint() {
        let a = ThreadStackLayout::for_thread(
            CpuIndex(0),
            ThreadId {
                slot: 0,
                generation: 1,
            },
        )
        .unwrap();
        let b = ThreadStackLayout::for_thread(
            CpuIndex(1),
            ThreadId {
                slot: 0,
                generation: 1,
            },
        )
        .unwrap();
        assert_eq!(b.slot_base - a.slot_base, CPU_STACK_REGION_STRIDE);
    }

    #[test]
    fn scheduler_capacity_fits_virtual_slot_capacity() {
        assert_eq!(MAX_THREAD_STACK_SLOTS, 256);
        assert!(
            ThreadStackLayout::for_thread(
                CpuIndex(0),
                ThreadId {
                    slot: (MAX_THREAD_STACK_SLOTS - 1) as u16,
                    generation: 1
                }
            )
            .is_ok()
        );
        assert_eq!(
            ThreadStackLayout::for_thread(
                CpuIndex(0),
                ThreadId {
                    slot: MAX_THREAD_STACK_SLOTS as u16,
                    generation: 1
                }
            ),
            Err(Error::ThreadSlotOutOfRange)
        );
    }

    #[test]
    fn layout_converts_to_context_stack_contract() {
        let layout = ThreadStackLayout::for_thread(
            CpuIndex(3),
            ThreadId {
                slot: 9,
                generation: 2,
            },
        )
        .unwrap();
        let stack = layout.context_stack().unwrap();
        assert_eq!(stack.guard_start, layout.guard_start);
        assert_eq!(stack.mapped_start, layout.mapped_start);
        assert_eq!(stack.top().unwrap(), layout.top);
    }
}
