// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_bootinfo::{MemoryRegionV1, memory_attr, memory_kind};

pub const PAGE_SIZE: u64 = 4096;
pub const DEFAULT_LOW_MEMORY_RESERVE: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PhysFrame(u64);

impl PhysFrame {
    pub const fn start_address(self) -> u64 {
        self.0
    }
    pub const fn end_address(self) -> Option<u64> {
        self.0.checked_add(PAGE_SIZE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NoUsableMemory,
    InvalidRegion,
    Overflow,
    UnalignedMinimum,
}

pub struct BootstrapFrameAllocator<'a> {
    regions: &'a [MemoryRegionV1],
    region_index: usize,
    next: u64,
    end: u64,
    minimum_address: u64,
    allocated_frames: u64,
}

impl<'a> BootstrapFrameAllocator<'a> {
    pub fn new(regions: &'a [MemoryRegionV1]) -> Result<Self, Error> {
        Self::with_minimum_address(regions, DEFAULT_LOW_MEMORY_RESERVE)
    }

    pub fn with_minimum_address(
        regions: &'a [MemoryRegionV1],
        minimum_address: u64,
    ) -> Result<Self, Error> {
        if minimum_address & (PAGE_SIZE - 1) != 0 {
            return Err(Error::UnalignedMinimum);
        }
        let mut allocator = Self {
            regions,
            region_index: 0,
            next: 0,
            end: 0,
            minimum_address,
            allocated_frames: 0,
        };
        allocator.advance_region()?;
        Ok(allocator)
    }

    pub fn allocate(&mut self) -> Option<PhysFrame> {
        if self.next >= self.end && self.advance_region().is_err() {
            return None;
        }
        let frame = PhysFrame(self.next);
        self.next = self.next.checked_add(PAGE_SIZE)?;
        self.allocated_frames = self.allocated_frames.saturating_add(1);
        Some(frame)
    }

    pub const fn allocated_frames(&self) -> u64 {
        self.allocated_frames
    }
    pub const fn minimum_address(&self) -> u64 {
        self.minimum_address
    }

    fn advance_region(&mut self) -> Result<(), Error> {
        while self.region_index < self.regions.len() {
            let region = self.regions[self.region_index];
            self.region_index += 1;
            if !region.is_structurally_valid() {
                return Err(Error::InvalidRegion);
            }
            if region.kind != memory_kind::USABLE || region.attributes & memory_attr::RUNTIME != 0 {
                continue;
            }
            let raw_end = region.end().ok_or(Error::Overflow)?;
            let raw_start = core::cmp::max(region.start, self.minimum_address);
            let start = align_up(raw_start, PAGE_SIZE).ok_or(Error::Overflow)?;
            let end = align_down(raw_end, PAGE_SIZE);
            if start >= end {
                continue;
            }
            self.next = start;
            self.end = end;
            return Ok(());
        }
        Err(Error::NoUsableMemory)
    }
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}
const fn align_up(value: u64, align: u64) -> Option<u64> {
    match value.checked_add(align - 1) {
        Some(value) => Some(align_down(value, align)),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_low_memory_and_nonusable_regions() {
        let regions = [
            MemoryRegionV1::new(0, 0x20_0000, memory_kind::RESERVED, 0),
            MemoryRegionV1::new(0x80_000, 0x100_000, memory_kind::USABLE, 0),
            MemoryRegionV1::new(0x20_0000, 0x4000, memory_kind::RECLAIMABLE, 0),
            MemoryRegionV1::new(0x30_0000, 0x4000, memory_kind::USABLE, 0),
        ];
        let mut allocator = BootstrapFrameAllocator::new(&regions).unwrap();
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x10_0000);
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x10_1000);
    }

    #[test]
    fn runtime_flagged_usable_memory_is_never_allocated() {
        let regions = [
            MemoryRegionV1::new(0x20_0000, 0x4000, memory_kind::USABLE, memory_attr::RUNTIME),
            MemoryRegionV1::new(0x30_0000, 0x4000, memory_kind::USABLE, 0),
        ];
        let mut allocator = BootstrapFrameAllocator::new(&regions).unwrap();
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x30_0000);
    }

    #[test]
    fn allocator_returns_all_and_only_complete_frames() {
        let regions = [MemoryRegionV1::new(
            0x10_0003,
            0x3001,
            memory_kind::USABLE,
            0,
        )];
        let mut allocator = BootstrapFrameAllocator::new(&regions).unwrap();

        let first = allocator.allocate().unwrap();
        assert_eq!(first.start_address(), 0x10_1000);
        assert_eq!(first.end_address(), Some(0x10_2000));

        let second = allocator.allocate().unwrap();
        assert_eq!(second.start_address(), 0x10_2000);
        assert_eq!(second.end_address(), Some(0x10_3000));

        assert!(allocator.allocate().is_none());
        assert_eq!(allocator.allocated_frames(), 2);
    }

    #[test]
    fn custom_minimum_must_be_page_aligned() {
        let regions = [MemoryRegionV1::new(
            0x20_0000,
            0x4000,
            memory_kind::USABLE,
            0,
        )];
        assert_eq!(
            BootstrapFrameAllocator::with_minimum_address(&regions, 0x1234).err(),
            Some(Error::UnalignedMinimum)
        );
    }
}
