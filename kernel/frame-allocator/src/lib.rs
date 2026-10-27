// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_bootinfo::{MemoryRegionV1, memory_attr, memory_kind};

pub const PAGE_SIZE: u64 = 4096;
pub const LOW_MEMORY_RESERVE: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameRange {
    pub start: u64,
    pub pages: u64,
}

impl FrameRange {
    pub const EMPTY: Self = Self { start: 0, pages: 0 };

    pub fn new(start: u64, pages: u64) -> Result<Self, Error> {
        if pages == 0 || start & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidRange);
        }
        let bytes = pages.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?;
        start.checked_add(bytes).ok_or(Error::Overflow)?;
        Ok(Self { start, pages })
    }

    pub fn end(self) -> Result<u64, Error> {
        self.start
            .checked_add(self.pages.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)
    }

    pub fn bytes(self) -> Result<u64, Error> {
        self.pages.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidRange,
    Overflow,
    Capacity,
    NoMemory,
    DoubleFreeOrOverlap,
    ReservedRange,
    InvalidAlignment,
    InvalidBootMap,
}

/// Sorted, mergeable physical free extents with fixed metadata capacity.
///
/// This allocator owns only normalized `USABLE` RAM. Allocation splits an extent; free inserts a
/// range and coalesces adjacent neighbors. Explicit reservations are persistent ownership exclusions:
/// reserving a range transactionally removes its currently-free pages and later `free()` calls may
/// never reintroduce any overlapping page. Metadata never allocates. Future NUMA support should
/// instantiate one allocator per proximity domain rather than adding one global lock here.
pub struct ExtentAllocator<const N: usize> {
    extents: [FrameRange; N],
    len: usize,
    free_pages: u64,
    reservations: [FrameRange; N],
    reservation_len: usize,
}

impl<const N: usize> ExtentAllocator<N> {
    pub const fn new() -> Self {
        Self {
            extents: [FrameRange::EMPTY; N],
            len: 0,
            free_pages: 0,
            reservations: [FrameRange::EMPTY; N],
            reservation_len: 0,
        }
    }

    pub fn from_boot_map(regions: &[MemoryRegionV1]) -> Result<Self, Error> {
        let mut allocator = Self::new();
        let mut previous_end = 0u64;
        for region in regions.iter().copied() {
            if !region.is_structurally_valid() || region.start < previous_end {
                return Err(Error::InvalidBootMap);
            }
            previous_end = region.end().ok_or(Error::InvalidBootMap)?;
            if region.kind != memory_kind::USABLE || region.attributes & memory_attr::RUNTIME != 0 {
                continue;
            }
            let raw_end = region.end().ok_or(Error::Overflow)?;
            let start =
                align_up(region.start.max(LOW_MEMORY_RESERVE), PAGE_SIZE).ok_or(Error::Overflow)?;
            let end = align_down(raw_end, PAGE_SIZE);
            if start >= end {
                continue;
            }
            let pages = (end - start) / PAGE_SIZE;
            allocator.free(FrameRange::new(start, pages)?)?;
        }
        if allocator.free_pages == 0 {
            return Err(Error::NoMemory);
        }
        Ok(allocator)
    }

    pub const fn free_pages(&self) -> u64 {
        self.free_pages
    }
    pub const fn extent_count(&self) -> usize {
        self.len
    }
    pub fn extents(&self) -> &[FrameRange] {
        &self.extents[..self.len]
    }
    pub const fn reservation_count(&self) -> usize {
        self.reservation_len
    }
    pub fn reservations(&self) -> &[FrameRange] {
        &self.reservations[..self.reservation_len]
    }

    /// Permanently excludes a physical range from this allocator.
    ///
    /// Every currently-free page overlapping `range` is removed. The reservation itself is retained
    /// even when none of its pages are currently free, so a later `free()` cannot accidentally
    /// reintroduce kernel, firmware, page-table, initrd or other externally-owned frames.
    ///
    /// The operation is transactional: all split extents are first constructed in temporary fixed
    /// storage. If metadata capacity or arithmetic fails, neither free extents, accounting nor the
    /// persistent reservation set is changed.
    pub fn reserve(&mut self, range: FrameRange) -> Result<u64, Error> {
        let range = FrameRange::new(range.start, range.pages)?;
        let range_end = range.end()?;
        if self.reservation_len == N {
            return Err(Error::Capacity);
        }
        for reserved in self.reservations[..self.reservation_len].iter().copied() {
            if ranges_overlap(reserved.start, reserved.end()?, range.start, range_end) {
                return Err(Error::ReservedRange);
            }
        }

        let mut staged = [FrameRange::EMPTY; N];
        let mut staged_len = 0usize;
        let mut removed_pages = 0u64;

        for extent in self.extents[..self.len].iter().copied() {
            let extent_end = extent.end()?;
            if !ranges_overlap(extent.start, extent_end, range.start, range_end) {
                if staged_len == N {
                    return Err(Error::Capacity);
                }
                staged[staged_len] = extent;
                staged_len += 1;
                continue;
            }

            let overlap_start = extent.start.max(range.start);
            let overlap_end = extent_end.min(range_end);
            let overlap_pages = (overlap_end - overlap_start) / PAGE_SIZE;
            removed_pages = removed_pages
                .checked_add(overlap_pages)
                .ok_or(Error::Overflow)?;

            if extent.start < overlap_start {
                if staged_len == N {
                    return Err(Error::Capacity);
                }
                staged[staged_len] =
                    FrameRange::new(extent.start, (overlap_start - extent.start) / PAGE_SIZE)?;
                staged_len += 1;
            }
            if overlap_end < extent_end {
                if staged_len == N {
                    return Err(Error::Capacity);
                }
                staged[staged_len] =
                    FrameRange::new(overlap_end, (extent_end - overlap_end) / PAGE_SIZE)?;
                staged_len += 1;
            }
        }

        let remaining_pages = self
            .free_pages
            .checked_sub(removed_pages)
            .ok_or(Error::Overflow)?;
        self.extents = staged;
        self.len = staged_len;
        self.free_pages = remaining_pages;
        self.reservations[self.reservation_len] = range;
        self.reservation_len += 1;
        Ok(removed_pages)
    }

    pub fn allocate(&mut self, pages: u64, alignment_pages: u64) -> Result<FrameRange, Error> {
        if pages == 0 {
            return Err(Error::InvalidRange);
        }
        if alignment_pages == 0 || !alignment_pages.is_power_of_two() {
            return Err(Error::InvalidAlignment);
        }
        let alignment = alignment_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::Overflow)?;
        let requested_bytes = pages.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?;

        // Best-fit reduces fragmentation while keeping metadata operations bounded by N.
        let mut best: Option<(usize, u64, u64)> = None; // index, aligned start, waste pages
        for (index, extent) in self.extents[..self.len].iter().copied().enumerate() {
            let extent_end = extent.end()?;
            let aligned = align_up(extent.start, alignment).ok_or(Error::Overflow)?;
            let allocation_end = aligned
                .checked_add(requested_bytes)
                .ok_or(Error::Overflow)?;
            if allocation_end > extent_end {
                continue;
            }
            let prefix_pages = (aligned - extent.start) / PAGE_SIZE;
            let suffix_pages = (extent_end - allocation_end) / PAGE_SIZE;
            let waste = prefix_pages
                .checked_add(suffix_pages)
                .ok_or(Error::Overflow)?;
            if best.is_none_or(|(_, _, current)| waste < current) {
                best = Some((index, aligned, waste));
            }
        }
        let Some((index, start, _)) = best else {
            return Err(Error::NoMemory);
        };
        let old = self.extents[index];
        let old_end = old.end()?;
        let end = start.checked_add(requested_bytes).ok_or(Error::Overflow)?;
        let prefix_pages = (start - old.start) / PAGE_SIZE;
        let suffix_pages = (old_end - end) / PAGE_SIZE;

        match (prefix_pages, suffix_pages) {
            (0, 0) => self.remove_at(index),
            (0, suffix) => self.extents[index] = FrameRange::new(end, suffix)?,
            (prefix, 0) => self.extents[index] = FrameRange::new(old.start, prefix)?,
            (prefix, suffix) => {
                if self.len == N {
                    return Err(Error::Capacity);
                }
                self.extents[index] = FrameRange::new(old.start, prefix)?;
                self.insert_at(index + 1, FrameRange::new(end, suffix)?)?;
            }
        }
        self.free_pages = self.free_pages.checked_sub(pages).ok_or(Error::Overflow)?;
        FrameRange::new(start, pages)
    }

    pub fn allocate_page(&mut self) -> Result<u64, Error> {
        Ok(self.allocate(1, 1)?.start)
    }

    pub fn free(&mut self, range: FrameRange) -> Result<(), Error> {
        let range = FrameRange::new(range.start, range.pages)?;
        let end = range.end()?;
        for reserved in self.reservations[..self.reservation_len].iter().copied() {
            if ranges_overlap(reserved.start, reserved.end()?, range.start, end) {
                return Err(Error::ReservedRange);
            }
        }

        let mut position = 0usize;
        while position < self.len && self.extents[position].start < range.start {
            position += 1;
        }

        if position > 0 {
            let previous = self.extents[position - 1];
            if previous.end()? > range.start {
                return Err(Error::DoubleFreeOrOverlap);
            }
        }
        if position < self.len && end > self.extents[position].start {
            return Err(Error::DoubleFreeOrOverlap);
        }

        let merge_left = position > 0 && self.extents[position - 1].end()? == range.start;
        let merge_right = position < self.len && end == self.extents[position].start;
        match (merge_left, merge_right) {
            (true, true) => {
                let left = self.extents[position - 1];
                let right = self.extents[position];
                let pages = left
                    .pages
                    .checked_add(range.pages)
                    .and_then(|v| v.checked_add(right.pages))
                    .ok_or(Error::Overflow)?;
                self.extents[position - 1] = FrameRange::new(left.start, pages)?;
                self.remove_at(position);
            }
            (true, false) => {
                let left = self.extents[position - 1];
                self.extents[position - 1] = FrameRange::new(
                    left.start,
                    left.pages.checked_add(range.pages).ok_or(Error::Overflow)?,
                )?;
            }
            (false, true) => {
                let right = self.extents[position];
                self.extents[position] = FrameRange::new(
                    range.start,
                    range
                        .pages
                        .checked_add(right.pages)
                        .ok_or(Error::Overflow)?,
                )?;
            }
            (false, false) => {
                if self.len == N {
                    return Err(Error::Capacity);
                }
                self.insert_at(position, range)?;
            }
        }
        self.free_pages = self
            .free_pages
            .checked_add(range.pages)
            .ok_or(Error::Overflow)?;
        Ok(())
    }

    fn insert_at(&mut self, index: usize, range: FrameRange) -> Result<(), Error> {
        if self.len == N || index > self.len {
            return Err(Error::Capacity);
        }
        let mut cursor = self.len;
        while cursor > index {
            self.extents[cursor] = self.extents[cursor - 1];
            cursor -= 1;
        }
        self.extents[index] = range;
        self.len += 1;
        Ok(())
    }

    fn remove_at(&mut self, index: usize) {
        let mut cursor = index;
        while cursor + 1 < self.len {
            self.extents[cursor] = self.extents[cursor + 1];
            cursor += 1;
        }
        self.len -= 1;
        self.extents[self.len] = FrameRange::EMPTY;
    }
}

impl<const N: usize> Default for ExtentAllocator<N> {
    fn default() -> Self {
        Self::new()
    }
}

const fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

const fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}
const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    match value.checked_add(alignment - 1) {
        Some(aligned) => Some(align_down(aligned, alignment)),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usable(start: u64, len: u64) -> MemoryRegionV1 {
        MemoryRegionV1::new(start, len, memory_kind::USABLE, memory_attr::NONE)
    }

    #[test]
    fn boot_map_reserves_low_megabyte_and_nonusable_memory() {
        let map = [
            usable(0, 2 * 1024 * 1024),
            MemoryRegionV1::new(2 * 1024 * 1024, 1024 * 1024, memory_kind::FIRMWARE, 0),
            usable(3 * 1024 * 1024, 1024 * 1024),
        ];
        let allocator = ExtentAllocator::<8>::from_boot_map(&map).unwrap();
        assert_eq!(allocator.extents()[0].start, LOW_MEMORY_RESERVE);
        assert_eq!(allocator.extent_count(), 2);
    }

    #[test]
    fn split_then_free_coalesces_original_extent() {
        let mut allocator = ExtentAllocator::<8>::new();
        allocator
            .free(FrameRange::new(0x100000, 32).unwrap())
            .unwrap();
        let allocation = allocator.allocate(4, 1).unwrap();
        assert_eq!(allocator.free_pages(), 28);
        allocator.free(allocation).unwrap();
        assert_eq!(allocator.extent_count(), 1);
        assert_eq!(
            allocator.extents()[0],
            FrameRange::new(0x100000, 32).unwrap()
        );
        assert_eq!(allocator.free_pages(), 32);
    }

    #[test]
    fn aligned_allocation_splits_prefix_and_suffix() {
        let mut allocator = ExtentAllocator::<8>::new();
        allocator
            .free(FrameRange::new(0x101000, 31).unwrap())
            .unwrap();
        let allocation = allocator.allocate(2, 4).unwrap();
        assert_eq!(allocation.start & (4 * PAGE_SIZE - 1), 0);
        assert_eq!(allocation.pages, 2);
        assert_eq!(allocator.extent_count(), 2);
    }

    #[test]
    fn persistent_reservation_splits_free_space_and_blocks_reclaim() {
        let mut allocator = ExtentAllocator::<8>::new();
        allocator
            .free(FrameRange::new(0x100000, 8).unwrap())
            .unwrap();

        let reserved = FrameRange::new(0x103000, 2).unwrap();
        assert_eq!(allocator.reserve(reserved).unwrap(), 2);
        assert_eq!(allocator.free_pages(), 6);
        assert_eq!(allocator.extent_count(), 2);
        assert_eq!(allocator.reservation_count(), 1);
        assert_eq!(allocator.reservations(), &[reserved]);
        assert_eq!(allocator.free(reserved), Err(Error::ReservedRange));

        while let Ok(page) = allocator.allocate(1, 1) {
            assert!(page.end().unwrap() <= reserved.start || page.start >= reserved.end().unwrap());
        }
    }

    #[test]
    fn reservation_can_remove_pages_from_multiple_free_extents() {
        let mut allocator = ExtentAllocator::<8>::new();
        allocator
            .free(FrameRange::new(0x100000, 4).unwrap())
            .unwrap();
        allocator
            .free(FrameRange::new(0x108000, 4).unwrap())
            .unwrap();

        let reserved = FrameRange::new(0x102000, 8).unwrap();
        assert_eq!(allocator.reserve(reserved).unwrap(), 4);
        assert_eq!(allocator.free_pages(), 4);
        assert_eq!(
            allocator.extents()[0],
            FrameRange::new(0x100000, 2).unwrap()
        );
        assert_eq!(
            allocator.extents()[1],
            FrameRange::new(0x10a000, 2).unwrap()
        );
    }

    #[test]
    fn reservation_capacity_failure_is_transactional() {
        let mut allocator = ExtentAllocator::<1>::new();
        allocator
            .free(FrameRange::new(0x100000, 8).unwrap())
            .unwrap();
        let before = allocator.extents()[0];
        let free_before = allocator.free_pages();

        assert_eq!(
            allocator.reserve(FrameRange::new(0x103000, 2).unwrap()),
            Err(Error::Capacity)
        );
        assert_eq!(allocator.extents(), &[before]);
        assert_eq!(allocator.free_pages(), free_before);
        assert_eq!(allocator.reservation_count(), 0);
    }

    #[test]
    fn double_free_and_overlap_are_rejected() {
        let mut allocator = ExtentAllocator::<8>::new();
        allocator
            .free(FrameRange::new(0x200000, 4).unwrap())
            .unwrap();
        assert_eq!(
            allocator.free(FrameRange::new(0x201000, 1).unwrap()),
            Err(Error::DoubleFreeOrOverlap)
        );
    }

    #[test]
    fn allocation_never_uses_runtime_tagged_usable_region() {
        let map = [MemoryRegionV1::new(
            0x200000,
            0x100000,
            memory_kind::USABLE,
            memory_attr::RUNTIME,
        )];
        assert!(matches!(
            ExtentAllocator::<4>::from_boot_map(&map),
            Err(Error::NoMemory)
        ));
    }
}
