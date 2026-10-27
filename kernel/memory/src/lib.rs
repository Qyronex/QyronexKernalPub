// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_bootinfo::{MemoryRegionV1, memory_attr, memory_kind};

pub const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PhysFrame(u64);

impl PhysFrame {
    pub const fn containing_address(address: u64) -> Self {
        Self(address & !(PAGE_SIZE - 1))
    }
    pub const fn from_start_address(address: u64) -> Option<Self> {
        if address & (PAGE_SIZE - 1) == 0 {
            Some(Self(address))
        } else {
            None
        }
    }
    pub const fn start_address(self) -> u64 {
        self.0
    }
    pub const fn end_address(self) -> Option<u64> {
        self.0.checked_add(PAGE_SIZE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub kind: MemoryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryKind {
    Usable,
    Reclaimable,
    Reserved,
    Mmio,
    Firmware,
}

impl MemoryRegion {
    pub const EMPTY: Self = Self {
        start: 0,
        len: 0,
        kind: MemoryKind::Reserved,
    };

    pub fn from_boot(region: MemoryRegionV1) -> Result<Self, Error> {
        if !region.is_structurally_valid() {
            return Err(Error::InvalidBootRegion);
        }
        let kind = match region.kind {
            memory_kind::USABLE if region.attributes & memory_attr::RUNTIME == 0 => {
                MemoryKind::Usable
            }
            memory_kind::RECLAIMABLE | memory_kind::ACPI_RECLAIMABLE => MemoryKind::Reclaimable,
            memory_kind::MMIO => MemoryKind::Mmio,
            memory_kind::FIRMWARE | memory_kind::ACPI_NVS => MemoryKind::Firmware,
            _ => MemoryKind::Reserved,
        };
        Ok(Self {
            start: region.start,
            len: region.len,
            kind,
        })
    }

    pub const fn end(self) -> Option<u64> {
        self.start.checked_add(self.len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Empty,
    Capacity,
    Overflow,
    InvalidBootRegion,
    OverlappingRegions,
    InvalidRange,
}

/// Fixed-capacity normalized region list. Insertions are sorted and overlapping firmware
/// descriptors are rejected instead of letting ambiguous ownership reach the allocator.
pub struct RegionList<const N: usize> {
    regions: [MemoryRegion; N],
    len: usize,
}

impl<const N: usize> Default for RegionList<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RegionList<N> {
    pub const fn new() -> Self {
        Self {
            regions: [MemoryRegion::EMPTY; N],
            len: 0,
        }
    }
    pub fn as_slice(&self) -> &[MemoryRegion] {
        &self.regions[..self.len]
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn insert_boot(&mut self, boot: MemoryRegionV1) -> Result<(), Error> {
        self.insert(MemoryRegion::from_boot(boot)?)
    }

    pub fn insert(&mut self, region: MemoryRegion) -> Result<(), Error> {
        if region.len == 0 || region.end().is_none() {
            return Err(Error::InvalidRange);
        }
        if self.len == N {
            return Err(Error::Capacity);
        }
        let end = region.end().ok_or(Error::Overflow)?;
        let mut pos = 0;
        while pos < self.len && self.regions[pos].start < region.start {
            pos += 1;
        }
        if pos > 0 {
            let previous = self.regions[pos - 1];
            if previous.end().ok_or(Error::Overflow)? > region.start {
                return Err(Error::OverlappingRegions);
            }
        }
        if pos < self.len && end > self.regions[pos].start {
            return Err(Error::OverlappingRegions);
        }
        let mut i = self.len;
        while i > pos {
            self.regions[i] = self.regions[i - 1];
            i -= 1;
        }
        self.regions[pos] = region;
        self.len += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysRange {
    pub start: u64,
    pub end: u64,
}

impl PhysRange {
    pub const EMPTY: Self = Self { start: 0, end: 0 };

    pub fn covering(start: u64, len: u64) -> Result<Self, Error> {
        if len == 0 {
            return Err(Error::InvalidRange);
        }
        let raw_end = start.checked_add(len).ok_or(Error::Overflow)?;
        let aligned_start = align_down(start, PAGE_SIZE);
        let aligned_end = align_up(raw_end, PAGE_SIZE).ok_or(Error::Overflow)?;
        if aligned_start >= aligned_end {
            return Err(Error::InvalidRange);
        }
        Ok(Self {
            start: aligned_start,
            end: aligned_end,
        })
    }

    pub const fn contains_frame(self, frame: PhysFrame) -> bool {
        match frame.end_address() {
            Some(end) => frame.start_address() < self.end && end > self.start,
            None => true,
        }
    }
}

pub struct ReservationSet<const N: usize> {
    ranges: [PhysRange; N],
    len: usize,
}

impl<const N: usize> Default for ReservationSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ReservationSet<N> {
    pub const fn new() -> Self {
        Self {
            ranges: [PhysRange::EMPTY; N],
            len: 0,
        }
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn ranges(&self) -> &[PhysRange] {
        &self.ranges[..self.len]
    }

    pub fn reserve(&mut self, start: u64, len: u64) -> Result<(), Error> {
        let range = PhysRange::covering(start, len)?;
        if self.len == N {
            return Err(Error::Capacity);
        }
        self.ranges[self.len] = range;
        self.len += 1;
        Ok(())
    }

    pub fn contains(&self, frame: PhysFrame) -> bool {
        self.ranges[..self.len]
            .iter()
            .any(|range| range.contains_frame(frame))
    }
}

#[derive(Clone, Debug)]
pub struct BumpFrameAllocator<'a> {
    regions: &'a [MemoryRegion],
    region_index: usize,
    next: u64,
    end: u64,
}

impl<'a> BumpFrameAllocator<'a> {
    pub fn new(regions: &'a [MemoryRegion]) -> Result<Self, Error> {
        let mut allocator = Self {
            regions,
            region_index: 0,
            next: 0,
            end: 0,
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
        Some(frame)
    }

    fn advance_region(&mut self) -> Result<(), Error> {
        while self.region_index < self.regions.len() {
            let region = self.regions[self.region_index];
            self.region_index += 1;
            if region.kind != MemoryKind::Usable || region.len == 0 {
                continue;
            }
            let region_end = region
                .start
                .checked_add(region.len)
                .ok_or(Error::Overflow)?;
            let start = align_up(region.start, PAGE_SIZE).ok_or(Error::Overflow)?;
            let end = align_down(region_end, PAGE_SIZE);
            if start >= end {
                continue;
            }
            self.next = start;
            self.end = end;
            return Ok(());
        }
        Err(Error::Empty)
    }
}

/// Early allocator that skips frames owned by the loader, kernel image, boot structures,
/// stacks, page tables, initrd or other explicitly reserved ranges.
pub struct ReservedFrameAllocator<'a, 'r, const R: usize> {
    inner: BumpFrameAllocator<'a>,
    reservations: &'r ReservationSet<R>,
}

impl<'a, 'r, const R: usize> ReservedFrameAllocator<'a, 'r, R> {
    pub fn new(
        regions: &'a [MemoryRegion],
        reservations: &'r ReservationSet<R>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: BumpFrameAllocator::new(regions)?,
            reservations,
        })
    }

    pub fn allocate(&mut self) -> Option<PhysFrame> {
        loop {
            let frame = self.inner.allocate()?;
            if !self.reservations.contains(frame) {
                return Some(frame);
            }
        }
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
    fn runtime_memory_never_becomes_usable() {
        let boot = MemoryRegionV1::new(0x1000, 0x4000, memory_kind::USABLE, memory_attr::RUNTIME);
        assert_eq!(
            MemoryRegion::from_boot(boot).unwrap().kind,
            MemoryKind::Reserved
        );
    }

    #[test]
    fn normalized_regions_reject_overlap_and_sort() {
        let mut list = RegionList::<4>::new();
        list.insert(MemoryRegion {
            start: 0x4000,
            len: 0x1000,
            kind: MemoryKind::Usable,
        })
        .unwrap();
        list.insert(MemoryRegion {
            start: 0x1000,
            len: 0x1000,
            kind: MemoryKind::Reserved,
        })
        .unwrap();
        assert_eq!(list.as_slice()[0].start, 0x1000);
        assert_eq!(list.as_slice()[1].start, 0x4000);
        assert_eq!(
            list.insert(MemoryRegion {
                start: 0x4800,
                len: 0x1000,
                kind: MemoryKind::Usable
            }),
            Err(Error::OverlappingRegions)
        );
    }

    #[test]
    fn allocates_only_whole_pages_from_usable_memory() {
        let regions = [
            MemoryRegion {
                start: 0x1003,
                len: 0x4000,
                kind: MemoryKind::Reserved,
            },
            MemoryRegion {
                start: 0x2003,
                len: 0x4000,
                kind: MemoryKind::Usable,
            },
        ];
        let mut allocator = BumpFrameAllocator::new(&regions).unwrap();
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x3000);
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x4000);
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x5000);
        assert!(allocator.allocate().is_none());
    }

    #[test]
    fn reservations_are_page_granular_and_never_reissued() {
        let regions = [MemoryRegion {
            start: 0x1000,
            len: 0x8000,
            kind: MemoryKind::Usable,
        }];
        let mut reservations = ReservationSet::<4>::new();
        reservations.reserve(0x2800, 0x900).unwrap();
        assert_eq!(
            reservations.ranges(),
            &[PhysRange {
                start: 0x2000,
                end: 0x4000,
            }]
        );
        let mut allocator = ReservedFrameAllocator::new(&regions, &reservations).unwrap();
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x1000);
        assert_eq!(allocator.allocate().unwrap().start_address(), 0x4000);
    }
}
