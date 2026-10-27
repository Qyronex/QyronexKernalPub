// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_load_plan::{LoadPerms, LoadPlan, PAGE_SIZE, PlannedSegment};

const MAX_PHYS_EXCLUSIVE: u64 = 1 << 52;

pub trait PageAllocator {
    /// Returns a page-aligned physical base for `page_count` contiguous pages.
    fn allocate_pages(&mut self, page_count: usize) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AllocationFailed,
    UnalignedPhysical,
    PhysicalOverflow,
    PhysicalOverlap,
    AddressOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundSegment {
    pub plan: PlannedSegment,
    pub physical_start: u64,
}

impl BoundSegment {
    pub fn physical_end(self) -> Result<u64, Error> {
        let len = (self.plan.page_count as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::PhysicalOverflow)?;
        self.physical_start
            .checked_add(len)
            .ok_or(Error::PhysicalOverflow)
    }

    pub fn file_destination(self) -> Result<u64, Error> {
        self.physical_start
            .checked_add(self.plan.in_page_offset as u64)
            .ok_or(Error::AddressOverflow)
    }

    pub fn allocation_len(self) -> Result<usize, Error> {
        self.plan
            .page_count
            .checked_mul(PAGE_SIZE as usize)
            .ok_or(Error::PhysicalOverflow)
    }

    pub fn pages(self) -> SegmentPages {
        SegmentPages {
            segment: self,
            index: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageMapping {
    pub virtual_address: u64,
    pub physical_address: u64,
    pub perms: LoadPerms,
}

pub struct SegmentPages {
    segment: BoundSegment,
    index: usize,
}

impl Iterator for SegmentPages {
    type Item = Result<PageMapping, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.segment.plan.page_count {
            return None;
        }
        let offset = match (self.index as u64).checked_mul(PAGE_SIZE) {
            Some(value) => value,
            None => return Some(Err(Error::AddressOverflow)),
        };
        self.index += 1;
        Some(Ok(PageMapping {
            virtual_address: match self.segment.plan.virtual_page_start.checked_add(offset) {
                Some(value) => value,
                None => return Some(Err(Error::AddressOverflow)),
            },
            physical_address: match self.segment.physical_start.checked_add(offset) {
                Some(value) => value,
                None => return Some(Err(Error::AddressOverflow)),
            },
            perms: self.segment.plan.perms,
        }))
    }
}

pub struct BoundImage<const N: usize> {
    segments: [Option<BoundSegment>; N],
    len: usize,
    entry: u64,
}

impl<const N: usize> BoundImage<N> {
    pub fn allocate(plan: &LoadPlan<N>, allocator: &mut impl PageAllocator) -> Result<Self, Error> {
        let mut image = Self {
            segments: [None; N],
            len: 0,
            entry: plan.entry(),
        };
        for planned in plan.segments() {
            let physical_start = allocator
                .allocate_pages(planned.page_count)
                .ok_or(Error::AllocationFailed)?;
            if physical_start & (PAGE_SIZE - 1) != 0 {
                return Err(Error::UnalignedPhysical);
            }
            let bound = BoundSegment {
                plan: *planned,
                physical_start,
            };
            let end = bound.physical_end()?;
            if end > MAX_PHYS_EXCLUSIVE {
                return Err(Error::PhysicalOverflow);
            }
            for existing in image.segments[..image.len].iter().flatten() {
                if physical_start < existing.physical_end()? && existing.physical_start < end {
                    return Err(Error::PhysicalOverlap);
                }
            }
            image.segments[image.len] = Some(bound);
            image.len += 1;
        }
        Ok(image)
    }

    pub const fn entry(&self) -> u64 {
        self.entry
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn segments(&self) -> impl Iterator<Item = &BoundSegment> {
        self.segments[..self.len].iter().flatten()
    }
    pub fn pages(&self) -> impl Iterator<Item = Result<PageMapping, Error>> + '_ {
        self.segments().flat_map(|segment| segment.pages())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_elf::Image;

    struct LinearAllocator {
        next: u64,
    }
    impl PageAllocator for LinearAllocator {
        fn allocate_pages(&mut self, page_count: usize) -> Option<u64> {
            let base = self.next;
            self.next = self.next.checked_add(page_count as u64 * PAGE_SIZE)?;
            Some(base)
        }
    }

    fn elf() -> [u8; 0x200] {
        let mut b = [0u8; 0x200];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b[24..32].copy_from_slice(&0xffff_ffff_8020_0000u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        let p = 64;
        b[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0x100u64.to_le_bytes());
        b[p + 16..p + 24].copy_from_slice(&0xffff_ffff_8020_0000u64.to_le_bytes());
        b[p + 32..p + 40].copy_from_slice(&0x20u64.to_le_bytes());
        b[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        b[p + 48..p + 56].copy_from_slice(&0x100u64.to_le_bytes());
        b
    }

    #[test]
    fn image_is_bound_to_arbitrary_physical_pages() {
        let bytes = elf();
        let image = Image::parse(&bytes).unwrap();
        let plan = LoadPlan::<4>::from_image(&image).unwrap();
        let mut allocator = LinearAllocator { next: 0x20_0000 };
        let bound = BoundImage::allocate(&plan, &mut allocator).unwrap();
        let segment = *bound.segments().next().unwrap();
        assert_eq!(segment.physical_start, 0x20_0000);
        assert_eq!(segment.file_destination().unwrap(), 0x20_0000);
        let page = bound.pages().next().unwrap().unwrap();
        assert_eq!(page.virtual_address, 0xffff_ffff_8020_0000);
        assert_eq!(page.physical_address, 0x20_0000);
    }

    #[test]
    fn allocator_returning_unaligned_memory_is_rejected() {
        let bytes = elf();
        let image = Image::parse(&bytes).unwrap();
        let plan = LoadPlan::<4>::from_image(&image).unwrap();
        let mut allocator = LinearAllocator { next: 0x20_0001 };
        assert!(matches!(
            BoundImage::allocate(&plan, &mut allocator),
            Err(Error::UnalignedPhysical)
        ));
    }
}
