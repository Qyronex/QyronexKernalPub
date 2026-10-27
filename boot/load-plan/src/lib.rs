// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_elf::{Image, ImageType, Segment};

pub const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    AddressOverflow,
    InvalidAlignment,
    InvalidLoadBias,
    NonCanonicalVirtualAddress,
    OverlappingPageMappings,
    EmptySegment,
    FileRangeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadPerms {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlannedSegment {
    pub virtual_page_start: u64,
    pub page_count: usize,
    pub in_page_offset: usize,
    pub file_offset: usize,
    pub file_size: usize,
    pub memory_size: usize,
    pub perms: LoadPerms,
}

impl PlannedSegment {
    pub fn virtual_end(&self) -> Result<u64, Error> {
        let span = (self.page_count as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::AddressOverflow)?;
        self.virtual_page_start
            .checked_add(span)
            .ok_or(Error::AddressOverflow)
    }

    pub fn file_end(&self) -> Result<usize, Error> {
        self.file_offset
            .checked_add(self.file_size)
            .ok_or(Error::FileRangeOverflow)
    }
}

pub struct LoadPlan<const N: usize> {
    segments: [Option<PlannedSegment>; N],
    len: usize,
    entry: u64,
}

impl<const N: usize> LoadPlan<N> {
    /// Preserves the historical fixed-address behavior. ET_EXEC images use a zero bias, while
    /// ET_DYN callers that need relocation must opt into `from_image_with_bias` explicitly.
    pub fn from_image(image: &Image<'_>) -> Result<Self, Error> {
        Self::from_image_with_bias(image, 0)
    }

    /// Builds a deterministic load plan with one explicit relocation bias.
    ///
    /// ET_EXEC remains fixed-address and rejects any non-zero bias. ET_DYN accepts only a
    /// page-aligned bias; each PT_LOAD segment still has to satisfy its own ELF p_align
    /// congruence after relocation, so a caller cannot silently choose an incompatible base.
    pub fn from_image_with_bias(image: &Image<'_>, load_bias: u64) -> Result<Self, Error> {
        match image.image_type() {
            ImageType::Executable if load_bias != 0 => return Err(Error::InvalidLoadBias),
            ImageType::SharedObject if !load_bias.is_multiple_of(PAGE_SIZE) => {
                return Err(Error::InvalidLoadBias);
            }
            _ => {}
        }

        let entry = image
            .entry()
            .checked_add(load_bias)
            .ok_or(Error::AddressOverflow)?;
        let mut plan = Self {
            segments: [None; N],
            len: 0,
            entry,
        };
        if !is_canonical_48(plan.entry) {
            return Err(Error::NonCanonicalVirtualAddress);
        }
        for segment in image.load_segments() {
            let segment = segment.map_err(|_| Error::AddressOverflow)?;
            let planned = plan_segment_with_bias(segment, load_bias)?;
            if plan.len == N {
                return Err(Error::Capacity);
            }
            for existing in plan.segments[..plan.len].iter().flatten() {
                if planned.virtual_page_start < existing.virtual_end()?
                    && existing.virtual_page_start < planned.virtual_end()?
                {
                    return Err(Error::OverlappingPageMappings);
                }
            }
            plan.segments[plan.len] = Some(planned);
            plan.len += 1;
        }
        Ok(plan)
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
    pub fn segments(&self) -> impl Iterator<Item = &PlannedSegment> {
        self.segments[..self.len].iter().flatten()
    }
}

#[cfg(test)]
fn plan_segment(segment: Segment) -> Result<PlannedSegment, Error> {
    plan_segment_with_bias(segment, 0)
}

fn plan_segment_with_bias(segment: Segment, load_bias: u64) -> Result<PlannedSegment, Error> {
    if segment.memory_size == 0 {
        return Err(Error::EmptySegment);
    }
    let virtual_addr = segment
        .virtual_addr
        .checked_add(load_bias)
        .ok_or(Error::AddressOverflow)?;
    if segment.align > 1
        && (!segment.align.is_power_of_two()
            || virtual_addr % segment.align != segment.offset % segment.align)
    {
        return Err(Error::InvalidAlignment);
    }
    if !is_canonical_48(virtual_addr) {
        return Err(Error::NonCanonicalVirtualAddress);
    }
    let virtual_page_start = align_down(virtual_addr, PAGE_SIZE);
    let in_page_offset = virtual_addr
        .checked_sub(virtual_page_start)
        .ok_or(Error::AddressOverflow)?;
    let span = in_page_offset
        .checked_add(segment.memory_size)
        .ok_or(Error::AddressOverflow)?;
    let page_count_u64 = span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(Error::AddressOverflow)?
        / PAGE_SIZE;
    let page_count = usize::try_from(page_count_u64).map_err(|_| Error::AddressOverflow)?;
    let file_offset = usize::try_from(segment.offset).map_err(|_| Error::FileRangeOverflow)?;
    let file_size = usize::try_from(segment.file_size).map_err(|_| Error::FileRangeOverflow)?;
    file_offset
        .checked_add(file_size)
        .ok_or(Error::FileRangeOverflow)?;
    let memory_size = usize::try_from(segment.memory_size).map_err(|_| Error::AddressOverflow)?;
    Ok(PlannedSegment {
        virtual_page_start,
        page_count,
        in_page_offset: in_page_offset as usize,
        file_offset,
        file_size,
        memory_size,
        perms: LoadPerms {
            readable: segment.readable(),
            writable: segment.writable(),
            executable: segment.executable(),
        },
    })
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

pub const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(vaddr: u64, offset: u64, file: u64, memory: u64, flags: u32) -> Segment {
        Segment {
            offset,
            virtual_addr: vaddr,
            physical_addr: 0,
            file_size: file,
            memory_size: memory,
            align: 0x1000,
            flags,
        }
    }

    fn minimal_image(image_type: u16) -> [u8; 0x120] {
        let mut bytes = [0u8; 0x120];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&image_type.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x20_100u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let p = 64;
        bytes[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&0x20_100u64.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&0x20u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    #[test]
    fn page_plan_preserves_unaligned_segment_prefix() {
        let planned = plan_segment(seg(0xffff_ffff_8020_0123, 0x123, 0x500, 0x1800, 5)).unwrap();
        assert_eq!(planned.virtual_page_start, 0xffff_ffff_8020_0000);
        assert_eq!(planned.in_page_offset, 0x123);
        assert_eq!(planned.page_count, 2);
        assert!(planned.perms.executable);
        assert!(!planned.perms.writable);
    }

    #[test]
    fn elf_alignment_congruence_is_enforced() {
        assert_eq!(
            plan_segment(seg(0xffff_ffff_8020_0100, 0x200, 0x100, 0x1000, 4)),
            Err(Error::InvalidAlignment)
        );
    }

    #[test]
    fn rejects_noncanonical_load_address() {
        assert_eq!(
            plan_segment(seg(0x0001_0000_0000_0000, 0, 1, 0x1000, 4)),
            Err(Error::NonCanonicalVirtualAddress)
        );
    }

    #[test]
    fn et_exec_rejects_nonzero_load_bias() {
        let bytes = minimal_image(2);
        let image = Image::parse(&bytes).unwrap();
        assert!(matches!(
            LoadPlan::<2>::from_image_with_bias(&image, PAGE_SIZE),
            Err(Error::InvalidLoadBias)
        ));
    }

    #[test]
    fn et_dyn_accepts_explicit_page_aligned_load_bias() {
        let bytes = minimal_image(3);
        let image = Image::parse(&bytes).unwrap();
        let plan = LoadPlan::<2>::from_image_with_bias(&image, 0x40_000).unwrap();
        assert_eq!(plan.entry(), 0x60_100);
        let segment = plan.segments().next().unwrap();
        assert_eq!(segment.virtual_page_start, 0x60_000);
        assert_eq!(segment.in_page_offset, 0x100);
    }

    #[test]
    fn et_dyn_rejects_unaligned_load_bias() {
        let bytes = minimal_image(3);
        let image = Image::parse(&bytes).unwrap();
        assert!(matches!(
            LoadPlan::<2>::from_image_with_bias(&image, 1),
            Err(Error::InvalidLoadBias)
        ));
    }
}
