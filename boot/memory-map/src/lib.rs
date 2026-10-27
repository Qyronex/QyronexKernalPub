// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod slice;
pub use slice::NormalizedSlice;

use kernal_bootinfo::{MemoryRegionV1, memory_attr, memory_kind};

pub const UEFI_PAGE_SIZE: u64 = 4096;

pub mod uefi_type {
    pub const RESERVED: u32 = 0;
    pub const LOADER_CODE: u32 = 1;
    pub const LOADER_DATA: u32 = 2;
    pub const BOOT_SERVICES_CODE: u32 = 3;
    pub const BOOT_SERVICES_DATA: u32 = 4;
    pub const RUNTIME_SERVICES_CODE: u32 = 5;
    pub const RUNTIME_SERVICES_DATA: u32 = 6;
    pub const CONVENTIONAL: u32 = 7;
    pub const UNUSABLE: u32 = 8;
    pub const ACPI_RECLAIM: u32 = 9;
    pub const ACPI_NVS: u32 = 10;
    pub const MMIO: u32 = 11;
    pub const MMIO_PORT_SPACE: u32 = 12;
    pub const PAL_CODE: u32 = 13;
    pub const PERSISTENT_MEMORY: u32 = 14;
    pub const UNACCEPTED: u32 = 15;
}

pub mod uefi_attr {
    pub const UNCACHED: u64 = 0x0000_0000_0000_0001;
    pub const WRITE_COMBINE: u64 = 0x0000_0000_0000_0002;
    pub const NON_VOLATILE: u64 = 0x0000_0000_0000_8000;
    pub const RUNTIME: u64 = 0x8000_0000_0000_0000;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareRegion {
    pub memory_type: u32,
    pub physical_start: u64,
    pub page_count: u64,
    pub attributes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Empty,
    AddressOverflow,
    LengthOverflow,
    Capacity,
    Overlap,
}

pub fn normalize(region: FirmwareRegion) -> Result<MemoryRegionV1, Error> {
    if region.page_count == 0 {
        return Err(Error::Empty);
    }
    let len = region
        .page_count
        .checked_mul(UEFI_PAGE_SIZE)
        .ok_or(Error::LengthOverflow)?;
    region
        .physical_start
        .checked_add(len)
        .ok_or(Error::AddressOverflow)?;

    let runtime = region.attributes & uefi_attr::RUNTIME != 0
        || matches!(
            region.memory_type,
            uefi_type::RUNTIME_SERVICES_CODE | uefi_type::RUNTIME_SERVICES_DATA
        );
    let kind = if runtime {
        memory_kind::FIRMWARE
    } else {
        match region.memory_type {
            uefi_type::CONVENTIONAL => memory_kind::USABLE,
            uefi_type::LOADER_CODE | uefi_type::LOADER_DATA => memory_kind::RESERVED,
            uefi_type::BOOT_SERVICES_CODE | uefi_type::BOOT_SERVICES_DATA => {
                memory_kind::RECLAIMABLE
            }
            uefi_type::ACPI_RECLAIM => memory_kind::ACPI_RECLAIMABLE,
            uefi_type::ACPI_NVS => memory_kind::ACPI_NVS,
            uefi_type::MMIO | uefi_type::MMIO_PORT_SPACE => memory_kind::MMIO,
            uefi_type::RUNTIME_SERVICES_CODE | uefi_type::RUNTIME_SERVICES_DATA => {
                memory_kind::FIRMWARE
            }
            uefi_type::PERSISTENT_MEMORY => memory_kind::RESERVED,
            _ => memory_kind::RESERVED,
        }
    };

    let mut attributes = memory_attr::NONE;
    if runtime {
        attributes |= memory_attr::RUNTIME;
    }
    if region.attributes & uefi_attr::NON_VOLATILE != 0
        || region.memory_type == uefi_type::PERSISTENT_MEMORY
    {
        attributes |= memory_attr::NON_VOLATILE;
    }
    if region.attributes & uefi_attr::WRITE_COMBINE != 0 {
        attributes |= memory_attr::WRITE_COMBINE;
    }
    if region.attributes & uefi_attr::UNCACHED != 0 {
        attributes |= memory_attr::UNCACHED;
    }
    Ok(MemoryRegionV1::new(
        region.physical_start,
        len,
        kind,
        attributes,
    ))
}

pub struct NormalizedMap<const N: usize> {
    entries: [Option<MemoryRegionV1>; N],
    len: usize,
}

impl<const N: usize> Default for NormalizedMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> NormalizedMap<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            len: 0,
        }
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn entries(&self) -> impl Iterator<Item = &MemoryRegionV1> {
        self.entries[..self.len].iter().flatten()
    }
    pub fn push_firmware(&mut self, firmware: FirmwareRegion) -> Result<(), Error> {
        self.insert(normalize(firmware)?)
    }

    pub fn insert(&mut self, region: MemoryRegionV1) -> Result<(), Error> {
        let end = region.end().ok_or(Error::AddressOverflow)?;
        let mut pos = 0usize;
        while pos < self.len && self.entries[pos].expect("occupied prefix").start < region.start {
            pos += 1;
        }
        if pos > 0 {
            let previous = self.entries[pos - 1].expect("occupied prefix");
            let previous_end = previous.end().ok_or(Error::AddressOverflow)?;
            if previous_end > region.start {
                return Err(Error::Overlap);
            }
            if previous_end == region.start
                && previous.kind == region.kind
                && previous.attributes == region.attributes
            {
                let combined = previous
                    .len
                    .checked_add(region.len)
                    .ok_or(Error::LengthOverflow)?;
                self.entries[pos - 1] = Some(MemoryRegionV1::new(
                    previous.start,
                    combined,
                    previous.kind,
                    previous.attributes,
                ));
                self.merge_forward(pos - 1)?;
                return Ok(());
            }
        }
        if pos < self.len {
            let next = self.entries[pos].expect("occupied prefix");
            if end > next.start {
                return Err(Error::Overlap);
            }
        }
        if self.len == N {
            return Err(Error::Capacity);
        }
        let mut i = self.len;
        while i > pos {
            self.entries[i] = self.entries[i - 1];
            i -= 1;
        }
        self.entries[pos] = Some(region);
        self.len += 1;
        self.merge_forward(pos)
    }

    fn merge_forward(&mut self, index: usize) -> Result<(), Error> {
        if index + 1 >= self.len {
            return Ok(());
        }
        let current = self.entries[index].expect("occupied prefix");
        let next = self.entries[index + 1].expect("occupied prefix");
        if current.end().ok_or(Error::AddressOverflow)? == next.start
            && current.kind == next.kind
            && current.attributes == next.attributes
        {
            let combined = current
                .len
                .checked_add(next.len)
                .ok_or(Error::LengthOverflow)?;
            self.entries[index] = Some(MemoryRegionV1::new(
                current.start,
                combined,
                current.kind,
                current.attributes,
            ));
            let mut i = index + 1;
            while i + 1 < self.len {
                self.entries[i] = self.entries[i + 1];
                i += 1;
            }
            self.len -= 1;
            self.entries[self.len] = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_memory_is_never_usable() {
        let region = normalize(FirmwareRegion {
            memory_type: uefi_type::CONVENTIONAL,
            physical_start: 0x1000,
            page_count: 8,
            attributes: uefi_attr::RUNTIME,
        })
        .unwrap();
        assert_eq!(region.kind, memory_kind::FIRMWARE);
        assert_ne!(region.attributes & memory_attr::RUNTIME, 0);
    }

    #[test]
    fn boot_services_are_reclaimable_but_loader_pages_remain_reserved() {
        let boot = normalize(FirmwareRegion {
            memory_type: uefi_type::BOOT_SERVICES_DATA,
            physical_start: 0x1000,
            page_count: 1,
            attributes: 0,
        })
        .unwrap();
        let loader = normalize(FirmwareRegion {
            memory_type: uefi_type::LOADER_DATA,
            physical_start: 0x2000,
            page_count: 1,
            attributes: 0,
        })
        .unwrap();
        assert_eq!(boot.kind, memory_kind::RECLAIMABLE);
        assert_eq!(loader.kind, memory_kind::RESERVED);
    }

    #[test]
    fn adjacent_equal_regions_are_merged() {
        let mut map = NormalizedMap::<4>::new();
        map.push_firmware(FirmwareRegion {
            memory_type: uefi_type::CONVENTIONAL,
            physical_start: 0x2000,
            page_count: 2,
            attributes: 0,
        })
        .unwrap();
        map.push_firmware(FirmwareRegion {
            memory_type: uefi_type::CONVENTIONAL,
            physical_start: 0x1000,
            page_count: 1,
            attributes: 0,
        })
        .unwrap();
        let only = *map.entries().next().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(only.start, 0x1000);
        assert_eq!(only.len, 0x3000);
    }

    #[test]
    fn overlaps_are_rejected() {
        let mut map = NormalizedMap::<4>::new();
        map.insert(MemoryRegionV1::new(0x1000, 0x2000, memory_kind::USABLE, 0))
            .unwrap();
        assert_eq!(
            map.insert(MemoryRegionV1::new(0x2000, 0x2000, memory_kind::USABLE, 0)),
            Err(Error::Overlap)
        );
    }
}
