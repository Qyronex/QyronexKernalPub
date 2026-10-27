// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const PAGE_SIZE: u64 = 4096;
pub const ENTRY_COUNT: usize = 512;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnalignedVirtualAddress,
    UnalignedPhysicalAddress,
    NonCanonicalVirtualAddress,
    WritableExecutable,
    InvalidPhysicalAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapFlags(u64);

impl MapFlags {
    pub const READ: Self = Self(0);
    pub const WRITE: Self = Self(1 << 1);
    pub const USER: Self = Self(1 << 2);
    pub const GLOBAL: Self = Self(1 << 8);
    pub const EXECUTE: Self = Self(1 << 63);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn writable(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }

    pub const fn executable(self) -> bool {
        self.0 & Self::EXECUTE.0 != 0
    }

    pub const fn user(self) -> bool {
        self.0 & Self::USER.0 != 0
    }

    pub const fn validate(self) -> Result<Self, Error> {
        if self.writable() && self.executable() {
            return Err(Error::WritableExecutable);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub const fn unused() -> Self {
        Self(0)
    }

    pub fn leaf(physical_address: u64, flags: MapFlags) -> Result<Self, Error> {
        flags.validate()?;
        if physical_address & (PAGE_SIZE - 1) != 0 {
            return Err(Error::UnalignedPhysicalAddress);
        }
        if physical_address & !ADDRESS_MASK != 0 {
            return Err(Error::InvalidPhysicalAddress);
        }

        let mut bits = physical_address | 1;
        if flags.writable() {
            bits |= 1 << 1;
        }
        if flags.user() {
            bits |= 1 << 2;
        }
        if flags.0 & MapFlags::GLOBAL.0 != 0 {
            bits |= 1 << 8;
        }
        if !flags.executable() {
            bits |= 1 << 63;
        }
        Ok(Self(bits))
    }

    pub const fn bits(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageIndexes {
    pub p4: usize,
    pub p3: usize,
    pub p2: usize,
    pub p1: usize,
}

pub fn page_indexes(virtual_address: u64) -> Result<PageIndexes, Error> {
    if virtual_address & (PAGE_SIZE - 1) != 0 {
        return Err(Error::UnalignedVirtualAddress);
    }
    if !is_canonical_48(virtual_address) {
        return Err(Error::NonCanonicalVirtualAddress);
    }
    Ok(PageIndexes {
        p4: ((virtual_address >> 39) & 0x1ff) as usize,
        p3: ((virtual_address >> 30) & 0x1ff) as usize,
        p2: ((virtual_address >> 21) & 0x1ff) as usize,
        p1: ((virtual_address >> 12) & 0x1ff) as usize,
    })
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
    fn rejects_writable_executable_pages() {
        let flags = MapFlags::WRITE.union(MapFlags::EXECUTE);
        assert_eq!(flags.validate(), Err(Error::WritableExecutable));
        assert_eq!(
            PageTableEntry::leaf(0x2000, flags),
            Err(Error::WritableExecutable)
        );
    }

    #[test]
    fn writable_page_is_non_executable_in_hardware_entry() {
        let entry = PageTableEntry::leaf(0x4000, MapFlags::WRITE).unwrap();
        assert_ne!(entry.bits() & (1 << 63), 0);
        assert_ne!(entry.bits() & (1 << 1), 0);
    }

    #[test]
    fn executable_page_is_not_writable() {
        let entry = PageTableEntry::leaf(0x8000, MapFlags::EXECUTE).unwrap();
        assert_eq!(entry.bits() & (1 << 63), 0);
        assert_eq!(entry.bits() & (1 << 1), 0);
    }

    #[test]
    fn high_half_address_has_expected_indexes() {
        let indexes = page_indexes(0xffff_ffff_8020_0000).unwrap();
        assert_eq!(indexes.p4, 511);
        assert!(indexes.p3 < ENTRY_COUNT);
        assert!(indexes.p2 < ENTRY_COUNT);
        assert!(indexes.p1 < ENTRY_COUNT);
    }

    #[test]
    fn rejects_noncanonical_address() {
        assert_eq!(
            page_indexes(0x0001_0000_0000_0000),
            Err(Error::NonCanonicalVirtualAddress)
        );
    }
}
