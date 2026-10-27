// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_paging::{PAGE_SIZE, page_indexes};

pub const RECURSIVE_PML4_SLOT: usize = 510;
pub const ENTRY_COUNT: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidSlot,
    InvalidIndex,
    Paging(kernal_paging::Error),
    Overflow,
}

impl From<kernal_paging::Error> for Error {
    fn from(value: kernal_paging::Error) -> Self {
        Self::Paging(value)
    }
}

pub const fn pml4_virtual(slot: usize) -> Result<u64, Error> {
    compose(slot, slot, slot, slot, 0)
}

pub const fn pdpt_virtual(slot: usize, p4: usize) -> Result<u64, Error> {
    compose(slot, slot, slot, p4, 0)
}

pub const fn pd_virtual(slot: usize, p4: usize, p3: usize) -> Result<u64, Error> {
    compose(slot, slot, p4, p3, 0)
}

pub const fn pt_virtual(slot: usize, p4: usize, p3: usize, p2: usize) -> Result<u64, Error> {
    compose(slot, p4, p3, p2, 0)
}

pub fn pte_virtual(slot: usize, mapped_virtual_address: u64) -> Result<u64, Error> {
    validate_slot(slot)?;
    let page = mapped_virtual_address & !(PAGE_SIZE - 1);
    let indexes = page_indexes(page)?;
    pt_virtual(slot, indexes.p4, indexes.p3, indexes.p2)?
        .checked_add((indexes.p1 as u64).checked_mul(8).ok_or(Error::Overflow)?)
        .ok_or(Error::Overflow)
}

pub fn pde_virtual(slot: usize, mapped_virtual_address: u64) -> Result<u64, Error> {
    validate_slot(slot)?;
    let page = mapped_virtual_address & !(PAGE_SIZE - 1);
    let indexes = page_indexes(page)?;
    pd_virtual(slot, indexes.p4, indexes.p3)?
        .checked_add((indexes.p2 as u64).checked_mul(8).ok_or(Error::Overflow)?)
        .ok_or(Error::Overflow)
}

pub fn pdpte_virtual(slot: usize, mapped_virtual_address: u64) -> Result<u64, Error> {
    validate_slot(slot)?;
    let page = mapped_virtual_address & !(PAGE_SIZE - 1);
    let indexes = page_indexes(page)?;
    pdpt_virtual(slot, indexes.p4)?
        .checked_add((indexes.p3 as u64).checked_mul(8).ok_or(Error::Overflow)?)
        .ok_or(Error::Overflow)
}

pub fn pml4e_virtual(slot: usize, mapped_virtual_address: u64) -> Result<u64, Error> {
    validate_slot(slot)?;
    let page = mapped_virtual_address & !(PAGE_SIZE - 1);
    let indexes = page_indexes(page)?;
    pml4_virtual(slot)?
        .checked_add((indexes.p4 as u64).checked_mul(8).ok_or(Error::Overflow)?)
        .ok_or(Error::Overflow)
}

const fn compose(p4: usize, p3: usize, p2: usize, p1: usize, offset: u16) -> Result<u64, Error> {
    if p4 >= ENTRY_COUNT || p3 >= ENTRY_COUNT || p2 >= ENTRY_COUNT || p1 >= ENTRY_COUNT {
        return Err(Error::InvalidIndex);
    }
    let raw = ((p4 as u64) << 39)
        | ((p3 as u64) << 30)
        | ((p2 as u64) << 21)
        | ((p1 as u64) << 12)
        | offset as u64;
    Ok(sign_extend_48(raw))
}

const fn validate_slot(slot: usize) -> Result<(), Error> {
    if slot < 256 || slot >= ENTRY_COUNT {
        Err(Error::InvalidSlot)
    } else {
        Ok(())
    }
}

const fn sign_extend_48(value: u64) -> u64 {
    if value & (1u64 << 47) != 0 {
        value | 0xffff_0000_0000_0000
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_slot_510_is_separate_from_slot_511_kernel_half() {
        let recursive_base = compose(RECURSIVE_PML4_SLOT, 0, 0, 0, 0).unwrap();
        let kernel_slot_base = compose(511, 0, 0, 0, 0).unwrap();
        assert_eq!(recursive_base, 0xffff_ff00_0000_0000);
        assert_eq!(kernel_slot_base, 0xffff_ff80_0000_0000);
        assert!(recursive_base < kernel_slot_base);
    }

    #[test]
    fn pte_address_targets_expected_recursive_pt_page() {
        let virtual_address = 0xffff_ff80_0100_3000;
        let indexes = page_indexes(virtual_address).unwrap();
        let pt = pt_virtual(RECURSIVE_PML4_SLOT, indexes.p4, indexes.p3, indexes.p2).unwrap();
        let pte = pte_virtual(RECURSIVE_PML4_SLOT, virtual_address).unwrap();
        assert_eq!(pte, pt + indexes.p1 as u64 * 8);
        assert_eq!(pte & 7, 0);
    }

    #[test]
    fn recursive_table_addresses_are_canonical() {
        for address in [
            pml4_virtual(RECURSIVE_PML4_SLOT).unwrap(),
            pdpt_virtual(RECURSIVE_PML4_SLOT, 511).unwrap(),
            pd_virtual(RECURSIVE_PML4_SLOT, 511, 0).unwrap(),
            pt_virtual(RECURSIVE_PML4_SLOT, 511, 0, 0).unwrap(),
        ] {
            assert_eq!(address >> 48, 0xffff);
        }
    }

    #[test]
    fn lower_half_recursive_slot_is_rejected() {
        assert_eq!(pte_virtual(1, 0x4000), Err(Error::InvalidSlot));
    }
}
