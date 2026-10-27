// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_paging::{MapFlags, PAGE_SIZE, PageTableEntry, page_indexes};

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const ENTRY_COUNT: usize = 512;
const FIRST_HIGH_HALF_PML4_SLOT: usize = 256;

pub trait Backend {
    fn allocate_zeroed_table(&mut self) -> Option<u64>;
    fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64>;
    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Paging(kernal_paging::Error),
    NullPage,
    BackendFailure,
    InvalidTableAddress,
    HugePageConflict,
    AlreadyMapped,
    NotMapped,
    InvalidRecursiveSlot,
    RecursiveSlotOccupied,
}

impl From<kernal_paging::Error> for Error {
    fn from(value: kernal_paging::Error) -> Self {
        Self::Paging(value)
    }
}

pub struct Mapper<'a, B: Backend> {
    backend: &'a mut B,
    root: u64,
}

impl<'a, B: Backend> Mapper<'a, B> {
    pub fn new(backend: &'a mut B, root: u64) -> Result<Self, Error> {
        validate_table_address(root)?;
        Ok(Self { backend, root })
    }

    pub const fn root(&self) -> u64 {
        self.root
    }

    pub fn map_page(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        flags: MapFlags,
    ) -> Result<(), Error> {
        if virtual_address == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(virtual_address)?;
        let table =
            self.ensure_leaf_table_inner(indexes.p4, indexes.p3, indexes.p2, flags.user())?;
        let current = self
            .backend
            .read_entry(table, indexes.p1)
            .ok_or(Error::BackendFailure)?;
        if current & PRESENT != 0 {
            return Err(Error::AlreadyMapped);
        }
        let leaf = PageTableEntry::leaf(physical_address, flags)?;
        if !self.backend.write_entry(table, indexes.p1, leaf.bits()) {
            return Err(Error::BackendFailure);
        }
        Ok(())
    }

    /// Ensures all intermediate tables for a 4 KiB leaf exist but leaves the PTE absent.
    /// This is used for bounded mapping windows whose leaf entries are mutated after CR3 handoff.
    pub fn ensure_leaf_table(&mut self, virtual_address: u64, user: bool) -> Result<u64, Error> {
        if virtual_address == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(virtual_address)?;
        self.ensure_leaf_table_inner(indexes.p4, indexes.p3, indexes.p2, user)
    }

    /// Installs a recursive PML4 mapping in the high half. The recursive subtree is supervisor
    /// writable but NX, so page-table memory can be edited but never executed through this alias.
    pub fn install_recursive_slot(&mut self, slot: usize) -> Result<(), Error> {
        if !(FIRST_HIGH_HALF_PML4_SLOT..ENTRY_COUNT).contains(&slot) {
            return Err(Error::InvalidRecursiveSlot);
        }
        let current = self
            .backend
            .read_entry(self.root, slot)
            .ok_or(Error::BackendFailure)?;
        if current & PRESENT != 0 {
            return Err(Error::RecursiveSlotOccupied);
        }
        let value = self.root | PRESENT | WRITABLE | NX;
        if !self.backend.write_entry(self.root, slot, value) {
            return Err(Error::BackendFailure);
        }
        Ok(())
    }

    pub fn translate(&self, virtual_address: u64) -> Result<u64, Error> {
        let page = virtual_address & !(PAGE_SIZE - 1);
        let offset = virtual_address & (PAGE_SIZE - 1);
        if page == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(page)?;
        let mut table = self.root;
        for index in [indexes.p4, indexes.p3, indexes.p2] {
            let entry = self
                .backend
                .read_entry(table, index)
                .ok_or(Error::BackendFailure)?;
            if entry & PRESENT == 0 {
                return Err(Error::NotMapped);
            }
            if entry & HUGE != 0 {
                return Err(Error::HugePageConflict);
            }
            table = entry & ADDRESS_MASK;
            validate_table_address(table)?;
        }
        let leaf = self
            .backend
            .read_entry(table, indexes.p1)
            .ok_or(Error::BackendFailure)?;
        if leaf & PRESENT == 0 {
            return Err(Error::NotMapped);
        }
        if leaf & HUGE != 0 {
            return Err(Error::HugePageConflict);
        }
        (leaf & ADDRESS_MASK)
            .checked_add(offset)
            .ok_or(Error::InvalidTableAddress)
    }

    pub fn unmap_page(&mut self, virtual_address: u64) -> Result<u64, Error> {
        if virtual_address == 0 {
            return Err(Error::NullPage);
        }
        let indexes = page_indexes(virtual_address)?;
        let mut table = self.root;
        for index in [indexes.p4, indexes.p3, indexes.p2] {
            let entry = self
                .backend
                .read_entry(table, index)
                .ok_or(Error::BackendFailure)?;
            if entry & PRESENT == 0 {
                return Err(Error::NotMapped);
            }
            if entry & HUGE != 0 {
                return Err(Error::HugePageConflict);
            }
            table = entry & ADDRESS_MASK;
            validate_table_address(table)?;
        }
        let leaf = self
            .backend
            .read_entry(table, indexes.p1)
            .ok_or(Error::BackendFailure)?;
        if leaf & PRESENT == 0 {
            return Err(Error::NotMapped);
        }
        if !self.backend.write_entry(table, indexes.p1, 0) {
            return Err(Error::BackendFailure);
        }
        Ok(leaf & ADDRESS_MASK)
    }

    fn ensure_leaf_table_inner(
        &mut self,
        p4: usize,
        p3: usize,
        p2: usize,
        user: bool,
    ) -> Result<u64, Error> {
        let mut table = self.root;
        for index in [p4, p3, p2] {
            table = self.next_table(table, index, user)?;
        }
        Ok(table)
    }

    fn next_table(&mut self, table: u64, index: usize, user: bool) -> Result<u64, Error> {
        let entry = self
            .backend
            .read_entry(table, index)
            .ok_or(Error::BackendFailure)?;
        if entry & PRESENT != 0 {
            if entry & HUGE != 0 {
                return Err(Error::HugePageConflict);
            }
            let child = entry & ADDRESS_MASK;
            validate_table_address(child)?;
            if user
                && entry & USER == 0
                && !self
                    .backend
                    .write_entry(table, index, entry | USER | WRITABLE)
            {
                return Err(Error::BackendFailure);
            }
            return Ok(child);
        }
        let child = self
            .backend
            .allocate_zeroed_table()
            .ok_or(Error::BackendFailure)?;
        validate_table_address(child)?;
        let mut value = child | PRESENT | WRITABLE;
        if user {
            value |= USER;
        }
        if !self.backend.write_entry(table, index, value) {
            return Err(Error::BackendFailure);
        }
        Ok(child)
    }
}

fn validate_table_address(address: u64) -> Result<(), Error> {
    if address & (PAGE_SIZE - 1) != 0 || address & !ADDRESS_MASK != 0 {
        Err(Error::InvalidTableAddress)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: usize = 24;
    const BASE: u64 = 0x10_0000;

    struct TestBackend {
        tables: [[u64; 512]; TABLES],
        used: usize,
    }
    impl TestBackend {
        fn new() -> Self {
            Self {
                tables: [[0; 512]; TABLES],
                used: 1,
            }
        }
        fn index(phys: u64) -> Option<usize> {
            if phys < BASE || !(phys - BASE).is_multiple_of(PAGE_SIZE) {
                return None;
            }
            let index = ((phys - BASE) / PAGE_SIZE) as usize;
            (index < TABLES).then_some(index)
        }
    }
    impl Backend for TestBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            if self.used == TABLES {
                return None;
            }
            let index = self.used;
            self.used += 1;
            self.tables[index] = [0; 512];
            Some(BASE + index as u64 * PAGE_SIZE)
        }
        fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
            Some(*self.tables.get(Self::index(table_phys)?)?.get(index)?)
        }
        fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
            let Some(table) = Self::index(table_phys).and_then(|i| self.tables.get_mut(i)) else {
                return false;
            };
            let Some(entry) = table.get_mut(index) else {
                return false;
            };
            *entry = value;
            true
        }
    }

    #[test]
    fn maps_and_translates_high_half_page() {
        let mut backend = TestBackend::new();
        let root = BASE;
        let mut mapper = Mapper::new(&mut backend, root).unwrap();
        let virtual_address = 0xffff_ffff_8020_0000;
        mapper
            .map_page(
                virtual_address,
                0x40_0000,
                MapFlags::EXECUTE.union(MapFlags::GLOBAL),
            )
            .unwrap();
        assert_eq!(
            mapper.translate(virtual_address + 0x321).unwrap(),
            0x40_0321
        );
    }

    #[test]
    fn refuses_null_page_and_duplicate_mapping() {
        let mut backend = TestBackend::new();
        let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
        assert_eq!(
            mapper.map_page(0, 0x2000, MapFlags::READ),
            Err(Error::NullPage)
        );
        mapper.map_page(0x10_000, 0x2000, MapFlags::READ).unwrap();
        assert_eq!(
            mapper.map_page(0x10_000, 0x3000, MapFlags::READ),
            Err(Error::AlreadyMapped)
        );
    }

    #[test]
    fn user_mapping_propagates_user_bit_through_intermediate_tables() {
        let mut backend = TestBackend::new();
        {
            let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
            mapper
                .map_page(0x40_0000, 0x80_0000, MapFlags::READ.union(MapFlags::USER))
                .unwrap();
        }
        let p4 = page_indexes(0x40_0000).unwrap().p4;
        assert_ne!(backend.tables[0][p4] & USER, 0);
    }

    #[test]
    fn unmap_removes_leaf_translation() {
        let mut backend = TestBackend::new();
        let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
        mapper
            .map_page(0x20_000, 0x90_000, MapFlags::WRITE)
            .unwrap();
        assert_eq!(mapper.unmap_page(0x20_000).unwrap(), 0x90_000);
        assert_eq!(mapper.translate(0x20_000), Err(Error::NotMapped));
    }

    #[test]
    fn ensure_leaf_table_creates_path_without_present_leaf() {
        let mut backend = TestBackend::new();
        let address = 0xffff_ff80_0100_0000;
        let (leaf_table, translation) = {
            let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
            let leaf_table = mapper.ensure_leaf_table(address, false).unwrap();
            let translation = mapper.translate(address);
            (leaf_table, translation)
        };
        let indexes = page_indexes(address).unwrap();
        assert_ne!(leaf_table, 0);
        assert_eq!(
            backend.read_entry(leaf_table, indexes.p1).unwrap() & PRESENT,
            0
        );
        assert_eq!(translation, Err(Error::NotMapped));
    }

    #[test]
    fn recursive_slot_is_high_half_rw_nx_and_points_to_root() {
        let mut backend = TestBackend::new();
        let (duplicate, invalid) = {
            let mut mapper = Mapper::new(&mut backend, BASE).unwrap();
            mapper.install_recursive_slot(510).unwrap();
            (
                mapper.install_recursive_slot(510),
                mapper.install_recursive_slot(1),
            )
        };
        let entry = backend.tables[0][510];
        assert_eq!(entry & ADDRESS_MASK, BASE);
        assert_ne!(entry & PRESENT, 0);
        assert_ne!(entry & WRITABLE, 0);
        assert_ne!(entry & NX, 0);
        assert_eq!(entry & USER, 0);
        assert_eq!(duplicate, Err(Error::RecursiveSlotOccupied));
        assert_eq!(invalid, Err(Error::InvalidRecursiveSlot));
    }
}
