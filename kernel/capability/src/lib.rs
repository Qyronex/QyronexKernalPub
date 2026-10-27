// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct ObjectId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CapHandle {
    pub slot: u32,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CapRights(u32);

impl CapRights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const MAP: Self = Self(1 << 3);
    pub const GRANT: Self = Self(1 << 4);
    pub const SIGNAL: Self = Self(1 << 5);
    pub const WAIT: Self = Self(1 << 6);
    pub const CONTROL: Self = Self(1 << 7);
    pub const DMA: Self = Self(1 << 8);
    pub const IRQ: Self = Self(1 << 9);
    pub const DEBUG: Self = Self(1 << 10);
    pub const ALL: Self = Self((1 << 11) - 1);

    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    pub object: ObjectId,
    pub rights: CapRights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapError {
    TableFull,
    InvalidSlot,
    StaleHandle,
    InsufficientRights,
}

#[derive(Clone, Copy)]
struct Entry {
    generation: u32,
    occupied: bool,
    object: ObjectId,
    rights: CapRights,
    parent: Option<CapHandle>,
}

impl Entry {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        object: ObjectId(0),
        rights: CapRights::NONE,
        parent: None,
    };
}

pub struct CapabilityTable<const N: usize> {
    entries: [Entry; N],
}

impl<const N: usize> Default for CapabilityTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CapabilityTable<N> {
    pub const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; N],
        }
    }

    pub fn insert_root(
        &mut self,
        object: ObjectId,
        rights: CapRights,
    ) -> Result<CapHandle, CapError> {
        self.insert(object, rights, None)
    }

    pub fn derive(
        &mut self,
        parent: CapHandle,
        requested: CapRights,
    ) -> Result<CapHandle, CapError> {
        let parent_capability = self.resolve(parent)?;
        if !parent_capability.rights.contains(requested) {
            return Err(CapError::InsufficientRights);
        }
        self.insert(parent_capability.object, requested, Some(parent))
    }

    pub fn resolve(&self, handle: CapHandle) -> Result<Capability, CapError> {
        let entry = self.entry(handle)?;
        Ok(Capability {
            object: entry.object,
            rights: entry.rights,
        })
    }

    pub fn revoke(&mut self, handle: CapHandle) -> Result<(), CapError> {
        self.entry(handle)?;
        self.invalidate_slot(handle.slot as usize);
        loop {
            let mut changed = false;
            for slot in 0..N {
                if !self.entries[slot].occupied {
                    continue;
                }
                if let Some(parent) = self.entries[slot].parent
                    && self.resolve(parent).is_err()
                {
                    self.invalidate_slot(slot);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    fn insert(
        &mut self,
        object: ObjectId,
        rights: CapRights,
        parent: Option<CapHandle>,
    ) -> Result<CapHandle, CapError> {
        for (slot, entry) in self.entries.iter_mut().enumerate() {
            if !entry.occupied {
                entry.occupied = true;
                entry.object = object;
                entry.rights = rights;
                entry.parent = parent;
                return Ok(CapHandle {
                    slot: slot as u32,
                    generation: entry.generation,
                });
            }
        }
        Err(CapError::TableFull)
    }

    fn entry(&self, handle: CapHandle) -> Result<&Entry, CapError> {
        let entry = self
            .entries
            .get(handle.slot as usize)
            .ok_or(CapError::InvalidSlot)?;
        if !entry.occupied || entry.generation != handle.generation {
            return Err(CapError::StaleHandle);
        }
        Ok(entry)
    }

    fn invalidate_slot(&mut self, slot: usize) {
        let entry = &mut self.entries[slot];
        entry.occupied = false;
        entry.object = ObjectId(0);
        entry.rights = CapRights::NONE;
        entry.parent = None;
        entry.generation = entry.generation.wrapping_add(1);
        if entry.generation == 0 {
            entry.generation = 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw() -> CapRights {
        CapRights::READ.union(CapRights::WRITE)
    }

    #[test]
    fn derived_rights_can_be_reduced() {
        let mut table = CapabilityTable::<8>::new();
        let root = table.insert_root(ObjectId(7), rw()).unwrap();
        let child = table.derive(root, CapRights::READ).unwrap();
        assert_eq!(table.resolve(child).unwrap().rights, CapRights::READ);
    }

    #[test]
    fn derived_rights_cannot_grow() {
        let mut table = CapabilityTable::<8>::new();
        let root = table.insert_root(ObjectId(7), CapRights::READ).unwrap();
        assert_eq!(table.derive(root, rw()), Err(CapError::InsufficientRights));
    }

    #[test]
    fn stale_handle_is_rejected_after_slot_reuse() {
        let mut table = CapabilityTable::<1>::new();
        let old = table.insert_root(ObjectId(1), CapRights::CONTROL).unwrap();
        table.revoke(old).unwrap();
        let new = table.insert_root(ObjectId(2), CapRights::CONTROL).unwrap();
        assert_ne!(old.generation, new.generation);
        assert_eq!(table.resolve(old), Err(CapError::StaleHandle));
    }

    #[test]
    fn revocation_invalidates_tree() {
        let mut table = CapabilityTable::<8>::new();
        let root = table.insert_root(ObjectId(9), rw()).unwrap();
        let child = table.derive(root, CapRights::READ).unwrap();
        let grandchild = table.derive(child, CapRights::READ).unwrap();
        table.revoke(root).unwrap();
        assert_eq!(table.resolve(child), Err(CapError::StaleHandle));
        assert_eq!(table.resolve(grandchild), Err(CapError::StaleHandle));
    }
}
