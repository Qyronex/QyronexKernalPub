// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_capability::ObjectId;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Thread = 1,
    AddressSpace = 2,
    Endpoint = 3,
    Notification = 4,
    Frame = 5,
    Irq = 6,
    IommuDomain = 7,
    Device = 8,
    Process = 9,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    InvalidObject,
    StaleObject,
    KindMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectMeta {
    pub kind: ObjectKind,
    pub owner_domain: u32,
    pub flags: u32,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    occupied: bool,
    meta: ObjectMeta,
}

impl Slot {
    const EMPTY: Self = Self {
        generation: 1,
        occupied: false,
        meta: ObjectMeta {
            kind: ObjectKind::Thread,
            owner_domain: 0,
            flags: 0,
        },
    };
}

/// Fixed-capacity object identity registry.
///
/// Object IDs encode a 32-bit generation and 32-bit slot. Capabilities refer to these IDs,
/// so destruction/reuse cannot silently retarget an old capability to a different object.
pub struct ObjectTable<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> Default for ObjectTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ObjectTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
        }
    }

    pub fn create(&mut self, meta: ObjectMeta) -> Result<ObjectId, Error> {
        if N > u32::MAX as usize {
            return Err(Error::Capacity);
        }
        for (slot, entry) in self.slots.iter_mut().enumerate() {
            if !entry.occupied {
                entry.occupied = true;
                entry.meta = meta;
                return Ok(encode_id(slot as u32, entry.generation));
            }
        }
        Err(Error::Capacity)
    }

    pub fn resolve(&self, id: ObjectId) -> Result<ObjectMeta, Error> {
        let (slot, generation) = decode_id(id);
        let entry = self.slots.get(slot as usize).ok_or(Error::InvalidObject)?;
        if !entry.occupied {
            return Err(Error::InvalidObject);
        }
        if entry.generation != generation {
            return Err(Error::StaleObject);
        }
        Ok(entry.meta)
    }

    pub fn resolve_kind(&self, id: ObjectId, expected: ObjectKind) -> Result<ObjectMeta, Error> {
        let meta = self.resolve(id)?;
        if meta.kind != expected {
            return Err(Error::KindMismatch);
        }
        Ok(meta)
    }

    pub fn destroy(&mut self, id: ObjectId) -> Result<ObjectMeta, Error> {
        let (slot, generation) = decode_id(id);
        let entry = self
            .slots
            .get_mut(slot as usize)
            .ok_or(Error::InvalidObject)?;
        if !entry.occupied {
            return Err(Error::InvalidObject);
        }
        if entry.generation != generation {
            return Err(Error::StaleObject);
        }
        let old = entry.meta;
        entry.occupied = false;
        entry.generation = next_generation(entry.generation);
        entry.meta = Slot::EMPTY.meta;
        Ok(old)
    }
}

pub const fn encode_id(slot: u32, generation: u32) -> ObjectId {
    ObjectId(((generation as u64) << 32) | slot as u64)
}

pub const fn decode_id(id: ObjectId) -> (u32, u32) {
    (id.0 as u32, (id.0 >> 32) as u32)
}

const fn next_generation(current: u32) -> u32 {
    let next = current.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thread(owner_domain: u32) -> ObjectMeta {
        ObjectMeta {
            kind: ObjectKind::Thread,
            owner_domain,
            flags: 0,
        }
    }

    #[test]
    fn stale_object_id_cannot_alias_reused_slot() {
        let mut table = ObjectTable::<1>::new();
        let old = table.create(thread(1)).unwrap();
        table.destroy(old).unwrap();
        let new = table.create(thread(2)).unwrap();
        assert_ne!(old, new);
        assert_eq!(table.resolve(old), Err(Error::StaleObject));
        assert_eq!(table.resolve(new).unwrap().owner_domain, 2);
    }

    #[test]
    fn object_kind_is_checked_explicitly() {
        let mut table = ObjectTable::<2>::new();
        let id = table
            .create(ObjectMeta {
                kind: ObjectKind::Endpoint,
                owner_domain: 4,
                flags: 0,
            })
            .unwrap();
        assert_eq!(
            table.resolve_kind(id, ObjectKind::Thread),
            Err(Error::KindMismatch)
        );
        assert_eq!(
            table
                .resolve_kind(id, ObjectKind::Endpoint)
                .unwrap()
                .owner_domain,
            4
        );
    }

    #[test]
    fn destroy_returns_metadata() {
        let mut table = ObjectTable::<1>::new();
        let id = table.create(thread(7)).unwrap();
        assert_eq!(table.destroy(id).unwrap(), thread(7));
        assert_eq!(table.resolve(id), Err(Error::InvalidObject));
    }
}
