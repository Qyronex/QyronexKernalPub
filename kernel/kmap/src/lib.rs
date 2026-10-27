// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};
use kernal_paging::{MapFlags, PAGE_SIZE, is_canonical_48};

pub const MAX_SLOTS: usize = 64;
const MAX_PHYSICAL_ADDRESS_EXCLUSIVE: u64 = 1u64 << 52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CachePolicy {
    WriteBack,
    Uncached,
    WriteCombining,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingRequest {
    pub physical_address: u64,
    pub writable: bool,
    pub cache: CachePolicy,
}

impl MappingRequest {
    pub fn validate(self) -> Result<Self, Error> {
        if self.physical_address & (PAGE_SIZE - 1) != 0 {
            return Err(Error::UnalignedPhysicalAddress);
        }
        if self.physical_address >= MAX_PHYSICAL_ADDRESS_EXCLUSIVE {
            return Err(Error::PhysicalAddressTooHigh);
        }
        Ok(self)
    }

    /// Temporary physical mappings are never executable by design.
    pub const fn page_flags(self) -> MapFlags {
        if self.writable {
            MapFlags::READ
                .union(MapFlags::WRITE)
                .union(MapFlags::GLOBAL)
        } else {
            MapFlags::READ.union(MapFlags::GLOBAL)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ZeroSlots,
    TooManySlots,
    UnalignedWindow,
    NonCanonicalWindow,
    WindowOverflow,
    UnalignedPhysicalAddress,
    PhysicalAddressTooHigh,
    Exhausted,
}

pub struct KmapWindow {
    base: u64,
    slots: u8,
    occupied: AtomicU64,
}

impl KmapWindow {
    pub fn new(base: u64, slots: usize) -> Result<Self, Error> {
        if slots == 0 {
            return Err(Error::ZeroSlots);
        }
        if slots > MAX_SLOTS {
            return Err(Error::TooManySlots);
        }
        if base & (PAGE_SIZE - 1) != 0 {
            return Err(Error::UnalignedWindow);
        }
        if !is_canonical_48(base) {
            return Err(Error::NonCanonicalWindow);
        }
        let len = (slots as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::WindowOverflow)?;
        let end = base.checked_add(len).ok_or(Error::WindowOverflow)?;
        if end == 0 || !is_canonical_48(end - 1) {
            return Err(Error::NonCanonicalWindow);
        }
        Ok(Self {
            base,
            slots: slots as u8,
            occupied: AtomicU64::new(0),
        })
    }

    pub const fn base(&self) -> u64 {
        self.base
    }
    pub const fn slot_count(&self) -> usize {
        self.slots as usize
    }

    pub fn claim(&self, request: MappingRequest) -> Result<KmapLease<'_>, Error> {
        let request = request.validate()?;
        let allowed = slot_mask(self.slots as usize);
        loop {
            let current = self.occupied.load(Ordering::Acquire);
            let available = (!current) & allowed;
            if available == 0 {
                return Err(Error::Exhausted);
            }
            let index = available.trailing_zeros() as usize;
            let bit = 1u64 << index;
            if self
                .occupied
                .compare_exchange_weak(current, current | bit, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let virtual_address = self.base + index as u64 * PAGE_SIZE;
                return Ok(KmapLease {
                    window: self,
                    slot: index as u8,
                    virtual_address,
                    request,
                    _not_send: PhantomData,
                });
            }
        }
    }

    pub fn occupied_slots(&self) -> u32 {
        (self.occupied.load(Ordering::Acquire) & slot_mask(self.slots as usize)).count_ones()
    }

    fn release(&self, slot: u8) {
        let bit = 1u64 << slot;
        self.occupied.fetch_and(!bit, Ordering::AcqRel);
    }
}

pub struct KmapLease<'a> {
    window: &'a KmapWindow,
    slot: u8,
    virtual_address: u64,
    request: MappingRequest,
    // Raw mutable pointer marker intentionally prevents Send/Sync auto-traits. A per-CPU mapping
    // must be torn down on the CPU whose page-table/TLB window owns it.
    _not_send: PhantomData<*mut ()>,
}

impl KmapLease<'_> {
    pub const fn slot(&self) -> usize {
        self.slot as usize
    }
    pub const fn virtual_address(&self) -> u64 {
        self.virtual_address
    }
    pub const fn request(&self) -> MappingRequest {
        self.request
    }
}

impl Drop for KmapLease<'_> {
    fn drop(&mut self) {
        self.window.release(self.slot);
    }
}

const fn slot_mask(slots: usize) -> u64 {
    if slots >= 64 {
        u64::MAX
    } else {
        (1u64 << slots) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xffff_ff80_0100_0000;

    #[test]
    fn leases_unique_slots_and_reuses_released_slot() {
        let window = KmapWindow::new(BASE, 2).unwrap();
        let request = MappingRequest {
            physical_address: 0x2000,
            writable: true,
            cache: CachePolicy::WriteBack,
        };
        let first = window.claim(request).unwrap();
        let second = window
            .claim(MappingRequest {
                physical_address: 0x3000,
                ..request
            })
            .unwrap();
        assert_ne!(first.slot(), second.slot());
        assert_eq!(window.occupied_slots(), 2);
        let released_slot = first.slot();
        drop(first);
        let third = window
            .claim(MappingRequest {
                physical_address: 0x4000,
                ..request
            })
            .unwrap();
        assert_eq!(third.slot(), released_slot);
    }

    #[test]
    fn exhaustion_is_bounded() {
        let window = KmapWindow::new(BASE, 1).unwrap();
        let _lease = window
            .claim(MappingRequest {
                physical_address: 0,
                writable: false,
                cache: CachePolicy::WriteBack,
            })
            .unwrap();
        assert_eq!(
            window
                .claim(MappingRequest {
                    physical_address: 0x1000,
                    writable: false,
                    cache: CachePolicy::WriteBack
                })
                .err(),
            Some(Error::Exhausted)
        );
    }

    #[test]
    fn kmap_permissions_are_always_nx() {
        let writable = MappingRequest {
            physical_address: 0x1000,
            writable: true,
            cache: CachePolicy::WriteBack,
        };
        let readonly = MappingRequest {
            physical_address: 0x2000,
            writable: false,
            cache: CachePolicy::WriteBack,
        };
        assert!(writable.page_flags().writable());
        assert!(!writable.page_flags().executable());
        assert!(!readonly.page_flags().writable());
        assert!(!readonly.page_flags().executable());
    }

    #[test]
    fn rejects_invalid_windows_and_physical_addresses() {
        assert_eq!(
            KmapWindow::new(BASE + 1, 1).err(),
            Some(Error::UnalignedWindow)
        );
        assert_eq!(KmapWindow::new(BASE, 65).err(), Some(Error::TooManySlots));
        assert_eq!(
            MappingRequest {
                physical_address: 3,
                writable: false,
                cache: CachePolicy::Uncached
            }
            .validate(),
            Err(Error::UnalignedPhysicalAddress)
        );
        assert_eq!(
            MappingRequest {
                physical_address: 1u64 << 52,
                writable: false,
                cache: CachePolicy::Uncached
            }
            .validate(),
            Err(Error::PhysicalAddressTooHigh)
        );
    }
}
