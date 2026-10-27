// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const PAGE_SIZE: u64 = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciDeviceId {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciDeviceId {
    pub const fn is_valid(self) -> bool {
        self.device < 32 && self.function < 8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaPerms(u8);

impl DmaPerms {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn is_valid(self) -> bool {
        self.0 != 0 && self.0 & !Self::READ_WRITE.0 == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaMapping {
    pub iova: u64,
    pub phys: u64,
    pub len: u64,
    pub perms: DmaPerms,
}

impl DmaMapping {
    pub fn new(iova: u64, phys: u64, len: u64, perms: DmaPerms) -> Result<Self, Error> {
        if len == 0
            || iova & (PAGE_SIZE - 1) != 0
            || phys & (PAGE_SIZE - 1) != 0
            || len & (PAGE_SIZE - 1) != 0
        {
            return Err(Error::UnalignedOrEmpty);
        }
        if !perms.is_valid() {
            return Err(Error::InvalidPermissions);
        }
        iova.checked_add(len).ok_or(Error::Overflow)?;
        phys.checked_add(len).ok_or(Error::Overflow)?;
        Ok(Self {
            iova,
            phys,
            len,
            perms,
        })
    }

    pub const fn iova_end(self) -> Option<u64> {
        self.iova.checked_add(self.len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    InvalidDevice,
    DeviceAlreadyAssigned,
    DeviceNotAssigned,
    UnalignedOrEmpty,
    InvalidPermissions,
    Overflow,
    Overlap,
    MappingNotFound,
}

#[derive(Clone, Copy)]
struct DeviceSlot {
    occupied: bool,
    device: PciDeviceId,
}

impl DeviceSlot {
    const EMPTY: Self = Self {
        occupied: false,
        device: PciDeviceId {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
        },
    };
}

#[derive(Clone, Copy)]
struct MappingSlot {
    occupied: bool,
    mapping: DmaMapping,
}

impl MappingSlot {
    const EMPTY: Self = Self {
        occupied: false,
        mapping: DmaMapping {
            iova: 0,
            phys: 0,
            len: PAGE_SIZE,
            perms: DmaPerms::READ,
        },
    };
}

/// Hardware-independent IOMMU domain policy.
///
/// Hardware backends (Intel VT-d, AMD-Vi, ARM SMMU) consume this validated state. A device is
/// not considered safe for userspace bus mastering until the backend has materialized the
/// domain and completed an invalidation/fence.
pub struct Domain<const DEVICES: usize, const MAPPINGS: usize> {
    devices: [DeviceSlot; DEVICES],
    mappings: [MappingSlot; MAPPINGS],
}

impl<const D: usize, const M: usize> Default for Domain<D, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const D: usize, const M: usize> Domain<D, M> {
    pub const fn new() -> Self {
        Self {
            devices: [DeviceSlot::EMPTY; D],
            mappings: [MappingSlot::EMPTY; M],
        }
    }

    pub fn attach_device(&mut self, device: PciDeviceId) -> Result<(), Error> {
        if !device.is_valid() {
            return Err(Error::InvalidDevice);
        }
        if self
            .devices
            .iter()
            .any(|slot| slot.occupied && slot.device == device)
        {
            return Err(Error::DeviceAlreadyAssigned);
        }
        let slot = self
            .devices
            .iter_mut()
            .find(|slot| !slot.occupied)
            .ok_or(Error::Capacity)?;
        *slot = DeviceSlot {
            occupied: true,
            device,
        };
        Ok(())
    }

    pub fn detach_device(&mut self, device: PciDeviceId) -> Result<(), Error> {
        let slot = self
            .devices
            .iter_mut()
            .find(|slot| slot.occupied && slot.device == device)
            .ok_or(Error::DeviceNotAssigned)?;
        *slot = DeviceSlot::EMPTY;
        Ok(())
    }

    pub fn map(&mut self, mapping: DmaMapping) -> Result<(), Error> {
        let end = mapping.iova_end().ok_or(Error::Overflow)?;
        for slot in &self.mappings {
            if !slot.occupied {
                continue;
            }
            let other = slot.mapping;
            let other_end = other.iova_end().ok_or(Error::Overflow)?;
            if mapping.iova < other_end && end > other.iova {
                return Err(Error::Overlap);
            }
        }
        let slot = self
            .mappings
            .iter_mut()
            .find(|slot| !slot.occupied)
            .ok_or(Error::Capacity)?;
        *slot = MappingSlot {
            occupied: true,
            mapping,
        };
        Ok(())
    }

    pub fn unmap(&mut self, iova: u64, len: u64) -> Result<DmaMapping, Error> {
        let slot = self
            .mappings
            .iter_mut()
            .find(|slot| slot.occupied && slot.mapping.iova == iova && slot.mapping.len == len)
            .ok_or(Error::MappingNotFound)?;
        let mapping = slot.mapping;
        *slot = MappingSlot::EMPTY;
        Ok(mapping)
    }

    pub fn translate_for_test(&self, iova: u64, write: bool) -> Option<u64> {
        for slot in &self.mappings {
            if !slot.occupied {
                continue;
            }
            let mapping = slot.mapping;
            let end = mapping.iova_end()?;
            if (mapping.iova..end).contains(&iova) {
                if write && mapping.perms.bits() & DmaPerms::WRITE.bits() == 0 {
                    return None;
                }
                return mapping.phys.checked_add(iova - mapping.iova);
            }
        }
        None
    }
}

/// Registry preventing a PCI function from being simultaneously assigned to two domains.
pub struct AssignmentRegistry<const N: usize> {
    entries: [Option<(PciDeviceId, u32)>; N],
}

impl<const N: usize> Default for AssignmentRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AssignmentRegistry<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    pub fn assign(&mut self, device: PciDeviceId, domain: u32) -> Result<(), Error> {
        if !device.is_valid() {
            return Err(Error::InvalidDevice);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|(existing, _)| *existing == device)
        {
            return Err(Error::DeviceAlreadyAssigned);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some((device, domain));
        Ok(())
    }

    pub fn release(&mut self, device: PciDeviceId, domain: u32) -> Result<(), Error> {
        let slot = self.entries.iter_mut().find(|entry| matches!(entry, Some((existing, owner)) if *existing == device && *owner == domain)).ok_or(Error::DeviceNotAssigned)?;
        *slot = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(n: u8) -> PciDeviceId {
        PciDeviceId {
            segment: 0,
            bus: 0,
            device: n,
            function: 0,
        }
    }

    #[test]
    fn mappings_cannot_overlap_in_iova_space() {
        let mut domain = Domain::<2, 4>::new();
        domain
            .map(DmaMapping::new(0x1000, 0x8000, 0x2000, DmaPerms::READ_WRITE).unwrap())
            .unwrap();
        assert_eq!(
            domain.map(DmaMapping::new(0x2000, 0xa000, 0x1000, DmaPerms::READ).unwrap()),
            Err(Error::Overlap)
        );
    }

    #[test]
    fn read_only_dma_rejects_write_translation() {
        let mut domain = Domain::<1, 2>::new();
        domain
            .map(DmaMapping::new(0x4000, 0x9000, 0x1000, DmaPerms::READ).unwrap())
            .unwrap();
        assert_eq!(domain.translate_for_test(0x4123, false), Some(0x9123));
        assert_eq!(domain.translate_for_test(0x4123, true), None);
    }

    #[test]
    fn a_device_cannot_belong_to_multiple_domains() {
        let mut registry = AssignmentRegistry::<4>::new();
        registry.assign(dev(3), 10).unwrap();
        assert_eq!(
            registry.assign(dev(3), 11),
            Err(Error::DeviceAlreadyAssigned)
        );
        registry.release(dev(3), 10).unwrap();
        registry.assign(dev(3), 11).unwrap();
    }

    #[test]
    fn invalid_pci_function_is_rejected() {
        let mut domain = Domain::<1, 1>::new();
        assert_eq!(
            domain.attach_device(PciDeviceId {
                segment: 0,
                bus: 0,
                device: 32,
                function: 0
            }),
            Err(Error::InvalidDevice)
        );
    }
}
