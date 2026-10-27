// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CpuIndex(pub u16);

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuState {
    Offline = 0,
    Starting = 1,
    Online = 2,
    Failed = 3,
}

impl CpuState {
    fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Offline,
            1 => Self::Starting,
            2 => Self::Online,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuDescriptor {
    pub index: CpuIndex,
    pub apic_id: u32,
    pub processor_uid: u32,
    pub proximity_domain: Option<u32>,
}

impl CpuDescriptor {
    const EMPTY: Self = Self {
        index: CpuIndex(0),
        apic_id: 0,
        processor_uid: 0,
        proximity_domain: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuRegistration {
    pub apic_id: u32,
    pub processor_uid: u32,
    pub proximity_domain: Option<u32>,
}

#[derive(Debug)]
struct CpuSlot {
    descriptor: CpuDescriptor,
    state: AtomicU8,
}

impl CpuSlot {
    const fn new() -> Self {
        Self {
            descriptor: CpuDescriptor::EMPTY,
            state: AtomicU8::new(CpuState::Offline as u8),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    TooManyCpusForIndex,
    DuplicateApicId,
    DuplicateProcessorUid,
    UnknownCpu,
    InvalidTransition,
    AlreadyInitialized,
    InitializationInProgress,
}

pub struct CpuRegistry<const N: usize> {
    slots: [CpuSlot; N],
    len: usize,
}

impl<const N: usize> Default for CpuRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CpuRegistry<N> {
    pub const fn new() -> Self {
        Self {
            slots: [const { CpuSlot::new() }; N],
            len: 0,
        }
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn register(
        &mut self,
        apic_id: u32,
        processor_uid: u32,
        proximity_domain: Option<u32>,
    ) -> Result<CpuIndex, Error> {
        if self.slots[..self.len]
            .iter()
            .any(|slot| slot.descriptor.apic_id == apic_id)
        {
            return Err(Error::DuplicateApicId);
        }
        if self.slots[..self.len]
            .iter()
            .any(|slot| slot.descriptor.processor_uid == processor_uid)
        {
            return Err(Error::DuplicateProcessorUid);
        }
        if self.len == N {
            return Err(Error::Capacity);
        }
        let index_u16 = u16::try_from(self.len).map_err(|_| Error::TooManyCpusForIndex)?;
        let index = CpuIndex(index_u16);
        self.slots[self.len].descriptor = CpuDescriptor {
            index,
            apic_id,
            processor_uid,
            proximity_domain,
        };
        self.slots[self.len]
            .state
            .store(CpuState::Offline as u8, Ordering::Relaxed);
        self.len += 1;
        Ok(index)
    }

    pub fn descriptor(&self, index: CpuIndex) -> Option<CpuDescriptor> {
        let position = index.0 as usize;
        (position < self.len).then(|| self.slots[position].descriptor)
    }

    pub fn descriptors(&self) -> impl Iterator<Item = CpuDescriptor> + '_ {
        self.slots[..self.len].iter().map(|slot| slot.descriptor)
    }

    pub fn index_for_apic_id(&self, apic_id: u32) -> Option<CpuIndex> {
        self.slots[..self.len]
            .iter()
            .find(|slot| slot.descriptor.apic_id == apic_id)
            .map(|slot| slot.descriptor.index)
    }

    pub fn state(&self, index: CpuIndex) -> Result<CpuState, Error> {
        let slot = self.slot(index)?;
        Ok(CpuState::from_raw(slot.state.load(Ordering::Acquire)))
    }

    pub fn mark_starting(&self, index: CpuIndex) -> Result<(), Error> {
        self.transition(index, CpuState::Offline, CpuState::Starting)
    }

    pub fn mark_online(&self, index: CpuIndex) -> Result<(), Error> {
        self.transition(index, CpuState::Starting, CpuState::Online)
    }

    pub fn mark_failed(&self, index: CpuIndex) -> Result<(), Error> {
        let slot = self.slot(index)?;
        loop {
            let current = slot.state.load(Ordering::Acquire);
            if current == CpuState::Online as u8 || current == CpuState::Failed as u8 {
                return Err(Error::InvalidTransition);
            }
            if slot
                .state
                .compare_exchange_weak(
                    current,
                    CpuState::Failed as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Legacy explicit helper retained for unit-level registry use. Production bootstrap should
    /// prefer `mark_starting` then `mark_online` after all per-CPU runtime invariants are live.
    pub fn set_bsp_online(&self, index: CpuIndex) -> Result<(), Error> {
        self.transition(index, CpuState::Offline, CpuState::Online)
    }

    pub fn online_count(&self) -> usize {
        self.slots[..self.len]
            .iter()
            .filter(|slot| slot.state.load(Ordering::Acquire) == CpuState::Online as u8)
            .count()
    }

    fn transition(&self, index: CpuIndex, from: CpuState, to: CpuState) -> Result<(), Error> {
        let slot = self.slot(index)?;
        slot.state
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Error::InvalidTransition)
    }

    fn slot(&self, index: CpuIndex) -> Result<&CpuSlot, Error> {
        let position = index.0 as usize;
        if position >= self.len {
            return Err(Error::UnknownCpu);
        }
        Ok(&self.slots[position])
    }
}

/// One-time publication wrapper for topology-derived CPU identities.
///
/// `initialize` freezes descriptors but intentionally leaves the BSP in `Starting`, not `Online`.
/// The Core may publish Online only after descriptor/IDT, GS, scheduler, Local APIC runtime, timer
/// and idle-thread invariants are all established.
pub struct CpuRegistryCell<const N: usize> {
    state: AtomicU8,
    registry: UnsafeCell<CpuRegistry<N>>,
}

// SAFETY: initialization is single-writer via `state`; after READY, only atomics mutate.
unsafe impl<const N: usize> Sync for CpuRegistryCell<N> {}

impl<const N: usize> CpuRegistryCell<N> {
    const EMPTY: u8 = 0;
    const INITIALIZING: u8 = 1;
    const READY: u8 = 2;

    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::EMPTY),
            registry: UnsafeCell::new(CpuRegistry::new()),
        }
    }

    pub fn initialize(
        &'static self,
        registrations: &[CpuRegistration],
        bsp_apic_id: u32,
    ) -> Result<&'static CpuRegistry<N>, Error> {
        match self.state.compare_exchange(
            Self::EMPTY,
            Self::INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(Self::INITIALIZING) => return Err(Error::InitializationInProgress),
            Err(_) => return Err(Error::AlreadyInitialized),
        }

        // SAFETY: this initializer exclusively owns the registry while state=INITIALIZING.
        let registry = unsafe { &mut *self.registry.get() };
        *registry = CpuRegistry::new();
        for registration in registrations {
            if let Err(error) = registry.register(
                registration.apic_id,
                registration.processor_uid,
                registration.proximity_domain,
            ) {
                *registry = CpuRegistry::new();
                self.state.store(Self::EMPTY, Ordering::Release);
                return Err(error);
            }
        }
        let Some(bsp) = registry.index_for_apic_id(bsp_apic_id) else {
            *registry = CpuRegistry::new();
            self.state.store(Self::EMPTY, Ordering::Release);
            return Err(Error::UnknownCpu);
        };
        if let Err(error) = registry.mark_starting(bsp) {
            *registry = CpuRegistry::new();
            self.state.store(Self::EMPTY, Ordering::Release);
            return Err(error);
        }

        self.state.store(Self::READY, Ordering::Release);
        // SAFETY: READY freezes all non-atomic registry fields for the process lifetime.
        Ok(unsafe { &*self.registry.get() })
    }

    pub fn get(&'static self) -> Option<&'static CpuRegistry<N>> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return None;
        }
        // SAFETY: acquire observes READY and therefore completed initialization.
        Some(unsafe { &*self.registry.get() })
    }
}

impl<const N: usize> Default for CpuRegistryCell<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_indices_follow_registration_order() {
        let mut registry = CpuRegistry::<4>::new();
        assert_eq!(registry.register(7, 10, Some(0)).unwrap(), CpuIndex(0));
        assert_eq!(registry.register(42, 11, Some(1)).unwrap(), CpuIndex(1));
        assert_eq!(registry.index_for_apic_id(42), Some(CpuIndex(1)));
        assert_eq!(registry.descriptor(CpuIndex(0)).unwrap().apic_id, 7);
    }

    #[test]
    fn lifecycle_rejects_skipped_or_repeated_transitions() {
        let mut registry = CpuRegistry::<2>::new();
        let cpu = registry.register(1, 1, None).unwrap();
        assert_eq!(registry.mark_online(cpu), Err(Error::InvalidTransition));
        registry.mark_starting(cpu).unwrap();
        registry.mark_online(cpu).unwrap();
        assert_eq!(registry.mark_online(cpu), Err(Error::InvalidTransition));
        assert_eq!(registry.state(cpu).unwrap(), CpuState::Online);
    }

    #[test]
    fn explicit_direct_online_helper_still_works_only_once() {
        let mut registry = CpuRegistry::<1>::new();
        let bsp = registry.register(2, 3, None).unwrap();
        registry.set_bsp_online(bsp).unwrap();
        assert_eq!(registry.online_count(), 1);
        assert_eq!(registry.set_bsp_online(bsp), Err(Error::InvalidTransition));
    }

    #[test]
    fn duplicate_hardware_identity_is_rejected() {
        let mut registry = CpuRegistry::<4>::new();
        registry.register(5, 10, None).unwrap();
        assert_eq!(registry.register(5, 11, None), Err(Error::DuplicateApicId));
        assert_eq!(
            registry.register(6, 10, None),
            Err(Error::DuplicateProcessorUid)
        );
    }

    #[test]
    fn one_shot_cell_publishes_bsp_as_starting_until_core_finishes_runtime_setup() {
        static CELL: CpuRegistryCell<4> = CpuRegistryCell::new();
        let registrations = [
            CpuRegistration {
                apic_id: 2,
                processor_uid: 10,
                proximity_domain: Some(0),
            },
            CpuRegistration {
                apic_id: 4,
                processor_uid: 11,
                proximity_domain: Some(0),
            },
        ];
        let registry = CELL.initialize(&registrations, 2).unwrap();
        let bsp = registry.index_for_apic_id(2).unwrap();
        assert_eq!(registry.state(bsp), Ok(CpuState::Starting));
        assert_eq!(registry.online_count(), 0);
        registry.mark_online(bsp).unwrap();
        assert_eq!(registry.online_count(), 1);
        let ap = registry.index_for_apic_id(4).unwrap();
        registry.mark_starting(ap).unwrap();
        registry.mark_online(ap).unwrap();
        assert_eq!(registry.online_count(), 2);
    }
}
