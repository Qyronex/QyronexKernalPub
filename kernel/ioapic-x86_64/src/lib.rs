// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ptr::{read_volatile, write_volatile};
use kernal_kmap::{CachePolicy, MappingRequest};
use kernal_kmap_x86_64::{ActiveMapping, KmapController};

const IOREGSEL_OFFSET: u64 = 0x00;
const IOWIN_OFFSET: u64 = 0x10;
const REG_ID: u8 = 0x00;
const REG_VERSION: u8 = 0x01;
const REDIRECTION_BASE: u8 = 0x10;
const REDIRECTION_MASKED: u32 = 1 << 16;
const REDIRECTION_LEVEL: u32 = 1 << 15;
const REDIRECTION_ACTIVE_LOW: u32 = 1 << 13;

pub const MAX_REDIRECTION_ENTRIES: usize = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidMmioBase,
    MappingFailed,
    InvalidRegister,
    InvalidPin,
    InvalidVector,
    InvalidDestination,
    TooManyEntries,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerMode {
    Edge,
    Level,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub vector: u8,
    pub destination_apic_id: u8,
    pub polarity: Polarity,
    pub trigger: TriggerMode,
    pub masked: bool,
}

impl Route {
    pub fn encode(self) -> Result<u64, Error> {
        if self.vector < 0x20 {
            return Err(Error::InvalidVector);
        }
        let mut low = self.vector as u32;
        if self.polarity == Polarity::ActiveLow {
            low |= REDIRECTION_ACTIVE_LOW;
        }
        if self.trigger == TriggerMode::Level {
            low |= REDIRECTION_LEVEL;
        }
        if self.masked {
            low |= REDIRECTION_MASKED;
        }
        Ok(((self.destination_apic_id as u64) << 56) | low as u64)
    }
}

pub trait IoApicAccess {
    fn read_register(&self, register: u8) -> Result<u32, Error>;
    fn write_register(&mut self, register: u8, value: u32) -> Result<(), Error>;
}

pub struct IoApic<A: IoApicAccess> {
    access: A,
    gsi_base: u32,
    redirection_entries: u8,
}

impl<A: IoApicAccess> IoApic<A> {
    pub fn probe(access: A, gsi_base: u32) -> Result<Self, Error> {
        let version = access.read_register(REG_VERSION)?;
        let max_index = ((version >> 16) & 0xff) as usize;
        let count = max_index.checked_add(1).ok_or(Error::TooManyEntries)?;
        if count == 0 || count > MAX_REDIRECTION_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        Ok(Self {
            access,
            gsi_base,
            redirection_entries: count as u8,
        })
    }

    pub fn id(&self) -> Result<u8, Error> {
        Ok(((self.access.read_register(REG_ID)? >> 24) & 0xf) as u8)
    }
    pub const fn gsi_base(&self) -> u32 {
        self.gsi_base
    }
    pub const fn redirection_entries(&self) -> u8 {
        self.redirection_entries
    }
    pub fn gsi_end_exclusive(&self) -> Option<u32> {
        self.gsi_base.checked_add(self.redirection_entries as u32)
    }

    pub fn contains_gsi(&self, gsi: u32) -> bool {
        self.gsi_end_exclusive()
            .is_some_and(|end| self.gsi_base <= gsi && gsi < end)
    }

    /// Masks every pin before the kernel permits maskable interrupts. High dword is preserved;
    /// only the mask bit in the low dword changes.
    pub fn mask_all(&mut self) -> Result<(), Error> {
        for pin in 0..self.redirection_entries {
            let low_reg = redirection_register(pin, false)?;
            let current = self.access.read_register(low_reg)?;
            self.access
                .write_register(low_reg, current | REDIRECTION_MASKED)?;
        }
        Ok(())
    }

    /// Programs a route fail-closed: low dword is first written masked, destination is updated,
    /// and only then may the requested final low dword become unmasked.
    pub fn set_route(&mut self, pin: u8, route: Route) -> Result<(), Error> {
        if pin >= self.redirection_entries {
            return Err(Error::InvalidPin);
        }
        let encoded = route.encode()?;
        let low_reg = redirection_register(pin, false)?;
        let high_reg = redirection_register(pin, true)?;
        let low = encoded as u32;
        let high = (encoded >> 32) as u32;
        self.access
            .write_register(low_reg, low | REDIRECTION_MASKED)?;
        self.access.write_register(high_reg, high)?;
        self.access.write_register(low_reg, low)
    }

    pub fn mask_pin(&mut self, pin: u8) -> Result<(), Error> {
        if pin >= self.redirection_entries {
            return Err(Error::InvalidPin);
        }
        let register = redirection_register(pin, false)?;
        let low = self.access.read_register(register)?;
        self.access
            .write_register(register, low | REDIRECTION_MASKED)
    }

    pub fn pin_for_gsi(&self, gsi: u32) -> Result<u8, Error> {
        if !self.contains_gsi(gsi) {
            return Err(Error::InvalidPin);
        }
        u8::try_from(gsi - self.gsi_base).map_err(|_| Error::InvalidPin)
    }

    pub fn into_inner(self) -> A {
        self.access
    }
}

fn redirection_register(pin: u8, high: bool) -> Result<u8, Error> {
    let index = (pin as u16).checked_mul(2).ok_or(Error::InvalidRegister)?;
    let register = (REDIRECTION_BASE as u16)
        .checked_add(index)
        .and_then(|value| value.checked_add(high as u16))
        .ok_or(Error::InvalidRegister)?;
    u8::try_from(register).map_err(|_| Error::InvalidRegister)
}

pub struct MmioAccess<'a> {
    mapping: ActiveMapping<'a>,
}
impl<'a> MmioAccess<'a> {
    pub fn map(kmap: &'a KmapController, physical_base: u64) -> Result<Self, Error> {
        if physical_base == 0 || physical_base & 0xfff != 0 {
            return Err(Error::InvalidMmioBase);
        }
        let mapping = kmap
            .map(MappingRequest {
                physical_address: physical_base,
                writable: true,
                cache: CachePolicy::Uncached,
            })
            .map_err(|_| Error::MappingFailed)?;
        Ok(Self { mapping })
    }

    fn selector(&self) -> *mut u32 {
        (self.mapping.virtual_address() + IOREGSEL_OFFSET) as *mut u32
    }
    fn window(&self) -> *mut u32 {
        (self.mapping.virtual_address() + IOWIN_OFFSET) as *mut u32
    }
}

impl IoApicAccess for MmioAccess<'_> {
    fn read_register(&self, register: u8) -> Result<u32, Error> {
        // SAFETY: both pointers lie inside the live UC IOAPIC MMIO page; selector/window access
        // is volatile and serialized by the single-owner bootstrap controller.
        unsafe {
            write_volatile(self.selector(), register as u32);
            Ok(read_volatile(self.window()))
        }
    }

    fn write_register(&mut self, register: u8, value: u32) -> Result<(), Error> {
        // SAFETY: same single-owner UC MMIO contract as read_register.
        unsafe {
            write_volatile(self.selector(), register as u32);
            write_volatile(self.window(), value);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Fake {
        regs: [u32; 256],
    }
    impl Fake {
        fn with_entries(entries: u8) -> Self {
            let mut value = Self { regs: [0; 256] };
            value.regs[REG_VERSION as usize] = ((entries as u32 - 1) & 0xff) << 16 | 0x11;
            value
        }
    }
    impl IoApicAccess for Fake {
        fn read_register(&self, register: u8) -> Result<u32, Error> {
            Ok(self.regs[register as usize])
        }
        fn write_register(&mut self, register: u8, value: u32) -> Result<(), Error> {
            self.regs[register as usize] = value;
            Ok(())
        }
    }

    #[test]
    fn probe_decodes_redirection_count() {
        let apic = IoApic::probe(Fake::with_entries(24), 0).unwrap();
        assert_eq!(apic.redirection_entries(), 24);
        assert_eq!(apic.gsi_end_exclusive(), Some(24));
    }

    #[test]
    fn mask_all_sets_every_low_mask_bit() {
        let mut apic = IoApic::probe(Fake::with_entries(4), 32).unwrap();
        apic.mask_all().unwrap();
        let fake = apic.into_inner();
        for pin in 0..4u8 {
            let register = redirection_register(pin, false).unwrap();
            assert_ne!(fake.regs[register as usize] & REDIRECTION_MASKED, 0);
        }
    }

    #[test]
    fn route_encodes_level_low_destination() {
        let route = Route {
            vector: 0x40,
            destination_apic_id: 7,
            polarity: Polarity::ActiveLow,
            trigger: TriggerMode::Level,
            masked: false,
        };
        let encoded = route.encode().unwrap();
        assert_eq!(encoded >> 56, 7);
        assert_eq!(encoded as u32 & 0xff, 0x40);
        assert_ne!(encoded as u32 & REDIRECTION_ACTIVE_LOW, 0);
        assert_ne!(encoded as u32 & REDIRECTION_LEVEL, 0);
        assert_eq!(encoded as u32 & REDIRECTION_MASKED, 0);
    }

    #[test]
    fn gsi_to_pin_is_bounds_checked() {
        let apic = IoApic::probe(Fake::with_entries(8), 24).unwrap();
        assert_eq!(apic.pin_for_gsi(24).unwrap(), 0);
        assert_eq!(apic.pin_for_gsi(31).unwrap(), 7);
        assert_eq!(apic.pin_for_gsi(32), Err(Error::InvalidPin));
    }
}
