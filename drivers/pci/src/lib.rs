// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const CONFIG_SPACE_SIZE: usize = 4096;
pub const LEGACY_CONFIG_SIZE: usize = 256;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl Address {
    pub const fn is_valid(self) -> bool {
        self.device < 32 && self.function < 8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAddress,
    BusOutsideWindow,
    Overflow,
    Truncated,
    NoDevice,
    MalformedCapability,
    CapabilityLoop,
    InvalidBar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcamWindow {
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamWindow {
    pub fn config_address(self, address: Address) -> Result<u64, Error> {
        if !address.is_valid() {
            return Err(Error::InvalidAddress);
        }
        if address.segment != self.segment
            || !(self.start_bus..=self.end_bus).contains(&address.bus)
        {
            return Err(Error::BusOutsideWindow);
        }
        let bus = (address.bus - self.start_bus) as u64;
        self.base
            .checked_add(bus << 20)
            .ok_or(Error::Overflow)?
            .checked_add((address.device as u64) << 15)
            .ok_or(Error::Overflow)?
            .checked_add((address.function as u64) << 12)
            .ok_or(Error::Overflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision: u8,
    pub programming_interface: u8,
    pub subclass: u8,
    pub class: u8,
    pub header_type: u8,
    pub subsystem_vendor_id: Option<u16>,
    pub subsystem_id: Option<u16>,
}

impl Header {
    pub fn parse(config: &[u8]) -> Result<Self, Error> {
        if config.len() < 64 {
            return Err(Error::Truncated);
        }
        let vendor_id = read_u16(config, 0)?;
        if vendor_id == 0xffff {
            return Err(Error::NoDevice);
        }
        let header_type = config[0x0e];
        let type_number = header_type & 0x7f;
        let (subsystem_vendor_id, subsystem_id) = if type_number == 0 {
            (Some(read_u16(config, 0x2c)?), Some(read_u16(config, 0x2e)?))
        } else {
            (None, None)
        };
        Ok(Self {
            vendor_id,
            device_id: read_u16(config, 2)?,
            command: read_u16(config, 4)?,
            status: read_u16(config, 6)?,
            revision: config[8],
            programming_interface: config[9],
            subclass: config[10],
            class: config[11],
            header_type,
            subsystem_vendor_id,
            subsystem_id,
        })
    }

    pub const fn multifunction(self) -> bool {
        self.header_type & 0x80 != 0
    }
    pub const fn has_capabilities(self) -> bool {
        self.status & (1 << 4) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bar {
    Io { base: u32 },
    Memory32 { base: u32, prefetchable: bool },
    Memory64 { base: u64, prefetchable: bool },
}

impl Bar {
    pub fn parse(low: u32, high: Option<u32>) -> Result<Self, Error> {
        if low & 1 != 0 {
            return Ok(Self::Io { base: low & !0x3 });
        }
        let prefetchable = low & (1 << 3) != 0;
        match (low >> 1) & 0x3 {
            0 => Ok(Self::Memory32 {
                base: low & !0xf,
                prefetchable,
            }),
            2 => {
                let high = high.ok_or(Error::InvalidBar)?;
                Ok(Self::Memory64 {
                    base: ((high as u64) << 32) | (low as u64 & !0xf),
                    prefetchable,
                })
            }
            _ => Err(Error::InvalidBar),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    pub id: u8,
    pub offset: u8,
}

pub struct Capabilities<'a> {
    config: &'a [u8],
    next: u8,
    visited: u64,
    finished: bool,
}

impl<'a> Capabilities<'a> {
    pub fn new(config: &'a [u8], header: Header) -> Result<Self, Error> {
        if config.len() < LEGACY_CONFIG_SIZE {
            return Err(Error::Truncated);
        }
        let next = if header.has_capabilities() {
            config[0x34] & 0xfc
        } else {
            0
        };
        Ok(Self {
            config,
            next,
            visited: 0,
            finished: false,
        })
    }
}

impl Iterator for Capabilities<'_> {
    type Item = Result<Capability, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.next == 0 {
            return None;
        }
        let offset = self.next as usize;
        if !(0x40..=0xfc).contains(&offset) || offset + 2 > LEGACY_CONFIG_SIZE {
            self.finished = true;
            return Some(Err(Error::MalformedCapability));
        }
        let index = (offset - 0x40) / 4;
        let bit = 1u64 << index;
        if self.visited & bit != 0 {
            self.finished = true;
            return Some(Err(Error::CapabilityLoop));
        }
        self.visited |= bit;
        let capability = Capability {
            id: self.config[offset],
            offset: offset as u8,
        };
        let raw_next = self.config[offset + 1];
        if raw_next != 0 && raw_next & 0x3 != 0 {
            self.finished = true;
            return Some(Err(Error::MalformedCapability));
        }
        self.next = raw_next;
        Some(Ok(capability))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedCapability {
    pub id: u16,
    pub version: u8,
    pub offset: u16,
}

pub struct ExtendedCapabilities<'a> {
    config: &'a [u8],
    next: u16,
    remaining: u16,
}

impl<'a> ExtendedCapabilities<'a> {
    pub fn new(config: &'a [u8]) -> Result<Self, Error> {
        if config.len() < CONFIG_SPACE_SIZE {
            return Err(Error::Truncated);
        }
        Ok(Self {
            config,
            next: 0x100,
            remaining: 960,
        })
    }
}

impl Iterator for ExtendedCapabilities<'_> {
    type Item = Result<ExtendedCapability, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == 0 || self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let offset = self.next as usize;
        if !(0x100..=0xffc).contains(&offset) || offset & 0x3 != 0 {
            self.next = 0;
            return Some(Err(Error::MalformedCapability));
        }
        let header = match read_u32(self.config, offset) {
            Ok(value) => value,
            Err(error) => {
                self.next = 0;
                return Some(Err(error));
            }
        };
        let id = header as u16;
        if id == 0 || id == 0xffff {
            self.next = 0;
            return None;
        }
        let version = ((header >> 16) & 0xf) as u8;
        let next = ((header >> 20) & 0xfff) as u16;
        if next == self.next {
            self.next = 0;
            return Some(Err(Error::CapabilityLoop));
        }
        self.next = next;
        Some(Ok(ExtendedCapability {
            id,
            version,
            offset: offset as u16,
        }))
    }
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let raw: [u8; 2] = bytes
        .get(at..at + 2)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u16::from_le_bytes(raw))
}
fn read_u32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u32::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecam_address_matches_pcie_layout() {
        let window = EcamWindow {
            base: 0xe000_0000,
            segment: 0,
            start_bus: 0x20,
            end_bus: 0x2f,
        };
        let address = Address {
            segment: 0,
            bus: 0x21,
            device: 3,
            function: 2,
        };
        assert_eq!(
            window.config_address(address).unwrap(),
            0xe000_0000 + (1 << 20) + (3 << 15) + (2 << 12)
        );
    }

    #[test]
    fn absent_device_is_not_parsed_as_header() {
        let config = [0xffu8; 64];
        assert_eq!(Header::parse(&config), Err(Error::NoDevice));
    }

    #[test]
    fn capability_cycle_is_detected() {
        let mut config = [0u8; 256];
        config[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        config[6..8].copy_from_slice(&(1u16 << 4).to_le_bytes());
        config[0x34] = 0x40;
        config[0x40] = 5;
        config[0x41] = 0x44;
        config[0x44] = 0x11;
        config[0x45] = 0x40;
        let header = Header::parse(&config).unwrap();
        let mut caps = Capabilities::new(&config, header).unwrap();
        assert!(caps.next().unwrap().is_ok());
        assert!(caps.next().unwrap().is_ok());
        assert_eq!(caps.next().unwrap(), Err(Error::CapabilityLoop));
    }

    #[test]
    fn parses_64bit_bar_without_truncation() {
        let bar = Bar::parse(0x3456_700c, Some(0x0000_1234)).unwrap();
        assert_eq!(
            bar,
            Bar::Memory64 {
                base: 0x0000_1234_3456_7000,
                prefetchable: true
            }
        );
    }
}
