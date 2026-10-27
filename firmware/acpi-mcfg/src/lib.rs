// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_acpi::{Error as AcpiError, Sdt};

const MCFG_FIXED_LEN: usize = 44;
const ENTRY_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Acpi(AcpiError),
    BadSignature,
    BadLength,
    InvalidBusRange,
    Overflow,
}

impl From<AcpiError> for Error {
    fn from(value: AcpiError) -> Self {
        Self::Acpi(value)
    }
}

pub struct Mcfg<'a> {
    table: Sdt<'a>,
}

impl<'a> Mcfg<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let table = Sdt::parse(bytes)?;
        if table.header().signature != *b"MCFG" {
            return Err(Error::BadSignature);
        }
        if table.bytes().len() < MCFG_FIXED_LEN
            || !(table.bytes().len() - MCFG_FIXED_LEN).is_multiple_of(ENTRY_LEN)
        {
            return Err(Error::BadLength);
        }
        Ok(Self { table })
    }

    pub fn entries(&self) -> Entries<'_> {
        Entries {
            bytes: &self.table.bytes()[MCFG_FIXED_LEN..],
            offset: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McfgEntry {
    pub base_address: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl McfgEntry {
    pub const fn bus_count(self) -> u16 {
        self.end_bus as u16 - self.start_bus as u16 + 1
    }

    pub fn window_len(self) -> Result<u64, Error> {
        (self.bus_count() as u64)
            .checked_mul(1 << 20)
            .ok_or(Error::Overflow)
    }
}

pub struct Entries<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for Entries<'_> {
    type Item = Result<McfgEntry, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let entry = &self.bytes[self.offset..self.offset + ENTRY_LEN];
        self.offset += ENTRY_LEN;
        let parsed = McfgEntry {
            base_address: read_u64(entry, 0),
            segment: read_u16(entry, 8),
            start_bus: entry[10],
            end_bus: entry[11],
        };
        if parsed.start_bus > parsed.end_bus {
            return Some(Err(Error::InvalidBusRange));
        }
        if parsed
            .base_address
            .checked_add(parsed.window_len().unwrap_or(u64::MAX))
            .is_none()
        {
            return Some(Err(Error::Overflow));
        }
        Some(Ok(parsed))
    }
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(
        bytes[at..at + 8]
            .try_into()
            .expect("MCFG entry has fixed validated length"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(table: &mut [u8]) {
        table[9] = 0;
        let sum = table.iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
        table[9] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn parses_multiple_ecam_windows() {
        let mut bytes = [0u8; 76];
        bytes[..4].copy_from_slice(b"MCFG");
        bytes[4..8].copy_from_slice(&76u32.to_le_bytes());
        bytes[44..52].copy_from_slice(&0xe000_0000u64.to_le_bytes());
        bytes[54] = 0;
        bytes[55] = 0x7f;
        bytes[60..68].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
        bytes[68..70].copy_from_slice(&1u16.to_le_bytes());
        bytes[70] = 0x80;
        bytes[71] = 0xff;
        checksum(&mut bytes);
        let mcfg = Mcfg::parse(&bytes).unwrap();
        let mut entries = mcfg.entries();
        let first = entries.next().unwrap().unwrap();
        let second = entries.next().unwrap().unwrap();
        assert_eq!(first.base_address, 0xe000_0000);
        assert_eq!(first.bus_count(), 128);
        assert_eq!(second.segment, 1);
        assert_eq!(second.start_bus, 0x80);
    }

    #[test]
    fn rejects_reversed_bus_range() {
        let mut bytes = [0u8; 60];
        bytes[..4].copy_from_slice(b"MCFG");
        bytes[4..8].copy_from_slice(&60u32.to_le_bytes());
        bytes[54] = 5;
        bytes[55] = 4;
        checksum(&mut bytes);
        let mcfg = Mcfg::parse(&bytes).unwrap();
        assert_eq!(mcfg.entries().next().unwrap(), Err(Error::InvalidBusRange));
    }
}
