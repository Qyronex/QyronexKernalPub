// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_acpi::{Error as AcpiError, Sdt};

const SRAT_FIXED_LEN: usize = 48;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Acpi(AcpiError),
    BadSignature,
    BadLength,
    MalformedEntry,
    Overflow,
}
impl From<AcpiError> for Error {
    fn from(value: AcpiError) -> Self {
        Self::Acpi(value)
    }
}

pub struct Srat<'a> {
    table: Sdt<'a>,
}

impl<'a> Srat<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let table = Sdt::parse(bytes)?;
        if table.header().signature != *b"SRAT" {
            return Err(Error::BadSignature);
        }
        if table.bytes().len() < SRAT_FIXED_LEN {
            return Err(Error::BadLength);
        }
        Ok(Self { table })
    }

    pub fn entries(&self) -> Entries<'_> {
        Entries {
            bytes: &self.table.bytes()[SRAT_FIXED_LEN..],
            offset: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Entry {
    LocalApicAffinity {
        proximity_domain: u32,
        apic_id: u8,
        enabled: bool,
        clock_domain: u32,
    },
    MemoryAffinity {
        proximity_domain: u32,
        base: u64,
        len: u64,
        enabled: bool,
        hot_pluggable: bool,
        non_volatile: bool,
    },
    LocalX2ApicAffinity {
        proximity_domain: u32,
        x2apic_id: u32,
        enabled: bool,
        clock_domain: u32,
    },
    Unknown {
        entry_type: u8,
        length: u8,
    },
}

pub struct Entries<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for Entries<'_> {
    type Item = Result<Entry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        if self.offset > self.bytes.len() || self.bytes.len() - self.offset < 2 {
            self.offset = self.bytes.len();
            return Some(Err(Error::MalformedEntry));
        }
        let entry_type = self.bytes[self.offset];
        let length = self.bytes[self.offset + 1] as usize;
        if length < 2
            || self
                .offset
                .checked_add(length)
                .is_none_or(|end| end > self.bytes.len())
        {
            self.offset = self.bytes.len();
            return Some(Err(Error::MalformedEntry));
        }
        let entry = &self.bytes[self.offset..self.offset + length];
        self.offset += length;
        Some(parse_entry(entry_type, entry))
    }
}

fn parse_entry(entry_type: u8, bytes: &[u8]) -> Result<Entry, Error> {
    match entry_type {
        0 => {
            require_len(bytes, 16)?;
            let domain = bytes[2] as u32
                | ((bytes[9] as u32) << 8)
                | ((bytes[10] as u32) << 16)
                | ((bytes[11] as u32) << 24);
            let flags = read_u32(bytes, 4)?;
            Ok(Entry::LocalApicAffinity {
                proximity_domain: domain,
                apic_id: bytes[3],
                enabled: flags & 1 != 0,
                clock_domain: read_u32(bytes, 12)?,
            })
        }
        1 => {
            require_len(bytes, 40)?;
            let base = read_u32(bytes, 8)? as u64 | ((read_u32(bytes, 12)? as u64) << 32);
            let len = read_u32(bytes, 16)? as u64 | ((read_u32(bytes, 20)? as u64) << 32);
            base.checked_add(len).ok_or(Error::Overflow)?;
            let flags = read_u32(bytes, 28)?;
            Ok(Entry::MemoryAffinity {
                proximity_domain: read_u32(bytes, 2)?,
                base,
                len,
                enabled: flags & 1 != 0,
                hot_pluggable: flags & 2 != 0,
                non_volatile: flags & 4 != 0,
            })
        }
        2 => {
            require_len(bytes, 24)?;
            let flags = read_u32(bytes, 12)?;
            Ok(Entry::LocalX2ApicAffinity {
                proximity_domain: read_u32(bytes, 4)?,
                x2apic_id: read_u32(bytes, 8)?,
                enabled: flags & 1 != 0,
                clock_domain: read_u32(bytes, 16)?,
            })
        }
        _ => Ok(Entry::Unknown {
            entry_type,
            length: bytes.len() as u8,
        }),
    }
}

fn require_len(bytes: &[u8], min: usize) -> Result<(), Error> {
    if bytes.len() < min {
        Err(Error::MalformedEntry)
    } else {
        Ok(())
    }
}
fn read_u32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(Error::MalformedEntry)?
        .try_into()
        .map_err(|_| Error::MalformedEntry)?;
    Ok(u32::from_le_bytes(raw))
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
    fn parses_cpu_and_memory_affinity() {
        let mut bytes = [0u8; 104];
        bytes[..4].copy_from_slice(b"SRAT");
        bytes[4..8].copy_from_slice(&104u32.to_le_bytes());
        bytes[48] = 0;
        bytes[49] = 16;
        bytes[50] = 2;
        bytes[51] = 7;
        bytes[52..56].copy_from_slice(&1u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&3u32.to_le_bytes());
        bytes[64] = 1;
        bytes[65] = 40;
        bytes[66..70].copy_from_slice(&2u32.to_le_bytes());
        bytes[72..76].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        bytes[80..84].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&1u32.to_le_bytes());
        checksum(&mut bytes);
        let srat = Srat::parse(&bytes).unwrap();
        let mut entries = srat.entries();
        assert_eq!(
            entries.next().unwrap().unwrap(),
            Entry::LocalApicAffinity {
                proximity_domain: 2,
                apic_id: 7,
                enabled: true,
                clock_domain: 3
            }
        );
        assert_eq!(
            entries.next().unwrap().unwrap(),
            Entry::MemoryAffinity {
                proximity_domain: 2,
                base: 0x8000_0000,
                len: 0x4000_0000,
                enabled: true,
                hot_pluggable: false,
                non_volatile: false
            }
        );
    }

    #[test]
    fn zero_length_entry_is_rejected_without_looping() {
        let mut bytes = [0u8; 50];
        bytes[..4].copy_from_slice(b"SRAT");
        bytes[4..8].copy_from_slice(&50u32.to_le_bytes());
        bytes[48] = 99;
        bytes[49] = 0;
        checksum(&mut bytes);
        let srat = Srat::parse(&bytes).unwrap();
        assert_eq!(srat.entries().next().unwrap(), Err(Error::MalformedEntry));
    }
}
