// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_acpi::{MadtEntry, Rsdp, SdtHeader};
use kernal_physical_io::PhysicalReader;

pub const SDT_HEADER_LEN: usize = 36;
pub const MADT_FIXED_LEN: usize = 44;
pub const MAX_SDT_LENGTH: usize = 16 * 1024 * 1024;
pub const MAX_ROOT_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Io,
    BadSignature,
    BadChecksum,
    BadLength,
    AddressOverflow,
    TooManyEntries,
    MalformedEntry,
    DuplicateTable,
    TableNotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalSdt {
    pub address: u64,
    pub header: SdtHeader,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTable {
    pub address: u64,
    pub entry_size: u8,
    pub entry_count: usize,
}

impl RootTable {
    pub fn entry<R: PhysicalReader>(&self, reader: &R, index: usize) -> Result<u64, Error> {
        if index >= self.entry_count {
            return Err(Error::BadLength);
        }
        let offset = SDT_HEADER_LEN
            .checked_add(
                index
                    .checked_mul(self.entry_size as usize)
                    .ok_or(Error::AddressOverflow)?,
            )
            .ok_or(Error::AddressOverflow)?;
        let address = self
            .address
            .checked_add(offset as u64)
            .ok_or(Error::AddressOverflow)?;
        match self.entry_size {
            8 => reader.read_u64(address).map_err(|_| Error::Io),
            4 => reader
                .read_u32(address)
                .map(|value| value as u64)
                .map_err(|_| Error::Io),
            _ => Err(Error::BadLength),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalMadt {
    pub address: u64,
    pub length: u32,
    pub local_apic_address: u32,
    pub flags: u32,
}

impl PhysicalMadt {
    pub fn entries(self) -> MadtCursor {
        MadtCursor {
            next: self.address + MADT_FIXED_LEN as u64,
            end: self.address + self.length as u64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MadtCursor {
    next: u64,
    end: u64,
}

impl MadtCursor {
    pub fn next<R: PhysicalReader>(&mut self, reader: &R) -> Result<Option<MadtEntry>, Error> {
        if self.next == self.end {
            return Ok(None);
        }
        if self.next > self.end || self.end - self.next < 2 {
            return Err(Error::MalformedEntry);
        }
        let entry_type = reader.read_u8(self.next).map_err(|_| Error::Io)?;
        let length = reader
            .read_u8(self.next.checked_add(1).ok_or(Error::AddressOverflow)?)
            .map_err(|_| Error::Io)?;
        if length < 2 {
            return Err(Error::MalformedEntry);
        }
        let entry_end = self
            .next
            .checked_add(length as u64)
            .ok_or(Error::AddressOverflow)?;
        if entry_end > self.end {
            return Err(Error::MalformedEntry);
        }
        let base = self.next;
        self.next = entry_end;

        let result = match entry_type {
            0 => {
                require_len(length, 8)?;
                MadtEntry::LocalApic {
                    processor_uid: read_u8(reader, base, 2)?,
                    apic_id: read_u8(reader, base, 3)?,
                    flags: read_u32(reader, base, 4)?,
                }
            }
            1 => {
                require_len(length, 12)?;
                MadtEntry::IoApic {
                    io_apic_id: read_u8(reader, base, 2)?,
                    address: read_u32(reader, base, 4)?,
                    gsi_base: read_u32(reader, base, 8)?,
                }
            }
            2 => {
                require_len(length, 10)?;
                MadtEntry::InterruptSourceOverride {
                    bus: read_u8(reader, base, 2)?,
                    source: read_u8(reader, base, 3)?,
                    gsi: read_u32(reader, base, 4)?,
                    flags: read_u16(reader, base, 8)?,
                }
            }
            5 => {
                require_len(length, 12)?;
                MadtEntry::LocalApicAddressOverride {
                    address: read_u64(reader, base, 4)?,
                }
            }
            9 => {
                require_len(length, 16)?;
                MadtEntry::LocalX2Apic {
                    x2apic_id: read_u32(reader, base, 4)?,
                    flags: read_u32(reader, base, 8)?,
                    processor_uid: read_u32(reader, base, 12)?,
                }
            }
            _ => MadtEntry::Unknown { entry_type, length },
        };
        Ok(Some(result))
    }
}

pub fn read_rsdp<R: PhysicalReader>(reader: &R, address: u64) -> Result<Rsdp, Error> {
    let mut bytes = [0u8; 36];
    reader
        .read_exact(address, &mut bytes)
        .map_err(|_| Error::Io)?;
    Rsdp::parse(&bytes).map_err(|error| match error {
        kernal_acpi::Error::BadSignature => Error::BadSignature,
        kernal_acpi::Error::BadChecksum => Error::BadChecksum,
        kernal_acpi::Error::BadLength | kernal_acpi::Error::Truncated => Error::BadLength,
        kernal_acpi::Error::MalformedEntry => Error::MalformedEntry,
    })
}

pub fn read_sdt<R: PhysicalReader>(reader: &R, address: u64) -> Result<PhysicalSdt, Error> {
    let mut bytes = [0u8; SDT_HEADER_LEN];
    reader
        .read_exact(address, &mut bytes)
        .map_err(|_| Error::Io)?;
    let length = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::BadLength)?) as usize;
    if !(SDT_HEADER_LEN..=MAX_SDT_LENGTH).contains(&length) {
        return Err(Error::BadLength);
    }
    address
        .checked_add(length as u64)
        .ok_or(Error::AddressOverflow)?;
    if reader.checksum8(address, length).map_err(|_| Error::Io)? != 0 {
        return Err(Error::BadChecksum);
    }
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&bytes[0..4]);
    Ok(PhysicalSdt {
        address,
        header: SdtHeader {
            signature,
            length: length as u32,
            revision: bytes[8],
        },
    })
}

pub fn read_root_table<R: PhysicalReader>(reader: &R, rsdp: Rsdp) -> Result<RootTable, Error> {
    let (address, expected, entry_size) = match rsdp.xsdt_address {
        Some(address) if address != 0 => (address, *b"XSDT", 8u8),
        _ if rsdp.rsdt_address != 0 => (rsdp.rsdt_address as u64, *b"RSDT", 4u8),
        _ => return Err(Error::TableNotFound),
    };
    let table = read_sdt(reader, address)?;
    if table.header.signature != expected {
        return Err(Error::BadSignature);
    }
    let payload = table.header.length as usize - SDT_HEADER_LEN;
    if !payload.is_multiple_of(entry_size as usize) {
        return Err(Error::BadLength);
    }
    let entry_count = payload / entry_size as usize;
    if entry_count > MAX_ROOT_ENTRIES {
        return Err(Error::TooManyEntries);
    }
    Ok(RootTable {
        address,
        entry_size,
        entry_count,
    })
}

pub fn find_unique_table<R: PhysicalReader>(
    reader: &R,
    root: RootTable,
    signature: [u8; 4],
) -> Result<PhysicalSdt, Error> {
    let mut found = None;
    for index in 0..root.entry_count {
        let address = root.entry(reader, index)?;
        if address == 0 {
            continue;
        }
        let table = read_sdt(reader, address)?;
        if table.header.signature == signature {
            if found.is_some() {
                return Err(Error::DuplicateTable);
            }
            found = Some(table);
        }
    }
    found.ok_or(Error::TableNotFound)
}

pub fn read_madt<R: PhysicalReader>(reader: &R, address: u64) -> Result<PhysicalMadt, Error> {
    let table = read_sdt(reader, address)?;
    if table.header.signature != *b"APIC" {
        return Err(Error::BadSignature);
    }
    if (table.header.length as usize) < MADT_FIXED_LEN {
        return Err(Error::BadLength);
    }
    Ok(PhysicalMadt {
        address,
        length: table.header.length,
        local_apic_address: reader.read_u32(address + 36).map_err(|_| Error::Io)?,
        flags: reader.read_u32(address + 40).map_err(|_| Error::Io)?,
    })
}

fn require_len(actual: u8, required: u8) -> Result<(), Error> {
    if actual < required {
        Err(Error::MalformedEntry)
    } else {
        Ok(())
    }
}
fn read_u8<R: PhysicalReader>(reader: &R, base: u64, offset: u64) -> Result<u8, Error> {
    reader
        .read_u8(base.checked_add(offset).ok_or(Error::AddressOverflow)?)
        .map_err(|_| Error::Io)
}
fn read_u16<R: PhysicalReader>(reader: &R, base: u64, offset: u64) -> Result<u16, Error> {
    reader
        .read_u16(base.checked_add(offset).ok_or(Error::AddressOverflow)?)
        .map_err(|_| Error::Io)
}
fn read_u32<R: PhysicalReader>(reader: &R, base: u64, offset: u64) -> Result<u32, Error> {
    reader
        .read_u32(base.checked_add(offset).ok_or(Error::AddressOverflow)?)
        .map_err(|_| Error::Io)
}
fn read_u64<R: PhysicalReader>(reader: &R, base: u64, offset: u64) -> Result<u64, Error> {
    reader
        .read_u64(base.checked_add(offset).ok_or(Error::AddressOverflow)?)
        .map_err(|_| Error::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_physical_io::{Error as IoError, PhysicalReader};

    const BASE: u64 = 0x1000;

    struct SliceReader<'a> {
        bytes: &'a [u8],
    }
    impl PhysicalReader for SliceReader<'_> {
        fn read_exact(&self, physical_address: u64, destination: &mut [u8]) -> Result<(), IoError> {
            let offset = physical_address.checked_sub(BASE).ok_or(IoError::Backend)? as usize;
            let end = offset
                .checked_add(destination.len())
                .ok_or(IoError::AddressOverflow)?;
            destination.copy_from_slice(self.bytes.get(offset..end).ok_or(IoError::Backend)?);
            Ok(())
        }
    }

    fn fix_checksum(table: &mut [u8]) {
        table[9] = 0;
        let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        table[9] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn streams_xsdt_and_madt_without_contiguous_mapping() {
        let mut image = [0u8; 256];
        // XSDT at BASE, one entry pointing to MADT at BASE+0x80.
        image[0..4].copy_from_slice(b"XSDT");
        image[4..8].copy_from_slice(&44u32.to_le_bytes());
        image[36..44].copy_from_slice(&(BASE + 0x80).to_le_bytes());
        fix_checksum(&mut image[0..44]);

        let madt = &mut image[0x80..0x80 + 52];
        madt[0..4].copy_from_slice(b"APIC");
        madt[4..8].copy_from_slice(&52u32.to_le_bytes());
        madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        madt[44] = 0;
        madt[45] = 8;
        madt[46] = 1;
        madt[47] = 2;
        madt[48..52].copy_from_slice(&1u32.to_le_bytes());
        fix_checksum(madt);

        let reader = SliceReader { bytes: &image };
        let root = RootTable {
            address: BASE,
            entry_size: 8,
            entry_count: 1,
        };
        let found = find_unique_table(&reader, root, *b"APIC").unwrap();
        let madt = read_madt(&reader, found.address).unwrap();
        assert_eq!(madt.local_apic_address, 0xfee0_0000);
        let mut cursor = madt.entries();
        assert_eq!(
            cursor.next(&reader).unwrap(),
            Some(MadtEntry::LocalApic {
                processor_uid: 1,
                apic_id: 2,
                flags: 1
            })
        );
        assert_eq!(cursor.next(&reader).unwrap(), None);
    }

    #[test]
    fn malformed_zero_length_madt_entry_is_rejected() {
        let mut image = [0u8; 64];
        image[0..4].copy_from_slice(b"APIC");
        image[4..8].copy_from_slice(&46u32.to_le_bytes());
        image[44] = 99;
        image[45] = 0;
        fix_checksum(&mut image[..46]);
        let reader = SliceReader { bytes: &image };
        let madt = read_madt(&reader, BASE).unwrap();
        assert_eq!(madt.entries().next(&reader), Err(Error::MalformedEntry));
    }
}
