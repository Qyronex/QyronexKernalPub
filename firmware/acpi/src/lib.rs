// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const SDT_HEADER_LEN: usize = 36;
const MADT_FIXED_LEN: usize = 44;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadSignature,
    BadChecksum,
    BadLength,
    MalformedEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rsdp {
    pub revision: u8,
    pub rsdt_address: u32,
    pub xsdt_address: Option<u64>,
}

impl Rsdp {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 20 {
            return Err(Error::Truncated);
        }
        if bytes.get(0..8) != Some(RSDP_SIGNATURE) {
            return Err(Error::BadSignature);
        }
        if !checksum_ok(&bytes[..20]) {
            return Err(Error::BadChecksum);
        }
        let revision = bytes[15];
        let rsdt_address = read_u32(bytes, 16)?;
        if revision < 2 {
            return Ok(Self {
                revision,
                rsdt_address,
                xsdt_address: None,
            });
        }
        if bytes.len() < 36 {
            return Err(Error::Truncated);
        }
        let length = read_u32(bytes, 20)? as usize;
        if length < 36 || length > bytes.len() {
            return Err(Error::BadLength);
        }
        if !checksum_ok(&bytes[..length]) {
            return Err(Error::BadChecksum);
        }
        Ok(Self {
            revision,
            rsdt_address,
            xsdt_address: Some(read_u64(bytes, 24)?),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
}

pub struct Sdt<'a> {
    bytes: &'a [u8],
    header: SdtHeader,
}

impl<'a> Sdt<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < SDT_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let length = read_u32(bytes, 4)? as usize;
        if length < SDT_HEADER_LEN || length > bytes.len() {
            return Err(Error::BadLength);
        }
        if !checksum_ok(&bytes[..length]) {
            return Err(Error::BadChecksum);
        }
        let mut signature = [0u8; 4];
        signature.copy_from_slice(&bytes[..4]);
        Ok(Self {
            bytes: &bytes[..length],
            header: SdtHeader {
                signature,
                length: length as u32,
                revision: bytes[8],
            },
        })
    }

    pub const fn header(&self) -> SdtHeader {
        self.header
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

pub struct Madt<'a> {
    table: Sdt<'a>,
    local_apic_address: u32,
    flags: u32,
}

impl<'a> Madt<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let table = Sdt::parse(bytes)?;
        if table.header().signature != *b"APIC" {
            return Err(Error::BadSignature);
        }
        if table.bytes().len() < MADT_FIXED_LEN {
            return Err(Error::BadLength);
        }
        Ok(Self {
            local_apic_address: read_u32(table.bytes(), 36)?,
            flags: read_u32(table.bytes(), 40)?,
            table,
        })
    }

    pub const fn local_apic_address(&self) -> u32 {
        self.local_apic_address
    }
    pub const fn flags(&self) -> u32 {
        self.flags
    }
    pub fn entries(&self) -> MadtEntries<'_> {
        MadtEntries {
            bytes: &self.table.bytes()[MADT_FIXED_LEN..],
            offset: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MadtEntry {
    LocalApic {
        processor_uid: u8,
        apic_id: u8,
        flags: u32,
    },
    IoApic {
        io_apic_id: u8,
        address: u32,
        gsi_base: u32,
    },
    InterruptSourceOverride {
        bus: u8,
        source: u8,
        gsi: u32,
        flags: u16,
    },
    LocalApicAddressOverride {
        address: u64,
    },
    LocalX2Apic {
        x2apic_id: u32,
        flags: u32,
        processor_uid: u32,
    },
    Unknown {
        entry_type: u8,
        length: u8,
    },
}

impl MadtEntry {
    pub const fn processor_enabled(self) -> Option<bool> {
        match self {
            Self::LocalApic { flags, .. } | Self::LocalX2Apic { flags, .. } => {
                Some(flags & 1 != 0 || flags & 2 != 0)
            }
            _ => None,
        }
    }
}

pub struct MadtEntries<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for MadtEntries<'_> {
    type Item = Result<MadtEntry, Error>;

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
        Some(parse_madt_entry(entry_type, entry))
    }
}

fn parse_madt_entry(entry_type: u8, entry: &[u8]) -> Result<MadtEntry, Error> {
    match entry_type {
        0 => {
            require_len(entry, 8)?;
            Ok(MadtEntry::LocalApic {
                processor_uid: entry[2],
                apic_id: entry[3],
                flags: read_u32(entry, 4)?,
            })
        }
        1 => {
            require_len(entry, 12)?;
            Ok(MadtEntry::IoApic {
                io_apic_id: entry[2],
                address: read_u32(entry, 4)?,
                gsi_base: read_u32(entry, 8)?,
            })
        }
        2 => {
            require_len(entry, 10)?;
            Ok(MadtEntry::InterruptSourceOverride {
                bus: entry[2],
                source: entry[3],
                gsi: read_u32(entry, 4)?,
                flags: read_u16(entry, 8)?,
            })
        }
        5 => {
            require_len(entry, 12)?;
            Ok(MadtEntry::LocalApicAddressOverride {
                address: read_u64(entry, 4)?,
            })
        }
        9 => {
            require_len(entry, 16)?;
            Ok(MadtEntry::LocalX2Apic {
                x2apic_id: read_u32(entry, 4)?,
                flags: read_u32(entry, 8)?,
                processor_uid: read_u32(entry, 12)?,
            })
        }
        _ => Ok(MadtEntry::Unknown {
            entry_type,
            length: entry.len() as u8,
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

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
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
fn read_u64(bytes: &[u8], at: usize) -> Result<u64, Error> {
    let raw: [u8; 8] = bytes
        .get(at..at + 8)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix_checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        let sum = bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b));
        bytes[checksum_offset] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn parses_acpi2_rsdp_and_checks_both_checksums() {
        let mut rsdp = [0u8; 36];
        rsdp[..8].copy_from_slice(RSDP_SIGNATURE);
        rsdp[15] = 2;
        rsdp[16..20].copy_from_slice(&0x1234u32.to_le_bytes());
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&0x1234_5678_9abcu64.to_le_bytes());
        fix_checksum(&mut rsdp[..20], 8);
        fix_checksum(&mut rsdp, 32);
        let parsed = Rsdp::parse(&rsdp).unwrap();
        assert_eq!(parsed.xsdt_address, Some(0x1234_5678_9abc));
        rsdp[10] ^= 1;
        assert_eq!(Rsdp::parse(&rsdp), Err(Error::BadChecksum));
    }

    #[test]
    fn parses_madt_processors_and_rejects_truncated_entries() {
        let mut bytes = [0u8; 68];
        bytes[..4].copy_from_slice(b"APIC");
        bytes[4..8].copy_from_slice(&(68u32).to_le_bytes());
        bytes[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        bytes[44] = 0;
        bytes[45] = 8;
        bytes[46] = 3;
        bytes[47] = 7;
        bytes[48..52].copy_from_slice(&1u32.to_le_bytes());
        bytes[52] = 9;
        bytes[53] = 16;
        bytes[56..60].copy_from_slice(&42u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&1u32.to_le_bytes());
        bytes[64..68].copy_from_slice(&9u32.to_le_bytes());
        fix_checksum(&mut bytes, 9);
        let madt = Madt::parse(&bytes).unwrap();
        let entries: [MadtEntry; 2] = [
            madt.entries().next().unwrap().unwrap(),
            madt.entries().nth(1).unwrap().unwrap(),
        ];
        assert_eq!(
            entries[0],
            MadtEntry::LocalApic {
                processor_uid: 3,
                apic_id: 7,
                flags: 1
            }
        );
        assert!(entries[1].processor_enabled().unwrap());
    }

    #[test]
    fn malformed_zero_length_madt_entry_does_not_loop() {
        let mut bytes = [0u8; 46];
        bytes[..4].copy_from_slice(b"APIC");
        bytes[4..8].copy_from_slice(&(46u32).to_le_bytes());
        bytes[44] = 99;
        bytes[45] = 0;
        fix_checksum(&mut bytes, 9);
        let madt = Madt::parse(&bytes).unwrap();
        assert_eq!(madt.entries().next().unwrap(), Err(Error::MalformedEntry));
    }
}
