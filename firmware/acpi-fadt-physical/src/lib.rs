// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]

use kernal_acpi_fadt::{PM_TIMER_PREFIX_LEN, PmTimer, parse_validated_prefix};
use kernal_acpi_physical::read_sdt;
use kernal_physical_io::PhysicalReader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Acpi(kernal_acpi_physical::Error),
    Io,
    Fadt(kernal_acpi_fadt::Error),
}

pub fn read_pm_timer<R: PhysicalReader>(reader: &R, address: u64) -> Result<PmTimer, Error> {
    let table = read_sdt(reader, address).map_err(Error::Acpi)?;
    if table.header.signature != *b"FACP" {
        return Err(Error::Acpi(kernal_acpi_physical::Error::BadSignature));
    }
    let declared = table.header.length as usize;
    let prefix_len = core::cmp::min(declared, PM_TIMER_PREFIX_LEN);
    let mut prefix = [0u8; PM_TIMER_PREFIX_LEN];
    reader
        .read_exact(address, &mut prefix[..prefix_len])
        .map_err(|_| Error::Io)?;
    parse_validated_prefix(&prefix[..prefix_len], declared).map_err(Error::Fadt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_acpi_fadt::{AddressSpace, PM_TIMER_HZ};
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
    fn streams_large_fadt_and_returns_pm_timer() {
        let mut bytes = [0u8; 300];
        let table_len = bytes.len() as u32;
        bytes[..4].copy_from_slice(b"FACP");
        bytes[4..8].copy_from_slice(&table_len.to_le_bytes());
        bytes[76..80].copy_from_slice(&0x408u32.to_le_bytes());
        bytes[91] = 4;
        fix_checksum(&mut bytes);

        let timer = read_pm_timer(&SliceReader { bytes: &bytes }, BASE).unwrap();
        assert_eq!(timer.address_space, AddressSpace::SystemIo);
        assert_eq!(timer.address, 0x408);
        assert_eq!(timer.width_bits, 24);
        assert_eq!(PM_TIMER_HZ, 3_579_545);
    }

    #[test]
    fn full_table_checksum_is_still_required() {
        let mut bytes = [0u8; 116];
        let table_len = bytes.len() as u32;
        bytes[..4].copy_from_slice(b"FACP");
        bytes[4..8].copy_from_slice(&table_len.to_le_bytes());
        bytes[76..80].copy_from_slice(&0x408u32.to_le_bytes());
        bytes[91] = 4;
        fix_checksum(&mut bytes);
        bytes[100] ^= 1;

        assert!(matches!(
            read_pm_timer(&SliceReader { bytes: &bytes }, BASE),
            Err(Error::Acpi(kernal_acpi_physical::Error::BadChecksum))
        ));
    }
}
