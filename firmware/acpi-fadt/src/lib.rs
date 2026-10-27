// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]

pub const PM_TIMER_HZ: u64 = 3_579_545;
pub const PM_TIMER_PREFIX_LEN: usize = 220;
const FADT_MIN_PM_TIMER_LEN: usize = 92;
const FADT_MIN_FLAGS_LEN: usize = 116;
const FADT_MIN_X_PM_TIMER_LEN: usize = 220;
const PM_TMR_BLK_OFFSET: usize = 76;
const PM_TMR_LEN_OFFSET: usize = 91;
const FLAGS_OFFSET: usize = 112;
const X_PM_TMR_BLK_OFFSET: usize = 208;
const TMR_VAL_EXT: u32 = 1 << 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSpace {
    SystemMemory,
    SystemIo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmTimer {
    pub address_space: AddressSpace,
    pub address: u64,
    pub width_bits: u8,
}

impl PmTimer {
    pub const fn mask(self) -> u32 {
        if self.width_bits == 32 {
            u32::MAX
        } else {
            0x00ff_ffff
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadSignature,
    BadLength,
    MissingTimer,
    UnsupportedAddressSpace,
    InvalidAddress,
    InvalidRegisterWidth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GenericAddress {
    address_space: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64,
}

/// Parses a complete FADT byte slice.
pub fn parse_pm_timer(bytes: &[u8]) -> Result<PmTimer, Error> {
    if bytes.len() < FADT_MIN_PM_TIMER_LEN {
        return Err(Error::Truncated);
    }
    if bytes.get(0..4) != Some(b"FACP") {
        return Err(Error::BadSignature);
    }
    let declared = read_u32(bytes, 4)? as usize;
    if declared < FADT_MIN_PM_TIMER_LEN || declared > bytes.len() {
        return Err(Error::BadLength);
    }
    parse_validated_prefix(
        &bytes[..core::cmp::min(declared, PM_TIMER_PREFIX_LEN)],
        declared,
    )
}

/// Parses only the FADT prefix needed for PM-timer discovery after a caller has independently
/// validated the complete ACPI SDT checksum and length.
///
/// `declared_length` must be the checksum-validated FADT header length. This API deliberately
/// requires every field that exists according to that declared length, up to the 220-byte prefix.
pub fn parse_validated_prefix(bytes: &[u8], declared_length: usize) -> Result<PmTimer, Error> {
    if declared_length < FADT_MIN_PM_TIMER_LEN {
        return Err(Error::BadLength);
    }
    let required = core::cmp::min(declared_length, PM_TIMER_PREFIX_LEN);
    if bytes.len() < required {
        return Err(Error::Truncated);
    }
    if bytes.get(0..4) != Some(b"FACP") {
        return Err(Error::BadSignature);
    }
    let header_length = read_u32(bytes, 4)? as usize;
    if header_length != declared_length {
        return Err(Error::BadLength);
    }

    let width_bits = if declared_length >= FADT_MIN_FLAGS_LEN
        && read_u32(bytes, FLAGS_OFFSET)? & TMR_VAL_EXT != 0
    {
        32
    } else {
        24
    };
    let legacy_length = bytes[PM_TMR_LEN_OFFSET];

    if declared_length >= FADT_MIN_X_PM_TIMER_LEN {
        let gas = parse_gas(bytes, X_PM_TMR_BLK_OFFSET)?;
        if gas.address != 0 {
            return timer_from_gas(gas, width_bits);
        }
    }

    let legacy = read_u32(bytes, PM_TMR_BLK_OFFSET)? as u64;
    if legacy == 0 || legacy_length < 4 {
        return Err(Error::MissingTimer);
    }
    Ok(PmTimer {
        address_space: AddressSpace::SystemIo,
        address: legacy,
        width_bits,
    })
}

fn timer_from_gas(gas: GenericAddress, width_bits: u8) -> Result<PmTimer, Error> {
    if gas.address == 0 {
        return Err(Error::InvalidAddress);
    }
    if gas.bit_offset != 0 {
        return Err(Error::InvalidRegisterWidth);
    }
    if gas.bit_width != 0 && gas.bit_width < width_bits {
        return Err(Error::InvalidRegisterWidth);
    }
    let address_space = match gas.address_space {
        0 => AddressSpace::SystemMemory,
        1 => AddressSpace::SystemIo,
        _ => return Err(Error::UnsupportedAddressSpace),
    };
    if !matches!(gas.access_size, 0 | 3) {
        return Err(Error::InvalidRegisterWidth);
    }
    Ok(PmTimer {
        address_space,
        address: gas.address,
        width_bits,
    })
}

fn parse_gas(bytes: &[u8], offset: usize) -> Result<GenericAddress, Error> {
    let gas = bytes.get(offset..offset + 12).ok_or(Error::Truncated)?;
    Ok(GenericAddress {
        address_space: gas[0],
        bit_width: gas[1],
        bit_offset: gas[2],
        access_size: gas[3],
        address: u64::from_le_bytes(gas[4..12].try_into().map_err(|_| Error::Truncated)?),
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fadt(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        bytes[..4].copy_from_slice(b"FACP");
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes
    }

    #[test]
    fn legacy_pm_timer_defaults_to_24_bit() {
        let mut bytes = fadt(116);
        bytes[PM_TMR_BLK_OFFSET..PM_TMR_BLK_OFFSET + 4].copy_from_slice(&0x408u32.to_le_bytes());
        bytes[PM_TMR_LEN_OFFSET] = 4;
        assert_eq!(
            parse_pm_timer(&bytes),
            Ok(PmTimer {
                address_space: AddressSpace::SystemIo,
                address: 0x408,
                width_bits: 24
            })
        );
    }

    #[test]
    fn timer_value_extension_selects_32_bit_counter() {
        let mut bytes = fadt(116);
        bytes[PM_TMR_BLK_OFFSET..PM_TMR_BLK_OFFSET + 4].copy_from_slice(&0x408u32.to_le_bytes());
        bytes[PM_TMR_LEN_OFFSET] = 4;
        bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&TMR_VAL_EXT.to_le_bytes());
        let timer = parse_pm_timer(&bytes).unwrap();
        assert_eq!(timer.width_bits, 32);
        assert_eq!(timer.mask(), u32::MAX);
    }

    #[test]
    fn extended_gas_is_preferred_over_legacy_address() {
        let mut bytes = fadt(220);
        bytes[PM_TMR_BLK_OFFSET..PM_TMR_BLK_OFFSET + 4].copy_from_slice(&0x408u32.to_le_bytes());
        bytes[PM_TMR_LEN_OFFSET] = 4;
        bytes[X_PM_TMR_BLK_OFFSET] = 1;
        bytes[X_PM_TMR_BLK_OFFSET + 1] = 32;
        bytes[X_PM_TMR_BLK_OFFSET + 3] = 3;
        bytes[X_PM_TMR_BLK_OFFSET + 4..X_PM_TMR_BLK_OFFSET + 12]
            .copy_from_slice(&0x1234u64.to_le_bytes());
        assert_eq!(parse_pm_timer(&bytes).unwrap().address, 0x1234);
    }

    #[test]
    fn unsupported_gas_does_not_silently_fall_back() {
        let mut bytes = fadt(220);
        bytes[PM_TMR_BLK_OFFSET..PM_TMR_BLK_OFFSET + 4].copy_from_slice(&0x408u32.to_le_bytes());
        bytes[PM_TMR_LEN_OFFSET] = 4;
        bytes[X_PM_TMR_BLK_OFFSET] = 2;
        bytes[X_PM_TMR_BLK_OFFSET + 1] = 32;
        bytes[X_PM_TMR_BLK_OFFSET + 3] = 3;
        bytes[X_PM_TMR_BLK_OFFSET + 4..X_PM_TMR_BLK_OFFSET + 12]
            .copy_from_slice(&0x1234u64.to_le_bytes());
        assert_eq!(parse_pm_timer(&bytes), Err(Error::UnsupportedAddressSpace));
    }

    #[test]
    fn validated_prefix_can_parse_large_fadt_without_copying_entire_table() {
        let declared = 300usize;
        let mut prefix = vec![0u8; PM_TIMER_PREFIX_LEN];
        prefix[..4].copy_from_slice(b"FACP");
        prefix[4..8].copy_from_slice(&(declared as u32).to_le_bytes());
        prefix[PM_TMR_BLK_OFFSET..PM_TMR_BLK_OFFSET + 4].copy_from_slice(&0x408u32.to_le_bytes());
        prefix[PM_TMR_LEN_OFFSET] = 4;
        assert_eq!(
            parse_validated_prefix(&prefix, declared).unwrap().address,
            0x408
        );
    }

    #[test]
    fn missing_required_prefix_bytes_are_rejected() {
        let mut prefix = vec![0u8; 116];
        prefix[..4].copy_from_slice(b"FACP");
        prefix[4..8].copy_from_slice(&220u32.to_le_bytes());
        assert_eq!(parse_validated_prefix(&prefix, 220), Err(Error::Truncated));
    }

    #[test]
    fn missing_timer_is_rejected() {
        let bytes = fadt(116);
        assert_eq!(parse_pm_timer(&bytes), Err(Error::MissingTimer));
    }
}
