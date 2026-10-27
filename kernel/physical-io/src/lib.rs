// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AddressOverflow,
    Backend,
}

pub trait PhysicalReader {
    fn read_exact(&self, physical_address: u64, destination: &mut [u8]) -> Result<(), Error>;

    fn read_u8(&self, physical_address: u64) -> Result<u8, Error> {
        let mut bytes = [0u8; 1];
        self.read_exact(physical_address, &mut bytes)?;
        Ok(bytes[0])
    }

    fn read_u16(&self, physical_address: u64) -> Result<u16, Error> {
        let mut bytes = [0u8; 2];
        self.read_exact(physical_address, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&self, physical_address: u64) -> Result<u32, Error> {
        let mut bytes = [0u8; 4];
        self.read_exact(physical_address, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&self, physical_address: u64) -> Result<u64, Error> {
        let mut bytes = [0u8; 8];
        self.read_exact(physical_address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn checksum8(&self, physical_address: u64, len: usize) -> Result<u8, Error> {
        const CHUNK: usize = 64;
        let mut scratch = [0u8; CHUNK];
        let mut offset = 0usize;
        let mut sum = 0u8;
        while offset < len {
            let count = core::cmp::min(CHUNK, len - offset);
            let address = physical_address
                .checked_add(offset as u64)
                .ok_or(Error::AddressOverflow)?;
            self.read_exact(address, &mut scratch[..count])?;
            for byte in &scratch[..count] {
                sum = sum.wrapping_add(*byte);
            }
            offset += count;
        }
        Ok(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SliceReader<'a> {
        base: u64,
        bytes: &'a [u8],
    }
    impl PhysicalReader for SliceReader<'_> {
        fn read_exact(&self, physical_address: u64, destination: &mut [u8]) -> Result<(), Error> {
            let offset = physical_address
                .checked_sub(self.base)
                .ok_or(Error::Backend)? as usize;
            let end = offset
                .checked_add(destination.len())
                .ok_or(Error::AddressOverflow)?;
            let source = self.bytes.get(offset..end).ok_or(Error::Backend)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    #[test]
    fn endian_helpers_and_checksum_are_deterministic() {
        let bytes = [1u8, 2, 3, 4, 250, 0, 0, 0];
        let reader = SliceReader {
            base: 0x1000,
            bytes: &bytes,
        };
        assert_eq!(reader.read_u16(0x1000).unwrap(), 0x0201);
        assert_eq!(reader.read_u32(0x1000).unwrap(), 0x0403_0201);
        assert_eq!(reader.checksum8(0x1000, bytes.len()).unwrap(), 4);
    }
}
