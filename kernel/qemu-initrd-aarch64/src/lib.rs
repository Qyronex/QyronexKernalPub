// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_elf::{Image, Machine};
use kernal_fdt_initrd::InitrdRange;

/// QEMU `virt` RAM contract used by the existing AArch64 proof command (`-m 512M`).
pub const QEMU_VIRT_RAM_BASE: u64 = 0x4000_0000;
pub const QEMU_VIRT_RAM_BYTES: u64 = 512 * 1024 * 1024;
/// Deliberately bounded proof payload. The unchanged static-musl fixture is far below this ceiling.
pub const MAX_QEMU_INITRD_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Empty,
    AddressOverflow,
    OutsideQemuRam,
    TooLarge,
    LengthNotRepresentable,
    LengthMismatch,
    Elf(kernal_elf::Error),
}

impl From<kernal_elf::Error> for Error {
    fn from(value: kernal_elf::Error) -> Self {
        Self::Elf(value)
    }
}

/// A physical QEMU initrd range that is safe for the existing pre-TTBR0-retire proof code to view.
///
/// This value carries no mapping authority. The Core boot owner remains responsible for the single
/// unsafe conversion from `(physical_start, len)` into a temporary byte slice while the low RAM
/// identity alias is still valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedInitrd {
    physical_start: u64,
    len: usize,
}

impl ValidatedInitrd {
    pub fn from_fdt(range: InitrdRange) -> Result<Self, Error> {
        validate_qemu_bounds(range.start(), range.end())
    }

    pub const fn physical_start(self) -> u64 {
        self.physical_start
    }

    pub const fn len(self) -> usize {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Validates that a caller-provided view is exactly this transport object and is a supported
    /// AArch64 ELF image before the production Linux loader receives it.
    pub fn parse_aarch64_elf<'a>(self, bytes: &'a [u8]) -> Result<Image<'a>, Error> {
        if bytes.len() != self.len {
            return Err(Error::LengthMismatch);
        }
        Image::parse_for_machine(bytes, Machine::Aarch64).map_err(Error::Elf)
    }
}

pub fn validate_qemu_bounds(start: u64, end: u64) -> Result<ValidatedInitrd, Error> {
    if start >= end {
        return Err(Error::Empty);
    }
    let len = end.checked_sub(start).ok_or(Error::AddressOverflow)?;
    if len > MAX_QEMU_INITRD_BYTES {
        return Err(Error::TooLarge);
    }

    let ram_end = QEMU_VIRT_RAM_BASE
        .checked_add(QEMU_VIRT_RAM_BYTES)
        .ok_or(Error::AddressOverflow)?;
    if start < QEMU_VIRT_RAM_BASE || end > ram_end {
        return Err(Error::OutsideQemuRam);
    }

    let len = usize::try_from(len).map_err(|_| Error::LengthNotRepresentable)?;
    Ok(ValidatedInitrd {
        physical_start: start,
        len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_aarch64_elf() -> [u8; 0x120] {
        const ELF64_EHDR_SIZE: usize = 64;
        const ELF64_PHDR_SIZE: usize = 56;
        const ET_EXEC: u16 = 2;
        const EM_AARCH64: u16 = 183;
        const PT_LOAD: u32 = 1;

        let mut bytes = [0u8; 0x120];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // ELFDATA2LSB
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x0040_0000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF64_EHDR_SIZE as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let p = ELF64_EHDR_SIZE;
        bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
        bytes[p + 8..p + 16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&0x0040_0000u64.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0x0020_0000u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&0x20u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    #[test]
    fn accepts_bounded_range_inside_qemu_ram() {
        let start = QEMU_VIRT_RAM_BASE + 0x0200_0000;
        let end = start + 0x4000;
        let validated = validate_qemu_bounds(start, end).unwrap();
        assert_eq!(validated.physical_start(), start);
        assert_eq!(validated.len(), 0x4000);
        assert!(!validated.is_empty());
    }

    #[test]
    fn rejects_empty_oversized_and_outside_ranges() {
        assert_eq!(
            validate_qemu_bounds(QEMU_VIRT_RAM_BASE, QEMU_VIRT_RAM_BASE),
            Err(Error::Empty)
        );
        assert_eq!(
            validate_qemu_bounds(
                QEMU_VIRT_RAM_BASE,
                QEMU_VIRT_RAM_BASE + MAX_QEMU_INITRD_BYTES + 1,
            ),
            Err(Error::TooLarge)
        );
        assert_eq!(
            validate_qemu_bounds(QEMU_VIRT_RAM_BASE - 1, QEMU_VIRT_RAM_BASE + 1),
            Err(Error::OutsideQemuRam)
        );
        let ram_end = QEMU_VIRT_RAM_BASE + QEMU_VIRT_RAM_BYTES;
        assert_eq!(
            validate_qemu_bounds(ram_end - 1, ram_end + 1),
            Err(Error::OutsideQemuRam)
        );
    }

    #[test]
    fn validates_exact_aarch64_elf_view() {
        let bytes = minimal_aarch64_elf();
        let start = QEMU_VIRT_RAM_BASE + 0x0100_0000;
        let validated = validate_qemu_bounds(start, start + bytes.len() as u64).unwrap();
        let image = validated.parse_aarch64_elf(&bytes).unwrap();
        assert_eq!(image.entry(), 0x0040_0000);
    }

    #[test]
    fn rejects_length_mismatch_and_wrong_machine() {
        let mut bytes = minimal_aarch64_elf();
        let start = QEMU_VIRT_RAM_BASE + 0x0100_0000;
        let validated = validate_qemu_bounds(start, start + bytes.len() as u64).unwrap();
        assert_eq!(
            validated.parse_aarch64_elf(&bytes[..bytes.len() - 1]),
            Err(Error::LengthMismatch)
        );

        bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        assert!(matches!(
            validated.parse_aarch64_elf(&bytes),
            Err(Error::Elf(kernal_elf::Error::UnsupportedMachine))
        ));
    }
}
