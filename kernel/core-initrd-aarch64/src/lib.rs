// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_cpio::Archive;
use kernal_elf::{Image, Machine};
use kernal_fdt::Blob;
use kernal_fdt_initrd::{InitrdRange, parse_initrd};
use kernal_paging::PAGE_SIZE;
use kernal_qemu_initrd_aarch64::ValidatedInitrd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Empty,
    DtbLengthOverflow,
    InvalidKernelRange,
    OverlapsDtb,
    OverlapsKernel,
    MappingSpanOverflow,
    MappedPageOverlapsDtb,
    MappedPageOverlapsKernel,
    FdtInitrd(kernal_fdt_initrd::Error),
    MissingInitrd,
    Qemu(kernal_qemu_initrd_aarch64::Error),
    ProofMismatch,
    InitrdLengthMismatch,
    Cpio(kernal_cpio::Error),
    MissingInitramfsFile,
    Elf(kernal_elf::Error),
}

impl From<kernal_fdt_initrd::Error> for Error {
    fn from(value: kernal_fdt_initrd::Error) -> Self {
        Self::FdtInitrd(value)
    }
}

impl From<kernal_qemu_initrd_aarch64::Error> for Error {
    fn from(value: kernal_qemu_initrd_aarch64::Error) -> Self {
        Self::Qemu(value)
    }
}

impl From<kernal_cpio::Error> for Error {
    fn from(value: kernal_cpio::Error) -> Self {
        Self::Cpio(value)
    }
}

impl From<kernal_elf::Error> for Error {
    fn from(value: kernal_elf::Error) -> Self {
        Self::Elf(value)
    }
}

/// Physical initrd range after the Core boot policy has proven that neither its exact bytes nor the
/// complete physical pages required to map those bytes overlap the live DTB or linker-owned kernel.
///
/// This value is deliberately not mapping or dereference authority. A protected mapping owner must
/// still combine it with bounded QEMU-RAM/size validation and establish an explicit supervisor-only
/// byte view before any payload is parsed or loaded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonOverlappingInitrdRange {
    start: u64,
    end: u64,
}

impl NonOverlappingInitrdRange {
    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Initrd after the complete safe Core provenance chain has succeeded.
///
/// Construction proves all of the following against the same FDT-published half-open range:
/// - the `/chosen` initrd properties are structurally valid and complete;
/// - the exact payload range does not overlap the live DTB bytes or linker-owned kernel image;
/// - the page-rounded physical span a page-table owner must map also remains disjoint from the
///   page-rounded DTB and kernel reservations;
/// - the range is non-empty, bounded to the QEMU `virt` RAM contract and below the proof-size limit.
///
/// This still grants no mapping or dereference authority. The protected initrd owner must establish a
/// bounded supervisor-only read-only/NX TTBR1 alias and expose its exact bytes through a scoped borrow;
/// the low RAM identity aliases may already have been retired. ELF validation/loading remains owned by
/// the existing canonical parser and AArch64 Linux loader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreValidatedInitrd {
    overlap: NonOverlappingInitrdRange,
    qemu: ValidatedInitrd,
}

impl CoreValidatedInitrd {
    pub const fn physical_start(self) -> u64 {
        self.qemu.physical_start()
    }

    pub const fn physical_end(self) -> u64 {
        self.overlap.end()
    }

    pub const fn len(self) -> usize {
        self.qemu.len()
    }

    pub const fn is_empty(self) -> bool {
        self.qemu.is_empty()
    }

    /// Validates the executable payload exposed by the protected initrd mapping.
    ///
    /// The accepted Step-15 direct-ELF path remains byte-for-byte delegated to the existing QEMU
    /// initrd/ELF validator. Step 28 adds one explicit alternate container shape only: a validated
    /// `newc`/CRC-newc archive whose immutable `bin/busybox` regular file is then passed to the same
    /// canonical AArch64 ELF parser. Any other non-ELF payload keeps the historical fail-closed path.
    pub fn parse_aarch64_elf<'a>(self, bytes: &'a [u8]) -> Result<Image<'a>, Error> {
        if bytes.starts_with(b"070701") || bytes.starts_with(b"070702") {
            return self.parse_initramfs_aarch64_elf(bytes, b"bin/busybox");
        }
        self.qemu.parse_aarch64_elf(bytes).map_err(Error::Qemu)
    }

    /// Selects one immutable regular file from a fully validated CPIO/newc initramfs.
    ///
    /// The caller must provide the exact byte view corresponding to this provenance object. Path
    /// normalization, symlink traversal, extraction and mutable VFS behavior are intentionally not
    /// performed here. The CPIO layer accepts only its canonical bounded relative-path policy, and
    /// the authority boundary remains exact pathname bytes rather than UTF-8 text.
    pub fn initramfs_regular_file<'a>(
        self,
        bytes: &'a [u8],
        path: &[u8],
    ) -> Result<&'a [u8], Error> {
        if bytes.len() != self.len() {
            return Err(Error::InitrdLengthMismatch);
        }

        Archive::parse(bytes)?
            .regular_file(path)?
            .ok_or(Error::MissingInitramfsFile)
    }

    /// Selects an immutable initramfs file through the proven initrd byte view and validates it with
    /// the existing canonical AArch64 ELF parser. This does not add a second ELF loader and does not
    /// special-case executable behavior by process name.
    pub fn parse_initramfs_aarch64_elf<'a>(
        self,
        bytes: &'a [u8],
        path: &[u8],
    ) -> Result<Image<'a>, Error> {
        let elf = self.initramfs_regular_file(bytes, path)?;
        Image::parse_for_machine(elf, Machine::Aarch64).map_err(Error::Elf)
    }
}

/// Discovers the FDT `/chosen` initrd and joins the existing transport, reserved-range and QEMU
/// bounds proofs into one fail-closed Core value.
///
/// `dtb_start` must identify the physical start of this exact already-validated `blob`.
/// `kernel_start..kernel_end` must be the linker-owned physical image range represented by
/// `__kernel_start` and `__kernel_end`.
pub fn discover_qemu_initrd(
    blob: &Blob<'_>,
    dtb_start: u64,
    kernel_start: u64,
    kernel_end: u64,
) -> Result<CoreValidatedInitrd, Error> {
    let range = parse_initrd(blob)?.ok_or(Error::MissingInitrd)?;
    let overlap = validate_non_overlapping_initrd(
        range,
        dtb_start,
        blob.header().total_size,
        kernel_start,
        kernel_end,
    )?;
    let qemu = ValidatedInitrd::from_fdt(range)?;

    let overlap_len = usize::try_from(overlap.len()).map_err(|_| Error::ProofMismatch)?;
    if overlap.start() != qemu.physical_start() || overlap_len != qemu.len() {
        return Err(Error::ProofMismatch);
    }

    Ok(CoreValidatedInitrd { overlap, qemu })
}

/// Adds the Core-specific reserved-range proof missing from the transport-only FDT/QEMU initrd
/// helpers.
///
/// `dtb_start..dtb_start+dtb_len` is the exact validated blob currently borrowed by Core.
/// `kernel_start..kernel_end` must be the linker-owned physical image range represented by
/// `__kernel_start` and `__kernel_end`. All intervals are half-open. Because an MMU cannot map a
/// partial page, this proof rejects a payload whose outward-rounded mapping pages would alias a DTB
/// or kernel reservation even when the exact payload bytes only touch that reservation's boundary.
pub fn validate_non_overlapping_initrd(
    range: InitrdRange,
    dtb_start: u64,
    dtb_len: usize,
    kernel_start: u64,
    kernel_end: u64,
) -> Result<NonOverlappingInitrdRange, Error> {
    validate_non_overlapping_bounds(
        range.start(),
        range.end(),
        dtb_start,
        dtb_len,
        kernel_start,
        kernel_end,
    )
}

fn validate_non_overlapping_bounds(
    start: u64,
    end: u64,
    dtb_start: u64,
    dtb_len: usize,
    kernel_start: u64,
    kernel_end: u64,
) -> Result<NonOverlappingInitrdRange, Error> {
    if start >= end {
        return Err(Error::Empty);
    }
    if kernel_start >= kernel_end {
        return Err(Error::InvalidKernelRange);
    }

    let dtb_len = u64::try_from(dtb_len).map_err(|_| Error::DtbLengthOverflow)?;
    let dtb_end = dtb_start
        .checked_add(dtb_len)
        .ok_or(Error::DtbLengthOverflow)?;

    if ranges_overlap(start, end, dtb_start, dtb_end) {
        return Err(Error::OverlapsDtb);
    }
    if ranges_overlap(start, end, kernel_start, kernel_end) {
        return Err(Error::OverlapsKernel);
    }

    let (mapped_start, mapped_end) = page_cover(start, end)?;
    let (dtb_page_start, dtb_page_end) = page_cover(dtb_start, dtb_end)?;
    if ranges_overlap(mapped_start, mapped_end, dtb_page_start, dtb_page_end) {
        return Err(Error::MappedPageOverlapsDtb);
    }
    let (kernel_page_start, kernel_page_end) = page_cover(kernel_start, kernel_end)?;
    if ranges_overlap(mapped_start, mapped_end, kernel_page_start, kernel_page_end) {
        return Err(Error::MappedPageOverlapsKernel);
    }

    Ok(NonOverlappingInitrdRange { start, end })
}

fn page_cover(start: u64, end: u64) -> Result<(u64, u64), Error> {
    if start >= end {
        return Err(Error::MappingSpanOverflow);
    }
    let mask = PAGE_SIZE - 1;
    let page_start = start & !mask;
    let page_end = end.checked_add(mask).ok_or(Error::MappingSpanOverflow)? & !mask;
    if page_start >= page_end {
        return Err(Error::MappingSpanOverflow);
    }
    Ok((page_start, page_end))
}

const fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

#[cfg(test)]
mod tests {
    use super::*;

    const DTB_START: u64 = 0x4000_0000;
    const DTB_LEN: usize = 0x20_000;
    const KERNEL_START: u64 = 0x4020_0000;
    const KERNEL_END: u64 = 0x4080_0000;
    const INITRD_START: u64 = 0x4800_0000;

    fn validate(start: u64, end: u64) -> Result<NonOverlappingInitrdRange, Error> {
        validate_non_overlapping_bounds(start, end, DTB_START, DTB_LEN, KERNEL_START, KERNEL_END)
    }

    fn validated_for_len(len: usize) -> CoreValidatedInitrd {
        let end = INITRD_START + u64::try_from(len).unwrap();
        let overlap = validate(INITRD_START, end).unwrap();
        let qemu = kernal_qemu_initrd_aarch64::validate_qemu_bounds(INITRD_START, end).unwrap();
        CoreValidatedInitrd { overlap, qemu }
    }

    fn minimal_aarch64_elf() -> [u8; 0x120] {
        const ELF64_EHDR_SIZE: usize = 64;
        const ELF64_PHDR_SIZE: usize = 56;
        const ET_EXEC: u16 = 2;
        const EM_AARCH64: u16 = 183;
        const PT_LOAD: u32 = 1;

        let mut bytes = [0u8; 0x120];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
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
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&0x0040_0000u64.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0x0020_0000u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&0x20u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    fn push_hex(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn push_newc_entry(out: &mut Vec<u8>, path: &str, mode: u32, data: &[u8]) {
        let start = out.len();
        out.extend_from_slice(b"070701");
        for value in [
            1,
            mode,
            0,
            0,
            1,
            0,
            u32::try_from(data.len()).unwrap(),
            0,
            0,
            0,
            0,
            u32::try_from(path.len() + 1).unwrap(),
            0,
        ] {
            push_hex(out, value);
        }
        assert_eq!(out.len() - start, 110);
        out.extend_from_slice(path.as_bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn initramfs_with_file(path: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_newc_entry(&mut out, path, mode, data);
        push_newc_entry(&mut out, "TRAILER!!!", 0, &[]);
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        out
    }

    #[test]
    fn accepts_disjoint_qemu_initrd_range() {
        let accepted = validate(0x4800_0000, 0x4801_9000).unwrap();
        assert_eq!(accepted.start(), 0x4800_0000);
        assert_eq!(accepted.end(), 0x4801_9000);
        assert_eq!(accepted.len(), 0x1_9000);
        assert!(!accepted.is_empty());
    }

    #[test]
    fn rejects_touching_dtb_bytes_but_accepts_page_boundary() {
        assert_eq!(validate(0x4001_f000, 0x4002_1000), Err(Error::OverlapsDtb));
        assert!(validate(0x4002_0000, 0x4002_1000).is_ok());
    }

    #[test]
    fn rejects_kernel_overlap_but_accepts_page_aligned_end_boundary() {
        assert_eq!(
            validate(KERNEL_START - 0x1000, KERNEL_START + 0x1000),
            Err(Error::OverlapsKernel)
        );
        assert!(validate(KERNEL_END, KERNEL_END + 0x1000).is_ok());
    }

    #[test]
    fn rejects_payload_page_aliasing_unaligned_dtb_tail() {
        assert_eq!(
            validate_non_overlapping_bounds(
                0x4000_1234,
                0x4000_2234,
                DTB_START,
                0x1234,
                KERNEL_START,
                KERNEL_END,
            ),
            Err(Error::MappedPageOverlapsDtb)
        );
    }

    #[test]
    fn rejects_payload_page_aliasing_unaligned_kernel_boundary() {
        assert_eq!(
            validate_non_overlapping_bounds(
                0x401f_f000,
                0x4020_0123,
                DTB_START,
                DTB_LEN,
                0x4020_0123,
                KERNEL_END,
            ),
            Err(Error::MappedPageOverlapsKernel)
        );
    }

    #[test]
    fn validates_initramfs_file_and_delegates_to_canonical_elf_parser() {
        let elf = minimal_aarch64_elf();
        let bytes = initramfs_with_file("bin/tool", 0o100755, &elf);
        let initrd = validated_for_len(bytes.len());

        assert_eq!(
            initrd.initramfs_regular_file(&bytes, b"bin/tool").unwrap(),
            &elf
        );
        let image = initrd
            .parse_initramfs_aarch64_elf(&bytes, b"bin/tool")
            .unwrap();
        assert_eq!(image.entry(), 0x0040_0000);
    }

    #[test]
    fn protected_validation_accepts_step28_busybox_archive() {
        let elf = minimal_aarch64_elf();
        let bytes = initramfs_with_file("bin/busybox", 0o100755, &elf);
        let initrd = validated_for_len(bytes.len());

        let image = initrd.parse_aarch64_elf(&bytes).unwrap();
        assert_eq!(image.entry(), 0x0040_0000);
    }

    #[test]
    fn initramfs_selection_fails_closed_on_provenance_and_file_errors() {
        let elf = minimal_aarch64_elf();
        let bytes = initramfs_with_file("bin/tool", 0o100755, &elf);
        let initrd = validated_for_len(bytes.len());

        assert_eq!(
            initrd.initramfs_regular_file(&bytes[..bytes.len() - 1], b"bin/tool"),
            Err(Error::InitrdLengthMismatch)
        );
        assert_eq!(
            initrd.initramfs_regular_file(&bytes, b"bin/missing"),
            Err(Error::MissingInitramfsFile)
        );

        let directory = initramfs_with_file("bin", 0o040755, &[]);
        let directory_initrd = validated_for_len(directory.len());
        assert_eq!(
            directory_initrd.initramfs_regular_file(&directory, b"bin"),
            Err(Error::Cpio(kernal_cpio::Error::NotRegularFile))
        );
    }

    #[test]
    fn initramfs_elf_validation_rejects_wrong_machine() {
        let mut elf = minimal_aarch64_elf();
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        let bytes = initramfs_with_file("bin/tool", 0o100755, &elf);
        let initrd = validated_for_len(bytes.len());

        assert!(matches!(
            initrd.parse_initramfs_aarch64_elf(&bytes, b"bin/tool"),
            Err(Error::Elf(kernal_elf::Error::UnsupportedMachine))
        ));
    }

    #[test]
    fn invalid_bounds_fail_closed() {
        assert_eq!(validate(0x4800_0000, 0x4800_0000), Err(Error::Empty));
        assert_eq!(
            validate_non_overlapping_bounds(
                0x4800_0000,
                0x4800_1000,
                DTB_START,
                DTB_LEN,
                KERNEL_END,
                KERNEL_START,
            ),
            Err(Error::InvalidKernelRange)
        );
        assert_eq!(
            validate_non_overlapping_bounds(
                0x4800_0000,
                0x4800_1000,
                u64::MAX - 1,
                4,
                KERNEL_START,
                KERNEL_END,
            ),
            Err(Error::DtbLengthOverflow)
        );
        assert_eq!(
            page_cover(u64::MAX - 7, u64::MAX),
            Err(Error::MappingSpanOverflow)
        );
    }
}
