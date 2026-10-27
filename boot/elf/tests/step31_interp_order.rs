// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_elf::{Image, Machine};

const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const EHDR: usize = 64;
const PHDR: usize = 56;
const INTERP_OFFSET: usize = 0x180;
const INTERP: &[u8] = b"/lib/ld-linux-aarch64.so.1\0";

struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_size: u64,
    mem_size: u64,
    align: u64,
}

fn write_phdr(bytes: &mut [u8], at: usize, header: ProgramHeader) {
    bytes[at..at + 4].copy_from_slice(&header.kind.to_le_bytes());
    bytes[at + 4..at + 8].copy_from_slice(&header.flags.to_le_bytes());
    bytes[at + 8..at + 16].copy_from_slice(&header.offset.to_le_bytes());
    bytes[at + 16..at + 24].copy_from_slice(&header.vaddr.to_le_bytes());
    bytes[at + 24..at + 32].copy_from_slice(&0u64.to_le_bytes());
    bytes[at + 32..at + 40].copy_from_slice(&header.file_size.to_le_bytes());
    bytes[at + 40..at + 48].copy_from_slice(&header.mem_size.to_le_bytes());
    bytes[at + 48..at + 56].copy_from_slice(&header.align.to_le_bytes());
}

fn load_before_interp() -> [u8; 0x240] {
    let mut bytes = [0u8; 0x240];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x200u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    bytes[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

    // ELF requires PT_INTERP to precede every loadable segment entry. Keep the rest of the image
    // valid so rejection is attributable to the program-header ordering contract alone.
    let image_len = bytes.len() as u64;
    write_phdr(
        &mut bytes,
        EHDR,
        ProgramHeader {
            kind: PT_LOAD,
            flags: 5,
            offset: 0,
            vaddr: 0,
            file_size: image_len,
            mem_size: 0x1000,
            align: 0x1000,
        },
    );
    write_phdr(
        &mut bytes,
        EHDR + PHDR,
        ProgramHeader {
            kind: PT_INTERP,
            flags: 4,
            offset: INTERP_OFFSET as u64,
            vaddr: 0,
            file_size: INTERP.len() as u64,
            mem_size: INTERP.len() as u64,
            align: 1,
        },
    );
    bytes[INTERP_OFFSET..INTERP_OFFSET + INTERP.len()].copy_from_slice(INTERP);
    bytes
}

#[test]
fn rejects_pt_interp_after_a_loadable_segment() {
    let bytes = load_before_interp();
    assert!(
        Image::parse_for_machine(&bytes, Machine::Aarch64).is_err(),
        "PT_INTERP after PT_LOAD must fail closed before any runtime/VFS handoff"
    );
}
