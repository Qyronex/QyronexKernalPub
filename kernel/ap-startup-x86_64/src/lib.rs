// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::global_asm;
#[cfg(target_arch = "x86_64")]
use core::slice::from_raw_parts;

pub const PAGE_SIZE: u64 = 4096;
pub const BOOTSTRAP_SIZE: u64 = 8192;
pub const LOW_MEMORY_LIMIT: u64 = 1024 * 1024;
pub const MAILBOX_PAGE_OFFSET: u64 = PAGE_SIZE;
pub const MAILBOX_MAGIC: u64 = 0x4b45_524e_4150_424f;

const MAILBOX_MAGIC_OFFSET: usize = 0;
const MAILBOX_CR3_OFFSET: usize = 8;
const MAILBOX_STACK_OFFSET: usize = 16;
const MAILBOX_ENTRY_OFFSET: usize = 24;
const MAILBOX_CPU_OFFSET: usize = 32;
const MAILBOX_GDTR_OFFSET: usize = 40;
const MAILBOX_LONG_PTR_OFFSET: usize = 48;
const MAILBOX_PROTECTED_PTR_OFFSET: usize = 56;
const MAILBOX_GDT_OFFSET: usize = 64;
const MAILBOX_USED: usize = 96;

const KERNEL_CODE32_SELECTOR: u16 = 0x08;
const KERNEL_DATA_SELECTOR: u16 = 0x10;
const KERNEL_CODE64_SELECTOR: u16 = 0x18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidBootstrapAddress,
    RootAboveFourGiB,
    RootUnaligned,
    InvalidStack,
    InvalidEntry,
    CodeTooLarge,
    AddressOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupParameters {
    pub bootstrap_physical: u64,
    pub root_table_physical: u64,
    pub stack_pointer: u64,
    pub kernel_entry: u64,
    pub cpu_index: u16,
}

impl StartupParameters {
    pub fn validate(self) -> Result<Self, Error> {
        if self.bootstrap_physical < PAGE_SIZE
            || self.bootstrap_physical & (PAGE_SIZE - 1) != 0
            || self
                .bootstrap_physical
                .checked_add(BOOTSTRAP_SIZE)
                .ok_or(Error::AddressOverflow)?
                > LOW_MEMORY_LIMIT
        {
            return Err(Error::InvalidBootstrapAddress);
        }
        if self.root_table_physical & (PAGE_SIZE - 1) != 0 {
            return Err(Error::RootUnaligned);
        }
        if self.root_table_physical >= 1u64 << 32 {
            return Err(Error::RootAboveFourGiB);
        }
        if !is_canonical_48(self.stack_pointer) || self.stack_pointer & 0xf != 8 {
            return Err(Error::InvalidStack);
        }
        if !is_canonical_48(self.kernel_entry) || self.kernel_entry < 0xffff_8000_0000_0000 {
            return Err(Error::InvalidEntry);
        }
        Ok(self)
    }

    pub fn sipi_vector(self) -> Result<u8, Error> {
        let valid = self.validate()?;
        u8::try_from(valid.bootstrap_physical >> 12).map_err(|_| Error::InvalidBootstrapAddress)
    }
}

#[cfg(target_arch = "x86_64")]
pub fn trampoline_bytes() -> Result<&'static [u8], Error> {
    let start = core::ptr::addr_of!(kernal_ap_trampoline_start) as usize;
    let end = core::ptr::addr_of!(kernal_ap_trampoline_end) as usize;
    let len = end.checked_sub(start).ok_or(Error::CodeTooLarge)?;
    if len == 0 || len > PAGE_SIZE as usize {
        return Err(Error::CodeTooLarge);
    }
    // SAFETY: linker symbols delimit immutable code bytes in this image.
    Ok(unsafe { from_raw_parts(start as *const u8, len) })
}

#[cfg(not(target_arch = "x86_64"))]
pub fn trampoline_bytes() -> Result<&'static [u8], Error> {
    // Host tests only validate layout/size policy. No foreign-host trampoline is executable.
    static HOST_TEST_TRAMPOLINE: [u8; 64] = [0xcc; 64];
    Ok(&HOST_TEST_TRAMPOLINE)
}

pub fn build_mailbox(parameters: StartupParameters, destination: &mut [u8]) -> Result<(), Error> {
    let parameters = parameters.validate()?;
    if destination.len() < PAGE_SIZE as usize {
        return Err(Error::AddressOverflow);
    }
    destination.fill(0);

    write_u64(destination, MAILBOX_MAGIC_OFFSET, MAILBOX_MAGIC)?;
    write_u32(
        destination,
        MAILBOX_CR3_OFFSET,
        parameters.root_table_physical as u32,
    )?;
    write_u64(destination, MAILBOX_STACK_OFFSET, parameters.stack_pointer)?;
    write_u64(destination, MAILBOX_ENTRY_OFFSET, parameters.kernel_entry)?;
    write_u64(destination, MAILBOX_CPU_OFFSET, parameters.cpu_index as u64)?;

    let data_physical = parameters
        .bootstrap_physical
        .checked_add(MAILBOX_PAGE_OFFSET)
        .ok_or(Error::AddressOverflow)?;
    let gdt_physical = data_physical
        .checked_add(MAILBOX_GDT_OFFSET as u64)
        .ok_or(Error::AddressOverflow)?;
    let protected_target = parameters
        .bootstrap_physical
        .checked_add(protected_mode_offset()? as u64)
        .ok_or(Error::AddressOverflow)?;
    let long_target = parameters
        .bootstrap_physical
        .checked_add(long_mode_offset()? as u64)
        .ok_or(Error::AddressOverflow)?;

    // 6-byte 32-bit GDTR: limit then 32-bit linear base. All trampoline data is below 1 MiB.
    write_u16(destination, MAILBOX_GDTR_OFFSET, (4 * 8 - 1) as u16)?;
    write_u32(
        destination,
        MAILBOX_GDTR_OFFSET + 2,
        u32::try_from(gdt_physical).map_err(|_| Error::AddressOverflow)?,
    )?;

    // The copied trampoline must not contain link-time absolute far-jump targets. Both mode
    // transitions therefore consume m16:32 pointers from the mutable mailbox page.
    write_far_pointer(
        destination,
        MAILBOX_LONG_PTR_OFFSET,
        u32::try_from(long_target).map_err(|_| Error::AddressOverflow)?,
        KERNEL_CODE64_SELECTOR,
    )?;
    write_far_pointer(
        destination,
        MAILBOX_PROTECTED_PTR_OFFSET,
        u32::try_from(protected_target).map_err(|_| Error::AddressOverflow)?,
        KERNEL_CODE32_SELECTOR,
    )?;

    // Selector values are byte offsets into this GDT. Deriving slots from them keeps the
    // trampoline's hard architectural selector contract tied to the table layout.
    let mut gdt = [0u64; 4];
    gdt[(KERNEL_CODE32_SELECTOR / 8) as usize] = segment_descriptor(0, true, false);
    gdt[(KERNEL_DATA_SELECTOR / 8) as usize] = segment_descriptor(0, false, false);
    gdt[(KERNEL_CODE64_SELECTOR / 8) as usize] = segment_descriptor(0, true, true);
    for (index, descriptor) in gdt.iter().enumerate() {
        write_u64(destination, MAILBOX_GDT_OFFSET + index * 8, *descriptor)?;
    }
    debug_assert!(MAILBOX_USED <= PAGE_SIZE as usize);
    Ok(())
}

fn segment_descriptor(base: u32, executable: bool, long_mode: bool) -> u64 {
    let mut descriptor = 0u64;
    descriptor |= 0xffff;
    descriptor |= ((base as u64) & 0xffff) << 16;
    descriptor |= (((base as u64) >> 16) & 0xff) << 32;
    let access = if executable { 0x9a } else { 0x92 };
    descriptor |= (access as u64) << 40;
    descriptor |= 0xfu64 << 48;
    // Flags nibble is G, D/B, L, AVL. 32-bit code/data uses G=1,D=1,L=0; 64-bit code
    // uses G=1,D=0,L=1 as required by long mode.
    let flags = if long_mode { 0b1010u64 } else { 0b1100u64 };
    descriptor |= flags << 52;
    descriptor |= (((base as u64) >> 24) & 0xff) << 56;
    descriptor
}

#[cfg(target_arch = "x86_64")]
fn protected_mode_offset() -> Result<usize, Error> {
    symbol_offset(core::ptr::addr_of!(kernal_ap_protected_mode))
}

#[cfg(not(target_arch = "x86_64"))]
fn protected_mode_offset() -> Result<usize, Error> {
    Ok(16)
}

#[cfg(target_arch = "x86_64")]
fn long_mode_offset() -> Result<usize, Error> {
    symbol_offset(core::ptr::addr_of!(kernal_ap_long_mode))
}

#[cfg(not(target_arch = "x86_64"))]
fn long_mode_offset() -> Result<usize, Error> {
    Ok(32)
}

#[cfg(target_arch = "x86_64")]
fn symbol_offset(symbol: *const u8) -> Result<usize, Error> {
    let start = core::ptr::addr_of!(kernal_ap_trampoline_start) as usize;
    let symbol = symbol as usize;
    let offset = symbol.checked_sub(start).ok_or(Error::CodeTooLarge)?;
    if offset >= PAGE_SIZE as usize {
        Err(Error::CodeTooLarge)
    } else {
        Ok(offset)
    }
}

fn write_far_pointer(
    bytes: &mut [u8],
    offset: usize,
    target: u32,
    selector: u16,
) -> Result<(), Error> {
    write_u32(bytes, offset, target)?;
    write_u16(bytes, offset + 4, selector)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset + 2)
        .ok_or(Error::AddressOverflow)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or(Error::AddressOverflow)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), Error> {
    bytes
        .get_mut(offset..offset + 8)
        .ok_or(Error::AddressOverflow)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    static kernal_ap_trampoline_start: u8;
    static kernal_ap_trampoline_end: u8;
    static kernal_ap_protected_mode: u8;
    static kernal_ap_long_mode: u8;
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .balign 16
    .global kernal_ap_trampoline_start
    .global kernal_ap_trampoline_end
    .global kernal_ap_protected_mode
    .global kernal_ap_long_mode

    .code16
kernal_ap_trampoline_start:
    cli
    cld
    mov ax, cs
    movzx ebx, ax
    shl ebx, 4
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    # GDTR lives in mailbox page + 0x28, addressed relative to the SIPI code segment.
    lgdt cs:[0x1028]
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    # Position-independent far jump m16:32 through CS:(mailbox + 0x38).
    # Encoding: CS override, operand-size override, FF /5 with 16-bit disp16 addressing.
    .byte 0x2e, 0x66, 0xff, 0x2e
    .word 0x1038

    .code32
kernal_ap_protected_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    lea esi, [ebx + 0x1000]

    # PAE is mandatory for the IA-32e transition.
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    # Enable EFER.LME and EFER.NXE before setting CR0.PG.
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x00000900
    wrmsr

    mov eax, dword ptr [esi + 8]
    mov cr3, eax

    # Enable paging and supervisor write-protect while preserving PE.
    mov eax, cr0
    or eax, 0x80010000
    mov cr0, eax

    # m16:32 far pointer targets an identity-mapped byte in this code page.
    ljmp [esi + 48]

    .code64
kernal_ap_long_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov rsp, qword ptr [rsi + 16]
    xor rbp, rbp
    mov rdi, qword ptr [rsi + 32]
    jmp qword ptr [rsi + 24]

kernal_ap_trampoline_end:
    .code64
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trampoline_fits_one_code_page() {
        let bytes = trampoline_bytes().unwrap();
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= PAGE_SIZE as usize);
    }

    #[test]
    fn mailbox_keeps_code_and_mutable_data_on_separate_pages() {
        let params = StartupParameters {
            bootstrap_physical: 0x8000,
            root_table_physical: 0x20_0000,
            stack_pointer: 0xffff_ff80_4021_0ff8,
            kernel_entry: 0xffff_ffff_8020_1000,
            cpu_index: 3,
        };
        let mut page = [0u8; PAGE_SIZE as usize];
        build_mailbox(params, &mut page).unwrap();
        assert_eq!(
            u64::from_le_bytes(page[0..8].try_into().unwrap()),
            MAILBOX_MAGIC
        );
        assert_eq!(
            u32::from_le_bytes(page[8..12].try_into().unwrap()),
            0x20_0000
        );
        assert_eq!(
            u64::from_le_bytes(page[16..24].try_into().unwrap()),
            params.stack_pointer
        );
        assert_eq!(u64::from_le_bytes(page[32..40].try_into().unwrap()), 3);

        let protected = u32::from_le_bytes(page[56..60].try_into().unwrap()) as u64;
        let protected_selector = u16::from_le_bytes(page[60..62].try_into().unwrap());
        let long = u32::from_le_bytes(page[48..52].try_into().unwrap()) as u64;
        let long_selector = u16::from_le_bytes(page[52..54].try_into().unwrap());
        assert!(
            (params.bootstrap_physical..params.bootstrap_physical + PAGE_SIZE).contains(&protected)
        );
        assert!((params.bootstrap_physical..params.bootstrap_physical + PAGE_SIZE).contains(&long));
        assert_eq!(protected_selector, KERNEL_CODE32_SELECTOR);
        assert_eq!(long_selector, KERNEL_CODE64_SELECTOR);
    }

    #[test]
    fn sipi_vector_matches_low_page_number() {
        let params = StartupParameters {
            bootstrap_physical: 0x8_000,
            root_table_physical: 0x1000,
            stack_pointer: 0xffff_ff80_4021_0ff8,
            kernel_entry: 0xffff_ffff_8020_0000,
            cpu_index: 1,
        };
        assert_eq!(params.sipi_vector().unwrap(), 8);
    }

    #[test]
    fn ap_bootstrap_requires_cr3_below_four_gib() {
        let params = StartupParameters {
            bootstrap_physical: 0x8000,
            root_table_physical: 1u64 << 32,
            stack_pointer: 0xffff_ff80_4021_0ff8,
            kernel_entry: 0xffff_ffff_8020_0000,
            cpu_index: 1,
        };
        assert_eq!(params.validate(), Err(Error::RootAboveFourGiB));
    }

    #[test]
    fn code32_and_code64_descriptors_have_valid_mode_bits() {
        let code32 = segment_descriptor(0, true, false);
        let code64 = segment_descriptor(0, true, true);
        assert_eq!((code32 >> 40) & 0xff, 0x9a);
        assert_eq!((code32 >> 52) & 0xf, 0b1100);
        assert_eq!((code64 >> 40) & 0xff, 0x9a);
        assert_eq!((code64 >> 52) & 0xf, 0b1010);
    }
}
