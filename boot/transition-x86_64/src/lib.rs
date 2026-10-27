// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::{asm, global_asm};
#[cfg(target_arch = "x86_64")]
use core::slice::from_raw_parts;

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_IDENTITY_ADDRESS: u64 = 0x0000_7fff_ffff_f000;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionArgs {
    pub root_table: u64,
    pub stack_pointer: u64,
    pub kernel_entry: u64,
    pub bootinfo_virtual: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RootUnaligned,
    RootTooHigh,
    InvalidStack,
    InvalidEntry,
    InvalidBootInfo,
    TrampolineTooLarge,
}

impl TransitionArgs {
    pub const fn validate(self) -> Result<Self, Error> {
        if self.root_table & (PAGE_SIZE - 1) != 0 {
            return Err(Error::RootUnaligned);
        }
        if self.root_table >= (1u64 << 52) {
            return Err(Error::RootTooHigh);
        }
        if !is_canonical_48(self.stack_pointer) || self.stack_pointer & 0xf != 8 {
            return Err(Error::InvalidStack);
        }
        if !is_canonical_48(self.kernel_entry) || self.kernel_entry < 0xffff_8000_0000_0000 {
            return Err(Error::InvalidEntry);
        }
        if !is_canonical_48(self.bootinfo_virtual) || self.bootinfo_virtual < 0xffff_8000_0000_0000
        {
            return Err(Error::InvalidBootInfo);
        }
        Ok(self)
    }
}

// Keep this block section-agnostic so the same source assembles for PE/COFF UEFI and ELF x86
// targets. It contains no external references, relocations, stack accesses, or absolute addresses.
#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .balign 16
    .global kernal_transition_start
    .global kernal_transition_end
kernal_transition_start:
    cli
    cld
    mov cr3, rdi
    mov rsp, rsi
    xor rbp, rbp
    mov rdi, rcx
    jmp rdx
kernal_transition_end:
"#
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    static kernal_transition_start: u8;
    static kernal_transition_end: u8;
}

#[cfg(target_arch = "x86_64")]
pub fn trampoline_bytes() -> Result<&'static [u8], Error> {
    let start = core::ptr::addr_of!(kernal_transition_start) as usize;
    let end = core::ptr::addr_of!(kernal_transition_end) as usize;
    let len = end.checked_sub(start).ok_or(Error::TrampolineTooLarge)?;
    if len == 0 || len > PAGE_SIZE as usize {
        return Err(Error::TrampolineTooLarge);
    }
    // SAFETY: linker symbols delimit this immutable in-image instruction sequence.
    Ok(unsafe { from_raw_parts(start as *const u8, len) })
}

#[cfg(not(target_arch = "x86_64"))]
pub fn trampoline_bytes() -> Result<&'static [u8], Error> {
    // Host tests validate size/policy only; this byte sequence is never executable evidence.
    static HOST_TEST_TRAMPOLINE: [u8; 32] = [0xcc; 32];
    Ok(&HOST_TEST_TRAMPOLINE)
}

/// # Safety
/// `trampoline_address` must contain an exact executable copy of `trampoline_bytes()` and be
/// identity-mapped R-X by the new root. The root must map stack, BootInfo and kernel entry.
#[cfg(target_arch = "x86_64")]
pub unsafe fn jump(trampoline_address: u64, args: TransitionArgs) -> ! {
    let args = match args.validate() {
        Ok(args) => args,
        Err(_) => loop {
            core::hint::spin_loop();
        },
    };
    // SAFETY: paging and executable-copy invariants are delegated to the caller above.
    unsafe {
        asm!(
            "jmp {trampoline}",
            trampoline = in(reg) trampoline_address,
            in("rdi") args.root_table,
            in("rsi") args.stack_pointer,
            in("rdx") args.kernel_entry,
            in("rcx") args.bootinfo_virtual,
            options(noreturn)
        )
    }
}

pub const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trampoline_fits_single_page() {
        let bytes = trampoline_bytes().unwrap();
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= PAGE_SIZE as usize);
    }

    #[test]
    fn transition_requires_sysv_entry_stack_alignment() {
        let args = TransitionArgs {
            root_table: 0x1000,
            stack_pointer: 0xffff_ff80_0041_0ff8,
            kernel_entry: 0xffff_ffff_8020_0000,
            bootinfo_virtual: 0xffff_ff80_0020_0000,
        };
        assert!(args.validate().is_ok());
        assert_eq!(
            TransitionArgs {
                stack_pointer: args.stack_pointer + 8,
                ..args
            }
            .validate(),
            Err(Error::InvalidStack)
        );
    }

    #[test]
    fn rejects_lower_half_kernel_entry() {
        let args = TransitionArgs {
            root_table: 0x1000,
            stack_pointer: 0xffff_ff80_0041_0ff8,
            kernel_entry: 0x20_0000,
            bootinfo_virtual: 0xffff_ff80_0020_0000,
        };
        assert_eq!(args.validate(), Err(Error::InvalidEntry));
    }
}
