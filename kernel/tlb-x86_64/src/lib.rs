// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

pub const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unaligned,
    NonCanonical,
    UnsupportedHostArchitecture,
}

pub fn validate_page(address: u64) -> Result<u64, Error> {
    if address & (PAGE_SIZE - 1) != 0 {
        return Err(Error::Unaligned);
    }
    if !is_canonical_48(address) {
        return Err(Error::NonCanonical);
    }
    Ok(address)
}

/// Invalidates one page in the current CPU's TLB.
///
/// # Safety
/// Caller must execute at CPL0 and ensure this virtual page belongs to the currently active
/// address space. Cross-CPU users of the same address space require a separate shootdown protocol.
#[cfg(target_arch = "x86_64")]
pub unsafe fn invalidate_page(address: u64) -> Result<(), Error> {
    let address = validate_page(address)?;
    // SAFETY: caller provides CPL0/current-address-space contract; address validation is above.
    unsafe { asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags)) };
    Ok(())
}

/// Foreign-host support builds validate the address but never pretend to invalidate an x86 TLB.
///
/// # Safety
/// This function performs no privileged operation and always fails closed after validation.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn invalidate_page(address: u64) -> Result<(), Error> {
    let _ = validate_page(address)?;
    Err(Error::UnsupportedHostArchitecture)
}

const fn is_canonical_48(address: u64) -> bool {
    let upper = address >> 48;
    let sign = (address >> 47) & 1;
    (sign == 0 && upper == 0) || (sign == 1 && upper == 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_accepts_canonical_page_addresses() {
        assert_eq!(
            validate_page(0xffff_ffff_8000_0000),
            Ok(0xffff_ffff_8000_0000)
        );
        assert_eq!(validate_page(0x4000), Ok(0x4000));
    }

    #[test]
    fn validation_rejects_unaligned_and_noncanonical_values() {
        assert_eq!(validate_page(0x4001), Err(Error::Unaligned));
        assert_eq!(
            validate_page(0x0000_8000_0000_0000),
            Err(Error::NonCanonical)
        );
    }
}
