// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

pub const MASTER_DATA_PORT: u16 = 0x21;
pub const SLAVE_DATA_PORT: u16 = 0xa1;
pub const ALL_MASKED: u8 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Masks {
    pub master: u8,
    pub slave: u8,
}

/// Masks every IRQ line on both legacy 8259 PICs.
///
/// This does not remap or otherwise reprogram the PIC: early kernel policy is simply to make
/// legacy external IRQ delivery quiescent before APIC/IOAPIC routing is intentionally installed.
///
/// # Safety
/// Must run at CPL0 on x86_64 where legacy I/O port accesses are permitted.
#[cfg(target_arch = "x86_64")]
pub unsafe fn mask_all() -> Masks {
    // SAFETY: caller grants CPL0 I/O-port access; these are the architectural PIC mask ports.
    unsafe {
        outb(MASTER_DATA_PORT, ALL_MASKED);
        io_wait();
        outb(SLAVE_DATA_PORT, ALL_MASKED);
        io_wait();
    }
    Masks {
        master: ALL_MASKED,
        slave: ALL_MASKED,
    }
}

/// # Safety
/// Same CPL0/I/O-port contract as `mask_all`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_masks() -> Masks {
    // SAFETY: caller grants CPL0 I/O-port access.
    unsafe {
        Masks {
            master: inb(MASTER_DATA_PORT),
            slave: inb(SLAVE_DATA_PORT),
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: delegated to caller.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: delegated to caller.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags))
    };
    value
}

#[cfg(target_arch = "x86_64")]
unsafe fn io_wait() {
    // Port 0x80 is the conventional POST delay port; value is intentionally irrelevant.
    // SAFETY: caller grants CPL0 I/O-port access.
    unsafe { outb(0x80, 0) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_constants_cover_all_irq_lines() {
        assert_eq!(ALL_MASKED, 0xff);
        assert_eq!(MASTER_DATA_PORT, 0x21);
        assert_eq!(SLAVE_DATA_PORT, 0xa1);
    }
}
