// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

#[cfg(target_arch = "x86_64")]
const RFLAGS_IF: u64 = 1 << 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptState {
    was_enabled: bool,
}

impl InterruptState {
    pub const fn was_enabled(self) -> bool {
        self.was_enabled
    }
}

/// Captures IF and disables maskable local interrupts.
///
/// # Safety
/// Must execute at CPL0. Callers must restore the returned state on every non-terminal path.
#[cfg(target_arch = "x86_64")]
pub unsafe fn save_and_disable() -> InterruptState {
    let flags: u64;
    // SAFETY: caller guarantees CPL0; CLI intentionally changes IF, so this asm must NOT claim
    // preserves_flags to LLVM.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) flags
        );
    }
    InterruptState {
        was_enabled: flags & RFLAGS_IF != 0,
    }
}

/// Restores only the interrupt-enable state captured by `save_and_disable`.
///
/// # Safety
/// Must execute at CPL0 on the same CPU and logical critical section that produced `state`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn restore(state: InterruptState) {
    if state.was_enabled {
        // SAFETY: caller guarantees the critical section has ended and STI is now permitted.
        unsafe { asm!("sti", options(nomem, nostack)) };
    } else {
        // Keep IF clear; explicit CLI makes the postcondition independent of accidental changes.
        // SAFETY: caller guarantees CPL0.
        unsafe { asm!("cli", options(nomem, nostack)) };
    }
}

/// # Safety
/// Must execute at CPL0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enabled() -> bool {
    let flags: u64;
    // SAFETY: caller guarantees CPL0 and a valid stack. This sequence only observes flags.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags)) };
    flags & RFLAGS_IF != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_value_preserves_boolean_contract() {
        assert!(!InterruptState { was_enabled: false }.was_enabled());
        assert!(InterruptState { was_enabled: true }.was_enabled());
    }
}
