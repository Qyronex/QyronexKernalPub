// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InterruptsAlreadyEnabled,
}

/// Atomically crosses the idle sleep boundary on x86_64.
///
/// The caller enters with IF=0 after checking local runnable/reschedule state. `STI` delays
/// recognition of maskable interrupts until after the immediately following instruction, so the
/// adjacent `HLT` cannot lose an interrupt in a gap between enabling IF and sleeping. After an
/// interrupt returns, the trailing `CLI` re-establishes IF=0 before returning to the scheduler safe
/// point.
///
/// # Safety
/// Must execute at CPL0 on a CPU with a valid IDT, interrupt stack/TSS, GS CpuLocal and Local APIC
/// runtime state. Interrupt handlers must preserve the kernel context and return with IRETQ.
#[cfg(target_arch = "x86_64")]
pub unsafe fn halt_until_interrupt() -> Result<(), Error> {
    // SAFETY: caller guarantees CPL0; observation only reads RFLAGS.
    if unsafe { kernal_irq_state_x86_64::enabled() } {
        return Err(Error::InterruptsAlreadyEnabled);
    }
    // SAFETY: caller established all interrupt-entry invariants. Do not claim preserves_flags:
    // STI/CLI intentionally modify IF. Intel's STI interrupt shadow makes STI;HLT the standard
    // race-safe idle boundary when entered with IF clear.
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_is_stable() {
        assert_eq!(
            Error::InterruptsAlreadyEnabled,
            Error::InterruptsAlreadyEnabled
        );
    }
}
