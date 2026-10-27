// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::{RT_SIGFRAME_BYTES, RT_SIGFRAME_SIGINFO_OFFSET, RT_SIGFRAME_UCONTEXT_OFFSET};

pub const FRAME_RECORD_BYTES: usize = 16;
pub const FRAME_RECORD_ALIGNMENT: u64 = 16;
pub const SIGNAL_REGISTER: usize = 0;
pub const SIGINFO_REGISTER: usize = 1;
pub const UCONTEXT_REGISTER: usize = 2;
pub const FRAME_POINTER_REGISTER: usize = 29;
pub const LINK_REGISTER: usize = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalEntryError {
    InvalidSignal,
    StackUnderflow,
}

/// Exact placement of the minimal Kernal AArch64 signal frame plus Linux unwind record.
///
/// Linux arm64 first places one 16-byte `{fp, lr}` frame record below the chosen signal-stack top,
/// aligns it to 16 bytes, then places the aligned `rt_sigframe` below it. Addresses here are scalar
/// UAPI observations only; the caller must validate the resulting range against the canonical
/// Process/AddressSpace owner before usercopy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64SignalFramePlacement {
    frame_base: u64,
    frame_record_base: u64,
    stack_top: u64,
}

impl Aarch64SignalFramePlacement {
    pub const fn frame_base(self) -> u64 {
        self.frame_base
    }

    pub const fn frame_record_base(self) -> u64 {
        self.frame_record_base
    }

    pub const fn stack_top(self) -> u64 {
        self.stack_top
    }

    pub const fn siginfo_address(self) -> u64 {
        self.frame_base + RT_SIGFRAME_SIGINFO_OFFSET as u64
    }

    pub const fn ucontext_address(self) -> u64 {
        self.frame_base + RT_SIGFRAME_UCONTEXT_OFFSET as u64
    }

    pub const fn span_bytes(self) -> u64 {
        self.stack_top - self.frame_base
    }
}

/// Computes Linux arm64's frame-record + minimal-rt-sigframe placement from an already selected
/// signal-stack pointer. Alternate-stack selection is intentionally outside this pure ABI helper.
pub const fn place_minimal_signal_frame(
    chosen_stack_pointer: u64,
) -> Result<Aarch64SignalFramePlacement, SignalEntryError> {
    let record_unaligned = match chosen_stack_pointer.checked_sub(FRAME_RECORD_BYTES as u64) {
        Some(value) => value,
        None => return Err(SignalEntryError::StackUnderflow),
    };
    let frame_record_base = record_unaligned & !(FRAME_RECORD_ALIGNMENT - 1);
    let frame_base = match frame_record_base.checked_sub(RT_SIGFRAME_BYTES as u64) {
        Some(value) => value,
        None => return Err(SignalEntryError::StackUnderflow),
    };
    Ok(Aarch64SignalFramePlacement {
        frame_base,
        frame_record_base,
        stack_top: chosen_stack_pointer,
    })
}

/// Linux arm64's standalone unwind frame record stored immediately above the signal frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64SignalFrameRecord {
    previous_fp: u64,
    previous_lr: u64,
}

impl Aarch64SignalFrameRecord {
    pub const fn new(previous_fp: u64, previous_lr: u64) -> Self {
        Self {
            previous_fp,
            previous_lr,
        }
    }

    pub const fn previous_fp(self) -> u64 {
        self.previous_fp
    }

    pub const fn previous_lr(self) -> u64 {
        self.previous_lr
    }

    pub fn to_ne_bytes(self) -> [u8; FRAME_RECORD_BYTES] {
        let mut bytes = [0u8; FRAME_RECORD_BYTES];
        bytes[0..8].copy_from_slice(&self.previous_fp.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.previous_lr.to_ne_bytes());
        bytes
    }
}

/// Pure register plan for entering one Linux/AArch64 userspace signal handler.
///
/// PSTATE/BTI/TCO/SME state is deliberately absent. Those are architecture-owned feature policies
/// and must be applied separately only when Kernal owns matching generation state. For the current
/// minimal profile this plan changes only the universal AArch64 signal call convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64SignalHandlerEntry {
    signal: u8,
    handler: u64,
    sigreturn_trampoline: u64,
    placement: Aarch64SignalFramePlacement,
    siginfo_arguments: bool,
}

impl Aarch64SignalHandlerEntry {
    pub const fn new(
        signal: u8,
        handler: u64,
        sigreturn_trampoline: u64,
        placement: Aarch64SignalFramePlacement,
        siginfo_arguments: bool,
    ) -> Result<Self, SignalEntryError> {
        if signal == 0 || signal > 64 {
            return Err(SignalEntryError::InvalidSignal);
        }
        Ok(Self {
            signal,
            handler,
            sigreturn_trampoline,
            placement,
            siginfo_arguments,
        })
    }

    pub const fn signal(self) -> u8 {
        self.signal
    }

    pub const fn handler(self) -> u64 {
        self.handler
    }

    pub const fn sigreturn_trampoline(self) -> u64 {
        self.sigreturn_trampoline
    }

    pub const fn placement(self) -> Aarch64SignalFramePlacement {
        self.placement
    }

    pub const fn uses_siginfo_arguments(self) -> bool {
        self.siginfo_arguments
    }

    /// Applies only the register changes made by the common arm64 signal-call convention.
    ///
    /// `x1/x2` are intentionally preserved when SA_SIGINFO is absent, matching Linux. The caller
    /// must not commit this plan until every fallible frame/usercopy/architecture validation step has
    /// completed successfully.
    pub fn apply(self, registers: &mut [u64; 31], sp: &mut u64, pc: &mut u64) {
        registers[SIGNAL_REGISTER] = u64::from(self.signal);
        if self.siginfo_arguments {
            registers[SIGINFO_REGISTER] = self.placement.siginfo_address();
            registers[UCONTEXT_REGISTER] = self.placement.ucontext_address();
        }
        registers[FRAME_POINTER_REGISTER] = self.placement.frame_record_base();
        registers[LINK_REGISTER] = self.sigreturn_trampoline;
        *sp = self.placement.frame_base();
        *pc = self.handler;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_matches_linux_frame_record_then_sigframe_order() {
        let placement = place_minimal_signal_frame(0x8000_0008).unwrap();
        assert_eq!(placement.frame_record_base(), 0x7fff_fff0);
        assert_eq!(placement.frame_record_base() % 16, 0);
        assert_eq!(placement.frame_base() % 16, 0);
        assert_eq!(
            placement.frame_record_base() - placement.frame_base(),
            RT_SIGFRAME_BYTES as u64
        );
        assert_eq!(placement.siginfo_address(), placement.frame_base());
        assert_eq!(
            placement.ucontext_address(),
            placement.frame_base() + RT_SIGFRAME_UCONTEXT_OFFSET as u64
        );
    }

    #[test]
    fn placement_rejects_stack_underflow() {
        assert_eq!(
            place_minimal_signal_frame(8),
            Err(SignalEntryError::StackUnderflow)
        );
    }

    #[test]
    fn frame_record_encodes_previous_fp_and_lr() {
        let record = Aarch64SignalFrameRecord::new(0x1122, 0x3344).to_ne_bytes();
        assert_eq!(u64::from_ne_bytes(record[0..8].try_into().unwrap()), 0x1122);
        assert_eq!(
            u64::from_ne_bytes(record[8..16].try_into().unwrap()),
            0x3344
        );
    }

    #[test]
    fn siginfo_handler_entry_sets_linux_argument_registers() {
        let placement = place_minimal_signal_frame(0x9000_0000).unwrap();
        let entry =
            Aarch64SignalHandlerEntry::new(10, 0x4000_1000, 0x5000_2000, placement, true).unwrap();
        let mut registers = core::array::from_fn(|index| 0x100 + index as u64);
        let mut sp = 0x9000_0000;
        let mut pc = 0x4000_0000;
        entry.apply(&mut registers, &mut sp, &mut pc);

        assert_eq!(registers[0], 10);
        assert_eq!(registers[1], placement.siginfo_address());
        assert_eq!(registers[2], placement.ucontext_address());
        assert_eq!(registers[29], placement.frame_record_base());
        assert_eq!(registers[30], 0x5000_2000);
        assert_eq!(sp, placement.frame_base());
        assert_eq!(pc, 0x4000_1000);
    }

    #[test]
    fn non_siginfo_handler_preserves_x1_x2() {
        let placement = place_minimal_signal_frame(0x9000_0000).unwrap();
        let entry =
            Aarch64SignalHandlerEntry::new(15, 0x4000_1000, 0x5000_2000, placement, false).unwrap();
        let mut registers = [0u64; 31];
        registers[1] = 0xaaaa;
        registers[2] = 0xbbbb;
        let mut sp = 0;
        let mut pc = 0;
        entry.apply(&mut registers, &mut sp, &mut pc);
        assert_eq!(registers[1], 0xaaaa);
        assert_eq!(registers[2], 0xbbbb);
    }

    #[test]
    fn signal_zero_and_above_linux_max_are_rejected() {
        let placement = place_minimal_signal_frame(0x9000_0000).unwrap();
        assert_eq!(
            Aarch64SignalHandlerEntry::new(0, 1, 2, placement, false),
            Err(SignalEntryError::InvalidSignal)
        );
        assert_eq!(
            Aarch64SignalHandlerEntry::new(65, 1, 2, placement, false),
            Err(SignalEntryError::InvalidSignal)
        );
    }
}
