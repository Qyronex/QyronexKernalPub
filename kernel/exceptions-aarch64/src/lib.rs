// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "aarch64")]
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicUsize, Ordering};
use kernal_user_entry_aarch64::El0ReturnState;

pub const VECTOR_TABLE_ALIGNMENT: usize = 2048;
pub const VECTOR_SLOT_SIZE: usize = 128;
pub const VECTOR_COUNT: usize = 16;
pub const FRAME_BYTES: usize = core::mem::size_of::<ExceptionFrame>();
/// Synthetic first-run returns reserve the same 304-byte Rust frame plus the 16-byte x16/x17
/// temporary area consumed by a real vector entry. The existing restore epilogue advances SP by
/// exactly this amount before `eret`.
pub const SYNTHETIC_RETURN_BYTES: usize = FRAME_BYTES + 16;

const EC_SVC_AARCH64: u8 = 0x15;
const EC_INSTRUCTION_ABORT_LOWER_EL: u8 = 0x20;
const EC_INSTRUCTION_ABORT_CURRENT_EL: u8 = 0x21;
const EC_DATA_ABORT_LOWER_EL: u8 = 0x24;
const EC_DATA_ABORT_CURRENT_EL: u8 = 0x25;
const EC_BRK_AARCH64: u8 = 0x3c;
const ABORT_FAULT_STATUS_MASK: u32 = 0x3f;
const DATA_ABORT_WRITE: u32 = 1 << 6;
const ABORT_FAR_NOT_VALID: u32 = 1 << 10;
const SVC_IMMEDIATE_MASK: u32 = 0xffff;
const BRK_COMMENT_MASK: u32 = 0xffff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionKind {
    Synchronous,
    Irq,
    Fiq,
    SError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionSource {
    CurrentElSp0,
    CurrentElSpx,
    LowerElAarch64,
    LowerElAarch32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentElAarch64Synchronous {
    InstructionAbort {
        fault_status: u8,
        fault_address: Option<u64>,
    },
    DataAbort {
        fault_status: u8,
        write: bool,
        fault_address: Option<u64>,
    },
    Other {
        exception_class: u8,
        iss: u32,
    },
}

/// Decoded synchronous exception that originated from AArch64 EL0.
///
/// Steps 8 and 9 use this narrow architectural classification so runtime policy can distinguish
/// deliberate EL0 breakpoints, faults and native SVC entry without duplicating ESR_EL1 bit decoding.
/// Unknown lower-EL classes remain explicit and fail-closed at the policy layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LowerElAarch64Synchronous {
    SupervisorCall {
        immediate: u16,
    },
    Breakpoint {
        comment: u16,
    },
    InstructionAbort {
        fault_status: u8,
        fault_address: Option<u64>,
    },
    DataAbort {
        fault_status: u8,
        write: bool,
        fault_address: Option<u64>,
    },
    Other {
        exception_class: u8,
        iss: u32,
    },
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExceptionFrame {
    /// Architectural x0..x30 in register-number order.
    pub x: [u64; 31],
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    /// User stack pointer captured on exception entry and restored from this frame before `eret`.
    pub sp_el0: u64,
    vector: u64,
    /// Canonical per-PE TTBR0 switch generation sampled before any Rust lower-EL policy hook runs.
    /// Zero means the process-current generation was unavailable and Linux policy must fail closed.
    entry_switch_generation: u64,
}

impl ExceptionFrame {
    pub const fn vector_index(&self) -> usize {
        self.vector as usize
    }

    pub const fn kind(&self) -> ExceptionKind {
        match self.vector & 0x3 {
            0 => ExceptionKind::Synchronous,
            1 => ExceptionKind::Irq,
            2 => ExceptionKind::Fiq,
            _ => ExceptionKind::SError,
        }
    }

    pub const fn source(&self) -> ExceptionSource {
        match self.vector >> 2 {
            0 => ExceptionSource::CurrentElSp0,
            1 => ExceptionSource::CurrentElSpx,
            2 => ExceptionSource::LowerElAarch64,
            _ => ExceptionSource::LowerElAarch32,
        }
    }

    /// Returns the process-switch generation captured for this exact exception-frame instance.
    pub const fn entry_switch_generation(&self) -> u64 {
        self.entry_switch_generation
    }

    /// Rebinds this trapped frame to the exact nonzero user-switch generation now active for it.
    ///
    /// Exec replacement and an owner-controlled scheduler switch-away/switch-back both legitimately
    /// advance the architectural TTBR0 switch generation while the same trapped scheduler/Process
    /// generation retains this frame. The stale-frame guard therefore permits rebinding only after
    /// the exact intended binding has become current again.
    ///
    /// # Safety
    /// The caller must prove this frame still belongs to the exact current scheduler/Process
    /// generation and that the intended TTBR0 binding has already been activated. It must retain
    /// exclusive ownership of the frame through the final return/writeback window. Rebinding before
    /// activation, while a different scheduler generation is current, or to another Process breaks
    /// stale-frame rejection at the return and signal boundaries.
    pub unsafe fn rebind_entry_switch_generation(&mut self, generation: core::num::NonZeroU64) {
        self.entry_switch_generation = generation.get();
    }

    pub const fn exception_class(&self) -> u8 {
        ((self.esr_el1 >> 26) & 0x3f) as u8
    }

    pub const fn instruction_specific_syndrome(&self) -> u32 {
        (self.esr_el1 & 0x01ff_ffff) as u32
    }

    pub fn current_el_aarch64_synchronous(&self) -> Option<CurrentElAarch64Synchronous> {
        if self.kind() != ExceptionKind::Synchronous
            || !matches!(
                self.source(),
                ExceptionSource::CurrentElSp0 | ExceptionSource::CurrentElSpx
            )
        {
            return None;
        }

        let exception_class = self.exception_class();
        let iss = self.instruction_specific_syndrome();
        let fault_address = (iss & ABORT_FAR_NOT_VALID == 0).then_some(self.far_el1);
        Some(match exception_class {
            EC_INSTRUCTION_ABORT_CURRENT_EL => CurrentElAarch64Synchronous::InstructionAbort {
                fault_status: (iss & ABORT_FAULT_STATUS_MASK) as u8,
                fault_address,
            },
            EC_DATA_ABORT_CURRENT_EL => CurrentElAarch64Synchronous::DataAbort {
                fault_status: (iss & ABORT_FAULT_STATUS_MASK) as u8,
                write: iss & DATA_ABORT_WRITE != 0,
                fault_address,
            },
            _ => CurrentElAarch64Synchronous::Other {
                exception_class,
                iss,
            },
        })
    }

    /// Decodes the lower-EL AArch64 synchronous exceptions used by the current user-mode roadmap.
    ///
    /// Returns `None` for IRQ/FIQ/SError entries, current-EL exceptions, and AArch32 lower-EL
    /// entries. A lower-EL AArch64 synchronous exception with an unsupported EC is returned as
    /// [`LowerElAarch64Synchronous::Other`] rather than being silently reclassified.
    pub fn lower_el_aarch64_synchronous(&self) -> Option<LowerElAarch64Synchronous> {
        if self.kind() != ExceptionKind::Synchronous
            || self.source() != ExceptionSource::LowerElAarch64
        {
            return None;
        }

        let exception_class = self.exception_class();
        let iss = self.instruction_specific_syndrome();
        let fault_address = (iss & ABORT_FAR_NOT_VALID == 0).then_some(self.far_el1);
        Some(match exception_class {
            EC_SVC_AARCH64 => LowerElAarch64Synchronous::SupervisorCall {
                immediate: (iss & SVC_IMMEDIATE_MASK) as u16,
            },
            EC_BRK_AARCH64 => LowerElAarch64Synchronous::Breakpoint {
                comment: (iss & BRK_COMMENT_MASK) as u16,
            },
            EC_INSTRUCTION_ABORT_LOWER_EL => LowerElAarch64Synchronous::InstructionAbort {
                fault_status: (iss & ABORT_FAULT_STATUS_MASK) as u8,
                fault_address,
            },
            EC_DATA_ABORT_LOWER_EL => LowerElAarch64Synchronous::DataAbort {
                fault_status: (iss & ABORT_FAULT_STATUS_MASK) as u8,
                write: iss & DATA_ABORT_WRITE != 0,
                fault_address,
            },
            _ => LowerElAarch64Synchronous::Other {
                exception_class,
                iss,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyntheticReturnError {
    KernelStackMisaligned,
    KernelStackUnderflow,
}

/// Full-register first-run EL0 state that is restored by the same assembly epilogue used for a real
/// lower-EL exception return. The architectural return PC/SP/PSTATE remain represented by the
/// already validated [`El0ReturnState`]; this type adds only x0..x30 and the owned kernel exception
/// stack top needed to materialize the canonical `ExceptionFrame` layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticEl0Return {
    registers: [u64; 31],
    return_state: El0ReturnState,
    kernel_exception_sp: u64,
}

impl SyntheticEl0Return {
    pub fn new(
        registers: [u64; 31],
        return_state: El0ReturnState,
        kernel_exception_sp: u64,
    ) -> Result<Self, SyntheticReturnError> {
        if !kernel_exception_sp.is_multiple_of(16) {
            return Err(SyntheticReturnError::KernelStackMisaligned);
        }
        kernel_exception_sp
            .checked_sub(SYNTHETIC_RETURN_BYTES as u64)
            .ok_or(SyntheticReturnError::KernelStackUnderflow)?;
        Ok(Self {
            registers,
            return_state,
            kernel_exception_sp,
        })
    }

    pub const fn registers(&self) -> &[u64; 31] {
        &self.registers
    }

    pub const fn return_state(self) -> El0ReturnState {
        self.return_state
    }

    pub const fn kernel_exception_sp(self) -> u64 {
        self.kernel_exception_sp
    }

    pub const fn frame_base(self) -> u64 {
        self.kernel_exception_sp - SYNTHETIC_RETURN_BYTES as u64
    }
}

pub type ExceptionHandler = extern "C" fn(&mut ExceptionFrame);
/// Optional current-EL policy hook for recoverable synchronous AArch64 faults.
/// Returning `true` consumes the exception; `false` delegates it to the primary handler.
pub type CurrentElAarch64Handler = extern "C" fn(&mut ExceptionFrame) -> bool;
/// Optional user-mode policy hook for synchronous AArch64 exceptions originating below EL1.
/// Returning `true` consumes the exception; `false` delegates it to the primary handler.
pub type LowerElAarch64Handler = extern "C" fn(&mut ExceptionFrame) -> bool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    HandlerAlreadyInstalled,
    CurrentElHandlerAlreadyInstalled,
    LowerElHandlerAlreadyInstalled,
    LowerElHandlerMismatch,
    VectorTableMisaligned,
}

static HANDLER: AtomicUsize = AtomicUsize::new(0);
static CURRENT_EL_AARCH64_HANDLER: AtomicUsize = AtomicUsize::new(0);
static LOWER_EL_AARCH64_HANDLER: AtomicUsize = AtomicUsize::new(0);

pub fn install_handler(handler: ExceptionHandler) -> Result<(), Error> {
    let address = handler as *const () as usize;
    HANDLER
        .compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| Error::HandlerAlreadyInstalled)
}

pub fn install_current_el_aarch64_handler(handler: CurrentElAarch64Handler) -> Result<(), Error> {
    let address = handler as *const () as usize;
    CURRENT_EL_AARCH64_HANDLER
        .compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| Error::CurrentElHandlerAlreadyInstalled)
}

/// Installs a narrow policy hook for synchronous AArch64 exceptions taken from a lower EL.
///
/// The hook is intentionally narrower than the primary exception handler. IRQ/FIQ/SError and
/// current-EL synchronous exceptions never reach it. If it declines an exception, dispatch falls
/// through to the primary handler, preserving the existing fail-closed policy.
pub fn install_lower_el_aarch64_handler(handler: LowerElAarch64Handler) -> Result<(), Error> {
    let address = handler as *const () as usize;
    LOWER_EL_AARCH64_HANDLER
        .compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| Error::LowerElHandlerAlreadyInstalled)
}

/// Removes exactly the lower-EL hook previously installed by the caller.
///
/// The function compares the expected function address before clearing the slot, so one subsystem
/// cannot accidentally unregister another subsystem's handler after an ownership bug or race.
pub fn uninstall_lower_el_aarch64_handler(handler: LowerElAarch64Handler) -> Result<(), Error> {
    let address = handler as *const () as usize;
    LOWER_EL_AARCH64_HANDLER
        .compare_exchange(address, 0, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| Error::LowerElHandlerMismatch)
}

/// Installs the 2-KiB-aligned AArch64 vector table into VBAR_EL1.
///
/// # Safety
/// Caller must execute at EL1 or another level permitted to write VBAR_EL1. The text containing the
/// vector table must remain mapped executable and non-writable for the lifetime of exception use.
#[cfg(target_arch = "aarch64")]
pub unsafe fn install_vector_table() -> Result<u64, Error> {
    let address = vector_table_address();
    if address as usize & (VECTOR_TABLE_ALIGNMENT - 1) != 0 {
        return Err(Error::VectorTableMisaligned);
    }
    // SAFETY: delegated to caller; VBAR_EL1 requires a 2 KiB aligned executable address.
    unsafe {
        asm!("msr VBAR_EL1, {address}", address = in(reg) address, options(nomem, nostack));
        asm!("isb", options(nostack));
    }
    Ok(address)
}

#[cfg(target_arch = "aarch64")]
pub fn vector_table_address() -> u64 {
    unsafe extern "C" {
        static kernal_aarch64_vector_table: u8;
    }
    core::ptr::addr_of!(kernal_aarch64_vector_table) as u64
}

/// Materializes one canonical synthetic `ExceptionFrame` immediately below the caller-owned kernel
/// exception-stack top and enters the existing exception restore epilogue. No second GPR restore or
/// ERET sequence exists: both real exceptions and first-run schedulerable user threads converge on
/// `kernal_aarch64_exception_restore`.
///
/// # Safety
/// - Must execute at EL1 on the owner PE with interrupts/preemption/migration controlled by the
///   scheduler.
/// - The intended process TTBR0 root must already be active and remain current through `eret`.
/// - `state.kernel_exception_sp()` must be the top of a mapped, guarded, writable, non-executable
///   kernel stack owned exclusively by this exact thread, with at least `SYNTHETIC_RETURN_BYTES`
///   writable bytes below it.
/// - Per-thread architectural state not represented by `ExceptionFrame` (currently TPIDR_EL0) must
///   already have been installed for this exact scheduler generation.
///
/// This function never returns. The next lower-EL exception reuses the restored SP_EL1 top and
/// therefore grows a normal canonical frame over the synthetic first-run storage.
#[cfg(target_arch = "aarch64")]
pub unsafe fn resume_synthetic_el0(state: SyntheticEl0Return) -> ! {
    let frame_base = state.frame_base();
    let frame = ExceptionFrame {
        x: state.registers,
        elr_el1: state.return_state.return_pc(),
        spsr_el1: state.return_state.spsr_el1(),
        esr_el1: 0,
        far_el1: 0,
        sp_el0: state.return_state.user_sp(),
        vector: 8,
        entry_switch_generation: 0,
    };

    // SAFETY: delegated caller contract guarantees the exact 320-byte stack window is uniquely
    // writable. The first 304 bytes are the canonical Rust frame; the trailing 16 bytes correspond
    // to the vector-entry x16/x17 temporary area and are deterministically cleared.
    unsafe {
        core::ptr::write(frame_base as *mut ExceptionFrame, frame);
        core::ptr::write_bytes(
            (frame_base + FRAME_BYTES as u64) as *mut u8,
            0,
            SYNTHETIC_RETURN_BYTES - FRAME_BYTES,
        );
        asm!(
            "mov sp, {frame_base}",
            "b kernal_aarch64_exception_restore",
            frame_base = in(reg) frame_base,
            options(noreturn)
        )
    }
}

/// Host support never emulates a privileged EL0 exception return.
///
/// # Safety
/// This path always panics and is not runtime evidence.
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn resume_synthetic_el0(_state: SyntheticEl0Return) -> ! {
    panic!("AArch64 synthetic EL0 resume requires an AArch64 target")
}

/// Assembly calls this only after it has saved x0..x30 plus architectural exception metadata.
///
/// # Safety
/// `frame` must be the non-null, uniquely borrowed, writable `ExceptionFrame` allocated by the
/// current AArch64 exception-entry assembly on the active kernel exception stack. It must remain
/// valid for the complete dispatcher call and must not alias another mutable frame reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernal_aarch64_exception_dispatch(frame: *mut ExceptionFrame) {
    if frame.is_null() {
        fatal_unhandled_exception();
    }
    // SAFETY: delegated raw-frame contract guarantees a unique live frame for this dispatch. The
    // assembly initializes every field, including the generation slot, before Rust observes it.
    let frame = unsafe { &mut *frame };

    // Capture process-current identity before any lower-EL Rust policy hook can retain the frame or
    // switch address spaces. A later switch necessarily advances the canonical generation, so safe
    // Linux decode/writeback can reject this exact old frame even if a new process is current.
    frame.entry_switch_generation = if frame.source() == ExceptionSource::LowerElAarch64 {
        kernal_process_aarch64::current_user_switch_generation().unwrap_or(0)
    } else {
        0
    };

    if frame.kind() == ExceptionKind::Synchronous
        && matches!(
            frame.source(),
            ExceptionSource::CurrentElSp0 | ExceptionSource::CurrentElSpx
        )
    {
        let current_address = CURRENT_EL_AARCH64_HANDLER.load(Ordering::Acquire);
        if current_address != 0 {
            // SAFETY: the installer stores only the exact CurrentElAarch64Handler function type.
            let current_handler: CurrentElAarch64Handler =
                unsafe { core::mem::transmute(current_address) };
            if current_handler(frame) {
                return;
            }
        }
    }

    if frame.kind() == ExceptionKind::Synchronous
        && frame.source() == ExceptionSource::LowerElAarch64
    {
        let lower_address = LOWER_EL_AARCH64_HANDLER.load(Ordering::Acquire);
        if lower_address != 0 {
            // SAFETY: the installer stores only the exact LowerElAarch64Handler function type.
            let lower_handler: LowerElAarch64Handler =
                unsafe { core::mem::transmute(lower_address) };
            if lower_handler(frame) {
                return;
            }
        }
    }

    let address = HANDLER.load(Ordering::Acquire);
    if address == 0 {
        fatal_unhandled_exception();
    }
    // SAFETY: install_handler stores only values originating from the exact ExceptionHandler type;
    // AtomicUsize preserves that address bit-for-bit until loaded here.
    let handler: ExceptionHandler = unsafe { core::mem::transmute(address) };
    handler(frame);
}

fn fatal_unhandled_exception() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// Each vector slot first preserves x16/x17 before using x16 as the vector-index scratch register.
// The common path reserves exactly 304 bytes for the 304-byte ExceptionFrame, copies the saved
// x16/x17 into their canonical array positions, and leaves the temporary 16-byte pair outside the
// Rust-visible frame. Total exception-stack consumption remains 320 bytes, preserving AAPCS64
// 16-byte SP alignment and the accepted Step-9 exception-stack shape.
#[cfg(target_arch = "aarch64")]
global_asm!(
    r#"
    .section .text.kernal_aarch64_vectors, "ax"
    .balign 2048
    .global kernal_aarch64_vector_table
kernal_aarch64_vector_table:
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #0
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #1
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #2
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #3
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #4
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #5
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #6
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #7
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #8
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #9
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #10
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #11
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #12
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #13
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #14
    b kernal_aarch64_exception_common
    .balign 128
    sub sp, sp, #16
    stp x16, x17, [sp]
    mov x16, #15
    b kernal_aarch64_exception_common
    .balign 128

    .global kernal_aarch64_exception_common
kernal_aarch64_exception_common:
    sub sp, sp, #304
    stp x0,  x1,  [sp, #0]
    stp x2,  x3,  [sp, #16]
    stp x4,  x5,  [sp, #32]
    stp x6,  x7,  [sp, #48]
    stp x8,  x9,  [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]

    ldp x0, x1, [sp, #304]
    stp x0, x1, [sp, #128]

    mrs x0, ELR_EL1
    str x0, [sp, #248]
    mrs x0, SPSR_EL1
    str x0, [sp, #256]
    mrs x0, ESR_EL1
    str x0, [sp, #264]
    mrs x0, FAR_EL1
    str x0, [sp, #272]
    mrs x0, SP_EL0
    str x0, [sp, #280]
    str x16, [sp, #288]
    str xzr, [sp, #296]

    mov x0, sp
    bl kernal_aarch64_exception_dispatch

    .global kernal_aarch64_exception_restore
kernal_aarch64_exception_restore:
    ldr x16, [sp, #248]
    msr ELR_EL1, x16
    ldr x16, [sp, #256]
    msr SPSR_EL1, x16
    ldr x16, [sp, #280]
    msr SP_EL0, x16

    ldp x0,  x1,  [sp, #0]
    ldp x2,  x3,  [sp, #16]
    ldp x4,  x5,  [sp, #32]
    ldp x6,  x7,  [sp, #48]
    ldp x8,  x9,  [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #320
    eret
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(vector: u64, exception_class: u8, iss: u32, far_el1: u64) -> ExceptionFrame {
        ExceptionFrame {
            x: [0; 31],
            elr_el1: 0,
            spsr_el1: 0,
            esr_el1: ((exception_class as u64) << 26) | iss as u64,
            far_el1,
            sp_el0: 0,
            vector,
            entry_switch_generation: 0,
        }
    }

    #[test]
    fn rust_frame_layout_matches_assembly_offsets() {
        assert_eq!(FRAME_BYTES, 304);
        assert_eq!(SYNTHETIC_RETURN_BYTES, 320);
        let frame = ExceptionFrame {
            x: [0; 31],
            elr_el1: 0,
            spsr_el1: 0,
            esr_el1: 0,
            far_el1: 0,
            sp_el0: 0,
            vector: 0,
            entry_switch_generation: 0,
        };
        let base = &frame as *const ExceptionFrame as usize;
        assert_eq!((&frame.x[30] as *const u64 as usize) - base, 240);
        assert_eq!((&frame.elr_el1 as *const u64 as usize) - base, 248);
        assert_eq!((&frame.spsr_el1 as *const u64 as usize) - base, 256);
        assert_eq!((&frame.esr_el1 as *const u64 as usize) - base, 264);
        assert_eq!((&frame.far_el1 as *const u64 as usize) - base, 272);
        assert_eq!((&frame.sp_el0 as *const u64 as usize) - base, 280);
        assert_eq!((&frame.vector as *const u64 as usize) - base, 288);
        assert_eq!(
            (&frame.entry_switch_generation as *const u64 as usize) - base,
            296
        );
    }

    #[test]
    fn synthetic_return_reuses_validated_el0_state_and_exact_stack_shape() {
        let registers = core::array::from_fn(|index| 0x1000 + index as u64);
        let return_state =
            El0ReturnState::new(0x0000_0000_0003_0000, 0, 0x0000_0000_0008_0000).unwrap();
        let kernel_top = 0xffff_ffff_8040_0000;
        let state = SyntheticEl0Return::new(registers, return_state, kernel_top).unwrap();
        assert_eq!(state.registers(), &registers);
        assert_eq!(state.return_state(), return_state);
        assert_eq!(state.kernel_exception_sp(), kernel_top);
        assert_eq!(
            state.frame_base(),
            kernel_top - SYNTHETIC_RETURN_BYTES as u64
        );
        assert_eq!(state.frame_base() & 0xf, 0);
    }

    #[test]
    fn synthetic_return_rejects_misaligned_or_underflowing_kernel_stack() {
        let return_state =
            El0ReturnState::new(0x0000_0000_0003_0000, 0, 0x0000_0000_0008_0000).unwrap();
        assert_eq!(
            SyntheticEl0Return::new([0; 31], return_state, 0xffff_ffff_8040_0008),
            Err(SyntheticReturnError::KernelStackMisaligned)
        );
        assert_eq!(
            SyntheticEl0Return::new([0; 31], return_state, 0x100),
            Err(SyntheticReturnError::KernelStackUnderflow)
        );
    }

    #[test]
    fn vector_index_decodes_kind_and_source() {
        let mut frame = ExceptionFrame {
            x: [0; 31],
            elr_el1: 0,
            spsr_el1: 0,
            esr_el1: 0x15u64 << 26,
            far_el1: 0,
            sp_el0: 0,
            vector: 5,
            entry_switch_generation: 0,
        };
        assert_eq!(frame.kind(), ExceptionKind::Irq);
        assert_eq!(frame.source(), ExceptionSource::CurrentElSpx);
        assert_eq!(frame.exception_class(), 0x15);
        frame.vector = 8;
        assert_eq!(frame.kind(), ExceptionKind::Synchronous);
        assert_eq!(frame.source(), ExceptionSource::LowerElAarch64);
    }

    #[test]
    fn entry_switch_generation_is_frame_local_metadata() {
        let mut frame = frame(8, EC_SVC_AARCH64, 0, 0);
        assert_eq!(frame.entry_switch_generation(), 0);
        frame.entry_switch_generation = 41;
        assert_eq!(frame.entry_switch_generation(), 41);
    }

    #[test]
    fn current_el_data_abort_tracks_write_and_far() {
        let frame = frame(
            4,
            EC_DATA_ABORT_CURRENT_EL,
            DATA_ABORT_WRITE | 0x0f,
            0x2222_3000,
        );
        assert_eq!(
            frame.current_el_aarch64_synchronous(),
            Some(CurrentElAarch64Synchronous::DataAbort {
                fault_status: 0x0f,
                write: true,
                fault_address: Some(0x2222_3000),
            })
        );
    }

    #[test]
    fn current_el_classifier_rejects_lower_el_and_irq_entries() {
        assert_eq!(
            frame(8, EC_DATA_ABORT_CURRENT_EL, 0x04, 0).current_el_aarch64_synchronous(),
            None
        );
        assert_eq!(
            frame(5, EC_DATA_ABORT_CURRENT_EL, 0x04, 0).current_el_aarch64_synchronous(),
            None
        );
    }

    #[test]
    fn lower_el_svc_preserves_immediate() {
        let frame = frame(8, EC_SVC_AARCH64, 0x1234, 0);
        assert_eq!(
            frame.lower_el_aarch64_synchronous(),
            Some(LowerElAarch64Synchronous::SupervisorCall { immediate: 0x1234 })
        );
    }

    #[test]
    fn lower_el_breakpoint_preserves_brk_comment() {
        let frame = frame(8, EC_BRK_AARCH64, 0xbeef, 0);
        assert_eq!(
            frame.lower_el_aarch64_synchronous(),
            Some(LowerElAarch64Synchronous::Breakpoint { comment: 0xbeef })
        );
    }

    #[test]
    fn lower_el_instruction_abort_tracks_far_validity() {
        let valid = frame(8, EC_INSTRUCTION_ABORT_LOWER_EL, 0x05, 0x1234_5000);
        assert_eq!(
            valid.lower_el_aarch64_synchronous(),
            Some(LowerElAarch64Synchronous::InstructionAbort {
                fault_status: 0x05,
                fault_address: Some(0x1234_5000),
            })
        );

        let invalid = frame(
            8,
            EC_INSTRUCTION_ABORT_LOWER_EL,
            ABORT_FAR_NOT_VALID | 0x04,
            0xdead_beef,
        );
        assert_eq!(
            invalid.lower_el_aarch64_synchronous(),
            Some(LowerElAarch64Synchronous::InstructionAbort {
                fault_status: 0x04,
                fault_address: None,
            })
        );
    }

    #[test]
    fn lower_el_data_abort_tracks_write_and_far_validity() {
        let write = frame(
            8,
            EC_DATA_ABORT_LOWER_EL,
            DATA_ABORT_WRITE | 0x0d,
            0x4567_8000,
        );
        assert_eq!(
            write.lower_el_aarch64_synchronous(),
            Some(LowerElAarch64Synchronous::DataAbort {
                fault_status: 0x0d,
                write: true,
                fault_address: Some(0x4567_8000),
            })
        );

        let far_invalid = frame(
            8,
            EC_DATA_ABORT_LOWER_EL,
            ABORT_FAR_NOT_VALID | 0x04,
            0xdead_beef,
        );
        assert_eq!(
            far_invalid.lower_el_aarch64_synchronous(),
            Some(LowerElAarch64Synchronous::DataAbort {
                fault_status: 0x04,
                write: false,
                fault_address: None,
            })
        );
    }

    #[test]
    fn classifier_rejects_non_lower_el_aarch64_sync_entries() {
        assert_eq!(
            frame(4, EC_BRK_AARCH64, 1, 0).lower_el_aarch64_synchronous(),
            None
        );
        assert_eq!(
            frame(9, EC_BRK_AARCH64, 1, 0).lower_el_aarch64_synchronous(),
            None
        );
        assert_eq!(
            frame(12, EC_BRK_AARCH64, 1, 0).lower_el_aarch64_synchronous(),
            None
        );
    }

    #[test]
    fn unsupported_lower_el_sync_class_stays_explicit() {
        let frame = frame(8, 0x16, 0x12345, 0);
        assert_eq!(
            frame.lower_el_aarch64_synchronous(),
            Some(LowerElAarch64Synchronous::Other {
                exception_class: 0x16,
                iss: 0x12345,
            })
        );
    }
}
