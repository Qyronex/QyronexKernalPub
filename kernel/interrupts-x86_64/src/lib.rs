// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicUsize, Ordering};
use kernal_exceptions_x86_64::ExtraGate;

pub const TIMER_VECTOR: u8 = 0xe0;
pub const RESCHEDULE_VECTOR: u8 = 0xe1;
pub const SPURIOUS_VECTOR: u8 = 0xff;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub rflags: u64,
}

impl InterruptFrame {
    pub const fn from_user_mode(&self) -> bool {
        self.code_segment & 3 != 0
    }
}

pub type InterruptHandler = fn(&mut InterruptFrame);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    HandlerAlreadyInstalled,
}

static HANDLER: AtomicUsize = AtomicUsize::new(0);

pub fn install_handler(handler: InterruptHandler) -> Result<(), Error> {
    let pointer = handler as usize;
    match HANDLER.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(existing) if existing == pointer => Ok(()),
        Err(_) => Err(Error::HandlerAlreadyInstalled),
    }
}

pub fn idt_gates() -> [ExtraGate; 3] {
    [
        ExtraGate {
            vector: TIMER_VECTOR,
            handler: stub_address(TIMER_VECTOR),
            ist: 0,
            dpl: 0,
        },
        ExtraGate {
            vector: RESCHEDULE_VECTOR,
            handler: stub_address(RESCHEDULE_VECTOR),
            ist: 0,
            dpl: 0,
        },
        ExtraGate {
            vector: SPURIOUS_VECTOR,
            handler: stub_address(SPURIOUS_VECTOR),
            ist: 0,
            dpl: 0,
        },
    ]
}

#[unsafe(no_mangle)]
extern "C" fn kernal_interrupt_dispatch(raw: *mut InterruptFrame) {
    if raw.is_null() {
        emergency_halt();
    }
    // SAFETY: generated stubs save exactly InterruptFrame's register/prefix layout before call.
    let frame = unsafe { &mut *raw };
    // Ring-3 interrupt entry requires SWAPGS/user-stack semantics not enabled yet. Fail closed if
    // such a transition becomes possible before the dedicated syscall/user IRQ entry lands.
    if frame.from_user_mode() {
        emergency_halt();
    }
    let pointer = HANDLER.load(Ordering::Acquire);
    if pointer == 0 {
        emergency_halt();
    }
    // SAFETY: install_handler stores only InterruptHandler function-pointer representations.
    let handler: InterruptHandler = unsafe { core::mem::transmute(pointer) };
    handler(frame);
}

#[cfg(target_arch = "x86_64")]
fn emergency_halt() -> ! {
    loop {
        // SAFETY: terminal kernel interrupt path.
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn emergency_halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn stub_address(vector: u8) -> u64 {
    match vector {
        TIMER_VECTOR => kernal_interrupt_e0 as *const () as usize as u64,
        RESCHEDULE_VECTOR => kernal_interrupt_e1 as *const () as usize as u64,
        SPURIOUS_VECTOR => kernal_interrupt_ff as *const () as usize as u64,
        _ => 0,
    }
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn kernal_interrupt_e0();
    fn kernal_interrupt_e1();
    fn kernal_interrupt_ff();
}

#[cfg(not(target_arch = "x86_64"))]
extern "C" fn kernal_interrupt_e0() {}
#[cfg(not(target_arch = "x86_64"))]
extern "C" fn kernal_interrupt_e1() {}
#[cfg(not(target_arch = "x86_64"))]
extern "C" fn kernal_interrupt_ff() {}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .macro IRQ_STUB name, vector
    .global \name
\name:
    push \vector
    jmp kernal_interrupt_common
    .endm

    IRQ_STUB kernal_interrupt_e0, 0xe0
    IRQ_STUB kernal_interrupt_e1, 0xe1
    IRQ_STUB kernal_interrupt_ff, 0xff

kernal_interrupt_common:
    cld
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, rsp
    mov rax, rsp
    and rsp, -16
    sub rsp, 16
    mov [rsp], rax
    call kernal_interrupt_dispatch
    mov rsp, [rsp]

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 8
    iretq
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_irq_vectors_are_unique_and_outside_exception_range() {
        let gates = idt_gates();
        assert!(
            gates
                .iter()
                .all(|gate| gate.vector >= 32 && gate.handler != 0)
        );
        assert_ne!(gates[0].vector, gates[1].vector);
        assert_ne!(gates[0].vector, gates[2].vector);
        assert_ne!(gates[1].vector, gates[2].vector);
    }

    #[test]
    fn frame_detects_privilege_transition_by_cs_rpl() {
        let mut frame: InterruptFrame = unsafe { core::mem::zeroed() };
        frame.code_segment = 0x08;
        assert!(!frame.from_user_mode());
        frame.code_segment = 0x23;
        assert!(frame.from_user_mode());
    }
}
