// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86_64")]
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
#[cfg(target_arch = "x86_64")]
use kernal_arch_x86_64::idt;
use kernal_arch_x86_64::idt::{Entry, Table};
use kernal_descriptors_x86_64::Selector;

pub const EXCEPTION_VECTOR_COUNT: usize = 32;
pub const DOUBLE_FAULT_IST: u8 = 1;
pub const NMI_IST: u8 = 2;
pub const MACHINE_CHECK_IST: u8 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExceptionFrame {
    pub vector: u64,
    pub error_code: u64,
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub rflags: u64,
    pub fault_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawExceptionFrame {
    vector: u64,
    error_code: u64,
    instruction_pointer: u64,
    code_segment: u64,
    rflags: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtraGate {
    pub vector: u8,
    pub handler: u64,
    pub ist: u8,
    pub dpl: u8,
}

pub type ExceptionHandler = fn(ExceptionFrame) -> !;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized,
    InitializationInProgress,
    InvalidGate,
    DuplicateGate,
    HandlerAlreadyInstalled,
}

static HANDLER: AtomicUsize = AtomicUsize::new(0);

pub fn install_handler(handler: ExceptionHandler) -> Result<(), Error> {
    let pointer = handler as usize;
    match HANDLER.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(existing) if existing == pointer => Ok(()),
        Err(_) => Err(Error::HandlerAlreadyInstalled),
    }
}

pub struct ExceptionTableCell {
    state: AtomicU8,
    table: UnsafeCell<Table>,
}
// SAFETY: one successful initializer mutates the table; state=2 freezes it permanently.
unsafe impl Sync for ExceptionTableCell {}

impl ExceptionTableCell {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            table: UnsafeCell::new(Table::new()),
        }
    }

    pub fn prepare(
        &'static self,
        handler: ExceptionHandler,
    ) -> Result<PreparedIdt<'static>, Error> {
        self.prepare_with_gates(handler, &[])
    }

    pub fn prepare_with_gates(
        &'static self,
        handler: ExceptionHandler,
        extras: &[ExtraGate],
    ) -> Result<PreparedIdt<'static>, Error> {
        install_handler(handler)?;
        validate_extra_gates(extras)?;
        match self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(1) => return Err(Error::InitializationInProgress),
            Err(_) => return self.prepared().ok_or(Error::AlreadyInitialized),
        }
        // SAFETY: successful CAS grants exclusive initialization ownership.
        let table = unsafe { &mut *self.table.get() };
        for vector in 0u8..EXCEPTION_VECTOR_COUNT as u8 {
            let ist = match vector {
                8 => DOUBLE_FAULT_IST,
                2 => NMI_IST,
                18 => MACHINE_CHECK_IST,
                _ => 0,
            };
            let dpl = if vector == 3 { 3 } else { 0 };
            let gate =
                Entry::interrupt_gate(stub_address(vector), Selector::KERNEL_CODE.bits(), ist, dpl)
                    .ok_or(Error::InvalidGate)?;
            table.set(vector, gate);
        }
        for extra in extras {
            let gate = Entry::interrupt_gate(
                extra.handler,
                Selector::KERNEL_CODE.bits(),
                extra.ist,
                extra.dpl,
            )
            .ok_or(Error::InvalidGate)?;
            table.set(extra.vector, gate);
        }
        self.state.store(2, Ordering::Release);
        self.prepared().ok_or(Error::AlreadyInitialized)
    }

    pub fn prepared(&'static self) -> Option<PreparedIdt<'static>> {
        if self.state.load(Ordering::Acquire) != 2 {
            return None;
        }
        // SAFETY: state=2 means initialization completed and static table is immutable.
        Some(PreparedIdt {
            _table: unsafe { &*self.table.get() },
        })
    }
}
impl Default for ExceptionTableCell {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_extra_gates(extras: &[ExtraGate]) -> Result<(), Error> {
    for (index, gate) in extras.iter().enumerate() {
        if gate.vector < EXCEPTION_VECTOR_COUNT as u8
            || gate.handler == 0
            || gate.ist > 7
            || gate.dpl > 3
        {
            return Err(Error::InvalidGate);
        }
        if extras[..index]
            .iter()
            .any(|previous| previous.vector == gate.vector)
        {
            return Err(Error::DuplicateGate);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct PreparedIdt<'a> {
    _table: &'a Table,
}
impl PreparedIdt<'static> {
    /// # Safety
    /// Must execute at CPL0 after GDT/TSS load. Any requested IST slots must be live.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn load(self) {
        unsafe { idt::load(self._table) };
    }
}

#[unsafe(no_mangle)]
extern "C" fn kernal_exception_dispatch(raw: *const RawExceptionFrame) -> ! {
    if raw.is_null() {
        emergency_halt();
    }
    // SAFETY: every generated stub passes RSP at the normalized five-word prefix.
    let raw = unsafe { *raw };
    let frame = ExceptionFrame {
        vector: raw.vector,
        error_code: raw.error_code,
        instruction_pointer: raw.instruction_pointer,
        code_segment: raw.code_segment,
        rflags: raw.rflags,
        fault_address: if raw.vector == 14 { read_cr2() } else { 0 },
    };
    let pointer = HANDLER.load(Ordering::Acquire);
    if pointer == 0 {
        emergency_halt();
    }
    // SAFETY: install_handler stores only an ExceptionHandler function-pointer representation.
    let handler: ExceptionHandler = unsafe { core::mem::transmute(pointer) };
    handler(frame)
}

#[cfg(target_arch = "x86_64")]
fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: dispatcher is entered from the CPL0 exception IDT.
    unsafe { asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags)) };
    value
}

#[cfg(not(target_arch = "x86_64"))]
fn read_cr2() -> u64 {
    panic!("x86 CR2 is unavailable on this host architecture")
}

#[cfg(target_arch = "x86_64")]
fn emergency_halt() -> ! {
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn emergency_halt() -> ! {
    panic!("x86 exception dispatch is unavailable on this host architecture")
}

#[cfg(target_arch = "x86_64")]
fn stub_address(vector: u8) -> u64 {
    match vector {
        0 => kernal_exception_0 as *const () as usize as u64,
        1 => kernal_exception_1 as *const () as usize as u64,
        2 => kernal_exception_2 as *const () as usize as u64,
        3 => kernal_exception_3 as *const () as usize as u64,
        4 => kernal_exception_4 as *const () as usize as u64,
        5 => kernal_exception_5 as *const () as usize as u64,
        6 => kernal_exception_6 as *const () as usize as u64,
        7 => kernal_exception_7 as *const () as usize as u64,
        8 => kernal_exception_8 as *const () as usize as u64,
        9 => kernal_exception_9 as *const () as usize as u64,
        10 => kernal_exception_10 as *const () as usize as u64,
        11 => kernal_exception_11 as *const () as usize as u64,
        12 => kernal_exception_12 as *const () as usize as u64,
        13 => kernal_exception_13 as *const () as usize as u64,
        14 => kernal_exception_14 as *const () as usize as u64,
        15 => kernal_exception_15 as *const () as usize as u64,
        16 => kernal_exception_16 as *const () as usize as u64,
        17 => kernal_exception_17 as *const () as usize as u64,
        18 => kernal_exception_18 as *const () as usize as u64,
        19 => kernal_exception_19 as *const () as usize as u64,
        20 => kernal_exception_20 as *const () as usize as u64,
        21 => kernal_exception_21 as *const () as usize as u64,
        22 => kernal_exception_22 as *const () as usize as u64,
        23 => kernal_exception_23 as *const () as usize as u64,
        24 => kernal_exception_24 as *const () as usize as u64,
        25 => kernal_exception_25 as *const () as usize as u64,
        26 => kernal_exception_26 as *const () as usize as u64,
        27 => kernal_exception_27 as *const () as usize as u64,
        28 => kernal_exception_28 as *const () as usize as u64,
        29 => kernal_exception_29 as *const () as usize as u64,
        30 => kernal_exception_30 as *const () as usize as u64,
        31 => kernal_exception_31 as *const () as usize as u64,
        _ => unreachable_stub as *const () as usize as u64,
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn stub_address(vector: u8) -> u64 {
    // Host-only support-crate tests need a non-zero canonical-looking handler address,
    // but must never execute x86 exception entry code on a foreign ISA.
    const HOST_TEST_STUB_BASE: u64 = 0x0000_0000_0010_0000;
    HOST_TEST_STUB_BASE + u64::from(vector) * 16
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn kernal_exception_0();
    fn kernal_exception_1();
    fn kernal_exception_2();
    fn kernal_exception_3();
    fn kernal_exception_4();
    fn kernal_exception_5();
    fn kernal_exception_6();
    fn kernal_exception_7();
    fn kernal_exception_8();
    fn kernal_exception_9();
    fn kernal_exception_10();
    fn kernal_exception_11();
    fn kernal_exception_12();
    fn kernal_exception_13();
    fn kernal_exception_14();
    fn kernal_exception_15();
    fn kernal_exception_16();
    fn kernal_exception_17();
    fn kernal_exception_18();
    fn kernal_exception_19();
    fn kernal_exception_20();
    fn kernal_exception_21();
    fn kernal_exception_22();
    fn kernal_exception_23();
    fn kernal_exception_24();
    fn kernal_exception_25();
    fn kernal_exception_26();
    fn kernal_exception_27();
    fn kernal_exception_28();
    fn kernal_exception_29();
    fn kernal_exception_30();
    fn kernal_exception_31();
    fn unreachable_stub();
}

#[cfg(target_arch = "x86_64")]
global_asm!(
    r#"
    .macro EXC_NOERR n
    .global kernal_exception_\n
kernal_exception_\n:
    push 0
    push \n
    jmp kernal_exception_common
    .endm

    .macro EXC_ERR n
    .global kernal_exception_\n
kernal_exception_\n:
    push \n
    jmp kernal_exception_common
    .endm

    EXC_NOERR 0
    EXC_NOERR 1
    EXC_NOERR 2
    EXC_NOERR 3
    EXC_NOERR 4
    EXC_NOERR 5
    EXC_NOERR 6
    EXC_NOERR 7
    EXC_ERR   8
    EXC_NOERR 9
    EXC_ERR   10
    EXC_ERR   11
    EXC_ERR   12
    EXC_ERR   13
    EXC_ERR   14
    EXC_NOERR 15
    EXC_NOERR 16
    EXC_ERR   17
    EXC_NOERR 18
    EXC_NOERR 19
    EXC_NOERR 20
    EXC_ERR   21
    EXC_NOERR 22
    EXC_NOERR 23
    EXC_NOERR 24
    EXC_NOERR 25
    EXC_NOERR 26
    EXC_NOERR 27
    EXC_NOERR 28
    EXC_ERR   29
    EXC_ERR   30
    EXC_NOERR 31

    .global unreachable_stub
unreachable_stub:
    cli
2:
    hlt
    jmp 2b

kernal_exception_common:
    mov rdi, rsp
    and rsp, -16
    call kernal_exception_dispatch
    ud2
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy(_frame: ExceptionFrame) -> ! {
        panic!("not called")
    }

    #[test]
    fn fatal_vectors_use_distinct_ist_slots() {
        assert_eq!(DOUBLE_FAULT_IST, 1);
        assert_eq!(NMI_IST, 2);
        assert_eq!(MACHINE_CHECK_IST, 3);
    }

    #[test]
    fn all_exception_stub_addresses_are_nonzero() {
        for vector in 0..EXCEPTION_VECTOR_COUNT as u8 {
            assert_ne!(stub_address(vector), 0);
        }
    }

    #[test]
    fn external_gates_reject_exception_vectors_and_duplicates() {
        let invalid = [ExtraGate {
            vector: 3,
            handler: 1,
            ist: 0,
            dpl: 0,
        }];
        assert_eq!(validate_extra_gates(&invalid), Err(Error::InvalidGate));
        let duplicate = [
            ExtraGate {
                vector: 0xe0,
                handler: 1,
                ist: 0,
                dpl: 0,
            },
            ExtraGate {
                vector: 0xe0,
                handler: 2,
                ist: 0,
                dpl: 0,
            },
        ];
        assert_eq!(validate_extra_gates(&duplicate), Err(Error::DuplicateGate));
        let valid = [ExtraGate {
            vector: 0xe0,
            handler: dummy as *const () as usize as u64,
            ist: 0,
            dpl: 0,
        }];
        assert!(validate_extra_gates(&valid).is_ok());
    }
}
