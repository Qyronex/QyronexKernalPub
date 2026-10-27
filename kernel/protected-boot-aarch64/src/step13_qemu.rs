// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::RuntimeTablePool;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use kernal_exceptions_aarch64::{ExceptionFrame, LowerElAarch64Synchronous};
use kernal_linux_abi::{Errno, SyscallReturn, unsupported};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::ObjectTable;
use kernal_paging::PAGE_SIZE;
use kernal_process::{Personality, Process};
use kernal_process_aarch64::{ActiveProcess, BoundProcessAddressSpace};
use kernal_syscall_entry_aarch64::DecodedProcessSyscall;
use kernal_user_entry_aarch64::El0ReturnState;
use kernal_vm::{Backing, USER_MIN, VmPerms, Vma};

const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const RAM_END: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES;

// Step 12 owns [RAM_END-40 pages, RAM_END-16 pages). Step 11 starts at RAM_END-11 pages.
// Keep the Step-13 stack inside the proven free gap and continue reusing Step 9's immutable RX code.
const STEP12_POOL_END: u64 = RAM_END - (16 * PAGE_SIZE);
const STEP13_STACK_FRAME: u64 = RAM_END - (15 * PAGE_SIZE);
const STEP11_LOWEST_PROOF_FRAME: u64 = RAM_END - (11 * PAGE_SIZE);
const STEP9_CODE_FRAME: u64 = RAM_END - (6 * PAGE_SIZE);

const USER_ENTRY_VA: u64 = USER_MIN + 0x140_000;
const USER_STACK_VA: u64 = USER_MIN + 0x2c0_000;
const PROBE_INITIAL_X0: u64 = 0x5356_4300_0000_0013;
const PROBE_SYSCALL_NUMBER: u64 = 0xf009;
const PROBE_SYSCALLS: u8 = 3;
const PROBE_BRK_COMMENT: u16 = 0x0099;
const SVC_RETURN_OFFSETS: [u64; PROBE_SYSCALLS as usize] = [9 * 4, 10 * 4, 11 * 4];
const PROBE_BRK_OFFSET: u64 = 11 * 4;
const PSTATE_PAN_BIT: u64 = 1 << 22;

const ARG1_SENTINEL: u64 = 0x1111;
const ARG2_SENTINEL: u64 = 0x2222;
const ARG3_SENTINEL: u64 = 0x3333;
const ARG4_SENTINEL: u64 = 0x4444;
const ARG5_SENTINEL: u64 = 0x5555;
const X19_SENTINEL: u64 = 0x1919;
const X20_SENTINEL: u64 = 0x2020;

struct ActiveProofContext {
    process: Process<8>,
    space: BoundProcessAddressSpace<2>,
}

/// One-shot trusted process/address-space owner for the IRQ-masked Step-13 proof.
///
/// The process and the exact bound root are published together only after mapping preparation. The
/// exception path may borrow them only while this cell is ACTIVE, then derives an `ActiveProcess`
/// witness that independently rechecks the current PE's TTBR0 before every Linux ABI operation.
struct ActiveProcessCell {
    state: AtomicU8,
    storage: UnsafeCell<MaybeUninit<ActiveProofContext>>,
}

// SAFETY: the IRQ-masked BSP is the sole writer. It publishes one initialized immutable proof
// context with a release transition and never mutates it afterward. Exception readers acquire the
// ACTIVE state before borrowing it, and secondaries remain outside this BSP-only proof window.
unsafe impl Sync for ActiveProcessCell {}

impl ActiveProcessCell {
    const EMPTY: u8 = 0;
    const INITIALIZING: u8 = 1;
    const ACTIVE: u8 = 2;
    const INACTIVE: u8 = 3;

    const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::EMPTY),
            storage: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&'static self, context: ActiveProofContext) -> Result<(), ()> {
        self.state
            .compare_exchange(
                Self::EMPTY,
                Self::INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ())?;
        // SAFETY: the successful EMPTY -> INITIALIZING transition grants this BSP the sole write.
        unsafe { (*self.storage.get()).write(context) };
        self.state.store(Self::ACTIVE, Ordering::Release);
        Ok(())
    }

    fn with_active<R>(
        &'static self,
        operation: impl for<'a> FnOnce(&'a ActiveProofContext) -> R,
    ) -> Option<R> {
        if self.state.load(Ordering::Acquire) != Self::ACTIVE {
            return None;
        }
        // SAFETY: ACTIVE publishes an initialized immutable proof context. The IRQ-masked BSP
        // cannot deactivate this cell concurrently with its own synchronous exception handler. The
        // higher-ranked closure prevents either borrowed object from escaping this call.
        let context = unsafe { (&*self.storage.get()).assume_init_ref() };
        Some(operation(context))
    }

    fn deactivate(&'static self) -> Result<(), ()> {
        self.state
            .compare_exchange(
                Self::ACTIVE,
                Self::INACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| ())
    }
}

static ACTIVE_PROCESS: ActiveProcessCell = ActiveProcessCell::new();
static SVC_COUNT: AtomicU8 = AtomicU8::new(0);
static ROUNDTRIP_COMPLETE: AtomicBool = AtomicBool::new(false);
static ZERO_PAGE: [u8; PAGE_SIZE as usize] = [0; PAGE_SIZE as usize];

pub fn run(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    if kernal_arch_aarch64::current_exception_level() != 1 || !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 Linux personality proof requires IRQ-masked EL1\n",
        );
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal(serial, "KERNAL/ARM64: Step 13 requires PAN default-on\n");
    }

    let mut objects = ObjectTable::<8>::new();
    let process = Process::<8>::create(&mut objects, Personality::Linux).unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 Linux process creation failed\n",
        )
    });
    if process.personality() != Personality::Linux {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 process personality selection failed\n",
        );
    }

    let mut space = BoundProcessAddressSpace::<2>::create(&process, &objects, backend)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 13 Linux address-space creation failed\n",
            )
        });
    let reserved = proof_reservations().unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 proof reservation construction failed\n",
        )
    });
    prepare_linux_space(&process, &objects, &mut space, backend, &reserved).unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 Linux address-space preparation failed\n",
        )
    });

    SVC_COUNT.store(0, Ordering::Release);
    ROUNDTRIP_COMPLETE.store(false, Ordering::Release);
    ACTIVE_PROCESS
        .publish(ActiveProofContext { process, space })
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 13 active process was already published\n",
            )
        });

    kernal_exceptions_aarch64::install_lower_el_aarch64_handler(step13_lower_el_handler)
        .unwrap_or_else(|_| {
            let _ = ACTIVE_PROCESS.deactivate();
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 13 lower-EL handler install failed\n",
            )
        });

    let activation = ACTIVE_PROCESS.with_active(|active| {
        // SAFETY: this IRQ-masked BSP owns the prepared process/address-space switch window.
        unsafe { active.space.activate_owner(&active.process, &objects) }
    });
    if !matches!(activation, Some(Ok(()))) {
        abort_active(
            serial,
            "KERNAL/ARM64: Step 13 Linux TTBR0 activation failed\n",
        );
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        abort_active(
            serial,
            "KERNAL/ARM64: Step 13 PAN leaked before Linux EL0 entry\n",
        );
    }

    let user_sp = USER_STACK_VA
        .checked_add(PAGE_SIZE)
        .unwrap_or_else(|| crate::fatal_silent());
    let roundtrip = unsafe {
        kernal_user_entry_aarch64::enter_el0_qemu_roundtrip(
            USER_ENTRY_VA,
            user_sp,
            PROBE_INITIAL_X0,
        )
    };

    if unsafe { BoundProcessAddressSpace::<2>::deactivate() }.is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 TTBR0 deactivation serialization failed\n",
        );
    }
    if ACTIVE_PROCESS.deactivate().is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 active process deactivation failed\n",
        );
    }
    kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step13_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 13 lower-EL handler removal failed\n",
            )
        });

    if roundtrip.is_err()
        || SVC_COUNT.load(Ordering::Acquire) != PROBE_SYSCALLS
        || !ROUNDTRIP_COMPLETE.load(Ordering::Acquire)
        || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 13 Linux SVC/ERET roundtrip failed\n",
        );
    }

    serial
        .write_str("KERNAL/S13: ARM64 Linux personality SVC -> -ENOSYS -> ERET roundtrip passed\n");
    serial.write_str("KERNAL/S13: ARM64 syscall ABI selected from active live Process\n");
    serial.write_str("KERNAL/S13: ARM64 active Process witness matched trapped TTBR0 generation\n");
}

fn proof_reservations() -> Result<ReservationSet<4>, ()> {
    let state = crate::boot_state();
    if STEP12_POOL_END != RAM_END.checked_sub(16 * PAGE_SIZE).ok_or(())?
        || STEP13_STACK_FRAME < STEP12_POOL_END
        || STEP13_STACK_FRAME.checked_add(PAGE_SIZE).ok_or(())? > STEP11_LOWEST_PROOF_FRAME
        || STEP9_CODE_FRAME != RAM_END.checked_sub(6 * PAGE_SIZE).ok_or(())?
        || STEP13_STACK_FRAME < state.layout.bss.end
    {
        return Err(());
    }

    let mut reserved = ReservationSet::<4>::new();
    let kernel_len = state
        .layout
        .bss
        .end
        .checked_sub(state.layout.kernel_phys_base)
        .ok_or(())?;
    reserved
        .reserve(state.layout.kernel_phys_base, kernel_len)
        .map_err(|_| ())?;
    for region in state.physical_mmio.iter().copied() {
        reserved.reserve(region.base, region.size).map_err(|_| ())?;
    }

    for physical in [STEP13_STACK_FRAME, STEP9_CODE_FRAME] {
        let frame = PhysFrame::from_start_address(physical).ok_or(())?;
        if reserved.contains(frame) {
            return Err(());
        }
    }
    Ok(reserved)
}

fn prepare_linux_space(
    process: &Process<8>,
    objects: &ObjectTable<8>,
    space: &mut BoundProcessAddressSpace<2>,
    backend: &mut RuntimeTablePool,
    reserved: &ReservationSet<4>,
) -> Result<(), ()> {
    let code_frame = PhysFrame::from_start_address(STEP9_CODE_FRAME).ok_or(())?;
    let stack_frame = PhysFrame::from_start_address(STEP13_STACK_FRAME).ok_or(())?;
    let code_vma = Vma::new(
        USER_ENTRY_VA,
        PAGE_SIZE,
        VmPerms::READ.union(VmPerms::EXECUTE),
        Backing::Anonymous,
    )
    .map_err(|_| ())?;
    let stack_vma = Vma::new(
        USER_STACK_VA,
        PAGE_SIZE,
        VmPerms::READ.union(VmPerms::WRITE),
        Backing::Anonymous,
    )
    .map_err(|_| ())?;
    let handle = process.address_space_handle();

    space
        .map_user_page(
            process, objects, handle, backend, code_vma, code_frame, reserved,
        )
        .map_err(|_| ())?;
    space
        .map_user_page(
            process,
            objects,
            handle,
            backend,
            stack_vma,
            stack_frame,
            reserved,
        )
        .map_err(|_| ())?;

    if space
        .translate_user(process, objects, handle, backend, USER_ENTRY_VA)
        .map_err(|_| ())?
        != STEP9_CODE_FRAME
        || space
            .translate_user(process, objects, handle, backend, USER_STACK_VA)
            .map_err(|_| ())?
            != STEP13_STACK_FRAME
    {
        return Err(());
    }

    unsafe { space.activate_owner(process, objects) }.map_err(|_| ())?;
    let result = (|| {
        kernal_usercopy_aarch64::copy_to_user(USER_STACK_VA, &ZERO_PAGE).map_err(|_| ())?;
        if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
            return Err(());
        }
        Ok(())
    })();
    unsafe { BoundProcessAddressSpace::<2>::deactivate() }.map_err(|_| ())?;
    result
}

fn abort_active(serial: &crate::Serial, message: &str) -> ! {
    let _ = unsafe { BoundProcessAddressSpace::<2>::deactivate() };
    let _ = ACTIVE_PROCESS.deactivate();
    let _ = kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step13_lower_el_handler);
    crate::fatal(serial, message)
}

extern "C" fn step13_lower_el_handler(frame: &mut ExceptionFrame) -> bool {
    ACTIVE_PROCESS
        .with_active(|active| {
            if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
                crate::fatal_silent();
            }

            match frame.lower_el_aarch64_synchronous() {
                Some(LowerElAarch64Synchronous::SupervisorCall { immediate }) if immediate == 0 => {
                    let current = active
                        .space
                        .current_owner(&active.process)
                        .unwrap_or_else(|_| crate::fatal_silent());
                    handle_svc(&current, frame)
                }
                Some(LowerElAarch64Synchronous::Breakpoint { comment })
                    if comment == PROBE_BRK_COMMENT =>
                {
                    handle_terminal_brk(frame)
                }
                _ => crate::fatal_silent(),
            }
        })
        .unwrap_or(false)
}

fn handle_svc(current: &ActiveProcess<'_, 8, 2>, frame: &mut ExceptionFrame) -> bool {
    let call = SVC_COUNT.load(Ordering::Acquire);
    if call >= PROBE_SYSCALLS {
        crate::fatal_silent();
    }

    let expected_pc = USER_ENTRY_VA
        .checked_add(SVC_RETURN_OFFSETS[call as usize])
        .unwrap_or_else(|| crate::fatal_silent());
    let expected_sp = USER_STACK_VA
        .checked_add(PAGE_SIZE)
        .unwrap_or_else(|| crate::fatal_silent());
    let state = kernal_syscall_entry_aarch64::validate_linux_return(current, frame)
        .unwrap_or_else(|_| crate::fatal_silent());
    let expected_x0 = if call == 0 {
        PROBE_INITIAL_X0
    } else {
        SyscallReturn::error(Errno::ENOSYS).as_u64_bits()
    };
    if state.return_pc() != expected_pc
        || state.user_sp() != expected_sp
        || !registers_match(frame, expected_x0)
    {
        crate::fatal_silent();
    }

    let request = match kernal_syscall_entry_aarch64::decode_process_syscall(current, frame)
        .unwrap_or_else(|_| crate::fatal_silent())
    {
        DecodedProcessSyscall::Linux(request) => request,
        DecodedProcessSyscall::Native(_) => crate::fatal_silent(),
    };
    if request.number != PROBE_SYSCALL_NUMBER
        || request.args[0] != expected_x0
        || request.args[1] != ARG1_SENTINEL
        || request.args[2] != ARG2_SENTINEL
        || request.args[3] != ARG3_SENTINEL
        || request.args[4] != ARG4_SENTINEL
        || request.args[5] != ARG5_SENTINEL
    {
        crate::fatal_silent();
    }

    let result = unsupported(request);
    if result != SyscallReturn::error(Errno::ENOSYS) {
        crate::fatal_silent();
    }
    kernal_syscall_entry_aarch64::apply_linux_return(current, frame, result)
        .unwrap_or_else(|_| crate::fatal_silent());
    if !registers_match(frame, result.as_u64_bits()) {
        crate::fatal_silent();
    }

    if SVC_COUNT
        .compare_exchange(call, call + 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::fatal_silent();
    }
    true
}

fn handle_terminal_brk(frame: &mut ExceptionFrame) -> bool {
    let expected_pc = USER_ENTRY_VA
        .checked_add(PROBE_BRK_OFFSET)
        .unwrap_or_else(|| crate::fatal_silent());
    let expected_sp = USER_STACK_VA
        .checked_add(PAGE_SIZE)
        .unwrap_or_else(|| crate::fatal_silent());
    let state = El0ReturnState::new(frame.elr_el1, frame.spsr_el1, frame.sp_el0)
        .unwrap_or_else(|_| crate::fatal_silent());
    let enosys = SyscallReturn::error(Errno::ENOSYS).as_u64_bits();
    if SVC_COUNT.load(Ordering::Acquire) != PROBE_SYSCALLS
        || state.return_pc() != expected_pc
        || state.user_sp() != expected_sp
        || !registers_match(frame, enosys)
    {
        crate::fatal_silent();
    }

    frame.elr_el1 = qemu_resume_high_address().unwrap_or_else(|_| crate::fatal_silent());
    frame.spsr_el1 = kernal_user_entry_aarch64::QEMU_PROBE_RESUME_SPSR_EL1 | PSTATE_PAN_BIT;
    if ROUNDTRIP_COMPLETE.swap(true, Ordering::AcqRel) {
        crate::fatal_silent();
    }
    true
}

fn registers_match(frame: &ExceptionFrame, expected_x0: u64) -> bool {
    frame.x[0] == expected_x0
        && frame.x[1] == ARG1_SENTINEL
        && frame.x[2] == ARG2_SENTINEL
        && frame.x[3] == ARG3_SENTINEL
        && frame.x[4] == ARG4_SENTINEL
        && frame.x[5] == ARG5_SENTINEL
        && frame.x[8] == PROBE_SYSCALL_NUMBER
        && frame.x[19] == X19_SENTINEL
        && frame.x[20] == X20_SENTINEL
}

fn qemu_resume_high_address() -> Result<u64, ()> {
    let state = crate::boot_state();
    let address = kernal_user_entry_aarch64::qemu_probe_resume_address();
    let physical = state.layout.physical_text_entry(address).map_err(|_| ())?;
    let high = state.layout.high_alias(physical).map_err(|_| ())?;
    if high < state.layout.kernel_virt_base {
        return Err(());
    }
    Ok(high)
}
