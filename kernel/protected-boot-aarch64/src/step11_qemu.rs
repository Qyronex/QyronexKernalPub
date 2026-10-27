// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::RuntimeTablePool;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use kernal_exceptions_aarch64::{ExceptionFrame, LowerElAarch64Synchronous};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::ObjectTable;
use kernal_paging::PAGE_SIZE;
use kernal_process::{Personality, Process, ProcessState};
use kernal_process_aarch64::{BoundProcessAddressSpace, Error as ProcessSpaceError};
use kernal_user_entry_aarch64::El0ReturnState;
use kernal_vm::{Backing, USER_MIN, VmPerms, Vma};

const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const STEP11_A_STACK_FRAME: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES - (11 * PAGE_SIZE);
const STEP11_A_DATA_FRAME: u64 = STEP11_A_STACK_FRAME + PAGE_SIZE;
const STEP11_B_STACK_FRAME: u64 = STEP11_A_DATA_FRAME + PAGE_SIZE;
const STEP11_B_DATA_FRAME: u64 = STEP11_B_STACK_FRAME + PAGE_SIZE;
const STEP10_DATA_FRAME: u64 = STEP11_B_DATA_FRAME + PAGE_SIZE;
const STEP9_CODE_FRAME: u64 = STEP10_DATA_FRAME + PAGE_SIZE;

// Reuse the accepted Step-9 native payload at the same virtual entry. The physical page is immutable
// after Step 9 prepares and executes it, so both processes may safely share it RX while retaining
// independent stacks and data mappings.
const USER_ENTRY_VA: u64 = USER_MIN + 0x140_000;
const USER_STACK_VA: u64 = USER_MIN + 0x240_000;
const USER_DATA_VA: u64 = USER_MIN + 0x280_000;
const PROBE_BRK_COMMENT: u16 = 0x0099;
const PROBE_SYSCALLS: u8 = 3;
const SVC_RETURN_OFFSETS: [u64; PROBE_SYSCALLS as usize] = [9 * 4, 10 * 4, 11 * 4];
const PROBE_BRK_OFFSET: u64 = 11 * 4;
const PSTATE_PAN_BIT: u64 = 1 << 22;

const ARG1_SENTINEL: u64 = 0x1111;
const ARG2_SENTINEL: u64 = 0x2222;
const ARG3_SENTINEL: u64 = 0x3333;
const ARG4_SENTINEL: u64 = 0x4444;
const ARG5_SENTINEL: u64 = 0x5555;
const PROBE_SYSCALL_NUMBER: u64 = 0xf009;
const X19_SENTINEL: u64 = 0x1919;
const X20_SENTINEL: u64 = 0x2020;

const PROCESS_NONE: u8 = 0;
const PROCESS_A: u8 = 1;
const PROCESS_B: u8 = 2;
const PROCESS_A_X0: u64 = 0x11a0;
const PROCESS_B_X0: u64 = 0x11b0;
const PROCESS_A_DATA_INITIAL: u64 = 0xa11a_0000_0000_0011;
const PROCESS_B_DATA_INITIAL: u64 = 0xb11b_0000_0000_0022;
const PROCESS_A_DATA_AFTER: u64 = 0xa11a_ffff_0000_0011;
const PROCESS_B_DATA_AFTER: u64 = 0xb11b_ffff_0000_0022;

static ACTIVE_PROCESS: AtomicU8 = AtomicU8::new(PROCESS_NONE);
static SVC_COUNT: AtomicU8 = AtomicU8::new(0);
static ROUNDTRIP_COMPLETE: AtomicBool = AtomicBool::new(false);
static ZERO_PAGE: [u8; PAGE_SIZE as usize] = [0; PAGE_SIZE as usize];

pub fn run(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    if kernal_arch_aarch64::current_exception_level() != 1 || !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 process isolation proof requires IRQ-masked EL1\n",
        );
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal(serial, "KERNAL/ARM64: Step 11 requires PAN default-on\n");
    }

    let mut objects = ObjectTable::<8>::new();
    let mut left = Process::<8>::create(&mut objects, Personality::Native).unwrap_or_else(|_| {
        crate::fatal(serial, "KERNAL/ARM64: Step 11 process A creation failed\n")
    });
    let mut right = Process::<8>::create(&mut objects, Personality::Native).unwrap_or_else(|_| {
        crate::fatal(serial, "KERNAL/ARM64: Step 11 process B creation failed\n")
    });
    if left.id() == right.id()
        || left.address_space() == right.address_space()
        || left.address_space_handle() != right.address_space_handle()
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 process identity contract failed\n",
        );
    }

    let mut left_space = BoundProcessAddressSpace::<3>::create(&left, &objects, backend)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 process A root creation failed\n",
            )
        });
    let mut right_space = BoundProcessAddressSpace::<3>::create(&right, &objects, backend)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 process B root creation failed\n",
            )
        });

    let reserved = proof_reservations().unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 reservation construction failed\n",
        )
    });
    prepare_process_space(
        &left,
        &objects,
        &mut left_space,
        backend,
        &reserved,
        STEP11_A_STACK_FRAME,
        STEP11_A_DATA_FRAME,
        PROCESS_A_DATA_INITIAL,
    )
    .unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 process A space preparation failed\n",
        )
    });
    prepare_process_space(
        &right,
        &objects,
        &mut right_space,
        backend,
        &reserved,
        STEP11_B_STACK_FRAME,
        STEP11_B_DATA_FRAME,
        PROCESS_B_DATA_INITIAL,
    )
    .unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 process B space preparation failed\n",
        )
    });

    // Equal numeric handles in two private CSpaces must not authorize another process's root.
    if left_space.translate_user(
        &right,
        &objects,
        right.address_space_handle(),
        backend,
        USER_DATA_VA,
    ) != Err(ProcessSpaceError::WrongAddressSpace)
        || unsafe { left_space.activate_owner(&right, &objects) }
            != Err(ProcessSpaceError::WrongProcess)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 cross-process authority isolation failed\n",
        );
    }
    serial.write_str("KERNAL/S11: ARM64 cross-process CSpace authority denied\n");

    let mut thread_proof =
        crate::step11_thread_qemu::Step11ThreadProof::prepare(&mut objects, &mut left, &mut right)
            .unwrap_or_else(|_| {
                crate::fatal(
                    serial,
                    "KERNAL/ARM64: Step 11 scheduler/thread ownership preparation failed\n",
                )
            });
    serial.write_str(
        "KERNAL/S11: ARM64 process-local Thread capabilities bound to scheduler generations\n",
    );

    kernal_exceptions_aarch64::install_lower_el_aarch64_handler(step11_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 lower-EL handler install failed\n",
            )
        });

    thread_proof
        .schedule_left(&objects, &left)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 process A scheduling failed\n",
            )
        });
    run_native_process(
        serial,
        &left,
        &objects,
        &left_space,
        PROCESS_A,
        PROCESS_A_X0,
    );
    verify_and_replace_data(
        serial,
        &left,
        &objects,
        &left_space,
        PROCESS_A_DATA_INITIAL,
        PROCESS_A_DATA_AFTER,
        "KERNAL/ARM64: Step 11 process A data verification failed\n",
    );
    thread_proof
        .finish_left(&mut objects, &mut left)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 process A thread reap/release failed\n",
            )
        });
    serial.write_str(
        "KERNAL/S11: ARM64 process A native EL0 run + stale scheduler/thread handles rejected\n",
    );

    // Switching from A to B must expose B's distinct physical frame at the identical USER_DATA_VA.
    verify_data(
        serial,
        &right,
        &objects,
        &right_space,
        PROCESS_B_DATA_INITIAL,
        "KERNAL/ARM64: Step 11 stale A translation leaked into process B\n",
    );
    thread_proof
        .schedule_right(&objects, &right)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 process B scheduling failed\n",
            )
        });
    run_native_process(
        serial,
        &right,
        &objects,
        &right_space,
        PROCESS_B,
        PROCESS_B_X0,
    );
    verify_and_replace_data(
        serial,
        &right,
        &objects,
        &right_space,
        PROCESS_B_DATA_INITIAL,
        PROCESS_B_DATA_AFTER,
        "KERNAL/ARM64: Step 11 process B data verification failed\n",
    );
    thread_proof
        .finish_right(&mut objects, &mut right)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 process B thread reap/release failed\n",
            )
        });
    serial.write_str(
        "KERNAL/S11: ARM64 process B native EL0 run + stale scheduler/thread handles rejected\n",
    );

    // Switch back to A. A must still resolve its own modified frame, never B's last active mapping.
    verify_data(
        serial,
        &left,
        &objects,
        &left_space,
        PROCESS_A_DATA_AFTER,
        "KERNAL/ARM64: Step 11 stale B translation leaked into process A\n",
    );
    serial.write_str(
        "KERNAL/S11: ARM64 same-VA process address spaces isolated across TTBR0 switches\n",
    );

    kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step11_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 lower-EL handler removal failed\n",
            )
        });

    thread_proof
        .exit_processes(&mut objects, &mut left, &mut right)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 11 process exit/revocation proof failed\n",
            )
        });
    serial.write_str(
        "KERNAL/S11: ARM64 process exit revoked delegated authority after thread teardown\n",
    );

    if ACTIVE_PROCESS.load(Ordering::Acquire) != PROCESS_NONE
        || left.state() != ProcessState::Exited
        || right.state() != ProcessState::Exited
        || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 process proof postcondition failed\n",
        );
    }
}

fn proof_reservations() -> Result<ReservationSet<4>, ()> {
    let state = crate::boot_state();
    let qemu_ram_end = crate::QEMU_VIRT_RAM_BASE
        .checked_add(QEMU_RAM_BYTES)
        .ok_or(())?;
    let expected_step10_data = qemu_ram_end.checked_sub(7 * PAGE_SIZE).ok_or(())?;
    let expected_step9_code = qemu_ram_end.checked_sub(6 * PAGE_SIZE).ok_or(())?;
    if STEP10_DATA_FRAME != expected_step10_data
        || STEP9_CODE_FRAME != expected_step9_code
        || STEP11_A_STACK_FRAME.checked_add(PAGE_SIZE) != Some(STEP11_A_DATA_FRAME)
        || STEP11_A_DATA_FRAME.checked_add(PAGE_SIZE) != Some(STEP11_B_STACK_FRAME)
        || STEP11_B_STACK_FRAME.checked_add(PAGE_SIZE) != Some(STEP11_B_DATA_FRAME)
        || STEP11_B_DATA_FRAME.checked_add(PAGE_SIZE) != Some(STEP10_DATA_FRAME)
        || STEP11_A_STACK_FRAME < state.layout.bss.end
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

    for physical in [
        STEP11_A_STACK_FRAME,
        STEP11_A_DATA_FRAME,
        STEP11_B_STACK_FRAME,
        STEP11_B_DATA_FRAME,
    ] {
        let frame = PhysFrame::from_start_address(physical).ok_or(())?;
        if reserved.contains(frame) {
            return Err(());
        }
    }
    Ok(reserved)
}

#[allow(clippy::too_many_arguments)]
fn prepare_process_space<const CAPS: usize>(
    process: &Process<CAPS>,
    objects: &ObjectTable<8>,
    space: &mut BoundProcessAddressSpace<3>,
    backend: &mut RuntimeTablePool,
    reserved: &ReservationSet<4>,
    stack_physical: u64,
    data_physical: u64,
    initial_data: u64,
) -> Result<(), ()> {
    let code_frame = PhysFrame::from_start_address(STEP9_CODE_FRAME).ok_or(())?;
    let stack_frame = PhysFrame::from_start_address(stack_physical).ok_or(())?;
    let data_frame = PhysFrame::from_start_address(data_physical).ok_or(())?;

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
    let data_vma = Vma::new(
        USER_DATA_VA,
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
    space
        .map_user_page(
            process, objects, handle, backend, data_vma, data_frame, reserved,
        )
        .map_err(|_| ())?;

    if space
        .translate_user(process, objects, handle, backend, USER_ENTRY_VA)
        .map_err(|_| ())?
        != STEP9_CODE_FRAME
        || space
            .translate_user(process, objects, handle, backend, USER_STACK_VA)
            .map_err(|_| ())?
            != stack_physical
        || space
            .translate_user(process, objects, handle, backend, USER_DATA_VA)
            .map_err(|_| ())?
            != data_physical
    {
        return Err(());
    }

    // PAN is already enabled after Step 10. Populate writable user pages only through the accepted
    // bounded usercopy primitive; never open a second privileged user-access mechanism here.
    unsafe { space.activate_owner(process, objects) }.map_err(|_| ())?;
    let init_result = (|| {
        kernal_usercopy_aarch64::copy_to_user(USER_STACK_VA, &ZERO_PAGE).map_err(|_| ())?;
        kernal_usercopy_aarch64::copy_to_user(USER_DATA_VA, &ZERO_PAGE).map_err(|_| ())?;
        kernal_usercopy_aarch64::copy_to_user(USER_DATA_VA, &initial_data.to_le_bytes())
            .map_err(|_| ())?;
        let mut observed = [0u8; core::mem::size_of::<u64>()];
        kernal_usercopy_aarch64::copy_from_user(&mut observed, USER_DATA_VA).map_err(|_| ())?;
        if u64::from_le_bytes(observed) != initial_data
            || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
        {
            return Err(());
        }
        Ok(())
    })();
    unsafe { BoundProcessAddressSpace::<3>::deactivate() }.map_err(|_| ())?;
    init_result
}

fn run_native_process<const CAPS: usize>(
    serial: &crate::Serial,
    process: &Process<CAPS>,
    objects: &ObjectTable<8>,
    space: &BoundProcessAddressSpace<3>,
    active: u8,
    initial_x0: u64,
) {
    SVC_COUNT.store(0, Ordering::Release);
    ROUNDTRIP_COMPLETE.store(false, Ordering::Release);
    if ACTIVE_PROCESS
        .compare_exchange(PROCESS_NONE, active, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::fatal(serial, "KERNAL/ARM64: Step 11 process proof state reused\n");
    }

    if unsafe { space.activate_owner(process, objects) }.is_err() {
        ACTIVE_PROCESS.store(PROCESS_NONE, Ordering::Release);
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 process TTBR0 activation failed\n",
        );
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        abort_active_process(
            serial,
            "KERNAL/ARM64: Step 11 PAN state leaked before EL0 entry\n",
        );
    }

    let user_sp = USER_STACK_VA
        .checked_add(PAGE_SIZE)
        .unwrap_or_else(|| crate::fatal_silent());
    let roundtrip = unsafe {
        kernal_user_entry_aarch64::enter_el0_qemu_roundtrip(USER_ENTRY_VA, user_sp, initial_x0)
    };
    if roundtrip.is_err()
        || SVC_COUNT.load(Ordering::Acquire) != PROBE_SYSCALLS
        || !ROUNDTRIP_COMPLETE.load(Ordering::Acquire)
    {
        abort_active_process(
            serial,
            "KERNAL/ARM64: Step 11 native EL0 roundtrip failed\n",
        );
    }

    if unsafe { BoundProcessAddressSpace::<3>::deactivate() }.is_err() {
        ACTIVE_PROCESS.store(PROCESS_NONE, Ordering::Release);
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 TTBR0 deactivation serialization failed\n",
        );
    }
    ACTIVE_PROCESS.store(PROCESS_NONE, Ordering::Release);
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 PAN state leaked after EL0 execution\n",
        );
    }
}

fn abort_active_process(serial: &crate::Serial, message: &str) -> ! {
    // Abort paths never resume user or proof execution, so deactivation is explicitly best effort.
    let _ = unsafe { BoundProcessAddressSpace::<3>::deactivate() };
    ACTIVE_PROCESS.store(PROCESS_NONE, Ordering::Release);
    crate::fatal(serial, message)
}

fn verify_and_replace_data<const CAPS: usize>(
    serial: &crate::Serial,
    process: &Process<CAPS>,
    objects: &ObjectTable<8>,
    space: &BoundProcessAddressSpace<3>,
    expected: u64,
    replacement: u64,
    message: &str,
) {
    if unsafe { space.activate_owner(process, objects) }.is_err() {
        crate::fatal(serial, message);
    }
    let result = (|| {
        let current = read_user_u64()?;
        if current != expected {
            return Err(());
        }
        kernal_usercopy_aarch64::copy_to_user(USER_DATA_VA, &replacement.to_le_bytes())
            .map_err(|_| ())?;
        if read_user_u64()? != replacement || kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
            return Err(());
        }
        Ok(())
    })();
    if unsafe { BoundProcessAddressSpace::<3>::deactivate() }.is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 TTBR0 deactivation serialization failed\n",
        );
    }
    if result.is_err() {
        crate::fatal(serial, message);
    }
}

fn verify_data<const CAPS: usize>(
    serial: &crate::Serial,
    process: &Process<CAPS>,
    objects: &ObjectTable<8>,
    space: &BoundProcessAddressSpace<3>,
    expected: u64,
    message: &str,
) {
    if unsafe { space.activate_owner(process, objects) }.is_err() {
        crate::fatal(serial, message);
    }
    let result = read_user_u64();
    if unsafe { BoundProcessAddressSpace::<3>::deactivate() }.is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 11 TTBR0 deactivation serialization failed\n",
        );
    }
    if result != Ok(expected) || kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal(serial, message);
    }
}

fn read_user_u64() -> Result<u64, ()> {
    let mut bytes = [0u8; core::mem::size_of::<u64>()];
    kernal_usercopy_aarch64::copy_from_user(&mut bytes, USER_DATA_VA).map_err(|_| ())?;
    Ok(u64::from_le_bytes(bytes))
}

extern "C" fn step11_lower_el_handler(frame: &mut ExceptionFrame) -> bool {
    let active = ACTIVE_PROCESS.load(Ordering::Acquire);
    if active != PROCESS_A && active != PROCESS_B {
        return false;
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal_silent();
    }

    match frame.lower_el_aarch64_synchronous() {
        Some(LowerElAarch64Synchronous::SupervisorCall { immediate }) if immediate == 0 => {
            handle_svc(frame, active)
        }
        Some(LowerElAarch64Synchronous::Breakpoint { comment }) if comment == PROBE_BRK_COMMENT => {
            handle_terminal_brk(frame, active)
        }
        _ => crate::fatal_silent(),
    }
}

fn handle_svc(frame: &mut ExceptionFrame, active: u8) -> bool {
    let call = SVC_COUNT.load(Ordering::Acquire);
    if call >= PROBE_SYSCALLS {
        crate::fatal_silent();
    }
    let initial_x0 = process_initial_x0(active);
    let expected_pc = USER_ENTRY_VA
        .checked_add(SVC_RETURN_OFFSETS[call as usize])
        .unwrap_or_else(|| crate::fatal_silent());
    let user_sp = USER_STACK_VA
        .checked_add(PAGE_SIZE)
        .unwrap_or_else(|| crate::fatal_silent());
    let state = El0ReturnState::new(frame.elr_el1, frame.spsr_el1, frame.sp_el0)
        .unwrap_or_else(|_| crate::fatal_silent());
    if state.return_pc() != expected_pc
        || state.user_sp() != user_sp
        || !registers_match(frame, initial_x0 + u64::from(call))
    {
        crate::fatal_silent();
    }

    frame.x[0] = frame.x[0]
        .checked_add(1)
        .unwrap_or_else(|| crate::fatal_silent());
    frame.elr_el1 = state.return_pc();
    frame.spsr_el1 = state.spsr_el1();
    frame.sp_el0 = state.user_sp();
    if SVC_COUNT
        .compare_exchange(call, call + 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::fatal_silent();
    }
    true
}

fn handle_terminal_brk(frame: &mut ExceptionFrame, active: u8) -> bool {
    let initial_x0 = process_initial_x0(active);
    let expected_pc = USER_ENTRY_VA
        .checked_add(PROBE_BRK_OFFSET)
        .unwrap_or_else(|| crate::fatal_silent());
    let user_sp = USER_STACK_VA
        .checked_add(PAGE_SIZE)
        .unwrap_or_else(|| crate::fatal_silent());
    let state = El0ReturnState::new(frame.elr_el1, frame.spsr_el1, frame.sp_el0)
        .unwrap_or_else(|_| crate::fatal_silent());
    if SVC_COUNT.load(Ordering::Acquire) != PROBE_SYSCALLS
        || state.return_pc() != expected_pc
        || state.user_sp() != user_sp
        || !registers_match(frame, initial_x0 + u64::from(PROBE_SYSCALLS))
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

fn process_initial_x0(active: u8) -> u64 {
    match active {
        PROCESS_A => PROCESS_A_X0,
        PROCESS_B => PROCESS_B_X0,
        _ => crate::fatal_silent(),
    }
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
