// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::RuntimeTablePool;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use kernal_address_space_aarch64::{Aarch64AddressSpaceExt, Aarch64Root};
use kernal_exceptions_aarch64::{ExceptionFrame, LowerElAarch64Synchronous};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_paging::PAGE_SIZE;
use kernal_user_entry_aarch64::El0ReturnState;
use kernal_vm::{AddressSpace, Backing, USER_MIN, VmPerms, Vma};

const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const STEP7_FRAME_B: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES - PAGE_SIZE;
const STEP7_FRAME_A: u64 = STEP7_FRAME_B - PAGE_SIZE;
const STEP8_STACK_FRAME: u64 = STEP7_FRAME_A - PAGE_SIZE;
const STEP8_CODE_FRAME: u64 = STEP8_STACK_FRAME - PAGE_SIZE;
const USER_STACK_FRAME: u64 = STEP8_CODE_FRAME - PAGE_SIZE;
const USER_CODE_FRAME: u64 = USER_STACK_FRAME - PAGE_SIZE;

const USER_ENTRY_VA: u64 = USER_MIN + 0x140_000;
const USER_STACK_VA: u64 = USER_MIN + 0x180_000;
const PROBE_INITIAL_X0: u64 = 0x5356_4300_0000_0009;
const PROBE_SYSCALL_NUMBER: u64 = 0xf009;
const PROBE_RETURN_BASE: u64 = 0x9000;
const PROBE_SYSCALLS: u32 = 3;
const PROBE_BRK_COMMENT: u16 = 0x0099;
const MIN_KERNEL_STACK_HEADROOM: u64 = 4096;

const ARG1_SENTINEL: u64 = 0x1111;
const ARG2_SENTINEL: u64 = 0x2222;
const ARG3_SENTINEL: u64 = 0x3333;
const ARG4_SENTINEL: u64 = 0x4444;
const ARG5_SENTINEL: u64 = 0x5555;
const X19_SENTINEL: u64 = 0x1919;
const X20_SENTINEL: u64 = 0x2020;

const fn movz_x(register: u32, immediate: u16) -> u32 {
    0xd280_0000 | ((immediate as u32) << 5) | (register & 0x1f)
}

const SVC_ZERO: u32 = 0xd400_0001;
const BRK_PROBE: u32 = 0xd420_0000 | ((PROBE_BRK_COMMENT as u32) << 5);
const BRANCH_SELF: u32 = 0x1400_0000;

// The payload deliberately owns only transport semantics. PROBE_SYSCALL_NUMBER is feature-local and
// is not added to the stable native syscall-number table. x8 carries the number, x0..x5 are the
// native argument/result registers, and x19/x20 prove that the exception path preserves callee-saved
// state across repeated SVC -> EL1 -> ERET -> EL0 cycles.
const USER_PAYLOAD: [u32; 13] = [
    movz_x(1, ARG1_SENTINEL as u16),
    movz_x(2, ARG2_SENTINEL as u16),
    movz_x(3, ARG3_SENTINEL as u16),
    movz_x(4, ARG4_SENTINEL as u16),
    movz_x(5, ARG5_SENTINEL as u16),
    movz_x(8, PROBE_SYSCALL_NUMBER as u16),
    movz_x(19, X19_SENTINEL as u16),
    movz_x(20, X20_SENTINEL as u16),
    SVC_ZERO,
    SVC_ZERO,
    SVC_ZERO,
    BRK_PROBE,
    BRANCH_SELF,
];
const USER_PAYLOAD_BYTES: u64 = (USER_PAYLOAD.len() * core::mem::size_of::<u32>()) as u64;
const SVC_RETURN_OFFSETS: [u64; PROBE_SYSCALLS as usize] = [9 * 4, 10 * 4, 11 * 4];
const PROBE_BRK_OFFSET: u64 = 11 * 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedSvcProof {
    root: Aarch64Root,
    entry: u64,
    user_sp: u64,
}

impl PreparedSvcProof {
    pub const fn entry(self) -> u64 {
        self.entry
    }

    pub const fn user_sp(self) -> u64 {
        self.user_sp
    }

    /// Activates the already validated Step-9 TTBR0 root on the BSP.
    ///
    /// # Safety
    /// Caller must own the BSP's scheduler/preemption state with all secondary PEs still quiesced.
    pub unsafe fn activate(self) -> Result<(), ()> {
        // SAFETY: delegated to the caller contract and the root was built by `prepare` below.
        unsafe { self.root.activate() }.map_err(|_| ())
    }

    /// Restores the kernel-only final TTBR1 regime after the Step-9 proof completes.
    ///
    /// # Safety
    /// Caller must execute at EL1 after the controlled terminal BRK returned through the proof hook.
    pub unsafe fn deactivate() {
        // SAFETY: delegated to the caller contract above.
        unsafe { Aarch64Root::deactivate() };
    }
}

struct PreparedCell {
    state: AtomicU32,
    storage: UnsafeCell<MaybeUninit<PreparedSvcProof>>,
}

unsafe impl Sync for PreparedCell {}

impl PreparedCell {
    const EMPTY: u32 = 0;
    const INITIALIZING: u32 = 1;
    const READY: u32 = 2;

    const fn new() -> Self {
        Self {
            state: AtomicU32::new(Self::EMPTY),
            storage: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&'static self, proof: PreparedSvcProof) -> Result<(), ()> {
        self.state
            .compare_exchange(
                Self::EMPTY,
                Self::INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ())?;
        // SAFETY: successful transition grants the BSP the sole write before READY publication.
        unsafe { (*self.storage.get()).write(proof) };
        self.state.store(Self::READY, Ordering::Release);
        Ok(())
    }

    fn get(&'static self) -> Option<PreparedSvcProof> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return None;
        }
        // SAFETY: READY publishes an initialized immutable Copy value.
        Some(unsafe { *(&*self.storage.get()).assume_init_ref() })
    }
}

static PREPARED: PreparedCell = PreparedCell::new();
static PROOF_ACTIVE: AtomicBool = AtomicBool::new(false);
static PROOF_COMPLETE: AtomicBool = AtomicBool::new(false);
static SYSCALL_COUNT: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "step10-qemu-proof")]
static PAN_ENTRY_OBSERVED: AtomicBool = AtomicBool::new(false);

pub fn prepare(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    if prepare_inner(backend).is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 9 SVC address-space preparation failed\n",
        );
    }
    serial.write_str("KERNAL/S9: ARM64 dedicated native-SVC EL0 code + stack prepared\n");
}

pub fn run(serial: &crate::Serial) {
    let proof = PREPARED.get().unwrap_or_else(|| {
        crate::fatal(serial, "KERNAL/ARM64: Step 9 SVC proof was not prepared\n")
    });
    if kernal_arch_aarch64::current_exception_level() != 1 || !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 9 SVC proof requires IRQ-masked EL1\n",
        );
    }
    if !kernel_stack_has_headroom() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 9 SVC proof kernel stack headroom invalid\n",
        );
    }
    if SYSCALL_COUNT.load(Ordering::Acquire) != 0 || PROOF_COMPLETE.load(Ordering::Acquire) {
        crate::fatal(serial, "KERNAL/ARM64: Step 9 SVC proof state reused\n");
    }
    #[cfg(feature = "step10-qemu-proof")]
    if PAN_ENTRY_OBSERVED.load(Ordering::Acquire) {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 10 PAN-entry proof state reused\n",
        );
    }

    kernal_exceptions_aarch64::install_lower_el_aarch64_handler(step9_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 9 lower-EL handler install failed\n",
            )
        });
    if PROOF_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::fatal(serial, "KERNAL/ARM64: Step 9 SVC proof already active\n");
    }

    // SAFETY: the BSP exclusively owns this proof while secondaries remain at the protected-runtime
    // rendezvous. The prepared root maps one dedicated RX code page and one zeroed RW-NX stack page.
    if unsafe { proof.activate() }.is_err() {
        PROOF_ACTIVE.store(false, Ordering::Release);
        let _ =
            kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step9_lower_el_handler);
        crate::fatal(serial, "KERNAL/ARM64: Step 9 TTBR0 activation failed\n");
    }

    #[cfg(feature = "step10-qemu-proof")]
    {
        // Step 9 populated its user pages before PAN was enabled. From this point onward, Step 10
        // establishes the real exception-entry policy before executing any EL0 SVC. The EL0 return
        // state itself does not carry PAN, so each subsequent observation inside the SVC handler is
        // causal evidence that SCTLR_EL1.SPAN=0 forced PSTATE.PAN closed on exception entry.
        if kernal_usercopy_aarch64::enable_pan_default().is_err()
            || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
        {
            abort_active_proof(serial, "KERNAL/ARM64: Step 10 PAN-entry setup failed\n");
        }
    }

    // SAFETY: the active TTBR0 root maps proof.entry RX and proof.user_sp into the dedicated Step-9
    // stack. Valid SVCs return directly to EL0 through the normal vector ERET path. Only the terminal
    // validated BRK redirects to the existing EL1h QEMU resume label and returns from this wrapper.
    let roundtrip = unsafe {
        kernal_user_entry_aarch64::enter_el0_qemu_roundtrip(
            proof.entry(),
            proof.user_sp(),
            PROBE_INITIAL_X0,
        )
    };

    if roundtrip.is_err()
        || SYSCALL_COUNT.load(Ordering::Acquire) != PROBE_SYSCALLS
        || !PROOF_COMPLETE.load(Ordering::Acquire)
    {
        abort_active_proof(serial, "KERNAL/ARM64: Step 9 SVC/ERET roundtrip failed\n");
    }
    #[cfg(feature = "step10-qemu-proof")]
    if !PAN_ENTRY_OBSERVED.load(Ordering::Acquire) {
        abort_active_proof(
            serial,
            "KERNAL/ARM64: Step 10 PAN exception-entry observation missing\n",
        );
    }

    // SAFETY: terminal BRK returned through the validated EL1h resume path; user execution is over.
    unsafe { PreparedSvcProof::deactivate() };
    PROOF_ACTIVE.store(false, Ordering::Release);
    kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step9_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 9 lower-EL handler removal failed\n",
            )
        });

    if kernal_arch_aarch64::current_exception_level() != 1 || !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 9 SVC roundtrip postcondition failed\n",
        );
    }
    serial.write_str("KERNAL/S9: ARM64 repeated native SVC/ERET roundtrip passed\n");
    #[cfg(feature = "step10-qemu-proof")]
    serial.write_str("KERNAL/S10: ARM64 real EL0->EL1 SVC entry forced PAN closed\n");
}

fn abort_active_proof(serial: &crate::Serial, message: &str) -> ! {
    // SAFETY: this helper is reached only after the proof root was activated and control is at EL1.
    unsafe { PreparedSvcProof::deactivate() };
    PROOF_ACTIVE.store(false, Ordering::Release);
    let _ = kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step9_lower_el_handler);
    crate::fatal(serial, message)
}

fn prepare_inner(backend: &mut RuntimeTablePool) -> Result<(), ()> {
    let state = crate::boot_state();
    let qemu_ram_end = crate::QEMU_VIRT_RAM_BASE
        .checked_add(QEMU_RAM_BYTES)
        .ok_or(())?;
    if STEP7_FRAME_B.checked_add(PAGE_SIZE) != Some(qemu_ram_end)
        || STEP8_STACK_FRAME.checked_add(PAGE_SIZE) != Some(STEP7_FRAME_A)
        || STEP8_CODE_FRAME.checked_add(PAGE_SIZE) != Some(STEP8_STACK_FRAME)
        || USER_STACK_FRAME.checked_add(PAGE_SIZE) != Some(STEP8_CODE_FRAME)
        || USER_CODE_FRAME.checked_add(PAGE_SIZE) != Some(USER_STACK_FRAME)
        || USER_CODE_FRAME < state.layout.bss.end
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

    let code_frame = PhysFrame::from_start_address(USER_CODE_FRAME).ok_or(())?;
    let stack_frame = PhysFrame::from_start_address(USER_STACK_FRAME).ok_or(())?;
    if reserved.contains(code_frame) || reserved.contains(stack_frame) {
        return Err(());
    }

    let mut space = AddressSpace::<Aarch64Root, 2>::new(Aarch64Root::new(backend).map_err(|_| ())?);
    populate_frames(&mut space, backend, code_frame, stack_frame, &reserved)?;

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
    space
        .map_user_page(backend, code_vma, code_frame, &reserved)
        .map_err(|_| ())?;
    space
        .map_user_page(backend, stack_vma, stack_frame, &reserved)
        .map_err(|_| ())?;

    if space
        .translate_user(backend, USER_ENTRY_VA)
        .map_err(|_| ())?
        != USER_CODE_FRAME
        || space
            .translate_user(backend, USER_STACK_VA)
            .map_err(|_| ())?
            != USER_STACK_FRAME
    {
        return Err(());
    }

    let user_sp = USER_STACK_VA.checked_add(PAGE_SIZE).ok_or(())?;
    PREPARED.publish(PreparedSvcProof {
        root: *space.root(),
        entry: USER_ENTRY_VA,
        user_sp,
    })
}

fn populate_frames(
    space: &mut AddressSpace<Aarch64Root, 2>,
    backend: &mut RuntimeTablePool,
    code_frame: PhysFrame,
    stack_frame: PhysFrame,
    reserved: &ReservationSet<4>,
) -> Result<(), ()> {
    let staging_perms = VmPerms::READ.union(VmPerms::WRITE);
    let code_staging =
        Vma::new(USER_ENTRY_VA, PAGE_SIZE, staging_perms, Backing::Anonymous).map_err(|_| ())?;
    let stack_staging =
        Vma::new(USER_STACK_VA, PAGE_SIZE, staging_perms, Backing::Anonymous).map_err(|_| ())?;
    space
        .map_user_page(backend, code_staging, code_frame, reserved)
        .map_err(|_| ())?;
    if space
        .map_user_page(backend, stack_staging, stack_frame, reserved)
        .is_err()
    {
        let _ = space.unmap_user_page(backend, USER_ENTRY_VA);
        return Err(());
    }

    // SAFETY: the BSP exclusively owns this temporary TTBR0 root. Both Step-9 pages are dedicated
    // RAM frames mapped RW-NX; no EL0 execution or secondary-PE access is possible while populated.
    if unsafe { space.root().activate() }.is_err() {
        return Err(());
    }
    let write_result = unsafe { initialize_user_pages() };
    // SAFETY: regardless of initialization success, no EL0 execution began and the BSP owns the root.
    unsafe { Aarch64Root::deactivate() };
    write_result?;

    if space
        .unmap_user_page(backend, USER_ENTRY_VA)
        .map_err(|_| ())?
        != code_frame
        || space
            .unmap_user_page(backend, USER_STACK_VA)
            .map_err(|_| ())?
            != stack_frame
    {
        return Err(());
    }
    Ok(())
}

unsafe fn initialize_user_pages() -> Result<(), ()> {
    // SAFETY: caller activated a root mapping both complete pages RW-NX to exclusive dedicated RAM.
    unsafe {
        write_bytes(USER_ENTRY_VA as *mut u8, 0, PAGE_SIZE as usize);
        write_bytes(USER_STACK_VA as *mut u8, 0, PAGE_SIZE as usize);
        let destination = USER_ENTRY_VA as *mut u32;
        for (index, instruction) in USER_PAYLOAD.iter().copied().enumerate() {
            write_volatile(destination.add(index), instruction);
        }
        for (index, expected) in USER_PAYLOAD.iter().copied().enumerate() {
            if read_volatile(destination.add(index)) != expected {
                return Err(());
            }
        }
        kernal_cache_aarch64::sync_modified_code(USER_ENTRY_VA, USER_ENTRY_VA, USER_PAYLOAD_BYTES)
            .map_err(|_| ())?;
    }
    Ok(())
}

extern "C" fn step9_lower_el_handler(frame: &mut ExceptionFrame) -> bool {
    if !PROOF_ACTIVE.load(Ordering::Acquire) {
        return false;
    }
    let Some(proof) = PREPARED.get() else {
        crate::fatal_silent();
    };

    match frame.lower_el_aarch64_synchronous() {
        Some(LowerElAarch64Synchronous::SupervisorCall { immediate }) if immediate == 0 => {
            handle_svc(frame, proof)
        }
        Some(LowerElAarch64Synchronous::Breakpoint { comment }) if comment == PROBE_BRK_COMMENT => {
            handle_terminal_brk(frame, proof)
        }
        _ => crate::fatal_silent(),
    }
}

fn handle_svc(frame: &mut ExceptionFrame, proof: PreparedSvcProof) -> bool {
    let call = SYSCALL_COUNT.load(Ordering::Acquire);
    if call >= PROBE_SYSCALLS {
        crate::fatal_silent();
    }

    #[cfg(feature = "step10-qemu-proof")]
    {
        if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
            crate::fatal_silent();
        }
        if call == 0 {
            if PAN_ENTRY_OBSERVED.swap(true, Ordering::AcqRel) {
                crate::fatal_silent();
            }
        } else if !PAN_ENTRY_OBSERVED.load(Ordering::Acquire) {
            crate::fatal_silent();
        }
    }

    let expected_return_pc = proof
        .entry()
        .checked_add(SVC_RETURN_OFFSETS[call as usize])
        .unwrap_or_else(|| crate::fatal_silent());
    let expected_x0 = if call == 0 {
        PROBE_INITIAL_X0
    } else {
        PROBE_RETURN_BASE + u64::from(call)
    };

    let return_state = El0ReturnState::new(frame.elr_el1, frame.spsr_el1, frame.sp_el0)
        .unwrap_or_else(|_| crate::fatal_silent());
    if return_state.return_pc() != expected_return_pc
        || return_state.user_sp() != proof.user_sp()
        || !registers_match(frame, expected_x0)
    {
        crate::fatal_silent();
    }

    // Only x0 is the Step-9 proof result register. All other argument/callee-saved sentinels remain
    // untouched and are re-checked on the next SVC and the terminal BRK.
    frame.x[0] = PROBE_RETURN_BASE + u64::from(call) + 1;
    frame.elr_el1 = return_state.return_pc();
    frame.spsr_el1 = return_state.spsr_el1();
    frame.sp_el0 = return_state.user_sp();

    if SYSCALL_COUNT
        .compare_exchange(call, call + 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::fatal_silent();
    }
    true
}

fn handle_terminal_brk(frame: &mut ExceptionFrame, proof: PreparedSvcProof) -> bool {
    #[cfg(feature = "step10-qemu-proof")]
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal_silent();
    }

    let expected_brk = proof
        .entry()
        .checked_add(PROBE_BRK_OFFSET)
        .unwrap_or_else(|| crate::fatal_silent());
    let return_state = El0ReturnState::new(frame.elr_el1, frame.spsr_el1, frame.sp_el0)
        .unwrap_or_else(|_| crate::fatal_silent());
    if SYSCALL_COUNT.load(Ordering::Acquire) != PROBE_SYSCALLS
        || return_state.return_pc() != expected_brk
        || return_state.user_sp() != proof.user_sp()
        || !registers_match(frame, PROBE_RETURN_BASE + u64::from(PROBE_SYSCALLS))
    {
        crate::fatal_silent();
    }

    let resume = qemu_resume_high_address().unwrap_or_else(|_| crate::fatal_silent());
    frame.elr_el1 = resume;
    frame.spsr_el1 = kernal_user_entry_aarch64::QEMU_PROBE_RESUME_SPSR_EL1;
    if PROOF_COMPLETE.swap(true, Ordering::AcqRel) {
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

fn kernel_stack_has_headroom() -> bool {
    let state = crate::boot_state();
    let stack_low = match state.layout.high_alias(state.layout.boot_guard.end) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let stack_high = match state.layout.high_alias(state.layout.secondary_stacks.start) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let sp = current_stack_pointer();
    (stack_low..=stack_high).contains(&sp)
        && sp
            .checked_sub(stack_low)
            .is_some_and(|headroom| headroom >= MIN_KERNEL_STACK_HEADROOM)
}

fn current_stack_pointer() -> u64 {
    let sp: u64;
    // SAFETY: MOV from SP is an architectural register read and does not modify machine state.
    unsafe { asm!("mov {sp}, sp", sp = out(reg) sp, options(nomem, nostack, preserves_flags)) };
    sp
}
