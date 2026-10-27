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
use kernal_vm::{AddressSpace, Backing, USER_MIN, VmPerms, Vma};

const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const STEP7_FRAME_B: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES - PAGE_SIZE;
const STEP7_FRAME_A: u64 = STEP7_FRAME_B - PAGE_SIZE;
const USER_STACK_FRAME: u64 = STEP7_FRAME_A - PAGE_SIZE;
const USER_CODE_FRAME: u64 = USER_STACK_FRAME - PAGE_SIZE;
const USER_ENTRY_VA: u64 = USER_MIN + 0x40_000;
const USER_STACK_VA: u64 = USER_MIN + 0x80_000;
const USER_FAULT_VA: u64 = USER_MIN + 0xc0_000;
const PROBE_ARGUMENT0: u64 = 0x4b45_524e_414c_0008;
const PROBE_BRK_OFFSET: u64 = 4;
const PROBE_FAULT_ENTRY_OFFSET: u64 = 8;
const TRANSLATION_FAULT_LEVEL_3: u8 = 0x07;
const MIN_KERNEL_STACK_HEADROOM: u64 = 4096;

const ADD_X0_X0_1: u32 = 0x9100_0400;
const BRK_PROBE: u32 =
    0xd420_0000 | ((kernal_user_entry_aarch64::QEMU_PROBE_BRK_COMMENT as u32) << 5);
const LDR_X1_FROM_X0: u32 = 0xf940_0001;
const BRANCH_SELF: u32 = 0x1400_0000;
const USER_PAYLOAD: [u32; 4] = [ADD_X0_X0_1, BRK_PROBE, LDR_X1_FROM_X0, BRANCH_SELF];
const USER_PAYLOAD_BYTES: u64 = (USER_PAYLOAD.len() * core::mem::size_of::<u32>()) as u64;

const PROOF_IDLE: u32 = 0;
const PROOF_EXPECT_BREAKPOINT: u32 = 1;
const PROOF_BREAKPOINT_COMPLETE: u32 = 2;
const PROOF_EXPECT_DATA_ABORT: u32 = 3;
const PROOF_DATA_ABORT_COMPLETE: u32 = 4;

/// Fully mapped Step-8 QEMU proof address space. The root is kept private so activation cannot skip
/// this module's construction checks; callers receive only the narrow one-shot operations needed by
/// the protected runtime proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedEl0Proof {
    root: Aarch64Root,
    entry: u64,
    fault_entry: u64,
    fault_address: u64,
    user_sp: u64,
    argument0: u64,
}

impl PreparedEl0Proof {
    pub const fn entry(self) -> u64 {
        self.entry
    }

    pub const fn fault_entry(self) -> u64 {
        self.fault_entry
    }

    pub const fn fault_address(self) -> u64 {
        self.fault_address
    }

    pub const fn user_sp(self) -> u64 {
        self.user_sp
    }

    pub const fn argument0(self) -> u64 {
        self.argument0
    }

    /// Activates the already validated Step-8 TTBR0 root on the BSP.
    ///
    /// # Safety
    /// Caller must own the BSP's scheduler/preemption state with user execution quiesced.
    pub unsafe fn activate(self) -> Result<(), ()> {
        // SAFETY: delegated to the caller contract and the root was built by `prepare` below.
        unsafe { self.root.activate() }.map_err(|_| ())
    }

    /// Restores the kernel-only final TTBR1 regime after the QEMU EL0 roundtrips.
    ///
    /// # Safety
    /// Caller must execute at EL1 after user execution has trapped back into the controlled proof.
    pub unsafe fn deactivate() {
        // SAFETY: delegated to the caller contract above.
        unsafe { Aarch64Root::deactivate() };
    }
}

struct PreparedCell {
    state: AtomicU32,
    storage: UnsafeCell<MaybeUninit<PreparedEl0Proof>>,
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

    fn publish(&'static self, proof: PreparedEl0Proof) -> Result<(), ()> {
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

    fn get(&'static self) -> Option<PreparedEl0Proof> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return None;
        }
        // SAFETY: READY publishes an initialized immutable Copy value.
        Some(unsafe { *(&*self.storage.get()).assume_init_ref() })
    }
}

static PREPARED: PreparedCell = PreparedCell::new();
static PROOF_ACTIVE: AtomicBool = AtomicBool::new(false);
static PROOF_PHASE: AtomicU32 = AtomicU32::new(PROOF_IDLE);

/// Returns the immutable proof descriptor prepared by the BSP protected-runtime phase.
pub fn prepared_el0_qemu_proof() -> Option<PreparedEl0Proof> {
    PREPARED.get()
}

/// Builds a real EL0 RX code page and RW-NX stack using dedicated non-kernel RAM frames.
///
/// Both frames are first mapped RW-NX only while the BSP zeroes them and writes the tiny payload.
/// Cache maintenance then makes the stores visible to instruction fetch. The writable code mapping
/// is removed before the same frame is remapped RX, so no writable executable alias exists and no
/// kernel, MMIO, page-table or stack-reserved frame becomes user-accessible.
pub fn prepare(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    if prepare_inner(backend).is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 8 EL0 address-space preparation failed\n",
        );
    }
    serial.write_str("KERNAL/S8: ARM64 dedicated EL0 RX code + zeroed RW-NX stack prepared\n");
}

/// Executes two real EL1 -> EL0 -> EL1h roundtrips and then restores TTBR0-disabled state.
///
/// The first executes a normal ADD before a deliberate BRK. The second starts at a separate payload
/// entry and performs a read from a proven-unmapped user address, producing a lower-EL data abort.
/// Neither path uses SVC, so Step 9 remains gated.
pub fn run(serial: &crate::Serial) {
    let proof = PREPARED.get().unwrap_or_else(|| {
        crate::fatal(serial, "KERNAL/ARM64: Step 8 EL0 proof was not prepared\n")
    });
    if kernal_arch_aarch64::current_exception_level() != 1 || !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 8 EL0 proof requires IRQ-masked EL1\n",
        );
    }
    if !kernel_stack_has_headroom() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 8 EL0 proof kernel stack headroom invalid\n",
        );
    }
    kernal_exceptions_aarch64::install_lower_el_aarch64_handler(step8_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 8 lower-EL handler install failed\n",
            )
        });
    if PROOF_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
        || PROOF_PHASE.load(Ordering::Acquire) != PROOF_IDLE
    {
        crate::fatal(serial, "KERNAL/ARM64: Step 8 EL0 proof state invalid\n");
    }

    // SAFETY: protected runtime owns the BSP, IRQs are masked, VBAR_EL1 is installed, and prepare()
    // built this TTBR0 root from the accepted Step-7 address-space mechanism.
    if unsafe { proof.activate() }.is_err() {
        PROOF_ACTIVE.store(false, Ordering::Release);
        crate::fatal(serial, "KERNAL/ARM64: Step 8 TTBR0 activation failed\n");
    }

    PROOF_PHASE.store(PROOF_EXPECT_BREAKPOINT, Ordering::Release);
    // SAFETY: the active root maps proof.entry RX and proof.user_sp into a RW-NX user stack. The
    // installed lower-EL handler validates the BRK and redirects only that exact proof to EL1h.
    let breakpoint_roundtrip = unsafe {
        kernal_user_entry_aarch64::enter_el0_qemu_roundtrip(
            proof.entry(),
            proof.user_sp(),
            proof.argument0(),
        )
    };
    if breakpoint_roundtrip.is_err()
        || PROOF_PHASE.load(Ordering::Acquire) != PROOF_BREAKPOINT_COMPLETE
    {
        abort_active_proof(
            serial,
            "KERNAL/ARM64: Step 8 EL0 breakpoint roundtrip failed\n",
        );
    }

    PROOF_PHASE.store(PROOF_EXPECT_DATA_ABORT, Ordering::Release);
    // SAFETY: the same active root maps the fault payload RX and leaves proof.fault_address
    // deliberately unmapped. The lower-EL hook accepts only the exact read translation fault.
    let fault_roundtrip = unsafe {
        kernal_user_entry_aarch64::enter_el0_qemu_roundtrip(
            proof.fault_entry(),
            proof.user_sp(),
            proof.fault_address(),
        )
    };
    if fault_roundtrip.is_err() || PROOF_PHASE.load(Ordering::Acquire) != PROOF_DATA_ABORT_COMPLETE
    {
        abort_active_proof(
            serial,
            "KERNAL/ARM64: Step 8 EL0 page-fault roundtrip failed\n",
        );
    }

    // SAFETY: both normal returns above are validated EL1h resume paths; user execution is over.
    unsafe { PreparedEl0Proof::deactivate() };
    PROOF_ACTIVE.store(false, Ordering::Release);
    kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step8_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 8 lower-EL handler removal failed\n",
            )
        });

    if kernal_arch_aarch64::current_exception_level() != 1
        || !kernal_arch_aarch64::irqs_masked()
        || PROOF_PHASE.load(Ordering::Acquire) != PROOF_DATA_ABORT_COMPLETE
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 8 EL0 roundtrip postcondition failed\n",
        );
    }
    serial.write_str("KERNAL/S8: ARM64 EL1 -> EL0 ADD+BRK -> EL1 roundtrip passed\n");
    serial.write_str("KERNAL/S8: ARM64 EL0 unmapped read -> data-abort -> EL1 roundtrip passed\n");
}

fn abort_active_proof(serial: &crate::Serial, message: &str) -> ! {
    // SAFETY: this helper is called only after the proof root was activated and EL0 returned to EL1.
    unsafe { PreparedEl0Proof::deactivate() };
    PROOF_ACTIVE.store(false, Ordering::Release);
    let _ = kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step8_lower_el_handler);
    crate::fatal(serial, message)
}

fn prepare_inner(backend: &mut RuntimeTablePool) -> Result<(), ()> {
    let state = crate::boot_state();
    let qemu_ram_end = crate::QEMU_VIRT_RAM_BASE
        .checked_add(QEMU_RAM_BYTES)
        .ok_or(())?;
    if STEP7_FRAME_B.checked_add(PAGE_SIZE) != Some(qemu_ram_end)
        || USER_STACK_FRAME.checked_add(PAGE_SIZE) != Some(STEP7_FRAME_A)
        || USER_CODE_FRAME.checked_add(PAGE_SIZE) != Some(USER_STACK_FRAME)
        || USER_CODE_FRAME < state.layout.bss.end
        || USER_FAULT_VA & (PAGE_SIZE - 1) != 0
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
        || space.translate_user(backend, USER_FAULT_VA).is_ok()
    {
        return Err(());
    }

    let fault_entry = USER_ENTRY_VA
        .checked_add(PROBE_FAULT_ENTRY_OFFSET)
        .ok_or(())?;
    let user_sp = USER_STACK_VA.checked_add(PAGE_SIZE).ok_or(())?;
    PREPARED.publish(PreparedEl0Proof {
        root: *space.root(),
        entry: USER_ENTRY_VA,
        fault_entry,
        fault_address: USER_FAULT_VA,
        user_sp,
        argument0: PROBE_ARGUMENT0,
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

    // SAFETY: the BSP exclusively owns this temporary TTBR0 root. Both pages are dedicated RAM
    // frames mapped RW-NX, and no EL0 execution or secondary-PE access is possible in this phase.
    if unsafe { space.root().activate() }.is_err() {
        return Err(());
    }
    let write_result = unsafe { initialize_user_pages() };
    // SAFETY: whether initialization succeeded or failed, no user execution began and the BSP owns
    // the active root; return immediately to the final kernel-only TTBR1 regime.
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

extern "C" fn step8_lower_el_handler(frame: &mut ExceptionFrame) -> bool {
    if !PROOF_ACTIVE.load(Ordering::Acquire) {
        return false;
    }
    let Some(proof) = PREPARED.get() else {
        crate::fatal_silent();
    };
    let phase = PROOF_PHASE.load(Ordering::Acquire);
    match (phase, frame.lower_el_aarch64_synchronous()) {
        (PROOF_EXPECT_BREAKPOINT, Some(LowerElAarch64Synchronous::Breakpoint { comment }))
            if comment == kernal_user_entry_aarch64::QEMU_PROBE_BRK_COMMENT
                && frame.elr_el1
                    == proof
                        .entry()
                        .checked_add(PROBE_BRK_OFFSET)
                        .unwrap_or_else(|| crate::fatal_silent())
                && frame.spsr_el1 == kernal_user_entry_aarch64::EL0T_SPSR_EL1
                && frame.x[0]
                    == proof
                        .argument0()
                        .checked_add(1)
                        .unwrap_or_else(|| crate::fatal_silent()) =>
        {
            complete_expected_trap(frame, PROOF_EXPECT_BREAKPOINT, PROOF_BREAKPOINT_COMPLETE)
        }
        (
            PROOF_EXPECT_DATA_ABORT,
            Some(LowerElAarch64Synchronous::DataAbort {
                fault_status,
                write,
                fault_address,
            }),
        ) if fault_status == TRANSLATION_FAULT_LEVEL_3
            && !write
            && fault_address == Some(proof.fault_address())
            && frame.elr_el1 == proof.fault_entry()
            && frame.spsr_el1 == kernal_user_entry_aarch64::EL0T_SPSR_EL1
            && frame.x[0] == proof.fault_address() =>
        {
            complete_expected_trap(frame, PROOF_EXPECT_DATA_ABORT, PROOF_DATA_ABORT_COMPLETE)
        }
        _ => crate::fatal_silent(),
    }
}

fn complete_expected_trap(frame: &mut ExceptionFrame, expected: u32, complete: u32) -> bool {
    let resume = qemu_resume_high_address().unwrap_or_else(|_| crate::fatal_silent());
    frame.elr_el1 = resume;
    frame.spsr_el1 = kernal_user_entry_aarch64::QEMU_PROBE_RESUME_SPSR_EL1;
    if PROOF_PHASE
        .compare_exchange(expected, complete, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::fatal_silent();
    }
    true
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
