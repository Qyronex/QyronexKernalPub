// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::RuntimeTablePool;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernal_exceptions_aarch64::{ExceptionFrame, LowerElAarch64Synchronous};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::ObjectTable;
use kernal_paging::PAGE_SIZE;
use kernal_process::{Personality, Process};
use kernal_process_aarch64::BoundProcessAddressSpace;
use kernal_user_elf::LoadPolicy;
use kernal_user_elf_aarch64::required_pages;
use kernal_user_elf_runtime_aarch64::{load_aarch64_elf, plan_aarch64_elf};

const USER_ELF: &[u8] = include_bytes!(env!("KERNAL_STEP12_USER_ELF"));
const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SEGMENTS: usize = 8;
const PROCESS_CAPS: usize = 8;
const OBJECTS: usize = 8;
const VMAS: usize = 32;
const RESERVED_RANGES: usize = 4;
const MAX_FRAMES: usize = 24;

// Keep the Step-12 proof pool below every older Step-9/10/11 fixed proof frame. The 24-page pool
// occupies [RAM_END-40 pages, RAM_END-16 pages), leaving five pages of separation before Step 11's
// lowest frame at RAM_END-11 pages.
const STEP12_POOL_START: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES - (40 * PAGE_SIZE);
const STEP12_POOL_END: u64 = STEP12_POOL_START + (MAX_FRAMES as u64 * PAGE_SIZE);
const STEP11_LOWEST_PROOF_FRAME: u64 =
    crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES - (11 * PAGE_SIZE);

const SUCCESS_BRK_COMMENT: u16 = 0x0120;
const FAILURE_BRK_COMMENT: u16 = 0x0121;
// _start: ADRP, ADD, LDR, CBNZ, MOV, BRK.
const SUCCESS_BRK_OFFSET: u64 = 5 * 4;
const SUCCESS_X0: u64 = 0x12;
const PSTATE_PAN_BIT: u64 = 1 << 22;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static ROUNDTRIP_COMPLETE: AtomicBool = AtomicBool::new(false);
static EXPECTED_ENTRY: AtomicU64 = AtomicU64::new(0);
static EXPECTED_SP: AtomicU64 = AtomicU64::new(0);

pub fn run(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    if kernal_arch_aarch64::current_exception_level() != 1 || !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 ELF proof requires IRQ-masked EL1\n",
        );
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal(serial, "KERNAL/ARM64: Step 12 requires PAN default-on\n");
    }

    let policy = LoadPolicy::default();
    let plan = plan_aarch64_elf::<MAX_SEGMENTS>(USER_ELF, policy).unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 embedded AArch64 ELF rejected\n",
        )
    });
    let required = required_pages(&plan).unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 frame-count planning failed\n",
        )
    });
    if required == 0 || required > MAX_FRAMES {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 embedded ELF exceeds proof frame pool\n",
        );
    }

    let reserved = proof_reservations().unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 reservation construction failed\n",
        )
    });
    let frames = proof_frames();

    let mut objects = ObjectTable::<OBJECTS>::new();
    let process = Process::<PROCESS_CAPS>::create(&mut objects, Personality::Native)
        .unwrap_or_else(|_| {
            crate::fatal(serial, "KERNAL/ARM64: Step 12 process creation failed\n")
        });
    let mut space = BoundProcessAddressSpace::<VMAS>::create(&process, &objects, backend)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 12 process address-space creation failed\n",
            )
        });

    let loaded = unsafe {
        load_aarch64_elf::<MAX_SEGMENTS, PROCESS_CAPS, OBJECTS, VMAS, RESERVED_RANGES, _>(
            USER_ELF,
            policy,
            &frames[..required],
            &process,
            &objects,
            &mut space,
            backend,
            &reserved,
        )
    }
    .unwrap_or_else(|_| crate::fatal(serial, "KERNAL/ARM64: Step 12 ELF load failed\n"));

    if loaded.entry != plan.entry()
        || loaded.initial_sp != plan.stack().initial_sp()
        || loaded.mapped.total_pages().ok() != Some(required)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 loaded-image contract mismatch\n",
        );
    }

    EXPECTED_ENTRY.store(loaded.entry, Ordering::Release);
    EXPECTED_SP.store(loaded.initial_sp, Ordering::Release);
    ROUNDTRIP_COMPLETE.store(false, Ordering::Release);
    if ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::fatal(serial, "KERNAL/ARM64: Step 12 proof state reused\n");
    }

    kernal_exceptions_aarch64::install_lower_el_aarch64_handler(step12_lower_el_handler)
        .unwrap_or_else(|_| {
            ACTIVE.store(false, Ordering::Release);
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 12 lower-EL handler install failed\n",
            )
        });

    if unsafe { space.activate_owner(&process, &objects) }.is_err() {
        ACTIVE.store(false, Ordering::Release);
        let _ =
            kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step12_lower_el_handler);
        crate::fatal(serial, "KERNAL/ARM64: Step 12 TTBR0 activation failed\n");
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        abort_active(
            serial,
            "KERNAL/ARM64: Step 12 PAN leaked before ELF entry\n",
        );
    }

    let roundtrip = unsafe {
        kernal_user_entry_aarch64::enter_el0_qemu_roundtrip(loaded.entry, loaded.initial_sp, 0)
    };

    if unsafe { BoundProcessAddressSpace::<VMAS>::deactivate() }.is_err() {
        ACTIVE.store(false, Ordering::Release);
        let _ =
            kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step12_lower_el_handler);
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 TTBR0 deactivation serialization failed\n",
        );
    }
    ACTIVE.store(false, Ordering::Release);
    kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step12_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 12 lower-EL handler removal failed\n",
            )
        });

    if roundtrip.is_err()
        || !ROUNDTRIP_COMPLETE.load(Ordering::Acquire)
        || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 12 native ELF roundtrip failed\n",
        );
    }

    serial.write_str(
        "KERNAL/S12: ARM64 static ELF real entry + BSS zero + initial stack proof passed\n",
    );
}

fn proof_frames() -> [PhysFrame; MAX_FRAMES] {
    core::array::from_fn(|index| {
        let index = u64::try_from(index).unwrap_or_else(|_| crate::fatal_silent());
        let address = STEP12_POOL_START
            .checked_add(
                index
                    .checked_mul(PAGE_SIZE)
                    .unwrap_or_else(|| crate::fatal_silent()),
            )
            .unwrap_or_else(|| crate::fatal_silent());
        PhysFrame::from_start_address(address).unwrap_or_else(|| crate::fatal_silent())
    })
}

fn proof_reservations() -> Result<ReservationSet<RESERVED_RANGES>, ()> {
    let state = crate::boot_state();
    if STEP12_POOL_START < state.layout.bss.end
        || STEP12_POOL_END > STEP11_LOWEST_PROOF_FRAME
        || STEP12_POOL_START < crate::QEMU_VIRT_RAM_BASE
        || STEP12_POOL_END
            > crate::QEMU_VIRT_RAM_BASE
                .checked_add(QEMU_RAM_BYTES)
                .ok_or(())?
    {
        return Err(());
    }

    let mut reserved = ReservationSet::<RESERVED_RANGES>::new();
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

    for frame in proof_frames() {
        if reserved.contains(frame) {
            return Err(());
        }
    }
    Ok(reserved)
}

fn abort_active(serial: &crate::Serial, message: &str) -> ! {
    // Abort paths never resume user or proof execution, so deactivation is explicitly best effort.
    let _ = unsafe { BoundProcessAddressSpace::<VMAS>::deactivate() };
    ACTIVE.store(false, Ordering::Release);
    let _ = kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step12_lower_el_handler);
    crate::fatal(serial, message)
}

extern "C" fn step12_lower_el_handler(frame: &mut ExceptionFrame) -> bool {
    if !ACTIVE.load(Ordering::Acquire) {
        return false;
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal_silent();
    }

    match frame.lower_el_aarch64_synchronous() {
        Some(LowerElAarch64Synchronous::Breakpoint { comment })
            if comment == SUCCESS_BRK_COMMENT =>
        {
            handle_success_brk(frame)
        }
        Some(LowerElAarch64Synchronous::Breakpoint { comment })
            if comment == FAILURE_BRK_COMMENT =>
        {
            // The user ELF takes this path only when its NOLOAD/BSS probe is non-zero.
            crate::fatal_silent()
        }
        _ => crate::fatal_silent(),
    }
}

fn handle_success_brk(frame: &mut ExceptionFrame) -> bool {
    let entry = EXPECTED_ENTRY.load(Ordering::Acquire);
    let user_sp = EXPECTED_SP.load(Ordering::Acquire);
    let expected_pc = entry
        .checked_add(SUCCESS_BRK_OFFSET)
        .unwrap_or_else(|| crate::fatal_silent());

    if frame.elr_el1 != expected_pc
        || frame.sp_el0 != user_sp
        || frame.x[0] != SUCCESS_X0
        || frame.x[2] != 0
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
