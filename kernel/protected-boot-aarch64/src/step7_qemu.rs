// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::RuntimeTablePool;
use core::arch::asm;
use kernal_address_space_aarch64::{Aarch64AddressSpaceExt, Aarch64Root};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_paging::PAGE_SIZE;
use kernal_vm::{AddressSpace, Backing, USER_MIN, VmPerms, Vma};

const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const PROBE_FRAME_B: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES - PAGE_SIZE;
const PROBE_FRAME_A: u64 = PROBE_FRAME_B - PAGE_SIZE;
const PROBE_VA: u64 = USER_MIN + 0x20_000;
const PAR_FAULT: u64 = 1;
const PAR_PHYS_MASK: u64 = 0x0000_ffff_ffff_f000;

/// Runs the Step-7 AArch64 same-VA/different-frame translation proof after every PE has retired the
/// Step-6 TTBR0 regime. The runtime table backend is owned by the encompassing proof suite so Step 7
/// and Step 8 allocate monotonically from one cursor instead of creating overlapping allocators.
pub fn run(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    // SAFETY: enter_runtime_protected_regime invokes this only on the BSP, with IRQs still masked,
    // after all PEs have published final TTBR1-only state. The proof restores TTBR0-disabled state
    // before returning.
    if unsafe { run_inner(backend) }.is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 7 same-VA address-space switch proof failed\n",
        );
    }
    serial.write_str("KERNAL/S7: ARM64 same-VA TTBR0 switch proof passed\n");
}

unsafe fn run_inner(backend: &mut RuntimeTablePool) -> Result<(), ()> {
    let state = crate::boot_state();
    let qemu_ram_end = crate::QEMU_VIRT_RAM_BASE
        .checked_add(QEMU_RAM_BYTES)
        .ok_or(())?;
    let frame_b_end = PROBE_FRAME_B.checked_add(PAGE_SIZE).ok_or(())?;
    if PROBE_FRAME_A < crate::QEMU_VIRT_RAM_BASE
        || PROBE_FRAME_A < state.layout.bss.end
        || PROBE_FRAME_A.checked_add(PAGE_SIZE) != Some(PROBE_FRAME_B)
        || frame_b_end != qemu_ram_end
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

    let frame_a = PhysFrame::from_start_address(PROBE_FRAME_A).ok_or(())?;
    let frame_b = PhysFrame::from_start_address(PROBE_FRAME_B).ok_or(())?;
    if reserved.contains(frame_a) || reserved.contains(frame_b) {
        return Err(());
    }

    let mut left = AddressSpace::<Aarch64Root, 2>::new(Aarch64Root::new(backend).map_err(|_| ())?);
    let mut right = AddressSpace::<Aarch64Root, 2>::new(Aarch64Root::new(backend).map_err(|_| ())?);
    let vma = Vma::new(PROBE_VA, PAGE_SIZE, VmPerms::READ, Backing::Anonymous).map_err(|_| ())?;

    left.map_user_page(backend, vma, frame_a, &reserved)
        .map_err(|_| ())?;
    right
        .map_user_page(backend, vma, frame_b, &reserved)
        .map_err(|_| ())?;

    if left.translate_user(backend, PROBE_VA).map_err(|_| ())? != PROBE_FRAME_A
        || right.translate_user(backend, PROBE_VA).map_err(|_| ())? != PROBE_FRAME_B
    {
        return Err(());
    }

    // SAFETY: the BSP owns this IRQ-masked switch window and both roots contain only the single
    // validated lower-half probe mapping. Kernel execution remains entirely in TTBR1.
    if unsafe { left.root().activate() }.is_err() {
        return Err(());
    }
    let first_a = unsafe { active_el0_translation(PROBE_VA) };
    if first_a != Some(PROBE_FRAME_A) {
        // SAFETY: restore the kernel-only TTBR1 regime before any failure escapes this proof.
        unsafe { Aarch64Root::deactivate() };
        return Err(());
    }

    // SAFETY: same BSP-owned switch window; activation performs the ASID-0 full invalidation.
    if unsafe { right.root().activate() }.is_err() {
        unsafe { Aarch64Root::deactivate() };
        return Err(());
    }
    let value_b = unsafe { active_el0_translation(PROBE_VA) };
    if value_b != Some(PROBE_FRAME_B) {
        unsafe { Aarch64Root::deactivate() };
        return Err(());
    }

    // Switch back once more so a stale B translation is observable as well.
    // SAFETY: same BSP-owned switch window.
    if unsafe { left.root().activate() }.is_err() {
        unsafe { Aarch64Root::deactivate() };
        return Err(());
    }
    let second_a = unsafe { active_el0_translation(PROBE_VA) };
    // SAFETY: every success/failure path returns to the Step-6 final TTBR1-only regime.
    unsafe { Aarch64Root::deactivate() };
    if second_a != Some(PROBE_FRAME_A) {
        return Err(());
    }

    if left.unmap_user_page(backend, PROBE_VA).map_err(|_| ())? != frame_a
        || right.unmap_user_page(backend, PROBE_VA).map_err(|_| ())? != frame_b
    {
        return Err(());
    }
    Ok(())
}

/// Resolves one EL0 read translation through the currently active stage-1 regime without actually
/// dereferencing the user address. `AT S1E0R` therefore tests TTBR0 selection and TLB invalidation
/// directly while remaining independent of EL1 PAN state.
///
/// # Safety
/// Caller must execute at EL1 with a valid active TTBR0 regime and must serialize TTBR0/TCR changes
/// around this instruction sequence.
unsafe fn active_el0_translation(virtual_address: u64) -> Option<u64> {
    let par: u64;
    // SAFETY: caller owns EL1 translation-register access for this proof window.
    unsafe {
        asm!(
            "at s1e0r, {va}",
            "isb",
            "mrs {par}, PAR_EL1",
            va = in(reg) virtual_address,
            par = out(reg) par,
            options(nostack, preserves_flags)
        )
    };
    if par & PAR_FAULT != 0 {
        return None;
    }
    Some((par & PAR_PHYS_MASK) | (virtual_address & (PAGE_SIZE - 1)))
}
