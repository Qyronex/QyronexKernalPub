// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::RuntimeTablePool;
use kernal_address_space_aarch64::{Aarch64AddressSpaceExt, Aarch64Root};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_paging::PAGE_SIZE;
use kernal_usercopy::Error as UsercopyError;
use kernal_vm::{AddressSpace, Backing, USER_MIN, VmPerms, Vma};

const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const STEP10_DATA_FRAME: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES - (7 * PAGE_SIZE);
const STEP9_CODE_FRAME: u64 = STEP10_DATA_FRAME + PAGE_SIZE;
const USER_DATA_VA: u64 = USER_MIN + 0x1c0_000;
const UNMAPPED_USER_VA: u64 = USER_DATA_VA + (2 * PAGE_SIZE);
const DATA_OFFSET: u64 = 0x80;
const PATTERN: [u8; 16] = [
    0x4b, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x2d, 0x53, 0x31, 0x30, 0xa5, 0x5a, 0x11, 0x22, 0x33, 0x44,
];

pub fn run(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    if !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 10 usercopy proof requires IRQs masked\n",
        );
    }

    let space = prepare_space(backend).unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 10 usercopy address-space preparation failed\n",
        )
    });

    // SAFETY: the BSP exclusively owns TTBR0 while secondary PEs remain at the protected-runtime
    // rendezvous. The root contains exactly one user RW-NX page dedicated to this proof.
    if unsafe { space.root().activate() }.is_err() {
        crate::fatal(serial, "KERNAL/ARM64: Step 10 TTBR0 activation failed\n");
    }

    let result = run_active_proof(serial);

    // SAFETY: the active proof returned at EL1 with PAN restored and no user execution in flight.
    unsafe { Aarch64Root::deactivate() };

    if result.is_err() {
        crate::fatal(serial, "KERNAL/ARM64: Step 10 usercopy/PAN proof failed\n");
    }
}

fn prepare_space(backend: &mut RuntimeTablePool) -> Result<AddressSpace<Aarch64Root, 1>, ()> {
    let state = crate::boot_state();
    let qemu_ram_end = crate::QEMU_VIRT_RAM_BASE
        .checked_add(QEMU_RAM_BYTES)
        .ok_or(())?;
    let expected_step9_code = qemu_ram_end.checked_sub(6 * PAGE_SIZE).ok_or(())?;
    if STEP9_CODE_FRAME != expected_step9_code
        || STEP10_DATA_FRAME.checked_add(PAGE_SIZE) != Some(STEP9_CODE_FRAME)
        || STEP10_DATA_FRAME < state.layout.bss.end
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

    let data_frame = PhysFrame::from_start_address(STEP10_DATA_FRAME).ok_or(())?;
    if reserved.contains(data_frame) {
        return Err(());
    }

    let mut space = AddressSpace::<Aarch64Root, 1>::new(Aarch64Root::new(backend).map_err(|_| ())?);
    let data_vma = Vma::new(
        USER_DATA_VA,
        PAGE_SIZE,
        VmPerms::READ.union(VmPerms::WRITE),
        Backing::Anonymous,
    )
    .map_err(|_| ())?;
    space
        .map_user_page(backend, data_vma, data_frame, &reserved)
        .map_err(|_| ())?;
    if space
        .translate_user(backend, USER_DATA_VA)
        .map_err(|_| ())?
        != STEP10_DATA_FRAME
    {
        return Err(());
    }
    Ok(space)
}

fn run_active_proof(serial: &crate::Serial) -> Result<(), ()> {
    kernal_usercopy_aarch64::enable_pan_default().map_err(|_| ())?;
    if kernal_usercopy_aarch64::pan_enabled().map_err(|_| ())? != true {
        return Err(());
    }
    serial.write_str("KERNAL/S10: ARM64 PAN default-deny active\n");

    let address = USER_DATA_VA.checked_add(DATA_OFFSET).ok_or(())?;
    kernal_usercopy_aarch64::copy_to_user(address, &PATTERN).map_err(|_| ())?;
    let mut observed = [0u8; PATTERN.len()];
    kernal_usercopy_aarch64::copy_from_user(&mut observed, address).map_err(|_| ())?;
    if observed != PATTERN || kernal_usercopy_aarch64::pan_enabled().map_err(|_| ())? != true {
        return Err(());
    }
    serial.write_str("KERNAL/S10: ARM64 bounded usercopy read/write roundtrip passed\n");

    let mut byte = [0u8; 1];
    if kernal_usercopy_aarch64::copy_from_user(&mut byte, UNMAPPED_USER_VA)
        != Err(UsercopyError::Fault)
        || kernal_usercopy_aarch64::copy_to_user(UNMAPPED_USER_VA, &[0x5a])
            != Err(UsercopyError::Fault)
        || kernal_usercopy_aarch64::pan_enabled().map_err(|_| ())? != true
    {
        return Err(());
    }
    serial.write_str("KERNAL/S10: ARM64 unmapped usercopy faults recovered as errors\n");

    // SAFETY: address remains mapped user-readable by the proof root; the helper intentionally keeps
    // PAN enabled and recovers only the exact expected direct-read data abort.
    if !unsafe { kernal_usercopy_aarch64::qemu_probe_pan_blocks_read(address) }.map_err(|_| ())?
        || kernal_usercopy_aarch64::pan_enabled().map_err(|_| ())? != true
    {
        return Err(());
    }
    serial.write_str("KERNAL/S10: ARM64 direct EL1 user read blocked by PAN\n");
    Ok(())
}
