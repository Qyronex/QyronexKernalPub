// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod mmu;
mod transition_state;

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::cell::UnsafeCell;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::mem::MaybeUninit;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::ptr::{read_volatile, write_volatile};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::slice::from_raw_parts;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::sync::atomic::AtomicU32;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_arch_aarch64::{CpuAffinity, TranslationAccess};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_fdt::Blob;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_fdt_aarch64::{MmioRegion, PlatformInfo, parse_platform};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_page_table_aarch64::{
    Backend, Mapper, activate_el1_transition_and_branch, finalize_el1_transition_ttbr0,
    prepare_el1_transition,
};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_paging::{MapFlags, PAGE_SIZE};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use mmu::{
    BootstrapLayout, MmioAlias, PageRange, PhysicalTablePool, PreparedBootstrap, map_step6_layout,
    plan_mmio_aliases, remove_step6_low_aliases,
};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use transition_state::TransitionCoordinator;

const MAX_PROOF_PES: usize = 4;
const BOOT_MMIO_REGIONS: usize = 3;
const QEMU_VIRT_RAM_BASE: u64 = 0x4000_0000;
const MAX_QEMU_DTB_BYTES: usize = 2 * 1024 * 1024;
const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_HEADER_BYTES: usize = 40;
const RESCHEDULE_SGI: u8 = 1;
const PROOF_TIMEOUT_SECONDS: u64 = 5;

const PL011_DR: u64 = 0x000;
const PL011_FR: u64 = 0x018;
const PL011_LCR_H: u64 = 0x02c;
const PL011_CR: u64 = 0x030;
const PL011_IMSC: u64 = 0x038;
const PL011_ICR: u64 = 0x044;
const PL011_FR_TXFF: u32 = 1 << 5;
const PL011_LCR_H_WLEN_8: u32 = 0b11 << 5;
const PL011_CR_UARTEN: u32 = 1 << 0;
const PL011_CR_TXE: u32 = 1 << 8;
const PL011_CR_RXE: u32 = 1 << 9;

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Returns whether the protected Step-6 bootstrap owns this kernel instance.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Selects the protected physical secondary trampoline while the Step-6 bootstrap is active.
///
/// The requested entry is still validated as linker-owned text. This prevents a caller from using
/// the bootstrap override to hide an otherwise invalid PSCI target.
pub fn cpu_on_entry(requested_entry: u64) -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if is_active() {
            let state = boot_state();
            state
                .layout
                .physical_text_entry(requested_entry)
                .unwrap_or_else(|_| fatal_silent());
            let candidate = kernal_aarch64_protected_secondary_start as *const () as u64;
            return state
                .layout
                .physical_text_entry(candidate)
                .unwrap_or_else(|_| fatal_silent());
        }
    }
    requested_entry
}

/// Performs the one-shot all-PE TTBR0 retirement immediately before PSCI SYSTEM_OFF.
///
/// Returning `true` tells the PSCI layer that a successful SYSTEM_OFF must not return into the old
/// caller, because the physical UART/kernel aliases have deliberately been retired.
pub fn before_system_off() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if is_active() {
            protected_shutdown();
            return true;
        }
    }
    false
}

/// Terminal fallback if firmware returns after the protected SYSTEM_OFF path.
pub fn system_off_returned() -> ! {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        if let Some(state) = BOOT_STATE.get() {
            let serial = Serial::new(state.mmio_aliases[0].virtual_region);
            serial.write_str("KERNAL/ARM64: PSCI SYSTEM_OFF unexpectedly returned after TTBR0 retirement\n");
        }
    }
    fatal_silent()
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy)]
struct BootState {
    layout: BootstrapLayout,
    root_table: u64,
    expected_pes: usize,
    physical_mmio: [MmioRegion; BOOT_MMIO_REGIONS],
    mmio_aliases: [MmioAlias; BOOT_MMIO_REGIONS],
    mpidrs: [u64; MAX_PROOF_PES],
    table_pages_used: usize,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
struct BootStateCell {
    state: AtomicU32,
    storage: UnsafeCell<MaybeUninit<BootState>>,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe impl Sync for BootStateCell {}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl BootStateCell {
    const EMPTY: u32 = 0;
    const INITIALIZING: u32 = 1;
    const READY: u32 = 2;

    const fn new() -> Self {
        Self {
            state: AtomicU32::new(Self::EMPTY),
            storage: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&'static self, value: BootState) -> Result<(), ()> {
        self.state
            .compare_exchange(
                Self::EMPTY,
                Self::INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ())?;
        // SAFETY: the successful state transition gives this BSP exclusive initialization access.
        unsafe { (*self.storage.get()).write(value) };
        self.state.store(Self::READY, Ordering::Release);
        Ok(())
    }

    fn get(&'static self) -> Option<&'static BootState> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return None;
        }
        // SAFETY: READY publishes an initialized static object which is immutable thereafter.
        Some(unsafe { (&*self.storage.get()).assume_init_ref() })
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static BOOT_STATE: BootStateCell = BootStateCell::new();
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static TRANSITION: TransitionCoordinator = TransitionCoordinator::new();
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static RETIRE_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static SHUTDOWN_STARTED: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static PE_FINALIZED: [AtomicBool; MAX_PROOF_PES] =
    [const { AtomicBool::new(false) }; MAX_PROOF_PES];

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
core::arch::global_asm!(
    r#"
    .section .text._protected_start, "ax"
    .global kernal_aarch64_protected_start
    .type kernal_aarch64_protected_start, %function
kernal_aarch64_protected_start:
    msr daifset, #0xf
    mov x20, x0

    adrp x2, __bss_start
    add  x2, x2, :lo12:__bss_start
    adrp x3, __bss_end
    add  x3, x3, :lo12:__bss_end
1:
    cmp x2, x3
    b.hs 2f
    str xzr, [x2], #8
    b 1b
2:
    adrp x2, __boot_stack_top
    add  x2, x2, :lo12:__boot_stack_top

    mrs x1, CurrentEL
    cmp x1, #0x8
    b.eq 3f
    cmp x1, #0x4
    b.eq 4f
    b 9f

3:
    mov x3, #1
    lsl x3, x3, #31
    msr HCR_EL2, x3
    mrs x3, CNTHCTL_EL2
    orr x3, x3, #3
    msr CNTHCTL_EL2, x3
    msr CNTVOFF_EL2, xzr
    msr SP_EL1, x2
    adr x3, 4f
    msr ELR_EL2, x3
    mov x3, #0x3c5
    msr SPSR_EL2, x3
    isb
    eret

4:
    mov sp, x2
    mov x0, x20
    bl kernal_aarch64_protected_boot

9:
    wfe
    b 9b

    .section .text._protected_secondary_start, "ax"
    .global kernal_aarch64_protected_secondary_start
    .type kernal_aarch64_protected_secondary_start, %function
kernal_aarch64_protected_secondary_start:
    msr daifset, #0xf
    mov x19, x0

    adrp x2, __secondary_stacks_bottom
    add  x2, x2, :lo12:__secondary_stacks_bottom
    sub x4, x19, #1
    mov x3, #17
    lsl x3, x3, #12
    madd x2, x4, x3, x2
    mov x5, #1
    lsl x5, x5, #12
    add x2, x2, x5
    mov x3, #1
    lsl x3, x3, #16
    add x2, x2, x3

    mrs x1, CurrentEL
    cmp x1, #0x8
    b.eq .Lprotected_secondary_from_el2
    cmp x1, #0x4
    b.eq .Lprotected_secondary_el1
    b .Lprotected_secondary_halt

.Lprotected_secondary_from_el2:
    mov x3, #1
    lsl x3, x3, #31
    msr HCR_EL2, x3
    mrs x3, CNTHCTL_EL2
    orr x3, x3, #3
    msr CNTHCTL_EL2, x3
    msr CNTVOFF_EL2, xzr
    msr SP_EL1, x2
    adr x3, .Lprotected_secondary_el1
    msr ELR_EL2, x3
    mov x3, #0x3c5
    msr SPSR_EL2, x3
    isb
    eret

.Lprotected_secondary_el1:
    mov sp, x2
    mov x0, x19
    bl kernal_aarch64_protected_secondary_boot

.Lprotected_secondary_halt:
    wfe
    b .Lprotected_secondary_halt
"#
);

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn kernal_aarch64_main(dtb_physical: u64) -> !;
    fn kernal_aarch64_secondary_main(index: u64) -> !;

    fn kernal_aarch64_protected_secondary_start();

    static __kernel_phys_base: u8;
    static __kernel_virt_base: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __bss_start: u8;
    static __bss_end: u8;
    static __boot_stack_guard_start: u8;
    static __boot_stack_bottom: u8;
    static __boot_stack_top: u8;
    static __secondary_stacks_bottom: u8;
    static __secondary_stacks_top: u8;
    static __scheduler_worker_guard_start: u8;
    static __scheduler_worker_stack_bottom: u8;
    static __boot_page_tables_start: u8;
    static __boot_page_tables_end: u8;
    static __secondary_stack_stride: u8;
    static __stack_guard_size: u8;
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[unsafe(no_mangle)]
pub extern "C" fn kernal_aarch64_protected_boot(dtb_physical: u64) -> ! {
    let (blob, dtb_bytes) = unsafe { qemu_dtb(dtb_physical) }.unwrap_or_else(fatal_silent);
    let platform = parse_platform::<256>(&blob).unwrap_or_else(|_| fatal_silent());
    let serial_region = platform.pl011.unwrap_or_else(fatal_silent);
    // SAFETY: validated DTB MMIO with translation still disabled.
    let serial = unsafe { Serial::initialize(serial_region) };

    serial.write_str("KERNAL/ARM64: protected bootstrap entered physically\n");
    if kernal_arch_aarch64::current_exception_level() != 1 {
        fatal(&serial, "KERNAL/ARM64: protected bootstrap did not reach EL1\n");
    }
    let gic = platform
        .gic
        .unwrap_or_else(|| fatal(&serial, "KERNAL/ARM64: protected bootstrap requires GICv3\n"));
    let (expected_pes, mpidrs) = discover_mpidrs(&platform)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: protected CPU topology rejected\n"));
    let layout = linker_layout()
        .and_then(BootstrapLayout::validate)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: protected linker layout rejected\n"));
    let physical_mmio = [serial_region, gic.distributor, gic.redistributor];
    let aliases = plan_mmio_aliases(layout, &physical_mmio)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: protected MMIO alias plan failed\n"));
    let prepared = unsafe { prepare_tables(layout, &physical_mmio, dtb_physical, dtb_bytes) }
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: protected page-table construction failed\n"));

    TRANSITION
        .configure(expected_pes)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: protected transition state rejected\n"));
    BOOT_STATE
        .publish(BootState {
            layout,
            root_table: prepared.root_table,
            expected_pes,
            physical_mmio,
            mmio_aliases: aliases,
            mpidrs,
            table_pages_used: prepared.table_pages_used,
        })
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: protected boot state publication failed\n"));

    let hook_physical = layout
        .physical_text_entry(kernal_aarch64_transition_wait_hook as *const () as u64)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: wait-hook physical entry invalid\n"));
    let hook_high = layout
        .high_alias(hook_physical)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: wait-hook high entry invalid\n"));
    kernal_arch_aarch64::install_wait_hook_address(hook_high)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: wait-hook installation failed\n"));
    ACTIVE.store(true, Ordering::Release);

    serial.write_str("KERNAL/ARM64: protected tables ready root=");
    serial.write_hex_u64(prepared.root_table);
    serial.write_str(" pages=");
    serial.write_u64(prepared.table_pages_used as u64);
    serial.write_str("\n");

    let config = prepare_el1_transition(prepared.root_table)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: EL1 transition configuration failed\n"));
    let high_stack = layout
        .high_alias(symbol_address(core::ptr::addr_of!(__boot_stack_top)))
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: BSP high stack invalid\n"));
    let high_entry_physical = layout
        .physical_text_entry(kernal_aarch64_protected_high_main as *const () as u64)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: BSP high continuation invalid\n"));
    let high_entry = layout
        .high_alias(high_entry_physical)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: BSP high continuation alias failed\n"));

    // SAFETY: page tables contain dual mappings for code/stack and the continuation never returns.
    unsafe {
        activate_el1_transition_and_branch(config, high_stack, high_entry, dtb_physical, 0)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[unsafe(no_mangle)]
pub extern "C" fn kernal_aarch64_protected_secondary_boot(index: u64) -> ! {
    if !is_active() {
        fatal_silent();
    }
    let state = boot_state();
    let Ok(index_usize) = usize::try_from(index) else {
        fatal_silent();
    };
    if index_usize == 0 || index_usize >= state.expected_pes {
        fatal_silent();
    }
    let config = prepare_el1_transition(state.root_table).unwrap_or_else(|_| fatal_silent());
    let physical_stack = secondary_stack_top(state.layout, index_usize).unwrap_or_else(fatal_silent);
    let high_stack = state
        .layout
        .high_alias(physical_stack)
        .unwrap_or_else(|_| fatal_silent());
    let high_entry_physical = state
        .layout
        .physical_text_entry(kernal_aarch64_protected_secondary_high as *const () as u64)
        .unwrap_or_else(|_| fatal_silent());
    let high_entry = state
        .layout
        .high_alias(high_entry_physical)
        .unwrap_or_else(|_| fatal_silent());

    // SAFETY: the shared root maps this PE's code/stack in both regimes and the branch is one-way.
    unsafe { activate_el1_transition_and_branch(config, high_stack, high_entry, index, 0) }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
extern "C" fn kernal_aarch64_protected_high_main(dtb_physical: u64, _unused: u64) -> ! {
    let state = boot_state();
    verify_initial_high_state(state).unwrap_or_else(|_| fatal_silent());
    TRANSITION.mark_high(0).unwrap_or_else(|_| fatal_silent());
    kernal_arch_aarch64::send_event();
    // SAFETY: direct relative call from the high alias reaches the old high-alias continuation.
    unsafe { kernal_aarch64_main(dtb_physical) }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
extern "C" fn kernal_aarch64_protected_secondary_high(index: u64, _unused: u64) -> ! {
    let state = boot_state();
    let Ok(index_usize) = usize::try_from(index) else {
        fatal_silent();
    };
    if index_usize == 0 || index_usize >= state.expected_pes {
        fatal_silent();
    }
    let observed = CpuAffinity::from_mpidr(kernal_arch_aarch64::read_mpidr_el1()).packed();
    let expected = CpuAffinity::from_mpidr(state.mpidrs[index_usize]).packed();
    if observed != expected {
        fatal_silent();
    }
    verify_initial_high_state(state).unwrap_or_else(|_| fatal_silent());
    TRANSITION
        .mark_high(index_usize)
        .unwrap_or_else(|_| fatal_silent());
    kernal_arch_aarch64::send_event();
    // SAFETY: relative call remains in TTBR1 and the original secondary continuation never returns.
    unsafe { kernal_aarch64_secondary_main(index) }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernal_aarch64_transition_wait_hook() {
    if !RETIRE_REQUESTED.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: original secondary/BSP runtime installs a static high-alias TPIDR_EL1 before WFI.
    let local = unsafe { kernal_percpu_aarch64::current() };
    let index = local.index().0 as usize;
    if index >= MAX_PROOF_PES {
        fatal_silent();
    }
    if PE_FINALIZED[index]
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    // SAFETY: BSP removed shared low leaves and published RETIRE_REQUESTED with Release ordering.
    unsafe { finalize_el1_transition_ttbr0() };
    TRANSITION
        .mark_protected(index)
        .unwrap_or_else(|_| fatal_silent());
    kernal_arch_aarch64::send_event();
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn protected_shutdown() {
    if SHUTDOWN_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        fatal_silent();
    }
    let state = boot_state();
    let serial = Serial::new(state.mmio_aliases[0].virtual_region);
    if !kernal_arch_aarch64::irqs_masked() {
        fatal(&serial, "KERNAL/ARM64: protected shutdown requires IRQs masked\n");
    }
    wait_for_all_high(state, &serial);

    // SAFETY: all PEs execute high with IRQs masked; no future path consumes physical MMIO pointers.
    unsafe {
        remove_step6_low_aliases(state.root_table, state.layout, &state.physical_mmio)
    }
    .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: low-alias removal failed\n"));
    TRANSITION
        .publish_low_aliases_removed(0)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: low-alias publication failed\n"));
    RETIRE_REQUESTED.store(true, Ordering::Release);
    kernal_arch_aarch64::data_sync_barrier_inner_shareable();
    kernal_arch_aarch64::send_event();

    // SAFETY: BSP has installed TPIDR_EL1 and owns the global shutdown phase.
    unsafe { kernal_aarch64_transition_wait_hook() };
    wake_secondaries(state, &serial);
    wait_for_all_protected(state, &serial);
    verify_final_protection(state)
        .unwrap_or_else(|_| fatal(&serial, "KERNAL/ARM64: protected translation proof failed\n"));

    serial.write_str("KERNAL/ARM64: all PEs retired TTBR0\n");
    serial.write_str("KERNAL/ARM64: W^X + null + guard + high-MMIO proof passed\n");
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn wait_for_all_high(state: &BootState, serial: &Serial) {
    let start = kernal_arch_aarch64::read_virtual_counter();
    let frequency = kernal_arch_aarch64::counter_frequency_hz();
    loop {
        match TRANSITION.all_high() {
            Ok(true) => return,
            Ok(false) => {}
            Err(_) => fatal(serial, "KERNAL/ARM64: high-transition barrier invalid\n"),
        }
        if timeout_expired(start, frequency) {
            fatal(serial, "KERNAL/ARM64: timeout waiting for all high PEs\n");
        }
        for index in 1..state.expected_pes {
            if state.mpidrs[index] == 0 {
                fatal(serial, "KERNAL/ARM64: missing secondary MPIDR at high barrier\n");
            }
        }
        core::hint::spin_loop();
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn wake_secondaries(state: &BootState, serial: &Serial) {
    for index in 1..state.expected_pes {
        let target = CpuAffinity::from_mpidr(state.mpidrs[index]);
        // SAFETY: GICv3 system-register interface is live and this SGI only wakes a parked PE.
        unsafe { kernal_gicv3_aarch64::send_sgi1(RESCHEDULE_SGI, target) }
            .unwrap_or_else(|_| fatal(serial, "KERNAL/ARM64: protected wake SGI failed\n"));
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn wait_for_all_protected(state: &BootState, serial: &Serial) {
    let start = kernal_arch_aarch64::read_virtual_counter();
    let frequency = kernal_arch_aarch64::counter_frequency_hz();
    let mut last_wake = start;
    loop {
        match TRANSITION.all_protected() {
            Ok(true) => return,
            Ok(false) => {}
            Err(_) => fatal(serial, "KERNAL/ARM64: protected barrier invalid\n"),
        }
        let now = kernal_arch_aarch64::read_virtual_counter();
        if frequency != 0 && now.wrapping_sub(last_wake) >= frequency / 20 {
            wake_secondaries(state, serial);
            kernal_arch_aarch64::send_event();
            last_wake = now;
        }
        if timeout_expired(start, frequency) {
            fatal(serial, "KERNAL/ARM64: timeout waiting for TTBR0 retirement\n");
        }
        core::hint::spin_loop();
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn verify_initial_high_state(state: &BootState) -> Result<(), ()> {
    let translation = kernal_arch_aarch64::el1_translation_state();
    if !translation.mmu_enabled() || !translation.write_xor_execute_enabled() {
        return Err(());
    }
    let pc = current_pc();
    let sp = current_sp();
    let expected_text = state.layout.high_alias(state.layout.text.start).map_err(|_| ())?;
    if !high_half(pc) || !high_half(sp) || pc < expected_text {
        return Err(());
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn verify_final_protection(state: &BootState) -> Result<(), ()> {
    if !TRANSITION.all_protected().map_err(|_| ())? {
        return Err(());
    }
    verify_initial_high_state(state)?;
    let high_text = state
        .layout
        .high_alias(state.layout.text.start)
        .map_err(|_| ())?;
    let high_data = state
        .layout
        .high_alias(state.layout.data.start)
        .map_err(|_| ())?;
    let high_guard = state
        .layout
        .high_alias(state.layout.boot_guard.start)
        .map_err(|_| ())?;
    let high_serial = state.mmio_aliases[0].virtual_region.base;

    // SAFETY: all probes execute at EL1 against the active coherent Stage-1 regime.
    let null_read = unsafe {
        kernal_arch_aarch64::probe_el1_translation(0, TranslationAccess::Read)
    };
    let low_text = unsafe {
        kernal_arch_aarch64::probe_el1_translation(
            state.layout.text.start,
            TranslationAccess::Read,
        )
    };
    let low_serial = unsafe {
        kernal_arch_aarch64::probe_el1_translation(
            state.physical_mmio[0].base,
            TranslationAccess::Read,
        )
    };
    let low_dtb = unsafe {
        kernal_arch_aarch64::probe_el1_translation(QEMU_VIRT_RAM_BASE, TranslationAccess::Read)
    };
    let guard_read = unsafe {
        kernal_arch_aarch64::probe_el1_translation(high_guard, TranslationAccess::Read)
    };
    let text_read = unsafe {
        kernal_arch_aarch64::probe_el1_translation(high_text, TranslationAccess::Read)
    };
    let text_write = unsafe {
        kernal_arch_aarch64::probe_el1_translation(high_text, TranslationAccess::Write)
    };
    let data_write = unsafe {
        kernal_arch_aarch64::probe_el1_translation(high_data, TranslationAccess::Write)
    };
    let serial_write = unsafe {
        kernal_arch_aarch64::probe_el1_translation(high_serial, TranslationAccess::Write)
    };

    if !null_read.faulted()
        || !low_text.faulted()
        || !low_serial.faulted()
        || !low_dtb.faulted()
        || !guard_read.faulted()
        || text_read.faulted()
        || !text_write.faulted()
        || data_write.faulted()
        || serial_write.faulted()
    {
        return Err(());
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn prepare_tables(
    layout: BootstrapLayout,
    mmio: &[MmioRegion],
    dtb_physical: u64,
    dtb_bytes: usize,
) -> Result<PreparedBootstrap, ()> {
    // SAFETY: linker reserves this range exclusively and Stage-1 translation is still disabled.
    let mut backend = unsafe { PhysicalTablePool::new(layout.page_tables) }.map_err(|_| ())?;
    let root = backend.allocate_zeroed_table().ok_or(())?;
    {
        let mut mapper = Mapper::new(&mut backend, root).map_err(|_| ())?;
        map_step6_layout(&mut mapper, layout, mmio).map_err(|_| ())?;
        map_dtb_identity(&mut mapper, layout, dtb_physical, dtb_bytes)?;
    }
    Ok(PreparedBootstrap {
        root_table: root,
        table_pages_used: backend.used_pages().map_err(|_| ())?,
    })
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_dtb_identity<B: Backend>(
    mapper: &mut Mapper<'_, B>,
    layout: BootstrapLayout,
    dtb_physical: u64,
    dtb_bytes: usize,
) -> Result<(), ()> {
    if dtb_physical != QEMU_VIRT_RAM_BASE || dtb_bytes < FDT_HEADER_BYTES {
        return Err(());
    }
    let raw_end = dtb_physical.checked_add(dtb_bytes as u64).ok_or(())?;
    let end = raw_end.checked_add(PAGE_SIZE - 1).ok_or(())? & !(PAGE_SIZE - 1);
    if end > layout.kernel_phys_base {
        return Err(());
    }
    let mut page = dtb_physical & !(PAGE_SIZE - 1);
    while page < end {
        mapper
            .map_page(page, page, MapFlags::READ)
            .map_err(|_| ())?;
        page = page.checked_add(PAGE_SIZE).ok_or(())?;
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn linker_layout() -> Result<BootstrapLayout, mmu::Error> {
    Ok(BootstrapLayout {
        kernel_phys_base: symbol_address(core::ptr::addr_of!(__kernel_phys_base)),
        kernel_virt_base: symbol_address(core::ptr::addr_of!(__kernel_virt_base)),
        text: PageRange::new(
            symbol_address(core::ptr::addr_of!(__text_start)),
            symbol_address(core::ptr::addr_of!(__text_end)),
        ),
        rodata: PageRange::new(
            symbol_address(core::ptr::addr_of!(__rodata_start)),
            symbol_address(core::ptr::addr_of!(__rodata_end)),
        ),
        data: PageRange::new(
            symbol_address(core::ptr::addr_of!(__data_start)),
            symbol_address(core::ptr::addr_of!(__data_end)),
        ),
        bss: PageRange::new(
            symbol_address(core::ptr::addr_of!(__bss_start)),
            symbol_address(core::ptr::addr_of!(__bss_end)),
        ),
        boot_guard: PageRange::new(
            symbol_address(core::ptr::addr_of!(__boot_stack_guard_start)),
            symbol_address(core::ptr::addr_of!(__boot_stack_bottom)),
        ),
        secondary_stacks: PageRange::new(
            symbol_address(core::ptr::addr_of!(__secondary_stacks_bottom)),
            symbol_address(core::ptr::addr_of!(__secondary_stacks_top)),
        ),
        secondary_stack_stride: symbol_address(core::ptr::addr_of!(__secondary_stack_stride)),
        stack_guard_size: symbol_address(core::ptr::addr_of!(__stack_guard_size)),
        worker_guard: PageRange::new(
            symbol_address(core::ptr::addr_of!(__scheduler_worker_guard_start)),
            symbol_address(core::ptr::addr_of!(__scheduler_worker_stack_bottom)),
        ),
        page_tables: PageRange::new(
            symbol_address(core::ptr::addr_of!(__boot_page_tables_start)),
            symbol_address(core::ptr::addr_of!(__boot_page_tables_end)),
        ),
    })
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn discover_mpidrs<const N: usize>(platform: &PlatformInfo<N>) -> Result<(usize, [u64; MAX_PROOF_PES]), ()> {
    let bsp = kernal_arch_aarch64::read_mpidr_el1();
    let bsp_affinity = CpuAffinity::from_mpidr(bsp).packed();
    let mut mpidrs = [0u64; MAX_PROOF_PES];
    mpidrs[0] = bsp;
    let mut count = 1usize;
    let mut found_bsp = false;

    for cpu in platform.cpus().iter().filter(|cpu| cpu.enabled) {
        let affinity = CpuAffinity::from_mpidr(cpu.mpidr).packed();
        if affinity == bsp_affinity {
            if found_bsp {
                return Err(());
            }
            found_bsp = true;
            continue;
        }
        if count == MAX_PROOF_PES {
            return Err(());
        }
        if mpidrs[..count]
            .iter()
            .any(|existing| CpuAffinity::from_mpidr(*existing).packed() == affinity)
        {
            return Err(());
        }
        mpidrs[count] = cpu.mpidr;
        count += 1;
    }
    if !found_bsp {
        return Err(());
    }
    Ok((count, mpidrs))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn secondary_stack_top(layout: BootstrapLayout, index: usize) -> Option<u64> {
    let slot = index.checked_sub(1)? as u64;
    let offset = slot.checked_mul(layout.secondary_stack_stride)?;
    let guard = layout.secondary_stacks.start.checked_add(offset)?;
    let top = guard.checked_add(layout.secondary_stack_stride)?;
    (top <= layout.secondary_stacks.end).then_some(top)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn boot_state() -> &'static BootState {
    BOOT_STATE.get().unwrap_or_else(fatal_silent)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn timeout_expired(start: u64, frequency: u64) -> bool {
    frequency == 0
        || kernal_arch_aarch64::read_virtual_counter().wrapping_sub(start)
            >= frequency.saturating_mul(PROOF_TIMEOUT_SECONDS)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn symbol_address(symbol: *const u8) -> u64 {
    symbol as u64
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn high_half(address: u64) -> bool {
    address >> 48 == 0xffff
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn current_pc() -> u64 {
    let pc: u64;
    // SAFETY: ADR observes the current instruction address without memory access.
    unsafe { core::arch::asm!("adr {pc}, .", pc = out(reg) pc, options(nomem, nostack, preserves_flags)) };
    pc
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn current_sp() -> u64 {
    let sp: u64;
    // SAFETY: pure architectural SP read.
    unsafe { core::arch::asm!("mov {sp}, sp", sp = out(reg) sp, options(nomem, nostack, preserves_flags)) };
    sp
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn qemu_dtb(physical: u64) -> Option<(Blob<'static>, usize)> {
    if physical != QEMU_VIRT_RAM_BASE {
        return None;
    }
    let magic = unsafe { read_be_u32_volatile(physical) }?;
    if magic != FDT_MAGIC {
        return None;
    }
    let total_size = unsafe { read_be_u32_volatile(physical.checked_add(4)?) }? as usize;
    if !(FDT_HEADER_BYTES..=MAX_QEMU_DTB_BYTES).contains(&total_size) {
        return None;
    }
    // SAFETY: QEMU supplies the DTB in RAM; size is bounded before constructing the slice.
    let bytes = unsafe { from_raw_parts(physical as *const u8, total_size) };
    Some((Blob::parse(bytes).ok()?, total_size))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn read_be_u32_volatile(address: u64) -> Option<u32> {
    if address & 3 != 0 {
        return None;
    }
    // SAFETY: caller restricts this to the QEMU DTB header in RAM.
    Some(u32::from_be(unsafe { read_volatile(address as *const u32) }))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy)]
struct Serial {
    region: MmioRegion,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Serial {
    const fn new(region: MmioRegion) -> Self {
        Self { region }
    }

    unsafe fn initialize(region: MmioRegion) -> Self {
        let serial = Self::new(region);
        unsafe {
            serial.write_register(PL011_CR, 0);
            serial.write_register(PL011_IMSC, 0);
            serial.write_register(PL011_ICR, u32::MAX);
            serial.write_register(PL011_LCR_H, PL011_LCR_H_WLEN_8);
            serial.write_register(
                PL011_CR,
                PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE,
            );
        }
        serial
    }

    fn write_str(&self, text: &str) {
        for byte in text.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }

    fn write_hex_u64(&self, value: u64) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.write_str("0x");
        for shift in (0..16).rev() {
            self.write_byte(HEX[((value >> (shift * 4)) & 0xf) as usize]);
        }
    }

    fn write_u64(&self, mut value: u64) {
        if value == 0 {
            self.write_byte(b'0');
            return;
        }
        let mut digits = [0u8; 20];
        let mut cursor = digits.len();
        while value != 0 {
            cursor -= 1;
            digits[cursor] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        for byte in &digits[cursor..] {
            self.write_byte(*byte);
        }
    }

    fn write_byte(&self, byte: u8) {
        while unsafe { self.read_register(PL011_FR) } & PL011_FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        // SAFETY: checked MMIO region and transmitter-ready status above.
        unsafe { self.write_register(PL011_DR, byte as u32) };
    }

    unsafe fn read_register(&self, offset: u64) -> u32 {
        let address = self.checked_address(offset).unwrap_or_else(fatal_silent);
        // SAFETY: address is bounded inside the validated PL011 aperture.
        unsafe { read_volatile(address as *const u32) }
    }

    unsafe fn write_register(&self, offset: u64, value: u32) {
        let address = self.checked_address(offset).unwrap_or_else(fatal_silent);
        // SAFETY: address is bounded inside the validated PL011 aperture.
        unsafe { write_volatile(address as *mut u32, value) };
    }

    fn checked_address(&self, offset: u64) -> Option<u64> {
        let address = self.region.base.checked_add(offset)?;
        let end = address.checked_add(core::mem::size_of::<u32>() as u64)?;
        let region_end = self.region.base.checked_add(self.region.size)?;
        (self.region.base != 0 && address >= self.region.base && end <= region_end).then_some(address)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn fatal(serial: &Serial, message: &str) -> ! {
    serial.write_str(message);
    fatal_silent()
}

fn fatal_silent() -> ! {
    loop {
        #[cfg(target_arch = "aarch64")]
        // SAFETY: WFE is a side-effect-free terminal wait in this fail-stop path.
        unsafe {
            core::arch::asm!("wfe", options(nomem, nostack));
        }
        #[cfg(not(target_arch = "aarch64"))]
        core::hint::spin_loop();
    }
}
