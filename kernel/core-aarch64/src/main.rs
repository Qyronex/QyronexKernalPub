// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::slice::{from_raw_parts, from_raw_parts_mut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use kernal_arch_aarch64::CpuAffinity;
use kernal_exceptions_aarch64::{ExceptionFrame, ExceptionKind};
use kernal_fdt::Blob;
use kernal_fdt_aarch64::{MmioRegion, PlatformInfo, PsciConduit, parse_platform};
use kernal_gicv3_aarch64::{
    AcknowledgedInterrupt, Error as GicError, GicV3, MmioAccess, RESCHEDULE_SGI_DEFAULT,
    Region as GicRegion,
};
use kernal_percpu::CpuIndex;
use kernal_percpu_aarch64::CpuLocalCell;
use kernal_psci_aarch64::{Conduit, Psci};
use kernal_scheduler::ThreadId;
use kernal_scheduler_cpu::CpuSchedulerCell;
use kernal_thread_context::KernelStack;

#[cfg(feature = "qemu-proof")]
mod step15_qemu;

/*
 * QEMU virt documents RAM at 0x4000_0000 and, for bare-metal ELF boots, places its generated DTB
 * at the start of RAM. This constant is deliberately confined to the QEMU proof entry path; device
 * MMIO addresses are never hard-coded and are discovered from that DTB.
 */
const QEMU_VIRT_RAM_BASE: u64 = 0x4000_0000;
const MAX_QEMU_DTB_BYTES: usize = 2 * 1024 * 1024;
const MAX_BOOT_CPUS: usize = 256;
const MAX_PROOF_CPUS: usize = 4;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_HEADER_BYTES: usize = 40;

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

const TIMER_INTERVAL_NS: u64 = 5_000_000;
const REQUIRED_TIMER_IRQS: u32 = 2;
const REQUIRED_RESCHEDULE_IRQS: u32 = 1;
const NO_INTERRUPT: u32 = u32::MAX;
const PROOF_TIMEOUT_SECONDS: u64 = 5;

const CPU_OFFLINE: u32 = 0;
const CPU_STARTING: u32 = 1;
const CPU_ONLINE: u32 = 2;
const CPU_FAILED: u32 = 3;

const STACK_GUARD_BYTES: u64 = 0x1000;
const BOOT_STACK_BYTES: u64 = 0x4_0000;
const SECONDARY_STACK_BYTES: u64 = 0x4_0000;
const SCHEDULER_WORKER_STACK_BYTES: u64 = 0x1_0000;
const SECONDARY_STACK_STRIDE: u64 = STACK_GUARD_BYTES + SECONDARY_STACK_BYTES;
const SCHEDULER_THREADS_PER_CPU: usize = 16;
const REMOTE_WAKE_SLOTS: usize = 8;
const IDLE_PRIORITY: u8 = 0;
const SMOKE_WORKER_PRIORITY: u8 = 63;
const SCHEDULER_SMOKE_IDLE: u32 = 0;
const SCHEDULER_SMOKE_WORKER_ENTERED: u32 = 1;
const SCHEDULER_SMOKE_REAPED: u32 = 2;
const SCHEDULER_SMOKE_FAILED: u32 = u32::MAX;

static CPU_LOCALS: [CpuLocalCell; MAX_PROOF_CPUS] = [const { CpuLocalCell::new() }; MAX_PROOF_CPUS];
static CPU_SCHEDULERS: [CpuSchedulerCell<SCHEDULER_THREADS_PER_CPU, REMOTE_WAKE_SLOTS>;
    MAX_PROOF_CPUS] = [const { CpuSchedulerCell::new() }; MAX_PROOF_CPUS];
static CPU_MPIDRS: [AtomicU64; MAX_PROOF_CPUS] = [const { AtomicU64::new(0) }; MAX_PROOF_CPUS];
static CPU_STATES: [AtomicU32; MAX_PROOF_CPUS] =
    [const { AtomicU32::new(CPU_OFFLINE) }; MAX_PROOF_CPUS];
static TIMER_IRQS: [AtomicU32; MAX_PROOF_CPUS] = [const { AtomicU32::new(0) }; MAX_PROOF_CPUS];
static RESCHEDULE_IRQS: [AtomicU32; MAX_PROOF_CPUS] = [const { AtomicU32::new(0) }; MAX_PROOF_CPUS];
static UNEXPECTED_IRQS: [AtomicU32; MAX_PROOF_CPUS] =
    [const { AtomicU32::new(NO_INTERRUPT) }; MAX_PROOF_CPUS];
static RESCHEDULE_PROBE_PUBLISHED: [AtomicBool; MAX_PROOF_CPUS] =
    [const { AtomicBool::new(false) }; MAX_PROOF_CPUS];
static PROOF_DONE: [AtomicBool; MAX_PROOF_CPUS] =
    [const { AtomicBool::new(false) }; MAX_PROOF_CPUS];
static RUNTIME_SCHEDULER_TICK_ACTIVE: [AtomicBool; MAX_PROOF_CPUS] =
    [const { AtomicBool::new(false) }; MAX_PROOF_CPUS];
static BSP_REMOTE_SGI_SENT: AtomicBool = AtomicBool::new(false);
static EXPECTED_CPUS: AtomicU32 = AtomicU32::new(0);
static SCHEDULER_SMOKE_STATE: AtomicU32 = AtomicU32::new(SCHEDULER_SMOKE_IDLE);

static TIMER_INTID: AtomicU32 = AtomicU32::new(NO_INTERRUPT);
static GICD_BASE: AtomicU64 = AtomicU64::new(0);
static GICD_SIZE: AtomicU64 = AtomicU64::new(0);
static GICR_BASE: AtomicU64 = AtomicU64::new(0);
static GICR_SIZE: AtomicU64 = AtomicU64::new(0);

/*
 * BSP entry accepts either EL1 directly or the common EL2 firmware/hypervisor handoff. Interrupts
 * stay masked. EL2 is reduced to non-secure EL1h with AArch64 execution and EL1 virtual-counter
 * access. No stack is used until the linker-owned bootstrap stack has been selected.
 */
global_asm!(
    r#"
    .section .text._start, "ax"
    .global _start
    .type _start, %function
_start:
    msr daifset, #0xf

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
    mov x0, #1
    lsl x0, x0, #30
    bl kernal_aarch64_main

9:
    wfe
    b 9b

    .section .text._secondary_start, "ax"
    .global kernal_aarch64_secondary_entry
    .type kernal_aarch64_secondary_entry, %function
kernal_aarch64_secondary_entry:
    msr daifset, #0xf
    mov x19, x0

    adrp x2, __secondary_stacks_bottom
    add  x2, x2, :lo12:__secondary_stacks_bottom
    sub x4, x19, #1
    mov x3, #65
    lsl x3, x3, #12
    madd x2, x4, x3, x2
    mov x5, #1
    lsl x5, x5, #12
    add x2, x2, x5
    mov x3, #1
    lsl x3, x3, #18
    add x2, x2, x3

    mrs x1, CurrentEL
    cmp x1, #0x8
    b.eq .Lsecondary_from_el2
    cmp x1, #0x4
    b.eq .Lsecondary_el1
    b .Lsecondary_halt

.Lsecondary_from_el2:
    mov x3, #1
    lsl x3, x3, #31
    msr HCR_EL2, x3
    mrs x3, CNTHCTL_EL2
    orr x3, x3, #3
    msr CNTHCTL_EL2, x3
    msr CNTVOFF_EL2, xzr
    msr SP_EL1, x2
    adr x3, .Lsecondary_el1
    msr ELR_EL2, x3
    mov x3, #0x3c5
    msr SPSR_EL2, x3
    isb
    eret

.Lsecondary_el1:
    mov sp, x2
    mov x0, x19
    bl kernal_aarch64_secondary_main

.Lsecondary_halt:
    wfe
    b .Lsecondary_halt
"#
);

#[derive(Clone, Copy)]
struct Pl011 {
    region: MmioRegion,
}

impl Pl011 {
    /// # Safety
    /// `region` must describe a validated PL011 Device aperture mapped in the active address regime
    /// before any method is called.
    unsafe fn initialize(region: MmioRegion) -> Self {
        let serial = Self { region };
        unsafe {
            serial.write_register(PL011_CR, 0);
            serial.write_register(PL011_IMSC, 0);
            serial.write_register(PL011_ICR, u32::MAX);
            serial.write_register(PL011_LCR_H, PL011_LCR_H_WLEN_8);
            serial.write_register(PL011_CR, PL011_CR_UARTEN | PL011_CR_TXE | PL011_CR_RXE);
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
            let nibble = ((value >> (shift * 4)) & 0xf) as usize;
            self.write_byte(HEX[nibble]);
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
        unsafe { self.write_register(PL011_DR, byte as u32) };
    }

    unsafe fn read_register(&self, offset: u64) -> u32 {
        let address = self
            .checked_address(offset)
            .unwrap_or_else(|| fatal_silent());
        // SAFETY: constructor contract and checked aperture guarantee a valid PL011 register access.
        unsafe { read_volatile(address as *const u32) }
    }

    unsafe fn write_register(&self, offset: u64, value: u32) {
        let address = self
            .checked_address(offset)
            .unwrap_or_else(|| fatal_silent());
        // SAFETY: constructor contract and checked aperture guarantee a valid PL011 register access.
        unsafe { write_volatile(address as *mut u32, value) };
    }

    fn checked_address(&self, offset: u64) -> Option<u64> {
        let address = self.region.base.checked_add(offset)?;
        let end = address.checked_add(core::mem::size_of::<u32>() as u64)?;
        let region_end = self.region.base.checked_add(self.region.size)?;
        (self.region.base != 0 && address >= self.region.base && end <= region_end)
            .then_some(address)
    }
}
struct PhysicalGicMmio;

impl MmioAccess for PhysicalGicMmio {
    fn read32(&self, address: u64) -> Result<u32, GicError> {
        if address & 3 != 0 {
            return Err(GicError::Mmio);
        }
        // SAFETY: GicV3 bounds every access against DTB-derived Distributor/Redistributor regions.
        Ok(unsafe { read_volatile(address as *const u32) })
    }

    fn write32(&mut self, address: u64, value: u32) -> Result<(), GicError> {
        if address & 3 != 0 {
            return Err(GicError::Mmio);
        }
        // SAFETY: GicV3 bounds every access against the DTB-derived Distributor/Redistributor region.
        unsafe { write_volatile(address as *mut u32, value) };
        Ok(())
    }

    fn read64(&self, address: u64) -> Result<u64, GicError> {
        if address & 7 != 0 {
            return Err(GicError::Mmio);
        }
        // SAFETY: GicV3 bounds every access against the DTB-derived Redistributor region.
        Ok(unsafe { read_volatile(address as *const u64) })
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernal_aarch64_main(dtb_physical: u64) -> ! {
    let blob = unsafe { qemu_dtb(dtb_physical) }.unwrap_or_else(|| fatal_silent());
    let platform = parse_platform::<MAX_BOOT_CPUS>(&blob).unwrap_or_else(|_| fatal_silent());
    let serial_physical = platform.pl011.unwrap_or_else(|| fatal_silent());
    let serial_region = kernal_protected_boot_aarch64::runtime_mmio_region(serial_physical);
    // SAFETY: the FDT parser validated the physical aperture; protected boot resolves it to the
    // mapped TTBR1 Device alias while active, otherwise the original physical aperture is used.
    let serial = unsafe { Pl011::initialize(serial_region) };

    serial.write_str("KERNAL/ARM64: physical entry reached\n");
    serial.write_str("KERNAL/ARM64: DTB accepted\n");

    let exception_level = kernal_arch_aarch64::current_exception_level();
    serial.write_str("KERNAL/ARM64: CurrentEL=");
    serial.write_u64(exception_level as u64);
    serial.write_str("\n");
    if exception_level != 1 {
        fatal_with_serial(&serial, "KERNAL/ARM64: expected EL1 after bootstrap\n");
    }

    serial.write_str("KERNAL/ARM64: CPUs discovered=");
    serial.write_u64(platform.cpus().len() as u64);
    serial.write_str("\n");
    if platform.cpus().is_empty() {
        fatal_with_serial(&serial, "KERNAL/ARM64: DTB contains no CPUs\n");
    }

    let Some(gic_physical) = platform.gic else {
        fatal_with_serial(&serial, "KERNAL/ARM64: GICv3 node missing\n");
    };
    serial.write_str("KERNAL/ARM64: GICD=");
    serial.write_hex_u64(gic_physical.distributor.base);
    serial.write_str(" GICR=");
    serial.write_hex_u64(gic_physical.redistributor.base);
    serial.write_str("\n");
    let gic_info = kernal_fdt_aarch64::GicV3Info {
        distributor: kernal_protected_boot_aarch64::runtime_mmio_region(gic_physical.distributor),
        redistributor: kernal_protected_boot_aarch64::runtime_mmio_region(
            gic_physical.redistributor,
        ),
    };

    let Some(timer_info) = platform.timer_interrupts else {
        fatal_with_serial(&serial, "KERNAL/ARM64: architected timer node missing\n");
    };
    serial.write_str("KERNAL/ARM64: virtual timer INTID=");
    serial.write_u64(timer_info.virtual_timer as u64);
    serial.write_str("\n");

    let frequency = kernal_arch_aarch64::counter_frequency_hz();
    serial.write_str("KERNAL/ARM64: counter Hz=");
    serial.write_u64(frequency);
    serial.write_str("\n");
    if frequency == 0 {
        fatal_with_serial(&serial, "KERNAL/ARM64: zero counter frequency\n");
    }

    let psci = psci_from_platform(&platform)
        .unwrap_or_else(|| fatal_with_serial(&serial, "KERNAL/ARM64: PSCI conduit missing\n"));
    // SAFETY: the conduit came from the validated DTB and bootstrap normalized execution to EL1.
    let version = unsafe { psci.version() }
        .unwrap_or_else(|_| fatal_with_serial(&serial, "KERNAL/ARM64: PSCI version call failed\n"));
    serial.write_str("KERNAL/ARM64: PSCI ");
    serial.write_u64(version.major as u64);
    serial.write_str(".");
    serial.write_u64(version.minor as u64);
    serial.write_str(" accepted\n");

    let expected_cpus = configure_cpu_slots(&platform, &serial);
    serial.write_str("KERNAL/ARM64: enabled proof PEs=");
    serial.write_u64(expected_cpus as u64);
    serial.write_str("\n");

    prepare_bsp_cpu_local(&serial);
    let bsp_idle = prepare_bsp_scheduler(&serial);
    run_bsp_scheduler_smoke(&serial, bsp_idle);

    publish_irq_runtime(gic_info, timer_info.virtual_timer);
    install_bsp_irq_runtime(&serial, gic_info, timer_info.virtual_timer);
    CPU_STATES[0].store(CPU_ONLINE, Ordering::Release);
    serial.write_str("KERNAL/ARM64: BSP per-CPU + scheduler idle + EL1 vectors + GICv3 ready\n");

    start_secondary_cpus(&serial, psci, expected_cpus);
    #[cfg(feature = "qemu-proof")]
    step15_qemu::install(&serial);
    kernal_protected_boot_aarch64::enter_runtime_protected_regime();
    serial.write_str("KERNAL/ARM64: final TTBR1-only runtime entered\n");
    dispatch_reschedule_probes(&serial, expected_cpus);

    if prove_current_cpu_interrupt_delivery(0).is_err() {
        fatal_with_serial(&serial, "KERNAL/ARM64: BSP interrupt proof failed\n");
    }
    PROOF_DONE[0].store(true, Ordering::Release);

    wait_for_all_proofs(&serial, expected_cpus);
    print_proof_summary(&serial, expected_cpus);
    serial.write_str("KERNAL/ARM64: PSCI SMP IRQ proof passed\n");

    #[cfg(all(feature = "qemu-proof", feature = "step15-qemu-proof"))]
    {
        if !PROOF_DONE[0].load(Ordering::Acquire) {
            fatal_with_serial(
                &serial,
                "KERNAL/ARM64: runtime scheduler tick before IRQ proof completion\n",
            );
        }
        // The bounded bootstrap proof intentionally disarms CNTV after REQUIRED_TIMER_IRQS. Step 30
        // needs a live scheduling tick again before EL0 resumes; otherwise a CPU-bound fork child can
        // monopolize a one-vCPU guest and prevent its parent from issuing SIGSTOP/SIGCONT.
        // SAFETY: BSP owns the local virtual timer, IRQs are still masked, and the PPI/GIC interface
        // remain installed from the completed interrupt proof.
        if unsafe { kernal_timer_aarch64::arm_after_ns(TIMER_INTERVAL_NS) }.is_err() {
            fatal_with_serial(&serial, "KERNAL/ARM64: runtime scheduler tick arm failed\n");
        }
        RUNTIME_SCHEDULER_TICK_ACTIVE[0].store(true, Ordering::Release);

        // SAFETY: the per-PE interrupt proof returned with IRQs masked and no preemption/IRQ nesting;
        // the persistent Step-15 runtime owns the exact Process/address-space generation published by
        // the protected callback. The helper ends that borrow before entering the scheduler switch.
        if unsafe { step15_qemu::resume_initial_linux(&serial) }.is_err() {
            fatal_with_serial(
                &serial,
                "KERNAL/ARM64: Step 15 initial Linux resume failed\n",
            );
        }
        serial.write_str("KERNAL/ARM64: requesting PSCI SYSTEM_OFF after Step 15 resume\n");
        // SAFETY: if the suspended BSP idle context resumes, the live diagnostic path is complete.
        let _ = unsafe { psci.system_off() };
        fatal_with_serial(&serial, "KERNAL/ARM64: PSCI SYSTEM_OFF returned\n");
    }

    #[cfg(all(feature = "qemu-proof", not(feature = "step15-qemu-proof")))]
    {
        serial.write_str("KERNAL/ARM64: requesting PSCI SYSTEM_OFF\n");
        // SAFETY: proof path has completed all current smoke checks and owns the VM shutdown.
        let _ = unsafe { psci.system_off() };
        fatal_with_serial(&serial, "KERNAL/ARM64: PSCI SYSTEM_OFF returned\n");
    }

    #[cfg(not(feature = "qemu-proof"))]
    idle_forever()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernal_aarch64_secondary_main(raw_index: u64) -> ! {
    let Ok(index) = usize::try_from(raw_index) else {
        fatal_silent();
    };
    let expected_cpus = EXPECTED_CPUS.load(Ordering::Acquire) as usize;
    if index == 0 || index >= expected_cpus || index >= MAX_PROOF_CPUS {
        fatal_silent();
    }
    if kernal_arch_aarch64::current_exception_level() != 1 {
        secondary_fail(index);
    }

    let current_mpidr = kernal_arch_aarch64::read_mpidr_el1();
    let expected_mpidr = CPU_MPIDRS[index].load(Ordering::Acquire);
    if CpuAffinity::from_mpidr(current_mpidr).packed()
        != CpuAffinity::from_mpidr(expected_mpidr).packed()
    {
        secondary_fail(index);
    }

    let Ok(cpu_index) = u16::try_from(index) else {
        secondary_fail(index);
    };
    let cpu = CpuIndex(cpu_index);
    let local = CPU_LOCALS[index]
        .prepare(cpu, current_mpidr)
        .unwrap_or_else(|_| secondary_fail(index));
    // SAFETY: this PE is still non-migratable, IRQ-masked bootstrap code and owns `local`.
    unsafe { kernal_percpu_aarch64::install_bootstrap_tpidr_el1(local) }
        .unwrap_or_else(|_| secondary_fail(index));

    if prepare_secondary_scheduler(index, cpu).is_err() {
        secondary_fail(index);
    }
    if install_secondary_irq_runtime().is_err() {
        secondary_fail(index);
    }
    if CPU_STATES[index]
        .compare_exchange(
            CPU_STARTING,
            CPU_ONLINE,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        secondary_fail(index);
    }

    // Hold every secondary IRQ-masked until BSP has removed all low aliases and every PE has
    // retired TTBR0. This uses only SEV/shared state, so no proof SGI is consumed by the barrier.
    kernal_protected_boot_aarch64::wait_for_runtime_protected_regime();

    /*
     * For SMP runs, PE 1 supplies a genuinely remote reschedule SGI to the BSP. This avoids
     * counting a BSP self-SGI as the multi-PE proof while keeping the one-PE smoke path valid.
     */
    if index == 1 && expected_cpus > 1 {
        RESCHEDULE_PROBE_PUBLISHED[0].store(true, Ordering::Release);
        let bsp = CpuAffinity::from_mpidr(CPU_MPIDRS[0].load(Ordering::Acquire));
        // SAFETY: this secondary's GIC CPU interface is live and publication precedes the SGI.
        if unsafe { kernal_gicv3_aarch64::send_sgi1(RESCHEDULE_SGI_DEFAULT, bsp) }.is_err() {
            secondary_fail(index);
        }
        BSP_REMOTE_SGI_SENT.store(true, Ordering::Release);
    }

    if prove_current_cpu_interrupt_delivery(index).is_err() {
        secondary_fail(index);
    }
    PROOF_DONE[index].store(true, Ordering::Release);
    kernal_arch_aarch64::send_event();

    idle_forever()
}

fn configure_cpu_slots<const N: usize>(platform: &PlatformInfo<N>, serial: &Pl011) -> usize {
    let bsp_mpidr = kernal_arch_aarch64::read_mpidr_el1();
    let bsp_affinity = CpuAffinity::from_mpidr(bsp_mpidr).packed();
    CPU_MPIDRS[0].store(bsp_mpidr, Ordering::Release);
    CPU_STATES[0].store(CPU_STARTING, Ordering::Release);

    let mut found_bsp = false;
    let mut count = 1usize;
    for cpu in platform.cpus().iter().filter(|cpu| cpu.enabled) {
        let affinity = CpuAffinity::from_mpidr(cpu.mpidr).packed();
        if affinity == bsp_affinity {
            if found_bsp {
                fatal_with_serial(
                    serial,
                    "KERNAL/ARM64: duplicate BSP affinity in DTB CPU list\n",
                );
            }
            found_bsp = true;
            continue;
        }
        if count == MAX_PROOF_CPUS {
            fatal_with_serial(
                serial,
                "KERNAL/ARM64: proof supports at most 4 enabled PEs\n",
            );
        }
        for existing_mpidr in CPU_MPIDRS.iter().take(count) {
            let existing_affinity =
                CpuAffinity::from_mpidr(existing_mpidr.load(Ordering::Acquire)).packed();
            if affinity == existing_affinity {
                fatal_with_serial(serial, "KERNAL/ARM64: duplicate CPU affinity in DTB\n");
            }
        }
        CPU_MPIDRS[count].store(cpu.mpidr, Ordering::Release);
        count += 1;
    }

    if !found_bsp {
        fatal_with_serial(
            serial,
            "KERNAL/ARM64: BSP affinity missing from DTB CPU list\n",
        );
    }
    EXPECTED_CPUS.store(count as u32, Ordering::Release);
    count
}

fn prepare_bsp_cpu_local(serial: &Pl011) {
    let mpidr = kernal_arch_aarch64::read_mpidr_el1();
    let local = CPU_LOCALS[0]
        .prepare(CpuIndex(0), mpidr)
        .unwrap_or_else(|_| {
            fatal_with_serial(serial, "KERNAL/ARM64: BSP CpuLocal prepare failed\n")
        });
    // SAFETY: BSP bootstrap is non-migratable and still has IRQs masked.
    unsafe { kernal_percpu_aarch64::install_bootstrap_tpidr_el1(local) }
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: BSP TPIDR_EL1 failed\n"));
}

fn prepare_bsp_scheduler(serial: &Pl011) -> ThreadId {
    let scheduler = &CPU_SCHEDULERS[0];
    if scheduler.prepare(CpuIndex(0)).is_err() {
        fatal_with_serial(serial, "KERNAL/ARM64: BSP scheduler prepare failed\n");
    }
    let stack = boot_stack()
        .unwrap_or_else(|| fatal_with_serial(serial, "KERNAL/ARM64: BSP stack contract invalid\n"));
    let sp = current_stack_pointer();
    // SAFETY: BSP is owner, IRQ-masked, non-migrating, with TPIDR_EL1 installed and this live stack.
    let idle = unsafe { scheduler.bootstrap_adopt_current(IDLE_PRIORITY, sp, stack, 0) }
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: BSP idle adoption failed\n"));
    serial.write_str("KERNAL/ARM64: BSP scheduler idle adopted\n");
    idle
}

fn prepare_secondary_scheduler(index: usize, cpu: CpuIndex) -> Result<ThreadId, ()> {
    let scheduler = CPU_SCHEDULERS.get(index).ok_or(())?;
    scheduler.prepare(cpu).map_err(|_| ())?;
    let stack = secondary_stack(index).ok_or(())?;
    let sp = current_stack_pointer();
    // SAFETY: secondary is owner, IRQ-masked, non-migrating, with TPIDR_EL1 installed and is
    // executing on the exact linker-reserved stack represented by `stack`.
    unsafe { scheduler.bootstrap_adopt_current(IDLE_PRIORITY, sp, stack, 0) }.map_err(|_| ())
}

fn run_bsp_scheduler_smoke(serial: &Pl011, idle: ThreadId) {
    SCHEDULER_SMOKE_STATE.store(SCHEDULER_SMOKE_IDLE, Ordering::Release);
    let scheduler = &CPU_SCHEDULERS[0];
    let stack = scheduler_worker_stack().unwrap_or_else(|| {
        fatal_with_serial(serial, "KERNAL/ARM64: worker stack contract invalid\n")
    });
    let word_count = usize::try_from(stack.mapped_len / 8).unwrap_or_else(|_| {
        fatal_with_serial(serial, "KERNAL/ARM64: worker stack size overflow\n")
    });
    // SAFETY: linker reserves this entire aligned stack exclusively for the one BSP smoke worker;
    // the BSP is single-threaded with IRQs masked while the initial context frame is written.
    let words = unsafe { from_raw_parts_mut(stack.mapped_start as *mut u64, word_count) };
    let top = stack
        .top()
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: worker stack top invalid\n"));
    let start =
        kernal_context_aarch64::build_initial_context(words, top, scheduler_smoke_worker, 0)
            .unwrap_or_else(|_| {
                fatal_with_serial(serial, "KERNAL/ARM64: worker context build failed\n")
            });
    let saved_sp = stack
        .mapped_start
        .checked_add((start as u64) * 8)
        .unwrap_or_else(|| fatal_with_serial(serial, "KERNAL/ARM64: worker saved SP overflow\n"));

    // SAFETY: BSP owns the scheduler, IRQs remain masked and the AArch64 initial context is valid.
    let worker =
        unsafe { scheduler.bootstrap_create_ready(SMOKE_WORKER_PRIORITY, saved_sp, stack, 0) }
            .unwrap_or_else(|_| {
                fatal_with_serial(serial, "KERNAL/ARM64: worker scheduler insert failed\n")
            });
    serial.write_str("KERNAL/ARM64: scheduler worker ready\n");

    // SAFETY: worker has higher priority than idle and both context stacks are valid/reserved.
    let resumed = unsafe { scheduler.bootstrap_yield() }.unwrap_or_else(|_| {
        fatal_with_serial(serial, "KERNAL/ARM64: idle-to-worker switch failed\n")
    });
    if resumed != idle
        || SCHEDULER_SMOKE_STATE.load(Ordering::Acquire) != SCHEDULER_SMOKE_WORKER_ENTERED
    {
        fatal_with_serial(
            serial,
            "KERNAL/ARM64: scheduler worker did not return to idle\n",
        );
    }
    serial.write_str("KERNAL/ARM64: scheduler worker exited; idle resumed\n");

    // The smoke stack is permanently linker-reserved, so there is no dynamic resource teardown.
    // SAFETY: idle is current, IRQs are masked and worker is Exited/non-running.
    let reaped_stack = unsafe { scheduler.bootstrap_reap_exited_after_teardown(worker, idle) }
        .unwrap_or_else(|_| {
            fatal_with_serial(serial, "KERNAL/ARM64: scheduler worker reap failed\n")
        });
    if reaped_stack != stack {
        fatal_with_serial(
            serial,
            "KERNAL/ARM64: scheduler worker stack identity changed\n",
        );
    }
    SCHEDULER_SMOKE_STATE.store(SCHEDULER_SMOKE_REAPED, Ordering::Release);
    serial.write_str(
        "KERNAL/ARM64: scheduler lifecycle idle -> worker -> exited -> idle -> reap passed\n",
    );
}

extern "C" fn scheduler_smoke_worker(argument: u64) -> ! {
    if argument != 0 {
        SCHEDULER_SMOKE_STATE.store(SCHEDULER_SMOKE_FAILED, Ordering::Release);
        fatal_silent();
    }
    // SAFETY: BSP scheduler installed TPIDR_EL1 before the context switch and migration is absent.
    let local = unsafe { kernal_percpu_aarch64::current() };
    if local.index() != CpuIndex(0) {
        SCHEDULER_SMOKE_STATE.store(SCHEDULER_SMOKE_FAILED, Ordering::Release);
        fatal_silent();
    }
    SCHEDULER_SMOKE_STATE.store(SCHEDULER_SMOKE_WORKER_ENTERED, Ordering::Release);
    let scheduler = &CPU_SCHEDULERS[0];
    // SAFETY: worker is current owner, IRQs remain masked and bootstrap preemption is inactive.
    let _ = unsafe { scheduler.bootstrap_exit_current_and_switch() };
    SCHEDULER_SMOKE_STATE.store(SCHEDULER_SMOKE_FAILED, Ordering::Release);
    fatal_silent()
}

fn boot_stack() -> Option<KernelStack> {
    unsafe extern "C" {
        static __boot_stack_guard_start: u8;
        static __boot_stack_bottom: u8;
        static __boot_stack_top: u8;
    }
    let guard = core::ptr::addr_of!(__boot_stack_guard_start) as u64;
    let mapped = core::ptr::addr_of!(__boot_stack_bottom) as u64;
    let top = core::ptr::addr_of!(__boot_stack_top) as u64;
    let len = top.checked_sub(mapped)?;
    if mapped != guard.checked_add(STACK_GUARD_BYTES)? || len != BOOT_STACK_BYTES {
        return None;
    }
    KernelStack::new(guard, mapped, len).ok()
}

fn secondary_stack(index: usize) -> Option<KernelStack> {
    if index == 0 || index >= MAX_PROOF_CPUS {
        return None;
    }
    unsafe extern "C" {
        static __secondary_stacks_bottom: u8;
    }
    let pool = core::ptr::addr_of!(__secondary_stacks_bottom) as u64;
    let slot = u64::try_from(index.checked_sub(1)?).ok()?;
    let guard = pool.checked_add(slot.checked_mul(SECONDARY_STACK_STRIDE)?)?;
    let mapped = guard.checked_add(STACK_GUARD_BYTES)?;
    KernelStack::new(guard, mapped, SECONDARY_STACK_BYTES).ok()
}

fn scheduler_worker_stack() -> Option<KernelStack> {
    unsafe extern "C" {
        static __scheduler_worker_guard_start: u8;
        static __scheduler_worker_stack_bottom: u8;
        static __scheduler_worker_stack_top: u8;
    }
    let guard = core::ptr::addr_of!(__scheduler_worker_guard_start) as u64;
    let mapped = core::ptr::addr_of!(__scheduler_worker_stack_bottom) as u64;
    let top = core::ptr::addr_of!(__scheduler_worker_stack_top) as u64;
    let len = top.checked_sub(mapped)?;
    if mapped != guard.checked_add(STACK_GUARD_BYTES)? || len != SCHEDULER_WORKER_STACK_BYTES {
        return None;
    }
    KernelStack::new(guard, mapped, len).ok()
}

fn current_stack_pointer() -> u64 {
    let sp: u64;
    // SAFETY: MOV from SP is an architectural register read and does not modify machine state.
    unsafe { asm!("mov {sp}, sp", sp = out(reg) sp, options(nomem, nostack, preserves_flags)) };
    sp
}

fn publish_irq_runtime(gic_info: kernal_fdt_aarch64::GicV3Info, timer_intid: u32) {
    GICD_BASE.store(gic_info.distributor.base, Ordering::Release);
    GICD_SIZE.store(gic_info.distributor.size, Ordering::Release);
    GICR_BASE.store(gic_info.redistributor.base, Ordering::Release);
    GICR_SIZE.store(gic_info.redistributor.size, Ordering::Release);
    TIMER_INTID.store(timer_intid, Ordering::Release);
    kernal_arch_aarch64::data_sync_barrier_inner_shareable();
}

fn install_bsp_irq_runtime(
    serial: &Pl011,
    gic_info: kernal_fdt_aarch64::GicV3Info,
    timer_intid: u32,
) {
    kernal_exceptions_aarch64::install_handler(aarch64_exception_handler)
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: handler install failed\n"));
    // SAFETY: vector code is linker-resident executable text and IRQs are still masked.
    unsafe { kernal_exceptions_aarch64::install_vector_table() }
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: VBAR install failed\n"));

    let distributor = GicRegion::new(gic_info.distributor.base, gic_info.distributor.size)
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: invalid GICD region\n"));
    let redistributors = GicRegion::new(gic_info.redistributor.base, gic_info.redistributor.size)
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: invalid GICR region\n"));
    let mut gic = GicV3::new(PhysicalGicMmio, distributor, redistributors);
    let interrupt_count = gic
        .initialize_distributor()
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: GICD init failed\n"));
    serial.write_str("KERNAL/ARM64: GIC INTIDs=");
    serial.write_u64(interrupt_count as u64);
    serial.write_str("\n");

    let affinity = kernal_arch_aarch64::current_affinity();
    let redistributor = gic
        .prepare_cpu_private_interrupts(affinity, timer_intid, RESCHEDULE_SGI_DEFAULT)
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: GICR init failed\n"));
    serial.write_str("KERNAL/ARM64: BSP GICR=");
    serial.write_hex_u64(redistributor);
    serial.write_str(" affinity=");
    serial.write_hex_u64(affinity.packed() as u64);
    serial.write_str("\n");

    // SAFETY: Distributor/Redistributor and enabled private interrupt sources are ready; DAIF.I is
    // still set, so enabling the GIC CPU interface cannot enter Rust prematurely.
    unsafe { kernal_gicv3_aarch64::enable_cpu_interface() }
        .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: GIC CPU interface failed\n"));
}

fn install_secondary_irq_runtime() -> Result<(), ()> {
    // SAFETY: every secondary is at EL1, on a dedicated stack, with IRQs still masked.
    unsafe { kernal_exceptions_aarch64::install_vector_table() }.map_err(|_| ())?;

    let distributor = GicRegion::new(
        GICD_BASE.load(Ordering::Acquire),
        GICD_SIZE.load(Ordering::Acquire),
    )
    .map_err(|_| ())?;
    let redistributors = GicRegion::new(
        GICR_BASE.load(Ordering::Acquire),
        GICR_SIZE.load(Ordering::Acquire),
    )
    .map_err(|_| ())?;
    let timer_intid = TIMER_INTID.load(Ordering::Acquire);
    let mut gic = GicV3::new(PhysicalGicMmio, distributor, redistributors);
    gic.prepare_cpu_private_interrupts(
        kernal_arch_aarch64::current_affinity(),
        timer_intid,
        RESCHEDULE_SGI_DEFAULT,
    )
    .map_err(|_| ())?;
    // SAFETY: current PE Redistributor/private interrupts are ready and DAIF.I remains masked.
    unsafe { kernal_gicv3_aarch64::enable_cpu_interface() }.map_err(|_| ())?;
    Ok(())
}

fn start_secondary_cpus(serial: &Pl011, psci: Psci, expected_cpus: usize) {
    if expected_cpus <= 1 {
        return;
    }

    unsafe extern "C" {
        fn kernal_aarch64_secondary_entry();
    }
    let entry = kernal_aarch64_secondary_entry as *const () as u64;
    if entry & 3 != 0 {
        fatal_with_serial(serial, "KERNAL/ARM64: secondary entry misaligned\n");
    }

    kernal_arch_aarch64::data_sync_barrier_inner_shareable();
    for index in 1..expected_cpus {
        if CPU_STATES[index]
            .compare_exchange(
                CPU_OFFLINE,
                CPU_STARTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            fatal_with_serial(
                serial,
                "KERNAL/ARM64: invalid secondary state before CPU_ON\n",
            );
        }
        let mpidr = CPU_MPIDRS[index].load(Ordering::Acquire);
        serial.write_str("KERNAL/ARM64: PSCI CPU_ON index=");
        serial.write_u64(index as u64);
        serial.write_str(" target=");
        serial.write_hex_u64(mpidr);
        serial.write_str("\n");
        // SAFETY: target comes from bounded DTB CPU data, entry is linker-resident executable text,
        // context ID selects a reserved secondary stack, and shared bootstrap state is published.
        if unsafe { psci.cpu_on(mpidr, entry, index as u64) }.is_err() {
            CPU_STATES[index].store(CPU_FAILED, Ordering::Release);
            fatal_with_serial(serial, "KERNAL/ARM64: PSCI CPU_ON failed\n");
        }
    }

    wait_for_all_online(serial, expected_cpus);
    for mpidr_slot in CPU_MPIDRS.iter().take(expected_cpus).skip(1) {
        let mpidr = mpidr_slot.load(Ordering::Acquire);
        // SAFETY: same validated PSCI conduit used for CPU_ON and MPIDR is the corresponding target.
        let state = unsafe { psci.affinity_info(mpidr, 0) }.unwrap_or_else(|_| {
            fatal_with_serial(serial, "KERNAL/ARM64: PSCI affinity_info failed\n")
        });
        if state != 0 {
            fatal_with_serial(serial, "KERNAL/ARM64: PSCI reports secondary not ON\n");
        }
    }
    serial.write_str("KERNAL/ARM64: all PSCI secondaries Online with scheduler idle\n");
}

fn wait_for_all_online(serial: &Pl011, expected_cpus: usize) {
    let start = kernal_arch_aarch64::read_virtual_counter();
    let frequency = kernal_arch_aarch64::counter_frequency_hz();
    loop {
        let mut all_online = true;
        for state in CPU_STATES.iter().take(expected_cpus).skip(1) {
            match state.load(Ordering::Acquire) {
                CPU_ONLINE => {}
                CPU_FAILED => {
                    fatal_with_serial(serial, "KERNAL/ARM64: secondary bootstrap failed\n")
                }
                _ => all_online = false,
            }
        }
        if all_online {
            return;
        }
        if proof_timeout_expired(start, frequency) {
            fatal_with_serial(
                serial,
                "KERNAL/ARM64: timeout waiting for secondary Online\n",
            );
        }
        core::hint::spin_loop();
    }
}

fn dispatch_reschedule_probes(serial: &Pl011, expected_cpus: usize) {
    if expected_cpus == 1 {
        RESCHEDULE_PROBE_PUBLISHED[0].store(true, Ordering::Release);
        let target = CpuAffinity::from_mpidr(CPU_MPIDRS[0].load(Ordering::Acquire));
        // SAFETY: BSP GIC CPU interface is ready; publication precedes the one-PE self-SGI proof.
        unsafe { kernal_gicv3_aarch64::send_sgi1(RESCHEDULE_SGI_DEFAULT, target) }
            .unwrap_or_else(|_| fatal_with_serial(serial, "KERNAL/ARM64: BSP self SGI failed\n"));
        return;
    }

    let start = kernal_arch_aarch64::read_virtual_counter();
    let frequency = kernal_arch_aarch64::counter_frequency_hz();
    while !BSP_REMOTE_SGI_SENT.load(Ordering::Acquire) {
        if CPU_STATES[1].load(Ordering::Acquire) == CPU_FAILED {
            fatal_with_serial(serial, "KERNAL/ARM64: PE1 failed before BSP remote SGI\n");
        }
        if proof_timeout_expired(start, frequency) {
            fatal_with_serial(serial, "KERNAL/ARM64: timeout waiting for BSP remote SGI\n");
        }
        core::hint::spin_loop();
    }

    for index in 1..expected_cpus {
        RESCHEDULE_PROBE_PUBLISHED[index].store(true, Ordering::Release);
        let target = CpuAffinity::from_mpidr(CPU_MPIDRS[index].load(Ordering::Acquire));
        // SAFETY: target PE is Online with its GIC interface ready; publication precedes the SGI.
        unsafe { kernal_gicv3_aarch64::send_sgi1(RESCHEDULE_SGI_DEFAULT, target) }.unwrap_or_else(
            |_| fatal_with_serial(serial, "KERNAL/ARM64: secondary SGI send failed\n"),
        );
    }
}

fn prove_current_cpu_interrupt_delivery(index: usize) -> Result<(), ()> {
    let timer_intid = TIMER_INTID.load(Ordering::Acquire);
    if !(16..32).contains(&timer_intid) || index >= MAX_PROOF_CPUS {
        return Err(());
    }
    let frequency = kernal_arch_aarch64::counter_frequency_hz();
    if frequency == 0 {
        return Err(());
    }

    // SAFETY: this PE's virtual timer PPI is configured in GIC and CNTV registers are accessible.
    unsafe { kernal_timer_aarch64::arm_after_ns(TIMER_INTERVAL_NS) }.map_err(|_| ())?;
    let start = kernal_arch_aarch64::read_virtual_counter();
    // SAFETY: EL1 vector table, GIC CPU interface, timer PPI and reschedule SGI are initialized.
    unsafe { kernal_arch_aarch64::enable_irqs() };

    while TIMER_IRQS[index].load(Ordering::Acquire) < REQUIRED_TIMER_IRQS
        || RESCHEDULE_IRQS[index].load(Ordering::Acquire) < REQUIRED_RESCHEDULE_IRQS
    {
        if UNEXPECTED_IRQS[index].load(Ordering::Acquire) != NO_INTERRUPT
            || CPU_STATES[index].load(Ordering::Acquire) == CPU_FAILED
            || proof_timeout_expired(start, frequency)
        {
            // SAFETY: proof abort owns the local IRQ state.
            unsafe { kernal_arch_aarch64::disable_irqs() };
            return Err(());
        }
        // SAFETY: current PE waits at an interruptible boundary; scheduler switching occurs only
        // from explicit bootstrap safe points in this proof, never from the exception handler.
        unsafe { kernal_arch_aarch64::wait_for_interrupt() };
    }

    // SAFETY: proof counters are complete; no scheduler transition is pending on this PE.
    unsafe { kernal_arch_aarch64::disable_irqs() };
    Ok(())
}

fn wait_for_all_proofs(serial: &Pl011, expected_cpus: usize) {
    let start = kernal_arch_aarch64::read_virtual_counter();
    let frequency = kernal_arch_aarch64::counter_frequency_hz();
    loop {
        let mut complete = true;
        for index in 0..expected_cpus {
            if CPU_STATES[index].load(Ordering::Acquire) == CPU_FAILED {
                fatal_with_serial(serial, "KERNAL/ARM64: PE failed during IRQ proof\n");
            }
            if !PROOF_DONE[index].load(Ordering::Acquire) {
                complete = false;
            }
        }
        if complete {
            return;
        }
        if proof_timeout_expired(start, frequency) {
            fatal_with_serial(
                serial,
                "KERNAL/ARM64: timeout waiting for per-PE IRQ proofs\n",
            );
        }
        core::hint::spin_loop();
    }
}

fn print_proof_summary(serial: &Pl011, expected_cpus: usize) {
    for index in 0..expected_cpus {
        let unexpected = UNEXPECTED_IRQS[index].load(Ordering::Acquire);
        if unexpected != NO_INTERRUPT {
            serial.write_str("KERNAL/ARM64: unexpected INTID on PE ");
            serial.write_u64(index as u64);
            serial.write_str(" =");
            serial.write_u64(unexpected as u64);
            serial.write_str("\n");
            fatal_silent();
        }
        let timer = TIMER_IRQS[index].load(Ordering::Acquire);
        let reschedule = RESCHEDULE_IRQS[index].load(Ordering::Acquire);
        if timer < REQUIRED_TIMER_IRQS || reschedule < REQUIRED_RESCHEDULE_IRQS {
            fatal_with_serial(
                serial,
                "KERNAL/ARM64: per-PE interrupt counters below proof minimum\n",
            );
        }
        serial.write_str("KERNAL/ARM64: PE ");
        serial.write_u64(index as u64);
        serial.write_str(" Online timer IRQs=");
        serial.write_u64(timer as u64);
        serial.write_str(" reschedule SGIs=");
        serial.write_u64(reschedule as u64);
        serial.write_str("\n");
    }
}

fn proof_timeout_expired(start: u64, frequency: u64) -> bool {
    let timeout = frequency.saturating_mul(PROOF_TIMEOUT_SECONDS);
    kernal_arch_aarch64::read_virtual_counter().wrapping_sub(start) >= timeout
}

#[cfg(feature = "qemu-proof")]
fn service_step30_job_control_safe_point() {
    let index = current_cpu_index();
    match step15_qemu::service_step30_job_control_completions(index) {
        Ok(false) => {}
        Ok(true) => {
            let target = CpuAffinity::from_mpidr(CPU_MPIDRS[index].load(Ordering::Acquire));
            // SAFETY: the completed scheduler ACK remains durable in this PE's mailbox while the
            // RuntimeCell is busy. A self-SGI schedules a later exact-owner retry without reapplying
            // the already-completed RunQueue transition.
            unsafe { kernal_gicv3_aarch64::send_sgi1(RESCHEDULE_SGI_DEFAULT, target) }
                .unwrap_or_else(|_| fatal_silent());
        }
        Err(()) => fatal_silent(),
    }
}

extern "C" fn aarch64_exception_handler(frame: &mut ExceptionFrame) {
    if frame.kind() != ExceptionKind::Irq {
        #[cfg(feature = "qemu-proof")]
        if step15_qemu::step30_post_fork_reschedule_trace_pending() {
            step15_qemu::trace_step30_post_fork_non_irq_fatal(
                frame.vector_index() as u64,
                frame.esr_el1,
                frame.far_el1,
                frame.elr_el1,
                frame.spsr_el1,
                frame.x[20],
                frame.x[30],
            );
        }
        fatal_silent();
    }

    // SAFETY: IRQ delivery is enabled only after this PE publishes and installs its static CpuLocal.
    let local = unsafe { kernal_percpu_aarch64::current() };
    local.enter_irq();
    let Some(interrupt) = kernal_gicv3_aarch64::acknowledge_group1() else {
        if local.exit_irq().is_err() {
            fatal_silent();
        }
        #[cfg(feature = "qemu-proof")]
        service_step30_job_control_safe_point();
        service_reschedule_safe_point(local);
        #[cfg(feature = "qemu-proof")]
        if frame.source() == kernal_exceptions_aarch64::ExceptionSource::LowerElAarch64
            && step15_qemu::deliver_step30_signal_on_return(frame).is_err()
        {
            fatal_silent();
        }
        return;
    };
    handle_interrupt(interrupt);
    // SAFETY: `interrupt` is the unique outstanding real IAR1 acknowledge handled above. Remote wake
    // and job-control mailbox draining have completed before this EOI.
    unsafe { kernal_gicv3_aarch64::end_of_interrupt_group1(interrupt) };
    if local.exit_irq().is_err() {
        fatal_silent();
    }
    #[cfg(feature = "qemu-proof")]
    service_step30_job_control_safe_point();
    #[cfg(feature = "qemu-proof")]
    if step15_qemu::step30_post_fork_reschedule_trace_pending() {
        step15_qemu::trace_step30_post_fork_pre_reschedule();
    }
    service_reschedule_safe_point(local);
    #[cfg(feature = "qemu-proof")]
    if frame.source() == kernal_exceptions_aarch64::ExceptionSource::LowerElAarch64
        && step15_qemu::deliver_step30_signal_on_return(frame).is_err()
    {
        fatal_silent();
    }
}

fn handle_interrupt(interrupt: AcknowledgedInterrupt) {
    let index = current_cpu_index();
    let timer_intid = TIMER_INTID.load(Ordering::Acquire);
    if interrupt.intid == timer_intid {
        if PROOF_DONE[index].load(Ordering::Acquire)
            && RUNTIME_SCHEDULER_TICK_ACTIVE[index].load(Ordering::Acquire)
        {
            #[cfg(feature = "qemu-proof")]
            if step15_qemu::step30_post_fork_reschedule_trace_pending() {
                step15_qemu::trace_step30_post_fork_timer_irq();
            }
            // SAFETY: this executes in the timer IRQ on the PE whose virtual timer PPI is active.
            if unsafe { kernal_timer_aarch64::arm_after_ns(TIMER_INTERVAL_NS) }.is_err() {
                RUNTIME_SCHEDULER_TICK_ACTIVE[index].store(false, Ordering::Release);
                CPU_STATES[index].store(CPU_FAILED, Ordering::Release);
                return;
            }
            // SAFETY: IRQ delivery is enabled only after this PE installs its static CpuLocal.
            let local = unsafe { kernal_percpu_aarch64::current() };
            local.request_reschedule();
            return;
        }

        let count = TIMER_IRQS[index].fetch_add(1, Ordering::AcqRel) + 1;
        if count < REQUIRED_TIMER_IRQS {
            // SAFETY: this executes in the timer IRQ on the PE whose virtual timer PPI is active.
            if unsafe { kernal_timer_aarch64::arm_after_ns(TIMER_INTERVAL_NS) }.is_err() {
                CPU_STATES[index].store(CPU_FAILED, Ordering::Release);
            }
        } else {
            // SAFETY: same-PE timer IRQ owns the virtual timer programming state for this proof.
            unsafe { kernal_timer_aarch64::disarm() };
        }
        return;
    }

    if interrupt.intid == RESCHEDULE_SGI_DEFAULT as u32 {
        if !RESCHEDULE_PROBE_PUBLISHED[index].load(Ordering::Acquire) {
            UNEXPECTED_IRQS[index].store(interrupt.intid, Ordering::Release);
            return;
        }
        let scheduler = &CPU_SCHEDULERS[index];
        // SAFETY: exception entry has local IRQs masked; aarch64_exception_handler published
        // irq_depth=1 and the IRQ path never enters a scheduler preemption guard before this drain.
        let report = unsafe { scheduler.drain_remote_wakes_from_irq(REMOTE_WAKE_SLOTS) }
            .unwrap_or_else(|_| fatal_silent());
        if report.readied != 0 || report.already_ready != 0 {
            // SAFETY: same installed owner-local state used by the scheduler drain above.
            let local = unsafe { kernal_percpu_aarch64::current() };
            local.request_reschedule();
        }
        #[cfg(feature = "qemu-proof")]
        {
            // SAFETY: this is still the first-level owner IRQ before EOI/exit_irq. The exact transport
            // owner retains every completion until the post-IRQ Runtime composition acknowledges it.
            let job_control = unsafe { step15_qemu::drain_step30_job_control_from_irq(index) }
                .unwrap_or_else(|_| fatal_silent());
            if job_control.deschedule != 0 || job_control.readied != 0 {
                // SAFETY: same installed owner-local state used by both scheduler drains above.
                let local = unsafe { kernal_percpu_aarch64::current() };
                local.request_reschedule();
            }
        }
        RESCHEDULE_IRQS[index].fetch_add(1, Ordering::AcqRel);
        return;
    }

    UNEXPECTED_IRQS[index].store(interrupt.intid, Ordering::Release);
}

fn service_reschedule_safe_point(local: &'static kernal_percpu_aarch64::CpuLocal) {
    if !local.need_reschedule() {
        return;
    }
    // Context switching from the IRQ body is forbidden. Only the post-EOI, post-exit_irq safe point
    // may consume the request, with IRQs still architecturally masked by exception entry.
    if local.irq_depth() != 0 || local.preempt_count() != 0 {
        fatal_silent();
    }
    local.clear_reschedule();

    #[cfg(feature = "qemu-proof")]
    {
        let index = usize::from(local.index().0);
        let scheduler = CPU_SCHEDULERS.get(index).unwrap_or_else(|| fatal_silent());
        let trace_post_fork = step15_qemu::take_step30_post_fork_reschedule_trace();
        if trace_post_fork {
            // SAFETY: this is the same owner/quiescent safe point required by the reschedule below.
            match unsafe { scheduler.bootstrap_current_global_thread() } {
                Ok(current) => step15_qemu::trace_step30_post_fork_reschedule_current(
                    u64::from(current.cpu.0),
                    u64::from(current.local.slot),
                    u64::from(current.local.generation),
                ),
                Err(_) => step15_qemu::trace_step30_post_fork_reschedule_error(),
            }
        }
        // SAFETY: irq_depth and preempt_count are zero, local IRQs remain masked, and destination
        // Process/TTBR0 activation is completed by the canonical Step-30 callback before switching.
        let rescheduled = unsafe {
            scheduler.bootstrap_reschedule_with_job_control_destination_address_space(
                step15_qemu::activate_step30_scheduler_destination,
            )
        };
        if trace_post_fork {
            match &rescheduled {
                Ok(current) => step15_qemu::trace_step30_post_fork_reschedule_return(
                    u64::from(current.slot),
                    u64::from(current.generation),
                ),
                Err(_) => step15_qemu::trace_step30_post_fork_reschedule_error(),
            }
        }
        rescheduled.unwrap_or_else(|_| fatal_silent());
    }

    #[cfg(not(feature = "qemu-proof"))]
    {
        // The current freestanding non-proof image has no Process runtime that can legitimately
        // publish a remote wake. If that changes, it must install an equivalent destination owner.
        fatal_silent();
    }
}

fn current_cpu_index() -> usize {
    // SAFETY: IRQ delivery is enabled only after this PE has installed its static CpuLocal pointer.
    let local = unsafe { kernal_percpu_aarch64::current() };
    let index = local.index().0 as usize;
    if index >= MAX_PROOF_CPUS {
        fatal_silent();
    }
    index
}

fn secondary_fail(index: usize) -> ! {
    if index < MAX_PROOF_CPUS {
        CPU_STATES[index].store(CPU_FAILED, Ordering::Release);
        kernal_arch_aarch64::send_event();
    }
    fatal_silent()
}

fn psci_from_platform<const N: usize>(platform: &PlatformInfo<N>) -> Option<Psci> {
    match platform.psci? {
        PsciConduit::Smc => Some(Psci::new(Conduit::Smc)),
        PsciConduit::Hvc => Some(Psci::new(Conduit::Hvc)),
    }
}

/// Builds a bounded slice over the QEMU-generated DTB before any device MMIO is touched.
///
/// # Safety
/// This function is only valid for the QEMU `virt` bare-metal ELF proof contract where RAM starts
/// at 0x4000_0000 and the generated DTB occupies the beginning of that RAM.
unsafe fn qemu_dtb(physical: u64) -> Option<Blob<'static>> {
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
    // SAFETY: QEMU guarantees the DTB begins in guest RAM. The header-provided length is capped to
    // a small range inside that RAM before constructing the slice, and Blob::parse performs all
    // internal offset/range validation before exposing data.
    let bytes = unsafe { from_raw_parts(physical as *const u8, total_size) };
    Blob::parse(bytes).ok()
}

unsafe fn read_be_u32_volatile(address: u64) -> Option<u32> {
    if address & 3 != 0 {
        return None;
    }
    // SAFETY: caller guarantees this address belongs to the QEMU DTB header in RAM.
    let raw = unsafe { read_volatile(address as *const u32) };
    Some(u32::from_be(raw))
}

fn fatal_with_serial(serial: &Pl011, message: &str) -> ! {
    serial.write_str(message);
    fatal_silent()
}

fn fatal_silent() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn idle_forever() -> ! {
    loop {
        // SAFETY: proof secondaries remain parked until BSP requests whole-VM shutdown.
        unsafe { kernal_arch_aarch64::wait_for_interrupt() };
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    fatal_silent()
}
