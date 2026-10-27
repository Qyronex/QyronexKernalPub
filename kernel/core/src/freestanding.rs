// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::slice::{from_raw_parts, from_raw_parts_mut};
use core::sync::atomic::{fence, AtomicU64, Ordering};
use kernal_acpi_physical::{find_unique_table, read_madt, read_root_table, read_rsdp};
use kernal_ap_startup_x86_64::{build_mailbox, StartupParameters, PAGE_SIZE as AP_PAGE_SIZE};
use kernal_apic_x86_64::{HardwareLocalApic, DEFAULT_SPURIOUS_VECTOR};
use kernal_arch_x86_64::{detect_features, enable_smep};
use kernal_bootinfo::{memory_kind, BootInfoV1, MemoryRegionV1};
use kernal_descriptors_x86_64::{DescriptorCell, DescriptorConfig};
use kernal_exceptions_x86_64::{ExceptionFrame, ExceptionTableCell};
use kernal_frame_allocator::{ExtentAllocator, FrameRange};
use kernal_handoff::{HandoffLayout, MEMORY_MAP_VIRTUAL, PAGE_SIZE};
use kernal_idle_x86_64::halt_until_interrupt;
use kernal_interrupt_control_x86_64::quiesce as quiesce_external_interrupts;
use kernal_interrupts_x86_64::{
    idt_gates, install_handler as install_interrupt_handler, InterruptFrame, RESCHEDULE_VECTOR,
    SPURIOUS_VECTOR, TIMER_VECTOR,
};
use kernal_irq_runtime_x86_64::{
    apic_handle as runtime_apic_handle, arm_if_disarmed, handle_reschedule as runtime_reschedule,
    handle_timer as runtime_timer, prepare_cpu as prepare_irq_runtime,
    reschedule_interrupt_count, timer_interrupt_count,
};
use kernal_kmap::{CachePolicy, MappingRequest};
use kernal_kmap_x86_64::{window_base, KmapController, KMAP_SLOTS_PER_CPU};
use kernal_page_table::{Backend as PageTableBackend, Mapper};
use kernal_paging::MapFlags;
use kernal_percpu::{CpuIndex, CpuRegistration, CpuRegistry, CpuRegistryCell, CpuState};
use kernal_percpu_layout_x86_64::{
    GuardedStack, PerCpuLayout, IST_STACK_PAGES, KERNEL_STACK_PAGES,
};
use kernal_percpu_x86_64::{current as current_cpu_local, install_bootstrap_gs, CpuLocalCell};
use kernal_physical_io::{Error as PhysicalIoError, PhysicalReader};
use kernal_runtime_page_table_x86_64::RuntimePageTableBackend;
use kernal_scheduler::ThreadId;
use kernal_scheduler_cpu::CpuSchedulerCell;
use kernal_smp_x86_64::{start_one, TscDelay};
use kernal_thread_bootstrap_x86_64::create_ready as create_ready_thread;
use kernal_thread_context::KernelStack;
use kernal_thread_reaper_x86_64::reap_exited_local;
use kernal_topology::Topology;
use kernal_tsc_bootstrap_x86_64::resolve_and_publish as resolve_tsc_frequency;
use kernal_tsc_x86_64::detect as detect_tsc_frequency;

const COM1: u16 = 0x03f8;
const MAX_BOOT_MEMORY_REGIONS: usize = 2048;
const MAX_BOOT_CPUS: usize = 256;
const RUNTIME_EXTENTS: usize = 512;
const SCHEDULER_THREADS_PER_CPU: usize = 256;
const REMOTE_WAKE_SLOTS: usize = 64;
const IDLE_PRIORITY: u8 = 0;
const SMOKE_WORKER_PRIORITY: u8 = 63;
const AP_STACK_FRAME_COUNT: usize = KERNEL_STACK_PAGES + IST_STACK_PAGES * 3;
const TIMER_PROOF_DELAY_NS: u64 = 5_000_000;
const TIMER_PROOF_INTERRUPTS: u64 = 2;
const RESCHEDULE_PROOF_INTERRUPTS: u64 = 1;
const RAM_SELF_TEST_HEAD: u64 = 0x4b45_524e_414c_4d31;
const RAM_SELF_TEST_TAIL: u64 = 0x3154_5345_544d_4152;
#[cfg(feature = "qemu-exit")]
const QEMU_DEBUG_EXIT: u16 = 0x00f4;
#[cfg(feature = "qemu-exit")]
const QEMU_SUCCESS_VALUE: u32 = 0x10;
#[cfg(feature = "qemu-exit")]
const QEMU_FAILURE_VALUE: u32 = 0x11;

static BSP_DESCRIPTORS: DescriptorCell = DescriptorCell::new();
static BSP_EXCEPTIONS: ExceptionTableCell = ExceptionTableCell::new();
static AP_DESCRIPTORS: [DescriptorCell; MAX_BOOT_CPUS] =
    [const { DescriptorCell::new() }; MAX_BOOT_CPUS];
static CPU_LOCALS: [CpuLocalCell; MAX_BOOT_CPUS] =
    [const { CpuLocalCell::new() }; MAX_BOOT_CPUS];
static CPU_SCHEDULERS: [CpuSchedulerCell<SCHEDULER_THREADS_PER_CPU, REMOTE_WAKE_SLOTS>; MAX_BOOT_CPUS] =
    [const { CpuSchedulerCell::new() }; MAX_BOOT_CPUS];
static CPU_REGISTRY: CpuRegistryCell<MAX_BOOT_CPUS> = CpuRegistryCell::new();
static AP_LOCAL_APIC_PHYSICAL: AtomicU64 = AtomicU64::new(0);
static SCHEDULER_SMOKE_STATE: AtomicU64 = AtomicU64::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn _start(boot_info: *const BootInfoV1) -> ! {
    serial_init();
    serial_write("KERNAL/CORE: high-half entry reached\r\n");
    if boot_info.is_null() { fatal("KERNAL/CORE: null BootInfo\r\n"); }

    // SAFETY: the transition contract maps one BootInfoV1 page at the pointer passed in RDI.
    let info = unsafe { &*boot_info };
    if !info.is_compatible() { fatal("KERNAL/CORE: incompatible BootInfo\r\n"); }
    if !info.ap_trampoline_is_valid() { fatal("KERNAL/CORE: malformed AP bootstrap contract\r\n"); }
    let regions = match boot_memory_regions(info) {
        Some(regions) => regions,
        None => fatal("KERNAL/CORE: invalid normalized memory map\r\n"),
    };
    if !validate_memory_regions(regions) {
        fatal("KERNAL/CORE: malformed memory ownership map\r\n");
    }
    serial_write("KERNAL/CORE: BootInfo accepted\r\n");
    serial_write("KERNAL/CORE: normalized memory ownership accepted\r\n");

    let layout = match HandoffLayout::default_layout() {
        Ok(layout) => layout,
        Err(_) => fatal("KERNAL/CORE: handoff layout reconstruction failed\r\n"),
    };
    let ring0_stack_top = match layout.stack.mapped.end() {
        Some(top) => top,
        None => fatal("KERNAL/CORE: invalid ring0 stack range\r\n"),
    };
    let descriptors = match BSP_DESCRIPTORS.prepare(DescriptorConfig {
        ring0_stack_top,
        double_fault_stack_top: layout.exception_stacks.double_fault.initial_rsp,
        nmi_stack_top: layout.exception_stacks.nmi.initial_rsp,
        machine_check_stack_top: layout.exception_stacks.machine_check.initial_rsp,
    }) {
        Ok(descriptors) => descriptors,
        Err(_) => fatal("KERNAL/CORE: descriptor preparation failed\r\n"),
    };
    // SAFETY: interrupts are disabled, all configured stacks are mapped, storage is static.
    unsafe { descriptors.load() };
    serial_write("KERNAL/CORE: GDT and TSS active\r\n");

    if install_interrupt_handler(interrupt_handler).is_err() {
        fatal("KERNAL/CORE: IRQ handler installation failed\r\n");
    }
    let gates = idt_gates();
    let idt = match BSP_EXCEPTIONS.prepare_with_gates(exception_handler, &gates) {
        Ok(idt) => idt,
        Err(_) => fatal("KERNAL/CORE: IDT preparation failed\r\n"),
    };
    // SAFETY: GDT/TSS are active, IST1/2/3 are live guarded stacks, IDT storage is static.
    unsafe { idt.load() };
    serial_write("KERNAL/CORE: exception and IRQ IDT active\r\n");

    let features = detect_features();
    // SAFETY: no user mappings exist yet and every current kernel mapping is supervisor-only.
    unsafe { enable_smep(features) };
    if features.smep { serial_write("KERNAL/CORE: SMEP active\r\n"); }

    // SAFETY: loader pre-created CPU0's kmap PT and recursive PML4 slot; BSP cannot migrate yet.
    let kmap = match unsafe { KmapController::assume_prepared(0) } {
        Ok(kmap) => kmap,
        Err(_) => fatal("KERNAL/CORE: BSP kmap construction failed\r\n"),
    };
    let physical = ValidatedPhysicalReader { kmap: &kmap, regions };
    let topology = match discover_interrupt_topology(info, &physical) {
        Ok(topology) => topology,
        Err(()) => fatal("KERNAL/CORE: ACPI MADT topology discovery failed\r\n"),
    };
    serial_write("KERNAL/CORE: streaming ACPI topology verified\r\n");
    serial_write("KERNAL/CORE: enabled CPUs: ");
    serial_write_decimal(topology.enabled_cpu_count() as u64);
    serial_write("\r\n");
    serial_write("KERNAL/CORE: IOAPICs: ");
    serial_write_decimal(topology.io_apics().len() as u64);
    serial_write("\r\n");

    // SAFETY: IF is still clear; topology came from a validated MADT and BSP kmap is exclusive.
    let quiesce = match unsafe { quiesce_external_interrupts(&topology, &kmap) } {
        Ok(report) => report,
        Err(_) => fatal("KERNAL/CORE: failed to quiesce external interrupt controllers\r\n"),
    };
    serial_write("KERNAL/CORE: external IRQ sources masked; IOAPICs ");
    serial_write_decimal(quiesce.io_apics_masked as u64);
    serial_write(", redirection entries ");
    serial_write_decimal(quiesce.redirection_entries_masked as u64);
    serial_write("\r\n");

    // SAFETY: BSP is non-migrating at CPL0 and APIC mode setup is serialized before interrupts.
    let mut local_apic = match unsafe {
        HardwareLocalApic::initialize(&kmap, features, topology.local_apic_address())
    } {
        Ok(apic) => apic,
        Err(_) => fatal("KERNAL/CORE: local APIC initialization failed\r\n"),
    };
    if local_apic.mask_bootstrap_lvts().is_err()
        || local_apic.enable(DEFAULT_SPURIOUS_VECTOR).is_err()
    {
        fatal("KERNAL/CORE: local APIC bootstrap configuration failed\r\n");
    }
    let bsp_apic_id = match local_apic.id() {
        Ok(id) => id,
        Err(_) => fatal("KERNAL/CORE: local APIC ID read failed\r\n"),
    };
    if !topology.cpus().iter().any(|cpu| cpu.enabled && cpu.apic_id == bsp_apic_id) {
        fatal("KERNAL/CORE: BSP APIC ID missing from MADT\r\n");
    }

    let mut registrations = [CpuRegistration {
        apic_id: 0,
        processor_uid: 0,
        proximity_domain: None,
    }; MAX_BOOT_CPUS];
    let mut registration_count = 0usize;
    for cpu in topology.cpus().iter().filter(|cpu| cpu.enabled) {
        if registration_count == registrations.len() {
            fatal("KERNAL/CORE: CPU registration capacity exceeded\r\n");
        }
        registrations[registration_count] = CpuRegistration {
            apic_id: cpu.apic_id,
            processor_uid: cpu.processor_uid,
            proximity_domain: cpu.proximity_domain,
        };
        registration_count += 1;
    }
    let cpus = match CPU_REGISTRY.initialize(&registrations[..registration_count], bsp_apic_id) {
        Ok(registry) => registry,
        Err(_) => fatal("KERNAL/CORE: CPU registry publication failed\r\n"),
    };
    let bsp_index = match cpus.index_for_apic_id(bsp_apic_id) {
        Some(index) => index,
        None => fatal("KERNAL/CORE: BSP CPU index resolution failed\r\n"),
    };
    if cpus.state(bsp_index) != Ok(CpuState::Starting) {
        fatal("KERNAL/CORE: BSP registry did not enter Starting state\r\n");
    }

    let bsp_local_cell = match CPU_LOCALS.get(bsp_index.0 as usize) {
        Some(cell) => cell,
        None => fatal("KERNAL/CORE: BSP CpuLocal slot missing\r\n"),
    };
    let bsp_local = match bsp_local_cell.prepare(bsp_index, bsp_apic_id) {
        Ok(local) => local,
        Err(_) => fatal("KERNAL/CORE: BSP CpuLocal preparation failed\r\n"),
    };
    // SAFETY: BSP is non-migrating and the CpuLocal identity matches its verified APIC ID/index.
    if unsafe { install_bootstrap_gs(bsp_local) }.is_err() {
        fatal("KERNAL/CORE: BSP GS installation failed\r\n");
    }
    let bsp_scheduler = match CPU_SCHEDULERS.get(bsp_index.0 as usize) {
        Some(cell) => cell,
        None => fatal("KERNAL/CORE: BSP scheduler slot missing\r\n"),
    };
    if bsp_scheduler.prepare(bsp_index).is_err() {
        fatal("KERNAL/CORE: BSP scheduler owner publication failed\r\n");
    }

    AP_LOCAL_APIC_PHYSICAL.store(topology.local_apic_address(), Ordering::Release);

    let mut frames = match ExtentAllocator::<RUNTIME_EXTENTS>::from_boot_map(regions) {
        Ok(allocator) => allocator,
        Err(_) => fatal("KERNAL/CORE: runtime extent allocator construction failed\r\n"),
    };
    let test_frame = match frames.allocate_page() {
        Ok(frame) => frame,
        Err(_) => fatal("KERNAL/CORE: runtime frame allocation failed\r\n"),
    };
    if !ram_frame_self_test(test_frame, &kmap) {
        fatal("KERNAL/CORE: physical RAM kmap self-test failed\r\n");
    }
    let test_range = match FrameRange::new(test_frame, 1) {
        Ok(range) => range,
        Err(_) => fatal("KERNAL/CORE: self-test frame range invalid\r\n"),
    };
    if frames.free(test_range).is_err() {
        fatal("KERNAL/CORE: failed to return RAM self-test frame\r\n");
    }
    serial_write("KERNAL/CORE: reclaimable runtime allocator and RAM kmap verified\r\n");

    let root = match RuntimePageTableBackend::<ExtentAllocator<RUNTIME_EXTENTS>>::current_root() {
        Ok(root) => root,
        Err(_) => fatal("KERNAL/CORE: current CR3 unavailable for scheduler bootstrap\r\n"),
    };
    let bsp_stack = match KernelStack::new(
        layout.stack.guard.start,
        layout.stack.mapped.start,
        layout.stack.mapped.len,
    ) {
        Ok(stack) => stack,
        Err(_) => fatal("KERNAL/CORE: BSP idle stack contract invalid\r\n"),
    };
    // SAFETY: IF remains clear and this exact stack is the currently executing handoff stack.
    let bsp_idle = match unsafe {
        bsp_scheduler.bootstrap_adopt_current(IDLE_PRIORITY, current_rsp(), bsp_stack, root)
    } {
        Ok(id) => id,
        Err(_) => fatal("KERNAL/CORE: failed to adopt BSP bootstrap stack as idle thread\r\n"),
    };
    serial_write("KERNAL/SCHED: BSP idle adopted, slot ");
    serial_write_decimal(bsp_idle.slot as u64);
    serial_write(" generation ");
    serial_write_decimal(bsp_idle.generation as u64);
    serial_write("\r\n");

    // SAFETY: BSP is still non-migrating at CPL0 with IF=0. `physical` validates every firmware
    // read against the normalized ownership map. Resolver prefers CPUID 0x15 and otherwise uses
    // checksum-validated FADT + ACPI PM timer calibration before publishing one SMP-wide timebase.
    let bsp_frequency = match unsafe { resolve_tsc_frequency(&physical, info.rsdp_phys, features) } {
        Ok(frequency) => frequency,
        Err(_) => fatal("KERNAL/CORE: reliable TSC frequency resolution failed\r\n"),
    };
    if prepare_irq_runtime(bsp_index, &mut local_apic, features, bsp_frequency, TIMER_VECTOR).is_err() {
        fatal("KERNAL/CORE: BSP APIC/timer runtime preparation failed\r\n");
    }
    serial_write("KERNAL/CORE: BSP APIC runtime + one-shot timer prepared\r\n");

    run_bsp_scheduler_smoke(bsp_index, bsp_idle, bsp_scheduler, root, &mut frames, &kmap);

    // BSP reaches Online only after GS, scheduler, adopted idle, APIC runtime and timer are live.
    if cpus.mark_online(bsp_index).is_err() {
        fatal("KERNAL/CORE: BSP Online publication failed\r\n");
    }
    serial_write("KERNAL/CORE: BSP runtime complete; CpuIndex ");
    serial_write_decimal(bsp_index.0 as u64);
    serial_write(" now Online\r\n");

    let started = start_application_processors(
        info,
        cpus,
        bsp_index,
        &mut local_apic,
        &mut frames,
        &kmap,
        features,
        bsp_frequency,
    );
    serial_write("KERNAL/CORE: APs online: ");
    serial_write_decimal(started as u64);
    serial_write(" / ");
    serial_write_decimal(cpus.len().saturating_sub(1) as u64);
    serial_write("\r\n");
    serial_write("KERNAL/CORE: total CPUs online: ");
    serial_write_decimal(cpus.online_count() as u64);
    serial_write("\r\n");
    serial_write("KERNAL/CORE: runtime free frames: ");
    serial_write_decimal(frames.free_pages());
    serial_write("\r\n");

    #[cfg(feature = "qemu-exit")]
    if cpus.online_count() != cpus.len() {
        fatal("KERNAL/CORE: QEMU SMP proof requires every discovered CPU Online\r\n");
    }

    send_reschedule_probes(cpus, bsp_index);

    // Preserve the legacy xAPIC UC kmap lease for CPU lifetime. x2APIC has no mapping, but using
    // the same ownership rule keeps the runtime model uniform. No bootstrap API uses this object
    // after AP startup; IRQ-time access goes through the published RuntimeApicHandle.
    core::mem::forget(local_apic);

    run_bsp_irq_proof(cpus, bsp_index, bsp_scheduler);
    serial_write("KERNAL/CORE: timer + reschedule IPI proof complete\r\n");
    serial_write("KERNAL/CORE: privileged CR3/SMP/scheduler/IRQ runtime source path complete\r\n");

    #[cfg(feature = "qemu-exit")]
    {
        serial_write("KERNAL/CORE: triggering final #BP IDT self-test\r\n");
        // SAFETY: vector 3 is installed and terminal in smoke configuration. IF is clear because
        // halt_until_interrupt returns through CLI before this point.
        unsafe { asm!("int3", options(nomem, nostack, preserves_flags)) };
        fatal("KERNAL/CORE: #BP unexpectedly returned\r\n");
    }

    #[cfg(not(feature = "qemu-exit"))]
    runtime_idle_forever(bsp_index, bsp_scheduler)
}

fn run_bsp_scheduler_smoke(
    cpu: CpuIndex,
    idle: ThreadId,
    scheduler: &'static CpuSchedulerCell<SCHEDULER_THREADS_PER_CPU, REMOTE_WAKE_SLOTS>,
    root: u64,
    frames: &mut ExtentAllocator<RUNTIME_EXTENTS>,
    kmap: &KmapController,
) {
    SCHEDULER_SMOKE_STATE.store(0, Ordering::Release);
    // SAFETY: BSP is owner, IF=0, preemption inactive; closure does not context-switch while
    // scheduler table references are live.
    let created = match unsafe {
        scheduler.with_local(|run_queue, contexts, _wakes| {
            create_ready_thread(
                cpu,
                SMOKE_WORKER_PRIORITY,
                scheduler_smoke_worker,
                cpu.0 as u64,
                root,
                root,
                run_queue,
                contexts,
                frames,
                kmap,
            )
        })
    } {
        Ok(Ok(thread)) => thread,
        _ => fatal("KERNAL/SCHED: failed to create scheduler smoke worker\r\n"),
    };
    serial_write("KERNAL/SCHED: worker ready, slot ");
    serial_write_decimal(created.id.slot as u64);
    serial_write(" generation ");
    serial_write_decimal(created.id.generation as u64);
    serial_write("\r\n");

    // SAFETY: pre-STI bootstrap scheduler contract holds; worker has higher priority than idle.
    let resumed = match unsafe { scheduler.bootstrap_yield() } {
        Ok(id) => id,
        Err(_) => fatal("KERNAL/SCHED: idle-to-worker switch failed\r\n"),
    };
    if resumed != idle || SCHEDULER_SMOKE_STATE.load(Ordering::Acquire) != 1 {
        fatal("KERNAL/SCHED: worker did not switch back to expected idle thread\r\n");
    }
    serial_write("KERNAL/SCHED: worker exited and idle resumed\r\n");

    // SAFETY: idle is again current owner thread, IF=0, and worker is Exited/non-running.
    let report = match unsafe {
        scheduler.with_local(|run_queue, contexts, _wakes| {
            reap_exited_local(
                created.id,
                Some(idle),
                root,
                run_queue,
                contexts,
                frames,
                kmap,
            )
        })
    } {
        Ok(Ok(report)) => report,
        _ => fatal("KERNAL/SCHED: worker reaping failed\r\n"),
    };
    if report.pages_unmapped == 0 || report.pages_unmapped != report.pages_freed {
        fatal("KERNAL/SCHED: worker stack reclamation invariant failed\r\n");
    }
    SCHEDULER_SMOKE_STATE.store(2, Ordering::Release);
    serial_write("KERNAL/SCHED: context switch + exit + reap smoke complete; pages reclaimed ");
    serial_write_decimal(report.pages_freed as u64);
    serial_write("\r\n");
}

extern "C" fn scheduler_smoke_worker(cpu_index: u64) -> ! {
    let Ok(index_raw) = u16::try_from(cpu_index) else {
        fatal("KERNAL/SCHED: smoke worker invalid CPU index\r\n");
    };
    let index = CpuIndex(index_raw);
    // SAFETY: context switch set GS/current-thread before entering this worker; migration is off.
    let local = unsafe { current_cpu_local() };
    if local.index() != index {
        fatal("KERNAL/SCHED: smoke worker GS owner mismatch\r\n");
    }
    serial_write("KERNAL/SCHED: worker entered on scheduler-managed stack\r\n");
    SCHEDULER_SMOKE_STATE.store(1, Ordering::Release);
    let scheduler = match CPU_SCHEDULERS.get(index.0 as usize) {
        Some(cell) => cell,
        None => fatal("KERNAL/SCHED: smoke worker scheduler missing\r\n"),
    };
    // SAFETY: worker is current owner thread, IF=0 and bootstrap preemption remains inactive.
    let _ = unsafe { scheduler.bootstrap_exit_current_and_switch() };
    fatal("KERNAL/SCHED: exited smoke worker unexpectedly returned\r\n")
}

fn start_application_processors(
    info: &BootInfoV1,
    cpus: &'static CpuRegistry<MAX_BOOT_CPUS>,
    bsp: CpuIndex,
    local_apic: &mut HardwareLocalApic<'_>,
    frames: &mut ExtentAllocator<RUNTIME_EXTENTS>,
    kmap: &KmapController,
    features: kernal_arch_x86_64::CpuFeatures,
    frequency: kernal_tsc_x86_64::TscFrequency,
) -> usize {
    if cpus.len() <= 1 { return 0; }
    if info.ap_trampoline.is_empty() || !info.ap_trampoline_is_valid() {
        serial_write("KERNAL/SMP: no valid low-memory AP trampoline; staying degraded\r\n");
        return 0;
    }
    let delay = match TscDelay::new(frequency) {
        Ok(delay) => delay,
        Err(_) => {
            serial_write("KERNAL/SMP: unreliable TSC rejected for INIT/SIPI timing\r\n");
            return 0;
        }
    };
    let root = match RuntimePageTableBackend::<ExtentAllocator<RUNTIME_EXTENTS>>::current_root() {
        Ok(root) if root < (1u64 << 32) => root,
        _ => {
            serial_write("KERNAL/SMP: CR3 is not AP-start compatible\r\n");
            return 0;
        }
    };

    let mut online = 0usize;
    for descriptor in cpus.descriptors() {
        if descriptor.index == bsp { continue; }
        let layout = match prepare_ap_memory(descriptor.index, frames, kmap, root) {
            Ok(layout) => layout,
            Err(()) => {
                let _ = cpus.mark_failed(descriptor.index);
                serial_write("KERNAL/SMP: AP resource preparation failed for CpuIndex ");
                serial_write_decimal(descriptor.index.0 as u64);
                serial_write("\r\n");
                continue;
            }
        };

        let parameters = StartupParameters {
            bootstrap_physical: info.ap_trampoline.phys_addr,
            root_table_physical: root,
            stack_pointer: layout.kernel_stack.sysv_entry_rsp,
            kernel_entry: _ap_start as usize as u64,
            cpu_index: descriptor.index.0,
        };
        let vector = match parameters.sipi_vector() {
            Ok(vector) => vector,
            Err(_) => {
                let _ = cpus.mark_failed(descriptor.index);
                continue;
            }
        };
        let mailbox_address = match info.ap_trampoline.phys_addr.checked_add(AP_PAGE_SIZE) {
            Some(address) => address,
            None => {
                let _ = cpus.mark_failed(descriptor.index);
                continue;
            }
        };
        // SAFETY: loader identity-maps the second AP bootstrap page RW-NX in the active CR3.
        let mailbox = unsafe { from_raw_parts_mut(mailbox_address as *mut u8, AP_PAGE_SIZE as usize) };
        if build_mailbox(parameters, mailbox).is_err() {
            let _ = cpus.mark_failed(descriptor.index);
            continue;
        }
        fence(Ordering::SeqCst);

        serial_write("KERNAL/SMP: starting APIC ");
        serial_write_decimal(descriptor.apic_id as u64);
        serial_write(" as CpuIndex ");
        serial_write_decimal(descriptor.index.0 as u64);
        serial_write("\r\n");
        match start_one(cpus, descriptor.index, vector, local_apic, &delay) {
            Ok(()) => {
                online += 1;
                serial_write("KERNAL/SMP: CpuIndex online ");
                serial_write_decimal(descriptor.index.0 as u64);
                serial_write("\r\n");
            }
            Err(_) => {
                serial_write("KERNAL/SMP: CpuIndex failed or timed out ");
                serial_write_decimal(descriptor.index.0 as u64);
                serial_write("\r\n");
            }
        }
    }
    online
}

fn prepare_ap_memory(
    cpu: CpuIndex,
    frames: &mut ExtentAllocator<RUNTIME_EXTENTS>,
    kmap: &KmapController,
    root: u64,
) -> Result<PerCpuLayout, ()> {
    let layout = PerCpuLayout::for_cpu(cpu.0 as usize).map_err(|_| ())?;
    let mut physical = [0u64; AP_STACK_FRAME_COUNT];
    for address in &mut physical {
        let frame = frames.allocate_page().map_err(|_| ())?;
        zero_frame(frame, kmap)?;
        *address = frame;
    }

    let kernel_end = KERNEL_STACK_PAGES;
    let df_end = kernel_end + IST_STACK_PAGES;
    let nmi_end = df_end + IST_STACK_PAGES;
    let mc_end = nmi_end + IST_STACK_PAGES;

    let mut backend = RuntimePageTableBackend::new(frames, kmap);
    let mut mapper = Mapper::new(&mut backend, root).map_err(|_| ())?;
    map_stack(&mut mapper, layout.kernel_stack, &physical[..kernel_end])?;
    map_stack(&mut mapper, layout.double_fault_stack, &physical[kernel_end..df_end])?;
    map_stack(&mut mapper, layout.nmi_stack, &physical[df_end..nmi_end])?;
    map_stack(&mut mapper, layout.machine_check_stack, &physical[nmi_end..mc_end])?;

    let kmap_base = window_base(cpu.0 as usize).map_err(|_| ())?;
    let kmap_last = kmap_base
        .checked_add(((KMAP_SLOTS_PER_CPU - 1) as u64).checked_mul(PAGE_SIZE).ok_or(())?)
        .ok_or(())?;
    let first = mapper.ensure_leaf_table(kmap_base, false).map_err(|_| ())?;
    let last = mapper.ensure_leaf_table(kmap_last, false).map_err(|_| ())?;
    if first != last { return Err(()); }
    Ok(layout)
}

fn map_stack<B: PageTableBackend>(
    mapper: &mut Mapper<'_, B>,
    stack: GuardedStack,
    physical_frames: &[u64],
) -> Result<(), ()> {
    let expected_pages = usize::try_from(stack.mapped.len / PAGE_SIZE).map_err(|_| ())?;
    if expected_pages != physical_frames.len() { return Err(()); }
    let flags = MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::GLOBAL);
    for (index, physical) in physical_frames.iter().copied().enumerate() {
        let offset = (index as u64).checked_mul(PAGE_SIZE).ok_or(())?;
        mapper.map_page(stack.mapped.start.checked_add(offset).ok_or(())?, physical, flags)
            .map_err(|_| ())?;
    }
    Ok(())
}

fn zero_frame(physical: u64, kmap: &KmapController) -> Result<(), ()> {
    if physical == 0 || physical & (PAGE_SIZE - 1) != 0 { return Err(()); }
    let mapping = kmap.map(MappingRequest {
        physical_address: physical,
        writable: true,
        cache: CachePolicy::WriteBack,
    }).map_err(|_| ())?;
    // SAFETY: frame was just allocated exclusively and this lease is writable for one page.
    let base = unsafe { mapping.as_mut_ptr::<u8>() }.ok_or(())?;
    // SAFETY: live mapping spans exactly PAGE_SIZE bytes.
    unsafe { write_bytes(base, 0, PAGE_SIZE as usize) };
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn _ap_start(cpu_index: u64) -> ! {
    let Ok(index_raw) = u16::try_from(cpu_index) else { halt_forever(); };
    let index = CpuIndex(index_raw);
    let Some(cpus) = CPU_REGISTRY.get() else { halt_forever(); };
    let Some(descriptor) = cpus.descriptor(index) else { halt_forever(); };
    let layout = match PerCpuLayout::for_cpu(index.0 as usize) {
        Ok(layout) => layout,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: invalid per-CPU layout\r\n"),
    };

    let Some(cell) = AP_DESCRIPTORS.get(index.0 as usize) else { halt_forever(); };
    let descriptors = match cell.prepare(DescriptorConfig {
        ring0_stack_top: layout.kernel_stack.top,
        double_fault_stack_top: layout.double_fault_stack.top,
        nmi_stack_top: layout.nmi_stack.top,
        machine_check_stack_top: layout.machine_check_stack.top,
    }) {
        Ok(descriptors) => descriptors,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: GDT/TSS preparation failed\r\n"),
    };
    // SAFETY: AP entered CPL0 on its mapped high-half stack with interrupts disabled.
    unsafe { descriptors.load() };

    let Some(idt) = BSP_EXCEPTIONS.prepared() else {
        ap_fail(cpus, index, "KERNAL/AP: shared IDT unavailable\r\n");
    };
    // SAFETY: shared IDT is immutable/static and this AP's IST stacks are active in TSS.
    unsafe { idt.load() };

    let local_cell = match CPU_LOCALS.get(index.0 as usize) {
        Some(cell) => cell,
        None => ap_fail(cpus, index, "KERNAL/AP: CpuLocal slot missing\r\n"),
    };
    let local = match local_cell.prepare(index, descriptor.apic_id) {
        Ok(local) => local,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: CpuLocal preparation failed\r\n"),
    };
    // SAFETY: AP cannot migrate during bring-up and descriptor identity is topology-validated.
    if unsafe { install_bootstrap_gs(local) }.is_err() {
        ap_fail(cpus, index, "KERNAL/AP: GS installation failed\r\n");
    }

    let scheduler = match CPU_SCHEDULERS.get(index.0 as usize) {
        Some(cell) => cell,
        None => ap_fail(cpus, index, "KERNAL/AP: scheduler slot missing\r\n"),
    };
    if scheduler.prepare(index).is_err() {
        ap_fail(cpus, index, "KERNAL/AP: scheduler owner publication failed\r\n");
    }

    let features = detect_features();
    // SAFETY: all currently reachable kernel mappings are supervisor-only.
    unsafe { enable_smep(features) };

    // SAFETY: BSP pre-created this CPU's complete kmap PT path before SIPI; AP cannot migrate.
    let kmap = match unsafe { KmapController::assume_prepared(index.0 as usize) } {
        Ok(kmap) => kmap,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: kmap initialization failed\r\n"),
    };
    let local_apic_physical = AP_LOCAL_APIC_PHYSICAL.load(Ordering::Acquire);
    if local_apic_physical == 0 {
        ap_fail(cpus, index, "KERNAL/AP: local APIC address unavailable\r\n");
    }
    // SAFETY: AP runs at CPL0, is non-migrating, and initializes only its own Local APIC mode.
    let mut local_apic = match unsafe {
        HardwareLocalApic::initialize(&kmap, features, local_apic_physical)
    } {
        Ok(apic) => apic,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: local APIC initialization failed\r\n"),
    };
    if local_apic.mask_bootstrap_lvts().is_err()
        || local_apic.enable(DEFAULT_SPURIOUS_VECTOR).is_err()
    {
        ap_fail(cpus, index, "KERNAL/AP: local APIC configuration failed\r\n");
    }
    match local_apic.id() {
        Ok(apic_id) if apic_id == descriptor.apic_id => {}
        _ => ap_fail(cpus, index, "KERNAL/AP: APIC identity mismatch\r\n"),
    }

    // detect() returns the BSP-published reliable timebase before consulting local CPUID.
    let frequency = match detect_tsc_frequency(features) {
        Ok(frequency) => frequency,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: published reliable TSC frequency unavailable\r\n"),
    };
    if prepare_irq_runtime(index, &mut local_apic, features, frequency, TIMER_VECTOR).is_err() {
        ap_fail(cpus, index, "KERNAL/AP: APIC/timer runtime preparation failed\r\n");
    }

    let root = match RuntimePageTableBackend::<ExtentAllocator<RUNTIME_EXTENTS>>::current_root() {
        Ok(root) => root,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: current CR3 unavailable\r\n"),
    };
    let idle_stack = match KernelStack::new(
        layout.kernel_stack.guard.start,
        layout.kernel_stack.mapped.start,
        layout.kernel_stack.mapped.len,
    ) {
        Ok(stack) => stack,
        Err(_) => ap_fail(cpus, index, "KERNAL/AP: idle stack contract invalid\r\n"),
    };
    // SAFETY: AP is still pre-STI/non-preemptible and is executing on this exact guarded stack.
    if unsafe {
        scheduler.bootstrap_adopt_current(IDLE_PRIORITY, current_rsp(), idle_stack, root)
    }.is_err() {
        ap_fail(cpus, index, "KERNAL/AP: bootstrap idle adoption failed\r\n");
    }

    // Online is the final publication: descriptor/IDT, GS, scheduler idle, APIC runtime and timer.
    if cpus.mark_online(index).is_err() {
        ap_fail(cpus, index, "KERNAL/AP: lifecycle Online transition failed\r\n");
    }
    fence(Ordering::SeqCst);
    serial_write("KERNAL/AP: online CpuIndex ");
    serial_write_decimal(index.0 as u64);
    serial_write(" APIC ");
    serial_write_decimal(descriptor.apic_id as u64);
    serial_write("; GS + scheduler idle + timer runtime active\r\n");

    // Preserve a legacy xAPIC mapping for CPU lifetime. IRQ-time access uses RuntimeApicHandle.
    core::mem::forget(local_apic);
    runtime_idle_forever(index, scheduler)
}

fn send_reschedule_probes(cpus: &CpuRegistry<MAX_BOOT_CPUS>, source_cpu: CpuIndex) {
    let source = match runtime_apic_handle(source_cpu) {
        Ok(handle) => handle,
        Err(_) => fatal("KERNAL/IRQ: BSP runtime APIC handle missing\r\n"),
    };
    for descriptor in cpus.descriptors() {
        if cpus.state(descriptor.index) != Ok(CpuState::Online) { continue; }
        // BSP still runs with IF=0 here, serializing legacy xAPIC ICR use. Sending to self leaves
        // an interrupt pending until the first controlled STI; APs may receive immediately in idle.
        if source.send_fixed_ipi(descriptor.apic_id, RESCHEDULE_VECTOR).is_err() {
            fatal("KERNAL/IRQ: failed to send reschedule proof IPI\r\n");
        }
    }
    serial_write("KERNAL/IRQ: reschedule proof IPIs dispatched to Online CPUs\r\n");
}

fn run_bsp_irq_proof(
    cpus: &CpuRegistry<MAX_BOOT_CPUS>,
    cpu: CpuIndex,
    scheduler: &'static CpuSchedulerCell<SCHEDULER_THREADS_PER_CPU, REMOTE_WAKE_SLOTS>,
) {
    loop {
        scheduler_safe_point(scheduler);
        if all_online_irq_proofs_complete(cpus) { break; }
        // Keep a BSP watchdog one-shot active until every online AP has reported its own proof.
        // SAFETY: BSP is current/non-migrating at CPL0 with IF=0.
        if unsafe { arm_if_disarmed(cpu, TIMER_PROOF_DELAY_NS) }.is_err() {
            fatal("KERNAL/IRQ: failed to arm BSP one-shot timer\r\n");
        }
        // SAFETY: IDT/TSS/GS/APIC runtime/timer are complete and IF is currently clear.
        if unsafe { halt_until_interrupt() }.is_err() {
            fatal("KERNAL/IRQ: BSP idle wake boundary failed\r\n");
        }
    }
    scheduler_safe_point(scheduler);
    serial_write("KERNAL/IRQ: every Online CPU delivered >=2 timer IRQs and >=1 reschedule IPI\r\n");
}

fn all_online_irq_proofs_complete(cpus: &CpuRegistry<MAX_BOOT_CPUS>) -> bool {
    for descriptor in cpus.descriptors() {
        match cpus.state(descriptor.index) {
            Ok(CpuState::Online) => {
                if timer_interrupt_count(descriptor.index).unwrap_or(0) < TIMER_PROOF_INTERRUPTS {
                    return false;
                }
                if reschedule_interrupt_count(descriptor.index).unwrap_or(0) < RESCHEDULE_PROOF_INTERRUPTS {
                    return false;
                }
            }
            Ok(CpuState::Failed) => {}
            _ => return false,
        }
    }
    true
}

fn runtime_idle_forever(
    cpu: CpuIndex,
    scheduler: &'static CpuSchedulerCell<SCHEDULER_THREADS_PER_CPU, REMOTE_WAKE_SLOTS>,
) -> ! {
    loop {
        scheduler_safe_point(scheduler);
        if timer_interrupt_count(cpu).unwrap_or(0) < TIMER_PROOF_INTERRUPTS {
            // SAFETY: this CPU is current/non-migrating and IF is clear at the scheduler safe point.
            if unsafe { arm_if_disarmed(cpu, TIMER_PROOF_DELAY_NS) }.is_err() {
                fatal("KERNAL/IDLE: failed to arm one-shot timer\r\n");
            }
        }
        // SAFETY: all per-CPU interrupt runtime state is live. Returns after CLI with IF=0.
        if unsafe { halt_until_interrupt() }.is_err() {
            fatal("KERNAL/IDLE: interrupt wake boundary failed\r\n");
        }
    }
}

fn scheduler_safe_point(
    scheduler: &'static CpuSchedulerCell<SCHEDULER_THREADS_PER_CPU, REMOTE_WAKE_SLOTS>,
) {
    // SAFETY: all callers run on current CPL0 CPU after an IRQ has fully returned; GS is valid.
    let local = unsafe { current_cpu_local() };
    if !local.need_reschedule() { return; }
    local.clear_reschedule();
    // SAFETY: idle/safe-point path always arrives with IF=0, irq_depth=0 and no active preemption
    // guard. bootstrap_yield remains valid as the initial cooperative scheduler switch primitive.
    if unsafe { scheduler.bootstrap_yield() }.is_err() {
        fatal("KERNAL/SCHED: runtime scheduler safe-point failed\r\n");
    }
}

fn ap_fail(cpus: &CpuRegistry<MAX_BOOT_CPUS>, index: CpuIndex, message: &str) -> ! {
    serial_write(message);
    let _ = cpus.mark_failed(index);
    halt_forever()
}

struct ValidatedPhysicalReader<'a> {
    kmap: &'a KmapController,
    regions: &'a [MemoryRegionV1],
}

impl PhysicalReader for ValidatedPhysicalReader<'_> {
    fn read_exact(&self, physical_address: u64, destination: &mut [u8]) -> Result<(), PhysicalIoError> {
        if destination.is_empty() { return Ok(()); }
        if !physical_range_is_readable(self.regions, physical_address, destination.len() as u64) {
            return Err(PhysicalIoError::Backend);
        }
        PhysicalReader::read_exact(self.kmap, physical_address, destination)
    }
}

fn discover_interrupt_topology(
    info: &BootInfoV1,
    reader: &ValidatedPhysicalReader<'_>,
) -> Result<Topology<MAX_BOOT_CPUS, 1>, ()> {
    if info.rsdp_phys == 0 { return Err(()); }
    let rsdp = read_rsdp(reader, info.rsdp_phys).map_err(|_| ())?;
    let root = read_root_table(reader, rsdp).map_err(|_| ())?;
    let madt_sdt = find_unique_table(reader, root, *b"APIC").map_err(|_| ())?;
    let madt = read_madt(reader, madt_sdt.address).map_err(|_| ())?;
    let mut topology = Topology::<MAX_BOOT_CPUS, 1>::new();
    topology.set_local_apic_address(madt.local_apic_address as u64).map_err(|_| ())?;
    let mut cursor = madt.entries();
    while let Some(entry) = cursor.next(reader).map_err(|_| ())? {
        topology.apply_madt_entry(entry).map_err(|_| ())?;
    }
    if topology.enabled_cpu_count() == 0 { return Err(()); }
    Ok(topology)
}

fn boot_memory_regions(info: &BootInfoV1) -> Option<&'static [MemoryRegionV1]> {
    let count = info.memory_region_count as usize;
    if count == 0 || count > MAX_BOOT_MEMORY_REGIONS { return None; }
    if info.memory_region_size as usize != size_of::<MemoryRegionV1>() { return None; }
    let expected_len = count.checked_mul(size_of::<MemoryRegionV1>())?;
    if info.memory_map.len != expected_len as u64 || info.memory_map.phys_addr == 0 { return None; }
    // SAFETY: loader maps exactly `count` initialized entries at the fixed memory-map window.
    Some(unsafe { from_raw_parts(MEMORY_MAP_VIRTUAL as *const MemoryRegionV1, count) })
}

fn validate_memory_regions(regions: &[MemoryRegionV1]) -> bool {
    let mut previous_end = 0u64;
    for (index, region) in regions.iter().copied().enumerate() {
        if !region.is_structurally_valid() { return false; }
        let Some(end) = region.end() else { return false; };
        if index != 0 && region.start < previous_end { return false; }
        previous_end = end;
    }
    true
}

fn physical_range_is_readable(regions: &[MemoryRegionV1], start: u64, len: u64) -> bool {
    if len == 0 { return false; }
    let Some(end) = start.checked_add(len) else { return false; };
    regions.iter().copied().any(|region| {
        let Some(region_end) = region.end() else { return false; };
        region.start <= start && end <= region_end && region.kind != memory_kind::MMIO
    })
}

fn ram_frame_self_test(physical: u64, kmap: &KmapController) -> bool {
    if physical == 0 || physical & (PAGE_SIZE - 1) != 0 { return false; }
    let mapping = match kmap.map(MappingRequest {
        physical_address: physical,
        writable: true,
        cache: CachePolicy::WriteBack,
    }) {
        Ok(mapping) => mapping,
        Err(_) => return false,
    };
    // SAFETY: writable lease maps an exclusively allocated 4 KiB frame.
    let base = match unsafe { mapping.as_mut_ptr::<u8>() } {
        Some(base) => base,
        None => return false,
    };
    // SAFETY: frame is exclusive and exactly one page long.
    unsafe { write_bytes(base, 0, PAGE_SIZE as usize) };
    let head = base.cast::<u64>();
    // SAFETY: PAGE_SIZE is divisible by u64 alignment and this is the final aligned word.
    let tail = unsafe { base.add(PAGE_SIZE as usize - size_of::<u64>()).cast::<u64>() };
    // SAFETY: both pointers lie in the exclusive live mapping.
    unsafe {
        write_volatile(head, RAM_SELF_TEST_HEAD);
        write_volatile(tail, RAM_SELF_TEST_TAIL);
    }
    // SAFETY: both pointers remain aligned and mapped.
    let passed = unsafe {
        read_volatile(head) == RAM_SELF_TEST_HEAD && read_volatile(tail) == RAM_SELF_TEST_TAIL
    };
    // SAFETY: do not leave test data in a future metadata frame.
    unsafe { write_bytes(base, 0, PAGE_SIZE as usize) };
    passed
}

fn current_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: pure register read, no memory or flags modified.
    unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp
}

fn exception_handler(frame: ExceptionFrame) -> ! {
    serial_write("KERNAL/EXCEPTION: vector ");
    serial_write_decimal(frame.vector);
    serial_write("\r\n");
    #[cfg(feature = "qemu-exit")]
    if frame.vector == 3 {
        if SCHEDULER_SMOKE_STATE.load(Ordering::Acquire) != 2 {
            serial_write("KERNAL/CORE: #BP reached before scheduler smoke completion\r\n");
            qemu_exit_failure();
            halt_forever();
        }
        serial_write("KERNAL/CORE: final #BP self-test passed after scheduler/timer/IPI proof\r\n");
        qemu_exit_success();
        halt_forever();
    }
    #[cfg(feature = "qemu-exit")]
    qemu_exit_failure();
    halt_forever()
}

fn interrupt_handler(frame: &mut InterruptFrame) {
    // SAFETY: IF is enabled only after GS CpuLocal and IRQ runtime publication on this CPU.
    let local = unsafe { current_cpu_local() };
    local.enter_irq();
    let cpu = local.index();
    match frame.vector as u8 {
        SPURIOUS_VECTOR => {
            // Architectural APIC spurious interrupts are not acknowledged with EOI.
        }
        TIMER_VECTOR => {
            if runtime_timer(cpu, TIMER_VECTOR).is_err() {
                fatal("KERNAL/IRQ: timer runtime/EOI failed\r\n");
            }
            local.request_reschedule();
        }
        RESCHEDULE_VECTOR => {
            let scheduler = match CPU_SCHEDULERS.get(cpu.0 as usize) {
                Some(cell) => cell,
                None => fatal("KERNAL/IRQ: scheduler slot missing for reschedule IPI\r\n"),
            };
            // SAFETY: IRQ executes on the scheduler owner CPU with GS installed; drain is bounded.
            if unsafe { runtime_reschedule(cpu, scheduler, REMOTE_WAKE_SLOTS) }.is_err() {
                fatal("KERNAL/IRQ: reschedule runtime/EOI failed\r\n");
            }
            local.request_reschedule();
        }
        _ => fatal("KERNAL/IRQ: unexpected external vector\r\n"),
    }
    if local.exit_irq().is_err() { fatal("KERNAL/IRQ: irq-depth underflow\r\n"); }
}

fn fatal(message: &str) -> ! {
    serial_write(message);
    #[cfg(feature = "qemu-exit")]
    qemu_exit_failure();
    halt_forever()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! { fatal("KERNAL/PANIC: core panic\r\n") }

fn serial_init() {
    // SAFETY: early x86_64 diagnostics use conventional COM1.
    unsafe {
        outb(COM1 + 1, 0);
        outb(COM1 + 3, 0x80);
        outb(COM1, 3);
        outb(COM1 + 1, 0);
        outb(COM1 + 3, 3);
        outb(COM1 + 2, 0xc7);
        outb(COM1 + 4, 0x0b);
    }
}

fn serial_write(message: &str) {
    for byte in message.bytes() {
        while unsafe { inb(COM1 + 5) } & 0x20 == 0 {}
        unsafe { outb(COM1, byte) };
    }
}

fn serial_write_decimal(mut value: u64) {
    let mut buffer = [0u8; 20];
    let mut index = buffer.len();
    if value == 0 { serial_write("0"); return; }
    while value != 0 {
        index -= 1;
        buffer[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    for byte in &buffer[index..] {
        while unsafe { inb(COM1 + 5) } & 0x20 == 0 {}
        unsafe { outb(COM1, *byte) };
    }
}

fn halt_forever() -> ! {
    loop { unsafe { asm!("cli; hlt", options(nomem, nostack)) }; }
}

#[cfg(feature = "qemu-exit")]
fn qemu_exit_success() { unsafe { outl(QEMU_DEBUG_EXIT, QEMU_SUCCESS_VALUE) }; }
#[cfg(feature = "qemu-exit")]
fn qemu_exit_failure() { unsafe { outl(QEMU_DEBUG_EXIT, QEMU_FAILURE_VALUE) }; }

unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

#[cfg(feature = "qemu-exit")]
unsafe fn outl(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    }
    value
}
