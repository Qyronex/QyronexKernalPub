// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::Pl011;
use core::num::NonZeroU32;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernal_exceptions_aarch64::{ExceptionFrame, LowerElAarch64Synchronous};
use kernal_fdt_aarch64::MmioRegion;
use kernal_linux_aarch64_abi::classify_step30_runtime;
use kernal_linux_abi::{
    MAX_SYSCALL_ARGS, MinimumRuntimeCall, Step30RuntimeCall, SyscallRequest, SyscallReturn,
    unsupported,
};
use kernal_linux_bootstrap_aarch64::time::{ClockGettimeError, clock_gettime};
use kernal_protected_boot_aarch64::{
    RuntimeTablePool, Step15ProofCallback, install_step15_proof_callback,
    map_qemu_initrd_high_alias, runtime_ttbr1_root,
};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_smp::GlobalThreadId;

#[path = "step15_entropy.rs"]
pub(super) mod entropy;
#[path = "step15_exit.rs"]
mod exit;
#[path = "step15_futex.rs"]
pub(super) mod futex;
#[path = "step15_group_exit.rs"]
mod group_exit;
#[path = "step15_initial.rs"]
pub(super) mod initial;
#[path = "step15_kmap.rs"]
pub(super) mod kmap;
#[path = "step15_live_vm.rs"]
mod live_vm;
#[path = "step15_loader_frames.rs"]
pub(super) mod loader_frames;
#[path = "step15_memory.rs"]
pub(super) mod memory;
#[path = "step15_runtime_integrated.rs"]
pub(super) mod runtime;
#[path = "step30_signal_delivery.rs"]
mod signal_delivery;
#[path = "step30_sigreturn.rs"]
mod sigreturn;
#[path = "step28_mprotect.rs"]
mod step28_mprotect;
#[cfg(feature = "step29-qemu-proof")]
#[path = "step29_fd.rs"]
mod step29_fd;
#[cfg(feature = "step29-qemu-proof")]
#[path = "step29_fd_io.rs"]
mod step29_fd_io;
#[cfg(feature = "step29-qemu-proof")]
#[path = "step29_pipe_io.rs"]
mod step29_pipe_io;
#[cfg(feature = "step29-qemu-proof")]
#[path = "step29_runtime.rs"]
mod step29_runtime;
#[path = "step30_child_exit.rs"]
mod step30_child_exit;
#[path = "step30_exec_input.rs"]
mod step30_exec_input;
#[path = "step30_exec_source.rs"]
mod step30_exec_source;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[path = "step30_fork.rs"]
mod step30_fork;
#[path = "step30_runtime.rs"]
mod step30_runtime;
#[path = "step15_write.rs"]
mod write;

const _: () = assert!(runtime::STEP15_RUNTIME_THREADS == super::SCHEDULER_THREADS_PER_CPU);
const _: () = assert!(futex::STEP15_FUTEX_WAITERS == runtime::STEP15_RUNTIME_THREADS);
const STEP15_FUTEX_WAIT_PRIVATE: u64 = 128;

static STEP15_SVC_UART_BASE: AtomicU64 = AtomicU64::new(0);
static STEP15_SVC_UART_SIZE: AtomicU64 = AtomicU64::new(0);
static STEP30_POST_FORK_RESCHEDULE_TRACE_PENDING: AtomicBool = AtomicBool::new(false);

pub(super) fn install(serial: &Pl011) {
    if !cfg!(feature = "step15-qemu-proof") {
        return;
    }

    // QEMU `virt` publishes host-sourced randomness in the generated DTB. Capture it before the
    // protected-regime transition removes the original low DTB mapping; no counter/time fallback is
    // accepted for Linux AT_RANDOM.
    // SAFETY: install runs in the QEMU proof boot before entering the protected runtime regime.
    unsafe { entropy::publish_qemu_at_random() }.unwrap_or_else(|_| {
        super::fatal_with_serial(serial, "KERNAL/ARM64: Step 15 DTB rng-seed unavailable\n")
    });
    serial.write_str("KERNAL/ARM64: Step 15 DTB rng-seed captured\n");

    let context = core::ptr::from_ref(serial).cast_mut().cast::<()>();
    let callback = Step15ProofCallback::new(context, run_protected);
    unsafe { install_step15_proof_callback(callback) }.unwrap_or_else(|_| {
        super::fatal_with_serial(
            serial,
            "KERNAL/ARM64: Step 15 Core callback install failed\n",
        )
    });
    serial.write_str("KERNAL/ARM64: Step 15 Core callback installed\n");
}

unsafe fn run_protected(
    context: *mut (),
    mut backend: NonNull<RuntimeTablePool>,
) -> Result<(), ()> {
    if context.is_null() {
        return Err(());
    }

    let serial = unsafe { &*context.cast::<Pl011>() };
    // SAFETY: the mutable backend borrow exists only for this synchronous mapping transaction and is
    // dropped before reservation publication, allocator construction, ELF parsing, or any future
    // operation may block.
    let initrd = unsafe { map_qemu_initrd_high_alias(backend.as_mut()) }.map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 protected initrd mapped RO/NX\n");

    // Publish physical exclusions before the first safe byte borrow. This records the protected QEMU
    // low prefix plus the complete page-covering initrd range.
    memory::publish_frame_reservations(initrd).map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 physical frame reservations published\n");

    // Consume those exact reservations immediately into Core's sole persistent QEMU-RAM allocator.
    // Later initial-loader and VM calls receive only short serialized borrows of this same owner.
    memory::initialize_live_frame_allocator().map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 live frame allocator initialized\n");

    initrd.validate_aarch64_elf().map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 initrd AArch64 ELF accepted\n");

    // Build the real long-lived Linux Process/address-space owner while the protected callback still
    // owns the exact construction-window page-table cursor. Later loader/trap/pthread composition
    // borrows this same state; no proof-only root or temporary Process is created.
    // SAFETY: this callback is BSP-exclusive and `backend` is the unique mutable RuntimeTablePool
    // cursor supplied by the protected-boot owner for the duration of this synchronous callback.
    runtime::initialize_linux_runtime(unsafe { backend.as_mut() }).map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 persistent Linux runtime initialized\n");

    #[cfg(feature = "step29-qemu-proof")]
    {
        let process = runtime::with_linux_runtime(|state| state.process().id()).map_err(|_| ())?;
        step29_runtime::initialize(process, initrd).map_err(|_| ())?;
        serial.write_str("KERNAL/ARM64: Step 29 immutable initramfs root bound to Process\n");
    }

    // Keep the already-accepted ELF/leader construction path unchanged before adding the KMap owner.
    // KMap is not required for the initial image because that loader owns its existing frame-zeroing
    // path. It is needed only by later anonymous VM transactions, so delaying its installation avoids
    // perturbing the proven loader/leader transaction while still installing it before any EL0 mmap.
    // SAFETY: the same protected BSP quiescence owns the scheduler, runtime, frame pool and exact
    // construction-window backend for these synchronous, non-blocking transactions.
    let leader = unsafe {
        initial::load_and_publish(
            initrd,
            backend.as_mut(),
            &super::CPU_SCHEDULERS[0],
            super::SMOKE_WORKER_PRIORITY,
        )
    }
    .map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 initial Linux leader published PID=");
    serial.write_u64(leader.pid().get() as u64);
    serial.write_str(" TID=");
    serial.write_u64(leader.tid().get() as u64);
    serial.write_str("\n");

    // Retain one CPU0 KMap controller for every later anonymous VM transaction. Reconstructing a
    // controller per syscall would incorrectly forget a poisoned cleanup state and could make a
    // quarantined frame reusable. Installation remains inside the protected construction callback,
    // after the accepted loader/leader transaction and before the runtime can resume EL0.
    let root_table = runtime_ttbr1_root().ok_or(())?;
    // SAFETY: this protected callback is the IRQ-masked BSP/CPU0 owner, and `root_table` is the exact
    // already-active protected TTBR1 root published by protected boot for this construction window.
    unsafe { kmap::initialize(0, root_table) }.map_err(|_| ())?;
    // SAFETY: same BSP quiescence; this short borrow only reads the stable CPU-local window base and
    // cannot block or mutate the hierarchy.
    let kmap_base = unsafe { kmap::with_kmap(|controller| controller.base()) }.map_err(|_| ())?;
    serial.write_str("KERNAL/ARM64: Step 15 persistent KMap initialized base=");
    serial.write_hex_u64(kmap_base);
    serial.write_str("\n");
    Ok(())
}

fn install_unsupported_svc_fallback(serial: &Pl011) -> Result<(), ()> {
    STEP15_SVC_UART_BASE.store(serial.region.base, Ordering::Release);
    STEP15_SVC_UART_SIZE.store(serial.region.size, Ordering::Release);
    kernal_exceptions_aarch64::install_lower_el_aarch64_handler(step15_lower_el_fallback)
        .map_err(|_| ())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn activate_step30_scheduler_destination(
    destination: GlobalThreadId,
    expected_address_space: u64,
) {
    let activated = if expected_address_space == 0 {
        // Kernel/idle generations deliberately own no userspace root. Token zero is observation only
        // and must transition through the canonical AArch64 process-address-space deactivation owner.
        // SAFETY: scheduler callback runs in the same quiesced PE switch window as `activate_owner`.
        unsafe {
            kernal_process_aarch64::BoundProcessAddressSpace::<
                { runtime::STEP15_RUNTIME_VMAS },
            >::deactivate()
        }
        .map_err(|_| ())
    } else {
        runtime::with_linux_runtime(|state| {
            // SAFETY: the scheduler invokes this callback only after all scheduler/context borrows for
            // the exact selected generation ended and before CpuLocal/TLS/stack publication. Lower-EL
            // user access remains quiesced for the complete owner-controlled switch window.
            unsafe {
                state.activate_scheduler_destination_address_space(
                    destination,
                    expected_address_space,
                )
            }
            .map_err(|_| ())
        })
        .map_err(|_| ())
        .and_then(|result| result)
    };
    if activated.is_ok() {
        if let Some(serial) = step15_svc_serial() {
            serial.write_str("KERNAL/S30S selected cpu=");
            serial.write_u64(destination.cpu.0 as u64);
            serial.write_str(" slot=");
            serial.write_u64(destination.local.slot as u64);
            serial.write_str(" generation=");
            serial.write_u64(destination.local.generation as u64);
            serial.write_str(" token=");
            serial.write_hex_u64(expected_address_space);
            serial.write_str("\n");
        }
        return;
    }

    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 30 destination address-space activation failed cpu=");
        serial.write_u64(destination.cpu.0 as u64);
        serial.write_str(" slot=");
        serial.write_u64(destination.local.slot as u64);
        serial.write_str(" generation=");
        serial.write_u64(destination.local.generation as u64);
        serial.write_str(" token=");
        serial.write_hex_u64(expected_address_space);
        serial.write_str("\n");
    }

    // Scheduler selection is already committed when this callback runs. Returning after failed
    // Process/TTBR0 activation could resume a selected generation in the previous Process, so the
    // only safe containment is non-returning fail-closed execution on this IRQ-masked PE.
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn remote_wake_with_reschedule(
    target_scheduler: &'static kernal_scheduler_cpu::CpuSchedulerCell<
        { super::SCHEDULER_THREADS_PER_CPU },
        { super::REMOTE_WAKE_SLOTS },
    >,
    target: GlobalThreadId,
) -> Result<(), kernal_scheduler_cpu::Error> {
    // Publish the exact generation before interrupting its owner PE. GICv3 send_sgi1 performs the
    // required DSB ISHST so the mailbox publication is visible before the target observes the SGI.
    target_scheduler.remote_wake(target)?;
    let target_index = usize::from(target.cpu.0);
    let mpidr = super::CPU_MPIDRS
        .get(target_index)
        .ok_or(kernal_scheduler_cpu::Error::WrongOwner)?
        .load(Ordering::Acquire);
    let affinity = kernal_arch_aarch64::CpuAffinity::from_mpidr(mpidr);
    // SAFETY: the target generation belongs to the already-published target scheduler/PE. A failure
    // to notify after mailbox publication is an internal delivery invariant, never a userspace errno.
    unsafe {
        kernal_gicv3_aarch64::send_sgi1(kernal_gicv3_aarch64::RESCHEDULE_SGI_DEFAULT, affinity)
    }
    .map_err(|_| kernal_scheduler_cpu::Error::Invariant)
}

fn wake_wait_exit_batch(
    current_cpu: usize,
    scheduler: &'static kernal_scheduler_cpu::CpuSchedulerCell<
        { super::SCHEDULER_THREADS_PER_CPU },
        { super::REMOTE_WAKE_SLOTS },
    >,
    wakes: Option<kernal_linux_wait::WaitWakeBatch<{ runtime::STEP15_RUNTIME_PROCESSES }>>,
) -> Result<(), ()> {
    let Some(wakes) = wakes else {
        return Ok(());
    };
    for target in wakes.iter() {
        let target_index = usize::from(target.cpu.0);
        let target_scheduler = super::CPU_SCHEDULERS.get(target_index).ok_or(())?;
        if target_index == current_cpu {
            // SAFETY: the exact generation was returned by the canonical WaitTable publication
            // transaction and this finalizer retains the local scheduler owner/quiescence window.
            unsafe { scheduler.bootstrap_wake_local_exact(target) }.map_err(|_| ())?;
        } else {
            remote_wake_with_reschedule(target_scheduler, target).map_err(|_| ())?;
        }
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) unsafe fn drain_step30_job_control_from_irq(
    current_cpu: usize,
) -> Result<kernal_scheduler_smp::JobControlDrainReport, ()> {
    // SAFETY: delegated first-level owner-IRQ contract from the architecture exception handler.
    unsafe { step30_child_exit::drain_process_job_control_from_irq(current_cpu) }
}

pub(super) fn service_step30_job_control_completions(current_cpu: usize) -> Result<bool, ()> {
    step30_child_exit::service_process_job_control_completions(current_cpu)
}

pub(super) fn finalize_step30_pending_exit_after_resume(current_cpu: usize) -> Result<bool, ()> {
    let scheduler = super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    let scheduler_owner = scheduler.owner().map_err(|_| ())?;
    if usize::from(scheduler_owner.0) != current_cpu {
        return Err(());
    }
    let pending = runtime::with_linux_runtime(|state| state.pending_thread_exit(scheduler_owner))
        .map_err(|_| ())?;
    let Some(exited) = pending else {
        return Ok(false);
    };
    if exited.cpu != scheduler_owner {
        return Err(());
    }
    // SAFETY: the resumed synchronous SVC owns this PE's IRQ-masked scheduler window.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| ())?;
    if usize::from(current.cpu.0) != current_cpu {
        return Err(());
    }

    // SAFETY: `exited` is the exact pending lifecycle generation and `current` the exact resumed
    // reaper. The one-shot proof is consumed exactly once by the leader/pthread owner split below.
    let (retired_stack, proof) = unsafe {
        scheduler.bootstrap_reap_exited_after_teardown_with_proof(exited.local, current.local)
    }
    .map_err(|_| ())?;

    let finalized = runtime::with_linux_runtime(move |state| {
        let process_id = state.pending_exit_process(exited)?;
        let lifecycle = state.finalize_pending_thread_exit(
            exited,
            |ticket, exits, process, objects, bindings, identities| {
                let linux_pid = identities.bound_pid(process)?;
                let linux_tid =
                    identities.bound_tid_for_scheduler_thread(process, proof.thread())?;
                let (completion, cause) = if linux_tid == linux_pid {
                    let thread_handle = bindings
                        .authority_for_reaped_proof(objects, process.id(), &proof)
                        .map_err(kernal_process::Error::ThreadBinding)?;
                    let finalized = kernal_linux_exit_lifecycle::finalize_reaped_thread_with_cause(
                        ticket,
                        exits,
                        process,
                        objects,
                        bindings,
                        proof,
                        thread_handle,
                    )?;
                    (finalized.completion(), finalized.cause())
                } else {
                    let finalized =
                        kernal_linux_exit_lifecycle::finalize_reaped_thread_with_identity(
                            ticket, exits, process, objects, bindings, identities, proof,
                        )?;
                    (finalized.completion(), finalized.cause())
                };

                if matches!(
                    completion,
                    kernal_linux_exit_lifecycle::Completion::ProcessExited { .. }
                ) {
                    identities.retire_process(process)?;
                }
                Ok((completion, cause))
            },
        )?;
        Ok::<_, runtime::Error>((process_id, lifecycle))
    });
    let (process_id, (completion, cause)) = match finalized {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => {
            let _ = retired_stack;
            return Err(());
        }
    };
    let wakes = step30_child_exit::complete_process_exit_wait_after_lifecycle(
        process_id,
        completion,
        cause,
        current_cpu,
    )?;

    // Zombie publication or auto-reap consumed every matching committed waiter. Deliver those exact
    // generations before any unrelated fallible reclamation step can abort this post-commit path.
    wake_wait_exit_batch(current_cpu, scheduler, wakes)?;

    // SAFETY: scheduler reap proof was consumed by successful lifecycle finalization above.
    unsafe { kernal_core_aarch64::reclaim_reaped_clone_core_stack(retired_stack) }
        .map_err(|_| ())?;
    Ok(true)
}

pub(super) fn drain_step30_pending_exits_before_wait(current_cpu: usize) -> Result<(), ()> {
    let scheduler = super::CPU_SCHEDULERS.get(current_cpu).ok_or(())?;
    let scheduler_owner = scheduler.owner().map_err(|_| ())?;
    if usize::from(scheduler_owner.0) != current_cpu {
        return Err(());
    }

    for _ in 0..runtime::STEP15_RUNTIME_THREADS {
        if !finalize_step30_pending_exit_after_resume(current_cpu)? {
            return Ok(());
        }
    }

    let pending = runtime::with_linux_runtime(|state| state.pending_thread_exit(scheduler_owner))
        .map_err(|_| ())?;
    if pending.is_some() {
        return Err(());
    }
    Ok(())
}

fn step15_svc_serial() -> Option<Pl011> {
    let base = STEP15_SVC_UART_BASE.load(Ordering::Acquire);
    let size = STEP15_SVC_UART_SIZE.load(Ordering::Acquire);
    if base == 0 || size == 0 {
        return None;
    }
    Some(Pl011 {
        region: MmioRegion { base, size },
    })
}

fn arm_step30_post_fork_reschedule_trace() {
    STEP30_POST_FORK_RESCHEDULE_TRACE_PENDING.store(true, Ordering::Release);
}

pub(super) fn step30_post_fork_reschedule_trace_pending() -> bool {
    STEP30_POST_FORK_RESCHEDULE_TRACE_PENDING.load(Ordering::Acquire)
}

pub(super) fn take_step30_post_fork_reschedule_trace() -> bool {
    STEP30_POST_FORK_RESCHEDULE_TRACE_PENDING.swap(false, Ordering::AcqRel)
}

pub(super) fn trace_step30_post_fork_timer_irq() {
    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/S30I timer\n");
    }
}

pub(super) fn trace_step30_post_fork_non_irq_fatal(
    vector: u64,
    esr_el1: u64,
    far_el1: u64,
    elr_el1: u64,
    spsr_el1: u64,
    x20: u64,
    link_register: u64,
) {
    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/S30T non-irq-fatal kind=");
        serial.write_u64(vector & 0x3);
        serial.write_str(" source=");
        serial.write_u64(vector >> 2);
        serial.write_str(" esr=");
        serial.write_hex_u64(esr_el1);
        serial.write_str(" far=");
        serial.write_hex_u64(far_el1);
        serial.write_str(" elr=");
        serial.write_hex_u64(elr_el1);
        serial.write_str(" spsr=");
        serial.write_hex_u64(spsr_el1);
        serial.write_str(" x20=");
        serial.write_hex_u64(x20);
        serial.write_str(" lr=");
        serial.write_hex_u64(link_register);
        if elr_el1 >= 0xffff_ffff_8020_0000 && elr_el1 < 0xffff_ffff_8820_0000 && elr_el1 & 0x3 == 0
        {
            // SAFETY: this diagnostic runs only for the bounded Step-30 post-fork fault window.
            // The accepted AArch64 kernel is linked in this executable TTBR1 range and ELR is
            // instruction-aligned, so reading the faulting instruction cannot dereference FAR.
            let instruction = unsafe { core::ptr::read_volatile(elr_el1 as *const u32) };
            serial.write_str(" insn=");
            serial.write_hex_u64(u64::from(instruction));
        }
        serial.write_str("\n");
    }
}

pub(super) fn trace_step30_post_fork_pre_reschedule() {
    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/S30I pre-reschedule\n");
    }
}

pub(super) fn trace_step30_post_fork_reschedule_current(cpu: u64, slot: u64, generation: u64) {
    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/S30R current cpu=");
        serial.write_u64(cpu);
        serial.write_str(" slot=");
        serial.write_u64(slot);
        serial.write_str(" generation=");
        serial.write_u64(generation);
        serial.write_str("\n");
    }
}

pub(super) fn trace_step30_post_fork_reschedule_return(slot: u64, generation: u64) {
    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/S30R return slot=");
        serial.write_u64(slot);
        serial.write_str(" generation=");
        serial.write_u64(generation);
        serial.write_str("\n");
    }
}

pub(super) fn trace_step30_post_fork_reschedule_error() {
    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/S30R error\n");
    }
}

pub(super) fn deliver_step30_signal_on_return(frame: &mut ExceptionFrame) -> Result<(), ()> {
    if frame.kind() == kernal_exceptions_aarch64::ExceptionKind::Irq {
        let generation = core::num::NonZeroU64::new(
            kernal_process_aarch64::current_user_switch_generation().ok_or(())?,
        )
        .ok_or(())?;
        // SAFETY: the architecture caller invokes this bridge only after EOI/exit_irq and the
        // scheduler safe point. A legitimate switch-away/switch-back may advance the TTBR0 switch
        // generation while this exact lower-EL IRQ frame remains owned by the resumed generation.
        // Refresh only that observation before the canonical signal owner performs its ordinary
        // exact-current validation. Synchronous SVC frames retain their original entry generation.
        unsafe { frame.rebind_entry_switch_generation(generation) };
    }
    signal_delivery::deliver_on_return(frame)
}

extern "C" fn step15_lower_el_fallback(frame: &mut ExceptionFrame) -> bool {
    let current_cpu = super::current_cpu_index();
    let mut drained_empty = false;
    for _ in 0..runtime::STEP15_RUNTIME_THREADS {
        match finalize_step30_pending_exit_after_resume(current_cpu) {
            Ok(true) => {}
            Ok(false) => {
                drained_empty = true;
                break;
            }
            Err(()) => return false,
        }
    }
    if !drained_empty {
        let Some(scheduler) = super::CPU_SCHEDULERS.get(current_cpu) else {
            return false;
        };
        let scheduler_owner = match scheduler.owner() {
            Ok(owner) if usize::from(owner.0) == current_cpu => owner,
            Ok(_) | Err(_) => return false,
        };
        match runtime::with_linux_runtime(|state| state.pending_thread_exit(scheduler_owner)) {
            Ok(None) => {}
            Ok(Some(_)) | Err(_) => return false,
        }
    }

    let mut signal_frame_committed = false;
    if !step15_lower_el_dispatch(frame, &mut signal_frame_committed) {
        return false;
    }
    if signal_frame_committed {
        return true;
    }

    if frame.x[8] == 135 {
        let current = super::CPU_SCHEDULERS
            .get(current_cpu)
            .and_then(|scheduler| {
                // SAFETY: this lower-EL synchronous SVC still owns the current PE's IRQ-masked
                // scheduler window after the successful syscall dispatch and before EL0 return.
                unsafe { scheduler.bootstrap_current_global_thread() }.ok()
            });
        let current_switch_generation = kernal_process_aarch64::current_user_switch_generation();
        if let (Some(serial), Some(current)) = (step15_svc_serial(), current) {
            serial.write_str("KERNAL/S30T enter cpu=");
            serial.write_u64(u64::from(current.cpu.0));
            serial.write_str(" slot=");
            serial.write_u64(u64::from(current.local.slot));
            serial.write_str(" generation=");
            serial.write_u64(u64::from(current.local.generation));
            serial.write_str(" entry_switch_generation=");
            serial.write_u64(frame.entry_switch_generation());
            serial.write_str(" current_user_switch_generation=");
            match current_switch_generation {
                Some(generation) => serial.write_u64(generation),
                None => serial.write_str("none"),
            }
            serial.write_str("\n");
        }

        let result = deliver_step30_signal_on_return(frame);
        if let (Some(serial), Some(current)) = (step15_svc_serial(), current) {
            serial.write_str("KERNAL/S30T ");
            serial.write_str(if result.is_ok() { "ok" } else { "err" });
            serial.write_str(" cpu=");
            serial.write_u64(u64::from(current.cpu.0));
            serial.write_str(" slot=");
            serial.write_u64(u64::from(current.local.slot));
            serial.write_str(" generation=");
            serial.write_u64(u64::from(current.local.generation));
            serial.write_str(" entry_switch_generation=");
            serial.write_u64(frame.entry_switch_generation());
            serial.write_str(" current_user_switch_generation=");
            match current_switch_generation {
                Some(generation) => serial.write_u64(generation),
                None => serial.write_str("none"),
            }
            serial.write_str("\n");
        }
        return result.is_ok();
    }

    deliver_step30_signal_on_return(frame).is_ok()
}

fn step15_lower_el_dispatch(frame: &mut ExceptionFrame, signal_frame_committed: &mut bool) -> bool {
    let Some(LowerElAarch64Synchronous::SupervisorCall { immediate: 0 }) =
        frame.lower_el_aarch64_synchronous()
    else {
        return false;
    };

    let mut args = [0u64; MAX_SYSCALL_ARGS];
    args.copy_from_slice(&frame.x[..MAX_SYSCALL_ARGS]);
    let request = SyscallRequest::new(frame.x[8], args);

    #[cfg(feature = "step29-qemu-proof")]
    match step29_fd::handle(request, frame) {
        Ok(step29_fd::HandleOutcome::Handled) => {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 29 path/fd syscall nr=");
                serial.write_u64(request.number);
                serial.write_str(" result=");
                serial.write_hex_u64(frame.x[0]);
                serial.write_str("\n");
            }
            return true;
        }
        Ok(step29_fd::HandleOutcome::SignalFrameCommitted) => {
            *signal_frame_committed = true;
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 29 path/fd committed signal frame nr=");
                serial.write_u64(request.number);
                serial.write_str("\n");
            }
            return true;
        }
        Ok(step29_fd::HandleOutcome::NotHandled) => {}
        Err(()) => {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 29 path/fd invariant failed nr=");
                serial.write_u64(request.number);
                serial.write_str("\n");
            }
            return false;
        }
    }

    #[cfg(feature = "step29-qemu-proof")]
    match step29_fd_io::handle(request, frame) {
        Ok(true) => {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 29 fd-io syscall nr=");
                serial.write_u64(request.number);
                serial.write_str(" result=");
                serial.write_hex_u64(frame.x[0]);
                serial.write_str("\n");
            }
            return true;
        }
        Ok(false) => {}
        Err(()) => {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 29 fd-io invariant failed nr=");
                serial.write_u64(request.number);
                serial.write_str("\n");
            }
            return false;
        }
    }

    if request.number == 64 {
        if write::handle(frame) {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 15 write result=");
                serial.write_hex_u64(frame.x[0]);
                serial.write_str("\n");
            }
            return true;
        }
        if let Some(serial) = step15_svc_serial() {
            serial.write_str("KERNAL/ARM64: Step 15 write invariant failed\n");
        }
        return false;
    }

    if request.number == 214 && request.args[0] == 0 {
        let current_break = runtime::with_linux_runtime(|runtime| {
            let process_id = runtime.process().id();
            let (vm, _, _, _) = runtime.minimum_vm_parts();
            vm.current_break(process_id)
        });
        if let Ok(Ok(current_break)) = current_break {
            frame.x[0] = current_break;
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 15 brk(0) query -> ");
                serial.write_hex_u64(current_break);
                serial.write_str("\n");
            }
            return true;
        }
        if let Some(serial) = step15_svc_serial() {
            serial.write_str("KERNAL/ARM64: Step 15 brk(0) query failed\n");
        }
        return false;
    }

    if request.number == 214 {
        let call = MinimumRuntimeCall::Brk {
            address: request.args[0],
        };
        match live_vm::handle(call) {
            Ok(Ok(result)) => {
                frame.x[0] = result;
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 brk -> ");
                    serial.write_hex_u64(result);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(Err(_)) | Err(()) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 brk invariant failed\n");
                }
                return false;
            }
        }
    }

    if request.number == 226 {
        match step28_mprotect::handle(request.args[0], request.args[1], request.args[2]) {
            Ok(Ok(result)) => {
                frame.x[0] = result;
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 28 mprotect(PROT_READ) result=");
                    serial.write_hex_u64(result);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(Err(errno)) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 28 mprotect errno=");
                    serial.write_u64(errno.get() as u64);
                    serial.write_str(" prot=");
                    serial.write_hex_u64(request.args[2]);
                    serial.write_str("\n");
                }
                return true;
            }
            Err(()) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 28 mprotect invariant failed\n");
                }
                return false;
            }
        }
    }

    if request.number == 113 {
        match clock_gettime(request.args[0], request.args[1]) {
            Ok(result) => {
                frame.x[0] = result.as_u64_bits();
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 clock_gettime completed clock=");
                    serial.write_u64(request.args[0]);
                    serial.write_str("\n");
                }
                return true;
            }
            Err(ClockGettimeError::Errno(errno)) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 clock_gettime errno=");
                    serial.write_u64(errno.get() as u64);
                    serial.write_str("\n");
                }
                return true;
            }
            Err(_) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 clock_gettime invariant failed\n");
                }
                return false;
            }
        }
    }

    if request.number == 222 {
        let call = MinimumRuntimeCall::Mmap {
            address: request.args[0],
            length: request.args[1],
            protection: request.args[2],
            flags: request.args[3],
            fd: request.args[4],
            offset: request.args[5],
        };
        match live_vm::handle(call) {
            Ok(Ok(address)) => {
                frame.x[0] = address;
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 mmap -> ");
                    serial.write_hex_u64(address);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(Err(kernal_linux_vm::Error::Linux(errno))) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 mmap errno=");
                    serial.write_u64(errno.get() as u64);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(Err(_)) | Err(()) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 mmap invariant failed\n");
                }
                return false;
            }
        }
    }

    if request.number == 215 {
        let call = MinimumRuntimeCall::Munmap {
            address: request.args[0],
            length: request.args[1],
        };
        match live_vm::handle(call) {
            Ok(Ok(result)) => {
                frame.x[0] = result;
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 munmap result=");
                    serial.write_hex_u64(result);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(Err(kernal_linux_vm::Error::Linux(errno))) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 munmap errno=");
                    serial.write_u64(errno.get() as u64);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(Err(_)) | Err(()) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 munmap invariant failed\n");
                }
                return false;
            }
        }
    }

    if request.number == 93 {
        return exit::handle_thread_exit(request.args[0]);
    }

    if request.number == 94 {
        return exit::handle_group_exit(request.args[0]);
    }

    if request.number == 98 {
        let call = MinimumRuntimeCall::Futex {
            user_address: request.args[0],
            operation: request.args[1],
            value: request.args[2],
            timeout_or_val2: request.args[3],
            user_address2: request.args[4],
            value3: request.args[5],
        };

        let current_cpu = super::current_cpu_index();
        let Some(scheduler) = super::CPU_SCHEDULERS.get(current_cpu) else {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 15 futex scheduler owner unavailable\n");
            }
            return false;
        };

        // Resolve the exact currently-running scheduler generation before taking any Process/AS
        // observation. A raw PID, slot index, or address-space token is never sufficient authority.
        // SAFETY: lower-EL synchronous SVC owns this PE's IRQ-masked scheduler window.
        let current = match unsafe { scheduler.bootstrap_current_global_thread() } {
            Ok(current) if usize::from(current.cpu.0) == current_cpu => current,
            Ok(_) | Err(_) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str(
                        "KERNAL/ARM64: Step 30 futex exact current generation unavailable\n",
                    );
                }
                return false;
            }
        };

        // Extract only stable raw handles for the exact generation-bound Process owner. The mutable
        // runtime borrow ends before FUTEX_WAIT may suspend this kernel stack. Slot retention is
        // guaranteed by the live thread's canonical LinuxIdentity/process lifecycle binding.
        let owners = runtime::with_linux_runtime(|state| {
            let (process, address_space, _) = state.process_parts_for_scheduler_thread(current)?;
            Ok::<_, runtime::Error>((NonNull::from(process), NonNull::from(address_space)))
        });
        let Ok(Ok((process, address_space))) = owners else {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 30 futex exact process owner unavailable\n");
            }
            return false;
        };
        let frame_ptr = NonNull::from(&mut *frame);

        // SAFETY: the lower-EL SVC owns this PE's IRQ-masked scheduler window and the current
        // Process/TTBR0 binding. `process`, `address_space` and `frame_ptr` name stable owners, but no
        // Rust Process/address-space borrow survives the call. Local consumed waiters are delivered
        // synchronously through the current owner; foreign identities use the target owner's existing
        // remote-wake mailbox. Delivery failure is propagated as a fatal futex invariant.
        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        let dispatched = unsafe {
            kernal_linux_futex_trap_aarch64::dispatch_private_futex_raw_with_destination_address_space_signal_aware(
                process,
                address_space,
                frame_ptr,
                scheduler,
                futex::futexes(),
                call,
                activate_step30_scheduler_destination,
                |target| {
                    let target_index = usize::from(target.cpu.0);
                    let target_scheduler = super::CPU_SCHEDULERS
                        .get(target_index)
                        .ok_or(kernal_scheduler_cpu::Error::WrongOwner)?;
                    if target_index == current_cpu {
                        // SAFETY: this SVC retains the exact owner/quiescence window and `target`
                        // came from the generation-bound canonical futex waiter registry.
                        unsafe { scheduler.bootstrap_wake_local_exact(target) }
                    } else {
                        remote_wake_with_reschedule(target_scheduler, target)
                    }
                },
            )
        };
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        let dispatched = unsafe {
            kernal_linux_futex_trap_aarch64::dispatch_private_futex_raw_signal_aware(
                process,
                address_space,
                frame_ptr,
                scheduler,
                futex::futexes(),
                call,
                |target| {
                    let target_index = usize::from(target.cpu.0);
                    let target_scheduler = super::CPU_SCHEDULERS
                        .get(target_index)
                        .ok_or(kernal_scheduler_cpu::Error::WrongOwner)?;
                    if target_index == current_cpu {
                        unsafe { scheduler.bootstrap_wake_local_exact(target) }
                    } else {
                        remote_wake_with_reschedule(target_scheduler, target)
                    }
                },
            )
        };

        match dispatched {
            Ok(kernal_linux_futex_trap_aarch64::DispatchOutcome::Complete) => {
                if request.args[1] == STEP15_FUTEX_WAIT_PRIVATE
                    && finalize_step30_pending_exit_after_resume(current_cpu).is_err()
                {
                    if let Some(serial) = step15_svc_serial() {
                        serial.write_str(
                            "KERNAL/ARM64: Step 30 FUTEX_WAIT pending-exit finalize failed\n",
                        );
                    }
                    return false;
                }

                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 futex result=");
                    serial.write_hex_u64(frame.x[0]);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(kernal_linux_futex_trap_aarch64::DispatchOutcome::SignalInterrupted(
                interrupted,
            )) => {
                if interrupted != current || request.args[1] != STEP15_FUTEX_WAIT_PRIVATE {
                    if let Some(serial) = step15_svc_serial() {
                        serial.write_str(
                            "KERNAL/ARM64: Step 30 futex signal interruption identity mismatch\n",
                        );
                    }
                    return false;
                }

                let resumed = match unsafe { scheduler.bootstrap_current_global_thread() } {
                    Ok(resumed)
                        if resumed == interrupted && usize::from(resumed.cpu.0) == current_cpu =>
                    {
                        resumed
                    }
                    Ok(_) | Err(_) => {
                        if let Some(serial) = step15_svc_serial() {
                            serial.write_str(
                                "KERNAL/ARM64: Step 30 futex signal resume generation mismatch\n",
                            );
                        }
                        return false;
                    }
                };

                frame.x[..MAX_SYSCALL_ARGS].copy_from_slice(&request.args);

                match signal_delivery::deliver_interrupted_futex(frame, resumed) {
                    Ok(signal_delivery::InterruptedFutexDelivery::Restarted) => {
                        if let Some(serial) = step15_svc_serial() {
                            serial.write_str(
                                "KERNAL/ARM64: Step 30 futex signal interruption restarted\n",
                            );
                        }
                        return true;
                    }
                    Ok(signal_delivery::InterruptedFutexDelivery::SignalFrameCommitted) => {
                        *signal_frame_committed = true;
                        if let Some(serial) = step15_svc_serial() {
                            serial.write_str(
                                "KERNAL/ARM64: Step 30 futex signal handler frame committed\n",
                            );
                        }
                        return true;
                    }
                    Err(()) => {
                        if let Some(serial) = step15_svc_serial() {
                            serial.write_str(
                                "KERNAL/ARM64: Step 30 futex signal resume invariant failed\n",
                            );
                        }
                        return false;
                    }
                }
            }
            Err(_) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 futex invariant failed\n");
                }
                return false;
            }
        }
    }

    if request.number == 220 {
        let scheduler = &super::CPU_SCHEDULERS[0];
        // SAFETY: this lower-EL synchronous SVC owns CPU0's IRQ-masked scheduler window.
        let parent_thread = match unsafe { scheduler.bootstrap_current_global_thread() } {
            Ok(current) if current.cpu.0 == 0 => current,
            Ok(_) | Err(_) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 30 clone parent generation unavailable\n");
                }
                return false;
            }
        };

        match kernal_linux_clone::ProcessClonePlan::validate(
            request.args[0],
            request.args[1],
            request.args[2],
            request.args[3],
            request.args[4],
        ) {
            Ok(plan) => match plan.kind() {
                kernal_linux_clone::ProcessCloneKind::Fork => {
                    // SAFETY: this synchronous SVC retains CPU0's exact IRQ-masked scheduler owner
                    // window. `parent_thread` is the exact current generation, and the private fork
                    // helper performs the complete Process/AS/scheduler/identity transaction before
                    // returning the sole parent-visible PID receipt.
                    let published = match unsafe {
                        live_vm::fork_process(
                            frame,
                            parent_thread,
                            plan,
                            scheduler,
                            super::SMOKE_WORKER_PRIORITY,
                        )
                    } {
                        Ok(published) => published,
                        Err(()) => {
                            if let Some(serial) = step15_svc_serial() {
                                serial.write_str("KERNAL/ARM64: Step 30 fork transaction failed\n");
                            }
                            return false;
                        }
                    };
                    frame.x[0] = u64::from(published.child_pid().get());
                    arm_step30_post_fork_reschedule_trace();
                    if let Some(serial) = step15_svc_serial() {
                        serial.write_str("KERNAL/ARM64: Step 30 fork parent result=");
                        serial.write_hex_u64(frame.x[0]);
                        serial.write_str("\n");
                    }
                    return true;
                }
                kernal_linux_clone::ProcessCloneKind::Vfork => {
                    // The private-fork transaction owns a distinct AddressSpace and never suspends the
                    // parent. Reusing it for vfork would violate the owner model, so retain the pinned
                    // fail-closed Step-30 policy until an explicit shared-AS vfork transaction exists.
                    if let Some(serial) = step15_svc_serial() {
                        serial.write_str("KERNAL/ARM64: Step 30 vfork remains unsupported\n");
                    }
                    return false;
                }
            },
            Err(kernal_linux_clone::Error::UnsupportedFlags) => {}
            Err(
                kernal_linux_clone::Error::InvalidChildStack
                | kernal_linux_clone::Error::InvalidParentTid
                | kernal_linux_clone::Error::InvalidTls
                | kernal_linux_clone::Error::InvalidChildTid,
            ) => {
                frame.x[0] = SyscallReturn::error(kernal_linux_abi::Errno::EINVAL).as_u64_bits();
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 30 process clone arguments invalid\n");
                }
                return true;
            }
        }

        let call = MinimumRuntimeCall::Clone {
            flags: request.args[0],
            child_stack: request.args[1],
            parent_tid: request.args[2],
            tls: request.args[3],
            child_tid: request.args[4],
        };
        let dispatched = runtime::with_linux_runtime(|state| {
            let (process, address_space, objects, bindings, identities, exits) =
                state.initial_leader_parts();
            // SAFETY: a lower-EL synchronous SVC runs inside CPU0's exception-owned scheduler
            // window with the current Process/TTBR0 binding unchanged. The runtime borrow above is
            // exclusive for exactly this synchronous transaction and ends before returning to EL0;
            // the canonical Core transaction owns staging, Process/TID authority and rollback.
            unsafe {
                kernal_core_aarch64::dispatch_clone_with_core_stacks(
                    call,
                    frame,
                    process,
                    address_space,
                    objects,
                    bindings,
                    identities,
                    exits,
                    scheduler,
                    super::SMOKE_WORKER_PRIORITY,
                )
            }
        });

        match dispatched {
            Ok(Ok(())) => {
                let child_tid = match u32::try_from(frame.x[0]).ok().and_then(NonZeroU32::new) {
                    Some(tid) => tid,
                    None => {
                        if let Some(serial) = step15_svc_serial() {
                            serial.write_str("KERNAL/ARM64: Step 30 clone child TID invalid\n");
                        }
                        return false;
                    }
                };
                let signal_bound = runtime::with_linux_runtime(|state| {
                    state.inherit_same_process_thread_signal_mask(parent_thread, child_tid)
                });
                if !matches!(signal_bound, Ok(Ok(_))) {
                    // The clone is already Ready, but this SVC has not returned and the parent remains
                    // current. Fail closed before any scheduler boundary can expose a pthread lacking
                    // generation-bound SignalTable state.
                    if let Some(serial) = step15_svc_serial() {
                        serial.write_str("KERNAL/ARM64: Step 30 clone signal-mask bind failed\n");
                    }
                    return false;
                }
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 clone parent result=");
                    serial.write_hex_u64(frame.x[0]);
                    serial.write_str("\n");
                }
                return true;
            }
            Ok(Err(_)) | Err(_) => {
                if let Some(serial) = step15_svc_serial() {
                    serial.write_str("KERNAL/ARM64: Step 15 clone invariant failed\n");
                }
                return false;
            }
        }
    }

    if matches!(
        classify_step30_runtime(request),
        Some(Step30RuntimeCall::Wait4 { .. } | Step30RuntimeCall::WaitId { .. })
    ) {
        let current_cpu = super::current_cpu_index();
        if drain_step30_pending_exits_before_wait(current_cpu).is_err() {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 30 pre-Wait pending-exit drain failed\n");
            }
            return false;
        }
    }

    match step30_runtime::handle(request, frame) {
        Ok(step30_runtime::Outcome::Return(result)) => {
            frame.x[0] = result.as_u64_bits();
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 30 runtime syscall nr=");
                serial.write_u64(request.number);
                serial.write_str(" result=");
                serial.write_hex_u64(frame.x[0]);
                serial.write_str("\n");
            }
            return true;
        }
        Ok(step30_runtime::Outcome::NotHandled) => {}
        Ok(step30_runtime::Outcome::FrameCommitted) => {
            // The Step-30 owner already committed the authoritative frame. Never overwrite it via
            // the legacy x0 result path after exec or rt_sigreturn-style restoration.
            return true;
        }
        Ok(step30_runtime::Outcome::SignalFrameCommitted) => {
            // Blocking wait has already committed one exact signal handler frame. Suppress only the
            // ordinary return-hook pass for this same exception; no global/CPU sidecar state exists.
            *signal_frame_committed = true;
            return true;
        }
        Err(()) => {
            if let Some(serial) = step15_svc_serial() {
                serial.write_str("KERNAL/ARM64: Step 30 runtime invariant failed nr=");
                serial.write_u64(request.number);
                serial.write_str("\n");
            }
            return false;
        }
    }

    if is_classified_minimum_number(request.number) {
        if let Some(serial) = step15_svc_serial() {
            serial.write_str("KERNAL/ARM64: Step 15 first classified EL0 syscall nr=");
            serial.write_u64(request.number);
            serial.write_str(" x0=");
            serial.write_hex_u64(frame.x[0]);
            serial.write_str(" elr=");
            serial.write_hex_u64(frame.elr_el1);
            serial.write_str("\n");
        }
        return false;
    }

    let result = unsupported(request);
    frame.x[0] = result.as_u64_bits();
    if let Some(serial) = step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 15 unsupported EL0 syscall nr=");
        serial.write_u64(request.number);
        serial.write_str(" -> ENOSYS\n");
    }
    true
}

const fn is_classified_minimum_number(number: u64) -> bool {
    matches!(
        number,
        64 | 93 | 94 | 98 | 113 | 172 | 178 | 214 | 215 | 220 | 222 | 226
    )
}

pub(super) unsafe fn resume_initial_linux(serial: &Pl011) -> Result<(), ()> {
    let activation = runtime::with_linux_runtime(|runtime| {
        let (process, objects, space) = runtime.loader_parts();
        unsafe { space.activate_owner(process, objects) }
    })
    .map_err(|_| ())?;
    activation.map_err(|_| ())?;

    install_unsupported_svc_fallback(serial)?;
    serial.write_str("KERNAL/ARM64: Step 15 unsupported SVC fallback installed\n");
    serial.write_str("KERNAL/ARM64: Step 15 initial Linux TTBR0 activated\n");
    serial.write_str("KERNAL/ARM64: Step 15 yielding BSP idle to initial Linux leader\n");

    let _ = unsafe {
        super::CPU_SCHEDULERS[0]
            .bootstrap_yield_with_destination_address_space(activate_step30_scheduler_destination)
    }
    .map_err(|_| ())?;

    serial.write_str("KERNAL/ARM64: Step 15 Linux leader returned to BSP idle\n");
    unsafe { group_exit::finalize_after_resume(serial) }?;
    serial.write_str("KERNAL/ARM64: Step 15 Linux process fully finalized\n");
    Ok(())
}
