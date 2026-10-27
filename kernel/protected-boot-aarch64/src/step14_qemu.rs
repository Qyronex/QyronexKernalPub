// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::RuntimeTablePool;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::CapHandle;
use kernal_exceptions_aarch64::{ExceptionFrame, LowerElAarch64Synchronous};
use kernal_linux_abi::Errno;
use kernal_linux_bootstrap::{BootstrapContext, ExitScope, OutputFd};
use kernal_linux_bootstrap_aarch64::{TrapOutcome, dispatch_linux_syscall};
use kernal_linux_exit_lifecycle::{Completion, ExitCoordinator, finalize_reaped_thread};
use kernal_linux_identity::LinuxIdentityTable;
use kernal_linux_write_aarch64::{WriteError, write_from_user};
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_object::ObjectTable;
use kernal_paging::PAGE_SIZE;
use kernal_percpu::CpuIndex;
use kernal_process::{Personality, Process, ProcessState, ThreadObjectBindings};
use kernal_process_aarch64::BoundProcessAddressSpace;
use kernal_scheduler::{Error as SchedulerError, RunQueue, ThreadId, ThreadState};
use kernal_scheduler_smp::{GlobalThreadId, ReapedThreadProof};
use kernal_user_elf::LoadPolicy;
use kernal_user_elf_aarch64::required_pages;
use kernal_user_elf_runtime_aarch64::{load_aarch64_elf, plan_aarch64_elf};

const MAIN_USER_ELF: &[u8] = include_bytes!(env!("KERNAL_STEP14_USER_ELF"));
const EXIT_USER_ELF: &[u8] = include_bytes!(env!("KERNAL_STEP14_EXIT_USER_ELF"));

const QEMU_RAM_BYTES: u64 = 512 * 1024 * 1024;
const RAM_END: u64 = crate::QEMU_VIRT_RAM_BASE + QEMU_RAM_BYTES;
const MAX_SEGMENTS: usize = 8;
const PROCESS_CAPS: usize = 8;
const OBJECTS: usize = 8;
const VMAS: usize = 32;
const BINDINGS: usize = 1;
const SCHED_THREADS: usize = 1;
const RESERVED_RANGES: usize = 4;
const MAX_FRAMES: usize = 24;
const CPU0: CpuIndex = CpuIndex(0);
const THREAD_PRIORITY: u8 = 20;
const PSTATE_PAN_BIT: u64 = 1 << 22;

// Step 12 owns [RAM_END-40p, RAM_END-16p). Give the two Step-14 unchanged Linux images disjoint
// 24-page pools below it, with an eight-page gap before Step 12. Old proof roots are inactive before
// either pool is touched, and the two Step-14 runs never alias each other's backing frames.
const MAIN_POOL_START: u64 = RAM_END - (96 * PAGE_SIZE);
const EXIT_POOL_START: u64 = RAM_END - (72 * PAGE_SIZE);
const STEP14_POOL_END: u64 = RAM_END - (48 * PAGE_SIZE);
const STEP12_POOL_START: u64 = RAM_END - (40 * PAGE_SIZE);

const MAIN_EXPECTED_SVCS: u8 = 8;
const EXIT_EXPECTED_SVCS: u8 = 1;
const STDOUT_BYTES: u64 = b"step14-linux: stdout write ok\n".len() as u64;
const STDERR_BYTES: u64 = b"step14-linux: stderr write ok\n".len() as u64;

struct ActiveProofContext {
    process: Process<PROCESS_CAPS>,
    space: BoundProcessAddressSpace<VMAS>,
    objects: ObjectTable<OBJECTS>,
    scheduler: RunQueue<SCHED_THREADS>,
    bindings: ThreadObjectBindings<BINDINGS>,
    identities: LinuxIdentityTable<2, 2>,
    exits: ExitCoordinator<2>,
    thread_local: ThreadId,
    thread_handle: CapHandle,
    pid: NonZeroU32,
    tid: NonZeroU32,
    expected_scope: ExitScope,
    expected_svcs: u8,
    svc_count: u8,
    stdout_calls: u8,
    stderr_calls: u8,
    stdout_bytes: u64,
    stderr_bytes: u64,
    exit_complete: bool,
}

struct ActiveProofCell {
    state: AtomicU8,
    storage: UnsafeCell<MaybeUninit<ActiveProofContext>>,
}

// SAFETY: every safe mutable access takes exclusive ownership through an atomic state transition.
// The IRQ-masked BSP publishes one context before EL0 entry; each synchronous lower-EL invocation
// borrows it through ACTIVE -> BORROWED -> ACTIVE, and the BSP moves it out only through
// ACTIVE -> TAKING after the handler has redirected execution to the high kernel resume address.
unsafe impl Sync for ActiveProofCell {}

impl ActiveProofCell {
    const EMPTY: u8 = 0;
    const INITIALIZING: u8 = 1;
    const ACTIVE: u8 = 2;
    const BORROWED: u8 = 3;
    const TAKING: u8 = 4;

    const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::EMPTY),
            storage: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&'static self, context: ActiveProofContext) -> Result<(), ()> {
        self.state
            .compare_exchange(
                Self::EMPTY,
                Self::INITIALIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ())?;
        // SAFETY: EMPTY -> INITIALIZING grants this caller exclusive initialization ownership.
        unsafe { (*self.storage.get()).write(context) };
        self.state.store(Self::ACTIVE, Ordering::Release);
        Ok(())
    }

    fn with_active_mut<R>(
        &'static self,
        operation: impl FnOnce(&mut ActiveProofContext) -> R,
    ) -> Option<R> {
        if self
            .state
            .compare_exchange(
                Self::ACTIVE,
                Self::BORROWED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        // SAFETY: ACTIVE -> BORROWED gives this invocation exclusive mutable ownership until the
        // operation returns and ACTIVE is republished below.
        let context = unsafe { (&mut *self.storage.get()).assume_init_mut() };
        let result = operation(context);
        self.state.store(Self::ACTIVE, Ordering::Release);
        Some(result)
    }

    fn take(&'static self) -> Result<ActiveProofContext, ()> {
        self.state
            .compare_exchange(
                Self::ACTIVE,
                Self::TAKING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ())?;
        // SAFETY: ACTIVE -> TAKING gives the BSP exclusive ownership and the slot is initialized.
        // `read` moves the value out; the slot is not dropped again before a later publish replaces it.
        let context = unsafe { self.storage.get().read().assume_init() };
        self.state.store(Self::EMPTY, Ordering::Release);
        Ok(context)
    }
}

static ACTIVE_PROOF: ActiveProofCell = ActiveProofCell::new();

#[derive(Clone, Copy)]
struct ProofReport {
    pid: NonZeroU32,
    tid: NonZeroU32,
    svc_count: u8,
    stdout_calls: u8,
    stderr_calls: u8,
    stdout_bytes: u64,
    stderr_bytes: u64,
}

struct ProofBootstrapContext<'a> {
    pid: NonZeroU32,
    tid: NonZeroU32,
    stdout_calls: &'a mut u8,
    stderr_calls: &'a mut u8,
    stdout_bytes: &'a mut u64,
    stderr_bytes: &'a mut u64,
}

impl BootstrapContext for ProofBootstrapContext<'_> {
    fn write(&mut self, fd: OutputFd, user_buffer: u64, count: u64) -> Result<u64, Errno> {
        let serial = crate::Serial::new(crate::boot_state().mmio_aliases[0].virtual_region);
        let written = match write_from_user(user_buffer, count, |bytes| {
            // Preserve the Linux byte stream exactly. `Serial::write_str` inserts CR before LF and is
            // therefore intentionally not used for userspace output.
            for byte in bytes {
                serial.write_byte(*byte);
            }
        }) {
            Ok(written) => written,
            Err(WriteError::Errno(errno)) => return Err(errno),
            Err(WriteError::UserAccessInvariant(_)) => crate::fatal_silent(),
        };

        match fd {
            OutputFd::Stdout => {
                *self.stdout_calls = (*self.stdout_calls)
                    .checked_add(1)
                    .unwrap_or_else(|| crate::fatal_silent());
                *self.stdout_bytes = self
                    .stdout_bytes
                    .checked_add(written)
                    .unwrap_or_else(|| crate::fatal_silent());
            }
            OutputFd::Stderr => {
                *self.stderr_calls = (*self.stderr_calls)
                    .checked_add(1)
                    .unwrap_or_else(|| crate::fatal_silent());
                *self.stderr_bytes = self
                    .stderr_bytes
                    .checked_add(written)
                    .unwrap_or_else(|| crate::fatal_silent());
            }
        }
        Ok(written)
    }

    fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    fn tid(&self) -> NonZeroU32 {
        self.tid
    }
}

pub fn run(serial: &crate::Serial, backend: &mut RuntimeTablePool) {
    if kernal_arch_aarch64::current_exception_level() != 1 || !kernal_arch_aarch64::irqs_masked() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 Linux bootstrap proof requires IRQ-masked EL1\n",
        );
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal(serial, "KERNAL/ARM64: Step 14 requires PAN default-on\n");
    }

    let reserved = proof_reservations().unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 proof reservation construction failed\n",
        )
    });

    let identities = LinuxIdentityTable::<2, 2>::new();
    let exits = ExitCoordinator::<2>::new();
    let (main_report, identities, exits) = run_image(
        serial,
        backend,
        &reserved,
        MAIN_USER_ELF,
        MAIN_POOL_START,
        ExitScope::ThreadGroup,
        MAIN_EXPECTED_SVCS,
        identities,
        exits,
    );

    if main_report.pid != main_report.tid
        || main_report.svc_count != MAIN_EXPECTED_SVCS
        || main_report.stdout_calls != 1
        || main_report.stderr_calls != 1
        || main_report.stdout_bytes != STDOUT_BYTES
        || main_report.stderr_bytes != STDERR_BYTES
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 main Linux syscall proof mismatch\n",
        );
    }
    serial.write_str(
        "KERNAL/S14: unchanged Linux arm64 getpid/gettid/ENOSYS/write/exit_group passed\n",
    );

    let (exit_report, _identities, _exits) = run_image(
        serial,
        backend,
        &reserved,
        EXIT_USER_ELF,
        EXIT_POOL_START,
        ExitScope::Thread,
        EXIT_EXPECTED_SVCS,
        identities,
        exits,
    );
    if exit_report.pid != exit_report.tid
        || exit_report.pid == main_report.pid
        || exit_report.svc_count != EXIT_EXPECTED_SVCS
        || exit_report.stdout_calls != 0
        || exit_report.stderr_calls != 0
        || exit_report.stdout_bytes != 0
        || exit_report.stderr_bytes != 0
    {
        crate::fatal(serial, "KERNAL/ARM64: Step 14 thread-exit proof mismatch\n");
    }

    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 PAN leaked after Linux proof\n",
        );
    }
    serial.write_str("KERNAL/S14: Linux exit + reap + revoke + Process teardown passed\n");
    serial.write_str(
        "KERNAL/S14: Linux-visible PID/TID values stayed non-authoritative and non-reused\n",
    );
}

#[allow(clippy::too_many_arguments)]
fn run_image(
    serial: &crate::Serial,
    backend: &mut RuntimeTablePool,
    reserved: &ReservationSet<RESERVED_RANGES>,
    elf: &[u8],
    frame_start: u64,
    expected_scope: ExitScope,
    expected_svcs: u8,
    mut identities: LinuxIdentityTable<2, 2>,
    exits: ExitCoordinator<2>,
) -> (ProofReport, LinuxIdentityTable<2, 2>, ExitCoordinator<2>) {
    let policy = LoadPolicy::default();
    let plan = plan_aarch64_elf::<MAX_SEGMENTS>(elf, policy).unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 embedded Linux ELF rejected\n",
        )
    });
    let required = required_pages(&plan).unwrap_or_else(|_| {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 frame-count planning failed\n",
        )
    });
    if required == 0 || required > MAX_FRAMES {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 embedded Linux ELF exceeds proof frame pool\n",
        );
    }
    let frames = proof_frames(frame_start);

    let mut objects = ObjectTable::<OBJECTS>::new();
    let mut process = Process::<PROCESS_CAPS>::create(&mut objects, Personality::Linux)
        .unwrap_or_else(|_| {
            crate::fatal(serial, "KERNAL/ARM64: Step 14 process creation failed\n")
        });
    let mut space = BoundProcessAddressSpace::<VMAS>::create(&process, &objects, backend)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 14 process address-space creation failed\n",
            )
        });

    let loaded = unsafe {
        load_aarch64_elf::<MAX_SEGMENTS, PROCESS_CAPS, OBJECTS, VMAS, RESERVED_RANGES, _>(
            elf,
            policy,
            &frames[..required],
            &process,
            &objects,
            &mut space,
            backend,
            reserved,
        )
    }
    .unwrap_or_else(|_| crate::fatal(serial, "KERNAL/ARM64: Step 14 Linux ELF load failed\n"));
    if loaded.entry != plan.entry()
        || loaded.initial_sp != plan.stack().initial_sp()
        || loaded.mapped.total_pages().ok() != Some(required)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 loaded-image contract mismatch\n",
        );
    }

    let mut scheduler = RunQueue::<SCHED_THREADS>::new();
    let thread_local = scheduler.create(THREAD_PRIORITY).unwrap_or_else(|_| {
        crate::fatal(serial, "KERNAL/ARM64: Step 14 scheduler create failed\n")
    });
    let mut bindings = ThreadObjectBindings::<BINDINGS>::new();
    let thread_handle = exits
        .attach_thread(
            &mut process,
            &mut objects,
            &mut bindings,
            &scheduler,
            CPU0,
            GlobalThreadId::new(CPU0, thread_local),
        )
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 14 process Thread publication failed\n",
            )
        });
    let pid = identities
        .bind_leader(
            &process,
            &objects,
            &bindings,
            &scheduler,
            CPU0,
            thread_handle,
        )
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 14 Linux leader binding failed\n",
            )
        });
    let tid = identities
        .tid_for(
            &process,
            &objects,
            &bindings,
            &scheduler,
            CPU0,
            thread_handle,
        )
        .unwrap_or_else(|_| {
            crate::fatal(serial, "KERNAL/ARM64: Step 14 Linux TID lookup failed\n")
        });
    if pid != tid {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 single-thread PID/TID leader mismatch\n",
        );
    }
    scheduler
        .make_ready(thread_local)
        .unwrap_or_else(|_| crate::fatal(serial, "KERNAL/ARM64: Step 14 thread ready failed\n"));
    if scheduler.schedule().ok() != Some(Some(thread_local))
        || scheduler.state(thread_local).ok() != Some(ThreadState::Running)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 thread schedule selection failed\n",
        );
    }

    ACTIVE_PROOF
        .publish(ActiveProofContext {
            process,
            space,
            objects,
            scheduler,
            bindings,
            identities,
            exits,
            thread_local,
            thread_handle,
            pid,
            tid,
            expected_scope,
            expected_svcs,
            svc_count: 0,
            stdout_calls: 0,
            stderr_calls: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            exit_complete: false,
        })
        .unwrap_or_else(|_| crate::fatal(serial, "KERNAL/ARM64: Step 14 active state reused\n"));

    kernal_exceptions_aarch64::install_lower_el_aarch64_handler(step14_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 14 lower-EL handler install failed\n",
            )
        });

    let activation = ACTIVE_PROOF.with_active_mut(|active| {
        // SAFETY: this IRQ-masked BSP owns the prepared process/address-space proof window.
        unsafe {
            active
                .space
                .activate_owner(&active.process, &active.objects)
        }
    });
    if !matches!(activation, Some(Ok(()))) {
        abort_active(serial, "KERNAL/ARM64: Step 14 TTBR0 activation failed\n");
    }
    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        abort_active(
            serial,
            "KERNAL/ARM64: Step 14 PAN leaked before Linux entry\n",
        );
    }

    let roundtrip = unsafe {
        kernal_user_entry_aarch64::enter_el0_qemu_roundtrip(loaded.entry, loaded.initial_sp, 0)
    };

    if unsafe { BoundProcessAddressSpace::<VMAS>::deactivate() }.is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 TTBR0 deactivation serialization failed\n",
        );
    }
    kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step14_lower_el_handler)
        .unwrap_or_else(|_| {
            crate::fatal(
                serial,
                "KERNAL/ARM64: Step 14 lower-EL handler removal failed\n",
            )
        });

    let active = ACTIVE_PROOF.take().unwrap_or_else(|_| {
        crate::fatal(serial, "KERNAL/ARM64: Step 14 active state take failed\n")
    });
    if roundtrip.is_err()
        || !active.exit_complete
        || active.process.state() != ProcessState::Exited
        || !active.bindings.is_empty()
        || active.scheduler.state(active.thread_local) != Err(SchedulerError::InvalidThread)
        || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
    {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 14 Linux runtime roundtrip failed\n",
        );
    }

    let report = ProofReport {
        pid: active.pid,
        tid: active.tid,
        svc_count: active.svc_count,
        stdout_calls: active.stdout_calls,
        stderr_calls: active.stderr_calls,
        stdout_bytes: active.stdout_bytes,
        stderr_bytes: active.stderr_bytes,
    };
    (report, active.identities, active.exits)
}

fn proof_frames(start: u64) -> [PhysFrame; MAX_FRAMES] {
    core::array::from_fn(|index| {
        let index = u64::try_from(index).unwrap_or_else(|_| crate::fatal_silent());
        let address = start
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
    if MAIN_POOL_START < state.layout.bss.end
        || MAIN_POOL_START < crate::QEMU_VIRT_RAM_BASE
        || EXIT_POOL_START
            != MAIN_POOL_START
                .checked_add((MAX_FRAMES as u64) * PAGE_SIZE)
                .ok_or(())?
        || STEP14_POOL_END
            != EXIT_POOL_START
                .checked_add((MAX_FRAMES as u64) * PAGE_SIZE)
                .ok_or(())?
        || STEP14_POOL_END > STEP12_POOL_START
        || STEP14_POOL_END > RAM_END
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

    for frame in proof_frames(MAIN_POOL_START)
        .into_iter()
        .chain(proof_frames(EXIT_POOL_START))
    {
        if reserved.contains(frame) {
            return Err(());
        }
    }
    Ok(reserved)
}

fn abort_active(serial: &crate::Serial, message: &str) -> ! {
    let _ = unsafe { BoundProcessAddressSpace::<VMAS>::deactivate() };
    let _ = kernal_exceptions_aarch64::uninstall_lower_el_aarch64_handler(step14_lower_el_handler);
    crate::fatal(serial, message)
}

extern "C" fn step14_lower_el_handler(frame: &mut ExceptionFrame) -> bool {
    ACTIVE_PROOF
        .with_active_mut(|active| {
            if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
                crate::fatal_silent();
            }
            match frame.lower_el_aarch64_synchronous() {
                Some(LowerElAarch64Synchronous::SupervisorCall { immediate }) if immediate == 0 => {
                    handle_svc(active, frame)
                }
                _ => crate::fatal_silent(),
            }
        })
        .unwrap_or(false)
}

fn handle_svc(active: &mut ActiveProofContext, frame: &mut ExceptionFrame) -> bool {
    active.svc_count = active
        .svc_count
        .checked_add(1)
        .unwrap_or_else(|| crate::fatal_silent());
    if active.svc_count > active.expected_svcs {
        crate::fatal_silent();
    }

    let outcome = {
        let current = active
            .space
            .current_owner(&active.process)
            .unwrap_or_else(|_| crate::fatal_silent());
        let mut context = ProofBootstrapContext {
            pid: active.pid,
            tid: active.tid,
            stdout_calls: &mut active.stdout_calls,
            stderr_calls: &mut active.stderr_calls,
            stdout_bytes: &mut active.stdout_bytes,
            stderr_bytes: &mut active.stderr_bytes,
        };
        dispatch_linux_syscall(&current, frame, &mut context)
            .unwrap_or_else(|_| crate::fatal_silent())
    };

    if kernal_usercopy_aarch64::pan_enabled() != Ok(true) {
        crate::fatal_silent();
    }
    match outcome {
        TrapOutcome::Returned => true,
        TrapOutcome::Exit(request) => handle_exit(active, frame, request),
    }
}

fn handle_exit(
    active: &mut ActiveProofContext,
    frame: &mut ExceptionFrame,
    request: kernal_linux_bootstrap::ExitRequest,
) -> bool {
    if request.scope != active.expected_scope
        || request.status != 0
        || active.svc_count != active.expected_svcs
        || active.exit_complete
    {
        crate::fatal_silent();
    }

    // Persist exit_group state before the thread stops, matching the production lifecycle contract.
    let ticket = active
        .exits
        .begin_exit(request, &active.process)
        .unwrap_or_else(|_| crate::fatal_silent());
    active
        .scheduler
        .exit(active.thread_local)
        .unwrap_or_else(|_| crate::fatal_silent());
    if active.scheduler.state(active.thread_local) != Ok(ThreadState::Exited) {
        crate::fatal_silent();
    }

    // This is the same proof-only scheduler attestation pattern accepted by Step 11: this RunQueue is
    // owned solely by the IRQ-masked proof context, and the exact generation is minted only after its
    // successful reap. Production uses CpuSchedulerCell::bootstrap_reap_*_with_proof.
    active
        .scheduler
        .reap(active.thread_local)
        .unwrap_or_else(|_| crate::fatal_silent());
    let global = GlobalThreadId::new(CPU0, active.thread_local);
    // SAFETY: the exact proof-owned scheduler generation above has just completed reap().
    let proof = unsafe { ReapedThreadProof::new_unchecked(global) };
    let completion = finalize_reaped_thread(
        ticket,
        &mut active.exits,
        &mut active.process,
        &mut active.objects,
        &mut active.bindings,
        proof,
        active.thread_handle,
    )
    .unwrap_or_else(|_| crate::fatal_silent());
    if completion
        != (Completion::ProcessExited {
            thread: global,
            scope: active.expected_scope,
            status: 0,
        })
        || active.process.state() != ProcessState::Exited
        || !active.bindings.is_empty()
        || active.scheduler.state(active.thread_local) != Err(SchedulerError::InvalidThread)
        || active
            .process
            .resolve_thread(
                &active.objects,
                &active.bindings,
                &active.scheduler,
                CPU0,
                active.thread_handle,
            )
            .is_ok()
    {
        crate::fatal_silent();
    }
    active
        .identities
        .retire_process(&active.process)
        .unwrap_or_else(|_| crate::fatal_silent());
    if active.exits.is_group_draining(&active.process) {
        crate::fatal_silent();
    }

    frame.elr_el1 = qemu_resume_high_address().unwrap_or_else(|_| crate::fatal_silent());
    frame.spsr_el1 = kernal_user_entry_aarch64::QEMU_PROBE_RESUME_SPSR_EL1 | PSTATE_PAN_BIT;
    active.exit_complete = true;
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
