// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
use core::arch::asm;
use core::slice::from_raw_parts_mut;
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
use kernal_address_space_x86_64::{X86AddressSpaceExt, X86Root};
use kernal_context_x86_64::{
    CONTEXT_BYTES, CONTEXT_WORDS, KernelThreadEntry, build_initial_context,
};
use kernal_frame_allocator::{ExtentAllocator, FrameRange};
use kernal_kmap::{CachePolicy, MappingRequest};
use kernal_kmap_x86_64::KmapController;
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
use kernal_memory::{PhysFrame, ReservationSet};
use kernal_page_table::Mapper;
use kernal_paging::MapFlags;
use kernal_percpu::CpuIndex;
use kernal_runtime_page_table_x86_64::RuntimePageTableBackend;
use kernal_scheduler::{RunQueue, ThreadId};
use kernal_thread_context::ContextTable;
use kernal_thread_stack_x86_64::{PAGE_SIZE, THREAD_STACK_PAGES, ThreadStackLayout};
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
use kernal_vm::{AddressSpace, Backing, USER_MIN, VmPerms, Vma};

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
const STEP7_PROBE_VA: u64 = USER_MIN + 0x20_000;
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
const STEP7_MARKER_A: u64 = 0x5337_5838_3641_0001;
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
const STEP7_MARKER_B: u64 = 0x5337_5838_3642_0002;
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
const COM1: u16 = 0x03f8;
#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
static STEP7_QEMU_PROOF_DONE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Scheduler(kernal_scheduler::Error),
    StackLayout(kernal_thread_stack_x86_64::Error),
    Frame(kernal_frame_allocator::Error),
    Kmap,
    Paging(kernal_page_table::Error),
    Context(kernal_thread_context::Error),
    ContextBuild(kernal_context_x86_64::Error),
    #[cfg(feature = "step7-qemu-proof")]
    Step7Proof,
    /// Some leaf mapping may still reference the stack frames. Such frames must be leaked/contained
    /// rather than returned to the allocator because reuse would create an alias/use-after-free.
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreatedThread {
    pub id: ThreadId,
    pub saved_rsp: u64,
    pub stack: ThreadStackLayout,
}

/// Creates one ready kernel thread and rolls back owned leaf mappings/stack frames on failure.
///
/// Newly allocated intermediate page tables are intentionally retained because they cover the
/// deterministic per-CPU thread-stack arena and can be reused. If leaf rollback itself fails, the
/// stack frames are deliberately not freed: leaking memory is safer than recycling still-mapped RAM.
#[expect(
    clippy::too_many_arguments,
    reason = "bootstrap transaction crosses scheduler, context, frame, and page-table ownership domains"
)]
pub fn create_ready<const THREADS: usize, const EXTENTS: usize>(
    cpu: CpuIndex,
    priority: u8,
    entry: KernelThreadEntry,
    argument: u64,
    address_space: u64,
    root_table: u64,
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    frames: &mut ExtentAllocator<EXTENTS>,
    kmap: &KmapController,
) -> Result<CreatedThread, Error> {
    #[cfg(all(
        feature = "step7-qemu-proof",
        target_arch = "x86_64",
        target_os = "none"
    ))]
    step7_qemu_proof_once(root_table, frames, kmap)?;

    let id = run_queue.create(priority).map_err(Error::Scheduler)?;
    let stack = match ThreadStackLayout::for_thread(cpu, id) {
        Ok(stack) => stack,
        Err(error) => {
            rollback_scheduler(run_queue, id)?;
            return Err(Error::StackLayout(error));
        }
    };

    let mut physical = [0u64; THREAD_STACK_PAGES];
    let mut allocated = 0usize;
    for slot in &mut physical {
        match frames.allocate_page() {
            Ok(address) => {
                *slot = address;
                allocated += 1;
                if zero_page(address, kmap).is_err() {
                    rollback_unmapped_frames(frames, &physical[..allocated])?;
                    rollback_scheduler(run_queue, id)?;
                    return Err(Error::Kmap);
                }
            }
            Err(error) => {
                rollback_unmapped_frames(frames, &physical[..allocated])?;
                rollback_scheduler(run_queue, id)?;
                return Err(Error::Frame(error));
            }
        }
    }

    let mapped = match map_stack(root_table, stack, &physical, frames, kmap) {
        Ok(mapped) => mapped,
        Err(Error::Rollback) => {
            // Mapping rollback was incomplete; never return potentially aliased frames to free RAM.
            let _ = rollback_scheduler(run_queue, id);
            return Err(Error::Rollback);
        }
        Err(error) => {
            rollback_unmapped_frames(frames, &physical)?;
            rollback_scheduler(run_queue, id)?;
            return Err(error);
        }
    };

    let saved_rsp = match initialize_context(stack, entry, argument) {
        Ok(rsp) => rsp,
        Err(error) => {
            if rollback_mapped_stack(root_table, stack, &physical[..mapped], frames, kmap).is_err()
            {
                let _ = rollback_scheduler(run_queue, id);
                return Err(Error::Rollback);
            }
            rollback_scheduler(run_queue, id)?;
            return Err(Error::ContextBuild(error));
        }
    };

    let context_stack = match stack.context_stack() {
        Ok(value) => value,
        Err(error) => {
            if rollback_mapped_stack(root_table, stack, &physical[..mapped], frames, kmap).is_err()
            {
                let _ = rollback_scheduler(run_queue, id);
                return Err(Error::Rollback);
            }
            rollback_scheduler(run_queue, id)?;
            return Err(Error::StackLayout(error));
        }
    };
    if let Err(error) = contexts.insert(id, saved_rsp, context_stack, address_space) {
        if rollback_mapped_stack(root_table, stack, &physical[..mapped], frames, kmap).is_err() {
            let _ = rollback_scheduler(run_queue, id);
            return Err(Error::Rollback);
        }
        rollback_scheduler(run_queue, id)?;
        return Err(Error::Context(error));
    }
    if let Err(error) = run_queue.make_ready(id) {
        let _ = contexts.remove(id);
        if rollback_mapped_stack(root_table, stack, &physical[..mapped], frames, kmap).is_err() {
            let _ = rollback_scheduler(run_queue, id);
            return Err(Error::Rollback);
        }
        rollback_scheduler(run_queue, id)?;
        return Err(Error::Scheduler(error));
    }

    Ok(CreatedThread {
        id,
        saved_rsp,
        stack,
    })
}

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
fn step7_qemu_proof_once<const EXTENTS: usize>(
    kernel_root: u64,
    frames: &mut ExtentAllocator<EXTENTS>,
    kmap: &KmapController,
) -> Result<(), Error> {
    if STEP7_QEMU_PROOF_DONE.swap(true, Ordering::AcqRel) {
        return Ok(());
    }

    let left_physical = frames.allocate_page().map_err(Error::Frame)?;
    let right_physical = match frames.allocate_page() {
        Ok(value) => value,
        Err(error) => {
            let _ = free_probe_frame(frames, left_physical);
            return Err(Error::Frame(error));
        }
    };
    if write_probe_marker(left_physical, STEP7_MARKER_A, kmap).is_err()
        || write_probe_marker(right_physical, STEP7_MARKER_B, kmap).is_err()
    {
        let _ = free_probe_frame(frames, left_physical);
        let _ = free_probe_frame(frames, right_physical);
        return Err(Error::Step7Proof);
    }

    let left_frame = PhysFrame::from_start_address(left_physical).ok_or(Error::Step7Proof)?;
    let right_frame = PhysFrame::from_start_address(right_physical).ok_or(Error::Step7Proof)?;
    let reserved = ReservationSet::<1>::new();
    let vma = Vma::new(STEP7_PROBE_VA, PAGE_SIZE, VmPerms::READ, Backing::Anonymous)
        .map_err(|_| Error::Step7Proof)?;

    let mut backend = RuntimePageTableBackend::new(frames, kmap);
    let mut left = AddressSpace::<X86Root, 2>::new(
        X86Root::from_kernel_root(&mut backend, kernel_root).map_err(|_| Error::Step7Proof)?,
    );
    let mut right = AddressSpace::<X86Root, 2>::new(
        X86Root::from_kernel_root(&mut backend, kernel_root).map_err(|_| Error::Step7Proof)?,
    );
    left.map_user_page(&mut backend, vma, left_frame, &reserved)
        .map_err(|_| Error::Step7Proof)?;
    right
        .map_user_page(&mut backend, vma, right_frame, &reserved)
        .map_err(|_| Error::Step7Proof)?;

    if left
        .translate_user(&mut backend, STEP7_PROBE_VA)
        .map_err(|_| Error::Step7Proof)?
        != left_physical
        || right
            .translate_user(&mut backend, STEP7_PROBE_VA)
            .map_err(|_| Error::Step7Proof)?
            != right_physical
    {
        return Err(Error::Step7Proof);
    }

    // SAFETY: bootstrap runs at CPL0 with IF=0 and no APs yet use these roots. Both roots share the
    // accepted kernel half, so the current code/stack remain valid. The original root is restored
    // before any allocator/kmap operation resumes.
    let switch_ok = unsafe { run_step7_switch_probe(left.root(), right.root()) };
    // SAFETY: `kernel_root` was read from CR3 by the accepted runtime backend immediately before
    // this bootstrap path and remains live for the entire kernel lifetime.
    unsafe { restore_kernel_root(kernel_root) };
    if !switch_ok {
        return Err(Error::Step7Proof);
    }

    if left
        .unmap_user_page(&mut backend, STEP7_PROBE_VA)
        .map_err(|_| Error::Step7Proof)?
        != left_frame
        || right
            .unmap_user_page(&mut backend, STEP7_PROBE_VA)
            .map_err(|_| Error::Step7Proof)?
            != right_frame
    {
        return Err(Error::Step7Proof);
    }
    drop(backend);
    free_probe_frame(frames, left_physical)?;
    free_probe_frame(frames, right_physical)?;
    proof_serial_write("KERNAL/S7: x86 same-VA address-space switch proof passed\r\n");
    Ok(())
}

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
unsafe fn run_step7_switch_probe(left: &X86Root, right: &X86Root) -> bool {
    // SAFETY: caller owns the pre-AP, IF=0 bootstrap switch window.
    if unsafe { (*left).activate() }.is_err() {
        return false;
    }
    // SAFETY: the active left root maps this validated user VA read-only to an owned probe frame.
    let left_first = unsafe { core::ptr::read_volatile(STEP7_PROBE_VA as *const u64) };

    // SAFETY: same bootstrap contract; a normal CR3 write flushes non-global user translations.
    if unsafe { (*right).activate() }.is_err() {
        return false;
    }
    // SAFETY: the active right root maps the same VA to the distinct right probe frame.
    let right_value = unsafe { core::ptr::read_volatile(STEP7_PROBE_VA as *const u64) };

    // Switch back once more so stale B translations are also observable if CR3 invalidation fails.
    // SAFETY: same bootstrap contract as above.
    if unsafe { (*left).activate() }.is_err() {
        return false;
    }
    // SAFETY: left mapping is active again.
    let left_second = unsafe { core::ptr::read_volatile(STEP7_PROBE_VA as *const u64) };

    left_first == STEP7_MARKER_A && right_value == STEP7_MARKER_B && left_second == STEP7_MARKER_A
}

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
unsafe fn restore_kernel_root(root: u64) {
    // SAFETY: caller supplies the accepted current kernel CR3 captured before the smoke.
    unsafe {
        asm!(
            "mov cr3, {root}",
            root = in(reg) root,
            options(nostack, preserves_flags)
        )
    };
}

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
fn write_probe_marker(physical: u64, marker: u64, kmap: &KmapController) -> Result<(), Error> {
    let mapping = kmap
        .map(MappingRequest {
            physical_address: physical,
            writable: true,
            cache: CachePolicy::WriteBack,
        })
        .map_err(|_| Error::Step7Proof)?;
    // SAFETY: the probe frame was freshly allocated and remains exclusively owned by this smoke.
    let base = unsafe { mapping.as_mut_ptr::<u64>() }.ok_or(Error::Step7Proof)?;
    // SAFETY: one u64 write is within the live writable 4 KiB mapping.
    unsafe { core::ptr::write_volatile(base, marker) };
    Ok(())
}

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
fn free_probe_frame<const EXTENTS: usize>(
    frames: &mut ExtentAllocator<EXTENTS>,
    physical: u64,
) -> Result<(), Error> {
    frames
        .free(FrameRange::new(physical, 1).map_err(Error::Frame)?)
        .map_err(Error::Frame)
}

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "x86_64",
    target_os = "none"
))]
fn proof_serial_write(text: &str) {
    for byte in text.bytes() {
        // SAFETY: COM1 was initialized by the kernel before the scheduler bootstrap reaches here.
        unsafe {
            asm!(
                "out dx, al",
                in("dx") COM1,
                in("al") byte,
                options(nomem, nostack, preserves_flags)
            )
        };
    }
}

fn map_stack<const EXTENTS: usize>(
    root_table: u64,
    stack: ThreadStackLayout,
    physical: &[u64; THREAD_STACK_PAGES],
    frames: &mut ExtentAllocator<EXTENTS>,
    kmap: &KmapController,
) -> Result<usize, Error> {
    let mut backend = RuntimePageTableBackend::new(frames, kmap);
    let mut mapper = Mapper::new(&mut backend, root_table).map_err(Error::Paging)?;
    // Thread stacks are deliberately non-global because they are removable/recyclable mappings.
    let flags = MapFlags::READ.union(MapFlags::WRITE);
    let mut mapped = 0usize;
    for physical_address in physical.iter().copied() {
        let offset = (mapped as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::Rollback)?;
        let virtual_address = stack
            .mapped_start
            .checked_add(offset)
            .ok_or(Error::Rollback)?;
        if let Err(error) = mapper.map_page(virtual_address, physical_address, flags) {
            for rollback_index in 0..mapped {
                let rollback_offset = (rollback_index as u64)
                    .checked_mul(PAGE_SIZE)
                    .ok_or(Error::Rollback)?;
                let rollback_virtual = stack
                    .mapped_start
                    .checked_add(rollback_offset)
                    .ok_or(Error::Rollback)?;
                if mapper.unmap_page(rollback_virtual).is_err() {
                    return Err(Error::Rollback);
                }
            }
            return Err(Error::Paging(error));
        }
        mapped += 1;
    }
    Ok(mapped)
}

fn initialize_context(
    stack: ThreadStackLayout,
    entry: KernelThreadEntry,
    argument: u64,
) -> Result<u64, kernal_context_x86_64::Error> {
    let saved_rsp = stack
        .top
        .checked_sub(CONTEXT_BYTES as u64)
        .ok_or(kernal_context_x86_64::Error::StackTooSmall)?;
    // SAFETY: create_ready maps the complete stack RW-NX before this call. The final CONTEXT_WORDS
    // words lie inside that owned mapping and no thread can execute it before make_ready().
    let words = unsafe { from_raw_parts_mut(saved_rsp as *mut u64, CONTEXT_WORDS) };
    let start = build_initial_context(words, stack.top, entry, argument)?;
    debug_assert_eq!(start, 0);
    Ok(saved_rsp)
}

fn zero_page(physical: u64, kmap: &KmapController) -> Result<(), Error> {
    let mapping = kmap
        .map(MappingRequest {
            physical_address: physical,
            writable: true,
            cache: CachePolicy::WriteBack,
        })
        .map_err(|_| Error::Kmap)?;
    // SAFETY: caller exclusively owns freshly allocated physical frame.
    let base = unsafe { mapping.as_mut_ptr::<u8>() }.ok_or(Error::Kmap)?;
    // SAFETY: kmap lease spans exactly one writable 4 KiB page.
    unsafe { core::ptr::write_bytes(base, 0, PAGE_SIZE as usize) };
    Ok(())
}

fn rollback_mapped_stack<const EXTENTS: usize>(
    root_table: u64,
    stack: ThreadStackLayout,
    physical: &[u64],
    frames: &mut ExtentAllocator<EXTENTS>,
    kmap: &KmapController,
) -> Result<(), Error> {
    {
        let mut backend = RuntimePageTableBackend::new(frames, kmap);
        let mut mapper = Mapper::new(&mut backend, root_table).map_err(|_| Error::Rollback)?;
        for (index, expected) in physical.iter().copied().enumerate() {
            let offset = (index as u64)
                .checked_mul(PAGE_SIZE)
                .ok_or(Error::Rollback)?;
            let virtual_address = stack
                .mapped_start
                .checked_add(offset)
                .ok_or(Error::Rollback)?;
            let actual = mapper
                .unmap_page(virtual_address)
                .map_err(|_| Error::Rollback)?;
            if actual != expected {
                return Err(Error::Rollback);
            }
        }
    }
    rollback_unmapped_frames(frames, physical)
}

fn rollback_unmapped_frames<const EXTENTS: usize>(
    frames: &mut ExtentAllocator<EXTENTS>,
    physical: &[u64],
) -> Result<(), Error> {
    for address in physical.iter().copied() {
        frames
            .free(FrameRange::new(address, 1).map_err(Error::Frame)?)
            .map_err(Error::Frame)?;
    }
    Ok(())
}

fn rollback_scheduler<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    id: ThreadId,
) -> Result<(), Error> {
    run_queue.exit(id).map_err(|_| Error::Rollback)?;
    run_queue.reap(id).map_err(|_| Error::Rollback)
}
