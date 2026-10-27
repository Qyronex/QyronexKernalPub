// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_frame_allocator::{ExtentAllocator, FrameRange};
use kernal_kmap_x86_64::KmapController;
use kernal_page_table::Mapper;
use kernal_runtime_page_table_x86_64::RuntimePageTableBackend;
use kernal_scheduler::{RunQueue, ThreadId, ThreadState};
use kernal_thread_context::{ContextTable, ThreadContext};
use kernal_thread_stack_x86_64::{PAGE_SIZE, THREAD_STACK_PAGES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CurrentThread,
    NotExited,
    Context(kernal_thread_context::Error),
    InvalidStack,
    Paging(kernal_page_table::Error),
    Tlb(kernal_tlb_x86_64::Error),
    Frame(kernal_frame_allocator::Error),
    Scheduler(kernal_scheduler::Error),
    PhysicalMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReapReport {
    pub pages_unmapped: usize,
    pub pages_freed: usize,
}

/// Tears down one already-exited kernel thread on the owning address space.
///
/// Ordering is security-sensitive:
/// 1. prove the thread is Exited and is not the currently executing thread,
/// 2. remove every stack PTE,
/// 3. invalidate each local TLB entry,
/// 4. remove architecture context metadata,
/// 5. return physical frames,
/// 6. only then advance scheduler generation through `reap()`.
///
/// Any failure before step 6 intentionally leaves the scheduler slot non-reusable. Callers should
/// treat errors after partial teardown as fatal/containment events until a richer recovery state
/// machine exists. Cross-CPU address-space sharing requires a remote TLB shootdown before frames
/// are returned; this early API is only valid for CPU-local kernel-thread stacks in the shared
/// kernel CR3 before arbitrary user address spaces are running concurrently.
pub fn reap_exited_local<const THREADS: usize, const EXTENTS: usize>(
    id: ThreadId,
    current: Option<ThreadId>,
    root_table: u64,
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    frames: &mut ExtentAllocator<EXTENTS>,
    kmap: &KmapController,
) -> Result<ReapReport, Error> {
    if current == Some(id) {
        return Err(Error::CurrentThread);
    }
    if run_queue.state(id).map_err(Error::Scheduler)? != ThreadState::Exited {
        return Err(Error::NotExited);
    }

    let context = *contexts.get(id).map_err(Error::Context)?;
    let page_count = validate_context_stack(context)?;
    let mut physical = [0u64; THREAD_STACK_PAGES];

    {
        let mut backend = RuntimePageTableBackend::new(frames, kmap);
        let mut mapper = Mapper::new(&mut backend, root_table).map_err(Error::Paging)?;
        for (index, slot) in physical[..page_count].iter_mut().enumerate() {
            let offset = (index as u64)
                .checked_mul(PAGE_SIZE)
                .ok_or(Error::InvalidStack)?;
            let virtual_address = context
                .stack
                .mapped_start
                .checked_add(offset)
                .ok_or(Error::InvalidStack)?;
            let removed = mapper.unmap_page(virtual_address).map_err(Error::Paging)?;
            if removed == 0 || removed & (PAGE_SIZE - 1) != 0 {
                return Err(Error::PhysicalMismatch);
            }
            *slot = removed;
            // SAFETY: this API is for the currently active kernel address space at CPL0. The PTE
            // was removed immediately above. Remote users are excluded by the documented contract.
            unsafe { kernal_tlb_x86_64::invalidate_page(virtual_address) }.map_err(Error::Tlb)?;
        }
    }

    // Context removal occurs only after no local translation can still reach the stack.
    let removed_context = contexts.remove(id).map_err(Error::Context)?;
    if removed_context != context {
        return Err(Error::PhysicalMismatch);
    }

    let mut pages_freed = 0usize;
    for address in physical[..page_count].iter().copied() {
        frames
            .free(FrameRange::new(address, 1).map_err(Error::Frame)?)
            .map_err(Error::Frame)?;
        pages_freed += 1;
    }

    // Generation advance is deliberately the last operation. Once this succeeds the slot may be
    // reused and its deterministic virtual stack slot can safely receive new mappings.
    run_queue.reap(id).map_err(Error::Scheduler)?;
    Ok(ReapReport {
        pages_unmapped: page_count,
        pages_freed,
    })
}

fn validate_context_stack(context: ThreadContext) -> Result<usize, Error> {
    if context.stack.mapped_start == 0
        || context.stack.mapped_len == 0
        || context.stack.mapped_start & (PAGE_SIZE - 1) != 0
        || context.stack.mapped_len & (PAGE_SIZE - 1) != 0
    {
        return Err(Error::InvalidStack);
    }
    let pages =
        usize::try_from(context.stack.mapped_len / PAGE_SIZE).map_err(|_| Error::InvalidStack)?;
    if pages == 0 || pages > THREAD_STACK_PAGES {
        return Err(Error::InvalidStack);
    }
    context.stack.top().map_err(|_| Error::InvalidStack)?;
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_thread_context::KernelStack;

    fn context(mapped_len: u64) -> ThreadContext {
        ThreadContext {
            id: ThreadId {
                slot: 1,
                generation: 2,
            },
            saved_rsp: 0xffff_9000_0000_fff8,
            stack: KernelStack {
                guard_start: 0xffff_9000_0000_0000,
                mapped_start: 0xffff_9000_0000_1000,
                mapped_len,
            },
            address_space: 0,
        }
    }

    #[test]
    fn validates_bounded_page_aligned_stack() {
        assert_eq!(
            validate_context_stack(context(PAGE_SIZE * THREAD_STACK_PAGES as u64)),
            Ok(THREAD_STACK_PAGES)
        );
    }

    #[test]
    fn rejects_zero_unaligned_or_oversized_stack() {
        assert_eq!(validate_context_stack(context(0)), Err(Error::InvalidStack));
        assert_eq!(
            validate_context_stack(context(PAGE_SIZE + 1)),
            Err(Error::InvalidStack)
        );
        assert_eq!(
            validate_context_stack(context(PAGE_SIZE * (THREAD_STACK_PAGES as u64 + 1))),
            Err(Error::InvalidStack)
        );
    }
}
