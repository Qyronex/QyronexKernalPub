// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
#[path = "step30_fork.rs"]
mod step30_fork_tests;

#[cfg(test)]
#[allow(dead_code)]
#[path = "step15_runtime.rs"]
mod step15_runtime_tests;

#[cfg(test)]
#[allow(dead_code)]
#[path = "step30_sigreturn.rs"]
mod step30_sigreturn_tests;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod clone_stack {
    use core::cell::UnsafeCell;
    use core::mem::MaybeUninit;
    use core::slice::from_raw_parts_mut;
    use core::sync::atomic::{AtomicU8, Ordering};
    use kernal_exceptions_aarch64::ExceptionFrame;
    use kernal_linux_abi::MinimumRuntimeCall;
    use kernal_linux_clone_aarch64::{
        CloneChildState, PreparedCloneKernelContext, ProcessCloneReturnState,
    };
    use kernal_linux_clone_trap_aarch64::{
        CloneContextBuilder, CloneStackProvider, Error as CloneRuntimeError, StackPrepareError,
    };
    use kernal_linux_exit_lifecycle::ExitCoordinator;
    use kernal_linux_identity::LinuxIdentityTable;
    use kernal_object::ObjectTable;
    use kernal_process::{Process, ThreadObjectBindings};
    use kernal_process_aarch64::BoundProcessAddressSpace;
    use kernal_scheduler_cpu::CpuSchedulerCell;
    use kernal_thread_context::KernelStack;
    use kernal_thread_stack_aarch64::{Error as StackPoolError, StaticStackPool};
    use kernal_user_elf_runtime_aarch64::LoadedImage;
    use kernal_user_initial_context_aarch64::{
        Error as InitialUserContextError, PreparedInitialUserContext, prepare_initial_user_context,
    };

    pub const CLONE_STACK_CAPACITY: usize = 16;

    const POOL_EMPTY: u8 = 0;
    const POOL_INITIALIZING: u8 = 1;
    const POOL_READY: u8 = 2;
    const POOL_FAILED: u8 = 3;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum CloneStackInitError {
        LinkerContract,
        Pool(StackPoolError),
        Failed,
    }

    #[derive(Debug, Eq, PartialEq)]
    pub enum CloneDispatchError {
        StackPool(CloneStackInitError),
        Runtime(CloneRuntimeError<StackPoolError>),
    }

    #[derive(Debug, Eq, PartialEq)]
    pub enum CloneStackReclaimError {
        StackPool(CloneStackInitError),
        Reclaim(StackPoolError),
    }

    #[derive(Debug, Eq, PartialEq)]
    pub enum ProcessCloneStackError {
        StackPool(CloneStackInitError),
        Prepare(StackPrepareError<StackPoolError>),
    }

    /// Authority-free handoff between truthful Linux fork return-state construction and the later
    /// staged scheduler transaction. The prepared context owns one exclusive protected Core stack;
    /// `parent_return_value` is observation only and never Process/scheduler authority.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct PreparedProcessCloneStack {
        context: PreparedCloneKernelContext,
        parent_return_value: u64,
    }

    impl PreparedProcessCloneStack {
        pub const fn context(self) -> PreparedCloneKernelContext {
            self.context
        }

        pub const fn parent_return_value(self) -> u64 {
            self.parent_return_value
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub enum InitialUserStackError {
        StackPool(CloneStackInitError),
        Stack(StackPoolError),
        Context(InitialUserContextError),
        Reclaim(StackPoolError),
    }

    struct CloneStackPoolCell {
        state: AtomicU8,
        pool: UnsafeCell<MaybeUninit<StaticStackPool<CLONE_STACK_CAPACITY>>>,
    }

    // SAFETY: initialization is a one-way AtomicU8 state transition. After READY the pool object is
    // immutable and its slot ownership is synchronized internally by its atomic allocation bitmap.
    unsafe impl Sync for CloneStackPoolCell {}

    impl CloneStackPoolCell {
        const fn new() -> Self {
            Self {
                state: AtomicU8::new(POOL_EMPTY),
                pool: UnsafeCell::new(MaybeUninit::uninit()),
            }
        }

        fn get_or_initialize(
            &'static self,
        ) -> Result<&'static StaticStackPool<CLONE_STACK_CAPACITY>, CloneStackInitError> {
            loop {
                match self.state.load(Ordering::Acquire) {
                    POOL_READY => {
                        // SAFETY: READY is stored only after the unique initializer wrote `pool`.
                        return Ok(unsafe { (&*self.pool.get()).assume_init_ref() });
                    }
                    POOL_FAILED => return Err(CloneStackInitError::Failed),
                    POOL_INITIALIZING => core::hint::spin_loop(),
                    POOL_EMPTY => {
                        if self
                            .state
                            .compare_exchange(
                                POOL_EMPTY,
                                POOL_INITIALIZING,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_err()
                        {
                            continue;
                        }

                        let result = linker_clone_arena().and_then(|(start, end, stride)| {
                            // SAFETY: #434/#436 reserve this exact linker range for clone stacks and
                            // Protected Boot maps every payload RW-NX while leaving every first page
                            // unmapped in all live aliases. These mappings outlive the static pool.
                            unsafe { StaticStackPool::new_protected(start, end, stride) }
                                .map_err(CloneStackInitError::Pool)
                        });

                        match result {
                            Ok(pool) => {
                                // SAFETY: successful EMPTY->INITIALIZING gave this path unique write
                                // access; no reader may observe the object before the Release store.
                                unsafe { (*self.pool.get()).write(pool) };
                                self.state.store(POOL_READY, Ordering::Release);
                            }
                            Err(error) => {
                                self.state.store(POOL_FAILED, Ordering::Release);
                                return Err(error);
                            }
                        }
                    }
                    _ => {
                        self.state.store(POOL_FAILED, Ordering::Release);
                        return Err(CloneStackInitError::Failed);
                    }
                }
            }
        }
    }

    static CLONE_STACK_POOL: CloneStackPoolCell = CloneStackPoolCell::new();

    struct CoreCloneStackProvider {
        pool: &'static StaticStackPool<CLONE_STACK_CAPACITY>,
    }

    impl CloneStackProvider for CoreCloneStackProvider {
        type Error = StackPoolError;

        fn prepare(
            &mut self,
            child: CloneChildState,
            build: CloneContextBuilder,
        ) -> Result<PreparedCloneKernelContext, StackPrepareError<Self::Error>> {
            let stack = match self.pool.claim() {
                Ok(stack) => stack,
                Err(StackPoolError::Exhausted) => return Err(StackPrepareError::Exhausted),
                Err(error) => return Err(StackPrepareError::Backend(error)),
            };

            let word_bytes = core::mem::size_of::<u64>() as u64;
            if stack.mapped_len % word_bytes != 0
                || !stack
                    .mapped_start
                    .is_multiple_of(core::mem::align_of::<u64>() as u64)
            {
                // SAFETY: `stack` is the exact claim obtained above and has not escaped.
                let _ = unsafe { self.pool.reclaim(stack) };
                return Err(StackPrepareError::Backend(StackPoolError::InvalidArena));
            }
            let word_count = match usize::try_from(stack.mapped_len / word_bytes) {
                Ok(count) => count,
                Err(_) => {
                    // SAFETY: `stack` is still the exact current claim and has not escaped.
                    let _ = unsafe { self.pool.reclaim(stack) };
                    return Err(StackPrepareError::Backend(StackPoolError::AddressOverflow));
                }
            };

            // SAFETY: a successful pool claim gives this provider exclusive ownership of the exact
            // protected payload until the prepared context is transferred to the scheduler. The
            // linker/Protected-Boot contract guarantees the complete payload is mapped writable and
            // non-executable; the guard page is outside this slice.
            let words = unsafe { from_raw_parts_mut(stack.mapped_start as *mut u64, word_count) };
            words.fill(0);
            match build(words, stack, child) {
                Ok(prepared) => Ok(prepared),
                Err(error) => {
                    // SAFETY: builder failure transfers no scheduler ownership and the exact claim is
                    // still uniquely held here, so immediate reclaim cannot race slot reuse.
                    match unsafe { self.pool.reclaim(stack) } {
                        Ok(()) => Err(StackPrepareError::Context(error)),
                        Err(reclaim) => Err(StackPrepareError::Backend(reclaim)),
                    }
                }
            }
        }

        fn reclaim(&mut self, stack: KernelStack) -> Result<(), Self::Error> {
            // SAFETY: CoreCloneStackProvider is private and can only be instantiated by the wrapper
            // below, which hands it directly to the canonical clone transaction. That transaction
            // calls this safe trait edge only with the exact KernelStack returned by canonical
            // `bootstrap_cancel_staged` after all Process/TID authority has been removed. The private
            // provider never escapes, so a stale copied descriptor cannot be supplied after reuse.
            unsafe { self.pool.reclaim(stack) }
        }
    }

    /// Claims one protected Core stack for a still-unpublished process-fork child and writes the
    /// canonical one-shot AArch64 first-run image.
    ///
    /// `returns` was constructed by the accepted `ProcessCloneReturnState` owner after canonical child
    /// PID allocation. This wrapper owns no PID/Process/scheduler state: it atomically couples the
    /// child's truthful x0=0 state with the parent-visible child PID and transfers only the prepared
    /// stack token to the later staged scheduler transaction. Every preparation failure is reclaimed by
    /// the existing private `CoreCloneStackProvider` before the error escapes.
    pub fn prepare_process_clone_with_core_stack(
        returns: ProcessCloneReturnState,
    ) -> Result<PreparedProcessCloneStack, ProcessCloneStackError> {
        let pool = CLONE_STACK_POOL
            .get_or_initialize()
            .map_err(ProcessCloneStackError::StackPool)?;
        let mut stacks = CoreCloneStackProvider { pool };
        let context = stacks
            .prepare(
                returns.child(),
                kernal_linux_clone_runtime_aarch64::prepare_first_run_context,
            )
            .map_err(ProcessCloneStackError::Prepare)?;
        Ok(PreparedProcessCloneStack {
            context,
            parent_return_value: returns.parent_return_value(),
        })
    }

    /// Returns one process-fork stack that was prepared successfully but never transferred to a
    /// scheduler generation.
    ///
    /// # Safety
    /// `stack` must be the exact current allocation embedded in the `PreparedProcessCloneStack`
    /// produced by `prepare_process_clone_with_core_stack`. No scheduler generation may ever have
    /// received the prepared context, and no stale copied descriptor may invoke this after slot reuse.
    pub unsafe fn reclaim_unpublished_process_clone_core_stack(
        stack: KernelStack,
    ) -> Result<(), CloneStackReclaimError> {
        let pool = CLONE_STACK_POOL
            .get_or_initialize()
            .map_err(CloneStackReclaimError::StackPool)?;
        // SAFETY: delegated caller contract proves the exact current unpublished allocation.
        unsafe { pool.reclaim(stack) }.map_err(CloneStackReclaimError::Reclaim)
    }

    /// Claims one slot from the already integrated protected Core stack pool and builds the canonical
    /// first-run EL0 context for `loaded` in that exact storage.
    ///
    /// This deliberately reuses the same allocation-free stack owner used by pthread `clone`; it does
    /// not create a leader-only arena or a second stack identity namespace. On every preparation
    /// failure the exact claim is reclaimed before the error escapes. On success the returned
    /// non-Copy [`PreparedInitialUserContext`] is the handoff token to the existing staged scheduler
    /// publication path. After successful scheduler publication, the slot remains allocated until the
    /// scheduler/lifecycle owner returns the exact stack during cancellation or generation-safe reap.
    pub fn prepare_initial_user_with_core_stack(
        loaded: LoadedImage,
    ) -> Result<PreparedInitialUserContext, InitialUserStackError> {
        let pool = CLONE_STACK_POOL
            .get_or_initialize()
            .map_err(InitialUserStackError::StackPool)?;
        let stack = pool.claim().map_err(InitialUserStackError::Stack)?;
        let word_bytes = core::mem::size_of::<u64>() as u64;

        let word_count = if stack.mapped_len % word_bytes == 0
            && stack
                .mapped_start
                .is_multiple_of(core::mem::align_of::<u64>() as u64)
        {
            usize::try_from(stack.mapped_len / word_bytes)
                .map_err(|_| StackPoolError::AddressOverflow)
        } else {
            Err(StackPoolError::InvalidArena)
        };

        let word_count = match word_count {
            Ok(count) => count,
            Err(error) => {
                // SAFETY: `stack` is still the exact unpublished claim made above.
                return match unsafe { pool.reclaim(stack) } {
                    Ok(()) => Err(InitialUserStackError::Stack(error)),
                    Err(reclaim) => Err(InitialUserStackError::Reclaim(reclaim)),
                };
            }
        };

        // SAFETY: the successful pool claim is exclusive and Protected Boot permanently maps exactly
        // this payload RW-NX while keeping its guard page unmapped. No scheduler generation can use
        // the slot until the returned preparation token is explicitly published by its owner.
        let words = unsafe { from_raw_parts_mut(stack.mapped_start as *mut u64, word_count) };
        words.fill(0);
        match prepare_initial_user_context(words, stack, loaded) {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                // SAFETY: context preparation failed before scheduler publication, so this caller
                // still owns the exact current pool allocation and no stale descriptor can race reuse.
                match unsafe { pool.reclaim(stack) } {
                    Ok(()) => Err(InitialUserStackError::Context(error)),
                    Err(reclaim) => Err(InitialUserStackError::Reclaim(reclaim)),
                }
            }
        }
    }

    /// Returns an initial-user stack to the shared Core pool after scheduler/lifecycle ownership ends.
    ///
    /// # Safety
    /// `stack` must be the exact current allocation returned by the generation-safe scheduler
    /// cancellation/reap path for the initial user thread. No copied descriptor from an earlier use of
    /// the same slot may invoke this function after the slot is allocated again.
    pub unsafe fn reclaim_initial_user_core_stack(
        stack: KernelStack,
    ) -> Result<(), InitialUserStackError> {
        let pool = CLONE_STACK_POOL
            .get_or_initialize()
            .map_err(InitialUserStackError::StackPool)?;
        // SAFETY: delegated caller contract is the exact external lifecycle proof required by the
        // underlying allocation-free stack owner.
        unsafe { pool.reclaim(stack) }.map_err(InitialUserStackError::Reclaim)
    }

    /// Returns one published/reaped clone stack to the same protected Core pool that allocated it.
    ///
    /// This is deliberately separate from [`reclaim_initial_user_core_stack`]: a live pthread may
    /// release its stack only after the scheduler has consumed the exact published generation and the
    /// Linux lifecycle/identity owner has consumed the matching `ReapedThreadProof`. Keeping that
    /// ordering in the caller prevents a copied `KernelStack` descriptor from becoming sufficient
    /// authority to recycle a still-owned or stale slot.
    ///
    /// # Safety
    /// `stack` must be the exact `KernelStack` returned by
    /// `CpuSchedulerCell::bootstrap_reap_exited_after_teardown_with_proof` for a published clone
    /// generation. The matching one-shot `ReapedThreadProof` must already have been consumed
    /// successfully through `finalize_reaped_thread_with_identity`. No copied descriptor from this or
    /// an older allocation may invoke this function after the pool slot is released for reuse.
    pub unsafe fn reclaim_reaped_clone_core_stack(
        stack: KernelStack,
    ) -> Result<(), CloneStackReclaimError> {
        let pool = CLONE_STACK_POOL
            .get_or_initialize()
            .map_err(CloneStackReclaimError::StackPool)?;
        // SAFETY: delegated caller contract is exactly the post-reap/post-lifecycle ownership proof
        // required before the private allocation bitmap may make this protected slot reusable.
        unsafe { pool.reclaim(stack) }.map_err(CloneStackReclaimError::Reclaim)
    }

    /// Runs the already integrated Step-15 clone transaction with the one protected Core stack pool.
    ///
    /// The stack provider is deliberately private: this wrapper is the only place that can construct
    /// it, preserving the unsafe low-level pool reclaim contract behind the scheduler's exact staged
    /// cancellation/reap ownership path.
    ///
    /// # Safety
    /// The caller must satisfy `kernal_linux_clone_trap_aarch64::dispatch_clone`'s complete owner
    /// quiescence contract: local IRQs masked, irq_depth=0, preempt_count=0, migration suppressed and
    /// the current Process/TTBR0 binding stable for the entire clone transaction.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn dispatch_clone_with_core_stacks<
        const CAPS: usize,
        const VMAS: usize,
        const OBJECTS: usize,
        const BINDINGS: usize,
        const PROCESSES: usize,
        const IDS: usize,
        const GROUPS: usize,
        const SCHED_THREADS: usize,
        const WAKES: usize,
    >(
        call: MinimumRuntimeCall,
        frame: &mut ExceptionFrame,
        process: &mut Process<CAPS>,
        address_space: &BoundProcessAddressSpace<VMAS>,
        objects: &mut ObjectTable<OBJECTS>,
        bindings: &mut ThreadObjectBindings<BINDINGS>,
        identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
        exits: &ExitCoordinator<GROUPS>,
        scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
        priority: u8,
    ) -> Result<(), CloneDispatchError> {
        let pool = CLONE_STACK_POOL
            .get_or_initialize()
            .map_err(CloneDispatchError::StackPool)?;
        let mut stacks = CoreCloneStackProvider { pool };
        // SAFETY: delegated caller contract is exactly the underlying clone transaction contract;
        // the private provider adds no scheduler, Process, address-space or usercopy authority.
        unsafe {
            kernal_linux_clone_trap_aarch64::dispatch_clone(
                call,
                frame,
                process,
                address_space,
                objects,
                bindings,
                identities,
                exits,
                scheduler,
                &mut stacks,
                priority,
            )
        }
        .map_err(CloneDispatchError::Runtime)
    }

    fn linker_clone_arena() -> Result<(u64, u64, u64), CloneStackInitError> {
        unsafe extern "C" {
            static __clone_stacks_bottom: u8;
            static __clone_stacks_top: u8;
        }

        let start = core::ptr::addr_of!(__clone_stacks_bottom) as u64;
        let end = core::ptr::addr_of!(__clone_stacks_top) as u64;
        if start == 0
            || end <= start
            || !is_kernel_high_half(start)
            || !is_kernel_high_half(end - 1)
        {
            return Err(CloneStackInitError::LinkerContract);
        }

        let span = end
            .checked_sub(start)
            .ok_or(CloneStackInitError::LinkerContract)?;
        let count =
            u64::try_from(CLONE_STACK_CAPACITY).map_err(|_| CloneStackInitError::LinkerContract)?;
        if span % count != 0 {
            return Err(CloneStackInitError::LinkerContract);
        }
        let stride = span / count;
        if stride == 0
            || start.checked_add(
                stride
                    .checked_mul(count)
                    .ok_or(CloneStackInitError::LinkerContract)?,
            ) != Some(end)
        {
            return Err(CloneStackInitError::LinkerContract);
        }
        Ok((start, end, stride))
    }

    const fn is_kernel_high_half(address: u64) -> bool {
        address >= 0xffff_0000_0000_0000
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod initial_leader;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use clone_stack::{
    CLONE_STACK_CAPACITY, CloneDispatchError, CloneStackInitError, CloneStackReclaimError,
    InitialUserStackError, PreparedProcessCloneStack, ProcessCloneStackError,
    dispatch_clone_with_core_stacks, prepare_initial_user_with_core_stack,
    prepare_process_clone_with_core_stack, reclaim_initial_user_core_stack,
    reclaim_reaped_clone_core_stack, reclaim_unpublished_process_clone_core_stack,
};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use initial_leader::{
    InitialLeaderPublishError, PublishedInitialLinuxLeader,
    publish_initial_linux_leader_with_core_stack,
};
