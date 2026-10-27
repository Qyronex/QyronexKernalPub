// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod exit_split;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_percpu::CpuIndex;
use kernal_scheduler::RunQueue;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use kernal_scheduler::{ThreadId, ThreadState};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernal_scheduler_smp::DrainReport;
use kernal_scheduler_smp::{GlobalThreadId, ReapedThreadProof, RemoteWakeQueue};
use kernal_thread_context::ContextTable;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use kernal_thread_context::KernelStack;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized,
    InitializationInProgress,
    NotInitialized,
    WrongOwner,
    InterruptsEnabled,
    WrongIrqDepth,
    Busy,
    NoCurrentThread,
    NoRunnableThread,
    Invariant,
    PreemptState,
    Scheduler(kernal_scheduler::Error),
    Context(kernal_thread_context::Error),
    Wake(kernal_scheduler_smp::Error),
}

pub struct CpuSchedulerCell<const THREADS: usize, const WAKES: usize> {
    state: AtomicU8,
    owner: UnsafeCell<CpuIndex>,
    run_queue: UnsafeCell<MaybeUninit<RunQueue<THREADS>>>,
    contexts: UnsafeCell<MaybeUninit<ContextTable<THREADS>>>,
    wakes: UnsafeCell<MaybeUninit<RemoteWakeQueue<WAKES>>>,
}

// SAFETY: RunQueue and ContextTable mutation is exposed only through owner-checked local APIs.
// Thread-context mutation closes local IRQ/preemption reentrancy first. The dedicated IRQ drain
// is permitted only at irq_depth=1 with local maskable IRQs disabled; bootstrap mutation on either primary architecture
// requires local IRQs masked and preemption/IRQ depth zero. Foreign CPUs only touch wake atomics.
unsafe impl<const T: usize, const W: usize> Sync for CpuSchedulerCell<T, W> {}

impl<const THREADS: usize, const WAKES: usize> CpuSchedulerCell<THREADS, WAKES> {
    const EMPTY: u8 = 0;
    const INITIALIZING: u8 = 1;
    const READY: u8 = 2;

    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(Self::EMPTY),
            owner: UnsafeCell::new(CpuIndex(0)),
            run_queue: UnsafeCell::new(MaybeUninit::uninit()),
            contexts: UnsafeCell::new(MaybeUninit::uninit()),
            wakes: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn prepare(&'static self, owner: CpuIndex) -> Result<(), Error> {
        match self.state.compare_exchange(
            Self::EMPTY,
            Self::INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(Self::INITIALIZING) => return Err(Error::InitializationInProgress),
            Err(_) => return Err(Error::AlreadyInitialized),
        }
        // SAFETY: successful state transition gives this call exclusive initialization access.
        unsafe {
            *self.owner.get() = owner;
            (*self.run_queue.get()).write(RunQueue::new());
            (*self.contexts.get()).write(ContextTable::new());
            (*self.wakes.get()).write(RemoteWakeQueue::new(owner));
        }
        self.state.store(Self::READY, Ordering::Release);
        Ok(())
    }

    pub fn owner(&self) -> Result<CpuIndex, Error> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return Err(Error::NotInitialized);
        }
        // SAFETY: READY freezes owner forever.
        Ok(unsafe { *self.owner.get() })
    }

    pub fn remote_wake(&self, id: GlobalThreadId) -> Result<(), Error> {
        self.wakes()?.push(id).map_err(Error::Wake)
    }

    /// Returns the exact globally-owned scheduler generation currently executing on this CPU/PE.
    ///
    /// The returned identity is suitable for generation-bound wait registration only while the
    /// caller continues to hold the same owner/quiescence window. In particular, futex code must
    /// keep local IRQ/wake draining closed from waiter prepare/commit through the subsequent
    /// [`Self::bootstrap_block_current_and_switch`] call.
    ///
    /// # Safety
    /// Must run on the owner CPU/PE with local IRQs masked, irq_depth=0 and preempt_count=0.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_current_global_thread(&'static self) -> Result<GlobalThreadId, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        // SAFETY: owner quiescence prevents local queue/context mutation during validation.
        let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
        // SAFETY: same owner-only observation contract.
        let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
        if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
            || contexts
                .publication_state(current)
                .map_err(Error::Context)?
                != kernal_thread_context::PublicationState::Published
        {
            return Err(Error::Invariant);
        }
        Ok(GlobalThreadId::new(self.owner()?, current))
    }

    /// Runs a normal x86 thread-context owner operation with local interrupts and preemption disabled.
    ///
    /// # Safety
    /// Must execute at CPL0 after GS CpuLocal installation. NMI/MCE handlers must not call this and
    /// the closure must not retain references or context-switch while borrowed tables are live.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn with_local<R>(
        &'static self,
        operation: impl FnOnce(
            &mut RunQueue<THREADS>,
            &mut ContextTable<THREADS>,
            &RemoteWakeQueue<WAKES>,
        ) -> R,
    ) -> Result<R, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_local()? };
        // SAFETY: CPL0 and same CPU; saves IF and closes local IRQ reentrancy.
        let irq_state = unsafe { kernal_irq_state_x86_64::save_and_disable() };
        local.preempt_disable();

        // SAFETY: owner + IRQ-off + preemption-disabled establishes exclusive local mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner contract applies to context metadata.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        // SAFETY: mailbox is immutable after READY; its internals are atomic.
        let wakes = unsafe { (&*self.wakes.get()).assume_init_ref() };
        let result = operation(run_queue, contexts, wakes);

        let preempt_result = local.preempt_enable();
        // SAFETY: restores exactly the saved local interrupt state.
        unsafe { kernal_irq_state_x86_64::restore(irq_state) };
        if preempt_result.is_err() {
            return Err(Error::PreemptState);
        }
        Ok(result)
    }

    /// Drains already-published remote wakes directly from a first-level maskable IRQ on the owner CPU/PE.
    ///
    /// # Safety
    /// Must run from the owner CPU/PE's first-level maskable IRQ handler after `enter_irq()` and
    /// before `exit_irq()`. Local maskable IRQs must be disabled, `irq_depth` exactly 1 and the
    /// preemption count zero.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn drain_remote_wakes_from_irq(
        &'static self,
        maximum: usize,
    ) -> Result<DrainReport, Error> {
        // SAFETY: delegated current-CPU/PE owner contract.
        let local = unsafe { self.bootstrap_local()? };
        #[cfg(target_arch = "x86_64")]
        // SAFETY: CPL0 observation only.
        if unsafe { kernal_irq_state_x86_64::enabled() } {
            return Err(Error::InterruptsEnabled);
        }
        #[cfg(target_arch = "aarch64")]
        if !kernal_arch_aarch64::irqs_masked() {
            return Err(Error::InterruptsEnabled);
        }
        if local.irq_depth() != 1 {
            return Err(Error::WrongIrqDepth);
        }
        if local.preempt_count() != 0 {
            return Err(Error::Busy);
        }

        // SAFETY: first-level maskable IRQ + IF=0 cannot overlap local thread-context mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: READY freezes mailbox object; slots are atomic.
        let wakes = unsafe { (&*self.wakes.get()).assume_init_ref() };
        wakes.drain_into(run_queue, maximum).map_err(Error::Wake)
    }

    /// Adopts the currently executing bootstrap stack as this CPU's initial Running thread.
    ///
    /// # Safety
    /// Must run on the owner CPU/PE with local IRQs masked, irq_depth=0 and preempt_count=0.
    /// `saved_sp` must lie inside `stack` and identify the current live kernel stack.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_adopt_current(
        &'static self,
        priority: u8,
        saved_sp: u64,
        stack: KernelStack,
        address_space: u64,
    ) -> Result<ThreadId, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        if local.current_thread() != 0 {
            return Err(Error::Invariant);
        }

        // SAFETY: bootstrap quiescence establishes exclusive owner mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same exclusive owner contract.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        let id = run_queue.create(priority).map_err(Error::Scheduler)?;
        if let Err(error) = contexts.insert(id, saved_sp, stack, address_space) {
            rollback_new_thread(run_queue, id)?;
            return Err(Error::Context(error));
        }
        if let Err(error) = run_queue.make_ready(id) {
            let _ = contexts.remove(id);
            rollback_new_thread(run_queue, id)?;
            return Err(Error::Scheduler(error));
        }
        let selected = run_queue.schedule().map_err(Error::Scheduler)?;
        if selected != Some(id) {
            return Err(Error::Invariant);
        }
        local.set_current_thread(pack_thread(id));
        // SAFETY: this freshly adopted bootstrap/kernel context owns TLS value zero in ContextTable.
        unsafe { install_user_thread_pointer(0) };
        Ok(id)
    }

    /// Creates one exact scheduler generation and generation-owned metadata without publishing it to
    /// the Ready queue. This is the transactional creation boundary required by clone/thread setup:
    /// every fallible Process/TID/usercopy step may complete while the generation remains both
    /// scheduler-Blocked and `ContextTable::Staged`.
    ///
    /// TLS and optional clear-child-tid metadata are installed before this method returns, so later
    /// external setup never needs direct access to the private ContextTable. The generation can be
    /// consumed only by [`Self::bootstrap_publish_staged_ready`] or
    /// [`Self::bootstrap_cancel_staged`].
    ///
    /// # Safety
    /// Same owner/quiescence contract as `bootstrap_adopt_current`. `saved_sp` must point at a valid
    /// initial architecture context inside `stack`. `user_thread_pointer` and `clear_child_tid` must
    /// already have been validated by the architecture/Linux clone policy for this exact child.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bootstrap_create_staged_user_thread(
        &'static self,
        priority: u8,
        saved_sp: u64,
        stack: KernelStack,
        address_space: u64,
        user_thread_pointer: u64,
        clear_child_tid: Option<u64>,
    ) -> Result<ThreadId, Error> {
        // SAFETY: delegated caller contract; validating the local also proves owner/quiescence.
        let _local = unsafe { self.bootstrap_quiescent_local()? };
        // SAFETY: owner-quiescent mutation of both tables.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only contract.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        create_staged_user_thread(
            run_queue,
            contexts,
            priority,
            saved_sp,
            stack,
            address_space,
            user_thread_pointer,
            clear_child_tid,
        )
    }

    /// Final no-user-memory commit for one exact staged generation.
    ///
    /// All fallible external clone setup, including Process/Thread authority, Linux TID allocation and
    /// CLONE_PARENT_SETTID usercopy, must complete before this call. The helper first makes the exact
    /// Blocked generation Ready while owner-quiescent, then consumes the one-way Staged publication.
    /// If publication unexpectedly fails, Ready is rolled back to Blocked before the error escapes.
    /// Success has no further fallible step: the child is simultaneously Ready and Published.
    ///
    /// # Safety
    /// Same owner/quiescence contract as staged creation. Caller must own all external child state and
    /// guarantee that aborting after a successful return is no longer required.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_publish_staged_ready(&'static self, id: ThreadId) -> Result<(), Error> {
        // SAFETY: delegated caller contract.
        let _local = unsafe { self.bootstrap_quiescent_local()? };
        // SAFETY: owner-quiescent mutation of both tables.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only contract.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        publish_staged_ready(run_queue, contexts, id)
    }

    /// Cancels exactly one never-published staged generation and returns its kernel stack metadata.
    ///
    /// This is the only creation rollback that may discard staged TLS/clear-child-tid metadata without
    /// touching user memory: the child was never Ready/Running and therefore never acquired normal
    /// published cleanup obligations. A Published or non-Blocked generation is rejected.
    ///
    /// # Safety
    /// Same owner/quiescence contract as staged creation. Caller must have already rolled back any
    /// external Process/Thread/TID authority associated with `id` and must prove the generation was
    /// never successfully published.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_cancel_staged(
        &'static self,
        id: ThreadId,
    ) -> Result<KernelStack, Error> {
        // SAFETY: delegated caller contract.
        let _local = unsafe { self.bootstrap_quiescent_local()? };
        // SAFETY: owner-quiescent mutation of both tables.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only contract.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        cancel_staged_user_thread(run_queue, contexts, id)
    }

    /// Inserts a non-running bootstrap thread whose initial architecture context is already built.
    ///
    /// Existing kernel/bootstrap callers retain immediate Published+Ready behavior. Clone/thread
    /// creation with externally fallible setup must use the staged APIs above instead.
    ///
    /// # Safety
    /// Same owner/quiescence contract as `bootstrap_adopt_current`. `saved_sp` must point at a valid
    /// initial context frame inside `stack` for the active architecture's context-switch routine.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_create_ready(
        &'static self,
        priority: u8,
        saved_sp: u64,
        stack: KernelStack,
        address_space: u64,
    ) -> Result<ThreadId, Error> {
        // SAFETY: delegated caller contract; validating the local also proves ownership.
        let _local = unsafe { self.bootstrap_quiescent_local()? };
        // SAFETY: quiescent owner-only mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only mutation.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        let id = run_queue.create(priority).map_err(Error::Scheduler)?;
        if let Err(error) = contexts.insert(id, saved_sp, stack, address_space) {
            rollback_new_thread(run_queue, id)?;
            return Err(Error::Context(error));
        }
        if let Err(error) = run_queue.make_ready(id) {
            let _ = contexts.remove(id);
            rollback_new_thread(run_queue, id)?;
            return Err(Error::Scheduler(error));
        }
        Ok(id)
    }

    /// Cooperatively yields current to the highest-priority ready local thread.
    ///
    /// AArch64 saves the current hardware TPIDR_EL0 into the exact generation before selecting the
    /// next context, then installs the selected generation's stored value before the stack switch.
    ///
    /// # Safety
    /// Must run on the owner CPU/PE with local IRQs masked, irq_depth=0 and preempt_count=0.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_yield(&'static self) -> Result<ThreadId, Error> {
        // SAFETY: delegated caller contract is unchanged; no destination activation is requested.
        unsafe { self.bootstrap_yield_inner(None) }
    }

    /// Cooperatively yields while requiring caller-owned activation of the exact selected AArch64
    /// destination address space after scheduler/context borrows end and before the stack switch.
    ///
    /// The callback receives only the exact destination scheduler generation and its opaque
    /// generation-bound ContextTable address-space token. It must either complete the canonical
    /// owner activation or fail closed/non-returning; scheduler selection is already committed when
    /// this boundary is reached, so returning after a failed activation is forbidden.
    ///
    /// # Safety
    /// Same owner/quiescence contract as [`Self::bootstrap_yield`]. The callback must not re-enter
    /// this scheduler cell, retain supplied scalar observations as authority, or return unless the
    /// destination address space is active for the selected generation.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_yield_with_destination_address_space(
        &'static self,
        activate_destination: fn(GlobalThreadId, u64),
    ) -> Result<ThreadId, Error> {
        // SAFETY: delegated caller contract plus the stricter callback contract above.
        unsafe { self.bootstrap_yield_inner(Some(activate_destination)) }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    unsafe fn bootstrap_yield_inner(
        &'static self,
        activate_destination: Option<fn(GlobalThreadId, u64)>,
    ) -> Result<ThreadId, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let owner = self.owner()?;
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;

        let (old_sp_ptr, next_sp, next, next_tls, next_address_space) = {
            // SAFETY: quiescent owner-only mutation.
            let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
            // SAFETY: same owner-only mutation.
            let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
            if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
                || contexts
                    .publication_state(current)
                    .map_err(Error::Context)?
                    != kernal_thread_context::PublicationState::Published
            {
                return Err(Error::Invariant);
            }
            // SAFETY: owner/quiescence binds the sampled hardware register to `current`.
            unsafe { capture_user_thread_pointer(contexts, current)? };
            run_queue.yield_running(current).map_err(Error::Scheduler)?;
            let next = run_queue
                .schedule()
                .map_err(Error::Scheduler)?
                .ok_or(Error::NoRunnableThread)?;
            if next == current {
                local.set_current_thread(pack_thread(current));
                return Ok(current);
            }
            if contexts.publication_state(next).map_err(Error::Context)?
                != kernal_thread_context::PublicationState::Published
            {
                return Err(Error::Invariant);
            }
            let old_sp_ptr = {
                let context = contexts.get_mut(current).map_err(Error::Context)?;
                core::ptr::addr_of_mut!(context.saved_rsp)
            };
            let next_sp = contexts.get(next).map_err(Error::Context)?.saved_rsp;
            let next_tls = contexts.user_thread_pointer(next).map_err(Error::Context)?;
            let next_address_space = contexts.get(next).map_err(Error::Context)?.address_space;
            (old_sp_ptr, next_sp, next, next_tls, next_address_space)
        };

        if let Some(activate_destination) = activate_destination {
            activate_destination(GlobalThreadId::new(owner, next), next_address_space);
        }
        local.set_current_thread(pack_thread(next));
        // SAFETY: exact next-generation metadata was resolved while owner-quiescent.
        unsafe { install_user_thread_pointer(next_tls) };
        // SAFETY: all Rust references into scheduler tables ended before the architecture switch.
        unsafe { switch_context(old_sp_ptr, next_sp) };

        let observed = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        if observed != current {
            return Err(Error::Invariant);
        }
        Ok(current)
    }

    /// Blocks the exact current published generation and switches to one already-ready peer.
    ///
    /// This is the scheduler-owned transition required by FUTEX_WAIT after its Prepared/Committed
    /// handshake. The caller supplies the exact `GlobalThreadId` used for wait registration. The
    /// method refuses a different CPU, slot or generation before changing scheduler state. Remote
    /// wake producers may enqueue while this runs, but the caller's IRQ-masked owner window must keep
    /// wake draining closed until `current` has become Blocked and the replacement is selected.
    ///
    /// On AArch64, live TPIDR_EL0 is saved into the exact outgoing generation and the selected
    /// generation's stored TPIDR_EL0 is installed before the existing architecture switch. If no
    /// replacement is runnable, the method returns `NoRunnableThread` while the current generation
    /// remains Running, allowing the futex owner to cancel/roll back its committed waiter.
    ///
    /// When a later wake makes the blocked generation Ready and the scheduler selects it again, the
    /// suspended kernel context resumes here and this method returns the same exact global identity.
    ///
    /// # Safety
    /// Must execute on `expected_current.cpu` with local IRQs masked, irq_depth=0 and preempt_count=0.
    /// The caller must own the local scheduler switch window continuously from any external wait
    /// commit through this call. It must not drain local/remote wakes until this transition has either
    /// returned an error before blocking or switched away from the newly Blocked generation.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_block_current_and_switch(
        &'static self,
        expected_current: GlobalThreadId,
    ) -> Result<GlobalThreadId, Error> {
        // SAFETY: delegated caller contract is unchanged; no destination activation is requested.
        unsafe { self.bootstrap_block_current_and_switch_inner(expected_current, None) }
    }

    /// Blocks current and switches only after caller-owned activation of the exact selected AArch64
    /// destination address space.
    ///
    /// The activation callback is invoked after all scheduler/context borrows end and before CpuLocal,
    /// TPIDR_EL0 and stack transfer expose the selected generation. A callback that cannot establish
    /// the exact destination binding must fail closed/non-returning.
    ///
    /// # Safety
    /// Same owner/quiescence and committed-wait contract as
    /// [`Self::bootstrap_block_current_and_switch`]. The callback must not re-enter this scheduler.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_block_current_and_switch_with_destination_address_space(
        &'static self,
        expected_current: GlobalThreadId,
        activate_destination: fn(GlobalThreadId, u64),
    ) -> Result<GlobalThreadId, Error> {
        // SAFETY: delegated caller contract plus the stricter callback contract above.
        unsafe {
            self.bootstrap_block_current_and_switch_inner(
                expected_current,
                Some(activate_destination),
            )
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    unsafe fn bootstrap_block_current_and_switch_inner(
        &'static self,
        expected_current: GlobalThreadId,
        activate_destination: Option<fn(GlobalThreadId, u64)>,
    ) -> Result<GlobalThreadId, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let owner = self.owner()?;
        if expected_current.cpu != owner {
            return Err(Error::WrongOwner);
        }
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        if current != expected_current.local {
            return Err(Error::Invariant);
        }

        let (old_sp_ptr, next_sp, next, next_tls, next_address_space) = {
            // SAFETY: owner/quiescence establishes exclusive mutation of both tables.
            let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
            // SAFETY: same owner-only mutation contract.
            let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
            if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
                || contexts
                    .publication_state(current)
                    .map_err(Error::Context)?
                    != kernal_thread_context::PublicationState::Published
            {
                return Err(Error::Invariant);
            }

            // Save user TLS before selecting another exact generation. This metadata update is safe
            // even if no runnable peer exists because the current generation remains Running.
            // SAFETY: owner/quiescence binds the sampled hardware register to `current`.
            unsafe { capture_user_thread_pointer(contexts, current)? };

            // `schedule` does not mutate when no Ready work exists. If it selects a peer, keep current
            // Running until every selected-context lookup succeeds so any pre-block failure can put
            // that selected peer back on Ready and leave the caller running.
            let next = run_queue
                .schedule()
                .map_err(Error::Scheduler)?
                .ok_or(Error::NoRunnableThread)?;
            if next == current {
                return Err(Error::Invariant);
            }
            let next_metadata = (|| -> Result<(u64, u64, u64), Error> {
                if contexts.publication_state(next).map_err(Error::Context)?
                    != kernal_thread_context::PublicationState::Published
                {
                    return Err(Error::Invariant);
                }
                let next_sp = contexts.get(next).map_err(Error::Context)?.saved_rsp;
                let next_tls = contexts.user_thread_pointer(next).map_err(Error::Context)?;
                let next_address_space = contexts.get(next).map_err(Error::Context)?.address_space;
                Ok((next_sp, next_tls, next_address_space))
            })();
            let (next_sp, next_tls, next_address_space) = match next_metadata {
                Ok(metadata) => metadata,
                Err(error) => {
                    // Selected peer is still Running only inside this owner-exclusive critical
                    // section; make_ready accepts Running and restores its prior Ready visibility.
                    run_queue.make_ready(next).map_err(Error::Scheduler)?;
                    return Err(error);
                }
            };

            let old_sp_ptr = match contexts.get_mut(current) {
                Ok(context) => core::ptr::addr_of_mut!(context.saved_rsp),
                Err(error) => {
                    // `schedule()` already made `next` Running. Restore that peer before exposing the
                    // lookup failure so the caller never observes two logical Running generations.
                    run_queue.make_ready(next).map_err(Error::Scheduler)?;
                    return Err(Error::Context(error));
                }
            };
            if let Err(error) = run_queue.block(current) {
                // Current was prevalidated Running, so this is an internal scheduler failure. Restore
                // the selected peer to Ready before returning so a caller never sees two Running
                // generations after an error.
                run_queue.make_ready(next).map_err(Error::Scheduler)?;
                return Err(Error::Scheduler(error));
            }
            (old_sp_ptr, next_sp, next, next_tls, next_address_space)
        };

        if let Some(activate_destination) = activate_destination {
            activate_destination(GlobalThreadId::new(owner, next), next_address_space);
        }
        local.set_current_thread(pack_thread(next));
        // SAFETY: exact next-generation TLS was resolved under owner quiescence and table borrows end.
        unsafe { install_user_thread_pointer(next_tls) };
        // SAFETY: current is Blocked and the selected generation is Running before stack exchange.
        unsafe { switch_context(old_sp_ptr, next_sp) };

        let observed = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        if observed != current {
            return Err(Error::Invariant);
        }
        Ok(GlobalThreadId::new(owner, current))
    }

    /// Marks current Exited and switches to the next ready local thread.
    ///
    /// Successful switching must never return to the Exited thread. The selected generation's TLS
    /// is installed before the stack switch; the dead generation does not need another user TLS save.
    /// If no successor is runnable, or successor metadata cannot be validated, this returns without
    /// changing the current generation from Running. Any peer selected during failed validation is
    /// restored to Ready before the error is exposed.
    ///
    /// This legacy monolithic path is valid only when no generation-owned clear-child-tid cleanup is
    /// pending. Clone/pthread generations carrying `CLONE_CHILD_CLEARTID` must use the dedicated
    /// cleanup transaction in `exit_split`, which keeps the exiting process/TTBR0 active through the
    /// zero-store and private futex wake before selecting the successor.
    ///
    /// # Safety
    /// Same quiescent owner contract as `bootstrap_yield`.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_exit_current_and_switch(&'static self) -> Result<(), Error> {
        // SAFETY: delegated caller contract is unchanged; no destination activation is requested.
        unsafe { self.bootstrap_exit_current_and_switch_inner(None) }
    }

    /// Exits current and switches only after caller-owned activation of the exact selected AArch64
    /// destination address space. Activation failure is post-exit and therefore must not return.
    ///
    /// # Safety
    /// Same owner/quiescence contract as [`Self::bootstrap_exit_current_and_switch`]. The callback
    /// must either activate the exact destination generation or fail closed/non-returning.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_exit_current_and_switch_with_destination_address_space(
        &'static self,
        activate_destination: fn(GlobalThreadId, u64),
    ) -> Result<(), Error> {
        // SAFETY: delegated caller contract plus the stricter callback contract above.
        unsafe { self.bootstrap_exit_current_and_switch_inner(Some(activate_destination)) }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    unsafe fn bootstrap_exit_current_and_switch_inner(
        &'static self,
        activate_destination: Option<fn(GlobalThreadId, u64)>,
    ) -> Result<(), Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let owner = self.owner()?;
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;

        let (old_sp_ptr, next_sp, next, next_tls, next_address_space) = {
            // SAFETY: owner-only quiescent contract.
            let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
            // SAFETY: same owner-only contract.
            let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
            prepare_exit_switch(run_queue, contexts, current)?
        };

        if let Some(activate_destination) = activate_destination {
            activate_destination(GlobalThreadId::new(owner, next), next_address_space);
        }
        local.set_current_thread(pack_thread(next));
        // SAFETY: exact next-generation metadata was resolved under owner quiescence.
        unsafe { install_user_thread_pointer(next_tls) };
        // SAFETY: current is Exited and remains context-owned until destination thread reaps it.
        unsafe { switch_context(old_sp_ptr, next_sp) };
        Err(Error::Invariant)
    }

    /// Removes context metadata for an Exited thread and advances the scheduler slot generation.
    ///
    /// Resource teardown is deliberately not performed here. If the thread owns dynamically mapped
    /// stack pages, the caller must unmap/free them before invoking this method. A bootstrap proof
    /// backed by permanently reserved static memory has no dynamic stack resource to tear down.
    ///
    /// `ContextTable::remove` also enforces the generation-owned clear-child-tid obligation. A
    /// published Exited generation with pending user cleanup therefore cannot reach scheduler reap.
    ///
    /// # Safety
    /// Must run on the owner CPU/PE with local IRQs masked and the expected current thread active.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_reap_exited_after_teardown(
        &'static self,
        exited: ThreadId,
        expected_current: ThreadId,
    ) -> Result<KernelStack, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let observed = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        if observed != expected_current || exited == expected_current {
            return Err(Error::Invariant);
        }

        // SAFETY: quiescent owner-only mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only mutation.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        reap_exited_context_with(run_queue, contexts, exited, |run_queue, id| {
            run_queue.reap(id)
        })
    }

    /// Removes an Exited thread through the owner-checked CpuSchedulerCell path and returns an exact
    /// scheduler reap attestation for `{owner CPU, slot, generation}` together with the reclaimed
    /// stack metadata.
    ///
    /// This is the production bridge required by process/object teardown: safe process cleanup can
    /// consume the returned [`ReapedThreadProof`] instead of inferring reaping from an arbitrary
    /// `RunQueue`. The proof is minted only after this cell has validated the current CPU owner,
    /// quiescent IRQ/preemption state, removed the thread context, and successfully advanced the
    /// scheduler slot generation.
    ///
    /// # Safety
    /// Same owner/quiescence and prior-resource-teardown contract as
    /// [`Self::bootstrap_reap_exited_after_teardown`].
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_reap_exited_after_teardown_with_proof(
        &'static self,
        exited: ThreadId,
        expected_current: ThreadId,
    ) -> Result<(KernelStack, ReapedThreadProof), Error> {
        let owner = self.owner()?;
        // SAFETY: delegated caller contract is identical to the wrapped owner-checked reap path.
        let stack = unsafe { self.bootstrap_reap_exited_after_teardown(exited, expected_current)? };
        // SAFETY: the exact `exited` generation was successfully reaped by this frozen-owner cell
        // immediately above, after the method revalidated current-CPU ownership and quiescence.
        let proof = unsafe { ReapedThreadProof::new_unchecked(GlobalThreadId::new(owner, exited)) };
        Ok((stack, proof))
    }

    #[cfg(target_arch = "x86_64")]
    pub unsafe fn drain_remote_wakes(&'static self, maximum: usize) -> Result<DrainReport, Error> {
        // SAFETY: delegated caller contract for thread-context use.
        unsafe {
            self.with_local(|run_queue, _contexts, wakes| wakes.drain_into(run_queue, maximum))
        }?
        .map_err(Error::Wake)
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn bootstrap_local(
        &'static self,
    ) -> Result<&'static kernal_percpu_x86_64::CpuLocal, Error> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return Err(Error::NotInitialized);
        }
        // SAFETY: caller guarantees GS CpuLocal is installed.
        let local = unsafe { kernal_percpu_x86_64::current() };
        if local.index() != self.owner()? {
            return Err(Error::WrongOwner);
        }
        Ok(local)
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn bootstrap_local(
        &'static self,
    ) -> Result<&'static kernal_percpu_aarch64::CpuLocal, Error> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return Err(Error::NotInitialized);
        }
        // SAFETY: caller guarantees TPIDR_EL1 contains this PE's published CpuLocal.
        let local = unsafe { kernal_percpu_aarch64::current() };
        if local.index() != self.owner()? {
            return Err(Error::WrongOwner);
        }
        Ok(local)
    }

    #[cfg(target_arch = "x86_64")]
    unsafe fn bootstrap_quiescent_local(
        &'static self,
    ) -> Result<&'static kernal_percpu_x86_64::CpuLocal, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_local()? };
        // SAFETY: caller is CPL0; this only observes RFLAGS.IF.
        if unsafe { kernal_irq_state_x86_64::enabled() } {
            return Err(Error::InterruptsEnabled);
        }
        if local.preempt_count() != 0 || local.irq_depth() != 0 {
            return Err(Error::Busy);
        }
        Ok(local)
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn bootstrap_quiescent_local(
        &'static self,
    ) -> Result<&'static kernal_percpu_aarch64::CpuLocal, Error> {
        // SAFETY: delegated caller contract.
        let local = unsafe { self.bootstrap_local()? };
        if !kernal_arch_aarch64::irqs_masked() {
            return Err(Error::InterruptsEnabled);
        }
        if local.preempt_count() != 0 || local.irq_depth() != 0 {
            return Err(Error::Busy);
        }
        Ok(local)
    }

    fn wakes(&self) -> Result<&RemoteWakeQueue<WAKES>, Error> {
        if self.state.load(Ordering::Acquire) != Self::READY {
            return Err(Error::NotInitialized);
        }
        // SAFETY: READY publishes initialized mailbox object; slots are atomic.
        Ok(unsafe { (&*self.wakes.get()).assume_init_ref() })
    }
}

impl<const T: usize, const W: usize> Default for CpuSchedulerCell<T, W> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn pack_thread(id: ThreadId) -> u64 {
    id.slot as u64 | ((id.generation as u64) << 16)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn unpack_thread(value: u64) -> Option<ThreadId> {
    if value == 0 {
        return None;
    }
    let id = ThreadId {
        slot: value as u16,
        generation: (value >> 16) as u16,
    };
    (id.generation != 0).then_some(id)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[allow(clippy::too_many_arguments)]
fn create_staged_user_thread<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    priority: u8,
    saved_sp: u64,
    stack: KernelStack,
    address_space: u64,
    user_thread_pointer: u64,
    clear_child_tid: Option<u64>,
) -> Result<ThreadId, Error> {
    let id = run_queue.create(priority).map_err(Error::Scheduler)?;
    if let Err(error) = contexts.insert_staged(id, saved_sp, stack, address_space) {
        rollback_new_thread(run_queue, id)?;
        return Err(Error::Context(error));
    }
    if let Err(error) = contexts.update_user_thread_pointer(id, user_thread_pointer) {
        return Err(rollback_staged_setup_error(run_queue, contexts, id, error));
    }
    if let Some(user_address) = clear_child_tid
        && let Err(error) = contexts.initialize_clear_child_tid(id, user_address)
    {
        return Err(rollback_staged_setup_error(run_queue, contexts, id, error));
    }
    Ok(id)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn rollback_staged_setup_error<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    id: ThreadId,
    setup_error: kernal_thread_context::Error,
) -> Error {
    match cancel_staged_user_thread(run_queue, contexts, id) {
        Ok(_) => Error::Context(setup_error),
        Err(error) => error,
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn publish_staged_ready<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    id: ThreadId,
) -> Result<(), Error> {
    if run_queue.state(id).map_err(Error::Scheduler)? != ThreadState::Blocked
        || contexts.publication_state(id).map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Staged
    {
        return Err(Error::Invariant);
    }

    run_queue.make_ready(id).map_err(Error::Scheduler)?;
    if let Err(error) = contexts.publish(id) {
        if run_queue.block(id).is_err() {
            return Err(Error::Invariant);
        }
        return Err(Error::Context(error));
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn cancel_staged_user_thread<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    id: ThreadId,
) -> Result<KernelStack, Error> {
    cancel_staged_user_thread_with(run_queue, contexts, id, |contexts, id| {
        contexts.remove_staged(id)
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn cancel_staged_user_thread_with<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    id: ThreadId,
    remove_staged: impl FnOnce(
        &mut ContextTable<THREADS>,
        ThreadId,
    ) -> Result<
        kernal_thread_context::ThreadContext,
        kernal_thread_context::Error,
    >,
) -> Result<KernelStack, Error> {
    if run_queue.state(id).map_err(Error::Scheduler)? != ThreadState::Blocked
        || contexts.publication_state(id).map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Staged
    {
        return Err(Error::Invariant);
    }

    let user_thread_pointer = contexts
        .user_thread_pointer(id)
        .map_err(|_| Error::Invariant)?;
    let clear_child_tid = contexts
        .pending_clear_child_tid(id)
        .map_err(|_| Error::Invariant)?;
    let context = remove_staged(contexts, id).map_err(|_| Error::Invariant)?;

    if let Err(error) = run_queue.exit(id) {
        restore_staged_context(contexts, context, user_thread_pointer, clear_child_tid)?;
        return Err(Error::Scheduler(error));
    }
    if let Err(error) = run_queue.reap(id) {
        // The generation is fail-closed Exited if this impossible post-exit reap fails. Restore the
        // exact staged metadata so stack/TLS/clear-tid ownership is not lost to later diagnostics or
        // owner recovery, but never recreate scheduler visibility here.
        restore_staged_context(contexts, context, user_thread_pointer, clear_child_tid)?;
        return Err(Error::Scheduler(error));
    }
    Ok(context.stack)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn restore_staged_context<const THREADS: usize>(
    contexts: &mut ContextTable<THREADS>,
    context: kernal_thread_context::ThreadContext,
    user_thread_pointer: u64,
    clear_child_tid: Option<u64>,
) -> Result<(), Error> {
    contexts
        .insert_staged(
            context.id,
            context.saved_rsp,
            context.stack,
            context.address_space,
        )
        .map_err(|_| Error::Invariant)?;
    contexts
        .update_user_thread_pointer(context.id, user_thread_pointer)
        .map_err(|_| Error::Invariant)?;
    if let Some(user_address) = clear_child_tid {
        contexts
            .initialize_clear_child_tid(context.id, user_address)
            .map_err(|_| Error::Invariant)?;
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn prepare_exit_switch<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    current: ThreadId,
) -> Result<(*mut u64, u64, ThreadId, u64, u64), Error> {
    if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
        || contexts
            .publication_state(current)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
    {
        return Err(Error::Invariant);
    }

    // Do not touch the Ready queue when the exact generation still owns Linux clear-child-tid.
    // The dedicated exit-cleanup transaction must preserve Process/TTBR0 through zero-store+wake.
    exit_split::reject_pending_clear_child_tid(contexts, current)?;

    // Select a successor while `current` is still Running. No Ready work is a normal failure and
    // leaves the current generation untouched, unlike the old exit-before-schedule ordering.
    let next = run_queue
        .schedule()
        .map_err(Error::Scheduler)?
        .ok_or(Error::NoRunnableThread)?;
    if next == current {
        return Err(Error::Invariant);
    }

    // `schedule` made `next` Running. Every fallible metadata lookup must therefore restore it to
    // Ready before returning so the owner never leaks a second logical Running generation.
    let next_metadata = (|| -> Result<(u64, u64, u64), Error> {
        if contexts.publication_state(next).map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
        {
            return Err(Error::Invariant);
        }
        let next_sp = contexts.get(next).map_err(Error::Context)?.saved_rsp;
        let next_tls = contexts.user_thread_pointer(next).map_err(Error::Context)?;
        let next_address_space = contexts.get(next).map_err(Error::Context)?.address_space;
        Ok((next_sp, next_tls, next_address_space))
    })();
    let (next_sp, next_tls, next_address_space) = match next_metadata {
        Ok(metadata) => metadata,
        Err(error) => {
            run_queue.make_ready(next).map_err(Error::Scheduler)?;
            return Err(error);
        }
    };

    let old_sp_ptr = match contexts.get_mut(current) {
        Ok(context) => core::ptr::addr_of_mut!(context.saved_rsp),
        Err(error) => {
            run_queue.make_ready(next).map_err(Error::Scheduler)?;
            return Err(Error::Context(error));
        }
    };

    // Only after the successor and both context records are known-good may the current generation
    // cross the irreversible Running -> Exited boundary. A scheduler failure still restores `next`.
    if let Err(error) = run_queue.exit(current) {
        run_queue.make_ready(next).map_err(Error::Scheduler)?;
        return Err(Error::Scheduler(error));
    }

    Ok((old_sp_ptr, next_sp, next, next_tls, next_address_space))
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn reap_exited_context_with<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    exited: ThreadId,
    reap: impl FnOnce(&mut RunQueue<THREADS>, ThreadId) -> Result<(), kernal_scheduler::Error>,
) -> Result<KernelStack, Error> {
    if run_queue.state(exited).map_err(Error::Scheduler)? != ThreadState::Exited {
        return Err(Error::Invariant);
    }
    let exited_tls = contexts
        .user_thread_pointer(exited)
        .map_err(Error::Context)?;
    let context = contexts.remove(exited).map_err(Error::Context)?;
    if let Err(error) = reap(run_queue, exited) {
        if contexts
            .insert(
                context.id,
                context.saved_rsp,
                context.stack,
                context.address_space,
            )
            .is_err()
            || contexts
                .update_user_thread_pointer(exited, exited_tls)
                .is_err()
        {
            return Err(Error::Invariant);
        }
        return Err(Error::Scheduler(error));
    }
    Ok(context.stack)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn rollback_new_thread<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    id: ThreadId,
) -> Result<(), Error> {
    run_queue.exit(id).map_err(Error::Scheduler)?;
    run_queue.reap(id).map_err(Error::Scheduler)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn capture_user_thread_pointer<const THREADS: usize>(
    contexts: &mut ContextTable<THREADS>,
    current: ThreadId,
) -> Result<(), Error> {
    // SAFETY: caller holds owner/quiescent scheduler authority for the PE and current generation.
    let value = unsafe { kernal_context_aarch64::read_el0_thread_pointer() };
    contexts
        .update_user_thread_pointer(current, value)
        .map_err(Error::Context)
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
unsafe fn capture_user_thread_pointer<const THREADS: usize>(
    _contexts: &mut ContextTable<THREADS>,
    _current: ThreadId,
) -> Result<(), Error> {
    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn install_user_thread_pointer(value: u64) {
    // SAFETY: caller resolved `value` from the exact selected scheduler generation while owner-held.
    unsafe { kernal_context_aarch64::install_el0_thread_pointer(value) };
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
unsafe fn install_user_thread_pointer(_value: u64) {}

#[cfg(target_arch = "x86_64")]
unsafe fn switch_context(old_sp: *mut u64, new_sp: u64) {
    // SAFETY: caller ended all scheduler borrows and supplied validated context stack pointers.
    unsafe { kernal_context_x86_64::switch(old_sp, new_sp) };
}

#[cfg(target_arch = "aarch64")]
unsafe fn switch_context(old_sp: *mut u64, new_sp: u64) {
    // SAFETY: caller ended all scheduler borrows and supplied validated context stack pointers.
    unsafe { kernal_context_aarch64::switch(old_sp, new_sp) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published_context<const N: usize>(contexts: &mut ContextTable<N>, id: ThreadId, base: u64) {
        let stack = KernelStack::new(base, base + 0x1000, 0x4000).unwrap();
        contexts
            .insert(id, base + 0x4ff8, stack, base + 0x20_000)
            .unwrap();
    }

    fn staged_stack(base: u64) -> KernelStack {
        KernelStack::new(base, base + 0x1000, 0x4000).unwrap()
    }

    #[test]
    fn remote_interface_rejects_wrong_owner_without_touching_local_state() {
        static CELL: CpuSchedulerCell<8, 4> = CpuSchedulerCell::new();
        CELL.prepare(CpuIndex(2)).unwrap();
        let wrong = GlobalThreadId::new(
            CpuIndex(3),
            ThreadId {
                slot: 1,
                generation: 1,
            },
        );
        assert!(matches!(
            CELL.remote_wake(wrong),
            Err(Error::Wake(kernal_scheduler_smp::Error::WrongOwner))
        ));
    }

    #[test]
    fn owner_is_published_once() {
        static CELL: CpuSchedulerCell<4, 4> = CpuSchedulerCell::new();
        CELL.prepare(CpuIndex(7)).unwrap();
        assert_eq!(CELL.owner().unwrap(), CpuIndex(7));
        assert_eq!(CELL.prepare(CpuIndex(7)), Err(Error::AlreadyInitialized));
    }

    #[test]
    fn packed_thread_zero_is_reserved_for_no_current_thread() {
        let id = ThreadId {
            slot: 0,
            generation: 1,
        };
        let packed = pack_thread(id);
        assert_ne!(packed, 0);
        assert_eq!(unpack_thread(packed), Some(id));
        assert_eq!(unpack_thread(0), None);
    }

    #[test]
    fn staged_user_thread_is_not_schedulable_until_final_publish() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let stack = staged_stack(0x50_000);
        let tls = 0x0000_7000_1234_5000;
        let clear_tid = 0x0000_7000_0000_1000;

        let id = create_staged_user_thread(
            &mut run_queue,
            &mut contexts,
            12,
            0x54_ff8,
            stack,
            0x90_000,
            tls,
            Some(clear_tid),
        )
        .unwrap();

        assert_eq!(run_queue.state(id), Ok(ThreadState::Blocked));
        assert_eq!(run_queue.schedule().unwrap(), None);
        assert_eq!(
            contexts.publication_state(id),
            Ok(kernal_thread_context::PublicationState::Staged)
        );
        assert_eq!(contexts.user_thread_pointer(id), Ok(tls));
        assert_eq!(contexts.pending_clear_child_tid(id), Ok(Some(clear_tid)));

        publish_staged_ready(&mut run_queue, &mut contexts, id).unwrap();
        assert_eq!(run_queue.state(id), Ok(ThreadState::Ready));
        assert_eq!(
            contexts.publication_state(id),
            Ok(kernal_thread_context::PublicationState::Published)
        );
        assert_eq!(run_queue.schedule().unwrap(), Some(id));
    }

    #[test]
    fn publish_rejects_non_staged_context_without_making_thread_ready() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let id = run_queue.create(7).unwrap();
        published_context(&mut contexts, id, 0x60_000);

        assert_eq!(
            publish_staged_ready(&mut run_queue, &mut contexts, id),
            Err(Error::Invariant)
        );
        assert_eq!(run_queue.state(id), Ok(ThreadState::Blocked));
        assert_eq!(run_queue.schedule().unwrap(), None);
        assert_eq!(
            contexts.publication_state(id),
            Ok(kernal_thread_context::PublicationState::Published)
        );
    }

    #[test]
    fn cancelling_staged_thread_discards_metadata_and_advances_generation() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let stack = staged_stack(0x70_000);
        let old = create_staged_user_thread(
            &mut run_queue,
            &mut contexts,
            5,
            0x74_ff8,
            stack,
            0xa0_000,
            0x0000_7000_2222_0000,
            Some(0x0000_7000_0000_2000),
        )
        .unwrap();

        let returned = cancel_staged_user_thread(&mut run_queue, &mut contexts, old).unwrap();
        assert_eq!(returned, stack);
        assert_eq!(
            contexts.publication_state(old),
            Err(kernal_thread_context::Error::Missing)
        );
        assert_eq!(
            run_queue.state(old),
            Err(kernal_scheduler::Error::InvalidThread)
        );

        let replacement = run_queue.create(5).unwrap();
        assert_eq!(replacement.slot, old.slot);
        assert_ne!(replacement.generation, old.generation);
    }

    #[test]
    fn tls_setup_failure_uses_staged_cancel_and_advances_generation_once() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let stack = staged_stack(0x75_000);
        let old = run_queue.create(5).unwrap();
        contexts
            .insert_staged(old, 0x79_ff8, stack, 0xa5_000)
            .unwrap();

        assert_eq!(
            rollback_staged_setup_error(
                &mut run_queue,
                &mut contexts,
                old,
                kernal_thread_context::Error::Stale,
            ),
            Error::Context(kernal_thread_context::Error::Stale)
        );
        assert_eq!(
            contexts.publication_state(old),
            Err(kernal_thread_context::Error::Missing)
        );
        assert_eq!(
            run_queue.state(old),
            Err(kernal_scheduler::Error::InvalidThread)
        );
        let replacement = run_queue.create(5).unwrap();
        assert_eq!(replacement.slot, old.slot);
        assert_ne!(replacement.generation, old.generation);
    }

    #[test]
    fn clear_child_tid_setup_failure_uses_same_owned_cancel_transaction() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let old = create_staged_user_thread(
            &mut run_queue,
            &mut contexts,
            5,
            0x7e_ff8,
            staged_stack(0x7a_000),
            0xa8_000,
            0x0000_7000_aaaa_0000,
            Some(0x0000_7000_0000_2800),
        )
        .unwrap();

        assert_eq!(
            rollback_staged_setup_error(
                &mut run_queue,
                &mut contexts,
                old,
                kernal_thread_context::Error::InvalidUserCleanupState,
            ),
            Error::Context(kernal_thread_context::Error::InvalidUserCleanupState)
        );
        assert_eq!(
            contexts.publication_state(old),
            Err(kernal_thread_context::Error::Missing)
        );
        assert_eq!(
            run_queue.state(old),
            Err(kernal_scheduler::Error::InvalidThread)
        );
        let replacement = run_queue.create(5).unwrap();
        assert_eq!(replacement.slot, old.slot);
        assert_ne!(replacement.generation, old.generation);
    }

    #[test]
    fn failed_staged_removal_keeps_generation_and_all_metadata_owned() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let tls = 0x0000_7000_bbbb_0000;
        let clear_tid = 0x0000_7000_0000_2c00;
        let id = create_staged_user_thread(
            &mut run_queue,
            &mut contexts,
            5,
            0x8e_ff8,
            staged_stack(0x8a_000),
            0xac_000,
            tls,
            Some(clear_tid),
        )
        .unwrap();

        let result =
            cancel_staged_user_thread_with(&mut run_queue, &mut contexts, id, |_contexts, _id| {
                Err(kernal_thread_context::Error::InvalidPublicationState)
            });
        assert_eq!(result, Err(Error::Invariant));
        assert_eq!(run_queue.state(id), Ok(ThreadState::Blocked));
        assert_eq!(
            contexts.publication_state(id),
            Ok(kernal_thread_context::PublicationState::Staged)
        );
        assert_eq!(contexts.user_thread_pointer(id), Ok(tls));
        assert_eq!(contexts.pending_clear_child_tid(id), Ok(Some(clear_tid)));
        assert!(run_queue.create(5).is_err());
        assert_eq!(run_queue.state(id), Ok(ThreadState::Blocked));
    }

    #[test]
    fn published_thread_cannot_recover_staged_cancel_authority() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let id = create_staged_user_thread(
            &mut run_queue,
            &mut contexts,
            5,
            0x84_ff8,
            staged_stack(0x80_000),
            0xb0_000,
            0x0000_7000_3333_0000,
            None,
        )
        .unwrap();
        publish_staged_ready(&mut run_queue, &mut contexts, id).unwrap();

        assert_eq!(
            cancel_staged_user_thread(&mut run_queue, &mut contexts, id),
            Err(Error::Invariant)
        );
        assert_eq!(run_queue.state(id), Ok(ThreadState::Ready));
        assert_eq!(
            contexts.publication_state(id),
            Ok(kernal_thread_context::PublicationState::Published)
        );
    }

    #[test]
    fn exit_prepare_without_peer_keeps_current_running() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let current = run_queue.create(10).unwrap();
        published_context(&mut contexts, current, 0x10_000);
        run_queue.make_ready(current).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(current));

        assert_eq!(
            prepare_exit_switch(&mut run_queue, &mut contexts, current),
            Err(Error::NoRunnableThread)
        );
        assert_eq!(run_queue.state(current), Ok(ThreadState::Running));
        assert_eq!(
            contexts.publication_state(current),
            Ok(kernal_thread_context::PublicationState::Published)
        );
    }

    #[test]
    fn exit_prepare_metadata_failure_restores_selected_peer_ready() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let current = run_queue.create(10).unwrap();
        published_context(&mut contexts, current, 0x20_000);
        run_queue.make_ready(current).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(current));

        // Publish a runnable scheduler generation without matching context metadata to force the
        // exact post-schedule validation failure that previously stranded the selected peer Running.
        let peer = run_queue.create(9).unwrap();
        run_queue.make_ready(peer).unwrap();

        assert_eq!(
            prepare_exit_switch(&mut run_queue, &mut contexts, current),
            Err(Error::Context(kernal_thread_context::Error::Missing))
        );
        assert_eq!(run_queue.state(current), Ok(ThreadState::Running));
        assert_eq!(run_queue.state(peer), Ok(ThreadState::Ready));
    }

    #[test]
    fn legacy_exit_prepare_rejects_pending_clear_tid_without_successor() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let current = run_queue.create(10).unwrap();
        let current_stack = staged_stack(0x25_000);
        let clear_tid = 0x0000_7000_0000_1800;
        contexts
            .insert_staged(current, 0x29_ff8, current_stack, 0x45_000)
            .unwrap();
        contexts
            .initialize_clear_child_tid(current, clear_tid)
            .unwrap();
        contexts.publish(current).unwrap();
        run_queue.make_ready(current).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(current));

        assert_eq!(
            prepare_exit_switch(&mut run_queue, &mut contexts, current),
            Err(Error::Context(
                kernal_thread_context::Error::PendingUserCleanup
            ))
        );
        assert_eq!(run_queue.state(current), Ok(ThreadState::Running));
        assert_eq!(
            contexts.pending_clear_child_tid(current),
            Ok(Some(clear_tid))
        );
    }

    #[test]
    fn exit_prepare_commits_only_after_successor_metadata_is_valid() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let current = run_queue.create(10).unwrap();
        published_context(&mut contexts, current, 0x30_000);
        run_queue.make_ready(current).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(current));

        let peer = run_queue.create(9).unwrap();
        published_context(&mut contexts, peer, 0x40_000);
        let peer_tls = 0x0000_7000_1234_5000;
        contexts.update_user_thread_pointer(peer, peer_tls).unwrap();
        run_queue.make_ready(peer).unwrap();

        let (_old_sp_ptr, peer_sp, selected, selected_tls, selected_address_space) =
            prepare_exit_switch(&mut run_queue, &mut contexts, current).unwrap();
        assert_eq!(selected, peer);
        assert_eq!(selected_tls, peer_tls);
        assert_eq!(
            selected_address_space,
            contexts.get(peer).unwrap().address_space
        );
        assert_eq!(peer_sp, contexts.get(peer).unwrap().saved_rsp);
        assert_eq!(run_queue.state(current), Ok(ThreadState::Exited));
        assert_eq!(run_queue.state(peer), Ok(ThreadState::Running));
    }

    #[test]
    fn failed_reap_restores_exact_generation_tls() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let exited = run_queue.create(9).unwrap();
        let stack = KernelStack::new(0x10_000, 0x11_000, 0x4_000).unwrap();
        contexts.insert(exited, 0x14_ff8, stack, 0x44_000).unwrap();
        let tls = 0x0000_7000_1234_5000;
        contexts.update_user_thread_pointer(exited, tls).unwrap();
        run_queue.make_ready(exited).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(exited));
        run_queue.exit(exited).unwrap();

        let result =
            reap_exited_context_with(&mut run_queue, &mut contexts, exited, |_run_queue, _id| {
                Err(kernal_scheduler::Error::InvalidState)
            });

        assert_eq!(
            result,
            Err(Error::Scheduler(kernal_scheduler::Error::InvalidState))
        );
        assert_eq!(run_queue.state(exited), Ok(ThreadState::Exited));
        assert_eq!(contexts.user_thread_pointer(exited), Ok(tls));
        assert_eq!(
            contexts.publication_state(exited),
            Ok(kernal_thread_context::PublicationState::Published)
        );
    }

    #[test]
    fn pending_clear_child_tid_blocks_reap_before_generation_removal() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let exited = run_queue.create(9).unwrap();
        let stack = KernelStack::new(0x20_000, 0x21_000, 0x4_000).unwrap();
        contexts
            .insert_staged(exited, 0x24_ff8, stack, 0x55_000)
            .unwrap();
        contexts
            .initialize_clear_child_tid(exited, 0x0000_7000_0000_1000)
            .unwrap();
        contexts.publish(exited).unwrap();
        run_queue.make_ready(exited).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(exited));
        run_queue.exit(exited).unwrap();

        let result =
            reap_exited_context_with(&mut run_queue, &mut contexts, exited, |run_queue, id| {
                run_queue.reap(id)
            });

        assert_eq!(
            result,
            Err(Error::Context(
                kernal_thread_context::Error::PendingUserCleanup
            ))
        );
        assert_eq!(run_queue.state(exited), Ok(ThreadState::Exited));
        assert_eq!(
            contexts.pending_clear_child_tid(exited),
            Ok(Some(0x0000_7000_0000_1000))
        );
    }
}
