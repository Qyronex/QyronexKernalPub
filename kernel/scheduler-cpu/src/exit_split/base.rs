// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::*;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[derive(Clone, Copy)]
struct ExitedCurrent {
    old_sp_ptr: *mut u64,
    robust_list_head: Option<u64>,
    clear_child_tid: Option<u64>,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectedSuccessor {
    next_sp: u64,
    next: ThreadId,
    next_tls: u64,
    next_address_space: u64,
}

impl<const THREADS: usize, const WAKES: usize> CpuSchedulerCell<THREADS, WAKES> {
    /// Exits the exact current published generation, performs caller-owned cleanup while the old
    /// process/address-space binding and kernel stack remain active, then selects a successor.
    ///
    /// This is the scheduler transaction required by Linux `CLONE_CHILD_CLEARTID`. A joining parent
    /// may be Blocked in `FUTEX_WAIT` while the child is the only Running generation. The child must
    /// therefore become Exited before a successor is required: zeroing clear-child-tid and publishing
    /// the canonical private `FUTEX_WAKE(1)` may make that parent Ready for the first time.
    ///
    /// Once the Running -> Exited transition succeeds, every later error is post-commit and
    /// fail-closed. CpuLocal still names the Exited generation, its Process/TTBR0 binding and old
    /// kernel stack must remain active, and the caller must never return that generation to EL0.
    /// Scheduler/context borrows end before `cleanup` runs. The closure may perform the exact
    /// generation-owned fault-safe zero-store and futex wake, but it must not switch address spaces,
    /// select scheduler work, change CpuLocal current, or break owner quiescence.
    ///
    /// A local waiter consumed by the futex owner must be delivered synchronously through
    /// [`Self::bootstrap_wake_local_exact`]; a foreign waiter must use its owner cell's existing
    /// [`Self::remote_wake`] mailbox. Only after `cleanup` reports success does this method consume
    /// the exact pending clear-child-tid obligation, select and validate the now-Ready successor,
    /// install its TLS value and switch stacks.
    ///
    /// # Safety
    /// Must execute on `expected_current.cpu` with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0`, migration suppressed and the current Process/address-space binding stable.
    /// Those conditions must remain true through Exited commit, external cleanup, exact cleanup
    /// completion, successor selection and the final context switch. `cleanup` must obey the
    /// restrictions above.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_exit_current_with_cleanup_and_switch<E>(
        &'static self,
        expected_current: GlobalThreadId,
        cleanup: impl FnOnce(GlobalThreadId, Option<u64>, Option<u64>) -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<Error>,
    {
        // SAFETY: delegated caller contract is unchanged; no destination activation is requested.
        unsafe {
            self.bootstrap_exit_current_with_cleanup_and_switch_inner(
                expected_current,
                cleanup,
                None,
            )
        }
    }

    /// Runs the Linux exit-cleanup transaction and activates the exact selected AArch64 destination
    /// address space before the final non-returning stack switch.
    ///
    /// Cleanup still executes under the exiting Process/TTBR0. Only after robust-list and
    /// clear-child-tid obligations are consumed and a Published successor is selected does the
    /// destination callback run. It receives that exact generation plus its opaque ContextTable
    /// address-space token and must fail closed/non-returning if canonical activation cannot complete.
    ///
    /// # Safety
    /// Same owner/quiescence/cleanup contract as
    /// [`Self::bootstrap_exit_current_with_cleanup_and_switch`]. The destination callback must not
    /// re-enter this scheduler and must not return unless the exact destination binding is active.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_exit_current_with_cleanup_and_switch_destination_address_space<E>(
        &'static self,
        expected_current: GlobalThreadId,
        cleanup: impl FnOnce(GlobalThreadId, Option<u64>, Option<u64>) -> Result<(), E>,
        activate_destination: fn(GlobalThreadId, u64),
    ) -> Result<(), E>
    where
        E: From<Error>,
    {
        // SAFETY: delegated caller contract plus the stricter destination callback contract above.
        unsafe {
            self.bootstrap_exit_current_with_cleanup_and_switch_inner(
                expected_current,
                cleanup,
                Some(activate_destination),
            )
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    unsafe fn bootstrap_exit_current_with_cleanup_and_switch_inner<E>(
        &'static self,
        expected_current: GlobalThreadId,
        cleanup: impl FnOnce(GlobalThreadId, Option<u64>, Option<u64>) -> Result<(), E>,
        activate_destination: Option<fn(GlobalThreadId, u64)>,
    ) -> Result<(), E>
    where
        E: From<Error>,
    {
        // SAFETY: delegated caller contract establishes owner-local quiescence.
        let local = unsafe { self.bootstrap_quiescent_local() }.map_err(E::from)?;
        let owner = self.owner().map_err(E::from)?;
        if expected_current.cpu != owner {
            return Err(E::from(Error::WrongOwner));
        }
        let current = unpack_thread(local.current_thread())
            .ok_or(Error::NoCurrentThread)
            .map_err(E::from)?;
        if current != expected_current.local {
            return Err(E::from(Error::Invariant));
        }

        let exited = {
            // SAFETY: owner/quiescence establishes exclusive local scheduler/context mutation.
            let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
            // SAFETY: same owner-only contract.
            let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
            exit_current_for_cleanup(run_queue, contexts, current).map_err(E::from)?
        };

        // Table borrows ended above. CpuLocal, Process/TTBR0 and the old kernel stack still belong to
        // the exact Exited generation while the closure performs zero-store plus wake delivery.
        cleanup(
            GlobalThreadId::new(owner, current),
            exited.robust_list_head,
            exited.clear_child_tid,
        )?;

        let selected = {
            // SAFETY: delegated contract keeps this owner non-reentrant throughout external cleanup.
            let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
            // SAFETY: same owner-only contract.
            let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
            complete_cleanup_and_select(run_queue, contexts, current, exited).map_err(E::from)?
        };

        let observed = unpack_thread(local.current_thread())
            .ok_or(Error::NoCurrentThread)
            .map_err(E::from)?;
        if observed != current {
            return Err(E::from(Error::Invariant));
        }
        if let Some(activate_destination) = activate_destination {
            activate_destination(
                GlobalThreadId::new(owner, selected.next),
                selected.next_address_space,
            );
        }
        local.set_current_thread(pack_thread(selected.next));
        // SAFETY: exact successor TLS was resolved after cleanup while owner-quiescent.
        unsafe { install_user_thread_pointer(selected.next_tls) };
        // SAFETY: current is Exited, cleanup is complete, and successor is validated Running.
        unsafe { switch_context(exited.old_sp_ptr, selected.next_sp) };
        Err(E::from(Error::Invariant))
    }

    /// Delivers one exact local wake directly while the normal owner wake drain is intentionally
    /// closed by an exit-cleanup transaction.
    ///
    /// This is the owner-local half of canonical futex wake routing. A target owned by another CPU
    /// must use that CPU's existing `remote_wake` mailbox. Local delivery is synchronous so a pthread
    /// joiner blocked in `FUTEX_WAIT` can become Ready before exit successor selection. Only the exact
    /// Published+Blocked generation is accepted; Ready, Running, Exited and stale targets fail closed
    /// rather than silently losing a consumed futex waiter.
    ///
    /// # Safety
    /// Must execute on this scheduler's owner CPU/PE with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0` and migration suppressed. `target` must come from the canonical
    /// generation-bound wake owner and no concurrent local scheduler mutation may occur.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_wake_local_exact(
        &'static self,
        target: GlobalThreadId,
    ) -> Result<(), Error> {
        // SAFETY: delegated caller contract establishes owner-local quiescence.
        let _local = unsafe { self.bootstrap_quiescent_local()? };
        if target.cpu != self.owner()? {
            return Err(Error::WrongOwner);
        }
        // SAFETY: owner/quiescence establishes exclusive RunQueue mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only contract keeps exact-generation metadata stable.
        let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
        wake_local_exact(run_queue, contexts, target.local)
    }

    /// Updates Linux robust-list metadata for the exact current published generation.
    ///
    /// The scheduler remains the only bridge to its private [`ContextTable`]. The caller supplies the
    /// exact global generation it resolved before validating Linux userspace arguments; this method
    /// revalidates owner CPU, CpuLocal current, Running state and publication state under one
    /// quiescent owner window before delegating the metadata write to
    /// [`ContextTable::update_robust_list_head`]. No scalar TID or second robust-list registry is
    /// accepted as authority.
    ///
    /// # Safety
    /// Must execute on `expected_current.cpu` with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0` and migration suppressed. `user_address` must already have passed the Linux
    /// robust-list UAPI validation owned outside the scheduler.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_update_current_robust_list_head(
        &'static self,
        expected_current: GlobalThreadId,
        user_address: u64,
    ) -> Result<(), Error> {
        // SAFETY: delegated caller contract establishes exact owner-local quiescence.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let owner = self.owner()?;
        if expected_current.cpu != owner {
            return Err(Error::WrongOwner);
        }
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        if current != expected_current.local {
            return Err(Error::Invariant);
        }

        // SAFETY: owner quiescence stabilizes the current scheduler state for validation.
        let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
        // SAFETY: same owner-only contract establishes exclusive metadata mutation.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        update_current_robust_list_head(run_queue, contexts, current, user_address)
    }

    /// Replaces or disables clear-child-tid for the exact current published AArch64 generation.
    ///
    /// This is only the scheduler bridge for Linux `set_tid_address`: Linux Thread identity stays
    /// with its accepted owner. Owner/current/Running/Published state is revalidated before
    /// delegating to `ContextTable::update_published_clear_child_tid`. The pointer is opaque metadata;
    /// any later userspace fault belongs to exit-time clear-child-tid cleanup.
    ///
    /// # Safety
    /// Must execute on `expected_current.cpu` with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0` and migration suppressed for the complete metadata transaction.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_update_current_clear_child_tid(
        &'static self,
        expected_current: GlobalThreadId,
        user_address: Option<u64>,
    ) -> Result<(), Error> {
        // SAFETY: delegated caller contract establishes exact owner-local quiescence.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let owner = self.owner()?;
        if expected_current.cpu != owner {
            return Err(Error::WrongOwner);
        }
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        if current != expected_current.local {
            return Err(Error::Invariant);
        }
        // SAFETY: owner quiescence stabilizes scheduler state and gives exclusive metadata mutation.
        let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
        // SAFETY: same owner-only contract.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        update_current_clear_child_tid(run_queue, contexts, current, user_address)
    }

    /// Creates one clone-staged child which inherits the exact current scheduler address-space token.
    ///
    /// This is the CLONE_VM creation primitive. The parent must be the exact owner-local
    /// Published+Running generation. Its opaque ContextTable `address_space` token is copied directly
    /// into the child while both scheduler tables remain owner-quiescent; the token never crosses the
    /// public API and cannot be reconstructed from a Process handle or stale scalar. The child remains
    /// Blocked+Staged for the existing external setup/commit/cancel transaction.
    ///
    /// # Safety
    /// Must execute on this cell's owner CPU/PE with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0` and migration suppressed. `saved_sp`, `stack`, TLS and clear-child-tid must
    /// describe the exact not-yet-published child being created.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn bootstrap_create_staged_user_thread_shared_current_address_space(
        &'static self,
        priority: u8,
        saved_sp: u64,
        stack: KernelStack,
        user_thread_pointer: u64,
        clear_child_tid: Option<u64>,
    ) -> Result<ThreadId, Error> {
        // SAFETY: delegated caller contract establishes exact owner-local quiescence.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        // SAFETY: owner quiescence establishes exclusive local table mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only contract.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        let address_space = shared_current_address_space(run_queue, contexts, current)?;
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

    /// Runs one fallible external clone-setup transaction against the canonical private RunQueue
    /// while the exact child generation remains scheduler-Blocked and ContextTable-Staged.
    ///
    /// This is the narrow authority bridge between `CpuSchedulerCell` and Process/Linux identity
    /// setup. The private RunQueue is borrowed immutably only for the duration of `operation`; it is
    /// never returned or exposed as a standalone scheduler handle. The closure also receives the
    /// frozen owner CpuIndex and a non-Copy/non-Clone `StagedThreadProof` minted only after the exact
    /// generation has been validated against both canonical scheduler and publication state.
    ///
    /// The higher-ranked closure lifetime prevents the RunQueue reference from escaping in `R`.
    /// External Process/Thread-object/TID/usercopy work may run while the immutable view is live, but
    /// the closure must not call scheduler selection, wake draining, publish/cancel, context switch,
    /// migration or any other API that mutates/reenters this CpuSchedulerCell. After the closure
    /// returns, all RunQueue/ContextTable borrows are gone and the caller may perform exactly one
    /// normal staged publication or staged cancellation under the still-held owner transaction.
    ///
    /// # Safety
    /// Must execute on this cell's owner CPU/PE with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0` and migration suppressed. `staged` must be the exact generation returned by
    /// this cell's staged clone creation path. Owner quiescence and scheduler/publication state must
    /// remain unchanged for the entire closure, except for external non-scheduler authority tracked
    /// by that clone transaction.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_with_staged_thread<R, E, F>(
        &'static self,
        staged: ThreadId,
        operation: F,
    ) -> Result<R, E>
    where
        E: From<Error>,
        F: for<'a> FnOnce(
            &'a RunQueue<THREADS>,
            CpuIndex,
            kernal_scheduler_smp::StagedThreadProof,
        ) -> Result<R, E>,
    {
        // SAFETY: delegated caller contract establishes exact owner-local quiescence.
        let _local = unsafe { self.bootstrap_quiescent_local() }.map_err(E::from)?;
        let owner = self.owner().map_err(E::from)?;

        let proof = {
            // SAFETY: owner quiescence makes both immutable observations stable through attestation.
            let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
            // SAFETY: same owner-only observation contract.
            let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
            validate_staged_transaction(run_queue, contexts, staged).map_err(E::from)?;
            // SAFETY: the exact canonical RunQueue + ContextTable state was validated immediately
            // above under uninterrupted owner quiescence.
            unsafe {
                kernal_scheduler_smp::StagedThreadProof::new_unchecked(GlobalThreadId::new(
                    owner, staged,
                ))
            }
        };

        // ContextTable attestation borrow ended above. The closure gets only an immutable canonical
        // RunQueue view; its HRTB lifetime cannot be smuggled out through the unconstrained result R.
        // SAFETY: owner quiescence keeps this private table initialized and mutation-free by contract.
        let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
        operation(run_queue, owner, proof)
    }

    /// Publishes one exact staged clone generation with an irreversible external commit inside the
    /// same owner-quiescent transaction.
    ///
    /// This is the CLONE_PARENT_SETTID commit boundary. All Process/Thread authority, Linux TID,
    /// kernel-stack, TLS and clear-child-tid setup must already be complete while the child is
    /// Blocked+Staged. This method first performs the fallible Ready-queue transition while no
    /// external state is visible, then invokes `commit`. If `commit` reports failure, Ready is rolled
    /// back to Blocked and Staged authority is retained for normal clone cancellation.
    ///
    /// `commit` must report `Ok(())` only after its irreversible external effect has completed, and
    /// must report `Err` only when no such effect became visible. After `Ok`, the exact ContextTable
    /// generation is still Staged under the same exclusive owner borrow, so consuming the already
    /// validated one-way publication is an internal invariant rather than another recoverable step.
    /// Any impossible failure there fails closed and never returns an error after the external commit.
    ///
    /// # Safety
    /// Must execute on this cell's owner CPU/PE with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0` and migration suppressed. `staged` must still be the exact never-published
    /// generation created by this cell. `commit` must not reenter this scheduler, drain wakes, switch
    /// address spaces, enable migration/preemption/IRQs, or violate the visible-effect contract above.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_commit_staged_ready<E>(
        &'static self,
        staged: ThreadId,
        commit: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E>
    where
        E: From<Error>,
    {
        // SAFETY: delegated caller contract establishes uninterrupted owner-local quiescence.
        let _local = unsafe { self.bootstrap_quiescent_local() }.map_err(E::from)?;
        // SAFETY: owner/quiescence establishes exclusive local scheduler mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only contract gives exclusive generation-owned metadata mutation.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        commit_staged_ready(run_queue, contexts, staged, commit)
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
pub(super) fn reject_pending_clear_child_tid<const THREADS: usize>(
    contexts: &ContextTable<THREADS>,
    current: ThreadId,
) -> Result<(), Error> {
    if contexts
        .pending_clear_child_tid(current)
        .map_err(Error::Context)?
        .is_some()
        || contexts
            .pending_robust_list_head(current)
            .map_err(Error::Context)?
            .is_some()
    {
        return Err(Error::Context(
            kernal_thread_context::Error::PendingUserCleanup,
        ));
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn validate_staged_transaction<const THREADS: usize>(
    run_queue: &RunQueue<THREADS>,
    contexts: &ContextTable<THREADS>,
    staged: ThreadId,
) -> Result<(), Error> {
    if run_queue.state(staged).map_err(Error::Scheduler)? != ThreadState::Blocked
        || contexts.publication_state(staged).map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Staged
    {
        return Err(Error::Invariant);
    }
    Ok(())
}

#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
fn update_current_robust_list_head<const THREADS: usize>(
    run_queue: &RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    current: ThreadId,
    user_address: u64,
) -> Result<(), Error> {
    if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
        || contexts
            .publication_state(current)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
    {
        return Err(Error::Invariant);
    }
    contexts
        .update_robust_list_head(current, user_address)
        .map_err(Error::Context)
}

#[cfg(any(all(target_arch = "aarch64", target_os = "none"), test))]
fn update_current_clear_child_tid<const THREADS: usize>(
    run_queue: &RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    current: ThreadId,
    user_address: Option<u64>,
) -> Result<(), Error> {
    if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
        || contexts
            .publication_state(current)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
    {
        return Err(Error::Invariant);
    }
    contexts
        .update_published_clear_child_tid(current, user_address)
        .map_err(Error::Context)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn shared_current_address_space<const THREADS: usize>(
    run_queue: &RunQueue<THREADS>,
    contexts: &ContextTable<THREADS>,
    current: ThreadId,
) -> Result<u64, Error> {
    if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
        || contexts
            .publication_state(current)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
    {
        return Err(Error::Invariant);
    }
    Ok(contexts.get(current).map_err(Error::Context)?.address_space)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn commit_staged_ready<const THREADS: usize, E>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    staged: ThreadId,
    commit: impl FnOnce() -> Result<(), E>,
) -> Result<(), E>
where
    E: From<Error>,
{
    validate_staged_transaction(run_queue, contexts, staged).map_err(E::from)?;

    // This is still pre-commit: make_ready is transactional and restores Blocked if queue insertion
    // fails. Owner quiescence prevents this Ready+Staged generation from being selected while the
    // external commit closure runs.
    run_queue
        .make_ready(staged)
        .map_err(Error::Scheduler)
        .map_err(E::from)?;

    if let Err(error) = commit() {
        // No external effect became visible by the closure contract, so recover exact Staged+Blocked
        // abort authority. Failure to undo Ready is a privileged invariant, not the caller error.
        if run_queue.block(staged).is_err()
            || validate_staged_transaction(run_queue, contexts, staged).is_err()
        {
            return Err(E::from(Error::Invariant));
        }
        return Err(error);
    }

    // The external commit is now irreversible. No recoverable error may cross this boundary. The
    // exclusive ContextTable borrow and uninterrupted owner quiescence prove that this exact slot is
    // still the same Staged generation validated above. A failure can therefore only indicate an
    // internal ownership invariant violation and must fail closed rather than return to Linux.
    if contexts.publish(staged).is_err()
        || contexts.publication_state(staged)
            != Ok(kernal_thread_context::PublicationState::Published)
        || run_queue.state(staged) != Ok(ThreadState::Ready)
    {
        fail_closed_after_external_commit();
    }
    Ok(())
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn fail_closed_after_external_commit() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn wake_local_exact<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &ContextTable<THREADS>,
    target: ThreadId,
) -> Result<(), Error> {
    if contexts.publication_state(target).map_err(Error::Context)?
        != kernal_thread_context::PublicationState::Published
        || run_queue.state(target).map_err(Error::Scheduler)? != ThreadState::Blocked
    {
        return Err(Error::Invariant);
    }
    run_queue.make_ready(target).map_err(Error::Scheduler)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn exit_current_for_cleanup<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    current: ThreadId,
) -> Result<ExitedCurrent, Error> {
    if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
        || contexts
            .publication_state(current)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
    {
        return Err(Error::Invariant);
    }

    let robust_list_head = contexts
        .pending_robust_list_head(current)
        .map_err(Error::Context)?;
    let clear_child_tid = contexts
        .pending_clear_child_tid(current)
        .map_err(Error::Context)?;
    let old_sp_ptr = {
        let context = contexts.get_mut(current).map_err(Error::Context)?;
        core::ptr::addr_of_mut!(context.saved_rsp)
    };

    // This is the irreversible boundary. No successor is required yet because cleanup may wake the
    // only possible peer. Any later error must leave this exact generation fail-closed Exited.
    run_queue.exit(current).map_err(Error::Scheduler)?;

    let current_sp_ptr = {
        let context = contexts.get_mut(current).map_err(Error::Context)?;
        core::ptr::addr_of_mut!(context.saved_rsp)
    };
    if current_sp_ptr != old_sp_ptr
        || run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Exited
        || contexts
            .publication_state(current)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
        || contexts
            .pending_robust_list_head(current)
            .map_err(Error::Context)?
            != robust_list_head
        || contexts
            .pending_clear_child_tid(current)
            .map_err(Error::Context)?
            != clear_child_tid
    {
        return Err(Error::Invariant);
    }

    Ok(ExitedCurrent {
        old_sp_ptr,
        robust_list_head,
        clear_child_tid,
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
fn complete_cleanup_and_select<const THREADS: usize>(
    run_queue: &mut RunQueue<THREADS>,
    contexts: &mut ContextTable<THREADS>,
    current: ThreadId,
    exited: ExitedCurrent,
) -> Result<SelectedSuccessor, Error> {
    let current_sp_ptr = {
        let context = contexts.get_mut(current).map_err(Error::Context)?;
        core::ptr::addr_of_mut!(context.saved_rsp)
    };
    if current_sp_ptr != exited.old_sp_ptr
        || run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Exited
        || contexts
            .publication_state(current)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
        || contexts
            .pending_robust_list_head(current)
            .map_err(Error::Context)?
            != exited.robust_list_head
        || contexts
            .pending_clear_child_tid(current)
            .map_err(Error::Context)?
            != exited.clear_child_tid
    {
        return Err(Error::Invariant);
    }

    if exited.robust_list_head.is_some() {
        contexts
            .complete_robust_list_cleanup(current)
            .map_err(Error::Context)?;
    }
    if contexts
        .pending_robust_list_head(current)
        .map_err(Error::Context)?
        .is_some()
    {
        return Err(Error::Invariant);
    }

    if exited.clear_child_tid.is_some() {
        // External zero-store and every canonical wake delivery succeeded before this point. Consume
        // the exact obligation only now; failed external cleanup remains reap-blocking.
        contexts
            .complete_clear_child_tid(current)
            .map_err(Error::Context)?;
    }
    if contexts
        .pending_clear_child_tid(current)
        .map_err(Error::Context)?
        .is_some()
    {
        return Err(Error::Invariant);
    }

    let next = run_queue
        .schedule()
        .map_err(Error::Scheduler)?
        .ok_or(Error::NoRunnableThread)?;
    if next == current {
        return Err(Error::Invariant);
    }

    let metadata = (|| -> Result<(u64, u64, u64), Error> {
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
    let (next_sp, next_tls, next_address_space) = match metadata {
        Ok(metadata) => metadata,
        Err(error) => {
            // Current is already Exited and cannot be restored. Put only the speculatively selected
            // successor back on Ready so a post-commit metadata failure does not strand it Running.
            run_queue.make_ready(next).map_err(Error::Scheduler)?;
            return Err(error);
        }
    };

    Ok(SelectedSuccessor {
        next_sp,
        next,
        next_tls,
        next_address_space,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack(base: u64) -> KernelStack {
        KernelStack::new(base, base + 0x1000, 0x4000).unwrap()
    }

    fn install_published<const N: usize>(
        contexts: &mut ContextTable<N>,
        id: ThreadId,
        base: u64,
        clear_child_tid: Option<u64>,
    ) {
        if let Some(user_address) = clear_child_tid {
            contexts
                .insert_staged(id, base + 0x4ff8, stack(base), base + 0x20_000)
                .unwrap();
            contexts
                .initialize_clear_child_tid(id, user_address)
                .unwrap();
            contexts.publish(id).unwrap();
        } else {
            contexts
                .insert(id, base + 0x4ff8, stack(base), base + 0x20_000)
                .unwrap();
        }
    }

    fn running_thread<const N: usize>(
        run_queue: &mut RunQueue<N>,
        contexts: &mut ContextTable<N>,
        priority: u8,
        base: u64,
        clear_child_tid: Option<u64>,
    ) -> ThreadId {
        let id = run_queue.create(priority).unwrap();
        install_published(contexts, id, base, clear_child_tid);
        run_queue.make_ready(id).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(id));
        id
    }

    #[test]
    fn staged_transaction_accepts_only_exact_staged_blocked_generation() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let staged = run_queue.create(9).unwrap();
        contexts
            .insert_staged(staged, 0x14ff8, stack(0x10_000), 0x30_000)
            .unwrap();

        assert_eq!(
            validate_staged_transaction(&run_queue, &contexts, staged),
            Ok(())
        );

        run_queue.make_ready(staged).unwrap();
        assert_eq!(
            validate_staged_transaction(&run_queue, &contexts, staged),
            Err(Error::Invariant)
        );
    }

    #[test]
    fn robust_registration_requires_exact_running_published_generation() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x18_000, None);
        let robust_head = 0x0000_7000_0000_1800;

        assert_eq!(
            update_current_robust_list_head(&run_queue, &mut contexts, current, robust_head),
            Ok(())
        );
        assert_eq!(
            contexts.pending_robust_list_head(current),
            Ok(Some(robust_head))
        );

        let stale = ThreadId {
            slot: current.slot,
            generation: current.generation.wrapping_add(1),
        };
        assert!(
            update_current_robust_list_head(
                &run_queue,
                &mut contexts,
                stale,
                0x0000_7000_0000_2800,
            )
            .is_err()
        );
        assert_eq!(
            contexts.pending_robust_list_head(current),
            Ok(Some(robust_head))
        );
    }

    #[test]
    fn set_tid_address_metadata_requires_exact_running_published_generation() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x19_000, None);
        let first = 0x0000_7000_0000_3000;
        let replacement = first + 0x1000;

        assert_eq!(
            update_current_clear_child_tid(&run_queue, &mut contexts, current, Some(first)),
            Ok(())
        );
        assert_eq!(contexts.pending_clear_child_tid(current), Ok(Some(first)));
        assert_eq!(
            update_current_clear_child_tid(&run_queue, &mut contexts, current, Some(replacement)),
            Ok(())
        );
        assert_eq!(
            contexts.pending_clear_child_tid(current),
            Ok(Some(replacement))
        );
        assert_eq!(
            update_current_clear_child_tid(&run_queue, &mut contexts, current, None),
            Ok(())
        );
        assert_eq!(contexts.pending_clear_child_tid(current), Ok(None));

        let stale = ThreadId {
            slot: current.slot,
            generation: current.generation.wrapping_add(1),
        };
        assert!(
            update_current_clear_child_tid(&run_queue, &mut contexts, stale, Some(first)).is_err()
        );
        assert_eq!(contexts.pending_clear_child_tid(current), Ok(None));
    }

    #[test]
    fn shared_clone_address_space_requires_running_published_parent() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let token = 0x1234_5678_9abc_def0;
        let parent = run_queue.create(10).unwrap();
        contexts
            .insert(parent, 0x14ff8, stack(0x10_000), token)
            .unwrap();
        run_queue.make_ready(parent).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(parent));
        assert_eq!(
            shared_current_address_space(&run_queue, &contexts, parent),
            Ok(token)
        );

        let blocked = run_queue.create(9).unwrap();
        contexts
            .insert(blocked, 0x24ff8, stack(0x20_000), 0xfeed_beef)
            .unwrap();
        assert_eq!(
            shared_current_address_space(&run_queue, &contexts, blocked),
            Err(Error::Invariant)
        );
    }

    #[test]
    fn staged_parent_cannot_supply_shared_clone_address_space() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let parent = run_queue.create(10).unwrap();
        contexts
            .insert_staged(parent, 0x34ff8, stack(0x30_000), 0xcafe_f00d)
            .unwrap();
        run_queue.make_ready(parent).unwrap();
        assert_eq!(run_queue.schedule().unwrap(), Some(parent));
        assert_eq!(
            shared_current_address_space(&run_queue, &contexts, parent),
            Err(Error::Invariant)
        );
    }

    #[test]
    fn failed_staged_commit_restores_blocked_and_staged_authority() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let staged = run_queue.create(9).unwrap();
        contexts
            .insert_staged(staged, 0x14ff8, stack(0x10_000), 0x30_000)
            .unwrap();
        contexts
            .update_user_thread_pointer(staged, 0x0000_7000_0000_1000)
            .unwrap();
        contexts
            .initialize_clear_child_tid(staged, 0x0000_7000_0000_2000)
            .unwrap();
        let mut calls = 0;

        assert_eq!(
            commit_staged_ready(&mut run_queue, &mut contexts, staged, || {
                calls += 1;
                Err(Error::WrongOwner)
            }),
            Err(Error::WrongOwner)
        );
        assert_eq!(calls, 1);
        assert_eq!(run_queue.state(staged), Ok(ThreadState::Blocked));
        assert_eq!(
            contexts.publication_state(staged),
            Ok(kernal_thread_context::PublicationState::Staged)
        );
        assert_eq!(
            contexts.user_thread_pointer(staged),
            Ok(0x0000_7000_0000_1000)
        );
        assert_eq!(
            contexts.pending_clear_child_tid(staged),
            Ok(Some(0x0000_7000_0000_2000))
        );
    }

    #[test]
    fn successful_staged_commit_ends_ready_and_published() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let staged = run_queue.create(9).unwrap();
        contexts
            .insert_staged(staged, 0x24ff8, stack(0x20_000), 0x40_000)
            .unwrap();
        let mut committed = false;

        assert_eq!(
            commit_staged_ready::<_, Error>(&mut run_queue, &mut contexts, staged, || {
                committed = true;
                Ok(())
            }),
            Ok(())
        );
        assert!(committed);
        assert_eq!(run_queue.state(staged), Ok(ThreadState::Ready));
        assert_eq!(
            contexts.publication_state(staged),
            Ok(kernal_thread_context::PublicationState::Published)
        );
        assert_eq!(run_queue.schedule().unwrap(), Some(staged));
    }

    #[test]
    fn invalid_staged_commit_never_invokes_external_effect() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let published = run_queue.create(9).unwrap();
        contexts
            .insert(published, 0x34ff8, stack(0x30_000), 0x50_000)
            .unwrap();
        let mut calls = 0;

        assert_eq!(
            commit_staged_ready::<_, Error>(&mut run_queue, &mut contexts, published, || {
                calls += 1;
                Ok(())
            }),
            Err(Error::Invariant)
        );
        assert_eq!(calls, 0);
        assert_eq!(run_queue.state(published), Ok(ThreadState::Blocked));
        assert_eq!(
            contexts.publication_state(published),
            Ok(kernal_thread_context::PublicationState::Published)
        );
    }

    #[test]
    fn published_blocked_thread_cannot_masquerade_as_staged_clone_authority() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let published = run_queue.create(9).unwrap();
        contexts
            .insert(published, 0x24ff8, stack(0x20_000), 0x40_000)
            .unwrap();

        assert_eq!(run_queue.state(published), Ok(ThreadState::Blocked));
        assert_eq!(
            validate_staged_transaction(&run_queue, &contexts, published),
            Err(Error::Invariant)
        );
    }

    #[test]
    fn stale_generation_cannot_recover_staged_transaction_authority() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let staged = run_queue.create(9).unwrap();
        contexts
            .insert_staged(staged, 0x34ff8, stack(0x30_000), 0x50_000)
            .unwrap();
        let stale = ThreadId {
            slot: staged.slot,
            generation: staged.generation.wrapping_add(1),
        };

        assert!(validate_staged_transaction(&run_queue, &contexts, stale).is_err());
        assert_eq!(
            validate_staged_transaction(&run_queue, &contexts, staged),
            Ok(())
        );
    }

    #[test]
    fn legacy_exit_rejects_pending_cleanup_before_selecting_peer() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let clear_tid = 0x0000_7000_0000_1000;
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x10_000, Some(clear_tid));
        let peer = run_queue.create(9).unwrap();
        install_published(&mut contexts, peer, 0x20_000, None);
        run_queue.make_ready(peer).unwrap();

        assert_eq!(
            prepare_exit_switch(&mut run_queue, &mut contexts, current),
            Err(Error::Context(
                kernal_thread_context::Error::PendingUserCleanup
            ))
        );
        assert_eq!(run_queue.state(current), Ok(ThreadState::Running));
        assert_eq!(run_queue.state(peer), Ok(ThreadState::Ready));
        assert_eq!(
            contexts.pending_clear_child_tid(current),
            Ok(Some(clear_tid))
        );
    }

    #[test]
    fn robust_and_clear_cleanup_are_generation_bound_and_complete_together() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let clear_tid = 0x0000_7000_0000_2800;
        let robust_head = 0x0000_7000_0000_3800;
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x28_000, Some(clear_tid));
        contexts
            .update_robust_list_head(current, robust_head)
            .unwrap();
        let peer = run_queue.create(9).unwrap();
        install_published(&mut contexts, peer, 0x29_000, None);
        run_queue.make_ready(peer).unwrap();

        let exited = exit_current_for_cleanup(&mut run_queue, &mut contexts, current).unwrap();
        assert_eq!(exited.robust_list_head, Some(robust_head));
        assert_eq!(exited.clear_child_tid, Some(clear_tid));
        assert_eq!(
            contexts.remove(current),
            Err(kernal_thread_context::Error::PendingUserCleanup)
        );

        let stale = ThreadId {
            slot: current.slot,
            generation: current.generation.wrapping_add(1),
        };
        assert!(complete_cleanup_and_select(&mut run_queue, &mut contexts, stale, exited).is_err());
        assert_eq!(
            contexts.pending_robust_list_head(current),
            Ok(Some(robust_head))
        );
        assert_eq!(
            contexts.pending_clear_child_tid(current),
            Ok(Some(clear_tid))
        );
        assert_eq!(run_queue.state(peer), Ok(ThreadState::Ready));

        let selected =
            complete_cleanup_and_select(&mut run_queue, &mut contexts, current, exited).unwrap();
        assert_eq!(selected.next, peer);
        assert_eq!(contexts.pending_robust_list_head(current), Ok(None));
        assert_eq!(contexts.pending_clear_child_tid(current), Ok(None));
        assert_eq!(run_queue.state(current), Ok(ThreadState::Exited));
        assert_eq!(run_queue.state(peer), Ok(ThreadState::Running));
    }

    #[test]
    fn join_parent_can_become_first_successor_only_after_cleanup_wake() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let clear_tid = 0x0000_7000_0000_2000;

        let parent = running_thread(&mut run_queue, &mut contexts, 9, 0x30_000, None);
        run_queue.block(parent).unwrap();
        assert_eq!(run_queue.state(parent), Ok(ThreadState::Blocked));

        let child = running_thread(&mut run_queue, &mut contexts, 10, 0x40_000, Some(clear_tid));
        let exited = exit_current_for_cleanup(&mut run_queue, &mut contexts, child).unwrap();
        assert_eq!(run_queue.state(child), Ok(ThreadState::Exited));
        assert_eq!(run_queue.state(parent), Ok(ThreadState::Blocked));

        wake_local_exact(&mut run_queue, &contexts, parent).unwrap();
        let selected =
            complete_cleanup_and_select(&mut run_queue, &mut contexts, child, exited).unwrap();

        assert_eq!(selected.next, parent);
        assert_eq!(run_queue.state(child), Ok(ThreadState::Exited));
        assert_eq!(run_queue.state(parent), Ok(ThreadState::Running));
        assert_eq!(contexts.pending_clear_child_tid(child), Ok(None));
    }

    #[test]
    fn local_wake_rejects_nonblocked_and_stale_targets_without_requeue() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let waiter = run_queue.create(9).unwrap();
        install_published(&mut contexts, waiter, 0x50_000, None);
        run_queue.make_ready(waiter).unwrap();

        assert_eq!(
            wake_local_exact(&mut run_queue, &contexts, waiter),
            Err(Error::Invariant)
        );
        assert_eq!(run_queue.state(waiter), Ok(ThreadState::Ready));

        let stale = ThreadId {
            slot: waiter.slot,
            generation: waiter.generation.wrapping_add(1),
        };
        assert!(wake_local_exact(&mut run_queue, &contexts, stale).is_err());
        assert_eq!(run_queue.state(waiter), Ok(ThreadState::Ready));
    }

    #[test]
    fn failed_external_cleanup_leaves_obligation_and_blocks_reap() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let clear_tid = 0x0000_7000_0000_3000;
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x60_000, Some(clear_tid));

        let _exited = exit_current_for_cleanup(&mut run_queue, &mut contexts, current).unwrap();
        assert_eq!(run_queue.state(current), Ok(ThreadState::Exited));
        assert_eq!(
            contexts.pending_clear_child_tid(current),
            Ok(Some(clear_tid))
        );
        assert_eq!(
            contexts.remove(current),
            Err(kernal_thread_context::Error::PendingUserCleanup)
        );
    }

    #[test]
    fn successful_cleanup_without_successor_stays_fail_closed_exited() {
        let mut run_queue = RunQueue::<1>::new();
        let mut contexts = ContextTable::<1>::new();
        let clear_tid = 0x0000_7000_0000_4000;
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x70_000, Some(clear_tid));

        let exited = exit_current_for_cleanup(&mut run_queue, &mut contexts, current).unwrap();
        assert_eq!(
            complete_cleanup_and_select(&mut run_queue, &mut contexts, current, exited),
            Err(Error::NoRunnableThread)
        );
        assert_eq!(run_queue.state(current), Ok(ThreadState::Exited));
        assert_eq!(contexts.pending_clear_child_tid(current), Ok(None));
    }

    #[test]
    fn successor_metadata_failure_restores_peer_after_cleanup() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let clear_tid = 0x0000_7000_0000_5000;
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x80_000, Some(clear_tid));
        let peer = run_queue.create(9).unwrap();
        run_queue.make_ready(peer).unwrap();

        let exited = exit_current_for_cleanup(&mut run_queue, &mut contexts, current).unwrap();
        assert_eq!(
            complete_cleanup_and_select(&mut run_queue, &mut contexts, current, exited),
            Err(Error::Context(kernal_thread_context::Error::Missing))
        );
        assert_eq!(run_queue.state(current), Ok(ThreadState::Exited));
        assert_eq!(run_queue.state(peer), Ok(ThreadState::Ready));
        assert_eq!(contexts.pending_clear_child_tid(current), Ok(None));
    }

    #[test]
    fn stale_generation_cannot_complete_another_threads_cleanup() {
        let mut run_queue = RunQueue::<2>::new();
        let mut contexts = ContextTable::<2>::new();
        let clear_tid = 0x0000_7000_0000_6000;
        let current = running_thread(&mut run_queue, &mut contexts, 10, 0x90_000, Some(clear_tid));
        let peer = run_queue.create(9).unwrap();
        install_published(&mut contexts, peer, 0xa0_000, None);
        run_queue.make_ready(peer).unwrap();
        let exited = exit_current_for_cleanup(&mut run_queue, &mut contexts, current).unwrap();
        let stale = ThreadId {
            slot: current.slot,
            generation: current.generation.wrapping_add(1),
        };

        assert!(
            complete_cleanup_and_select(&mut run_queue, &mut contexts, stale, exited,).is_err()
        );
        assert_eq!(run_queue.state(current), Ok(ThreadState::Exited));
        assert_eq!(run_queue.state(peer), Ok(ThreadState::Ready));
        assert_eq!(
            contexts.pending_clear_child_tid(current),
            Ok(Some(clear_tid))
        );
    }
}
