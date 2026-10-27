// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::*;

mod base;
mod job_control;

pub(super) fn reject_pending_clear_child_tid<const THREADS: usize>(
    contexts: &ContextTable<THREADS>,
    current: ThreadId,
) -> Result<(), Error> {
    base::reject_pending_clear_child_tid(contexts, current)
}

impl<const THREADS: usize, const WAKES: usize> CpuSchedulerCell<THREADS, WAKES> {
    /// Returns the exact current published generation's robust-list registration for exec precommit.
    ///
    /// The observation is generation-bound metadata only. The caller must keep the same owner-local
    /// quiescent SVC window through robust-futex cleanup and the later
    /// [`Self::bootstrap_commit_current_exec_user_state`] call; no context switch or userspace return
    /// may occur between those operations.
    ///
    /// # Safety
    /// Must execute on `expected_current.cpu` with local IRQ delivery masked, `irq_depth=0`,
    /// `preempt_count=0` and migration suppressed. `expected_current` must be the exact current Linux
    /// scheduler generation selected by the canonical identity owner.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_current_exec_robust_list_head(
        &'static self,
        expected_current: GlobalThreadId,
    ) -> Result<Option<u64>, Error> {
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

        // SAFETY: owner quiescence stabilizes both scheduler and context metadata for observation.
        let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
        // SAFETY: same owner-only contract; this borrow is read-only.
        let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
        if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
            || contexts
                .publication_state(current)
                .map_err(Error::Context)?
                != kernal_thread_context::PublicationState::Published
        {
            return Err(Error::Invariant);
        }
        contexts
            .pending_robust_list_head(current)
            .map_err(Error::Context)
    }

    /// Atomically clears current-thread exec metadata and installs architectural TLS zero.
    ///
    /// All owner/current/Running/Published validation happens before the canonical ContextTable
    /// commit. `expected_robust_head` must equal the exact observation previously processed by the
    /// exec robust-futex cleanup under the still-active old TTBR0. A changed registration fails before
    /// any TLS or clear-child-tid mutation. After the ContextTable commit succeeds, installing
    /// TPIDR_EL0=0 is infallible under this owner window.
    ///
    /// # Safety
    /// Same owner/quiescence contract as [`Self::bootstrap_current_exec_robust_list_head`]. The caller
    /// must not allow a context switch, migration, userspace return or robust-list re-registration
    /// between the matching observation/cleanup and this commit.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_commit_current_exec_user_state(
        &'static self,
        expected_current: GlobalThreadId,
        expected_robust_head: Option<u64>,
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

        // SAFETY: owner quiescence stabilizes scheduler state for exact-current validation.
        let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
        // SAFETY: same owner-only contract establishes exclusive ContextTable metadata mutation.
        let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
        if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
            || contexts
                .publication_state(current)
                .map_err(Error::Context)?
                != kernal_thread_context::PublicationState::Published
        {
            return Err(Error::Invariant);
        }
        contexts
            .commit_published_exec_user_state(current, expected_robust_head)
            .map_err(Error::Context)?;

        // SAFETY: the exact current generation's canonical TLS metadata is now zero and the same
        // owner-quiescent SVC window still owns TPIDR_EL0 installation.
        unsafe { kernal_context_aarch64::install_el0_thread_pointer(0) };
        Ok(())
    }
}
