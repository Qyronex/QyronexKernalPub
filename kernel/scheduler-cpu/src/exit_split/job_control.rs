// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::*;
use kernal_scheduler::{JobControlContinueOutcome, JobControlStopOutcome};
use kernal_scheduler_smp::{
    JobControlAppliedOutcome, JobControlCommand, JobControlDrainReport, JobControlDrainResult,
    RemoteJobControlQueue,
};

impl<const THREADS: usize, const WAKES: usize> CpuSchedulerCell<THREADS, WAKES> {
    /// Applies one exact local job-control Stop under the canonical scheduler owner window.
    ///
    /// The target must already be a generation-qualified scheduler identity selected by the Linux
    /// Process/signal owners. This method revalidates owner CPU and Published ContextTable state
    /// before delegating to the sole RunQueue job-control authority.
    ///
    /// # Safety
    /// Must execute on `target.cpu` with local IRQs masked, irq_depth=0 and preempt_count=0.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_job_control_stop(
        &'static self,
        target: GlobalThreadId,
    ) -> Result<JobControlStopOutcome, Error> {
        // SAFETY: delegated caller contract establishes exact owner-local quiescence.
        let _local = unsafe { self.bootstrap_quiescent_local()? };
        if target.cpu != self.owner()? {
            return Err(Error::WrongOwner);
        }
        // SAFETY: quiescent owner window gives exclusive scheduler mutation and stable context state.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only window.
        let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
        if contexts
            .publication_state(target.local)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
        {
            return Err(Error::Invariant);
        }
        run_queue
            .job_control_stop(target.local)
            .map_err(Error::Scheduler)
    }

    /// Applies one exact local job-control Continue under the canonical scheduler owner window.
    ///
    /// Continue only clears the orthogonal stop hold. The RunQueue itself decides whether a real wake
    /// or pre-stop runnable state permits Ready publication; this bridge never manufactures a wake.
    ///
    /// # Safety
    /// Must execute on `target.cpu` with local IRQs masked, irq_depth=0 and preempt_count=0.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn bootstrap_job_control_continue(
        &'static self,
        target: GlobalThreadId,
    ) -> Result<JobControlContinueOutcome, Error> {
        // SAFETY: delegated caller contract establishes exact owner-local quiescence.
        let _local = unsafe { self.bootstrap_quiescent_local()? };
        if target.cpu != self.owner()? {
            return Err(Error::WrongOwner);
        }
        // SAFETY: quiescent owner window gives exclusive scheduler mutation and stable context state.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner-only window.
        let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
        if contexts
            .publication_state(target.local)
            .map_err(Error::Context)?
            != kernal_thread_context::PublicationState::Published
        {
            return Err(Error::Invariant);
        }
        run_queue
            .job_control_continue(target.local)
            .map_err(Error::Scheduler)
    }

    /// Drains already-published exact-generation job-control requests on their owner CPU/PE.
    ///
    /// This compatibility aggregate mirrors the remote-wake IRQ owner boundary. It is suitable for
    /// reschedule accounting only and must never authorize Linux-visible Stop/Continue publication;
    /// callers that need transaction ACK authority must use
    /// [`Self::drain_remote_job_control_exact_from_irq`].
    ///
    /// # Safety
    /// Must run from this owner PE's first-level maskable IRQ handler after `enter_irq()` and before
    /// `exit_irq()`, with local IRQs masked, irq_depth exactly 1 and preempt_count zero.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn drain_remote_job_control_from_irq<const CONTROL: usize>(
        &'static self,
        queue: &RemoteJobControlQueue<CONTROL>,
        maximum: usize,
    ) -> Result<JobControlDrainReport, Error> {
        // SAFETY: delegated first-level IRQ owner contract.
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
        if queue.owner() != self.owner()? {
            return Err(Error::WrongOwner);
        }

        // SAFETY: first-level IRQ owner window excludes local thread-context scheduler mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner window stabilizes publication metadata.
        let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
        let mut report = JobControlDrainReport::default();
        while report.observed < maximum {
            let Some(request) = queue.pop().map_err(Error::Wake)? else {
                break;
            };
            report.observed += 1;
            if request.thread().cpu != self.owner()? {
                return Err(Error::WrongOwner);
            }
            if !matches!(
                contexts.publication_state(request.thread().local),
                Ok(kernal_thread_context::PublicationState::Published)
            ) {
                report.stale += 1;
                continue;
            }
            match request.command() {
                JobControlCommand::Stop => match run_queue.job_control_stop(request.thread().local)
                {
                    Ok(JobControlStopOutcome::AlreadyStopped) => report.already_stopped += 1,
                    Ok(JobControlStopOutcome::Held) => report.held += 1,
                    Ok(JobControlStopOutcome::Deschedule) => report.deschedule += 1,
                    Err(
                        kernal_scheduler::Error::InvalidThread
                        | kernal_scheduler::Error::InvalidState,
                    ) => report.stale += 1,
                    Err(error) => return Err(Error::Scheduler(error)),
                },
                JobControlCommand::Continue => {
                    match run_queue.job_control_continue(request.thread().local) {
                        Ok(JobControlContinueOutcome::NotStopped) => report.not_stopped += 1,
                        Ok(JobControlContinueOutcome::Continued) => report.continued += 1,
                        Ok(JobControlContinueOutcome::Readied) => report.readied += 1,
                        Err(
                            kernal_scheduler::Error::InvalidThread
                            | kernal_scheduler::Error::InvalidState,
                        ) => report.stale += 1,
                        Err(error) => return Err(Error::Scheduler(error)),
                    }
                }
            }
        }
        if report.deschedule > 1 {
            return Err(Error::Invariant);
        }
        Ok(report)
    }

    /// Drains remote Job-Control requests and returns durable exact owner-CPU ACK evidence.
    ///
    /// Every successfully revalidated scheduler request receives an exact ACK, including
    /// `AlreadyStopped` and `NotStopped`. Those no-op outcomes satisfy process-transaction liveness
    /// but never authorize Linux-visible Stop/Continue publication. Unpublished/stale scheduler
    /// generations are discarded without ACK. Applied ACKs remain retained in the transport queue
    /// until Core/Runtime explicitly acknowledges them, so a temporary RuntimeCell Busy condition
    /// cannot erase completion evidence or cause the RunQueue operation to be applied twice.
    ///
    /// # Safety
    /// Same first-level owner-IRQ contract as [`Self::drain_remote_job_control_from_irq`]. `maximum`
    /// must not exceed the mailbox capacity.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub unsafe fn drain_remote_job_control_exact_from_irq<const CONTROL: usize>(
        &'static self,
        queue: &RemoteJobControlQueue<CONTROL>,
        maximum: usize,
    ) -> Result<JobControlDrainResult<CONTROL>, Error> {
        if maximum > CONTROL {
            return Err(Error::Invariant);
        }
        // SAFETY: delegated first-level IRQ owner contract.
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
        if queue.owner() != self.owner()? {
            return Err(Error::WrongOwner);
        }

        // SAFETY: first-level IRQ owner window excludes local thread-context scheduler mutation.
        let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
        // SAFETY: same owner window stabilizes publication metadata.
        let contexts = unsafe { (&*self.contexts.get()).assume_init_ref() };
        let mut report = JobControlDrainReport::default();
        while report.observed < maximum {
            let Some(claim) = queue.claim_pending().map_err(Error::Wake)? else {
                break;
            };
            let request = claim.request();
            report.observed += 1;
            if request.thread().cpu != self.owner()? {
                queue.restore_pending(claim).map_err(Error::Wake)?;
                return Err(Error::WrongOwner);
            }
            if !matches!(
                contexts.publication_state(request.thread().local),
                Ok(kernal_thread_context::PublicationState::Published)
            ) {
                report.stale += 1;
                queue.discard_pending(claim).map_err(Error::Wake)?;
                continue;
            }

            let outcome = match request.command() {
                JobControlCommand::Stop => match run_queue.job_control_stop(request.thread().local)
                {
                    Ok(JobControlStopOutcome::AlreadyStopped) => {
                        report.already_stopped += 1;
                        JobControlAppliedOutcome::AlreadyStopped
                    }
                    Ok(JobControlStopOutcome::Held) => {
                        report.held += 1;
                        JobControlAppliedOutcome::Held
                    }
                    Ok(JobControlStopOutcome::Deschedule) => {
                        report.deschedule += 1;
                        JobControlAppliedOutcome::Deschedule
                    }
                    Err(
                        kernal_scheduler::Error::InvalidThread
                        | kernal_scheduler::Error::InvalidState,
                    ) => {
                        report.stale += 1;
                        queue.discard_pending(claim).map_err(Error::Wake)?;
                        continue;
                    }
                    Err(error) => {
                        queue.restore_pending(claim).map_err(Error::Wake)?;
                        return Err(Error::Scheduler(error));
                    }
                },
                JobControlCommand::Continue => {
                    match run_queue.job_control_continue(request.thread().local) {
                        Ok(JobControlContinueOutcome::NotStopped) => {
                            report.not_stopped += 1;
                            JobControlAppliedOutcome::NotStopped
                        }
                        Ok(JobControlContinueOutcome::Continued) => {
                            report.continued += 1;
                            JobControlAppliedOutcome::Continued
                        }
                        Ok(JobControlContinueOutcome::Readied) => {
                            report.readied += 1;
                            JobControlAppliedOutcome::Readied
                        }
                        Err(
                            kernal_scheduler::Error::InvalidThread
                            | kernal_scheduler::Error::InvalidState,
                        ) => {
                            report.stale += 1;
                            queue.discard_pending(claim).map_err(Error::Wake)?;
                            continue;
                        }
                        Err(error) => {
                            queue.restore_pending(claim).map_err(Error::Wake)?;
                            return Err(Error::Scheduler(error));
                        }
                    }
                }
            };
            queue
                .complete_pending(claim, outcome)
                .map_err(Error::Wake)?;
        }
        if report.deschedule > 1 {
            return Err(Error::Invariant);
        }
        let completions = queue.completed_batch(CONTROL).map_err(Error::Wake)?;
        Ok(JobControlDrainResult::new(report, completions))
    }

    /// Services the existing post-IRQ reschedule boundary after job-control may already have placed
    /// the current generation under a stop hold.
    ///
    /// Ordinary reschedule requests use the existing yield path. A stopped current generation cannot
    /// do so because `job_control_stop` already transitioned Running -> held Ready. That case selects
    /// a successor without a second `yield_running` transition, saves the stopped kernel context, and
    /// later returns here only after SIGCONT plus normal scheduling makes this exact generation
    /// Running again.
    ///
    /// # Safety
    /// Must execute on this cell's owner AArch64 PE with IRQs masked, irq_depth=0 and preempt_count=0.
    /// The destination callback must activate the exact selected Process/address-space generation or
    /// fail closed before returning.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    pub unsafe fn bootstrap_reschedule_with_job_control_destination_address_space(
        &'static self,
        activate_destination: fn(GlobalThreadId, u64),
    ) -> Result<ThreadId, Error> {
        let stopped = {
            // SAFETY: delegated caller contract establishes owner-local quiescence.
            let local = unsafe { self.bootstrap_quiescent_local()? };
            let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
            // SAFETY: same owner window provides stable scheduler observation.
            let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
            run_queue
                .job_control_stopped(current)
                .map_err(Error::Scheduler)?
        };
        if !stopped {
            // SAFETY: caller contract is exactly the existing yield+destination contract.
            return unsafe {
                self.bootstrap_yield_with_destination_address_space(activate_destination)
            };
        }

        // SAFETY: same owner/quiescence contract; this specialized path expects current already held.
        unsafe { self.bootstrap_switch_stopped_current(activate_destination) }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    unsafe fn bootstrap_switch_stopped_current(
        &'static self,
        activate_destination: fn(GlobalThreadId, u64),
    ) -> Result<ThreadId, Error> {
        // SAFETY: delegated owner/quiescence contract.
        let local = unsafe { self.bootstrap_quiescent_local()? };
        let owner = self.owner()?;
        let current = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;

        let (old_sp_ptr, next_sp, next, next_tls, next_address_space) = {
            // SAFETY: owner quiescence gives exclusive mutation of scheduler/context tables.
            let run_queue = unsafe { (&mut *self.run_queue.get()).assume_init_mut() };
            // SAFETY: same owner-only window.
            let contexts = unsafe { (&mut *self.contexts.get()).assume_init_mut() };
            if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Ready
                || !run_queue
                    .job_control_stopped(current)
                    .map_err(Error::Scheduler)?
                || contexts
                    .publication_state(current)
                    .map_err(Error::Context)?
                    != kernal_thread_context::PublicationState::Published
            {
                return Err(Error::Invariant);
            }

            // SAFETY: current still owns live user TLS until the actual context switch below.
            unsafe { capture_user_thread_pointer(contexts, current)? };
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
                Ok((
                    contexts.get(next).map_err(Error::Context)?.saved_rsp,
                    contexts.user_thread_pointer(next).map_err(Error::Context)?,
                    contexts.get(next).map_err(Error::Context)?.address_space,
                ))
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
            (old_sp_ptr, next_sp, next, next_tls, next_address_space)
        };

        activate_destination(GlobalThreadId::new(owner, next), next_address_space);
        local.set_current_thread(pack_thread(next));
        // SAFETY: exact selected generation TLS was validated under owner quiescence.
        unsafe { install_user_thread_pointer(next_tls) };
        // SAFETY: stopped current is held Ready and successor is Running; all table borrows ended.
        unsafe { switch_context(old_sp_ptr, next_sp) };

        let observed = unpack_thread(local.current_thread()).ok_or(Error::NoCurrentThread)?;
        if observed != current {
            return Err(Error::Invariant);
        }
        // Continue + normal selection must have made this exact generation Running before resume.
        // SAFETY: owner quiescence is re-established when this suspended kernel context resumes.
        let run_queue = unsafe { (&*self.run_queue.get()).assume_init_ref() };
        if run_queue.state(current).map_err(Error::Scheduler)? != ThreadState::Running
            || run_queue
                .job_control_stopped(current)
                .map_err(Error::Scheduler)?
        {
            return Err(Error::Invariant);
        }
        Ok(current)
    }
}
