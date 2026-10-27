// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Exact scheduler generations that need notification after a kernel-generated SIGCHLD commit.
///
/// This is routing observation only. It carries no scheduler or signal authority and must be
/// consumed only after the sole Linux runtime borrow that produced it has ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessExitSignalTargets {
    threads: [Option<GlobalThreadId>; STEP15_RUNTIME_THREADS],
}

impl ProcessExitSignalTargets {
    const fn empty() -> Self {
        Self {
            threads: [None; STEP15_RUNTIME_THREADS],
        }
    }

    fn push(&mut self, thread: GlobalThreadId) -> Result<(), Error> {
        let slot = self
            .threads
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Error::InvalidState)?;
        *slot = Some(thread);
        Ok(())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.threads.iter().all(Option::is_none)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = GlobalThreadId> + '_ {
        self.threads.iter().flatten().copied()
    }
}

/// Exact live scheduler generations currently bound to one canonical Linux Process generation.
///
/// This is observation only. `process` and `pid` are retained together solely to make stale target
/// batches fail closed when Core later re-enters the canonical runtime owner. The batch carries no
/// Process capability and cannot authorize direct mutation of a foreign CPU RunQueue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessJobControlTargets {
    process: ObjectId,
    pid: NonZeroU32,
    threads: [Option<GlobalThreadId>; STEP15_RUNTIME_THREADS],
    len: usize,
}

impl ProcessJobControlTargets {
    const fn empty(process: ObjectId, pid: NonZeroU32) -> Self {
        Self {
            process,
            pid,
            threads: [None; STEP15_RUNTIME_THREADS],
            len: 0,
        }
    }

    fn push(&mut self, thread: GlobalThreadId) -> Result<(), Error> {
        let slot = self
            .threads
            .get_mut(self.len)
            .ok_or(Error::InvalidState)?;
        *slot = Some(thread);
        self.len += 1;
        Ok(())
    }

    pub(super) const fn process(&self) -> ObjectId {
        self.process
    }

    pub(super) const fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = GlobalThreadId> + '_ {
        self.threads[..self.len].iter().flatten().copied()
    }
}

/// Process-level Linux job-control observation authorized only after Core has collected real
/// scheduler completion for one exact transaction generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessJobControlEvent {
    Stopped { signal: u8 },
    Continued,
}

/// Cross-owner routing obligations produced by one process-level job-control publication.
/// Wait wakes and SIGCHLD notification targets are returned as exact scheduler generations; this
/// owner never mutates a RunQueue or sends an SGI itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessJobControlPublication {
    wakes: WaitWakeBatch<STEP15_RUNTIME_PROCESSES>,
    signal_targets: ProcessExitSignalTargets,
}

impl ProcessJobControlPublication {
    pub(super) const fn wakes(self) -> WaitWakeBatch<STEP15_RUNTIME_PROCESSES> {
        self.wakes
    }

    pub(super) const fn signal_targets(self) -> ProcessExitSignalTargets {
        self.signal_targets
    }
}

/// Cross-owner result after one final Process-exit completion has sampled the canonical SIGCHLD
/// action and, where applicable, committed the parent signal generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcessExitWaitDisposition {
    /// The lifecycle completion was thread-only, or the process has no retained parent publication.
    NoParentPublication,
    /// Ordinary Linux zombie publication committed in the sole Wait owner.
    ZombiePublished(WaitWakeBatch<STEP15_RUNTIME_PROCESSES>),
    /// SIGCHLD policy requires no zombie. The exact retained exited Process still needs its anonymous
    /// frames reclaimed before the Wait record and RuntimeProcessSlot may be removed.
    AutoReap(ObjectId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessExitWaitPlan {
    disposition: ProcessExitWaitDisposition,
    signal_targets: ProcessExitSignalTargets,
}

impl ProcessExitWaitPlan {
    pub(super) const fn disposition(self) -> ProcessExitWaitDisposition {
        self.disposition
    }

    pub(super) const fn signal_targets(self) -> ProcessExitSignalTargets {
        self.signal_targets
    }
}

impl Step15LinuxRuntime {
    /// Re-enters the canonical PID/Process owner and snapshots every currently bound exact scheduler
    /// generation for one live Process. No scalar PID becomes scheduler authority: the retained
    /// Process/AddressSpace owner and LinuxIdentity binding are both revalidated before enumeration.
    pub(super) fn job_control_targets_for_pid(
        &self,
        pid: NonZeroU32,
    ) -> Result<ProcessJobControlTargets, Error> {
        let process_id = self
            .identities
            .process_object_for_pid(pid)
            .map_err(|_| Error::InvalidState)?;
        let selected = if self.process.id() == process_id {
            RuntimeProcessSlot::validate(&self.process, &self.address_space)?;
            &self.process
        } else {
            let slot = self
                .additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == process_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if selected.id() != process_id
            || selected.state() != ProcessState::Live
            || self
                .identities
                .bound_pid(selected)
                .map_err(|_| Error::InvalidState)?
                != pid
        {
            return Err(Error::InvalidState);
        }

        let mut targets = ProcessJobControlTargets::empty(process_id, pid);
        for ordinal in 0..STEP15_RUNTIME_THREADS {
            match self.identities.bound_scheduler_thread_at(selected, ordinal) {
                Ok(Some(thread)) => targets.push(thread)?,
                Ok(None) => break,
                Err(_) => return Err(Error::InvalidState),
            }
        }
        if targets.is_empty() {
            return Err(Error::InvalidState);
        }
        Ok(targets)
    }

    /// Publishes one real process-level Stop/Continue observation after scheduler completion.
    ///
    /// `targets` is observation only. The canonical PID->Process binding and retained child/parent
    /// publication are revalidated before mutation. Wait visibility is unconditional for a real
    /// scheduler transition. `SA_NOCLDSTOP` suppresses only the generated SIGCHLD notification for
    /// both Stop and Continue and never suppresses the WaitTable observation.
    pub(super) fn publish_process_job_control_completion(
        &mut self,
        targets: ProcessJobControlTargets,
        event: ProcessJobControlEvent,
    ) -> Result<Option<ProcessJobControlPublication>, Error> {
        let current_targets = self.job_control_targets_for_pid(targets.pid())?;
        if current_targets != targets {
            return Err(Error::InvalidState);
        }

        // The bootstrap process has no retained parent publication inside this bounded runtime.
        if self.process.id() == targets.process() {
            return Ok(None);
        }

        let child_index = self
            .additional_processes
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|slot| slot.process.id() == targets.process())
            })
            .ok_or(Error::InvalidState)?;
        let (parent_id, parent_pid, child_pid) = {
            let child = self.additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&child.process, &child.address_space)?;
            if child.process.state() != ProcessState::Live
                || self
                    .identities
                    .bound_pid(&child.process)
                    .map_err(|_| Error::InvalidState)?
                    != targets.pid()
            {
                return Err(Error::InvalidState);
            }
            let publication = child.wait_publication.as_ref().ok_or(Error::InvalidState)?;
            (
                publication.parent(),
                publication.parent_pid(),
                publication.child_pid(),
            )
        };

        if self
            .identities
            .process_object_for_pid(parent_pid)
            .map_err(|_| Error::InvalidState)?
            != parent_id
        {
            return Err(Error::InvalidState);
        }

        // A real scheduler transition is already authoritative. Publish Wait first so artificial
        // SignalTable capacity cannot erase Linux job-control visibility.
        let wakes = {
            let Self {
                additional_processes,
                wait,
                ..
            } = self;
            let child = additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            let publication = child.wait_publication.as_ref().ok_or(Error::InvalidState)?;
            match event {
                ProcessJobControlEvent::Stopped { signal } => wait
                    .publish_stopped_with_wakes(publication, &child.process, signal)
                    .map_err(Error::Wait)?,
                ProcessJobControlEvent::Continued => wait
                    .publish_continued_with_wakes(publication, &child.process)
                    .map_err(Error::Wait)?,
            }
        };

        let mut signal_targets = ProcessExitSignalTargets::empty();
        {
            let Self {
                process,
                address_space,
                additional_processes,
                identities,
                credentials,
                signals,
                ..
            } = self;
            let child = additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&child.process, &child.address_space)?;
            let child_uid = credentials
                .credentials(&child.process)
                .map_err(Error::Credentials)?
                .ruid();

            let parent = if process.id() == parent_id {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                &*process
            } else {
                let parent_slot = additional_processes
                    .iter()
                    .flatten()
                    .find(|slot| slot.process.id() == parent_id)
                    .ok_or(Error::InvalidState)?;
                RuntimeProcessSlot::validate(&parent_slot.process, &parent_slot.address_space)?;
                &parent_slot.process
            };
            if parent.state() != ProcessState::Live
                || identities
                    .bound_pid(parent)
                    .map_err(|_| Error::InvalidState)?
                    != parent_pid
            {
                return Err(Error::InvalidState);
            }

            let sigchld = kernal_linux_signal::Signal::new(kernal_linux_signal::SIGCHLD)
                .ok_or(Error::InvalidState)?;
            let action = signals.action(parent, sigchld).map_err(Error::Signal)?;
            if action.flags() & kernal_linux_signal::SA_NOCLDSTOP == 0 {
                if matches!(action.disposition(), kernal_linux_signal::Disposition::Handler(_)) {
                    for ordinal in 0..STEP15_RUNTIME_THREADS {
                        match identities.bound_scheduler_thread_at(parent, ordinal) {
                            Ok(Some(thread)) => signal_targets.push(thread)?,
                            Ok(None) => break,
                            Err(_) => return Err(Error::InvalidState),
                        }
                    }
                    if signal_targets.is_empty() {
                        return Err(Error::InvalidState);
                    }
                }

                let provenance = match event {
                    ProcessJobControlEvent::Stopped { signal } => {
                        kernal_linux_signal::ChildSignalProvenance::stopped(
                            child_pid,
                            child_uid,
                            signal,
                        )
                        .ok_or(Error::InvalidState)?
                    }
                    ProcessJobControlEvent::Continued => {
                        kernal_linux_signal::ChildSignalProvenance::continued(child_pid, child_uid)
                    }
                };
                signals
                    .queue_signal_with_provenance(
                        parent,
                        sigchld,
                        kernal_linux_signal::SignalProvenance::Child(provenance),
                    )
                    .map_err(Error::Signal)?;
            }
        }

        Ok(Some(ProcessJobControlPublication {
            wakes,
            signal_targets,
        }))
    }

    /// Releases the exact exited child Process generation's Linux program-break metadata.
    ///
    /// The child must still be retained by the canonical runtime Process/AddressSpace owner and must
    /// already be Exited. Missing state is accepted only to make the exit plan retry-idempotent after
    /// a successful prior release or for pre-fix/manual test children that never owned a break slot.
    /// No live Process may lose its break state through this edge.
    fn retire_exited_process_break(&mut self, process_id: ObjectId) -> Result<(), Error> {
        if self.process.id() == process_id {
            return Err(Error::InvalidState);
        }
        let child = self
            .additional_processes
            .iter()
            .flatten()
            .find(|slot| slot.process.id() == process_id)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&child.process, &child.address_space)?;
        if child.process.state() != ProcessState::Exited {
            return Err(Error::InvalidState);
        }
        match self.vm.remove_process_break(process_id) {
            Ok(()) | Err(kernal_linux_vm::Error::MissingBreakState) => Ok(()),
            Err(_) => Err(Error::InvalidState),
        }
    }

    /// Samples the parent SIGCHLD action at the final Process-exit linearization point, commits the
    /// kernel-generated SIGCHLD when appropriate, and either publishes the ordinary zombie or returns
    /// an exact auto-reap observation for the owner-ordered resource drain.
    ///
    /// The child LinuxIdentity record is retired only after the lifecycle branches converge in Core.
    /// Parent authority is re-entered through the exact `(parent ObjectId, parent PID)` snapshot
    /// retained by the sole Wait owner. Scalar PID or ObjectId alone never authorizes signal policy.
    pub(super) fn prepare_process_exit_wait_plan(
        &mut self,
        process_id: ObjectId,
        completion: kernal_linux_exit_lifecycle::Completion,
        cause: kernal_linux_exit_lifecycle::ExitCause,
    ) -> Result<ProcessExitWaitPlan, Error> {
        if !matches!(
            completion,
            kernal_linux_exit_lifecycle::Completion::ProcessExited { .. }
        ) {
            return Ok(ProcessExitWaitPlan {
                disposition: ProcessExitWaitDisposition::NoParentPublication,
                signal_targets: ProcessExitSignalTargets::empty(),
            });
        }
        if self.process.id() == process_id {
            return Ok(ProcessExitWaitPlan {
                disposition: ProcessExitWaitDisposition::NoParentPublication,
                signal_targets: ProcessExitSignalTargets::empty(),
            });
        }

        let child_index = self
            .additional_processes
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|slot| slot.process.id() == process_id)
            })
            .ok_or(Error::InvalidState)?;
        let (parent_id, parent_pid, child_pid) = {
            let child = self.additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&child.process, &child.address_space)?;
            if child.process.state() != ProcessState::Exited {
                return Err(Error::InvalidState);
            }
            let publication = child.wait_publication.as_ref().ok_or(Error::InvalidState)?;
            (
                publication.parent(),
                publication.parent_pid(),
                publication.child_pid(),
            )
        };

        if self
            .identities
            .process_object_for_pid(parent_pid)
            .map_err(|_| Error::InvalidState)?
            != parent_id
        {
            return Err(Error::InvalidState);
        }

        let mut signal_targets = ProcessExitSignalTargets::empty();
        let auto_reap = {
            let Self {
                process,
                address_space,
                additional_processes,
                identities,
                credentials,
                signals,
                ..
            } = self;
            let parent = if process.id() == parent_id {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                &*process
            } else {
                let parent_slot = additional_processes
                    .iter()
                    .flatten()
                    .find(|slot| slot.process.id() == parent_id)
                    .ok_or(Error::InvalidState)?;
                RuntimeProcessSlot::validate(&parent_slot.process, &parent_slot.address_space)?;
                &parent_slot.process
            };
            if parent.state() != ProcessState::Live
                || identities
                    .bound_pid(parent)
                    .map_err(|_| Error::InvalidState)?
                    != parent_pid
            {
                return Err(Error::InvalidState);
            }

            let sigchld = kernal_linux_signal::Signal::new(kernal_linux_signal::SIGCHLD)
                .ok_or(Error::InvalidState)?;
            let action = signals.action(parent, sigchld).map_err(Error::Signal)?;
            if matches!(action.disposition(), kernal_linux_signal::Disposition::Handler(_)) {
                for ordinal in 0..STEP15_RUNTIME_THREADS {
                    match identities.bound_scheduler_thread_at(parent, ordinal) {
                        Ok(Some(thread)) => signal_targets.push(thread)?,
                        Ok(None) => break,
                        Err(_) => return Err(Error::InvalidState),
                    }
                }
                if signal_targets.is_empty() {
                    return Err(Error::InvalidState);
                }
            }

            // Step 30 has no setuid/setgid credential-mutation surface: fork inherits this exact
            // credential vector and no later syscall can change it. The live parent's real uid is
            // therefore also the exited child's real uid at this compatibility step. If credential
            // mutation is added later this observation must move to an exact child snapshot retained
            // before credential retirement.
            let child_uid = credentials
                .credentials(parent)
                .map_err(Error::Credentials)?
                .ruid();
            let child_provenance = match cause {
                kernal_linux_exit_lifecycle::ExitCause::Exited(status) => {
                    kernal_linux_signal::ChildSignalProvenance::exited(
                        child_pid,
                        child_uid,
                        status,
                    )
                }
                kernal_linux_exit_lifecycle::ExitCause::Signaled {
                    signal,
                    core_dumped,
                } => kernal_linux_signal::ChildSignalProvenance::signaled(
                    child_pid,
                    child_uid,
                    signal,
                    core_dumped,
                )
                .ok_or(Error::InvalidState)?,
            };

            // Linux distinguishes the default SIGCHLD action from an explicitly installed SIG_IGN:
            // both discard signal delivery, but only explicit SIG_IGN implies no zombie. Linux also
            // auto-reaps for SA_NOCLDWAIT; unlike SIG_IGN, a caught SIGCHLD is still generated.
            let auto_reap = matches!(
                action.disposition(),
                kernal_linux_signal::Disposition::Ignore
            ) || action.flags() & kernal_linux_signal::SA_NOCLDWAIT != 0;

            // Child provenance is committed before any zombie/auto-reap mutation so a caught handler
            // retains CLD_*, si_pid, si_uid and si_status even when SA_NOCLDWAIT destroys the child
            // record immediately afterward. Default/Ignore actions are still discarded by the sole
            // SignalTable, and standard-signal coalescing keeps the first pending child provenance.
            signals
                .queue_signal_with_provenance(
                    parent,
                    sigchld,
                    kernal_linux_signal::SignalProvenance::Child(child_provenance),
                )
                .map_err(Error::Signal)?;
            auto_reap
        };

        if auto_reap {
            self.retire_exited_process_break(process_id)?;
            return Ok(ProcessExitWaitPlan {
                disposition: ProcessExitWaitDisposition::AutoReap(process_id),
                signal_targets,
            });
        }

        let status = match cause {
            kernal_linux_exit_lifecycle::ExitCause::Exited(status) => WaitStatus::exited(status),
            kernal_linux_exit_lifecycle::ExitCause::Signaled {
                signal,
                core_dumped,
            } => WaitStatus::signaled(signal, core_dumped).map_err(Error::Wait)?,
        };
        let wakes = self
            .publish_process_exit_wait_status(process_id, status)?
            .ok_or(Error::InvalidState)?;
        self.retire_exited_process_break(process_id)?;

        Ok(ProcessExitWaitPlan {
            disposition: ProcessExitWaitDisposition::ZombiePublished(wakes),
            signal_targets,
        })
    }

    /// Completes one previously selected auto-reap after the caller has acquired live page-table and
    /// physical-frame owners in the canonical global order.
    ///
    /// Frame drain is retry-safe: a completed prior drain observes no remaining VMAs, while any
    /// partial cleanup failure poisons the address-space binding and fails closed. Exited credential
    /// and signal metadata retirement is idempotent. Only after those resources are closed does the
    /// sole Wait owner remove the child without a zombie and the runtime release the retained slot.
    pub(super) fn commit_process_auto_reap_reclaiming_frames<
        B: Backend,
        const FRAME_EXTENTS: usize,
    >(
        &mut self,
        process_id: ObjectId,
        page_tables: &mut B,
        frames: &mut kernal_frame_allocator::ExtentAllocator<FRAME_EXTENTS>,
    ) -> Result<WaitWakeBatch<STEP15_RUNTIME_PROCESSES>, Error> {
        if self.process.id() == process_id {
            return Err(Error::InvalidState);
        }
        let child_index = self
            .additional_processes
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|slot| slot.process.id() == process_id)
            })
            .ok_or(Error::InvalidState)?;
        {
            let child = self.additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&child.process, &child.address_space)?;
            if child.process.state() != ProcessState::Exited || child.wait_publication.is_none() {
                return Err(Error::InvalidState);
            }
        }

        {
            let child = self.additional_processes[child_index]
                .as_mut()
                .ok_or(Error::InvalidState)?;
            child
                .address_space
                .reclaim_exited_anonymous_user_frames(&child.process, page_tables, |frame| {
                    let Ok(range) =
                        kernal_frame_allocator::FrameRange::new(frame.start_address(), 1)
                    else {
                        return false;
                    };
                    frames.free(range).is_ok()
                })
                .map_err(Error::AddressSpace)?;

            // SAFETY: auto-reap is entered only for an exact retained Exited child after final
            // scheduler lifecycle completion. The frame drain above proved the VMA owner empty and
            // the caller owns the sole live RuntimeTablePool mutation window. Return the detached
            // TTBR0 hierarchy before WaitTable removes the final retained child publication/slot.
            unsafe {
                child
                    .address_space
                    .reclaim_exited_empty_page_table_tree(&child.process, page_tables)
            }
            .map_err(Error::AddressSpace)?;
        }

        {
            let Self {
                additional_processes,
                credentials,
                signals,
                ..
            } = self;
            let child = &additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?
                .process;
            match credentials.retire_process(child) {
                Ok(_) | Err(CredentialError::ProcessNotBound) => {}
                Err(error) => return Err(Error::Credentials(error)),
            }
            match signals.retire_process(child) {
                Ok(()) | Err(SignalError::ProcessNotBound) => {}
                Err(error) => return Err(Error::Signal(error)),
            }
        }

        let wakes = {
            let Self {
                additional_processes,
                wait,
                ..
            } = self;
            let child = additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            let publication = child.wait_publication.as_ref().ok_or(Error::InvalidState)?;
            wait.auto_reap_exit_with_wakes(publication, &child.process)
                .map_err(Error::Wait)?
        };

        let removed = self.additional_processes[child_index]
            .take()
            .ok_or(Error::InvalidState)?;
        debug_assert_eq!(removed.process.id(), process_id);
        Ok(wakes)
    }

    /// Observes one child status for the exact current scheduler generation while preserving the
    /// syscall's exact Linux event interests. This remains phase-1 only: no child or job-control
    /// observation is consumed until all fallible userspace result publication has completed.
    pub(super) fn observe_wait_for_scheduler_thread_with_interests(
        &mut self,
        scheduler_thread: GlobalThreadId,
        selector: WaitSelector,
        nohang: bool,
        interests: kernal_linux_wait::WaitInterests,
    ) -> Result<WaitOutcome, Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let Self {
            process,
            address_space,
            additional_processes,
            wait,
            ..
        } = self;
        let parent = if process.id() == parent_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if parent.id() != parent_id || parent.state() != ProcessState::Live {
            return Err(Error::InvalidState);
        }
        wait.wait(
            parent,
            selector,
            WaitOptions::with_interests(nohang, true, interests),
        )
        .map_err(Error::Wait)
    }

    /// Prepares one exact-generation blocking wait with the same event interests used during phase 1.
    /// The linear receipt retains those interests across signal and scheduler races.
    pub(super) fn prepare_wait_sleep_for_scheduler_thread_with_interests(
        &mut self,
        scheduler_thread: GlobalThreadId,
        selector: WaitSelector,
        interests: kernal_linux_wait::WaitInterests,
    ) -> Result<WaitPrepareOutcome, Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let Self {
            process,
            address_space,
            additional_processes,
            wait,
            ..
        } = self;
        let parent = if process.id() == parent_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if parent.id() != parent_id || parent.state() != ProcessState::Live {
            return Err(Error::InvalidState);
        }
        wait.prepare_sleep_with_interests(parent, selector, interests, scheduler_thread)
            .map_err(Error::Wait)
    }

    /// Consumes one exact nonterminal Stop/Continue observation after successful userspace writeback.
    /// The Wait owner checks class/status/generation and never reaps the child or releases any
    /// Process, AddressSpace, FD/OFD, credential or signal authority on this edge.
    pub(super) fn consume_wait_nonterminal_for_scheduler_thread(
        &mut self,
        scheduler_thread: GlobalThreadId,
        observation: WaitObservation,
    ) -> Result<(), Error> {
        let parent_id = {
            let (parent, _, _) = self.process_parts_for_scheduler_thread(scheduler_thread)?;
            parent.id()
        };
        let Self {
            process,
            address_space,
            additional_processes,
            wait,
            ..
        } = self;
        let parent = if process.id() == parent_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            &*process
        } else {
            let slot = additional_processes
                .iter()
                .flatten()
                .find(|slot| slot.process.id() == parent_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            &slot.process
        };
        if parent.id() != parent_id || parent.state() != ProcessState::Live {
            return Err(Error::InvalidState);
        }
        wait.consume_nonterminal_observation(parent, observation)
            .map_err(Error::Wait)
    }
}