// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Keep the accepted Step-15/30 runtime owner in one Rust module while extending only the final
// Step-30 integration seams. `include!` preserves all original privacy and pub(super) boundaries;
// no owner state is copied or shadowed.
include!("step15_runtime.rs");

/// Fixed-capacity scalar observations used only to enumerate already-published signal targets.
///
/// The entries are not Process authority. Every PID must re-enter the canonical PID -> retained
/// Process bridge before credentials or SignalTable state can be observed or mutated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SignalTargetPidBatch {
    pids: [Option<NonZeroU32>; STEP15_RUNTIME_PROCESSES],
}

impl SignalTargetPidBatch {
    const fn new() -> Self {
        Self {
            pids: [None; STEP15_RUNTIME_PROCESSES],
        }
    }

    fn push(&mut self, pid: NonZeroU32) -> Result<(), Error> {
        let slot = self
            .pids
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Error::InvalidState)?;
        *slot = Some(pid);
        Ok(())
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = NonZeroU32> + '_ {
        self.pids.iter().flatten().copied()
    }
}

/// Read-only decision for interrupting one exact blocked Linux syscall generation.
///
/// The value is derived from canonical SignalTable pending/mask/action state but owns none of that
/// state. The signal remains pending until the ordinary architecture signal-delivery transaction
/// prepares and commits it after the blocked syscall has resumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SignalSyscallInterruption {
    ReturnEintr,
    Restart,
    FatalDelivery,
}

impl Step15LinuxRuntime {
    /// Persists one fatal default-signal termination for the exact current scheduler generation.
    ///
    /// Capacity and exact Process/TID authority are proven before the canonical ExitCoordinator is
    /// mutated. Once `begin_signal_termination` succeeds, the returned lifecycle ticket is retained
    /// in the same pending-exit array used by ordinary exit/exit_group; no second exit registry is
    /// introduced.
    pub(super) fn prepare_signal_termination(
        &mut self,
        scheduler_thread: GlobalThreadId,
        signal: u8,
        core_dumped: bool,
    ) -> Result<(), Error> {
        if self
            .pending_exits
            .iter()
            .flatten()
            .any(|(thread, _)| *thread == scheduler_thread)
        {
            return Err(Error::InvalidState);
        }
        let pending_slot = self
            .pending_exits
            .iter()
            .position(Option::is_none)
            .ok_or(Error::InvalidState)?;
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;

        let ticket = {
            let Self {
                process,
                address_space,
                additional_processes,
                identities,
                exits,
                ..
            } = self;
            let selected = if process.id() == process_id {
                RuntimeProcessSlot::validate(&*process, &*address_space)?;
                &*process
            } else {
                let slot = additional_processes
                    .iter()
                    .flatten()
                    .find(|slot| slot.process.id() == process_id)
                    .ok_or(Error::InvalidState)?;
                RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
                &slot.process
            };
            if selected.id() != process_id {
                return Err(Error::InvalidState);
            }
            identities
                .bound_tid_for_scheduler_thread(selected, scheduler_thread)
                .map_err(|_| Error::InvalidState)?;
            exits
                .begin_signal_termination(selected, signal, core_dumped)
                .map_err(Error::Exit)?
        };

        // `begin_signal_termination` is the canonical owner and must return a ticket for the exact
        // Process it was given. Retain even an impossible mismatched ticket before failing closed so
        // a persisted group cause is never silently orphaned from the pending-exit owner.
        self.pending_exits[pending_slot] = Some((scheduler_thread, ticket));
        if ticket.process() != process_id {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    /// Publishes an already-encoded Linux child wait status for one exact retained Process.
    ///
    /// This is the same linear ChildExitPublication path as normal exit. The caller supplies only a
    /// WaitStatus produced from the proof-carrying lifecycle completion cause. Final zombie
    /// publication uses the wake-aware Wait owner edge so a waiter that committed after the earlier
    /// exit-transition notification cannot be lost. Scheduler generations are returned by value and
    /// must be routed only after the LinuxRuntime borrow ends.
    pub(super) fn publish_process_exit_wait_status(
        &mut self,
        process_id: ObjectId,
        status: WaitStatus,
    ) -> Result<Option<WaitWakeBatch<STEP15_RUNTIME_PROCESSES>>, Error> {
        if self.process.id() == process_id {
            return Ok(None);
        }

        let Self {
            additional_processes,
            wait,
            ..
        } = self;
        let slot = additional_processes
            .iter()
            .flatten()
            .find(|slot| slot.process.id() == process_id)
            .ok_or(Error::InvalidState)?;
        RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
        if slot.process.id() != process_id
            || slot.address_space.owner_process() != process_id
            || slot.address_space.address_space_object() != slot.process.address_space()
        {
            return Err(Error::InvalidState);
        }
        let publication = slot.wait_publication.as_ref().ok_or(Error::InvalidState)?;
        wait.publish_exit_with_wakes(publication, &slot.process, status)
            .map(Some)
            .map_err(Error::Wait)
    }

    /// Publishes the Linux wait status encoded from the proof-carrying lifecycle completion cause.
    ///
    /// The legacy `Completion::ProcessExited.status` field exists for ordinary-exit compatibility and
    /// must never overwrite a persisted `ExitCause::Signaled`. Only a final Process exit publishes a
    /// zombie status; thread-only completions leave the child publication untouched.
    pub(super) fn publish_process_exit_completion_wait(
        &mut self,
        process_id: ObjectId,
        completion: &kernal_linux_exit_lifecycle::ThreadIdentityCompletion,
    ) -> Result<Option<WaitWakeBatch<STEP15_RUNTIME_PROCESSES>>, Error> {
        if !matches!(
            completion.completion(),
            kernal_linux_exit_lifecycle::Completion::ProcessExited { .. }
        ) {
            return Ok(None);
        }

        let status = match completion.cause() {
            kernal_linux_exit_lifecycle::ExitCause::Exited(status) => WaitStatus::exited(status),
            kernal_linux_exit_lifecycle::ExitCause::Signaled {
                signal,
                core_dumped,
            } => WaitStatus::signaled(signal, core_dumped).map_err(Error::Wait)?,
        };
        self.publish_process_exit_wait_status(process_id, status)
    }

    /// Returns bounded PID observations for already-published, retained live Linux Processes.
    ///
    /// `process_group` filters through the canonical LinuxIdentity ProcessRecord owner. The runtime's
    /// retained Process/AddressSpace slots are only the bounded enumeration surface; no PID/PGID state
    /// is copied into another registry. Additional-process slots without a transferred Wait publication
    /// token are still staging/rollback state and are deliberately invisible to process-directed kill.
    /// Every returned PID is scalar observation only and must be reselected through
    /// `with_process_signal_target_for_pid` before signal mutation.
    pub(super) fn signal_target_pids(
        &self,
        process_group: Option<NonZeroU32>,
    ) -> Result<SignalTargetPidBatch, Error> {
        let mut batch = SignalTargetPidBatch::new();
        let identities = &self.identities;
        let mut observe = |process: &Process<STEP15_RUNTIME_CAPS>,
                           address_space: &BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>|
         -> Result<(), Error> {
            RuntimeProcessSlot::validate(process, address_space)?;
            if process.state() != ProcessState::Live {
                return Ok(());
            }
            if let Some(expected_group) = process_group {
                let actual_group = identities
                    .getpgid(process)
                    .map_err(|_| Error::InvalidState)?;
                if actual_group != expected_group {
                    return Ok(());
                }
            }
            let pid = identities
                .bound_pid(process)
                .map_err(|_| Error::InvalidState)?;
            batch.push(pid)
        };

        observe(&self.process, &self.address_space)?;
        for slot in self.additional_processes.iter().flatten() {
            if slot.wait_publication.is_none() {
                continue;
            }
            observe(&slot.process, &slot.address_space)?;
        }
        Ok(batch)
    }

    /// Selects at most one exact Linux thread whose currently-next canonical signal delivery
    /// truthfully interrupts a blocked syscall after a process-directed signal queue commit.
    ///
    /// Linux permits process-directed delivery to one eligible thread. The runtime therefore walks
    /// canonical LinuxIdentity generations in stable owner order and asks SignalTable to prepare the
    /// actual next delivery for each. Ignore/Stop/Continue never become a wait interruption; a caught
    /// handler carries its current SA_RESTART policy and fatal default is marked only for wake routing.
    /// Nothing is consumed and no Wait/scheduler state changes here. If another thread consumes a
    /// process-pending signal after this observation, the selected waiter rechecks and reblocks.
    pub(super) fn process_signal_wait_interrupt_target(
        &mut self,
        pid: NonZeroU32,
    ) -> Result<Option<(GlobalThreadId, SignalSyscallInterruption)>, Error> {
        let selected = self.with_process_signal_target_for_pid(
            pid,
            |process, _credentials, identities, signals| {
                for ordinal in 0..STEP15_RUNTIME_THREADS {
                    let thread = match identities.bound_scheduler_thread_at(process, ordinal) {
                        Ok(Some(thread)) => thread,
                        Ok(None) => break,
                        Err(_) => return Err(Error::InvalidState),
                    };
                    let Some(prepared) = signals
                        .prepare_delivery_for_thread(identities, process, thread)
                        .map_err(Error::Signal)?
                    else {
                        continue;
                    };
                    let interruption = match prepared.delivery() {
                        kernal_linux_signal::Delivery::Default {
                            action:
                                kernal_linux_signal::DefaultAction::Ignore
                                | kernal_linux_signal::DefaultAction::Continue
                                | kernal_linux_signal::DefaultAction::Stop,
                            ..
                        } => None,
                        kernal_linux_signal::Delivery::Default {
                            action: kernal_linux_signal::DefaultAction::Terminate { .. },
                            ..
                        } => Some(SignalSyscallInterruption::FatalDelivery),
                        kernal_linux_signal::Delivery::Handler { handler, .. } => {
                            if handler.flags() & kernal_linux_signal::SA_RESTART != 0 {
                                Some(SignalSyscallInterruption::Restart)
                            } else {
                                Some(SignalSyscallInterruption::ReturnEintr)
                            }
                        }
                    };
                    if let Some(interruption) = interruption {
                        return Ok(Some((thread, interruption)));
                    }
                }
                Ok(None)
            },
        )?;
        match selected {
            Some(result) => result,
            None => Ok(None),
        }
    }

    /// Classifies whether one exact blocked scheduler generation has a currently deliverable signal
    /// which truthfully interrupts its Linux syscall, without consuming or changing signal state.
    ///
    /// Selection remains entirely with the canonical SignalTable. Ignored/default-ignored signals and
    /// job-control Stop/Continue do not interrupt here. A caught handler requests either EINTR or
    /// restart from its canonical SA_RESTART flag. Fatal defaults request only that the generation be
    /// made runnable; ordinary signal delivery later consumes the receipt and enters non-returning exit.
    pub(super) fn signal_syscall_interruption_for_thread(
        &self,
        scheduler_thread: GlobalThreadId,
    ) -> Result<Option<SignalSyscallInterruption>, Error> {
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(scheduler_thread)
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
        self.identities
            .bound_tid_for_scheduler_thread(selected, scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        let Some(prepared) = self
            .signals
            .prepare_delivery_for_thread(&self.identities, selected, scheduler_thread)
            .map_err(Error::Signal)?
        else {
            return Ok(None);
        };

        match prepared.delivery() {
            kernal_linux_signal::Delivery::Default {
                action:
                    kernal_linux_signal::DefaultAction::Ignore
                    | kernal_linux_signal::DefaultAction::Continue
                    | kernal_linux_signal::DefaultAction::Stop,
                ..
            } => Ok(None),
            kernal_linux_signal::Delivery::Default {
                action: kernal_linux_signal::DefaultAction::Terminate { .. },
                ..
            } => Ok(Some(SignalSyscallInterruption::FatalDelivery)),
            kernal_linux_signal::Delivery::Handler { handler, .. } => {
                if handler.flags() & kernal_linux_signal::SA_RESTART != 0 {
                    Ok(Some(SignalSyscallInterruption::Restart))
                } else {
                    Ok(Some(SignalSyscallInterruption::ReturnEintr))
                }
            }
        }
    }

    /// Marks the sole Wait owner record for this exact scheduler generation as signal-interrupted.
    ///
    /// LinuxIdentity is revalidated before the Wait owner is mutated. The returned value is scalar
    /// post-commit routing information only: `Wake(thread)` means Core may route that exact generation
    /// through the existing scheduler wake owner after this runtime borrow ends. Prepared interruption
    /// returns no wake and is retained so a later signal-aware commit cannot block past the signal.
    pub(super) fn interrupt_wait_for_signal(
        &mut self,
        scheduler_thread: GlobalThreadId,
    ) -> Result<kernal_linux_wait::WaitInterruptOutcome, Error> {
        self.identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        self.wait
            .interrupt_sleep_for_thread(scheduler_thread)
            .map_err(Error::Wait)
    }

    /// Commits the exact linear wait receipt with signal-interruption awareness.
    ///
    /// The receipt's generation is re-entered through LinuxIdentity before WaitTable mutation. This
    /// does not consume pending signal state and does not wake scheduler state.
    pub(super) fn commit_wait_sleep_signal_aware(
        &mut self,
        receipt: &WaitSleepReceipt,
    ) -> Result<kernal_linux_wait::WaitSignalCommitOutcome, Error> {
        self.identities
            .process_object_for_scheduler_thread(receipt.thread())
            .map_err(|_| Error::InvalidState)?;
        self.wait
            .commit_sleep_signal_aware(receipt)
            .map_err(Error::Wait)
    }

    /// Consumes the exact retained Wait interruption only after Core has revalidated SignalTable.
    ///
    /// `Ok(false)` is the deliberate child-event-wins result: an intervening child exit converted the
    /// marker to Notified and Core must re-observe wait state instead of returning EINTR/restarting.
    pub(super) fn consume_interrupted_wait_for_signal(
        &mut self,
        receipt: WaitSleepReceipt,
    ) -> Result<bool, Error> {
        self.identities
            .process_object_for_scheduler_thread(receipt.thread())
            .map_err(|_| Error::InvalidState)?;
        self.wait
            .consume_interrupted_sleep(receipt)
            .map_err(Error::Wait)
    }

    /// Cancels the exact committed Linux wait registration for one scheduler generation after a
    /// signal owner has established that this specific blocked thread must leave the syscall.
    ///
    /// Compatibility-only bridge retained for older callers. New signal interruption composition must
    /// use `interrupt_wait_for_signal` so Prepared cannot race into a later scheduler block.
    pub(super) fn cancel_committed_wait_for_signal(
        &mut self,
        scheduler_thread: GlobalThreadId,
    ) -> Result<bool, Error> {
        self.identities
            .process_object_for_scheduler_thread(scheduler_thread)
            .map_err(|_| Error::InvalidState)?;
        self.wait
            .cancel_committed_sleep_for_thread(scheduler_thread)
            .map_err(Error::Wait)
    }

    /// Reclaims one exact exited child's anonymous userspace frames before destructive WaitTable reap.
    ///
    /// The caller already owns the sole live page-table backend and sole Core frame allocator before
    /// entering the runtime cell. This preserves the accepted global owner order. The exact zombie is
    /// re-observed with WNOWAIT before the first frame mutation; any cleanup error leaves the WaitTable
    /// zombie and retained Process/AddressSpace slot intact.
    pub(super) fn commit_wait_reap_reclaiming_frames<B: Backend, const FRAME_EXTENTS: usize>(
        &mut self,
        scheduler_thread: GlobalThreadId,
        expected: WaitObservation,
        page_tables: &mut B,
        frames: &mut kernal_frame_allocator::ExtentAllocator<FRAME_EXTENTS>,
    ) -> Result<(), Error> {
        if self.observe_wait_for_scheduler_thread(
            scheduler_thread,
            WaitSelector::Pid(expected.pid()),
            false,
        )? != WaitOutcome::Ready(expected)
        {
            return Err(Error::InvalidState);
        }

        let child_index = self
            .additional_processes
            .iter()
            .position(|slot| {
                slot.as_ref()
                    .is_some_and(|slot| slot.process.id() == expected.child())
            })
            .ok_or(Error::InvalidState)?;
        {
            let child = self.additional_processes[child_index]
                .as_ref()
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&child.process, &child.address_space)?;
            if child.process.id() != expected.child()
                || child.process.state() != ProcessState::Exited
                || child
                    .wait_publication
                    .as_ref()
                    .is_none_or(|publication| publication.child_pid() != expected.pid())
            {
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

            // SAFETY: the retained child is already ProcessState::Exited, its final scheduler
            // generation has been reaped before zombie publication, and the caller holds the sole
            // live RuntimeTablePool mutation window. The data-frame drain above proved the VMA owner
            // empty; the root remains retained here solely so its detached page-table hierarchy can
            // be returned before the destructive WaitTable/RuntimeProcessSlot release below.
            unsafe {
                child
                    .address_space
                    .reclaim_exited_empty_page_table_tree(&child.process, page_tables)
            }
            .map_err(Error::AddressSpace)?;
        }

        self.commit_wait_reap_for_scheduler_thread(scheduler_thread, expected)
    }
}

impl Step15LinuxRuntime {
    /// Commits a fully staged exec replacement for the exact currently-running Linux generation.
    ///
    /// Selection authority comes only from the canonical scheduler-generation -> Process identity
    /// relation. The retained primary or fork-child slot is revalidated before any activation. The
    /// caller must already have proved the Step-30 single-thread exec condition and must own the PE
    /// no-switch/IRQ/preemption/migration window for the complete call.
    ///
    /// On successful `activate_owner`, the replacement is installed into the retained runtime slot by
    /// an immediate infallible `mem::replace`. No fallible operation is permitted between hardware/
    /// logical TTBR0 activation and the slot swap. The exact superseded binding is returned by value
    /// for the canonical process-aarch64 reclaim owner.
    ///
    /// # Safety
    /// The caller must satisfy `BoundProcessAddressSpace::activate_owner` and must not permit a context
    /// switch, migration or lower-EL user access until the replacement has been installed.
    pub(super) unsafe fn commit_exec_address_space_replacement(
        &mut self,
        current: GlobalThreadId,
        replacement: BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>,
    ) -> Result<BoundProcessAddressSpace<STEP15_RUNTIME_VMAS>, Error> {
        let process_id = self
            .identities
            .process_object_for_scheduler_thread(current)
            .map_err(|_| Error::InvalidState)?;

        let Self {
            objects,
            process,
            address_space,
            additional_processes,
            identities,
            ..
        } = self;

        let (selected, retained_address_space) = if process.id() == process_id {
            RuntimeProcessSlot::validate(&*process, &*address_space)?;
            (&*process, address_space)
        } else {
            let slot = additional_processes
                .iter_mut()
                .flatten()
                .find(|slot| slot.process.id() == process_id)
                .ok_or(Error::InvalidState)?;
            RuntimeProcessSlot::validate(&slot.process, &slot.address_space)?;
            let RuntimeProcessSlot {
                process,
                address_space,
                ..
            } = slot;
            (&*process, address_space)
        };

        if selected.id() != process_id || selected.state() != ProcessState::Live {
            return Err(Error::InvalidState);
        }
        identities
            .bound_tid_for_scheduler_thread(selected, current)
            .map_err(|_| Error::InvalidState)?;
        retained_address_space
            .current_owner(selected)
            .map_err(Error::AddressSpace)?;

        if replacement.owner_process() != selected.id()
            || replacement.address_space_object() != selected.address_space()
            || replacement.is_poisoned()
        {
            return Err(Error::InvalidState);
        }

        // SAFETY: delegated caller contract owns this PE's quiesced address-space switch window.
        unsafe { replacement.activate_owner(selected, &*objects) }.map_err(Error::AddressSpace)?;
        let superseded = core::mem::replace(retained_address_space, replacement);
        Ok(superseded)
    }
}

// Additional Step-30 child-exit composition is kept in this same runtime module so it can borrow
// the canonical private Process/Identity/Signal/Wait owners without exposing or duplicating them.
include!("step30_child_exit_runtime_owner.rs");
