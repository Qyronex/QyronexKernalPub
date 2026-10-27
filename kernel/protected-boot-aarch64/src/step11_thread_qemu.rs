// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::{CapError, CapHandle, CapRights};
use kernal_object::ObjectTable;
use kernal_percpu::CpuIndex;
use kernal_process::{Error as ProcessError, Process, ResolvedThread, ThreadObjectBindings};
use kernal_scheduler::{Error as SchedulerError, RunQueue, ThreadId, ThreadState};
use kernal_scheduler_smp::{GlobalThreadId, ReapedThreadProof};

const CPU0: CpuIndex = CpuIndex(0);
const LEFT_PRIORITY: u8 = 20;
const RIGHT_PRIORITY: u8 = 10;

/// Step-11 runtime ownership proof that ties process-local Thread capabilities to the exact
/// scheduler slot+generation selected immediately before each native EL0 process run.
///
/// This helper owns no architectural state. The AArch64 process-isolation proof remains the owner of
/// TTBR0/PAN/EL0 transitions; this object only proves the architecture-neutral scheduler/object/CSpace
/// lifetime contract around those transitions.
pub(super) struct Step11ThreadProof {
    scheduler: RunQueue<2>,
    bindings: ThreadObjectBindings<2>,
    left_local: ThreadId,
    right_local: ThreadId,
    left_cap: CapHandle,
    right_cap: CapHandle,
}

impl Step11ThreadProof {
    pub(super) fn prepare(
        objects: &mut ObjectTable<8>,
        left: &mut Process<8>,
        right: &mut Process<8>,
    ) -> Result<Self, ()> {
        let mut scheduler = RunQueue::<2>::new();
        let left_local = scheduler.create(LEFT_PRIORITY).map_err(|_| ())?;
        let right_local = scheduler.create(RIGHT_PRIORITY).map_err(|_| ())?;
        let left_thread = GlobalThreadId::new(CPU0, left_local);
        let right_thread = GlobalThreadId::new(CPU0, right_local);
        let mut bindings = ThreadObjectBindings::<2>::new();

        let left_cap = left
            .attach_thread(objects, &mut bindings, &scheduler, CPU0, left_thread)
            .map_err(|_| ())?;
        let right_cap = right
            .attach_thread(objects, &mut bindings, &scheduler, CPU0, right_thread)
            .map_err(|_| ())?;

        // The two private CSpaces deliberately allocate the same local slot/generation. A raw
        // CapHandle is therefore only a process-local name: resolving `left_cap` through right must
        // yield right's scheduler generation, never left's object/authority.
        if left_cap != right_cap
            || Self::resolved(left, objects, &bindings, &scheduler, left_cap)? != left_thread
            || Self::resolved(right, objects, &bindings, &scheduler, right_cap)? != right_thread
            || Self::resolved(right, objects, &bindings, &scheduler, left_cap)? != right_thread
        {
            return Err(());
        }

        // Process destruction must fail while any exact scheduler generation is still bound.
        if left.exit(objects, &bindings) != Err(ProcessError::ThreadsRemain)
            || right.exit(objects, &bindings) != Err(ProcessError::ThreadsRemain)
        {
            return Err(());
        }

        scheduler.make_ready(left_local).map_err(|_| ())?;
        scheduler.make_ready(right_local).map_err(|_| ())?;

        Ok(Self {
            scheduler,
            bindings,
            left_local,
            right_local,
            left_cap,
            right_cap,
        })
    }

    /// Selects process A's exact bound scheduler generation. A has the higher proof priority, so B
    /// must remain Ready while A becomes Running.
    pub(super) fn schedule_left(
        &mut self,
        objects: &ObjectTable<8>,
        left: &Process<8>,
    ) -> Result<(), ()> {
        if self.scheduler.schedule().map_err(|_| ())? != Some(self.left_local)
            || self.scheduler.state(self.left_local).map_err(|_| ())? != ThreadState::Running
            || self.scheduler.state(self.right_local).map_err(|_| ())? != ThreadState::Ready
            || Self::resolved(
                left,
                objects,
                &self.bindings,
                &self.scheduler,
                self.left_cap,
            )? != GlobalThreadId::new(CPU0, self.left_local)
        {
            return Err(());
        }
        Ok(())
    }

    /// Completes A's `exit -> reap -> capability revoke/object release` lifetime and proves that both
    /// the old scheduler identity and old process-local capability are stale before slot reuse.
    pub(super) fn finish_left(
        &mut self,
        objects: &mut ObjectTable<8>,
        left: &mut Process<8>,
    ) -> Result<(), ()> {
        self.scheduler.exit(self.left_local).map_err(|_| ())?;
        if left.exit(objects, &self.bindings) != Err(ProcessError::ThreadsRemain) {
            return Err(());
        }
        self.scheduler.reap(self.left_local).map_err(|_| ())?;
        let old = GlobalThreadId::new(CPU0, self.left_local);
        // SAFETY: this proof-only RunQueue is owned solely by this object and the exact generation
        // above has just completed reap(). Production code obtains the equivalent attestation after
        // the owner-checked CpuSchedulerCell reap path.
        let proof = unsafe { ReapedThreadProof::new_unchecked(old) };
        if left
            .release_reaped_thread(objects, &mut self.bindings, proof, self.left_cap)
            .map_err(|_| ())?
            != old
            || left.resolve_thread(
                objects,
                &self.bindings,
                &self.scheduler,
                CPU0,
                self.left_cap,
            ) != Err(ProcessError::Capability(CapError::StaleHandle))
            || self.scheduler.state(self.left_local) != Err(SchedulerError::InvalidThread)
        {
            return Err(());
        }

        // Force immediate slot reuse and verify the scheduler generation changed. This proves the
        // stale GlobalThreadId cannot alias the replacement occupant of the same local slot.
        let replacement = self.scheduler.create(1).map_err(|_| ())?;
        if replacement.slot != self.left_local.slot
            || replacement.generation == self.left_local.generation
            || self.scheduler.state(self.left_local) != Err(SchedulerError::InvalidThread)
        {
            return Err(());
        }
        self.scheduler.exit(replacement).map_err(|_| ())?;
        self.scheduler.reap(replacement).map_err(|_| ())?;
        Ok(())
    }

    /// B is the only remaining Ready process thread after A's generation has been fully released.
    pub(super) fn schedule_right(
        &mut self,
        objects: &ObjectTable<8>,
        right: &Process<8>,
    ) -> Result<(), ()> {
        if self.scheduler.schedule().map_err(|_| ())? != Some(self.right_local)
            || self.scheduler.state(self.right_local).map_err(|_| ())? != ThreadState::Running
            || Self::resolved(
                right,
                objects,
                &self.bindings,
                &self.scheduler,
                self.right_cap,
            )? != GlobalThreadId::new(CPU0, self.right_local)
        {
            return Err(());
        }
        Ok(())
    }

    pub(super) fn finish_right(
        &mut self,
        objects: &mut ObjectTable<8>,
        right: &mut Process<8>,
    ) -> Result<(), ()> {
        self.scheduler.exit(self.right_local).map_err(|_| ())?;
        if right.exit(objects, &self.bindings) != Err(ProcessError::ThreadsRemain) {
            return Err(());
        }
        self.scheduler.reap(self.right_local).map_err(|_| ())?;
        let old = GlobalThreadId::new(CPU0, self.right_local);
        // SAFETY: this proof-only RunQueue is owned solely by this object and the exact generation
        // above has just completed reap(). Production code uses the owner-checked scheduler path.
        let proof = unsafe { ReapedThreadProof::new_unchecked(old) };
        if right
            .release_reaped_thread(objects, &mut self.bindings, proof, self.right_cap)
            .map_err(|_| ())?
            != old
            || right.resolve_thread(
                objects,
                &self.bindings,
                &self.scheduler,
                CPU0,
                self.right_cap,
            ) != Err(ProcessError::Capability(CapError::StaleHandle))
            || self.scheduler.state(self.right_local) != Err(SchedulerError::InvalidThread)
            || self.scheduler.schedule().map_err(|_| ())?.is_some()
            || !self.bindings.is_empty()
        {
            return Err(());
        }
        Ok(())
    }

    /// Proves explicit authority delegation and process-exit revocation only after every owned thread
    /// generation has been released. The peer stays live long enough to observe the delegated stale
    /// object before its own exit.
    pub(super) fn exit_processes(
        &self,
        objects: &mut ObjectTable<8>,
        left: &mut Process<8>,
        right: &mut Process<8>,
    ) -> Result<(), ()> {
        if !self.bindings.is_empty() {
            return Err(());
        }
        let delegated = left
            .delegate_to(objects, left.address_space_handle(), CapRights::MAP, right)
            .map_err(|_| ())?;
        left.exit(objects, &self.bindings).map_err(|_| ())?;
        if right
            .resolve_object(objects, delegated, CapRights::MAP)
            .is_ok()
        {
            return Err(());
        }
        right.exit(objects, &self.bindings).map_err(|_| ())?;
        Ok(())
    }

    fn resolved(
        process: &Process<8>,
        objects: &ObjectTable<8>,
        bindings: &ThreadObjectBindings<2>,
        scheduler: &RunQueue<2>,
        handle: CapHandle,
    ) -> Result<GlobalThreadId, ()> {
        let ResolvedThread {
            scheduler_thread, ..
        } = process
            .resolve_thread(objects, bindings, scheduler, CPU0, handle)
            .map_err(|_| ())?;
        Ok(scheduler_thread)
    }
}
