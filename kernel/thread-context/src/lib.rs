// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use kernal_scheduler::ThreadId;

pub const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelStack {
    pub guard_start: u64,
    pub mapped_start: u64,
    pub mapped_len: u64,
}

impl KernelStack {
    pub fn new(guard_start: u64, mapped_start: u64, mapped_len: u64) -> Result<Self, Error> {
        if guard_start == 0
            || mapped_start != guard_start.checked_add(PAGE_SIZE).ok_or(Error::Overflow)?
            || mapped_len == 0
            || guard_start & (PAGE_SIZE - 1) != 0
            || mapped_start & (PAGE_SIZE - 1) != 0
            || mapped_len & (PAGE_SIZE - 1) != 0
        {
            return Err(Error::InvalidStack);
        }
        mapped_start
            .checked_add(mapped_len)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            guard_start,
            mapped_start,
            mapped_len,
        })
    }

    pub fn top(self) -> Result<u64, Error> {
        self.mapped_start
            .checked_add(self.mapped_len)
            .ok_or(Error::Overflow)
    }

    pub fn contains_rsp(self, rsp: u64) -> bool {
        let Some(top) = self.mapped_start.checked_add(self.mapped_len) else {
            return false;
        };
        self.mapped_start <= rsp && rsp < top
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadContext {
    pub id: ThreadId,
    pub saved_rsp: u64,
    pub stack: KernelStack,
    pub address_space: u64,
}

impl ThreadContext {
    const EMPTY: Self = Self {
        id: ThreadId {
            slot: 0,
            generation: 0,
        },
        saved_rsp: 0,
        stack: KernelStack {
            guard_start: 0,
            mapped_start: 0,
            mapped_len: 0,
        },
        address_space: 0,
    };
}

/// One-way publication phase for the exact scheduler generation stored in this slot.
///
/// Existing `ContextTable::insert` callers remain immediately Published. Clone/thread creation can
/// instead use `insert_staged`, finish generation-owned initialization while the scheduler thread is
/// still non-runnable, then consume Staged exactly once with `publish`. A later ordinary Blocked
/// scheduler state must never recreate Staged cancellation/initialization authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    Staged,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    InvalidSlot,
    Duplicate,
    Stale,
    Missing,
    InvalidStack,
    InvalidRsp,
    InvalidPublicationState,
    InvalidUserCleanupState,
    PendingUserCleanup,
    Overflow,
}

/// Separates failure to acquire exact staged-generation ownership from a failure in the external
/// scheduler teardown executed while that ownership is held transactionally.
#[derive(Debug, Eq, PartialEq)]
pub enum StagedRollbackError<E> {
    Context(Error),
    Teardown(E),
}

#[derive(Clone, Copy)]
struct Slot {
    occupied: bool,
    generation: u16,
    context: ThreadContext,
    publication: PublicationState,
    // Architecture-neutral storage for the user thread-pointer value associated with this exact
    // scheduler generation. AArch64 Step 15 maps this value to TPIDR_EL0 at owner-controlled
    // selection/resume boundaries; no process-global TLS registry is introduced.
    user_thread_pointer: u64,
    // Optional CLONE_CHILD_CLEARTID user address owned by this exact scheduler generation. The
    // runtime performs the fault-safe zero-store and futex wake; this table only makes the cleanup
    // obligation unskippable by canonical published-context removal.
    pending_clear_child_tid: Option<u64>,
    // Optional Linux robust-list head already validated by the Linux credential/syscall policy
    // owner. The pointer is bound to this exact scheduler generation; this table never dereferences
    // userspace and never creates a second thread registry or futex owner. Published-context removal
    // remains blocked until the existing AArch64 exit/futex owners complete robust cleanup.
    pending_robust_list_head: Option<u64>,
}

impl Slot {
    const EMPTY: Self = Self {
        occupied: false,
        generation: 0,
        context: ThreadContext::EMPTY,
        // Empty slots have no live publication state. Published is the conservative default so a
        // future bug cannot interpret zeroed/empty metadata as unpublished cancellation authority.
        publication: PublicationState::Published,
        // Reused generations must never inherit user TLS or cleanup metadata from the prior occupant.
        user_thread_pointer: 0,
        pending_clear_child_tid: None,
        pending_robust_list_head: None,
    };
}

#[derive(Clone, Copy)]
struct StagedSlotRecord {
    index: usize,
    slot: Slot,
}

/// Fixed-capacity architecture-context metadata keyed by the scheduler's slot+generation ID.
///
/// A scheduler slot may be recycled, but an older ThreadId can never resolve a newer saved RSP,
/// publication phase, user thread pointer or pending user cleanup. This is security-critical because
/// restoring stale execution/TLS metadata, recovering one-time staging authority or completing a
/// recycled thread's CLONE_CHILD_CLEARTID/robust-list obligation would act on another generation.
pub struct ContextTable<const N: usize> {
    slots: [Slot; N],
    len: usize,
}

impl<const N: usize> ContextTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; N],
            len: 0,
        }
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Inserts an already-published generation, preserving the pre-Step-15 behavior for all existing
    /// scheduler callers.
    pub fn insert(
        &mut self,
        id: ThreadId,
        saved_rsp: u64,
        stack: KernelStack,
        address_space: u64,
    ) -> Result<(), Error> {
        self.insert_with_publication(
            id,
            saved_rsp,
            stack,
            address_space,
            PublicationState::Published,
        )
    }

    /// Inserts a generation that is not yet allowed to become normal published scheduler work.
    ///
    /// Callers must explicitly consume this phase through `publish`. The normal `remove` path rejects
    /// Staged contexts, so generic reap/teardown cannot silently bypass the staging owner. Failed
    /// creation rollback must use `remove_staged`.
    pub fn insert_staged(
        &mut self,
        id: ThreadId,
        saved_rsp: u64,
        stack: KernelStack,
        address_space: u64,
    ) -> Result<(), Error> {
        self.insert_with_publication(
            id,
            saved_rsp,
            stack,
            address_space,
            PublicationState::Staged,
        )
    }

    fn insert_with_publication(
        &mut self,
        id: ThreadId,
        saved_rsp: u64,
        stack: KernelStack,
        address_space: u64,
        publication: PublicationState,
    ) -> Result<(), Error> {
        let index = id.slot as usize;
        if index >= N {
            return Err(Error::InvalidSlot);
        }
        if self.slots[index].occupied {
            return if self.slots[index].generation == id.generation {
                Err(Error::Duplicate)
            } else {
                Err(Error::Stale)
            };
        }
        if !stack.contains_rsp(saved_rsp) || saved_rsp & 7 != 0 {
            return Err(Error::InvalidRsp);
        }
        self.slots[index] = Slot {
            occupied: true,
            generation: id.generation,
            context: ThreadContext {
                id,
                saved_rsp,
                stack,
                address_space,
            },
            publication,
            user_thread_pointer: 0,
            pending_clear_child_tid: None,
            pending_robust_list_head: None,
        };
        self.len = self.len.checked_add(1).ok_or(Error::Capacity)?;
        Ok(())
    }

    pub fn get(&self, id: ThreadId) -> Result<&ThreadContext, Error> {
        let slot = self.resolve(id)?;
        Ok(&slot.context)
    }

    pub fn get_mut(&mut self, id: ThreadId) -> Result<&mut ThreadContext, Error> {
        let slot = self.resolve_mut(id)?;
        Ok(&mut slot.context)
    }

    pub fn update_rsp(&mut self, id: ThreadId, saved_rsp: u64) -> Result<(), Error> {
        let context = self.get_mut(id)?;
        if !context.stack.contains_rsp(saved_rsp) || saved_rsp & 7 != 0 {
            return Err(Error::InvalidRsp);
        }
        context.saved_rsp = saved_rsp;
        Ok(())
    }

    /// Returns the opaque user TLS/thread-pointer value bound to exactly this generation.
    pub fn user_thread_pointer(&self, id: ThreadId) -> Result<u64, Error> {
        Ok(self.resolve(id)?.user_thread_pointer)
    }

    /// Replaces the opaque user TLS/thread-pointer value for exactly this generation.
    ///
    /// User-address validation and architecture-specific clone policy stay outside this table. This
    /// owner only prevents stale scheduler generations from reading or mutating another thread's TLS.
    pub fn update_user_thread_pointer(
        &mut self,
        id: ThreadId,
        user_thread_pointer: u64,
    ) -> Result<(), Error> {
        self.resolve_mut(id)?.user_thread_pointer = user_thread_pointer;
        Ok(())
    }

    /// Records one CLONE_CHILD_CLEARTID obligation while this exact child generation is still staged.
    ///
    /// The user address is intentionally opaque here. Clone policy validates it before this call and
    /// the architecture runtime later performs the zero-store and futex wake; this table only makes
    /// the cleanup obligation unskippable by canonical published-context removal. A published
    /// generation cannot acquire or replace this obligation through the clone-staging path.
    pub fn initialize_clear_child_tid(
        &mut self,
        id: ThreadId,
        user_address: u64,
    ) -> Result<(), Error> {
        let slot = self.resolve_mut(id)?;
        if slot.publication != PublicationState::Staged || slot.pending_clear_child_tid.is_some() {
            return Err(Error::InvalidUserCleanupState);
        }
        slot.pending_clear_child_tid = Some(user_address);
        Ok(())
    }

    /// Replaces or disables the clear-child-tid obligation for one exact published generation.
    ///
    /// This is the metadata half of Linux `set_tid_address`. The syscall owner must validate any
    /// nonzero userspace address before calling this method. `None` disables the exit-time zero/wake
    /// obligation. Staged clone initialization remains exclusively owned by
    /// [`Self::initialize_clear_child_tid`], and stale generations fail through exact slot resolution.
    pub fn update_published_clear_child_tid(
        &mut self,
        id: ThreadId,
        user_address: Option<u64>,
    ) -> Result<(), Error> {
        let slot = self.resolve_mut(id)?;
        if slot.publication != PublicationState::Published {
            return Err(Error::InvalidUserCleanupState);
        }
        slot.pending_clear_child_tid = user_address;
        Ok(())
    }

    /// Returns the pending CLONE_CHILD_CLEARTID address for exactly this scheduler generation.
    ///
    /// This read is non-consuming so a failed usercopy or futex wake can be retried. Only
    /// `complete_clear_child_tid` removes the obligation after the external runtime has completed
    /// both operations successfully.
    pub fn pending_clear_child_tid(&self, id: ThreadId) -> Result<Option<u64>, Error> {
        Ok(self.resolve(id)?.pending_clear_child_tid)
    }

    /// Marks this exact published generation's clear-child-tid cleanup complete.
    ///
    /// Runtime ordering is deliberately external: first make the exiting generation non-runnable
    /// while its address space is still current, then zero the user word, FUTEX_WAKE(1), and only
    /// after both succeed call this method. Canonical `remove` remains blocked until then.
    pub fn complete_clear_child_tid(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.resolve_mut(id)?;
        if slot.publication != PublicationState::Published || slot.pending_clear_child_tid.is_none()
        {
            return Err(Error::InvalidUserCleanupState);
        }
        slot.pending_clear_child_tid = None;
        Ok(())
    }

    /// Binds one already-validated Linux robust-list head to this exact published scheduler
    /// generation. The caller owns Linux ABI/user-range validation; this canonical context owner only
    /// provides generation safety and teardown ordering. Re-registering replaces the same thread's
    /// previous head, matching Linux per-thread `set_robust_list` ownership without a second registry.
    pub fn update_robust_list_head(
        &mut self,
        id: ThreadId,
        user_address: u64,
    ) -> Result<(), Error> {
        let slot = self.resolve_mut(id)?;
        if slot.publication != PublicationState::Published || user_address == 0 {
            return Err(Error::InvalidUserCleanupState);
        }
        slot.pending_robust_list_head = Some(user_address);
        Ok(())
    }

    /// Returns the exact generation's registered robust-list head without consuming it.
    ///
    /// Exit integration must keep this metadata live until every target-required robust-futex cleanup
    /// effect has completed successfully. Failed usercopy/CAS/wake work can therefore be retried or
    /// treated as fatal without silently allowing context reap.
    pub fn pending_robust_list_head(&self, id: ThreadId) -> Result<Option<u64>, Error> {
        Ok(self.resolve(id)?.pending_robust_list_head)
    }

    /// Atomically resets the per-thread userspace metadata that must not survive a successful exec.
    ///
    /// `expected_robust_head` is the exact non-consuming robust-list observation processed by the
    /// exec owner under the old userspace address space. Publication phase and robust generation are
    /// fully validated before any mutation, so a stale/re-registered robust head cannot partially
    /// clear TLS or `clear_child_tid`. Once validation succeeds, all three fields are updated through
    /// the same generation-bound slot borrow and no fallible operation remains between them.
    pub fn commit_published_exec_user_state(
        &mut self,
        id: ThreadId,
        expected_robust_head: Option<u64>,
    ) -> Result<(), Error> {
        let slot = self.resolve_mut(id)?;
        if slot.publication != PublicationState::Published
            || slot.pending_robust_list_head != expected_robust_head
        {
            return Err(Error::InvalidUserCleanupState);
        }
        slot.pending_robust_list_head = None;
        slot.pending_clear_child_tid = None;
        slot.user_thread_pointer = 0;
        Ok(())
    }

    /// Consumes the exact published generation's robust-list exit obligation after external cleanup.
    pub fn complete_robust_list_cleanup(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.resolve_mut(id)?;
        if slot.publication != PublicationState::Published
            || slot.pending_robust_list_head.is_none()
        {
            return Err(Error::InvalidUserCleanupState);
        }
        slot.pending_robust_list_head = None;
        Ok(())
    }

    pub fn publication_state(&self, id: ThreadId) -> Result<PublicationState, Error> {
        Ok(self.resolve(id)?.publication)
    }

    /// Consumes one-time staging authority for this exact generation.
    pub fn publish(&mut self, id: ThreadId) -> Result<(), Error> {
        let slot = self.resolve_mut(id)?;
        if slot.publication != PublicationState::Staged {
            return Err(Error::InvalidPublicationState);
        }
        slot.publication = PublicationState::Published;
        Ok(())
    }

    /// Removes only an ordinary published context whose required user cleanup has completed.
    ///
    /// Staged generations are deliberately rejected so canonical reap/teardown code cannot bypass
    /// their initialization/rollback owner. Published generations with pending clear-child-tid or
    /// robust-list cleanup are rejected so teardown cannot release a generation before its external
    /// Linux-visible exit effects complete.
    pub fn remove(&mut self, id: ThreadId) -> Result<ThreadContext, Error> {
        let slot = self.resolve(id)?;
        if slot.publication == PublicationState::Published
            && (slot.pending_clear_child_tid.is_some() || slot.pending_robust_list_head.is_some())
        {
            return Err(Error::PendingUserCleanup);
        }
        self.remove_with_publication(id, PublicationState::Published)
    }

    /// Removes a never-published staged context during fail-closed creation rollback.
    ///
    /// Because the generation never became runnable, rollback may discard staged TLS and a staged
    /// clear-child-tid obligation without writing user memory or waking a futex.
    pub fn remove_staged(&mut self, id: ThreadId) -> Result<ThreadContext, Error> {
        self.take_staged_record(id)
            .map(|record| record.slot.context)
    }

    /// Removes one exact staged generation transactionally around an external teardown operation.
    ///
    /// The full slot record (context, publication authority, TLS and pending clear-child-tid) remains
    /// private to this table. If `teardown` fails, the record is restored before the error is returned.
    /// Because safe callers hold this table through the exclusive `&mut self` borrow for the complete
    /// call and the closure receives no table reference, safe code cannot race a replacement into the
    /// temporarily empty slot or duplicate/move staging authority into another table.
    pub fn rollback_staged_with<E, F>(
        &mut self,
        id: ThreadId,
        teardown: F,
    ) -> Result<ThreadContext, StagedRollbackError<E>>
    where
        F: FnOnce() -> Result<(), E>,
    {
        let record = self
            .take_staged_record(id)
            .map_err(StagedRollbackError::Context)?;
        match teardown() {
            Ok(()) => Ok(record.slot.context),
            Err(error) => {
                self.restore_staged_record(record);
                Err(StagedRollbackError::Teardown(error))
            }
        }
    }

    fn take_staged_record(&mut self, id: ThreadId) -> Result<StagedSlotRecord, Error> {
        let index = id.slot as usize;
        if index >= N {
            return Err(Error::InvalidSlot);
        }
        let slot = self.slots[index];
        if !slot.occupied {
            return Err(Error::Missing);
        }
        if slot.generation != id.generation {
            return Err(Error::Stale);
        }
        if slot.publication != PublicationState::Staged {
            return Err(Error::InvalidPublicationState);
        }
        self.slots[index] = Slot::EMPTY;
        self.len -= 1;
        Ok(StagedSlotRecord { index, slot })
    }

    fn restore_staged_record(&mut self, record: StagedSlotRecord) {
        debug_assert!(!self.slots[record.index].occupied);
        debug_assert_eq!(record.slot.publication, PublicationState::Staged);
        self.slots[record.index] = record.slot;
        self.len += 1;
    }

    fn remove_with_publication(
        &mut self,
        id: ThreadId,
        expected: PublicationState,
    ) -> Result<ThreadContext, Error> {
        let index = id.slot as usize;
        if index >= N {
            return Err(Error::InvalidSlot);
        }
        let slot = &mut self.slots[index];
        if !slot.occupied {
            return Err(Error::Missing);
        }
        if slot.generation != id.generation {
            return Err(Error::Stale);
        }
        if slot.publication != expected {
            return Err(Error::InvalidPublicationState);
        }
        let context = slot.context;
        *slot = Slot::EMPTY;
        self.len -= 1;
        Ok(context)
    }

    fn resolve(&self, id: ThreadId) -> Result<&Slot, Error> {
        let index = id.slot as usize;
        if index >= N {
            return Err(Error::InvalidSlot);
        }
        let slot = &self.slots[index];
        if !slot.occupied {
            return Err(Error::Missing);
        }
        if slot.generation != id.generation {
            return Err(Error::Stale);
        }
        Ok(slot)
    }

    fn resolve_mut(&mut self, id: ThreadId) -> Result<&mut Slot, Error> {
        let index = id.slot as usize;
        if index >= N {
            return Err(Error::InvalidSlot);
        }
        let slot = &mut self.slots[index];
        if !slot.occupied {
            return Err(Error::Missing);
        }
        if slot.generation != id.generation {
            return Err(Error::Stale);
        }
        Ok(slot)
    }
}

impl<const N: usize> Default for ContextTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack() -> KernelStack {
        KernelStack::new(0x1000, 0x2000, 0x4000).unwrap()
    }

    #[test]
    fn stale_generation_cannot_recover_saved_rsp() {
        let mut table = ContextTable::<4>::new();
        let old = ThreadId {
            slot: 1,
            generation: 2,
        };
        table.insert(old, 0x5ff8, stack(), 7).unwrap();
        table.remove(old).unwrap();
        let new = ThreadId {
            slot: 1,
            generation: 3,
        };
        table.insert(new, 0x5ff8, stack(), 8).unwrap();
        assert_eq!(table.get(old), Err(Error::Stale));
        assert_eq!(table.get(new).unwrap().address_space, 8);
    }

    #[test]
    fn existing_insert_callers_are_published_and_use_normal_remove() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 1,
        };
        table.insert(id, 0x5ff8, stack(), 7).unwrap();
        assert_eq!(table.publication_state(id), Ok(PublicationState::Published));
        assert_eq!(table.pending_clear_child_tid(id), Ok(None));
        assert_eq!(table.pending_robust_list_head(id), Ok(None));
        assert_eq!(
            table.initialize_clear_child_tid(id, 0x0000_7000_0000_1000),
            Err(Error::InvalidUserCleanupState)
        );
        assert_eq!(table.publish(id), Err(Error::InvalidPublicationState));
        assert_eq!(table.remove_staged(id), Err(Error::InvalidPublicationState));
        assert_eq!(table.remove(id).unwrap().id, id);
    }

    #[test]
    fn staged_publication_is_one_way_and_blocks_generic_remove() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 4,
        };
        table.insert_staged(id, 0x5ff8, stack(), 9).unwrap();
        assert_eq!(table.publication_state(id), Ok(PublicationState::Staged));
        assert_eq!(table.user_thread_pointer(id), Ok(0));
        assert_eq!(table.pending_clear_child_tid(id), Ok(None));
        assert_eq!(table.pending_robust_list_head(id), Ok(None));
        assert_eq!(table.remove(id), Err(Error::InvalidPublicationState));
        assert_eq!(
            table.update_robust_list_head(id, 0x0000_7000_0000_3000),
            Err(Error::InvalidUserCleanupState)
        );
        table
            .update_user_thread_pointer(id, 0x0000_7000_1234_5000)
            .unwrap();
        table.publish(id).unwrap();
        assert_eq!(table.publication_state(id), Ok(PublicationState::Published));
        assert_eq!(table.user_thread_pointer(id), Ok(0x0000_7000_1234_5000));
        assert_eq!(table.publish(id), Err(Error::InvalidPublicationState));
        assert_eq!(table.remove_staged(id), Err(Error::InvalidPublicationState));
        assert_eq!(table.remove(id).unwrap().id, id);
    }

    #[test]
    fn clear_child_tid_obligation_survives_publication_and_blocks_reap() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 1,
            generation: 5,
        };
        let clear_tid = 0x0000_6000_0000_2000;
        table.insert_staged(id, 0x5ff8, stack(), 10).unwrap();
        table.initialize_clear_child_tid(id, clear_tid).unwrap();
        assert_eq!(table.pending_clear_child_tid(id), Ok(Some(clear_tid)));
        assert_eq!(
            table.initialize_clear_child_tid(id, clear_tid + 4),
            Err(Error::InvalidUserCleanupState)
        );
        table.publish(id).unwrap();
        assert_eq!(table.remove(id), Err(Error::PendingUserCleanup));
        assert_eq!(table.pending_clear_child_tid(id), Ok(Some(clear_tid)));
        table.complete_clear_child_tid(id).unwrap();
        assert_eq!(table.pending_clear_child_tid(id), Ok(None));
        assert_eq!(
            table.complete_clear_child_tid(id),
            Err(Error::InvalidUserCleanupState)
        );
        assert_eq!(table.remove(id).unwrap().id, id);
    }

    #[test]
    fn published_clear_child_tid_can_replace_and_disable_without_staged_authority() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 16,
        };
        let first = 0x0000_6000_0000_7000;
        let replacement = first + 0x1000;
        table.insert(id, 0x5ff8, stack(), 14).unwrap();

        table
            .update_published_clear_child_tid(id, Some(first))
            .unwrap();
        assert_eq!(table.pending_clear_child_tid(id), Ok(Some(first)));
        assert_eq!(table.remove(id), Err(Error::PendingUserCleanup));

        table
            .update_published_clear_child_tid(id, Some(replacement))
            .unwrap();
        assert_eq!(table.pending_clear_child_tid(id), Ok(Some(replacement)));

        table.update_published_clear_child_tid(id, None).unwrap();
        assert_eq!(table.pending_clear_child_tid(id), Ok(None));
        assert_eq!(table.remove(id).unwrap().id, id);
    }

    #[test]
    fn published_clear_child_tid_update_rejects_staged_and_stale_generations() {
        let mut table = ContextTable::<2>::new();
        let staged = ThreadId {
            slot: 1,
            generation: 17,
        };
        table.insert_staged(staged, 0x5ff8, stack(), 15).unwrap();
        assert_eq!(
            table.update_published_clear_child_tid(staged, Some(0x0000_6000_0000_8000),),
            Err(Error::InvalidUserCleanupState)
        );
        table.remove_staged(staged).unwrap();

        let current = ThreadId {
            slot: 1,
            generation: 18,
        };
        table.insert(current, 0x5ff8, stack(), 16).unwrap();
        assert_eq!(
            table.update_published_clear_child_tid(staged, Some(0x0000_6000_0000_9000),),
            Err(Error::Stale)
        );
        assert_eq!(table.pending_clear_child_tid(current), Ok(None));
    }

    #[test]
    fn robust_list_registration_is_generation_bound_and_reap_blocking() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 1,
            generation: 6,
        };
        let head = 0x0000_6000_0000_4000;
        table.insert(id, 0x5ff8, stack(), 10).unwrap();
        assert_eq!(table.pending_robust_list_head(id), Ok(None));
        assert_eq!(
            table.update_robust_list_head(id, 0),
            Err(Error::InvalidUserCleanupState)
        );
        table.update_robust_list_head(id, head).unwrap();
        assert_eq!(table.pending_robust_list_head(id), Ok(Some(head)));
        assert_eq!(table.remove(id), Err(Error::PendingUserCleanup));

        let replacement = head + 0x1000;
        table.update_robust_list_head(id, replacement).unwrap();
        assert_eq!(table.pending_robust_list_head(id), Ok(Some(replacement)));
        table.complete_robust_list_cleanup(id).unwrap();
        assert_eq!(table.pending_robust_list_head(id), Ok(None));
        assert_eq!(
            table.complete_robust_list_cleanup(id),
            Err(Error::InvalidUserCleanupState)
        );
        assert_eq!(table.remove(id).unwrap().id, id);
    }

    #[test]
    fn exec_user_state_commit_resets_cleanup_and_tls_in_one_generation() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 19,
        };
        let tls = 0x0000_7000_1234_5000;
        let clear_tid = 0x0000_6000_0000_a000;
        let robust_head = 0x0000_6000_0000_b000;
        table.insert(id, 0x5ff8, stack(), 17).unwrap();
        table.update_user_thread_pointer(id, tls).unwrap();
        table
            .update_published_clear_child_tid(id, Some(clear_tid))
            .unwrap();
        table.update_robust_list_head(id, robust_head).unwrap();

        table
            .commit_published_exec_user_state(id, Some(robust_head))
            .unwrap();
        assert_eq!(table.user_thread_pointer(id), Ok(0));
        assert_eq!(table.pending_clear_child_tid(id), Ok(None));
        assert_eq!(table.pending_robust_list_head(id), Ok(None));
        assert_eq!(table.remove(id).unwrap().id, id);
    }

    #[test]
    fn exec_user_state_commit_rejects_changed_robust_head_without_partial_reset() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 20,
        };
        let tls = 0x0000_7000_2222_5000;
        let clear_tid = 0x0000_6000_0000_c000;
        let robust_head = 0x0000_6000_0000_d000;
        table.insert(id, 0x5ff8, stack(), 18).unwrap();
        table.update_user_thread_pointer(id, tls).unwrap();
        table
            .update_published_clear_child_tid(id, Some(clear_tid))
            .unwrap();
        table.update_robust_list_head(id, robust_head).unwrap();

        assert_eq!(
            table.commit_published_exec_user_state(id, Some(robust_head + 0x1000)),
            Err(Error::InvalidUserCleanupState)
        );
        assert_eq!(table.user_thread_pointer(id), Ok(tls));
        assert_eq!(table.pending_clear_child_tid(id), Ok(Some(clear_tid)));
        assert_eq!(table.pending_robust_list_head(id), Ok(Some(robust_head)));
    }

    #[test]
    fn exec_user_state_commit_rejects_staged_and_stale_generations() {
        let mut table = ContextTable::<2>::new();
        let staged = ThreadId {
            slot: 1,
            generation: 21,
        };
        table.insert_staged(staged, 0x5ff8, stack(), 19).unwrap();
        table
            .update_user_thread_pointer(staged, 0x0000_7000_3333_5000)
            .unwrap();
        assert_eq!(
            table.commit_published_exec_user_state(staged, None),
            Err(Error::InvalidUserCleanupState)
        );
        assert_eq!(table.user_thread_pointer(staged), Ok(0x0000_7000_3333_5000));
        table.remove_staged(staged).unwrap();

        let current = ThreadId {
            slot: 1,
            generation: 22,
        };
        table.insert(current, 0x5ff8, stack(), 20).unwrap();
        assert_eq!(
            table.commit_published_exec_user_state(staged, None),
            Err(Error::Stale)
        );
        assert_eq!(table.user_thread_pointer(current), Ok(0));
    }

    #[test]
    fn failed_staged_creation_can_cancel_without_publishing_or_user_cleanup() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 1,
            generation: 7,
        };
        table.insert_staged(id, 0x5ff8, stack(), 11).unwrap();
        table
            .update_user_thread_pointer(id, 0x0000_6000_0000_1000)
            .unwrap();
        table
            .initialize_clear_child_tid(id, 0x0000_6000_0000_3000)
            .unwrap();
        assert_eq!(table.remove_staged(id).unwrap().id, id);
        assert_eq!(table.publication_state(id), Err(Error::Missing));
        assert_eq!(table.user_thread_pointer(id), Err(Error::Missing));
        assert_eq!(table.pending_clear_child_tid(id), Err(Error::Missing));
        assert_eq!(table.pending_robust_list_head(id), Err(Error::Missing));
    }

    #[test]
    fn failed_transactional_staged_teardown_restores_tls_and_clear_tid() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 1,
            generation: 11,
        };
        let tls = 0x0000_6000_0000_1000;
        let clear_tid = 0x0000_6000_0000_3000;
        table.insert_staged(id, 0x5ff8, stack(), 12).unwrap();
        table.update_user_thread_pointer(id, tls).unwrap();
        table.initialize_clear_child_tid(id, clear_tid).unwrap();
        let mut teardown_calls = 0;

        assert_eq!(
            table.rollback_staged_with(id, || {
                teardown_calls += 1;
                Err(17_u8)
            }),
            Err(StagedRollbackError::Teardown(17))
        );
        assert_eq!(teardown_calls, 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.publication_state(id), Ok(PublicationState::Staged));
        assert_eq!(table.user_thread_pointer(id), Ok(tls));
        assert_eq!(table.pending_clear_child_tid(id), Ok(Some(clear_tid)));
        assert_eq!(table.pending_robust_list_head(id), Ok(None));
        assert_eq!(table.get(id).unwrap().address_space, 12);
    }

    #[test]
    fn successful_transactional_staged_teardown_discards_only_after_success() {
        let mut contexts = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 1,
            generation: 12,
        };
        contexts.insert_staged(id, 0x5ff8, stack(), 13).unwrap();
        contexts
            .update_user_thread_pointer(id, 0x0000_6000_0000_5000)
            .unwrap();
        contexts
            .initialize_clear_child_tid(id, 0x0000_6000_0000_6000)
            .unwrap();

        assert_eq!(
            contexts.rollback_staged_with::<(), _>(id, || Ok(())),
            Ok(ThreadContext {
                id,
                saved_rsp: 0x5ff8,
                stack: stack(),
                address_space: 13,
            })
        );
        assert!(contexts.is_empty());
        assert_eq!(contexts.publication_state(id), Err(Error::Missing));
        assert_eq!(contexts.user_thread_pointer(id), Err(Error::Missing));
        assert_eq!(contexts.pending_clear_child_tid(id), Err(Error::Missing));
        assert_eq!(contexts.pending_robust_list_head(id), Err(Error::Missing));
    }

    #[test]
    fn stale_transactional_rollback_cannot_touch_reused_generation_or_call_teardown() {
        let mut table = ContextTable::<2>::new();
        let old = ThreadId {
            slot: 0,
            generation: 13,
        };
        table.insert_staged(old, 0x5ff8, stack(), 1).unwrap();
        table.remove_staged(old).unwrap();

        let new = ThreadId {
            slot: 0,
            generation: 14,
        };
        let tls = 0x0000_7000_1234_0000;
        table.insert_staged(new, 0x5ff8, stack(), 2).unwrap();
        table.update_user_thread_pointer(new, tls).unwrap();
        let mut teardown_calls = 0;

        assert_eq!(
            table.rollback_staged_with(old, || {
                teardown_calls += 1;
                Ok::<(), ()>(())
            }),
            Err(StagedRollbackError::Context(Error::Stale))
        );
        assert_eq!(teardown_calls, 0);
        assert_eq!(table.publication_state(new), Ok(PublicationState::Staged));
        assert_eq!(table.user_thread_pointer(new), Ok(tls));
        assert_eq!(table.pending_clear_child_tid(new), Ok(None));
        assert_eq!(table.pending_robust_list_head(new), Ok(None));
    }

    #[test]
    fn published_generation_cannot_enter_transactional_staged_teardown() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 15,
        };
        table.insert(id, 0x5ff8, stack(), 3).unwrap();
        let mut teardown_calls = 0;

        assert_eq!(
            table.rollback_staged_with(id, || {
                teardown_calls += 1;
                Ok::<(), ()>(())
            }),
            Err(StagedRollbackError::Context(Error::InvalidPublicationState))
        );
        assert_eq!(teardown_calls, 0);
        assert_eq!(table.publication_state(id), Ok(PublicationState::Published));
        assert_eq!(table.get(id).unwrap().address_space, 3);
    }

    #[test]
    fn stale_generation_cannot_recover_staging_tls_or_cleanup_after_slot_reuse() {
        let mut table = ContextTable::<2>::new();
        let old = ThreadId {
            slot: 0,
            generation: 8,
        };
        table.insert_staged(old, 0x5ff8, stack(), 1).unwrap();
        table
            .update_user_thread_pointer(old, 0x0000_7000_ffff_0000)
            .unwrap();
        table
            .initialize_clear_child_tid(old, 0x0000_6000_0000_4000)
            .unwrap();
        table.remove_staged(old).unwrap();

        let new = ThreadId {
            slot: 0,
            generation: 9,
        };
        table.insert_staged(new, 0x5ff8, stack(), 2).unwrap();
        assert_eq!(table.publication_state(old), Err(Error::Stale));
        assert_eq!(table.publish(old), Err(Error::Stale));
        assert_eq!(table.remove_staged(old), Err(Error::Stale));
        assert_eq!(table.user_thread_pointer(old), Err(Error::Stale));
        assert_eq!(table.pending_clear_child_tid(old), Err(Error::Stale));
        assert_eq!(table.pending_robust_list_head(old), Err(Error::Stale));
        assert_eq!(table.complete_clear_child_tid(old), Err(Error::Stale));
        assert_eq!(table.complete_robust_list_cleanup(old), Err(Error::Stale));
        assert_eq!(
            table.update_user_thread_pointer(old, 0xdead_beef),
            Err(Error::Stale)
        );
        assert_eq!(
            table.update_robust_list_head(old, 0x0000_7000_1111_0000),
            Err(Error::Stale)
        );
        assert_eq!(
            table.update_published_clear_child_tid(old, Some(0x0000_7000_2222_0000)),
            Err(Error::Stale)
        );
        assert_eq!(table.publication_state(new), Ok(PublicationState::Staged));
        assert_eq!(table.user_thread_pointer(new), Ok(0));
        assert_eq!(table.pending_clear_child_tid(new), Ok(None));
        assert_eq!(table.pending_robust_list_head(new), Ok(None));
        table.remove_staged(new).unwrap();
    }

    #[test]
    fn stack_guard_is_part_of_contract_but_never_valid_rsp() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 1,
        };
        assert_eq!(table.insert(id, 0x1000, stack(), 0), Err(Error::InvalidRsp));
        assert!(table.insert(id, 0x2000, stack(), 0).is_ok());
    }

    #[test]
    fn rsp_updates_must_stay_inside_owned_stack() {
        let mut table = ContextTable::<2>::new();
        let id = ThreadId {
            slot: 0,
            generation: 1,
        };
        table.insert(id, 0x5ff8, stack(), 0).unwrap();
        assert_eq!(table.update_rsp(id, 0x6000), Err(Error::InvalidRsp));
        table.update_rsp(id, 0x3000).unwrap();
        assert_eq!(table.get(id).unwrap().saved_rsp, 0x3000);
    }
}
