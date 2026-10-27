// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::{marker::PhantomData, ptr::NonNull};
use kernal_process::Process;
use kernal_process_aarch64::{ActiveProcess, BoundProcessAddressSpace, Error};

/// Stable non-owning source for short-lived [`ActiveProcess`] witnesses.
///
/// A blocking FUTEX_WAIT may suspend its kernel stack while another pthread from the same Process
/// runs. Keeping an `ActiveProcess` directly in that suspended frame would also keep shared Process
/// and address-space references live, conflicting with later owner-mutating operations. This handle
/// stores only raw addresses and reacquires the canonical witness inside one synchronous callback.
///
/// The higher-ranked callback prevents the witness and either underlying reference from escaping.
/// The handle is deliberately neither `Send` nor `Sync`; it is an owner-CPU trap resource rather than
/// ambient Process authority.
pub struct ActiveProcessHandle<const CAPS: usize, const VMAS: usize> {
    process: NonNull<Process<CAPS>>,
    space: NonNull<BoundProcessAddressSpace<VMAS>>,
    _not_send_sync: PhantomData<*mut ()>,
}

impl<const CAPS: usize, const VMAS: usize> ActiveProcessHandle<CAPS, VMAS> {
    /// Creates a stable source for scoped current-process validation from the unique runtime owners.
    ///
    /// No Rust reference is retained in the returned value. Requiring mutable owner references keeps
    /// the stored raw-pointer provenance aligned with the owner handles used by the blocking minimum
    /// runtime instead of deriving a long-lived pointer from a shared reference that later writes may
    /// invalidate.
    ///
    /// # Safety
    /// `process` and `space` must remain allocated at stable addresses while this handle can be used.
    /// Every [`Self::with_current`] call must execute under the canonical owner/quiescence contract:
    /// no conflicting mutable reference may exist during the callback, and no address-space switch,
    /// process teardown, migration or owner transfer may occur until the callback returns. Between
    /// callbacks the handle retains no Rust reference, so another owner-serialized pthread may access
    /// the same Process/address-space normally.
    pub unsafe fn new(
        process: &mut Process<CAPS>,
        space: &mut BoundProcessAddressSpace<VMAS>,
    ) -> Self {
        Self {
            process: NonNull::from(process),
            space: NonNull::from(space),
            _not_send_sync: PhantomData,
        }
    }

    /// Revalidates and exposes the canonical witness only for `operation`'s synchronous duration.
    pub fn with_current<R, F>(&self, operation: F) -> Result<R, Error>
    where
        F: for<'a> FnOnce(&ActiveProcess<'a, CAPS, VMAS>) -> R,
    {
        // SAFETY: guaranteed by the constructor's stable-address and scoped-aliasing contract.
        let process = unsafe { self.process.as_ref() };
        // SAFETY: guaranteed by the same constructor contract.
        let space = unsafe { self.space.as_ref() };
        let current = space.current_owner(process)?;
        Ok(operation(&current))
    }
}
