// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_usercopy::UserRange;

pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_VFORK: u64 = 0x0000_4000;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_DETACHED: u64 = 0x0040_0000;

/// Linux signal number used by the process-family clone shapes accepted in Step 30.
pub const LINUX_SIGCHLD: u64 = 17;
/// Exact legacy-clone flags for the target-required fork-shaped process creation path.
pub const FORK_PROCESS_FLAGS: u64 = LINUX_SIGCHLD;
/// Exact legacy-clone flags for the target-required vfork-shaped process creation path.
pub const VFORK_PROCESS_FLAGS: u64 = CLONE_VM | CLONE_VFORK | LINUX_SIGCHLD;

/// Exact flags emitted by the unchanged musl AArch64 pthread-create path targeted by Step 15.
pub const MUSL_PTHREAD_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED;

const AARCH64_STACK_ALIGNMENT: u64 = 16;
const LINUX_TID_BYTES: usize = core::mem::size_of::<u32>();
const LINUX_TID_ALIGNMENT: u64 = core::mem::align_of::<u32>() as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedFlags,
    InvalidChildStack,
    InvalidParentTid,
    InvalidTls,
    InvalidChildTid,
}

/// Target-required process-creation semantics carried by legacy AArch64 `clone`.
///
/// These variants deliberately describe only process-family behavior. The accepted pthread clone
/// contract remains represented by [`ClonePlan`] and cannot be confused with a new-process request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCloneKind {
    Fork,
    Vfork,
}

/// Authority-free preflight for the Step-30 fork/vfork process-family contract.
///
/// The first Step-30 process-family slice intentionally accepts only the two legacy-clone shapes
/// required by the unchanged static-musl shell target. Both inherit the parent's user stack pointer,
/// so the raw legacy `child_stack` argument must be zero. The remaining legacy-clone scalar
/// registers are semantically inactive for these exact flag shapes because no `CLONE_PARENT_SETTID`,
/// `CLONE_SETTLS` or child-TID selector is set. Linux ignores those raw register values, so this
/// preflight ignores them as well and never treats them as pointers or authority. Parent/child TID
/// address and TLS semantics remain part of the already-proven pthread clone surface unless a later
/// pinned target trace proves another process-oriented flag shape is required.
///
/// `Vfork` shares the parent's address space temporarily and requires the parent to remain suspended
/// until the child performs the later exec/exit handoff. This value records that semantic contract;
/// it grants no Process, AddressSpace, scheduler, VFS or capability authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessClonePlan {
    kind: ProcessCloneKind,
}

impl ProcessClonePlan {
    pub fn validate(
        flags: u64,
        child_stack: u64,
        _parent_tid: u64,
        _tls: u64,
        _child_tid: u64,
    ) -> Result<Self, Error> {
        let kind = match flags {
            FORK_PROCESS_FLAGS => ProcessCloneKind::Fork,
            VFORK_PROCESS_FLAGS => ProcessCloneKind::Vfork,
            _ => return Err(Error::UnsupportedFlags),
        };
        if child_stack != 0 {
            return Err(Error::InvalidChildStack);
        }
        Ok(Self { kind })
    }

    pub const fn kind(self) -> ProcessCloneKind {
        self.kind
    }

    /// Whether child and parent temporarily use the same address-space owner.
    pub const fn shares_address_space(self) -> bool {
        matches!(self.kind, ProcessCloneKind::Vfork)
    }

    /// Whether publication of the child requires suspending the parent until exec/exit handoff.
    pub const fn suspends_parent(self) -> bool {
        matches!(self.kind, ProcessCloneKind::Vfork)
    }
}

/// Authority-free scalar preflight for the minimum unchanged musl pthread clone operation.
///
/// This type never touches user memory. `UserRange` is reused only to validate complete structural
/// userspace ranges; the architecture/runtime owners later perform fault-safe usercopy and scheduler
/// publication after Process/CSpace authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClonePlan {
    child_stack: u64,
    parent_tid: u64,
    tls: u64,
    child_tid: u64,
}

impl ClonePlan {
    pub fn validate(
        flags: u64,
        child_stack: u64,
        parent_tid: u64,
        tls: u64,
        child_tid: u64,
    ) -> Result<Self, Error> {
        if flags != MUSL_PTHREAD_FLAGS {
            return Err(Error::UnsupportedFlags);
        }
        if !child_stack.is_multiple_of(AARCH64_STACK_ALIGNMENT)
            || UserRange::new(child_stack, 1).is_err()
        {
            return Err(Error::InvalidChildStack);
        }
        if !parent_tid.is_multiple_of(LINUX_TID_ALIGNMENT)
            || UserRange::new(parent_tid, LINUX_TID_BYTES).is_err()
        {
            return Err(Error::InvalidParentTid);
        }
        if UserRange::new(tls, 1).is_err() {
            return Err(Error::InvalidTls);
        }
        if !child_tid.is_multiple_of(LINUX_TID_ALIGNMENT)
            || UserRange::new(child_tid, LINUX_TID_BYTES).is_err()
        {
            return Err(Error::InvalidChildTid);
        }
        Ok(Self {
            child_stack,
            parent_tid,
            tls,
            child_tid,
        })
    }

    pub const fn child_stack(self) -> u64 {
        self.child_stack
    }

    pub const fn parent_tid(self) -> u64 {
        self.parent_tid
    }

    pub const fn tls(self) -> u64 {
        self.tls
    }

    pub const fn child_tid(self) -> u64 {
        self.child_tid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STACK: u64 = 0x0000_0000_0002_0000;
    const PTID: u64 = 0x0000_0000_0003_0000;
    const TLS: u64 = 0x0000_0000_0004_0008;
    const CTID: u64 = 0x0000_0000_0005_0000;

    #[test]
    fn exact_unchanged_musl_pthread_shape_is_accepted() {
        assert_eq!(MUSL_PTHREAD_FLAGS, 0x007d_0f00);
        let plan = ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK, PTID, TLS, CTID).unwrap();
        assert_eq!(plan.child_stack(), STACK);
        assert_eq!(plan.parent_tid(), PTID);
        assert_eq!(plan.tls(), TLS);
        assert_eq!(plan.child_tid(), CTID);
    }

    #[test]
    fn fork_and_vfork_process_shapes_are_distinct_and_fail_closed() {
        let fork = ProcessClonePlan::validate(FORK_PROCESS_FLAGS, 0, 0, 0, 0).unwrap();
        assert_eq!(fork.kind(), ProcessCloneKind::Fork);
        assert!(!fork.shares_address_space());
        assert!(!fork.suspends_parent());

        let vfork = ProcessClonePlan::validate(VFORK_PROCESS_FLAGS, 0, 0, 0, 0).unwrap();
        assert_eq!(vfork.kind(), ProcessCloneKind::Vfork);
        assert!(vfork.shares_address_space());
        assert!(vfork.suspends_parent());

        assert_eq!(
            ProcessClonePlan::validate(FORK_PROCESS_FLAGS | CLONE_FILES, 0, 0, 0, 0),
            Err(Error::UnsupportedFlags)
        );
        assert_eq!(
            ProcessClonePlan::validate(LINUX_SIGCHLD | CLONE_VM, 0, 0, 0, 0),
            Err(Error::UnsupportedFlags)
        );
        assert_eq!(
            ProcessClonePlan::validate(
                FORK_PROCESS_FLAGS | CLONE_PARENT_SETTID,
                0,
                PTID,
                TLS,
                CTID
            ),
            Err(Error::UnsupportedFlags)
        );
        assert_eq!(
            ProcessClonePlan::validate(MUSL_PTHREAD_FLAGS, 0, 0, 0, 0),
            Err(Error::UnsupportedFlags)
        );
    }

    #[test]
    fn process_family_inherits_stack_and_ignores_inactive_pointer_registers() {
        assert_eq!(
            ProcessClonePlan::validate(FORK_PROCESS_FLAGS, STACK, PTID, TLS, CTID),
            Err(Error::InvalidChildStack)
        );

        let fork = ProcessClonePlan::validate(FORK_PROCESS_FLAGS, 0, PTID, TLS, CTID).unwrap();
        assert_eq!(fork.kind(), ProcessCloneKind::Fork);
        assert!(!fork.shares_address_space());
        assert!(!fork.suspends_parent());

        let vfork = ProcessClonePlan::validate(VFORK_PROCESS_FLAGS, 0, PTID, TLS, CTID).unwrap();
        assert_eq!(vfork.kind(), ProcessCloneKind::Vfork);
        assert!(vfork.shares_address_space());
        assert!(vfork.suspends_parent());
    }

    #[test]
    fn missing_extra_or_signal_bits_fail_closed() {
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS & !CLONE_SETTLS, STACK, PTID, TLS, CTID),
            Err(Error::UnsupportedFlags)
        );
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS | 0x0100_0000, STACK, PTID, TLS, CTID),
            Err(Error::UnsupportedFlags)
        );
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS | LINUX_SIGCHLD, STACK, PTID, TLS, CTID),
            Err(Error::UnsupportedFlags)
        );
    }

    #[test]
    fn child_stack_reuses_user_range_policy_and_requires_aapcs_alignment() {
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK + 8, PTID, TLS, CTID),
            Err(Error::InvalidChildStack)
        );
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS, 0, PTID, TLS, CTID),
            Err(Error::InvalidChildStack)
        );
    }

    #[test]
    fn tid_words_require_complete_aligned_usercopy_ranges() {
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK, PTID + 1, TLS, CTID),
            Err(Error::InvalidParentTid)
        );
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK, PTID, TLS, CTID + 2),
            Err(Error::InvalidChildTid)
        );
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK, u64::MAX - 1, TLS, CTID),
            Err(Error::InvalidParentTid)
        );
    }

    #[test]
    fn tls_is_opaque_but_must_be_structurally_userspace() {
        assert!(ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK, PTID, TLS + 1, CTID).is_ok());
        assert_eq!(
            ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK, PTID, 0, CTID),
            Err(Error::InvalidTls)
        );
    }
}
