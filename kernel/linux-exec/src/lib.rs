// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Architecture-neutral Linux exec transaction policy.
//!
//! This crate owns sequencing only. It deliberately does not resolve paths, parse/load ELF images,
//! mutate page tables, copy user memory directly or implement a second descriptor table. Those
//! authorities remain with the accepted VFS, user-ELF, Process/AddressSpace, usercopy and linux-fd
//! owners.

use core::mem::size_of;
use kernal_capability::ObjectId;
use kernal_linux_fd::{Error as FdError, FdTable, FdToken, ReleasedObject};
use kernal_linux_vfs::AT_FDCWD;
use kernal_process::{Personality, Process, ProcessState};
use kernal_usercopy::{Error as UsercopyError, UserRange};

/// Linux `AT_SYMLINK_NOFOLLOW` accepted by `execveat` for the final pathname component.
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x0100;
/// Linux `AT_EMPTY_PATH` accepted by `execveat` for direct descriptor execution.
pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const EXECVEAT_SUPPORTED_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
const USER_POINTER_BYTES: usize = size_of::<u64>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NotLinuxProcess,
    InactiveProcess,
    ProcessChanged,
    UnsupportedExecveatFlags,
    EmptyPath,
    TooManyVectorEntries,
    ArgumentBytesExceeded,
    InvalidStringLength,
    Usercopy(UsercopyError),
    Fd(FdError),
}

impl From<FdError> for Error {
    fn from(value: FdError) -> Self {
        Self::Fd(value)
    }
}

impl From<UsercopyError> for Error {
    fn from(value: UsercopyError) -> Self {
        Self::Usercopy(value)
    }
}

/// Authority-free lookup policy for `execve` / `execveat`.
///
/// The plan preserves the exact dirfd and accepted Linux flags but performs no pathname resolution.
/// A later VFS owner must consume the already-copied pathname bytes and retained FD/VFS authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecLookupPlan {
    dirfd: i32,
    path_is_empty: bool,
    flags: u64,
}

impl ExecLookupPlan {
    /// Builds the ordinary `execve` lookup shape. Empty pathnames fail before any VFS mutation.
    pub fn execve(path_is_empty: bool) -> Result<Self, Error> {
        if path_is_empty {
            return Err(Error::EmptyPath);
        }
        Ok(Self {
            dirfd: AT_FDCWD,
            path_is_empty: false,
            flags: 0,
        })
    }

    /// Builds the `execveat` lookup shape without duplicating the VFS resolver.
    ///
    /// Only `AT_EMPTY_PATH` and `AT_SYMLINK_NOFOLLOW` are accepted. If the copied pathname is empty,
    /// `AT_EMPTY_PATH` must be present; the canonical FD/VFS owner later proves whether `dirfd`
    /// identifies an executable object. Non-empty relative-path semantics remain entirely with VFS.
    pub fn execveat(dirfd: i32, path_is_empty: bool, flags: u64) -> Result<Self, Error> {
        if flags & !EXECVEAT_SUPPORTED_FLAGS != 0 {
            return Err(Error::UnsupportedExecveatFlags);
        }
        if path_is_empty && flags & AT_EMPTY_PATH == 0 {
            return Err(Error::EmptyPath);
        }
        Ok(Self {
            dirfd,
            path_is_empty,
            flags,
        })
    }

    pub const fn dirfd(self) -> i32 {
        self.dirfd
    }

    pub const fn path_is_empty(self) -> bool {
        self.path_is_empty
    }

    pub const fn flags(self) -> u64 {
        self.flags
    }

    pub const fn allows_empty_path(self) -> bool {
        self.flags & AT_EMPTY_PATH != 0
    }

    pub const fn follows_final_symlink(self) -> bool {
        self.flags & AT_SYMLINK_NOFOLLOW == 0
    }
}

/// Bounded, authority-free description of one already-validated argv/envp string vector.
///
/// The entries are canonical [`UserRange`] values only; this crate never dereferences them. A
/// platform runtime must use the existing usercopy owner to read each pointer slot and scan/copy each
/// C string, then call [`Self::push_validated_c_string`] with the exact range including its terminal
/// NUL. The fixed capacity makes the vector fail closed without heap allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecStringVector<const N: usize> {
    entries: [Option<UserRange>; N],
    len: usize,
    total_bytes: usize,
}

impl<const N: usize> ExecStringVector<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            len: 0,
            total_bytes: 0,
        }
    }

    /// Returns the next pointer-table slot that the existing usercopy owner must read.
    ///
    /// The slot is always one AArch64/Linux pointer wide. After `N` non-null entries have been
    /// staged this still returns slot `N`, allowing the caller to prove the mandatory null terminator
    /// without silently accepting an over-capacity vector.
    pub fn next_pointer_slot(&self, vector_base: u64) -> Result<UserRange, Error> {
        let offset = self
            .len
            .checked_mul(USER_POINTER_BYTES)
            .ok_or(UsercopyError::Overflow)?;
        let address = vector_base
            .checked_add(u64::try_from(offset).map_err(|_| UsercopyError::Overflow)?)
            .ok_or(UsercopyError::Overflow)?;
        Ok(UserRange::new(address, USER_POINTER_BYTES)?)
    }

    /// Stages one C-string range after canonical usercopy has already established its terminal NUL.
    ///
    /// `len_with_nul` is deliberately part of the contract: zero cannot describe a C string, and
    /// [`UserRange`] independently enforces null-guard, user-range, overflow and per-copy size bounds.
    pub fn push_validated_c_string(
        &mut self,
        address: u64,
        len_with_nul: usize,
    ) -> Result<(), Error> {
        if len_with_nul == 0 {
            return Err(Error::InvalidStringLength);
        }
        if self.len == N {
            return Err(Error::TooManyVectorEntries);
        }
        let range = UserRange::new(address, len_with_nul)?;
        let total_bytes = self
            .total_bytes
            .checked_add(len_with_nul)
            .ok_or(Error::ArgumentBytesExceeded)?;
        self.entries[self.len] = Some(range);
        self.len += 1;
        self.total_bytes = total_bytes;
        Ok(())
    }

    /// Validates the pointer-table terminator read through canonical usercopy.
    pub fn finish(self, terminal_pointer: u64) -> Result<Self, Error> {
        if terminal_pointer != 0 {
            return Err(Error::TooManyVectorEntries);
        }
        Ok(self)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn entry(&self, index: usize) -> Option<UserRange> {
        self.entries.get(index).copied().flatten()
    }
}

impl<const N: usize> Default for ExecStringVector<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Completed argv/envp staging envelope with one explicit aggregate byte budget.
///
/// The byte budget is policy supplied by the later syscall owner; this crate does not invent a
/// second Linux `ARG_MAX`. It merely guarantees checked accounting across both already-validated
/// vectors before image preparation or CLOEXEC commit can begin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecArgumentStaging<const ARGV: usize, const ENVP: usize> {
    argv: ExecStringVector<ARGV>,
    envp: ExecStringVector<ENVP>,
    total_bytes: usize,
}

impl<const ARGV: usize, const ENVP: usize> ExecArgumentStaging<ARGV, ENVP> {
    pub fn new(
        argv: ExecStringVector<ARGV>,
        envp: ExecStringVector<ENVP>,
        max_total_bytes: usize,
    ) -> Result<Self, Error> {
        let total_bytes = argv
            .total_bytes()
            .checked_add(envp.total_bytes())
            .ok_or(Error::ArgumentBytesExceeded)?;
        if total_bytes > max_total_bytes {
            return Err(Error::ArgumentBytesExceeded);
        }
        Ok(Self {
            argv,
            envp,
            total_bytes,
        })
    }

    pub const fn argv(&self) -> &ExecStringVector<ARGV> {
        &self.argv
    }

    pub const fn envp(&self) -> &ExecStringVector<ENVP> {
        &self.envp
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

/// Linear Step-29 CLOEXEC handoff bound to one exact live Linux Process generation.
///
/// The value is intentionally neither `Copy` nor `Clone`. `commit_close_on_exec` consumes it by
/// value, while the underlying [`FdTable`] revalidates the complete generation-safe descriptor
/// snapshot before closing anything. A stale descriptor generation therefore rejects the entire
/// commit without a partial close.
///
/// Higher-level 30.2 code must create this handoff only after path, argv/env and ELF/image staging
/// have succeeded. Failed exec preparation must never consume it. Resource authorities returned by
/// the FD owner remain the caller's responsibility and must be released through their canonical
/// pipe/VFS owners.
#[derive(Debug, Eq, PartialEq)]
pub struct ExecCommitHandoff<const N: usize> {
    process: ObjectId,
    address_space: ObjectId,
    cloexec: [Option<FdToken>; N],
}

impl<const N: usize> ExecCommitHandoff<N> {
    /// Snapshots the complete bounded descriptor-local CLOEXEC set and binds it to the exact Linux
    /// Process/AddressSpace generation that will commit the image replacement.
    pub fn prepare<const CAPS: usize>(
        process: &Process<CAPS>,
        fds: &FdTable<N>,
    ) -> Result<Self, Error> {
        validate_live_linux_process(process)?;
        Ok(Self {
            process: process.id(),
            address_space: process.address_space(),
            cloexec: fds.prepare_close_on_exec()?,
        })
    }

    pub const fn process(&self) -> ObjectId {
        self.process
    }

    pub const fn address_space(&self) -> ObjectId {
        self.address_space
    }

    pub fn selected_descriptor_count(&self) -> usize {
        self.cloexec.iter().flatten().count()
    }

    /// Commits the exact Step-29 CLOEXEC snapshot once, after revalidating the Process generation.
    ///
    /// `FdTable::commit_close_on_exec` performs an all-or-nothing snapshot comparison before any
    /// descriptor state is removed. This method adds the process-generation binding required by the
    /// Step-30 exec transaction; it does not reinterpret FD/OFD or release semantics.
    pub fn commit_close_on_exec<const CAPS: usize>(
        self,
        process: &Process<CAPS>,
        fds: &mut FdTable<N>,
    ) -> Result<[Option<ReleasedObject>; N], Error> {
        validate_live_linux_process(process)?;
        if process.id() != self.process || process.address_space() != self.address_space {
            return Err(Error::ProcessChanged);
        }
        Ok(fds.commit_close_on_exec(self.cloexec)?)
    }
}

fn validate_live_linux_process<const CAPS: usize>(process: &Process<CAPS>) -> Result<(), Error> {
    if process.state() != ProcessState::Live {
        return Err(Error::InactiveProcess);
    }
    if process.personality() != Personality::Linux {
        return Err(Error::NotLinuxProcess);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_object::ObjectTable;

    const USER_BASE: u64 = 0x0000_0000_0001_0000;

    #[test]
    fn exec_lookup_plan_preserves_vfs_authority_and_execveat_flags() {
        let execve = ExecLookupPlan::execve(false).unwrap();
        assert_eq!(execve.dirfd(), AT_FDCWD);
        assert_eq!(execve.flags(), 0);
        assert!(execve.follows_final_symlink());
        assert_eq!(ExecLookupPlan::execve(true), Err(Error::EmptyPath));

        let empty = ExecLookupPlan::execveat(7, true, AT_EMPTY_PATH).unwrap();
        assert_eq!(empty.dirfd(), 7);
        assert!(empty.path_is_empty());
        assert!(empty.allows_empty_path());
        assert!(empty.follows_final_symlink());

        let nofollow =
            ExecLookupPlan::execveat(AT_FDCWD, false, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW).unwrap();
        assert!(!nofollow.path_is_empty());
        assert!(!nofollow.follows_final_symlink());
        assert_eq!(ExecLookupPlan::execveat(3, true, 0), Err(Error::EmptyPath));
        assert_eq!(
            ExecLookupPlan::execveat(3, false, 1 << 31),
            Err(Error::UnsupportedExecveatFlags)
        );
    }

    #[test]
    fn string_vector_exposes_only_validated_user_ranges() {
        let mut argv = ExecStringVector::<2>::new();
        let first_pointer = argv.next_pointer_slot(USER_BASE).unwrap();
        assert_eq!(first_pointer.start(), USER_BASE);
        assert_eq!(first_pointer.len(), USER_POINTER_BYTES);

        argv.push_validated_c_string(USER_BASE + 0x100, 5).unwrap();
        argv.push_validated_c_string(USER_BASE + 0x200, 7).unwrap();
        assert_eq!(argv.len(), 2);
        assert_eq!(argv.total_bytes(), 12);
        assert_eq!(argv.entry(0).unwrap().len(), 5);
        assert_eq!(argv.entry(1).unwrap().len(), 7);
        assert_eq!(argv.finish(0).unwrap().len(), 2);

        let full = argv;
        assert_eq!(
            full.next_pointer_slot(0),
            Err(Error::Usercopy(UsercopyError::NullGuard))
        );
        assert_eq!(full.finish(USER_BASE), Err(Error::TooManyVectorEntries));
        let mut full = full;
        assert_eq!(
            full.push_validated_c_string(USER_BASE + 0x300, 2),
            Err(Error::TooManyVectorEntries)
        );
    }

    #[test]
    fn string_and_aggregate_bounds_fail_closed() {
        let mut argv = ExecStringVector::<2>::new();
        assert_eq!(
            argv.push_validated_c_string(USER_BASE, 0),
            Err(Error::InvalidStringLength)
        );
        assert_eq!(
            argv.push_validated_c_string(0, 2),
            Err(Error::Usercopy(UsercopyError::NullGuard))
        );
        argv.push_validated_c_string(USER_BASE + 0x100, 8).unwrap();

        let mut envp = ExecStringVector::<2>::new();
        envp.push_validated_c_string(USER_BASE + 0x200, 9).unwrap();
        assert_eq!(
            ExecArgumentStaging::new(argv, envp, 16),
            Err(Error::ArgumentBytesExceeded)
        );
        let staged = ExecArgumentStaging::new(argv, envp, 17).unwrap();
        assert_eq!(staged.total_bytes(), 17);
        assert_eq!(staged.argv().len(), 1);
        assert_eq!(staged.envp().len(), 1);
    }

    #[test]
    fn handoff_closes_only_the_prepared_cloexec_generations() {
        let mut objects = ObjectTable::<2>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut fds = FdTable::<4>::new();
        let stdio = fds.seed_standard_descriptors().unwrap();
        fds.set_close_on_exec(stdio.stdout().fd(), true).unwrap();

        let handoff = ExecCommitHandoff::prepare(&process, &fds).unwrap();
        assert_eq!(handoff.process(), process.id());
        assert_eq!(handoff.address_space(), process.address_space());
        assert_eq!(handoff.selected_descriptor_count(), 1);

        let released = handoff.commit_close_on_exec(&process, &mut fds).unwrap();
        assert!(released.into_iter().all(|entry| entry.is_none()));
        assert!(fds.token_is_live(stdio.stdin()));
        assert!(!fds.token_is_live(stdio.stdout()));
        assert!(fds.token_is_live(stdio.stderr()));
    }

    #[test]
    fn descriptor_drift_rejects_the_whole_handoff_without_partial_close() {
        let mut objects = ObjectTable::<2>::new();
        let process = Process::<4>::create(&mut objects, Personality::Linux).unwrap();
        let mut fds = FdTable::<4>::new();
        let stdio = fds.seed_standard_descriptors().unwrap();
        fds.set_close_on_exec(stdio.stdout().fd(), true).unwrap();
        fds.set_close_on_exec(stdio.stderr().fd(), true).unwrap();

        let handoff = ExecCommitHandoff::prepare(&process, &fds).unwrap();
        fds.set_close_on_exec(stdio.stderr().fd(), false).unwrap();

        assert_eq!(
            handoff.commit_close_on_exec(&process, &mut fds),
            Err(Error::Fd(FdError::StaleOpenFile))
        );
        assert!(fds.token_is_live(stdio.stdout()));
        assert_eq!(fds.close_on_exec(stdio.stdout().fd()), Ok(true));
        assert!(fds.token_is_live(stdio.stderr()));
        assert_eq!(fds.close_on_exec(stdio.stderr().fd()), Ok(false));
    }

    #[test]
    fn native_process_cannot_prepare_linux_exec_handoff() {
        let mut objects = ObjectTable::<2>::new();
        let process = Process::<4>::create(&mut objects, Personality::Native).unwrap();
        let fds = FdTable::<4>::new();

        assert!(matches!(
            ExecCommitHandoff::prepare(&process, &fds),
            Err(Error::NotLinuxProcess)
        ));
    }
}
