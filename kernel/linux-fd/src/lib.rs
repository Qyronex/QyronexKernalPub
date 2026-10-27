// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_linux_pipe::Endpoint as PipeEndpoint;
use kernal_linux_vfs::{DirectoryScan, ReadOnlyDirectory, ReadOnlyFile};

mod pipe;
mod process_views;
mod stdio;
pub use pipe::{PipeDescriptors, ReleasedObject};
pub use process_views::{FdTableSet, FdViewId};
use stdio::ExternalBacking;
pub use stdio::{ExternalObject, OpenObjectKind, StandardDescriptors};

pub const FIRST_DYNAMIC_FD: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BadFd,
    TableFull,
    OffsetOverflow,
    StaleRead,
    InvalidReadLength,
    NotFile,
    NotDirectory,
    StaleDirectory,
    InvalidDirectoryCursor,
    StaleOpenFile,
    ReferenceOverflow,
    InvalidMinimumFd,
    InvalidTargetFd,
    SameDescriptor,
    InvalidSeek,
    SeekOverflow,
    NotSeekable,
    InvalidPreadOffset,
    StalePread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdToken {
    fd: i32,
    generation: u64,
}

impl FdToken {
    pub const fn fd(self) -> i32 {
        self.fd
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Generation-safe identity of one shared Linux open-file description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenFileId {
    index: usize,
    generation: u64,
}

impl OpenFileId {
    pub const fn index(self) -> usize {
        self.index
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub size: u64,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeekWhence {
    Set,
    Current,
    End,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadPlan {
    token: FdToken,
    open_file: OpenFileId,
    file: ReadOnlyFile,
    start_offset: u64,
    len: usize,
}

impl ReadPlan {
    pub const fn token(self) -> FdToken {
        self.token
    }

    pub const fn open_file(self) -> OpenFileId {
        self.open_file
    }

    pub const fn file(self) -> ReadOnlyFile {
        self.file
    }

    pub const fn start_offset(self) -> u64 {
        self.start_offset
    }

    pub const fn len(self) -> usize {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Immutable positional read plan. Unlike [`ReadPlan`], it never owns or commits the shared OFD
/// position. The descriptor and exact OFD generation are retained so callers can revalidate object
/// identity after bounded usercopy without making an alias-visible seek invalidate the plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreadPlan {
    token: FdToken,
    open_file: OpenFileId,
    file: ReadOnlyFile,
    offset: u64,
    len: usize,
}

impl PreadPlan {
    pub const fn token(self) -> FdToken {
        self.token
    }

    pub const fn open_file(self) -> OpenFileId {
        self.open_file
    }

    pub const fn file(self) -> ReadOnlyFile {
        self.file
    }

    pub const fn offset(self) -> u64 {
        self.offset
    }

    pub const fn len(self) -> usize {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryPlan {
    token: FdToken,
    open_file: OpenFileId,
    directory: ReadOnlyDirectory,
    start_cursor: usize,
}

impl DirectoryPlan {
    pub const fn token(self) -> FdToken {
        self.token
    }

    pub const fn open_file(self) -> OpenFileId {
        self.open_file
    }

    pub const fn directory(self) -> ReadOnlyDirectory {
        self.directory
    }

    pub const fn start_cursor(self) -> usize {
        self.start_cursor
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenObject {
    File(ReadOnlyFile),
    Directory(ReadOnlyDirectory),
    Pipe(PipeEndpoint),
    External(ExternalBacking),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpenState {
    object: OpenObject,
    offset: u64,
    status_flags: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorState {
    open_file: OpenFileId,
    close_on_exec: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorSlot {
    generation: u64,
    retired: bool,
    state: Option<DescriptorState>,
}

impl DescriptorSlot {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        state: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpenFileSlot {
    generation: u64,
    retired: bool,
    refs: usize,
    state: Option<OpenState>,
}

impl OpenFileSlot {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        refs: 0,
        state: None,
    };
}

/// Bounded per-process Linux descriptor owner with shared open-file descriptions.
///
/// Slots 0/1/2 are reserved from ordinary pre-stdio open allocation. Duplication primitives may
/// populate them according to Linux's lowest-free or exact-target rules. Descriptor and OFD
/// generations advance only when a new live identity is successfully installed; exhaustion never
/// wraps an old token.
pub struct FdTable<const N: usize> {
    descriptors: [DescriptorSlot; N],
    open_files: [OpenFileSlot; N],
    descriptor_generation_origin: u64,
    descriptor_generation_stride: u64,
}

impl<const N: usize> FdTable<N> {
    pub const fn new() -> Self {
        Self {
            descriptors: [DescriptorSlot::EMPTY; N],
            open_files: [OpenFileSlot::EMPTY; N],
            descriptor_generation_origin: 1,
            descriptor_generation_stride: 1,
        }
    }

    pub fn open_readonly(&mut self, file: ReadOnlyFile) -> Result<FdToken, Error> {
        self.open_readonly_with_flags(file, false, 0)
    }

    pub fn open_readonly_with_cloexec(
        &mut self,
        file: ReadOnlyFile,
        close_on_exec: bool,
    ) -> Result<FdToken, Error> {
        self.open_readonly_with_flags(file, close_on_exec, 0)
    }

    /// Opens one immutable file with descriptor-local and OFD-shared Linux flag state separated.
    pub fn open_readonly_with_flags(
        &mut self,
        file: ReadOnlyFile,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        self.open_object(OpenObject::File(file), close_on_exec, status_flags)
    }

    pub fn open_directory(&mut self, directory: ReadOnlyDirectory) -> Result<FdToken, Error> {
        self.open_directory_with_flags(directory, false, 0)
    }

    pub fn open_directory_with_cloexec(
        &mut self,
        directory: ReadOnlyDirectory,
        close_on_exec: bool,
    ) -> Result<FdToken, Error> {
        self.open_directory_with_flags(directory, close_on_exec, 0)
    }

    /// Opens one immutable directory with descriptor-local CLOEXEC and shared status flags.
    pub fn open_directory_with_flags(
        &mut self,
        directory: ReadOnlyDirectory,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        self.open_object(
            OpenObject::Directory(directory),
            close_on_exec,
            status_flags,
        )
    }

    /// Linux-policy immutable file open: choose the lowest free descriptor, including a closed
    /// standard-descriptor hole. The integration lane seeds 0/1/2 before exposing this path.
    pub fn open_readonly_linux_with_flags(
        &mut self,
        file: ReadOnlyFile,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        self.open_object_from(0, OpenObject::File(file), close_on_exec, status_flags)
    }

    /// Linux-policy immutable directory open with lowest-free descriptor allocation.
    pub fn open_directory_linux_with_flags(
        &mut self,
        directory: ReadOnlyDirectory,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        self.open_object_from(
            0,
            OpenObject::Directory(directory),
            close_on_exec,
            status_flags,
        )
    }

    fn open_object(
        &mut self,
        object: OpenObject,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        self.open_object_from(FIRST_DYNAMIC_FD, object, close_on_exec, status_flags)
    }

    fn open_object_from(
        &mut self,
        start: usize,
        object: OpenObject,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        let (descriptor_index, fd, descriptor_generation) = self.descriptor_candidate(start)?;
        let (open_file_index, open_file_generation) = self.open_file_candidate()?;
        let open_file = OpenFileId {
            index: open_file_index,
            generation: open_file_generation,
        };

        self.open_files[open_file_index].generation = open_file_generation;
        self.open_files[open_file_index].refs = 1;
        self.open_files[open_file_index].state = Some(OpenState {
            object,
            offset: 0,
            status_flags,
        });
        self.descriptors[descriptor_index].generation = descriptor_generation;
        self.descriptors[descriptor_index].state = Some(DescriptorState {
            open_file,
            close_on_exec,
        });
        Ok(FdToken {
            fd,
            generation: descriptor_generation,
        })
    }

    /// Compatibility helper for the pre-stdio dynamic-allocation policy. The supplied minimum is
    /// clamped to [`FIRST_DYNAMIC_FD`]. ABI `dup`/`F_DUPFD` wiring must use the explicit Linux-policy
    /// helpers below instead of relying on this clamp.
    pub fn duplicate(
        &mut self,
        fd: i32,
        minimum_fd: i32,
        close_on_exec: bool,
    ) -> Result<FdToken, Error> {
        let minimum = usize::try_from(minimum_fd).map_err(|_| Error::InvalidMinimumFd)?;
        self.duplicate_at_or_after(fd, core::cmp::max(minimum, FIRST_DYNAMIC_FD), close_on_exec)
    }

    /// Linux `dup` owner primitive: chooses the lowest available descriptor.
    ///
    /// The integration lane is responsible for seeding live standard descriptors before exposing
    /// this to userspace, so initial Linux process state still naturally allocates above fd 2.
    pub fn duplicate_lowest(&mut self, fd: i32, close_on_exec: bool) -> Result<FdToken, Error> {
        self.duplicate_at_or_after(fd, 0, close_on_exec)
    }

    /// Linux `F_DUPFD` / `F_DUPFD_CLOEXEC` owner primitive: chooses the lowest available descriptor
    /// at or above the exact nonnegative caller-supplied minimum, including fd 0/1/2 when free.
    pub fn duplicate_from(
        &mut self,
        fd: i32,
        minimum_fd: i32,
        close_on_exec: bool,
    ) -> Result<FdToken, Error> {
        self.descriptor(fd)?;
        let minimum = usize::try_from(minimum_fd).map_err(|_| Error::InvalidMinimumFd)?;
        if minimum >= N {
            return Err(Error::InvalidMinimumFd);
        }
        self.duplicate_at_or_after(fd, minimum, close_on_exec)
    }

    fn duplicate_at_or_after(
        &mut self,
        fd: i32,
        start: usize,
        close_on_exec: bool,
    ) -> Result<FdToken, Error> {
        let source = *self.descriptor(fd)?;
        let current_refs = self.open_file_slot(source.open_file)?.refs;
        let next_refs = current_refs
            .checked_add(1)
            .ok_or(Error::ReferenceOverflow)?;
        let (target_index, target_fd, target_generation) = self.descriptor_candidate(start)?;

        self.open_file_slot_mut(source.open_file)?.refs = next_refs;
        self.descriptors[target_index].generation = target_generation;
        self.descriptors[target_index].state = Some(DescriptorState {
            open_file: source.open_file,
            close_on_exec,
        });
        Ok(FdToken {
            fd: target_fd,
            generation: target_generation,
        })
    }

    /// Atomically replaces one exact in-range descriptor with an alias to `source_fd`'s OFD.
    ///
    /// Final pipe-endpoint release requires [`FdTable::duplicate_exact_with_release`]; this legacy
    /// helper fails closed before mutation if replacing the final descriptor of a pipe OFD.
    pub fn duplicate_exact(
        &mut self,
        source_fd: i32,
        target_fd: i32,
        close_on_exec: bool,
    ) -> Result<FdToken, Error> {
        let (token, release) =
            self.duplicate_exact_pipe_aware(source_fd, target_fd, close_on_exec, false)?;
        debug_assert!(release.is_none());
        Ok(token)
    }

    /// Closes a non-pipe descriptor using the compatibility surface.
    ///
    /// Final pipe endpoint release requires [`FdTable::close_with_release`]; this helper fails
    /// closed before mutation if it would otherwise discard the final external endpoint lease.
    pub fn close(&mut self, fd: i32) -> Result<(), Error> {
        let release = self.close_pipe_aware(fd, false)?;
        debug_assert!(release.is_none());
        Ok(())
    }

    pub fn close_on_exec(&self, fd: i32) -> Result<bool, Error> {
        Ok(self.descriptor(fd)?.close_on_exec)
    }

    pub fn set_close_on_exec(&mut self, fd: i32, value: bool) -> Result<(), Error> {
        self.descriptor_mut(fd)?.close_on_exec = value;
        Ok(())
    }

    /// Returns Linux file-status/access state owned by the shared open-file description.
    pub fn status_flags(&self, fd: i32) -> Result<u64, Error> {
        Ok(self
            .open_file_state(self.descriptor(fd)?.open_file)?
            .status_flags)
    }

    pub fn open_file_id(&self, fd: i32) -> Result<OpenFileId, Error> {
        Ok(self.descriptor(fd)?.open_file)
    }

    /// Updates the shared regular-file OFD position using Linux signed `off_t` rules.
    ///
    /// Positions beyond EOF are valid. Directories deliberately keep their VFS-owned logical cookie
    /// cursor and pipe/external endpoints are never seekable.
    pub fn seek(&mut self, fd: i32, offset: i64, whence: SeekWhence) -> Result<u64, Error> {
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state_mut(open_file)?;
        let file = match state.object {
            OpenObject::File(file) => file,
            OpenObject::Directory(_) | OpenObject::Pipe(_) | OpenObject::External(_) => {
                return Err(Error::NotSeekable);
            }
        };
        let base = match whence {
            SeekWhence::Set => 0i128,
            SeekWhence::Current => i128::from(state.offset),
            SeekWhence::End => i128::from(file.size()),
        };
        let next = base
            .checked_add(i128::from(offset))
            .ok_or(Error::SeekOverflow)?;
        if next < 0 {
            return Err(Error::InvalidSeek);
        }
        if next > i128::from(i64::MAX) {
            return Err(Error::SeekOverflow);
        }
        let next = u64::try_from(next).map_err(|_| Error::SeekOverflow)?;
        state.offset = next;
        Ok(next)
    }

    pub fn prepare_read(&self, fd: i32, max_len: usize) -> Result<ReadPlan, Error> {
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        let file = match state.object {
            OpenObject::File(file) => file,
            OpenObject::Directory(_) | OpenObject::Pipe(_) | OpenObject::External(_) => {
                return Err(Error::NotFile);
            }
        };
        let remaining = bounded_remaining(file.size(), state.offset);
        Ok(ReadPlan {
            token,
            open_file,
            file,
            start_offset: state.offset,
            len: core::cmp::min(remaining, max_len),
        })
    }

    pub fn commit_read(&mut self, plan: ReadPlan, bytes_read: usize) -> Result<(), Error> {
        if bytes_read > plan.len() {
            return Err(Error::InvalidReadLength);
        }
        let descriptor = self
            .descriptor_for_token(plan.token())
            .map_err(|_| Error::StaleRead)?;
        if descriptor.open_file != plan.open_file() {
            return Err(Error::StaleRead);
        }
        let state = self
            .open_file_state_mut(plan.open_file())
            .map_err(|_| Error::StaleRead)?;
        let file = match state.object {
            OpenObject::File(file) => file,
            OpenObject::Directory(_) | OpenObject::Pipe(_) | OpenObject::External(_) => {
                return Err(Error::StaleRead);
            }
        };
        if state.offset != plan.start_offset() || file != plan.file() {
            return Err(Error::StaleRead);
        }
        let bytes_read = u64::try_from(bytes_read).map_err(|_| Error::OffsetOverflow)?;
        let next = state
            .offset
            .checked_add(bytes_read)
            .ok_or(Error::OffsetOverflow)?;
        if bytes_read != 0 && next > file.size() {
            return Err(Error::InvalidReadLength);
        }
        state.offset = next;
        Ok(())
    }

    /// Prepares a positional immutable-file read without consulting or mutating the shared OFD
    /// position. Negative Linux `off_t` inputs are rejected before any state is exposed.
    pub fn prepare_pread(&self, fd: i32, offset: i64, max_len: usize) -> Result<PreadPlan, Error> {
        if offset < 0 {
            return Err(Error::InvalidPreadOffset);
        }
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        let file = match state.object {
            OpenObject::File(file) => file,
            OpenObject::External(_) => return Err(Error::NotSeekable),
            OpenObject::Directory(_) | OpenObject::Pipe(_) => return Err(Error::NotFile),
        };
        let offset = u64::try_from(offset).map_err(|_| Error::InvalidPreadOffset)?;
        Ok(PreadPlan {
            token,
            open_file,
            file,
            offset,
            len: core::cmp::min(bounded_remaining(file.size(), offset), max_len),
        })
    }

    /// Revalidates that a positional-read plan still names the exact live descriptor/OFD/file.
    /// Shared OFD offset movement is intentionally ignored because `pread64` is position-independent.
    pub fn validate_pread(&self, plan: PreadPlan) -> Result<(), Error> {
        let descriptor = self
            .descriptor_for_token(plan.token())
            .map_err(|_| Error::StalePread)?;
        if descriptor.open_file != plan.open_file() {
            return Err(Error::StalePread);
        }
        let state = self
            .open_file_state(plan.open_file())
            .map_err(|_| Error::StalePread)?;
        let file = match state.object {
            OpenObject::File(file) => file,
            OpenObject::Directory(_) | OpenObject::Pipe(_) | OpenObject::External(_) => {
                return Err(Error::StalePread);
            }
        };
        if file != plan.file() {
            return Err(Error::StalePread);
        }
        Ok(())
    }

    pub fn prepare_directory(&self, fd: i32) -> Result<DirectoryPlan, Error> {
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        let directory = match state.object {
            OpenObject::Directory(directory) => directory,
            OpenObject::File(_) | OpenObject::Pipe(_) | OpenObject::External(_) => {
                return Err(Error::NotDirectory);
            }
        };
        let start_cursor = usize::try_from(state.offset).map_err(|_| Error::OffsetOverflow)?;
        Ok(DirectoryPlan {
            token,
            open_file,
            directory,
            start_cursor,
        })
    }

    pub fn commit_directory(
        &mut self,
        plan: DirectoryPlan,
        scan: DirectoryScan<'_>,
    ) -> Result<(), Error> {
        if scan.directory() != plan.directory()
            || scan.start_cursor() != plan.start_cursor()
            || scan.next_cursor() <= plan.start_cursor()
        {
            return Err(Error::InvalidDirectoryCursor);
        }
        let descriptor = self
            .descriptor_for_token(plan.token())
            .map_err(|_| Error::StaleDirectory)?;
        if descriptor.open_file != plan.open_file() {
            return Err(Error::StaleDirectory);
        }
        let state = self
            .open_file_state_mut(plan.open_file())
            .map_err(|_| Error::StaleDirectory)?;
        let directory = match state.object {
            OpenObject::Directory(directory) => directory,
            OpenObject::File(_) | OpenObject::Pipe(_) | OpenObject::External(_) => {
                return Err(Error::StaleDirectory);
            }
        };
        let current = usize::try_from(state.offset).map_err(|_| Error::OffsetOverflow)?;
        if directory != plan.directory() || current != plan.start_cursor() {
            return Err(Error::StaleDirectory);
        }
        state.offset = u64::try_from(scan.next_cursor()).map_err(|_| Error::OffsetOverflow)?;
        Ok(())
    }

    pub fn metadata(&self, fd: i32) -> Result<Metadata, Error> {
        let state = self.open_file_state(self.descriptor(fd)?.open_file)?;
        let (size, mode) = match state.object {
            OpenObject::File(file) => (file.size(), file.mode()),
            OpenObject::Directory(directory) => (0, directory.mode()),
            OpenObject::Pipe(_) => (0, 0o010600),
            OpenObject::External(ExternalBacking::Stdio(_)) => (0, 0o020600),
            OpenObject::External(ExternalBacking::RetainedReadOnly(_))
            | OpenObject::External(ExternalBacking::WritableRegular(_)) => {
                return Err(Error::NotFile);
            }
        };
        Ok(Metadata { size, mode })
    }

    pub fn offset(&self, fd: i32) -> Result<u64, Error> {
        let state = self.open_file_state(self.descriptor(fd)?.open_file)?;
        match state.object {
            OpenObject::Pipe(_) | OpenObject::External(ExternalBacking::Stdio(_)) => {
                Err(Error::NotSeekable)
            }
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::External(ExternalBacking::RetainedReadOnly(_))
            | OpenObject::External(ExternalBacking::WritableRegular(_)) => Ok(state.offset),
        }
    }

    pub fn token(&self, fd: i32) -> Result<FdToken, Error> {
        let index = self.descriptor_slot_index(fd)?;
        let slot = &self.descriptors[index];
        if slot.retired || slot.state.is_none() {
            return Err(Error::BadFd);
        }
        Ok(FdToken {
            fd,
            generation: slot.generation,
        })
    }

    pub fn token_is_live(&self, token: FdToken) -> bool {
        self.descriptor_for_token(token)
            .and_then(|descriptor| self.validate_open_file(descriptor.open_file))
            .is_ok()
    }

    fn descriptor_for_token(&self, token: FdToken) -> Result<DescriptorState, Error> {
        let index = self.descriptor_slot_index(token.fd)?;
        let slot = &self.descriptors[index];
        if slot.retired || slot.generation != token.generation {
            return Err(Error::BadFd);
        }
        slot.state.ok_or(Error::BadFd)
    }

    fn descriptor(&self, fd: i32) -> Result<&DescriptorState, Error> {
        let index = self.descriptor_slot_index(fd)?;
        let slot = &self.descriptors[index];
        if slot.retired {
            return Err(Error::BadFd);
        }
        slot.state.as_ref().ok_or(Error::BadFd)
    }

    fn descriptor_mut(&mut self, fd: i32) -> Result<&mut DescriptorState, Error> {
        let index = self.descriptor_slot_index(fd)?;
        let slot = &mut self.descriptors[index];
        if slot.retired {
            return Err(Error::BadFd);
        }
        slot.state.as_mut().ok_or(Error::BadFd)
    }

    /// Range-only descriptor lookup. Allocation policy is deliberately separate and still starts
    /// at `FIRST_DYNAMIC_FD`, while exact-target duplication may populate any in-range slot.
    fn descriptor_slot_index(&self, fd: i32) -> Result<usize, Error> {
        let index = usize::try_from(fd).map_err(|_| Error::BadFd)?;
        if index >= N {
            return Err(Error::BadFd);
        }
        Ok(index)
    }

    fn validate_open_file(&self, id: OpenFileId) -> Result<(), Error> {
        self.open_file_state(id).map(|_| ())
    }

    fn open_file_slot(&self, id: OpenFileId) -> Result<&OpenFileSlot, Error> {
        let slot = self.open_files.get(id.index).ok_or(Error::StaleOpenFile)?;
        if slot.retired
            || slot.generation != id.generation
            || slot.state.is_none()
            || slot.refs == 0
        {
            return Err(Error::StaleOpenFile);
        }
        Ok(slot)
    }

    fn open_file_slot_mut(&mut self, id: OpenFileId) -> Result<&mut OpenFileSlot, Error> {
        let slot = self
            .open_files
            .get_mut(id.index)
            .ok_or(Error::StaleOpenFile)?;
        if slot.retired
            || slot.generation != id.generation
            || slot.state.is_none()
            || slot.refs == 0
        {
            return Err(Error::StaleOpenFile);
        }
        Ok(slot)
    }

    fn open_file_state(&self, id: OpenFileId) -> Result<&OpenState, Error> {
        self.open_file_slot(id)?
            .state
            .as_ref()
            .ok_or(Error::StaleOpenFile)
    }

    fn open_file_state_mut(&mut self, id: OpenFileId) -> Result<&mut OpenState, Error> {
        self.open_file_slot_mut(id)?
            .state
            .as_mut()
            .ok_or(Error::StaleOpenFile)
    }

    fn descriptor_candidate(&mut self, start: usize) -> Result<(usize, i32, u64), Error> {
        if start >= N {
            return Err(Error::TableFull);
        }
        let origin = self.descriptor_generation_origin;
        let stride = self.descriptor_generation_stride;
        for (index, slot) in self.descriptors.iter_mut().enumerate().skip(start) {
            if slot.retired || slot.state.is_some() {
                continue;
            }
            let Some(generation) = next_descriptor_generation(slot.generation, origin, stride)
            else {
                slot.retired = true;
                continue;
            };
            let Ok(fd) = i32::try_from(index) else {
                slot.retired = true;
                continue;
            };
            return Ok((index, fd, generation));
        }
        Err(Error::TableFull)
    }

    fn open_file_candidate(&mut self) -> Result<(usize, u64), Error> {
        for (index, slot) in self.open_files.iter_mut().enumerate() {
            if slot.retired || slot.state.is_some() {
                continue;
            }
            let Some(generation) = slot.generation.checked_add(1) else {
                slot.retired = true;
                continue;
            };
            return Ok((index, generation));
        }
        Err(Error::TableFull)
    }
}

fn next_descriptor_generation(current: u64, origin: u64, stride: u64) -> Option<u64> {
    if origin == 0 || stride == 0 || origin > stride {
        return None;
    }
    if current == 0 {
        Some(origin)
    } else {
        current.checked_add(stride)
    }
}

fn bounded_remaining(size: u64, offset: u64) -> usize {
    if offset >= size {
        return 0;
    }
    usize::try_from(size - offset).unwrap_or(usize::MAX)
}

impl<const N: usize> Default for FdTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_cpio::Archive;
    use kernal_linux_vfs::{AT_FDCWD, EntryId, InitramfsRoot, RootId};

    const MODE: u32 = 0o100644;
    const ROOT: RootId = RootId::new(7);
    const HEADER_LEN: usize = 110;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;

    fn file(entry_index: u16, size: u64) -> ReadOnlyFile {
        ReadOnlyFile::new(ROOT, EntryId::from_index(entry_index), MODE, size)
    }

    fn directory(entry_index: u16) -> ReadOnlyDirectory {
        ReadOnlyDirectory::new(ROOT, EntryId::from_index(entry_index), 0o040755)
    }

    fn hex(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn cpio_entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
        let start = out.len();
        out.extend_from_slice(b"070701");
        for value in [
            1,
            mode,
            0,
            0,
            1,
            0,
            u32::try_from(data.len()).unwrap(),
            0,
            0,
            0,
            0,
            u32::try_from(path.len() + 1).unwrap(),
            0,
        ] {
            hex(out, value);
        }
        assert_eq!(out.len() - start, HEADER_LEN);
        out.extend_from_slice(path);
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn directory_archive() -> Vec<u8> {
        let mut out = Vec::new();
        cpio_entry(&mut out, b".", S_IFDIR | 0o755, b"");
        cpio_entry(&mut out, b"etc", S_IFDIR | 0o755, b"");
        cpio_entry(&mut out, b"etc/hosts", S_IFREG | 0o644, b"host\n");
        cpio_entry(&mut out, b"TRAILER!!!", 0, b"");
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        out
    }

    #[test]
    fn preserves_accepted_numeric_fd_and_generation_contract() {
        let mut table = FdTable::<5>::new();
        let first = table.open_readonly(file(1, 6)).unwrap();
        let second = table.open_directory(directory(2)).unwrap();
        assert_eq!(first.fd(), 3);
        assert_eq!(second.fd(), 4);
        assert_eq!(first.generation(), 1);
        assert_eq!(second.generation(), 1);
        assert_eq!(table.open_readonly(file(3, 1)), Err(Error::TableFull));
    }

    #[test]
    fn duplicate_descriptors_share_one_open_file_offset() {
        let mut table = FdTable::<6>::new();
        let first = table.open_readonly(file(1, 10)).unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();
        assert_ne!(first.fd(), duplicate.fd());
        assert!(duplicate.fd() >= FIRST_DYNAMIC_FD as i32);
        assert_eq!(
            table.open_file_id(first.fd()),
            table.open_file_id(duplicate.fd())
        );
        let plan = table.prepare_read(first.fd(), 5).unwrap();
        table.commit_read(plan, 2).unwrap();
        assert_eq!(table.offset(duplicate.fd()), Ok(2));
        let duplicate_plan = table.prepare_read(duplicate.fd(), 4).unwrap();
        table.commit_read(duplicate_plan, 3).unwrap();
        assert_eq!(table.offset(first.fd()), Ok(5));
    }

    #[test]
    fn linux_dup_and_f_dupfd_policies_can_use_low_free_descriptors() {
        let mut table = FdTable::<7>::new();
        let source = table.open_readonly(file(1, 10)).unwrap();
        assert_eq!(source.fd(), 3);

        let lowest = table.duplicate_lowest(source.fd(), false).unwrap();
        assert_eq!(lowest.fd(), 0);
        assert_eq!(table.close_on_exec(lowest.fd()), Ok(false));
        assert_eq!(
            table.open_file_id(lowest.fd()),
            table.open_file_id(source.fd())
        );

        let from_one = table.duplicate_from(source.fd(), 1, true).unwrap();
        assert_eq!(from_one.fd(), 1);
        assert_eq!(table.close_on_exec(from_one.fd()), Ok(true));
        assert_eq!(
            table.open_file_id(from_one.fd()),
            table.open_file_id(source.fd())
        );

        let from_two = table.duplicate_from(source.fd(), 2, false).unwrap();
        assert_eq!(from_two.fd(), 2);
        assert_eq!(table.close_on_exec(from_two.fd()), Ok(false));
        assert_eq!(
            table.open_file_id(from_two.fd()),
            table.open_file_id(source.fd())
        );

        let dynamic = table.open_readonly(file(2, 1)).unwrap();
        assert_eq!(dynamic.fd(), 4);
    }

    #[test]
    fn linux_policy_open_reuses_lowest_free_standard_descriptor_hole() {
        const NONBLOCK: u64 = 0x800;
        let mut table = FdTable::<7>::new();
        let seed = table.open_readonly(file(1, 1)).unwrap();
        assert_eq!(seed.fd(), 3);
        for target in 0..3 {
            table.duplicate_exact(seed.fd(), target, false).unwrap();
        }
        table.close(seed.fd()).unwrap();

        let first = table
            .open_readonly_linux_with_flags(file(2, 2), true, NONBLOCK)
            .unwrap();
        assert_eq!(first.fd(), 3);
        assert_eq!(table.close_on_exec(first.fd()), Ok(true));
        assert_eq!(table.status_flags(first.fd()), Ok(NONBLOCK));

        let old_stdout = table.token(1).unwrap();
        table.close(1).unwrap();
        let reused = table
            .open_directory_linux_with_flags(directory(3), false, NONBLOCK)
            .unwrap();
        assert_eq!(reused.fd(), 1);
        assert_eq!(reused.generation(), old_stdout.generation() + 1);
        assert!(!table.token_is_live(old_stdout));
        assert_eq!(table.close_on_exec(reused.fd()), Ok(false));
        assert_eq!(table.status_flags(reused.fd()), Ok(NONBLOCK));
    }

    #[test]
    fn f_dupfd_minimum_is_exact_and_low_slot_reuse_advances_generation() {
        let mut table = FdTable::<7>::new();
        let source = table.open_readonly(file(1, 10)).unwrap();
        let low = table.duplicate_from(source.fd(), 1, false).unwrap();
        assert_eq!(low.fd(), 1);
        table.close(low.fd()).unwrap();

        let reused = table.duplicate_from(source.fd(), 1, true).unwrap();
        assert_eq!(reused.fd(), 1);
        assert_eq!(reused.generation(), low.generation() + 1);
        assert!(!table.token_is_live(low));
        assert_eq!(table.close_on_exec(reused.fd()), Ok(true));
        assert_eq!(
            table.duplicate_from(source.fd(), -1, false),
            Err(Error::InvalidMinimumFd)
        );
    }

    #[test]
    fn exact_duplicate_can_bind_reserved_fd_without_open_allocating_it() {
        let mut table = FdTable::<6>::new();
        let source = table
            .open_readonly_with_flags(file(1, 10), false, 0x800)
            .unwrap();
        assert_eq!(source.fd(), 3);
        assert_eq!(table.token(1), Err(Error::BadFd));

        let exact = table.duplicate_exact(source.fd(), 1, true).unwrap();
        assert_eq!(exact.fd(), 1);
        assert_eq!(exact.generation(), 1);
        assert_eq!(table.open_file_id(1), table.open_file_id(source.fd()));
        assert_eq!(table.status_flags(1), Ok(0x800));
        assert_eq!(table.close_on_exec(1), Ok(true));
        assert_eq!(table.seek(source.fd(), 4, SeekWhence::Set), Ok(4));
        assert_eq!(table.offset(1), Ok(4));

        table.close(1).unwrap();
        assert!(table.token_is_live(source));
        assert_eq!(table.token(1), Err(Error::BadFd));
    }

    #[test]
    fn exact_duplicate_releases_replaced_target_once_and_invalidates_its_token() {
        let mut table = FdTable::<6>::new();
        let source = table.open_readonly(file(1, 10)).unwrap();
        let target = table.open_readonly(file(2, 5)).unwrap();
        let target_open_file = table.open_file_id(target.fd()).unwrap();
        let exact = table
            .duplicate_exact(source.fd(), target.fd(), false)
            .unwrap();

        assert_eq!(exact.fd(), target.fd());
        assert_ne!(exact.generation(), target.generation());
        assert!(!table.token_is_live(target));
        assert_eq!(
            table.validate_open_file(target_open_file),
            Err(Error::StaleOpenFile)
        );
        assert_eq!(
            table.open_file_id(exact.fd()),
            table.open_file_id(source.fd())
        );

        table.close(source.fd()).unwrap();
        assert!(table.token_is_live(exact));
        table.close(exact.fd()).unwrap();
    }

    #[test]
    fn exact_duplicate_failures_leave_existing_bindings_unchanged() {
        let mut table = FdTable::<6>::new();
        let source = table.open_readonly(file(1, 10)).unwrap();
        let target = table.open_readonly(file(2, 5)).unwrap();
        let target_open_file = table.open_file_id(target.fd()).unwrap();

        assert_eq!(
            table.duplicate_exact(99, target.fd(), false),
            Err(Error::BadFd)
        );
        assert_eq!(table.open_file_id(target.fd()), Ok(target_open_file));
        assert!(table.token_is_live(target));
        assert_eq!(
            table.duplicate_exact(source.fd(), source.fd(), false),
            Err(Error::SameDescriptor)
        );
        assert!(table.token_is_live(source));
        assert_eq!(
            table.duplicate_exact(source.fd(), -1, false),
            Err(Error::InvalidTargetFd)
        );
        assert!(table.token_is_live(source));
    }

    #[test]
    fn exact_duplicate_generation_exhaustion_fails_without_mutation_or_revival() {
        let mut table = FdTable::<6>::new();
        let source = table.open_readonly(file(1, 10)).unwrap();
        let target = table.open_readonly(file(2, 5)).unwrap();
        let source_open_file = table.open_file_id(source.fd()).unwrap();
        let target_open_file = table.open_file_id(target.fd()).unwrap();
        let target_index = usize::try_from(target.fd()).unwrap();
        table.descriptors[target_index].generation = u64::MAX;

        assert_eq!(
            table.duplicate_exact(source.fd(), target.fd(), true),
            Err(Error::TableFull)
        );
        assert_eq!(table.descriptors[target_index].generation, u64::MAX);
        assert_eq!(table.open_file_id(source.fd()), Ok(source_open_file));
        assert_eq!(table.open_file_id(target.fd()), Ok(target_open_file));
        assert_eq!(table.open_file_slot(source_open_file).unwrap().refs, 1);
        assert_eq!(table.open_file_slot(target_open_file).unwrap().refs, 1);

        table.close(target.fd()).unwrap();
        assert_eq!(table.token(target.fd()), Err(Error::BadFd));
        assert_eq!(
            table.duplicate_exact(source.fd(), target.fd(), false),
            Err(Error::TableFull)
        );
        assert_eq!(table.descriptors[target_index].generation, u64::MAX);
        assert_eq!(table.open_file_slot(source_open_file).unwrap().refs, 1);
        assert_eq!(
            table.validate_open_file(target_open_file),
            Err(Error::StaleOpenFile)
        );
    }

    #[test]
    fn exact_duplicate_same_ofd_replacement_keeps_reference_count_balanced() {
        let mut table = FdTable::<6>::new();
        let source = table.open_readonly(file(1, 10)).unwrap();
        let alias = table.duplicate(source.fd(), 0, false).unwrap();
        let open_file = table.open_file_id(source.fd()).unwrap();
        assert_eq!(table.open_file_slot(open_file).unwrap().refs, 2);

        let replacement = table
            .duplicate_exact(source.fd(), alias.fd(), true)
            .unwrap();
        assert_eq!(table.open_file_slot(open_file).unwrap().refs, 2);
        assert!(!table.token_is_live(alias));
        assert!(table.token_is_live(replacement));
        assert_eq!(table.close_on_exec(replacement.fd()), Ok(true));
    }

    #[test]
    fn duplicate_directories_share_cursor_and_stale_prepared_alias() {
        let bytes = directory_archive();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT);
        let directory = root.open_directory_at(AT_FDCWD, b"/").unwrap();
        let mut table = FdTable::<6>::new();
        let first = table.open_directory(directory).unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();
        let first_plan = table.prepare_directory(first.fd()).unwrap();
        let stale_duplicate = table.prepare_directory(duplicate.fd()).unwrap();
        let scan = root
            .directory_entry_from(first_plan.directory(), first_plan.start_cursor())
            .unwrap()
            .unwrap();
        table.commit_directory(first_plan, scan).unwrap();
        assert_eq!(
            table
                .prepare_directory(duplicate.fd())
                .unwrap()
                .start_cursor(),
            scan.next_cursor()
        );
        assert_eq!(
            table.commit_directory(stale_duplicate, scan),
            Err(Error::StaleDirectory)
        );
    }

    #[test]
    fn status_flags_are_shared_but_cloexec_remains_descriptor_local() {
        const NONBLOCK: u64 = 0x800;
        let mut table = FdTable::<6>::new();
        let first = table
            .open_readonly_with_flags(file(1, 4), true, NONBLOCK)
            .unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();
        assert_eq!(table.status_flags(first.fd()), Ok(NONBLOCK));
        assert_eq!(table.status_flags(duplicate.fd()), Ok(NONBLOCK));
        assert_eq!(table.close_on_exec(first.fd()), Ok(true));
        assert_eq!(table.close_on_exec(duplicate.fd()), Ok(false));
    }

    #[test]
    fn closing_one_duplicate_keeps_open_file_live_until_last_close() {
        let mut table = FdTable::<6>::new();
        let first = table.open_readonly(file(1, 6)).unwrap();
        let open_file = table.open_file_id(first.fd()).unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();
        table.close(first.fd()).unwrap();
        assert!(!table.token_is_live(first));
        assert!(table.token_is_live(duplicate));
        assert!(table.validate_open_file(open_file).is_ok());
        table.close(duplicate.fd()).unwrap();
        assert_eq!(
            table.validate_open_file(open_file),
            Err(Error::StaleOpenFile)
        );
    }

    #[test]
    fn close_reuse_advances_descriptor_and_open_file_generations() {
        let mut table = FdTable::<4>::new();
        let first = table.open_readonly(file(1, 6)).unwrap();
        let old_open_file = table.open_file_id(first.fd()).unwrap();
        let stale = table.prepare_read(first.fd(), 1).unwrap();
        table.close(first.fd()).unwrap();
        let reused = table.open_directory(directory(2)).unwrap();
        let new_open_file = table.open_file_id(reused.fd()).unwrap();
        assert_eq!(reused.fd(), 3);
        assert_eq!(reused.generation(), 2);
        assert_eq!(old_open_file.index(), new_open_file.index());
        assert_eq!(new_open_file.generation(), old_open_file.generation() + 1);
        assert_eq!(table.commit_read(stale, 1), Err(Error::StaleRead));
    }

    #[test]
    fn cloexec_is_descriptor_local_and_resets_on_reuse() {
        let mut table = FdTable::<6>::new();
        let first = table.open_readonly_with_cloexec(file(1, 4), true).unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();
        assert_eq!(table.close_on_exec(first.fd()), Ok(true));
        assert_eq!(table.close_on_exec(duplicate.fd()), Ok(false));
        table.set_close_on_exec(duplicate.fd(), true).unwrap();
        assert_eq!(table.close_on_exec(first.fd()), Ok(true));
        assert_eq!(table.close_on_exec(duplicate.fd()), Ok(true));
        table.close(first.fd()).unwrap();
        let reused = table.open_readonly(file(2, 1)).unwrap();
        assert_eq!(reused.fd(), first.fd());
        assert_eq!(table.close_on_exec(reused.fd()), Ok(false));
    }

    #[test]
    fn stale_plan_cannot_commit_after_shared_offset_moves_via_duplicate() {
        let mut table = FdTable::<6>::new();
        let first = table.open_readonly(file(1, 10)).unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();
        let stale = table.prepare_read(first.fd(), 4).unwrap();
        let live = table.prepare_read(duplicate.fd(), 4).unwrap();
        table.commit_read(live, 1).unwrap();
        assert_eq!(table.commit_read(stale, 1), Err(Error::StaleRead));
    }

    #[test]
    fn seek_updates_shared_ofd_and_allows_beyond_eof() {
        let mut table = FdTable::<6>::new();
        let first = table.open_readonly(file(1, 6)).unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();

        assert_eq!(table.seek(first.fd(), 9, SeekWhence::Set), Ok(9));
        assert_eq!(table.offset(duplicate.fd()), Ok(9));
        assert!(table.prepare_read(duplicate.fd(), 4).unwrap().is_empty());

        assert_eq!(table.seek(duplicate.fd(), -3, SeekWhence::Current), Ok(6));
        assert_eq!(table.offset(first.fd()), Ok(6));
        assert_eq!(table.seek(first.fd(), -2, SeekWhence::End), Ok(4));
        assert_eq!(table.offset(duplicate.fd()), Ok(4));
    }

    #[test]
    fn seek_rejects_negative_or_overflow_without_mutation_and_directories() {
        let mut table = FdTable::<6>::new();
        let token = table.open_readonly(file(1, 6)).unwrap();
        assert_eq!(
            table.seek(token.fd(), -1, SeekWhence::Set),
            Err(Error::InvalidSeek)
        );
        assert_eq!(table.offset(token.fd()), Ok(0));
        assert_eq!(
            table.seek(token.fd(), i64::MAX, SeekWhence::Set),
            Ok(i64::MAX as u64)
        );
        assert_eq!(
            table.seek(token.fd(), 1, SeekWhence::Current),
            Err(Error::SeekOverflow)
        );
        assert_eq!(table.offset(token.fd()), Ok(i64::MAX as u64));

        let directory = table.open_directory(directory(2)).unwrap();
        assert_eq!(
            table.seek(directory.fd(), 0, SeekWhence::Set),
            Err(Error::NotSeekable)
        );
    }

    #[test]
    fn pread_is_explicit_and_ignores_shared_offset_movement() {
        let mut table = FdTable::<6>::new();
        let first = table.open_readonly(file(1, 10)).unwrap();
        let duplicate = table.duplicate(first.fd(), 0, false).unwrap();
        assert_eq!(table.seek(first.fd(), 5, SeekWhence::Set), Ok(5));

        let plan = table.prepare_pread(duplicate.fd(), 2, 4).unwrap();
        assert_eq!(plan.offset(), 2);
        assert_eq!(plan.len(), 4);
        assert_eq!(table.seek(first.fd(), 8, SeekWhence::Set), Ok(8));
        assert_eq!(table.validate_pread(plan), Ok(()));
        assert_eq!(table.offset(duplicate.fd()), Ok(8));

        let eof = table.prepare_pread(first.fd(), 10, 4).unwrap();
        assert!(eof.is_empty());
        assert_eq!(table.offset(first.fd()), Ok(8));
        assert_eq!(
            table.prepare_pread(first.fd(), -1, 4),
            Err(Error::InvalidPreadOffset)
        );
        assert_eq!(table.offset(first.fd()), Ok(8));
    }

    #[test]
    fn stale_pread_descriptor_cannot_revalidate_reused_identity() {
        let mut table = FdTable::<5>::new();
        let first = table.open_readonly(file(1, 10)).unwrap();
        let plan = table.prepare_pread(first.fd(), 0, 4).unwrap();
        table.close(first.fd()).unwrap();
        let reused = table.open_readonly(file(2, 10)).unwrap();
        assert_eq!(reused.fd(), first.fd());
        assert_ne!(reused.generation(), first.generation());
        assert_eq!(table.validate_pread(plan), Err(Error::StalePread));
    }

    #[test]
    fn directory_prepare_is_transactional_and_type_checked() {
        let mut table = FdTable::<5>::new();
        let dir = table.open_directory(directory(2)).unwrap();
        let plan = table.prepare_directory(dir.fd()).unwrap();
        assert_eq!(plan.start_cursor(), 0);
        assert_eq!(plan.directory(), directory(2));
        assert_eq!(table.offset(dir.fd()), Ok(0));
        let file_fd = table.open_readonly(file(3, 10)).unwrap().fd();
        assert_eq!(table.prepare_directory(file_fd), Err(Error::NotDirectory));
        assert_eq!(table.prepare_read(dir.fd(), 1), Err(Error::NotFile));
        assert_eq!(table.prepare_pread(dir.fd(), 0, 1), Err(Error::NotFile));
    }

    #[test]
    fn regular_read_keeps_accepted_bounds_and_partial_commit_behavior() {
        let mut table = FdTable::<4>::new();
        let token = table.open_readonly(file(1, 6)).unwrap();
        let plan = table.prepare_read(token.fd(), 5).unwrap();
        assert_eq!(table.commit_read(plan, 6), Err(Error::InvalidReadLength));
        assert_eq!(table.offset(token.fd()), Ok(0));
        table.commit_read(plan, 2).unwrap();
        assert_eq!(table.offset(token.fd()), Ok(2));
        assert_eq!(table.commit_read(plan, 1), Err(Error::StaleRead));
    }

    #[test]
    fn read_beyond_eof_is_empty_and_preserves_the_shared_position() {
        let mut table = FdTable::<4>::new();
        let token = table.open_readonly(file(1, 6)).unwrap();
        assert_eq!(table.seek(token.fd(), 9, SeekWhence::Set), Ok(9));
        let plan = table.prepare_read(token.fd(), 4).unwrap();
        assert!(plan.is_empty());
        assert_eq!(plan.start_offset(), 9);
        table.commit_read(plan, 0).unwrap();
        assert_eq!(table.offset(token.fd()), Ok(9));
    }

    #[test]
    fn generation_exhaustion_retires_descriptor_and_continues() {
        let mut table = FdTable::<5>::new();
        let old = table.open_readonly(file(1, 1)).unwrap();
        table.close(old.fd()).unwrap();
        table.descriptors[3].generation = u64::MAX;
        let next = table.open_readonly(file(2, 1)).unwrap();
        assert_eq!(next.fd(), 4);
        assert!(table.descriptors[3].retired);
        assert!(!table.token_is_live(old));
    }

    #[test]
    fn generation_exhaustion_retires_open_file_and_continues() {
        let mut table = FdTable::<5>::new();
        let first = table.open_readonly(file(1, 1)).unwrap();
        let old_open_file = table.open_file_id(first.fd()).unwrap();
        table.close(first.fd()).unwrap();
        table.open_files[old_open_file.index()].generation = u64::MAX;
        let second = table.open_readonly(file(2, 1)).unwrap();
        let new_open_file = table.open_file_id(second.fd()).unwrap();
        assert_ne!(new_open_file.index(), old_open_file.index());
        assert!(table.open_files[old_open_file.index()].retired);
    }

    #[test]
    fn table_full_open_does_not_consume_an_extra_open_file() {
        let mut table = FdTable::<4>::new();
        let first = table.open_readonly(file(1, 1)).unwrap();
        let open_file = table.open_file_id(first.fd()).unwrap();
        assert_eq!(table.open_readonly(file(2, 1)), Err(Error::TableFull));
        assert_eq!(table.open_file_id(first.fd()), Ok(open_file));
        assert_eq!(
            table
                .open_files
                .iter()
                .filter(|slot| slot.state.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn reserved_and_out_of_range_fds_fail_closed_until_exactly_populated() {
        let mut table = FdTable::<5>::new();
        for fd in [-1, 0, 1, 2, 5, 99] {
            assert_eq!(table.close(fd), Err(Error::BadFd));
            assert_eq!(table.prepare_read(fd, 1), Err(Error::BadFd));
            assert_eq!(table.prepare_directory(fd), Err(Error::BadFd));
        }
        let source = table.open_readonly(file(1, 2)).unwrap();
        table.duplicate_exact(source.fd(), 2, false).unwrap();
        assert!(table.token(2).is_ok());
        assert_eq!(table.prepare_read(2, 1).unwrap().file(), file(1, 2));
    }
}
