// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::*;
use kernal_linux_vfs::{
    OverlayDirectoryHandle, OverlayDirectoryScan, OverlayNodeHandle, RetainedRegularHandle,
};

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_APPEND: u64 = 0x0000_0400;
const O_NONBLOCK: u64 = 0x0000_0800;
const MUTABLE_STATUS_FLAGS: u64 = O_APPEND | O_NONBLOCK;
const STANDARD_INPUT_STATUS_FLAGS: u64 = O_RDONLY;
const STANDARD_OUTPUT_STATUS_FLAGS: u64 = O_WRONLY;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalObject {
    Stdin,
    Stdout,
    Stderr,
}

/// Private read-only VFS authority retained by one shared OFD.
///
/// Keeping both regular and directory authorities behind the already-established
/// `ExternalBacking::RetainedReadOnly` variant preserves the FD core's generic metadata/offset
/// matches while still allowing linux-fd to distinguish their public object kind and final release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RetainedReadOnlyBacking {
    Regular(OverlayNodeHandle),
    Directory(OverlayDirectoryHandle),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExternalBacking {
    Stdio(ExternalObject),
    RetainedReadOnly(RetainedReadOnlyBacking),
    WritableRegular(RetainedRegularHandle),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenObjectKind {
    File,
    Directory,
    Pipe,
    External(ExternalObject),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardDescriptors {
    stdin: FdToken,
    stdout: FdToken,
    stderr: FdToken,
}

impl StandardDescriptors {
    pub const fn stdin(self) -> FdToken {
        self.stdin
    }

    pub const fn stdout(self) -> FdToken {
        self.stdout
    }

    pub const fn stderr(self) -> FdToken {
        self.stderr
    }
}

fn writable_access(status_flags: u64) -> bool {
    matches!(status_flags & O_ACCMODE, O_WRONLY | O_RDWR)
}

fn readable_access(status_flags: u64) -> bool {
    matches!(status_flags & O_ACCMODE, O_RDONLY | O_RDWR)
}

fn readonly_access(status_flags: u64) -> bool {
    status_flags & O_ACCMODE == O_RDONLY
}

impl<const N: usize> FdTable<N> {
    pub fn seed_standard_descriptors(&mut self) -> Result<StandardDescriptors, Error> {
        let mut descriptor_generations = [0u64; 3];
        for (index, generation) in descriptor_generations.iter_mut().enumerate() {
            let slot = self.descriptors.get(index).ok_or(Error::TableFull)?;
            if slot.retired || slot.state.is_some() || slot.generation != 0 {
                return Err(Error::TableFull);
            }
            *generation = next_descriptor_generation(
                slot.generation,
                self.descriptor_generation_origin,
                self.descriptor_generation_stride,
            )
            .ok_or(Error::TableFull)?;
        }

        let open_files = self.standard_open_file_candidates()?;
        let identities = [
            ExternalObject::Stdin,
            ExternalObject::Stdout,
            ExternalObject::Stderr,
        ];
        let status_flags = [
            STANDARD_INPUT_STATUS_FLAGS,
            STANDARD_OUTPUT_STATUS_FLAGS,
            STANDARD_OUTPUT_STATUS_FLAGS,
        ];

        for index in 0..3 {
            let (open_file_index, open_file_generation) = open_files[index];
            let open_file = OpenFileId {
                index: open_file_index,
                generation: open_file_generation,
            };
            self.open_files[open_file_index].generation = open_file_generation;
            self.open_files[open_file_index].refs = 1;
            self.open_files[open_file_index].state = Some(OpenState {
                object: OpenObject::External(ExternalBacking::Stdio(identities[index])),
                offset: 0,
                status_flags: status_flags[index],
            });
            self.descriptors[index].generation = descriptor_generations[index];
            self.descriptors[index].state = Some(DescriptorState {
                open_file,
                close_on_exec: false,
            });
        }

        Ok(StandardDescriptors {
            stdin: FdToken {
                fd: 0,
                generation: descriptor_generations[0],
            },
            stdout: FdToken {
                fd: 1,
                generation: descriptor_generations[1],
            },
            stderr: FdToken {
                fd: 2,
                generation: descriptor_generations[2],
            },
        })
    }

    pub fn open_retained_directory_linux_with_flags(
        &mut self,
        directory: OverlayDirectoryHandle,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        if !readonly_access(status_flags) {
            return Err(Error::BadFd);
        }
        self.open_object_from(
            0,
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Directory(directory),
            )),
            close_on_exec,
            status_flags,
        )
    }

    pub fn retained_directory(&self, fd: i32) -> Result<OverlayDirectoryHandle, Error> {
        let state = self.open_file_state(self.descriptor(fd)?.open_file)?;
        match state.object {
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Directory(directory),
            )) => Ok(directory),
            _ => Err(Error::NotDirectory),
        }
    }

    pub fn prepare_retained_directory(
        &self,
        fd: i32,
    ) -> Result<(FdToken, OpenFileId, OverlayDirectoryHandle, usize), Error> {
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        if !readonly_access(state.status_flags) {
            return Err(Error::BadFd);
        }
        let directory = match state.object {
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Directory(directory),
            )) => directory,
            _ => return Err(Error::NotDirectory),
        };
        let cursor = usize::try_from(state.offset).map_err(|_| Error::OffsetOverflow)?;
        Ok((token, open_file, directory, cursor))
    }

    pub fn commit_retained_directory(
        &mut self,
        plan: (FdToken, OpenFileId, OverlayDirectoryHandle, usize),
        scan: OverlayDirectoryScan,
    ) -> Result<(), Error> {
        let (token, open_file, directory, start_cursor) = plan;
        if scan.directory() != directory
            || scan.start_cursor() != start_cursor
            || scan.next_cursor() <= start_cursor
        {
            return Err(Error::InvalidDirectoryCursor);
        }
        let descriptor = self
            .descriptor_for_token(token)
            .map_err(|_| Error::StaleDirectory)?;
        if descriptor.open_file != open_file {
            return Err(Error::StaleDirectory);
        }
        let state = self
            .open_file_state_mut(open_file)
            .map_err(|_| Error::StaleDirectory)?;
        let current = usize::try_from(state.offset).map_err(|_| Error::OffsetOverflow)?;
        if !readonly_access(state.status_flags)
            || current != start_cursor
            || state.object
                != OpenObject::External(ExternalBacking::RetainedReadOnly(
                    RetainedReadOnlyBacking::Directory(directory),
                ))
        {
            return Err(Error::StaleDirectory);
        }
        state.offset = u64::try_from(scan.next_cursor()).map_err(|_| Error::OffsetOverflow)?;
        Ok(())
    }

    pub fn open_retained_readonly_linux_with_flags(
        &mut self,
        logical: OverlayNodeHandle,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        if !readonly_access(status_flags) {
            return Err(Error::BadFd);
        }
        self.open_object_from(
            0,
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Regular(logical),
            )),
            close_on_exec,
            status_flags,
        )
    }

    pub fn retained_readonly(&self, fd: i32) -> Result<OverlayNodeHandle, Error> {
        let state = self.open_file_state(self.descriptor(fd)?.open_file)?;
        match state.object {
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Regular(logical),
            )) => Ok(logical),
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(_) => Err(Error::NotFile),
        }
    }

    pub fn prepare_retained_read(
        &self,
        fd: i32,
        max_len: usize,
    ) -> Result<(FdToken, OpenFileId, OverlayNodeHandle, u64, usize), Error> {
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        if !readonly_access(state.status_flags) {
            return Err(Error::BadFd);
        }
        let logical = match state.object {
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Regular(logical),
            )) => logical,
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(_) => return Err(Error::NotFile),
        };
        Ok((token, open_file, logical, state.offset, max_len))
    }

    pub fn commit_retained_read(
        &mut self,
        plan: (FdToken, OpenFileId, OverlayNodeHandle, u64, usize),
        bytes_read: usize,
    ) -> Result<u64, Error> {
        let (token, open_file, logical, expected_offset, max_len) = plan;
        if bytes_read > max_len {
            return Err(Error::InvalidReadLength);
        }
        let descriptor = self
            .descriptor_for_token(token)
            .map_err(|_| Error::StaleRead)?;
        if descriptor.open_file != open_file {
            return Err(Error::StaleRead);
        }
        let state = self
            .open_file_state_mut(open_file)
            .map_err(|_| Error::StaleRead)?;
        if !readonly_access(state.status_flags)
            || state.offset != expected_offset
            || state.object
                != OpenObject::External(ExternalBacking::RetainedReadOnly(
                    RetainedReadOnlyBacking::Regular(logical),
                ))
        {
            return Err(Error::StaleRead);
        }
        let count = u64::try_from(bytes_read).map_err(|_| Error::OffsetOverflow)?;
        let next = expected_offset
            .checked_add(count)
            .ok_or(Error::OffsetOverflow)?;
        state.offset = next;
        Ok(next)
    }

    pub fn prepare_retained_pread(
        &self,
        fd: i32,
        offset: i64,
        max_len: usize,
    ) -> Result<(FdToken, OpenFileId, OverlayNodeHandle, u64, usize), Error> {
        if offset < 0 {
            return Err(Error::InvalidPreadOffset);
        }
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        if !readonly_access(state.status_flags) {
            return Err(Error::BadFd);
        }
        let logical = match state.object {
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Regular(logical),
            )) => logical,
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(_) => return Err(Error::NotFile),
        };
        Ok((
            token,
            open_file,
            logical,
            u64::try_from(offset).map_err(|_| Error::InvalidPreadOffset)?,
            max_len,
        ))
    }

    pub fn validate_retained_pread(
        &self,
        plan: (FdToken, OpenFileId, OverlayNodeHandle, u64, usize),
    ) -> Result<(), Error> {
        let (token, open_file, logical, _, _) = plan;
        let descriptor = self
            .descriptor_for_token(token)
            .map_err(|_| Error::StalePread)?;
        if descriptor.open_file != open_file {
            return Err(Error::StalePread);
        }
        let state = self
            .open_file_state(open_file)
            .map_err(|_| Error::StalePread)?;
        if !readonly_access(state.status_flags)
            || state.object
                != OpenObject::External(ExternalBacking::RetainedReadOnly(
                    RetainedReadOnlyBacking::Regular(logical),
                ))
        {
            return Err(Error::StalePread);
        }
        Ok(())
    }

    pub fn seek_retained_readonly(
        &mut self,
        fd: i32,
        offset: i64,
        whence: SeekWhence,
        file_end: u64,
    ) -> Result<u64, Error> {
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state_mut(open_file)?;
        if !matches!(
            state.object,
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Regular(_)
            ))
        ) {
            return Err(Error::NotSeekable);
        }
        seek_live_regular(state, offset, whence, file_end)
    }

    pub fn retained_regular_metadata(
        &self,
        fd: i32,
        size: u64,
        mode: u32,
    ) -> Result<Metadata, Error> {
        let state = self.open_file_state(self.descriptor(fd)?.open_file)?;
        match state.object {
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Regular(_),
            ))
            | OpenObject::External(ExternalBacking::WritableRegular(_)) => {
                Ok(Metadata { size, mode })
            }
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Directory(_),
            ))
            | OpenObject::External(ExternalBacking::Stdio(_)) => Err(Error::NotFile),
        }
    }

    pub fn open_writable_linux_with_flags(
        &mut self,
        retained: RetainedRegularHandle,
        close_on_exec: bool,
        status_flags: u64,
    ) -> Result<FdToken, Error> {
        if !writable_access(status_flags) {
            return Err(Error::BadFd);
        }
        self.open_object_from(
            0,
            OpenObject::External(ExternalBacking::WritableRegular(retained)),
            close_on_exec,
            status_flags,
        )
    }

    pub fn writable_regular(&self, fd: i32) -> Result<RetainedRegularHandle, Error> {
        let state = self.open_file_state(self.descriptor(fd)?.open_file)?;
        match state.object {
            OpenObject::External(ExternalBacking::WritableRegular(retained)) => Ok(retained),
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(_) => Err(Error::NotFile),
        }
    }

    pub fn prepare_write(
        &self,
        fd: i32,
        max_len: usize,
    ) -> Result<(FdToken, OpenFileId, RetainedRegularHandle, u64, usize, bool), Error> {
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        if !writable_access(state.status_flags) {
            return Err(Error::BadFd);
        }
        let retained = match state.object {
            OpenObject::External(ExternalBacking::WritableRegular(retained)) => retained,
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(_) => return Err(Error::NotFile),
        };
        Ok((
            token,
            open_file,
            retained,
            state.offset,
            max_len,
            state.status_flags & O_APPEND != 0,
        ))
    }

    pub fn commit_write(
        &mut self,
        plan: (FdToken, OpenFileId, RetainedRegularHandle, u64, usize, bool),
        actual_start: u64,
        bytes_written: usize,
    ) -> Result<u64, Error> {
        let (token, open_file, retained, expected_offset, max_len, expected_append) = plan;
        if bytes_written > max_len {
            return Err(Error::InvalidReadLength);
        }
        let descriptor = self
            .descriptor_for_token(token)
            .map_err(|_| Error::StaleOpenFile)?;
        if descriptor.open_file != open_file {
            return Err(Error::StaleOpenFile);
        }
        let state = self
            .open_file_state_mut(open_file)
            .map_err(|_| Error::StaleOpenFile)?;
        if !writable_access(state.status_flags)
            || state.offset != expected_offset
            || (state.status_flags & O_APPEND != 0) != expected_append
            || state.object != OpenObject::External(ExternalBacking::WritableRegular(retained))
        {
            return Err(Error::StaleOpenFile);
        }
        if bytes_written == 0 {
            return Ok(state.offset);
        }
        if !expected_append && actual_start != expected_offset {
            return Err(Error::StaleOpenFile);
        }
        let count = u64::try_from(bytes_written).map_err(|_| Error::OffsetOverflow)?;
        let next = actual_start
            .checked_add(count)
            .ok_or(Error::OffsetOverflow)?;
        state.offset = next;
        Ok(next)
    }

    pub fn prepare_pwrite(
        &self,
        fd: i32,
        offset: i64,
        max_len: usize,
    ) -> Result<(FdToken, OpenFileId, RetainedRegularHandle, u64, usize, bool), Error> {
        if offset < 0 {
            return Err(Error::InvalidPreadOffset);
        }
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        if !writable_access(state.status_flags) {
            return Err(Error::BadFd);
        }
        let retained = match state.object {
            OpenObject::External(ExternalBacking::WritableRegular(retained)) => retained,
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(_) => return Err(Error::NotFile),
        };
        Ok((
            token,
            open_file,
            retained,
            u64::try_from(offset).map_err(|_| Error::InvalidPreadOffset)?,
            max_len,
            state.status_flags & O_APPEND != 0,
        ))
    }

    pub fn validate_pwrite(
        &self,
        plan: (FdToken, OpenFileId, RetainedRegularHandle, u64, usize, bool),
    ) -> Result<(), Error> {
        let (token, open_file, retained, _, _, expected_append) = plan;
        let descriptor = self
            .descriptor_for_token(token)
            .map_err(|_| Error::StaleOpenFile)?;
        if descriptor.open_file != open_file {
            return Err(Error::StaleOpenFile);
        }
        let state = self
            .open_file_state(open_file)
            .map_err(|_| Error::StaleOpenFile)?;
        if !writable_access(state.status_flags)
            || (state.status_flags & O_APPEND != 0) != expected_append
            || state.object != OpenObject::External(ExternalBacking::WritableRegular(retained))
        {
            return Err(Error::StaleOpenFile);
        }
        Ok(())
    }

    pub fn prepare_writable_read(
        &self,
        fd: i32,
        max_len: usize,
    ) -> Result<(FdToken, OpenFileId, RetainedRegularHandle, u64, usize), Error> {
        let token = self.token(fd)?;
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state(open_file)?;
        if !readable_access(state.status_flags) {
            return Err(Error::BadFd);
        }
        let retained = match state.object {
            OpenObject::External(ExternalBacking::WritableRegular(retained)) => retained,
            OpenObject::File(_)
            | OpenObject::Directory(_)
            | OpenObject::Pipe(_)
            | OpenObject::External(_) => return Err(Error::NotFile),
        };
        Ok((token, open_file, retained, state.offset, max_len))
    }

    pub fn commit_writable_read(
        &mut self,
        plan: (FdToken, OpenFileId, RetainedRegularHandle, u64, usize),
        bytes_read: usize,
    ) -> Result<u64, Error> {
        let (token, open_file, retained, expected_offset, max_len) = plan;
        if bytes_read > max_len {
            return Err(Error::InvalidReadLength);
        }
        let descriptor = self
            .descriptor_for_token(token)
            .map_err(|_| Error::StaleRead)?;
        if descriptor.open_file != open_file {
            return Err(Error::StaleRead);
        }
        let state = self
            .open_file_state_mut(open_file)
            .map_err(|_| Error::StaleRead)?;
        if !readable_access(state.status_flags)
            || state.offset != expected_offset
            || state.object != OpenObject::External(ExternalBacking::WritableRegular(retained))
        {
            return Err(Error::StaleRead);
        }
        let count = u64::try_from(bytes_read).map_err(|_| Error::OffsetOverflow)?;
        let next = expected_offset
            .checked_add(count)
            .ok_or(Error::OffsetOverflow)?;
        state.offset = next;
        Ok(next)
    }

    pub fn seek_writable(
        &mut self,
        fd: i32,
        offset: i64,
        whence: SeekWhence,
        file_end: u64,
    ) -> Result<u64, Error> {
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state_mut(open_file)?;
        if !matches!(
            state.object,
            OpenObject::External(ExternalBacking::WritableRegular(_))
        ) {
            return Err(Error::NotSeekable);
        }
        seek_live_regular(state, offset, whence, file_end)
    }

    pub fn set_mutable_status_flags(&mut self, fd: i32, requested: u64) -> Result<u64, Error> {
        let open_file = self.descriptor(fd)?.open_file;
        let state = self.open_file_state_mut(open_file)?;
        state.status_flags =
            (state.status_flags & !MUTABLE_STATUS_FLAGS) | (requested & MUTABLE_STATUS_FLAGS);
        Ok(state.status_flags)
    }

    pub fn next_close_on_exec(&self, after_fd: Option<i32>) -> Option<FdToken> {
        let start = match after_fd {
            None => 0,
            Some(fd) if fd < 0 => 0,
            Some(fd) => usize::try_from(fd).ok()?.checked_add(1)?,
        };
        for (index, slot) in self.descriptors.iter().enumerate().skip(start) {
            if slot.retired {
                continue;
            }
            let Some(state) = slot.state else {
                continue;
            };
            if !state.close_on_exec {
                continue;
            }
            let Ok(fd) = i32::try_from(index) else {
                continue;
            };
            return Some(FdToken {
                fd,
                generation: slot.generation,
            });
        }
        None
    }

    pub fn object_kind(&self, fd: i32) -> Result<OpenObjectKind, Error> {
        let object = self.open_file_state(self.descriptor(fd)?.open_file)?.object;
        Ok(match object {
            OpenObject::File(_) => OpenObjectKind::File,
            OpenObject::Directory(_) => OpenObjectKind::Directory,
            OpenObject::Pipe(_) => OpenObjectKind::Pipe,
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Directory(_),
            )) => OpenObjectKind::Directory,
            OpenObject::External(ExternalBacking::RetainedReadOnly(
                RetainedReadOnlyBacking::Regular(_),
            ))
            | OpenObject::External(ExternalBacking::WritableRegular(_)) => OpenObjectKind::File,
            OpenObject::External(ExternalBacking::Stdio(external)) => {
                OpenObjectKind::External(external)
            }
        })
    }

    fn standard_open_file_candidates(&self) -> Result<[(usize, u64); 3], Error> {
        let mut found = [None, None, None];
        let mut count = 0usize;
        for (index, slot) in self.open_files.iter().enumerate() {
            if slot.retired || slot.state.is_some() {
                continue;
            }
            let Some(generation) = slot.generation.checked_add(1) else {
                continue;
            };
            found[count] = Some((index, generation));
            count += 1;
            if count == 3 {
                break;
            }
        }
        match (found[0], found[1], found[2]) {
            (Some(stdin), Some(stdout), Some(stderr)) => Ok([stdin, stdout, stderr]),
            _ => Err(Error::TableFull),
        }
    }
}

fn seek_live_regular(
    state: &mut OpenState,
    offset: i64,
    whence: SeekWhence,
    file_end: u64,
) -> Result<u64, Error> {
    let base = match whence {
        SeekWhence::Set => 0i128,
        SeekWhence::Current => i128::from(state.offset),
        SeekWhence::End => i128::from(file_end),
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
