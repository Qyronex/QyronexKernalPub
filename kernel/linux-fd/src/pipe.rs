// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::stdio::RetainedReadOnlyBacking;
use super::*;
use kernal_linux_pipe::{End, Endpoint};
use kernal_linux_vfs::{OverlayDirectoryHandle, OverlayNodeHandle, RetainedRegularHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleasedObject {
    Pipe(Endpoint),
    RetainedDirectory(OverlayDirectoryHandle),
    RetainedReadOnly(OverlayNodeHandle),
    WritableRegular(RetainedRegularHandle),
}

impl ReleasedObject {
    pub const fn pipe_endpoint(self) -> Endpoint {
        match self {
            Self::Pipe(endpoint) => endpoint,
            Self::RetainedDirectory(_) | Self::RetainedReadOnly(_) | Self::WritableRegular(_) => {
                panic!("released object is not a pipe")
            }
        }
    }

    pub const fn retained_directory(self) -> Option<OverlayDirectoryHandle> {
        match self {
            Self::RetainedDirectory(directory) => Some(directory),
            Self::Pipe(_) | Self::RetainedReadOnly(_) | Self::WritableRegular(_) => None,
        }
    }

    pub const fn retained_readonly(self) -> Option<OverlayNodeHandle> {
        match self {
            Self::RetainedReadOnly(logical) => Some(logical),
            Self::Pipe(_) | Self::RetainedDirectory(_) | Self::WritableRegular(_) => None,
        }
    }

    pub const fn writable_regular(self) -> Option<RetainedRegularHandle> {
        match self {
            Self::WritableRegular(retained) => Some(retained),
            Self::Pipe(_) | Self::RetainedDirectory(_) | Self::RetainedReadOnly(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipeDescriptors {
    reader: FdToken,
    writer: FdToken,
}

impl PipeDescriptors {
    pub const fn reader(self) -> FdToken {
        self.reader
    }
    pub const fn writer(self) -> FdToken {
        self.writer
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClosePlan {
    token: FdToken,
    open_file: OpenFileId,
    expected_refs: usize,
    expected_object: OpenObject,
    release: Option<ReleasedObject>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactDuplicatePlan {
    source_token: FdToken,
    source_open_file: OpenFileId,
    source_refs: usize,
    target_fd: i32,
    target_generation: u64,
    target_next_generation: u64,
    target_open_file: Option<OpenFileId>,
    target_refs: Option<usize>,
    target_object: Option<OpenObject>,
    close_on_exec: bool,
    release: Option<ReleasedObject>,
}

impl<const N: usize> FdTable<N> {
    pub fn install_pipe_pair(
        &mut self,
        reader: Endpoint,
        writer: Endpoint,
        close_on_exec: bool,
        reader_status_flags: u64,
        writer_status_flags: u64,
    ) -> Result<PipeDescriptors, Error> {
        if reader.end() != End::Read || writer.end() != End::Write || reader.pipe() != writer.pipe()
        {
            return Err(Error::StaleOpenFile);
        }
        let [rd, wd] = self.descriptor_pair_candidates()?;
        let [ro, wo] = self.open_file_pair_candidates()?;
        let rid = OpenFileId {
            index: ro.0,
            generation: ro.1,
        };
        let wid = OpenFileId {
            index: wo.0,
            generation: wo.1,
        };
        self.open_files[ro.0].generation = ro.1;
        self.open_files[ro.0].refs = 1;
        self.open_files[ro.0].state = Some(OpenState {
            object: OpenObject::Pipe(reader),
            offset: 0,
            status_flags: reader_status_flags,
        });
        self.open_files[wo.0].generation = wo.1;
        self.open_files[wo.0].refs = 1;
        self.open_files[wo.0].state = Some(OpenState {
            object: OpenObject::Pipe(writer),
            offset: 0,
            status_flags: writer_status_flags,
        });
        self.descriptors[rd.0].generation = rd.2;
        self.descriptors[rd.0].state = Some(DescriptorState {
            open_file: rid,
            close_on_exec,
        });
        self.descriptors[wd.0].generation = wd.2;
        self.descriptors[wd.0].state = Some(DescriptorState {
            open_file: wid,
            close_on_exec,
        });
        Ok(PipeDescriptors {
            reader: FdToken {
                fd: rd.1,
                generation: rd.2,
            },
            writer: FdToken {
                fd: wd.1,
                generation: wd.2,
            },
        })
    }

    pub fn pipe_endpoint(&self, fd: i32) -> Result<Endpoint, Error> {
        match self.open_file_state(self.descriptor(fd)?.open_file)?.object {
            OpenObject::Pipe(endpoint) => Ok(endpoint),
            OpenObject::File(_) | OpenObject::Directory(_) | OpenObject::External(_) => {
                Err(Error::NotFile)
            }
        }
    }

    pub fn prepare_close_on_exec(&self) -> Result<[Option<FdToken>; N], Error> {
        self.close_on_exec_snapshot()
    }

    pub fn commit_close_on_exec(
        &mut self,
        plan: [Option<FdToken>; N],
    ) -> Result<[Option<ReleasedObject>; N], Error> {
        if self.close_on_exec_snapshot()? != plan {
            return Err(Error::StaleOpenFile);
        }

        let mut selected_refs = [0usize; N];
        let mut selected_open_files = [None; N];

        for token in plan.iter().flatten().copied() {
            let descriptor = self
                .descriptor_for_token(token)
                .map_err(|_| Error::StaleOpenFile)?;
            let open_file = descriptor.open_file;
            self.open_file_slot(open_file)
                .map_err(|_| Error::StaleOpenFile)?;
            let count = selected_refs
                .get_mut(open_file.index)
                .ok_or(Error::StaleOpenFile)?;
            *count = count.checked_add(1).ok_or(Error::ReferenceOverflow)?;
            let selected = selected_open_files
                .get_mut(open_file.index)
                .ok_or(Error::StaleOpenFile)?;
            match *selected {
                None => *selected = Some(open_file),
                Some(existing) if existing == open_file => {}
                Some(_) => return Err(Error::StaleOpenFile),
            }
        }

        let mut released = [None; N];
        for index in 0..N {
            let count = selected_refs[index];
            if count == 0 {
                continue;
            }
            let open_file = selected_open_files[index].ok_or(Error::StaleOpenFile)?;
            let slot = *self
                .open_file_slot(open_file)
                .map_err(|_| Error::StaleOpenFile)?;
            if count > slot.refs {
                return Err(Error::StaleOpenFile);
            }
            if count == slot.refs {
                released[index] = released_object(slot.state.ok_or(Error::StaleOpenFile)?.object);
            }
        }

        for token in plan.iter().flatten().copied() {
            let index = token.fd() as usize;
            debug_assert!(index < N);
            self.descriptors[index].state = None;
        }
        for index in 0..N {
            let count = selected_refs[index];
            if count == 0 {
                continue;
            }
            let open_file = selected_open_files[index];
            debug_assert!(open_file.is_some());
            debug_assert_eq!(open_file.map(|id| id.index), Some(index));
            let slot = &mut self.open_files[index];
            debug_assert!(slot.state.is_some());
            debug_assert!(slot.refs >= count);
            slot.refs -= count;
            if slot.refs == 0 {
                slot.state = None;
            }
        }
        Ok(released)
    }

    pub fn close_with_release<E, F>(&mut self, fd: i32, release: F) -> Result<Result<(), E>, Error>
    where
        F: FnOnce(ReleasedObject) -> Result<(), E>,
    {
        let plan = self.prepare_close(fd)?;
        if let Err(error) = release_if_needed(plan.release, release) {
            return Ok(Err(error));
        }
        self.commit_close(plan)?;
        Ok(Ok(()))
    }

    pub fn close_token_with_release<E, F>(
        &mut self,
        token: FdToken,
        release: F,
    ) -> Result<Result<(), E>, Error>
    where
        F: FnOnce(ReleasedObject) -> Result<(), E>,
    {
        let plan = self.prepare_close_token(token)?;
        if let Err(error) = release_if_needed(plan.release, release) {
            return Ok(Err(error));
        }
        self.commit_close(plan)?;
        Ok(Ok(()))
    }

    pub fn duplicate_exact_with_release<E, F>(
        &mut self,
        source_fd: i32,
        target_fd: i32,
        close_on_exec: bool,
        release: F,
    ) -> Result<Result<FdToken, E>, Error>
    where
        F: FnOnce(ReleasedObject) -> Result<(), E>,
    {
        let plan = self.prepare_duplicate_exact(source_fd, target_fd, close_on_exec)?;
        if let Err(error) = release_if_needed(plan.release, release) {
            return Ok(Err(error));
        }
        Ok(Ok(self.commit_duplicate_exact(plan)?))
    }

    pub(crate) fn close_pipe_aware(
        &mut self,
        fd: i32,
        _allow_pipe_release: bool,
    ) -> Result<Option<ReleasedObject>, Error> {
        let plan = self.prepare_close(fd)?;
        if plan.release.is_some() {
            return Err(Error::StaleOpenFile);
        }
        self.commit_close(plan)?;
        Ok(None)
    }

    pub(crate) fn duplicate_exact_pipe_aware(
        &mut self,
        source_fd: i32,
        target_fd: i32,
        close_on_exec: bool,
        _allow_pipe_release: bool,
    ) -> Result<(FdToken, Option<ReleasedObject>), Error> {
        let plan = self.prepare_duplicate_exact(source_fd, target_fd, close_on_exec)?;
        if plan.release.is_some() {
            return Err(Error::StaleOpenFile);
        }
        Ok((self.commit_duplicate_exact(plan)?, None))
    }

    fn close_on_exec_snapshot(&self) -> Result<[Option<FdToken>; N], Error> {
        let mut selected = [None; N];
        for (index, slot) in self.descriptors.iter().enumerate() {
            if slot.retired {
                continue;
            }
            let Some(state) = slot.state else {
                continue;
            };
            if !state.close_on_exec {
                continue;
            }
            let fd = i32::try_from(index).map_err(|_| Error::InvalidTargetFd)?;
            selected[index] = Some(FdToken {
                fd,
                generation: slot.generation,
            });
        }
        Ok(selected)
    }

    fn prepare_close(&self, fd: i32) -> Result<ClosePlan, Error> {
        self.prepare_close_token(self.token(fd)?)
    }

    fn prepare_close_token(&self, token: FdToken) -> Result<ClosePlan, Error> {
        let descriptor = self
            .descriptor_for_token(token)
            .map_err(|_| Error::StaleOpenFile)?;
        let slot = *self.open_file_slot(descriptor.open_file)?;
        let expected_object = slot.state.ok_or(Error::StaleOpenFile)?.object;
        let release = if slot.refs == 1 {
            released_object(expected_object)
        } else {
            None
        };
        Ok(ClosePlan {
            token,
            open_file: descriptor.open_file,
            expected_refs: slot.refs,
            expected_object,
            release,
        })
    }

    fn commit_close(&mut self, plan: ClosePlan) -> Result<(), Error> {
        let descriptor = self
            .descriptor_for_token(plan.token)
            .map_err(|_| Error::StaleOpenFile)?;
        if descriptor.open_file != plan.open_file {
            return Err(Error::StaleOpenFile);
        }
        let current = *self.open_file_slot(plan.open_file)?;
        if current.refs != plan.expected_refs
            || current.state.map(|state| state.object) != Some(plan.expected_object)
        {
            return Err(Error::StaleOpenFile);
        }
        let index = self.descriptor_slot_index(plan.token.fd())?;
        self.descriptors[index].state = None;
        let ofd = self.open_file_slot_mut(plan.open_file)?;
        ofd.refs -= 1;
        if ofd.refs == 0 {
            ofd.state = None;
        }
        Ok(())
    }

    fn prepare_duplicate_exact(
        &self,
        source_fd: i32,
        target_fd: i32,
        close_on_exec: bool,
    ) -> Result<ExactDuplicatePlan, Error> {
        if source_fd == target_fd {
            return Err(Error::SameDescriptor);
        }
        let source_token = self.token(source_fd)?;
        let source = *self.descriptor(source_fd)?;
        let source_slot = *self.open_file_slot(source.open_file)?;
        let target_index = self
            .descriptor_slot_index(target_fd)
            .map_err(|_| Error::InvalidTargetFd)?;
        let target_slot = self.descriptors[target_index];
        if target_slot.retired {
            return Err(Error::TableFull);
        }
        let target_next_generation = next_descriptor_generation(
            target_slot.generation,
            self.descriptor_generation_origin,
            self.descriptor_generation_stride,
        )
        .ok_or(Error::TableFull)?;
        let target_open_file = target_slot.state.map(|state| state.open_file);
        if target_open_file != Some(source.open_file) {
            source_slot
                .refs
                .checked_add(1)
                .ok_or(Error::ReferenceOverflow)?;
        }
        let (target_refs, target_object, release) = match target_open_file {
            Some(open_file) if open_file != source.open_file => {
                let slot = *self.open_file_slot(open_file)?;
                let object = slot.state.ok_or(Error::StaleOpenFile)?.object;
                (
                    Some(slot.refs),
                    Some(object),
                    if slot.refs == 1 {
                        released_object(object)
                    } else {
                        None
                    },
                )
            }
            _ => (None, None, None),
        };
        Ok(ExactDuplicatePlan {
            source_token,
            source_open_file: source.open_file,
            source_refs: source_slot.refs,
            target_fd,
            target_generation: target_slot.generation,
            target_next_generation,
            target_open_file,
            target_refs,
            target_object,
            close_on_exec,
            release,
        })
    }

    fn commit_duplicate_exact(&mut self, plan: ExactDuplicatePlan) -> Result<FdToken, Error> {
        let source = self
            .descriptor_for_token(plan.source_token)
            .map_err(|_| Error::StaleOpenFile)?;
        if source.open_file != plan.source_open_file {
            return Err(Error::StaleOpenFile);
        }
        let source_slot = *self.open_file_slot(plan.source_open_file)?;
        if source_slot.refs != plan.source_refs {
            return Err(Error::StaleOpenFile);
        }
        let target_index = self
            .descriptor_slot_index(plan.target_fd)
            .map_err(|_| Error::InvalidTargetFd)?;
        let target_slot = self.descriptors[target_index];
        if target_slot.retired
            || target_slot.generation != plan.target_generation
            || target_slot.state.map(|state| state.open_file) != plan.target_open_file
        {
            return Err(Error::StaleOpenFile);
        }
        if let (Some(open_file), Some(expected_refs), Some(expected_object)) =
            (plan.target_open_file, plan.target_refs, plan.target_object)
            && open_file != plan.source_open_file
        {
            let slot = *self.open_file_slot(open_file)?;
            if slot.refs != expected_refs
                || slot.state.map(|state| state.object) != Some(expected_object)
            {
                return Err(Error::StaleOpenFile);
            }
        }
        if plan.target_open_file != Some(plan.source_open_file) {
            self.open_file_slot_mut(plan.source_open_file)?.refs = plan.source_refs + 1;
        }
        if let (Some(target_open_file), Some(refs)) = (plan.target_open_file, plan.target_refs)
            && target_open_file != plan.source_open_file
        {
            let target = self.open_file_slot_mut(target_open_file)?;
            target.refs = refs - 1;
            if target.refs == 0 {
                target.state = None;
            }
        }
        self.descriptors[target_index].generation = plan.target_next_generation;
        self.descriptors[target_index].state = Some(DescriptorState {
            open_file: plan.source_open_file,
            close_on_exec: plan.close_on_exec,
        });
        Ok(FdToken {
            fd: plan.target_fd,
            generation: plan.target_next_generation,
        })
    }

    fn descriptor_pair_candidates(&self) -> Result<[(usize, i32, u64); 2], Error> {
        let mut found = [None, None];
        let mut count = 0usize;
        for (index, slot) in self.descriptors.iter().enumerate() {
            if slot.retired || slot.state.is_some() {
                continue;
            }
            let Some(generation) = next_descriptor_generation(
                slot.generation,
                self.descriptor_generation_origin,
                self.descriptor_generation_stride,
            ) else {
                continue;
            };
            let Ok(fd) = i32::try_from(index) else {
                continue;
            };
            found[count] = Some((index, fd, generation));
            count += 1;
            if count == 2 {
                break;
            }
        }
        match (found[0], found[1]) {
            (Some(a), Some(b)) => Ok([a, b]),
            _ => Err(Error::TableFull),
        }
    }

    fn open_file_pair_candidates(&self) -> Result<[(usize, u64); 2], Error> {
        let mut found = [None, None];
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
            if count == 2 {
                break;
            }
        }
        match (found[0], found[1]) {
            (Some(a), Some(b)) => Ok([a, b]),
            _ => Err(Error::TableFull),
        }
    }
}

fn release_if_needed<E, F>(object: Option<ReleasedObject>, release: F) -> Result<(), E>
where
    F: FnOnce(ReleasedObject) -> Result<(), E>,
{
    match object {
        Some(object) => release(object),
        None => Ok(()),
    }
}

pub(super) fn released_object(object: OpenObject) -> Option<ReleasedObject> {
    match object {
        OpenObject::Pipe(endpoint) => Some(ReleasedObject::Pipe(endpoint)),
        OpenObject::External(ExternalBacking::RetainedReadOnly(
            RetainedReadOnlyBacking::Directory(directory),
        )) => Some(ReleasedObject::RetainedDirectory(directory)),
        OpenObject::External(ExternalBacking::RetainedReadOnly(
            RetainedReadOnlyBacking::Regular(logical),
        )) => Some(ReleasedObject::RetainedReadOnly(logical)),
        OpenObject::External(ExternalBacking::WritableRegular(retained)) => {
            Some(ReleasedObject::WritableRegular(retained))
        }
        OpenObject::File(_)
        | OpenObject::Directory(_)
        | OpenObject::External(ExternalBacking::Stdio(_)) => None,
    }
}
