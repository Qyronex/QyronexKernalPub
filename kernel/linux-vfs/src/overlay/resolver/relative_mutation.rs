// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{OverlayError, OverlayNamespace, OverlayNodeHandle};
use crate::{
    AT_FDCWD, CanonicalPath, Error, LINUX_NAME_MAX, MAX_PATH_BYTES, MutableDirectoryHandle,
    MutableError, MutableNodeHandle, MutableNodeKind, MutableTimestamp, NodeKind,
    OverlayDirectoryHandle, RootedMutableError,
};

impl<
    'a,
    const NODES: usize,
    const DENTRIES: usize,
    const FILE_BYTES: usize,
    const TOMBSTONES: usize,
> OverlayNamespace<'a, NODES, DENTRIES, FILE_BYTES, TOMBSTONES>
{
    /// Creates one regular file relative to an already-open Overlay directory identity.
    /// Relative traversal never reconstructs the base directory's absolute pathname.
    pub fn create_regular_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.create_regular_at(path, mode, uid, gid, now);
        }
        let (parent_object, name) = self.relative_parent_object(base, path)?;
        self.require_relative_child_absent(parent_object, name)?;
        let (parent, visible_parent) = self.mutable_parent_for_relative_create(parent_object)?;
        let visible_child = optional_child_path(visible_parent, name)?;
        let node = self
            .upper
            .create_regular(parent, name, mode, uid, gid, now)?;
        if let Some(child) = visible_child {
            self.clear_tombstone(child);
        }
        Ok(node)
    }

    /// Creates one directory relative to a retained Overlay directory identity.
    pub fn mkdir_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.mkdir_at(path, mode, uid, gid, now);
        }
        let (parent_object, name) = self.relative_parent_object(base, path)?;
        self.require_relative_child_absent(parent_object, name)?;
        let (parent, visible_parent) = self.mutable_parent_for_relative_create(parent_object)?;
        let visible_child = optional_child_path(visible_parent, name)?;
        let node = self
            .upper
            .create_directory(parent, name, mode, uid, gid, now)?;
        if let Some(child) = visible_child {
            self.clear_tombstone(child);
        }
        Ok(node)
    }

    /// Removes one name relative to a retained Overlay directory identity. Upper removal follows the
    /// current parent identity; lower fallback suppression is keyed by stable lower provenance.
    pub fn unlink_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        remove_directory: bool,
    ) -> Result<(), OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.unlink_at(path, remove_directory);
        }

        let (parent_object, name) = self.relative_parent_object(base, path)?;
        let target = self.lookup_child_from_directory_object(parent_object, name)?;
        let kind = self.node_kind(target)?;
        if remove_directory {
            if kind != NodeKind::Directory {
                return Err(OverlayError::NotDirectory);
            }
            if matches!(target, OverlayNodeHandle::Immutable { .. }) {
                return Err(OverlayError::Mutable(RootedMutableError::Mutable(
                    MutableError::DirectoryNotEmpty,
                )));
            }
        } else if kind == NodeKind::Directory {
            return Err(OverlayError::IsDirectory);
        }

        let lower_child = self.lower_child_canonical(parent_object, name)?;
        if let Some(canonical) = lower_child {
            self.preflight_tombstone(canonical)?;
        }

        if let Some((parent, upper_node)) = self.upper_child_in_parent(parent_object, name)? {
            if self.logical_handle_for_upper(upper_node)? != target {
                return Err(OverlayError::Path(Error::HandleMismatch));
            }
            self.upper.unlink(parent, name, remove_directory)?;
        } else if matches!(target, OverlayNodeHandle::Mutable(_)) {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }

        if let Some(canonical) = lower_child {
            self.insert_tombstone(canonical)?;
        }
        Ok(())
    }

    /// Creates a hard link between two names rooted in retained Overlay directory identities.
    pub fn link_regular_from(
        &mut self,
        old_base: OverlayDirectoryHandle,
        old_path: &[u8],
        new_base: OverlayDirectoryHandle,
        new_path: &[u8],
    ) -> Result<(), OverlayError> {
        if old_path.first().copied() == Some(b'/') && new_path.first().copied() == Some(b'/') {
            return self.link_regular_at(old_path, new_path);
        }

        let source_parent = if old_path.first().copied() == Some(b'/') {
            None
        } else {
            Some(self.relative_parent_object(old_base, old_path)?)
        };
        let (source, source_canonical) = if old_path.first().copied() == Some(b'/') {
            let (source, canonical) = self.resolve_nofollow_at(old_path)?;
            (source, Some(canonical))
        } else {
            (self.resolve_nofollow_from(old_base, old_path)?, None)
        };
        match self.node_kind(source)? {
            NodeKind::Regular => {}
            NodeKind::Directory => return Err(OverlayError::IsDirectory),
            NodeKind::Symlink | NodeKind::Other(_) => return Err(OverlayError::NotRegular),
        }

        let (new_parent_object, new_name) = self.mutation_parent_object(new_base, new_path)?;
        self.require_relative_child_absent(new_parent_object, new_name)?;
        let source_entry = match source {
            OverlayNodeHandle::Immutable { entry_id, .. }
                if self.bound_upper_for_entry(entry_id).is_none() =>
            {
                Some(entry_id)
            }
            _ => None,
        };
        let destination_plan = self
            .parent_publication_path(new_parent_object)?
            .unwrap_or(CanonicalPath::root());
        self.preflight_compound_publication(source_entry, destination_plan, 1)?;

        let source_upper = match source_parent {
            Some((parent_object, name)) => {
                self.materialize_regular_child(parent_object, name, source)?
            }
            None => self.materialize_regular_object(source, source_canonical)?,
        };
        let destination_parent = self.materialize_parent_after_preflight(new_parent_object)?;
        self.upper
            .link(source_upper, destination_parent, new_name)?;
        if let Some(canonical) = self.lower_child_canonical(new_parent_object, new_name)? {
            self.clear_tombstone(canonical);
        }
        Ok(())
    }

    /// Renames one name between retained Overlay directory identities. The destination existence and
    /// type rules are decided before any copy-up/materialization, then one Upper rename commits the
    /// namespace move. Lower source fallback is suppressed only after that commit succeeds.
    pub fn rename_from(
        &mut self,
        old_base: OverlayDirectoryHandle,
        old_path: &[u8],
        new_base: OverlayDirectoryHandle,
        new_path: &[u8],
        no_replace: bool,
    ) -> Result<(), OverlayError> {
        if old_path.first().copied() == Some(b'/') && new_path.first().copied() == Some(b'/') {
            return self.rename_at(old_path, new_path, no_replace);
        }

        let (old_parent_object, old_name) = self.mutation_parent_object(old_base, old_path)?;
        let source = self.lookup_child_from_directory_object(old_parent_object, old_name)?;
        let source_kind = self.node_kind(source)?;

        let (new_parent_object, new_name) = self.mutation_parent_object(new_base, new_path)?;
        let target = match self.lookup_child_from_directory_object(new_parent_object, new_name) {
            Ok(handle) => Some(handle),
            Err(OverlayError::NotFound) => None,
            Err(error) => return Err(error),
        };
        if no_replace && target.is_some() {
            return Err(OverlayError::AlreadyExists);
        }
        if target.is_some_and(|target| target == source) {
            return Ok(());
        }

        // A pure lower directory remains outside the Step-29 rename policy. Once the exact lower
        // EntryId already owns an Upper directory binding, however, retained-relative rename must
        // re-enter that same mutable owner just like rename_at(). The logical handle deliberately
        // remains Immutable so stable lower identity survives the move.
        let source_entry = match source {
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Directory,
                ..
            } => {
                let Some(node) = self.bound_upper_for_entry(entry_id) else {
                    return Err(OverlayError::NotDirectory);
                };
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                None
            }
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Regular,
                ..
            } if self.bound_upper_for_entry(entry_id).is_none() => Some(entry_id),
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Regular,
                ..
            } => None,
            OverlayNodeHandle::Mutable(_) => None,
            OverlayNodeHandle::Immutable { .. } => return Err(OverlayError::NotRegular),
            OverlayNodeHandle::Root { .. } => return Err(OverlayError::NotDirectory),
        };

        if let Some(target) = target {
            match (source_kind, self.node_kind(target)?) {
                (NodeKind::Directory, NodeKind::Directory) => {
                    if matches!(target, OverlayNodeHandle::Immutable { .. }) {
                        return Err(OverlayError::Mutable(RootedMutableError::Mutable(
                            MutableError::DirectoryNotEmpty,
                        )));
                    }
                }
                (NodeKind::Directory, _) => return Err(OverlayError::NotDirectory),
                (_, NodeKind::Directory) => return Err(OverlayError::IsDirectory),
                _ => {}
            }
        }

        let source_lower = self.lower_child_canonical(old_parent_object, old_name)?;
        if let Some(canonical) = source_lower {
            self.preflight_tombstone(canonical)?;
        }
        let target_lower = self.lower_child_canonical(new_parent_object, new_name)?;
        let destination_plan = self
            .parent_publication_path(new_parent_object)?
            .unwrap_or(CanonicalPath::root());
        self.preflight_compound_publication(source_entry, destination_plan, 0)?;

        let source_upper = match source {
            OverlayNodeHandle::Mutable(node) => node,
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Directory,
                ..
            } => {
                let node = self
                    .bound_upper_for_entry(entry_id)
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                node
            }
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Regular,
                ..
            } => {
                if old_path.first().copied() == Some(b'/') {
                    self.materialize_regular_object(source, source_lower)?
                } else {
                    self.materialize_regular_child(old_parent_object, old_name, source)?
                }
            }
            _ => unreachable!(),
        };
        let old_parent = self.materialize_parent_after_preflight(old_parent_object)?;
        match self.upper.lookup(old_parent, old_name) {
            Ok(node) if node == source_upper => {}
            Ok(_) => return Err(OverlayError::Path(Error::HandleMismatch)),
            Err(error) => return Err(error.into()),
        }
        let new_parent = self.materialize_parent_after_preflight(new_parent_object)?;
        self.upper
            .rename(old_parent, old_name, new_parent, new_name, no_replace)?;

        if let Some(canonical) = source_lower {
            self.insert_tombstone(canonical)?;
        }
        if let Some(canonical) = target_lower {
            self.clear_tombstone(canonical);
        }
        Ok(())
    }

    /// Creates one symlink relative to a retained Overlay directory identity.
    pub fn symlink_from(
        &mut self,
        base: OverlayDirectoryHandle,
        target: &[u8],
        link_path: &[u8],
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, OverlayError> {
        if link_path.first().copied() == Some(b'/') {
            return self.symlink_at(target, link_path, uid, gid, now);
        }
        if target.len() > FILE_BYTES {
            return Err(OverlayError::Mutable(RootedMutableError::Mutable(
                MutableError::FileTooLarge,
            )));
        }
        let (parent_object, name) = self.relative_parent_object(base, link_path)?;
        self.require_relative_child_absent(parent_object, name)?;
        let (parent, visible_parent) = self.mutable_parent_for_relative_create(parent_object)?;
        let visible_child = optional_child_path(visible_parent, name)?;
        let node = self
            .upper
            .create_symlink(parent, name, target, uid, gid, now)?;
        if let Some(child) = visible_child {
            self.clear_tombstone(child);
        }
        Ok(node)
    }

    /// Reads a symlink target relative to a retained Overlay directory identity.
    pub fn readlink_from(
        &self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        output: &mut [u8],
    ) -> Result<usize, OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.readlink_at(path, output);
        }
        let handle = self.resolve_nofollow_from(base, path)?;
        if self.node_kind(handle)? != NodeKind::Symlink {
            return Err(OverlayError::NotRegular);
        }
        let mut target = [0u8; MAX_PATH_BYTES];
        let len = self.read_symlink_target(handle, &mut target)?;
        let copied = core::cmp::min(len, output.len());
        output[..copied].copy_from_slice(&target[..copied]);
        Ok(copied)
    }

    /// Changes mode relative to a retained Overlay directory identity.
    pub fn chmod_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        mode: u32,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.chmod_at(path, mode, now);
        }
        let node = self.mutable_regular_for_metadata_from(base, path)?;
        self.upper.chmod(node, mode, now).map_err(Into::into)
    }

    /// Changes ownership relative to a retained Overlay directory identity.
    pub fn chown_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        uid: Option<u32>,
        gid: Option<u32>,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.chown_at(path, uid, gid, now);
        }
        let node = self.mutable_regular_for_metadata_from(base, path)?;
        self.upper.chown(node, uid, gid, now).map_err(Into::into)
    }

    /// Changes timestamps relative to a retained Overlay directory identity.
    pub fn set_times_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        atime: MutableTimestamp,
        mtime: MutableTimestamp,
        ctime: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.set_times_at(path, atime, mtime, ctime);
        }
        let node = self.mutable_regular_for_metadata_from(base, path)?;
        self.upper
            .set_times(node, atime, mtime, ctime)
            .map_err(Into::into)
    }

    /// Truncates a regular file relative to retained directory authority. This never requires the
    /// base directory's current absolute presentation, so rename and PATH_MAX ancestry stay valid.
    pub fn truncate_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        length: u64,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.truncate_at(path, length, now);
        }
        let (_, backing) = self.materialize_regular_for_relative_owner(base, path)?;
        self.upper
            .truncate(backing, length, now)
            .map_err(Into::into)
    }

    /// Resolves and, when necessary, copy-ups one regular through the live retained parent identity.
    /// The returned logical object remains the stable union identity while `backing` is the exact
    /// mutable object suitable for a retained writable OFD handoff.
    pub(crate) fn materialize_regular_for_relative_owner(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
    ) -> Result<(OverlayNodeHandle, MutableNodeHandle), OverlayError> {
        let logical = self.resolve_following_from(base, path)?;
        let (parent_object, name) = self.relative_parent_object(base, path)?;
        let backing = match self.lookup_child_from_directory_object(parent_object, name) {
            Ok(direct) if direct == logical => {
                self.materialize_regular_child(parent_object, name, logical)?
            }
            Ok(_) | Err(OverlayError::NotFound) => {
                self.materialize_regular_object(logical, None)?
            }
            Err(error) => return Err(error),
        };
        Ok((logical, backing))
    }

    fn mutable_regular_for_metadata_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
    ) -> Result<MutableNodeHandle, OverlayError> {
        self.materialize_regular_for_relative_owner(base, path)
            .map(|(_, backing)| backing)
    }

    fn require_relative_child_absent(
        &self,
        parent: OverlayNodeHandle,
        name: &[u8],
    ) -> Result<(), OverlayError> {
        match self.lookup_child_from_directory_object(parent, name) {
            Ok(_) => Err(OverlayError::AlreadyExists),
            Err(OverlayError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn relative_parent_object<'p>(
        &self,
        base: OverlayDirectoryHandle,
        path: &'p [u8],
    ) -> Result<(OverlayNodeHandle, &'p [u8]), OverlayError> {
        self.validate_handle_root(base.object())?;
        self.validate_directory_object(base.object())?;
        let (raw_parent, name) = split_mutation_parent(path)?;
        let parent = if raw_parent.is_empty() {
            base.object()
        } else {
            self.resolve_following_from(base, raw_parent)?
        };
        self.validate_directory_object(parent)?;
        Ok((parent, name))
    }

    fn mutation_parent_object<'p>(
        &self,
        base: OverlayDirectoryHandle,
        path: &'p [u8],
    ) -> Result<(OverlayNodeHandle, &'p [u8]), OverlayError> {
        if path.first().copied() != Some(b'/') {
            return self.relative_parent_object(base, path);
        }
        let (raw_parent, name) = split_mutation_parent(path)?;
        let parent = if raw_parent.iter().all(|byte| *byte == b'/') {
            self.root_object()?
        } else {
            self.resolve_following_at(raw_parent)?.0
        };
        self.validate_directory_object(parent)?;
        Ok((parent, name))
    }

    fn mutable_parent_for_relative_create(
        &mut self,
        object: OverlayNodeHandle,
    ) -> Result<(MutableDirectoryHandle, Option<CanonicalPath>), OverlayError> {
        self.validate_directory_object(object)?;
        if let Some(directory) = self.mutable_directory_for_object(object)? {
            let visible = match self.upper.directory_canonical_path(directory) {
                Ok(path) => Some(path),
                Err(RootedMutableError::Path(Error::PathTooLong)) => None,
                Err(error) => return Err(error.into()),
            };
            return Ok((directory, visible));
        }

        let canonical = self
            .parent_publication_path(object)?
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        self.preflight_parent_final_publication(canonical)?;
        let directory = self.ensure_upper_directory(canonical)?;
        Ok((directory, Some(canonical)))
    }

    fn parent_publication_path(
        &self,
        object: OverlayNodeHandle,
    ) -> Result<Option<CanonicalPath>, OverlayError> {
        self.validate_directory_object(object)?;
        if self.mutable_directory_for_object(object)?.is_some() {
            return Ok(None);
        }
        match object {
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Directory,
                ..
            } => Ok(Some(self.lower_entry_canonical(entry_id)?)),
            OverlayNodeHandle::Root { .. } | OverlayNodeHandle::Mutable(_) => {
                Err(OverlayError::Path(Error::HandleMismatch))
            }
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotDirectory),
        }
    }

    fn materialize_parent_after_preflight(
        &mut self,
        object: OverlayNodeHandle,
    ) -> Result<MutableDirectoryHandle, OverlayError> {
        if let Some(directory) = self.mutable_directory_for_object(object)? {
            return Ok(directory);
        }
        let canonical = self
            .parent_publication_path(object)?
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        self.ensure_upper_directory(canonical)
    }

    fn materialize_regular_object(
        &mut self,
        object: OverlayNodeHandle,
        canonical_hint: Option<CanonicalPath>,
    ) -> Result<MutableNodeHandle, OverlayError> {
        match object {
            OverlayNodeHandle::Mutable(node) => match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => Ok(node),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            },
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Regular,
                ..
            } => {
                if let Some(node) = self.bound_upper_for_entry(entry_id) {
                    return match self.upper.metadata(node)?.kind() {
                        MutableNodeKind::Regular => Ok(node),
                        MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                        MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
                    };
                }
                let canonical = match canonical_hint {
                    Some(canonical) => canonical,
                    None => self.lower_entry_canonical(entry_id)?,
                };
                self.copy_up_regular_canonical(canonical)
            }
            OverlayNodeHandle::Root { .. }
            | OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotRegular),
        }
    }

    /// Materializes one lower regular child into the live parent directory identity. This path is
    /// used only for relative owner operations so a renamed retained lower parent can never fall
    /// back to the child's historical CPIO pathname as its publication address.
    fn materialize_regular_child(
        &mut self,
        parent_object: OverlayNodeHandle,
        name: &[u8],
        object: OverlayNodeHandle,
    ) -> Result<MutableNodeHandle, OverlayError> {
        self.validate_directory_object(parent_object)?;
        if self.lookup_child_from_directory_object(parent_object, name)? != object {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }
        match object {
            OverlayNodeHandle::Mutable(node) => match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => Ok(node),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            },
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Regular,
                file,
                ..
            } => {
                if self.logical_handle_for_entry(entry_id)? != object {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                if let Some(node) = self.bound_upper_for_entry(entry_id) {
                    return match self.upper.metadata(node)?.kind() {
                        MutableNodeKind::Regular => Ok(node),
                        MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                        MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
                    };
                }
                let file = file.ok_or(OverlayError::NotRegular)?;
                if file.root_id() != self.root_id() || file.entry_id() != entry_id {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                let capacity = u64::try_from(FILE_BYTES).unwrap_or(u64::MAX);
                if file.size() > capacity {
                    return Err(OverlayError::FileTooLarge);
                }
                let entry = self
                    .lower
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                if entry.nlink() != 1 {
                    return Err(OverlayError::Path(Error::UnsupportedNode));
                }
                if entry.mode() != file.mode()
                    || u64::try_from(entry.data().len()).ok() != Some(file.size())
                {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                let source_time = MutableTimestamp {
                    seconds: i64::from(entry.mtime()),
                    nanoseconds: 0,
                };
                let bytes = self.lower.read_at(file, 0, FILE_BYTES)?;
                self.preflight_lower_binding(entry_id)?;
                let parent = self.materialize_parent_after_preflight(parent_object)?;
                match self.upper.lookup(parent, name) {
                    Err(RootedMutableError::Mutable(MutableError::NotFound)) => {}
                    Ok(_) => return Err(OverlayError::Path(Error::HandleMismatch)),
                    Err(error) => return Err(error.into()),
                }
                let node = self.upper.create_regular(
                    parent,
                    name,
                    file.mode(),
                    entry.uid(),
                    entry.gid(),
                    source_time,
                )?;
                if let Err(error) = self.upper.write(node, 0, bytes, source_time) {
                    let _ = self.upper.unlink(parent, name, false);
                    return Err(error.into());
                }
                if let Err(error) = self.attach_lower_binding(entry_id, node) {
                    let _ = self.upper.unlink(parent, name, false);
                    return Err(error);
                }
                Ok(node)
            }
            OverlayNodeHandle::Root { .. }
            | OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotRegular),
        }
    }

    fn lower_entry_canonical(
        &self,
        entry_id: crate::EntryId,
    ) -> Result<CanonicalPath, OverlayError> {
        let entry = self
            .lower
            .archive
            .entry_by_id(entry_id)
            .map_err(Error::from)?
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        CanonicalPath::resolve_at(AT_FDCWD, entry.path()).map_err(Into::into)
    }

    fn upper_child_in_parent(
        &self,
        parent_object: OverlayNodeHandle,
        name: &[u8],
    ) -> Result<Option<(MutableDirectoryHandle, MutableNodeHandle)>, OverlayError> {
        let Some(parent) = self.mutable_directory_for_object(parent_object)? else {
            return Ok(None);
        };
        match self.upper.lookup(parent, name) {
            Ok(node) => Ok(Some((parent, node))),
            Err(RootedMutableError::Mutable(MutableError::NotFound)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn lower_child_canonical(
        &self,
        parent_object: OverlayNodeHandle,
        name: &[u8],
    ) -> Result<Option<CanonicalPath>, OverlayError> {
        let parent = match parent_object {
            OverlayNodeHandle::Root { .. } => Some(CanonicalPath::root()),
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Directory,
                ..
            } => Some(self.lower_entry_canonical(entry_id)?),
            OverlayNodeHandle::Immutable { .. } => return Err(OverlayError::NotDirectory),
            OverlayNodeHandle::Mutable(_) => None,
        };
        let Some(parent) = parent else {
            return Ok(None);
        };
        let child = CanonicalPath::resolve_from(parent, name)?;
        Ok(self.lower_kind(child)?.map(|_| child))
    }
}

fn optional_child_path(
    parent: Option<CanonicalPath>,
    name: &[u8],
) -> Result<Option<CanonicalPath>, OverlayError> {
    match parent {
        Some(parent) => match CanonicalPath::resolve_from(parent, name) {
            Ok(child) => Ok(Some(child)),
            Err(Error::PathTooLong) => Ok(None),
            Err(error) => Err(error.into()),
        },
        None => Ok(None),
    }
}

fn split_mutation_parent(path: &[u8]) -> Result<(&[u8], &[u8]), OverlayError> {
    if path.is_empty() {
        return Err(OverlayError::Path(Error::EmptyPath));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(OverlayError::Path(Error::PathTooLong));
    }
    if path.contains(&0) {
        return Err(OverlayError::Path(Error::EmbeddedNul));
    }

    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
        return Err(OverlayError::AlreadyExists);
    }
    let trimmed = &path[..end];
    let start = trimmed
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(0, |index| index + 1);
    let name = &trimmed[start..];
    if name.is_empty() || name.len() > LINUX_NAME_MAX || name == b"." || name == b".." {
        return Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::InvalidName,
        )));
    }
    Ok((&trimmed[..start], name))
}
