// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{
    AT_FDCWD, CanonicalPath, EntryId, Error, InitramfsRoot, LINUX_NAME_MAX, MAX_PATH_BYTES,
    MutableDirectoryHandle, MutableError, MutableNodeHandle, MutableNodeKind, MutableTimestamp,
    Node, NodeKind, ReadOnlyFile, RootId, RootedMutableError, RootedMutableNamespace,
};

mod identity;
pub use identity::{OverlayMetadata, RetainedRegularHandle};
mod resolver;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlayError {
    Path(Error),
    Mutable(RootedMutableError),
    NotFound,
    AlreadyExists,
    NotRegular,
    NotDirectory,
    IsDirectory,
    TombstoneTableFull,
    BindingTableFull,
    FileTooLarge,
}

impl From<Error> for OverlayError {
    fn from(value: Error) -> Self {
        Self::Path(value)
    }
}

impl From<RootedMutableError> for OverlayError {
    fn from(value: RootedMutableError) -> Self {
        Self::Mutable(value)
    }
}

/// Compact union object identity. The resolver returns the canonical pathname separately, so an
/// immutable handle only needs the stable CPIO [`EntryId`] plus its already-validated object facts.
/// This keeps persistent identities bounded without embedding a Linux PATH_MAX buffer in every
/// handle. Root/immutable identities also carry the opaque private Upper-root witness so two
/// OverlayNamespace instances that share one RootId/archive cannot exchange authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlayNodeHandle {
    Root {
        root: RootId,
        owner: MutableDirectoryHandle,
    },
    Immutable {
        root: RootId,
        owner: MutableDirectoryHandle,
        entry_id: EntryId,
        kind: NodeKind,
        file: Option<ReadOnlyFile>,
    },
    Mutable(MutableNodeHandle),
}

impl OverlayNodeHandle {
    pub const fn root_id(self) -> RootId {
        match self {
            Self::Root { root, .. } | Self::Immutable { root, .. } => root,
            Self::Mutable(node) => node.root_id(),
        }
    }
}

/// Bounded union of the accepted immutable CPIO root and one generation-safe mutable upper.
///
/// Upper objects shadow lower objects. Tombstones suppress lower fallback after removal. A lower
/// regular file is copied into the upper before a state-changing write/truncate; protected CPIO
/// bytes are never modified. The bounded lower-binding table preserves stable EntryId identity when
/// mutable backing is attached later by copy-up or lower-directory materialization.
pub struct OverlayNamespace<
    'a,
    const NODES: usize,
    const DENTRIES: usize,
    const FILE_BYTES: usize,
    const TOMBSTONES: usize,
> {
    lower: InitramfsRoot<'a>,
    upper: RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
    tombstones: [Option<CanonicalPath>; TOMBSTONES],
    lower_bindings: [Option<identity::LowerBinding>; NODES],
}

impl<
    'a,
    const NODES: usize,
    const DENTRIES: usize,
    const FILE_BYTES: usize,
    const TOMBSTONES: usize,
> OverlayNamespace<'a, NODES, DENTRIES, FILE_BYTES, TOMBSTONES>
{
    pub const fn new(lower: InitramfsRoot<'a>) -> Self {
        Self {
            upper: RootedMutableNamespace::new(lower.root_id()),
            lower,
            tombstones: [None; TOMBSTONES],
            lower_bindings: [None; NODES],
        }
    }

    pub const fn root_id(&self) -> RootId {
        self.lower.root_id()
    }

    pub const fn lower(&self) -> InitramfsRoot<'a> {
        self.lower
    }

    pub const fn upper(&self) -> &RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES> {
        &self.upper
    }

    pub(crate) fn upper_mut(&mut self) -> &mut RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES> {
        &mut self.upper
    }

    pub fn lookup_at(&self, path: &[u8]) -> Result<Option<OverlayNodeHandle>, OverlayError> {
        match self.resolve_following_at(path) {
            Ok((handle, _)) => Ok(Some(handle)),
            Err(OverlayError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn lookup_canonical(
        &self,
        canonical: CanonicalPath,
    ) -> Result<Option<OverlayNodeHandle>, OverlayError> {
        if canonical.is_root() {
            return Ok(Some(OverlayNodeHandle::Root {
                root: self.root_id(),
                owner: self.upper.root_directory(),
            }));
        }
        if self.is_tombstoned(canonical) {
            return Ok(None);
        }
        if let Some(node) = self.mutable_node_at(canonical)? {
            return self.logical_handle_for_upper(node).map(Some);
        }

        let entry = self
            .lower
            .archive
            .get_with_id(canonical.as_archive_bytes())
            .map_err(Error::from)?;
        let Some((entry_id, _entry)) = entry else {
            return Ok(None);
        };
        self.logical_handle_for_entry(entry_id).map(Some)
    }

    pub fn create_regular_at(
        &mut self,
        path: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, OverlayError> {
        // Validate the raw final component before resolving/materializing a lower-only parent. This
        // keeps NAME_MAX and malformed-name failures read-only and matches the other mutation paths.
        let (raw_parent, name) = split_raw_create_parent(path)?;
        let parent_path = if raw_parent.is_empty() || raw_parent.iter().all(|byte| *byte == b'/') {
            CanonicalPath::root()
        } else {
            let (parent_handle, canonical) = self.resolve_following_at(raw_parent)?;
            if self.node_kind(parent_handle)? != NodeKind::Directory {
                return Err(OverlayError::NotDirectory);
            }
            canonical
        };
        let canonical = CanonicalPath::resolve_from(parent_path, name)?;
        if self.lookup_canonical(canonical)?.is_some() {
            return Err(OverlayError::AlreadyExists);
        }

        // Reserve parent materialization plus the final inode/dentry as one additive transaction;
        // only after all read-only validation succeeds may the lower parent become visible in Upper.
        self.preflight_parent_final_publication(parent_path)?;
        let parent = self.ensure_upper_directory(parent_path)?;
        let node = self
            .upper
            .create_regular(parent, name, mode, uid, gid, now)?;
        self.clear_tombstone(canonical);
        Ok(node)
    }

    /// Materializes one lower regular file into the mutable upper without applying a new mutation
    /// timestamp. The copied inode is initialized exclusively from validated CPIO provenance; callers
    /// that subsequently mutate it commit their own ctime/mtime at that later operation boundary.
    pub fn copy_up_regular_at(&mut self, path: &[u8]) -> Result<MutableNodeHandle, OverlayError> {
        let (_, canonical) = self.resolve_following_at(path)?;
        self.copy_up_regular_canonical(canonical)
    }

    pub fn write_at(
        &mut self,
        path: &[u8],
        offset: u64,
        input: &[u8],
        now: MutableTimestamp,
    ) -> Result<usize, OverlayError> {
        let (_, canonical) = self.resolve_following_at(path)?;
        if input.is_empty() {
            self.validate_regular_without_copyup(canonical, offset)?;
            return Ok(0);
        }
        let node = self.copy_up_regular_canonical(canonical)?;
        self.upper
            .write(node, offset, input, now)
            .map_err(Into::into)
    }

    pub fn truncate_at(
        &mut self,
        path: &[u8],
        length: u64,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let (_, canonical) = self.resolve_following_at(path)?;
        let node = self.copy_up_regular_canonical(canonical)?;
        self.upper.truncate(node, length, now).map_err(Into::into)
    }

    /// Removes one non-directory name from the union. The final path component is deliberately not
    /// followed: unlinking a symlink removes the link itself, while lower-backed names receive a
    /// tombstone so later lookup cannot fall through and resurrect them.
    pub fn unlink_regular_at(&mut self, path: &[u8]) -> Result<(), OverlayError> {
        let (handle, canonical) = self.resolve_nofollow_at(path)?;
        if canonical.is_root() || matches!(handle, OverlayNodeHandle::Root { .. }) {
            return Err(OverlayError::IsDirectory);
        }

        let upper_node = match handle {
            OverlayNodeHandle::Mutable(node) => {
                if self.upper.metadata(node)?.kind() == MutableNodeKind::Directory {
                    return Err(OverlayError::IsDirectory);
                }
                Some(node)
            }
            OverlayNodeHandle::Immutable { entry_id, kind, .. } => {
                if kind == NodeKind::Directory {
                    return Err(OverlayError::IsDirectory);
                }
                self.bound_upper_for_entry(entry_id)
            }
            OverlayNodeHandle::Root { .. } => return Err(OverlayError::IsDirectory),
        };
        let lower_kind = self.lower_kind(canonical)?;
        if matches!(lower_kind, Some(NodeKind::Directory)) {
            return Err(OverlayError::IsDirectory);
        }
        if lower_kind.is_some() {
            self.preflight_tombstone(canonical)?;
        }
        if upper_node.is_some() {
            let (parent_path, name_start) = split_parent(canonical)?;
            let parent = self.upper_directory_existing(parent_path)?;
            let name = &canonical.as_relative_bytes()[name_start..];
            self.upper.unlink(parent, name, false)?;
        }
        if lower_kind.is_some() {
            self.insert_tombstone(canonical)?;
        }
        Ok(())
    }

    pub fn read_regular(
        &self,
        handle: OverlayNodeHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, OverlayError> {
        self.validate_handle_root(handle)?;
        match handle {
            OverlayNodeHandle::Root { .. } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Mutable(node) => {
                let metadata = self.upper.metadata(node)?;
                match metadata.kind() {
                    MutableNodeKind::Regular => {
                        self.upper.read(node, offset, output).map_err(Into::into)
                    }
                    MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                    MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
                }
            }
            OverlayNodeHandle::Immutable {
                entry_id,
                kind,
                file,
                ..
            } => {
                if kind == NodeKind::Directory {
                    return Err(OverlayError::IsDirectory);
                }
                if kind != NodeKind::Regular {
                    return Err(OverlayError::NotRegular);
                }
                if self.logical_handle_for_entry(entry_id)? != handle {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                if let Some(upper) = self.bound_upper_for_entry(entry_id) {
                    return match self.upper.metadata(upper)?.kind() {
                        MutableNodeKind::Regular => {
                            self.upper.read(upper, offset, output).map_err(Into::into)
                        }
                        MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                        MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
                    };
                }
                self.validate_lower_fallback(entry_id)?;
                let file = file.ok_or(OverlayError::NotRegular)?;
                let bytes = self.lower.read_at(file, offset, output.len())?;
                output[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
        }
    }

    /// Retains one regular-file object for a future descriptor/OFD owner. Lower-backed opens are
    /// recorded against EntryId so a later copy-up can attach mutable backing without changing the
    /// descriptor's logical identity.
    pub fn retain_open(&mut self, handle: OverlayNodeHandle) -> Result<(), OverlayError> {
        self.validate_handle_root(handle)?;
        match handle {
            OverlayNodeHandle::Root { .. } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable {
                entry_id,
                kind,
                file,
                ..
            } => match kind {
                NodeKind::Regular if file.is_some() => {
                    if self.logical_handle_for_entry(entry_id)? != handle {
                        return Err(OverlayError::Path(Error::HandleMismatch));
                    }
                    if self.bound_upper_for_entry(entry_id).is_none() {
                        self.validate_lower_fallback(entry_id)?;
                    }
                    self.retain_lower_binding(entry_id)
                }
                NodeKind::Directory => Err(OverlayError::IsDirectory),
                NodeKind::Regular | NodeKind::Symlink | NodeKind::Other(_) => {
                    Err(OverlayError::NotRegular)
                }
            },
            OverlayNodeHandle::Mutable(node) => match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => self.upper.retain_open(node).map_err(Into::into),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            },
        }
    }

    /// Releases one regular-file object previously retained for a descriptor/OFD.
    pub fn release_open(&mut self, handle: OverlayNodeHandle) -> Result<(), OverlayError> {
        self.validate_handle_root(handle)?;
        match handle {
            OverlayNodeHandle::Root { .. } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable {
                entry_id,
                kind,
                file,
                ..
            } => match kind {
                NodeKind::Regular if file.is_some() => {
                    if self.logical_handle_for_entry(entry_id)? != handle {
                        return Err(OverlayError::Path(Error::HandleMismatch));
                    }
                    self.release_lower_binding(entry_id)
                }
                NodeKind::Directory => Err(OverlayError::IsDirectory),
                NodeKind::Regular | NodeKind::Symlink | NodeKind::Other(_) => {
                    Err(OverlayError::NotRegular)
                }
            },
            OverlayNodeHandle::Mutable(node) => match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => self.upper.release_open(node).map_err(Into::into),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            },
        }
    }

    pub(super) fn validate_handle_root(
        &self,
        handle: OverlayNodeHandle,
    ) -> Result<(), OverlayError> {
        if handle.root_id() != self.root_id() {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }
        match handle {
            OverlayNodeHandle::Root { owner, .. } | OverlayNodeHandle::Immutable { owner, .. } => {
                self.upper.refresh_directory(owner)?;
            }
            OverlayNodeHandle::Mutable(_) => {}
        }
        Ok(())
    }

    fn validate_regular_without_copyup(
        &self,
        canonical: CanonicalPath,
        offset: u64,
    ) -> Result<(), OverlayError> {
        let start = usize::try_from(offset).map_err(|_| {
            OverlayError::Mutable(RootedMutableError::Mutable(MutableError::InvalidOffset))
        })?;
        if start > FILE_BYTES {
            return Err(OverlayError::Mutable(RootedMutableError::Mutable(
                MutableError::FileTooLarge,
            )));
        }

        let handle = self
            .lookup_canonical(canonical)?
            .ok_or(OverlayError::NotFound)?;
        match handle {
            OverlayNodeHandle::Root { .. } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable { kind, .. } => match kind {
                NodeKind::Regular => Ok(()),
                NodeKind::Directory => Err(OverlayError::IsDirectory),
                NodeKind::Symlink | NodeKind::Other(_) => Err(OverlayError::NotRegular),
            },
            OverlayNodeHandle::Mutable(node) => match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => Ok(()),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            },
        }
    }

    fn copy_up_regular_canonical(
        &mut self,
        canonical: CanonicalPath,
    ) -> Result<MutableNodeHandle, OverlayError> {
        if canonical.is_root() {
            return Err(OverlayError::IsDirectory);
        }
        if self.is_tombstoned(canonical) {
            return Err(OverlayError::NotFound);
        }
        if let Some(node) = self.mutable_node_at(canonical)? {
            return match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => Ok(node),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            };
        }

        // Public mutation entry points resolve through the union first. This lower resolver remains
        // a defensive fallback for direct canonical callers and still prevents copying a symlink
        // object over its target name.
        let (_, nofollow_node, nofollow_path) = match self
            .lower
            .resolve_nofollow_at(AT_FDCWD, canonical.as_relative_bytes())
        {
            Ok(value) => value,
            Err(Error::NotFound) => return Err(OverlayError::NotFound),
            Err(error) => return Err(error.into()),
        };
        let target_path = if nofollow_node.kind() == NodeKind::Symlink {
            let (_, target, resolved) = self
                .lower
                .resolve_following_at(AT_FDCWD, canonical.as_relative_bytes())?;
            if target.kind() == NodeKind::Directory {
                return Err(OverlayError::IsDirectory);
            }
            if target.kind() != NodeKind::Regular {
                return Err(OverlayError::NotRegular);
            }
            resolved
        } else {
            if nofollow_node.kind() == NodeKind::Directory {
                return Err(OverlayError::IsDirectory);
            }
            if nofollow_node.kind() != NodeKind::Regular {
                return Err(OverlayError::NotRegular);
            }
            nofollow_path
        };
        if target_path != canonical {
            return self.copy_up_regular_canonical(target_path);
        }

        let file = self
            .lower
            .open_readonly_at(AT_FDCWD, target_path.as_relative_bytes())?;
        if let Some(upper) = self.bound_upper_for_entry(file.entry_id()) {
            return match self.upper.metadata(upper)?.kind() {
                MutableNodeKind::Regular => Ok(upper),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            };
        }
        let capacity = u64::try_from(FILE_BYTES).unwrap_or(u64::MAX);
        if file.size() > capacity {
            return Err(OverlayError::FileTooLarge);
        }

        // Resolve the exact immutable metadata through the same stable EntryId that authenticated
        // this lower file. newc carries uid/gid/mtime but no independent atime/ctime, so the mutable
        // copy initializes all three timestamps from c_mtime rather than inventing another clock.
        let entry = self
            .lower
            .archive
            .entry_by_id(file.entry_id())
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

        // Read every immutable source byte and preflight logical binding capacity before publishing
        // a mutable object. This keeps provenance/binding failure fail-closed.
        let bytes = self.lower.read_at(file, 0, FILE_BYTES)?;
        self.preflight_lower_binding(file.entry_id())?;
        let (parent_path, name_start) = split_parent(target_path)?;
        let parent = self.ensure_upper_directory(parent_path)?;
        let name = &target_path.as_relative_bytes()[name_start..];
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
        if let Err(error) = self.attach_lower_binding(file.entry_id(), node) {
            let _ = self.upper.unlink(parent, name, false);
            return Err(error);
        }
        Ok(node)
    }

    fn ensure_upper_directory(
        &mut self,
        canonical: CanonicalPath,
    ) -> Result<MutableDirectoryHandle, OverlayError> {
        let mut current = self.upper.root_directory();
        if canonical.is_root() {
            return Ok(current);
        }
        let mut prefix = CanonicalPath::root();
        for component in canonical.as_relative_bytes().split(|byte| *byte == b'/') {
            let next_prefix = CanonicalPath::resolve_from(prefix, component)?;
            match self.upper.open_directory(current, component) {
                Ok(directory) => current = directory,
                Err(RootedMutableError::Mutable(MutableError::NotFound)) => {
                    if self.is_tombstoned(next_prefix) {
                        return Err(OverlayError::NotFound);
                    }
                    let (entry_id, entry) = self
                        .lower
                        .archive
                        .get_with_id(next_prefix.as_archive_bytes())
                        .map_err(Error::from)?
                        .ok_or(OverlayError::NotFound)?;
                    let lower = Node::from_entry(entry);
                    if lower.kind() != NodeKind::Directory {
                        return Err(OverlayError::NotDirectory);
                    }
                    if let Some(bound) = self.bound_upper_for_entry(entry_id) {
                        current = self.upper.directory_handle_from_node(bound)?;
                        prefix = next_prefix;
                        continue;
                    }
                    let source_time = MutableTimestamp {
                        seconds: i64::from(entry.mtime()),
                        nanoseconds: 0,
                    };
                    self.preflight_lower_binding(entry_id)?;
                    let node = self.upper.create_directory(
                        current,
                        component,
                        lower.mode(),
                        entry.uid(),
                        entry.gid(),
                        source_time,
                    )?;
                    if let Err(error) = self.attach_lower_binding(entry_id, node) {
                        let _ = self.upper.unlink(current, component, true);
                        return Err(error);
                    }
                    current = self.upper.directory_handle_from_node(node)?;
                }
                Err(error) => return Err(error.into()),
            }
            prefix = next_prefix;
        }
        Ok(current)
    }

    fn upper_directory_existing(
        &self,
        canonical: CanonicalPath,
    ) -> Result<MutableDirectoryHandle, OverlayError> {
        let mut current = self.upper.root_directory();
        if canonical.is_root() {
            return Ok(current);
        }
        for component in canonical.as_relative_bytes().split(|byte| *byte == b'/') {
            current = match self.upper.open_directory(current, component) {
                Ok(directory) => directory,
                Err(RootedMutableError::Mutable(MutableError::NotFound)) => {
                    return Err(OverlayError::NotFound);
                }
                Err(error) => return Err(error.into()),
            };
        }
        Ok(current)
    }

    fn mutable_node_at(
        &self,
        canonical: CanonicalPath,
    ) -> Result<Option<MutableNodeHandle>, OverlayError> {
        if canonical.is_root() {
            return Ok(None);
        }
        let mut components = canonical
            .as_relative_bytes()
            .split(|byte| *byte == b'/')
            .peekable();
        let mut parent = self.upper.root_directory();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                return match self.upper.lookup(parent, component) {
                    Ok(node) => Ok(Some(node)),
                    Err(RootedMutableError::Mutable(MutableError::NotFound)) => Ok(None),
                    Err(error) => Err(error.into()),
                };
            }
            parent = match self.upper.open_directory(parent, component) {
                Ok(directory) => directory,
                Err(RootedMutableError::Mutable(MutableError::NotFound)) => return Ok(None),
                Err(error) => return Err(error.into()),
            };
        }
        Ok(None)
    }

    fn lower_kind(&self, canonical: CanonicalPath) -> Result<Option<NodeKind>, OverlayError> {
        if canonical.is_root() {
            return Ok(Some(NodeKind::Directory));
        }
        let entry = self
            .lower
            .archive
            .get(canonical.as_archive_bytes())
            .map_err(Error::from)?;
        Ok(entry.map(|entry| Node::from_entry(entry).kind()))
    }

    fn is_tombstoned(&self, canonical: CanonicalPath) -> bool {
        self.tombstones
            .iter()
            .flatten()
            .any(|path| *path == canonical)
    }

    fn preflight_tombstone(&self, canonical: CanonicalPath) -> Result<(), OverlayError> {
        if self.is_tombstoned(canonical) || self.tombstones.iter().any(Option::is_none) {
            Ok(())
        } else {
            Err(OverlayError::TombstoneTableFull)
        }
    }

    fn insert_tombstone(&mut self, canonical: CanonicalPath) -> Result<(), OverlayError> {
        if self.is_tombstoned(canonical) {
            return Ok(());
        }
        let slot = self
            .tombstones
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(OverlayError::TombstoneTableFull)?;
        *slot = Some(canonical);
        Ok(())
    }

    fn clear_tombstone(&mut self, canonical: CanonicalPath) {
        if let Some(slot) = self
            .tombstones
            .iter_mut()
            .find(|slot| **slot == Some(canonical))
        {
            *slot = None;
        }
    }
}

fn split_raw_create_parent(path: &[u8]) -> Result<(&[u8], &[u8]), OverlayError> {
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

fn split_parent(canonical: CanonicalPath) -> Result<(CanonicalPath, usize), OverlayError> {
    let path = canonical.as_relative_bytes();
    if path.is_empty() {
        return Err(OverlayError::AlreadyExists);
    }
    if let Some(separator) = path.iter().rposition(|byte| *byte == b'/') {
        let parent = CanonicalPath::resolve_at(AT_FDCWD, &path[..separator])?;
        Ok((parent, separator + 1))
    } else {
        Ok((CanonicalPath::root(), 0))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use kernal_cpio::Archive;

    const HEADER_LEN: usize = 110;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const ROOT: RootId = RootId::new(71);
    const T1: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 0,
    };
    const T2: MutableTimestamp = MutableTimestamp {
        seconds: 2,
        nanoseconds: 0,
    };

    type Overlay<'a> = OverlayNamespace<'a, 16, 24, 64, 8>;

    fn hex(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
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

    fn archive_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        entry(&mut out, b".", S_IFDIR | 0o755, b"");
        entry(&mut out, b"etc", S_IFDIR | 0o755, b"");
        entry(&mut out, b"etc/base", S_IFREG | 0o644, b"base");
        entry(&mut out, b"etc/keep", S_IFREG | 0o644, b"keep");
        entry(&mut out, b"target", S_IFREG | 0o644, b"target");
        entry(&mut out, b"alias", S_IFLNK | 0o777, b"target");
        entry(&mut out, b"TRAILER!!!", 0, b"");
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        out
    }

    fn overlay(bytes: &[u8]) -> Overlay<'_> {
        Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
    }

    #[test]
    fn upper_lookup_precedes_lower_and_copy_up_preserves_cpio_bytes() {
        let bytes = archive_bytes();
        let lower_before = bytes.clone();
        let mut overlay = overlay(&bytes);
        let lower_handle = overlay.lookup_at(b"/etc/base").unwrap().unwrap();
        let mut read = [0u8; 8];
        assert_eq!(overlay.read_regular(lower_handle, 0, &mut read), Ok(4));
        assert_eq!(&read[..4], b"base");

        assert_eq!(overlay.write_at(b"/etc/base", 0, b"UP", T2), Ok(2));
        let upper_handle = overlay.lookup_at(b"/etc/base").unwrap().unwrap();
        assert_eq!(upper_handle, lower_handle);
        assert!(matches!(upper_handle, OverlayNodeHandle::Immutable { .. }));
        let mut changed = [0u8; 8];
        assert_eq!(overlay.read_regular(upper_handle, 0, &mut changed), Ok(4));
        assert_eq!(&changed[..4], b"UPse");
        assert_eq!(bytes, lower_before);

        let lower_file = overlay
            .lower()
            .open_readonly_at(AT_FDCWD, b"etc/base")
            .unwrap();
        assert_eq!(overlay.lower().read_at(lower_file, 0, 8).unwrap(), b"base");
    }

    #[test]
    fn zero_length_write_does_not_copy_up_lower_file() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        assert_eq!(
            overlay.write_at(b"/etc/base", 1 << 20, b"", T2),
            Err(OverlayError::Mutable(RootedMutableError::Mutable(
                MutableError::FileTooLarge,
            )))
        );
        assert!(matches!(
            overlay.lookup_at(b"/etc/base").unwrap(),
            Some(OverlayNodeHandle::Immutable { .. })
        ));
    }

    #[test]
    fn write_through_lower_symlink_copies_up_target_not_alias_name() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        assert_eq!(overlay.write_at(b"/alias", 0, b"UP", T2), Ok(2));
        let target = overlay.lookup_at(b"/target").unwrap().unwrap();
        let alias = overlay.lookup_at(b"/alias").unwrap().unwrap();
        assert_eq!(target, alias);
        assert!(matches!(target, OverlayNodeHandle::Immutable { .. }));
    }

    #[test]
    fn write_through_mutable_symlink_uses_union_target() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        let root = overlay.upper.root_directory();
        overlay
            .upper
            .create_symlink(root, b"upper-alias", b"/etc/base", 0, 0, T1)
            .unwrap();

        assert_eq!(overlay.write_at(b"/upper-alias", 0, b"UP", T2), Ok(2));
        let target = overlay.lookup_at(b"/etc/base").unwrap().unwrap();
        assert!(matches!(target, OverlayNodeHandle::Immutable { .. }));
        let mut read = [0u8; 8];
        assert_eq!(overlay.read_regular(target, 0, &mut read), Ok(4));
        assert_eq!(&read[..4], b"UPse");
    }

    #[test]
    fn unlink_final_symlink_does_not_remove_its_target() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.unlink_regular_at(b"/alias").unwrap();
        assert_eq!(overlay.lookup_at(b"/alias"), Ok(None));
        assert!(matches!(
            overlay.lookup_at(b"/target").unwrap(),
            Some(OverlayNodeHandle::Immutable { .. })
        ));
    }

    #[test]
    fn mutation_beneath_immutable_directory_materializes_only_upper_parent() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay
            .create_regular_at(b"/etc/new", 0o600, 1, 2, T1)
            .unwrap();
        assert!(matches!(
            overlay.lookup_at(b"/etc/new").unwrap(),
            Some(OverlayNodeHandle::Mutable(_))
        ));
        assert!(matches!(
            overlay.lookup_at(b"/etc/keep").unwrap(),
            Some(OverlayNodeHandle::Immutable { .. })
        ));
    }

    #[test]
    fn tombstone_prevents_lower_resurrection_and_recreate_clears_it() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.unlink_regular_at(b"/etc/base").unwrap();
        assert_eq!(overlay.lookup_at(b"/etc/base"), Ok(None));

        overlay
            .create_regular_at(b"/etc/base", 0o600, 0, 0, T1)
            .unwrap();
        assert!(matches!(
            overlay.lookup_at(b"/etc/base").unwrap(),
            Some(OverlayNodeHandle::Mutable(_))
        ));
    }

    #[test]
    fn truncate_copies_up_before_modifying_upper() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.truncate_at(b"/etc/base", 2, T2).unwrap();
        let handle = overlay.lookup_at(b"/etc/base").unwrap().unwrap();
        let mut read = [0u8; 8];
        assert_eq!(overlay.read_regular(handle, 0, &mut read), Ok(2));
        assert_eq!(&read[..2], b"ba");

        let lower_file = overlay
            .lower()
            .open_readonly_at(AT_FDCWD, b"etc/base")
            .unwrap();
        assert_eq!(overlay.lower().read_at(lower_file, 0, 8).unwrap(), b"base");
    }
}
