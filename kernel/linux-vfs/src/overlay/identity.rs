// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{OverlayError, OverlayNamespace, OverlayNodeHandle};
use crate::{
    AT_FDCWD, CanonicalPath, EntryId, Error, MutableError, MutableNodeHandle, MutableNodeKind,
    MutableTimestamp, Node, NodeKind, ReadOnlyFile, RootedMutableError,
};

type SourceDevice = (u32, u32);
type SourceProvenance = (Option<u32>, Option<SourceDevice>, Option<SourceDevice>);

/// VFS-owned logical lower-object state.
///
/// `entry_id` remains the stable logical identity. `upper` is only the current mutable backing and
/// may be attached later by copy-up/materialization. `open_references` counts logical opens that were
/// acquired through the lower identity before or after that transition. One aggregate mutable open
/// reference is held while this count is non-zero, preventing unlink from reclaiming the backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LowerBinding {
    entry_id: EntryId,
    upper: Option<MutableNodeHandle>,
    open_references: u32,
}

impl LowerBinding {
    pub(super) const fn detached(entry_id: EntryId) -> Self {
        Self {
            entry_id,
            upper: None,
            open_references: 0,
        }
    }
}

/// Borrow-free architecture-neutral metadata snapshot for one union object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverlayMetadata {
    object: OverlayNodeHandle,
    kind: NodeKind,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u32,
    size: u64,
    source_ino: Option<u32>,
    source_device: Option<(u32, u32)>,
    source_rdev: Option<(u32, u32)>,
    atime: MutableTimestamp,
    mtime: MutableTimestamp,
    ctime: MutableTimestamp,
}

impl OverlayMetadata {
    pub const fn object(self) -> OverlayNodeHandle {
        self.object
    }
    pub const fn kind(self) -> NodeKind {
        self.kind
    }
    pub const fn mode(self) -> u32 {
        self.mode
    }
    pub const fn uid(self) -> u32 {
        self.uid
    }
    pub const fn gid(self) -> u32 {
        self.gid
    }
    pub const fn links(self) -> u32 {
        self.links
    }
    pub const fn size(self) -> u64 {
        self.size
    }
    pub const fn source_ino(self) -> Option<u32> {
        self.source_ino
    }
    pub const fn source_device(self) -> Option<(u32, u32)> {
        self.source_device
    }
    pub const fn source_rdev(self) -> Option<(u32, u32)> {
        self.source_rdev
    }
    pub const fn atime(self) -> MutableTimestamp {
        self.atime
    }
    pub const fn mtime(self) -> MutableTimestamp {
        self.mtime
    }
    pub const fn ctime(self) -> MutableTimestamp {
        self.ctime
    }
}

/// Opaque writable regular-file capability retained for one FD/OFD owner.
///
/// The logical union identity remains visible for stat/object correlation, while the concrete
/// mutable backing identity stays private to VFS. Copying this small token does not create an
/// additional VFS open reference; descriptor duplication must continue to share the owning OFD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRegularHandle {
    logical: OverlayNodeHandle,
    backing: MutableNodeHandle,
}

impl RetainedRegularHandle {
    pub const fn object(self) -> OverlayNodeHandle {
        self.logical
    }
}

impl<
    'a,
    const NODES: usize,
    const DENTRIES: usize,
    const FILE_BYTES: usize,
    const TOMBSTONES: usize,
> OverlayNamespace<'a, NODES, DENTRIES, FILE_BYTES, TOMBSTONES>
{
    pub(crate) fn logical_handle_for_entry(
        &self,
        entry_id: EntryId,
    ) -> Result<OverlayNodeHandle, OverlayError> {
        let entry = self
            .lower
            .archive
            .entry_by_id(entry_id)
            .map_err(Error::from)?
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        let node = Node::from_entry(entry);
        let file = (node.kind() == NodeKind::Regular)
            .then(|| ReadOnlyFile::new(self.root_id(), entry_id, node.mode(), node.size()));
        Ok(OverlayNodeHandle::Immutable {
            root: self.root_id(),
            owner: self.upper.root_directory(),
            entry_id,
            kind: node.kind(),
            file,
        })
    }

    pub(crate) fn logical_handle_for_upper(
        &self,
        upper: MutableNodeHandle,
    ) -> Result<OverlayNodeHandle, OverlayError> {
        if let Some(entry_id) = self.lower_entry_for_upper(upper) {
            self.logical_handle_for_entry(entry_id)
        } else {
            Ok(OverlayNodeHandle::Mutable(upper))
        }
    }

    pub(crate) fn bound_upper_for_entry(&self, entry_id: EntryId) -> Option<MutableNodeHandle> {
        let binding = self
            .lower_bindings
            .iter()
            .flatten()
            .find(|binding| binding.entry_id == entry_id)?;
        let upper = binding.upper?;
        self.upper.metadata(upper).ok().map(|_| upper)
    }

    pub(crate) fn lower_entry_for_upper(&self, upper: MutableNodeHandle) -> Option<EntryId> {
        self.lower_bindings
            .iter()
            .flatten()
            .find(|binding| binding.upper == Some(upper) && self.upper.metadata(upper).is_ok())
            .map(|binding| binding.entry_id)
    }

    pub(super) fn preflight_lower_binding(&self, entry_id: EntryId) -> Result<(), OverlayError> {
        self.preflight_publication(Some(entry_id), CanonicalPath::root(), 0, 0)
    }

    pub(super) fn preflight_compound_publication(
        &self,
        source_entry: Option<EntryId>,
        destination_parent: CanonicalPath,
        extra_dentries: usize,
    ) -> Result<(), OverlayError> {
        self.preflight_publication(source_entry, destination_parent, 0, extra_dentries)
    }

    pub(super) fn preflight_parent_final_publication(
        &self,
        destination_parent: CanonicalPath,
    ) -> Result<(), OverlayError> {
        self.preflight_publication(None, destination_parent, 1, 1)
    }

    fn preflight_publication(
        &self,
        source_entry: Option<EntryId>,
        destination_parent: CanonicalPath,
        extra_nodes: usize,
        extra_dentries: usize,
    ) -> Result<(), OverlayError> {
        let mut required = [None; NODES];
        let mut required_len = 0usize;

        if let Some(entry_id) = source_entry {
            self.collect_lower_publication(entry_id, &mut required, &mut required_len)?;
        }

        if !destination_parent.is_root() && self.mutable_node_at(destination_parent)?.is_none() {
            if self.is_tombstoned(destination_parent) {
                return Err(OverlayError::NotFound);
            }
            let (entry_id, entry) = self
                .lower
                .archive
                .get_with_id(destination_parent.as_archive_bytes())
                .map_err(Error::from)?
                .ok_or(OverlayError::NotFound)?;
            if Node::from_entry(entry).kind() != NodeKind::Directory {
                return Err(OverlayError::NotDirectory);
            }
            self.collect_lower_publication(entry_id, &mut required, &mut required_len)?;
        }

        let required_nodes = required_len
            .checked_add(extra_nodes)
            .ok_or(OverlayError::Mutable(RootedMutableError::Mutable(
                MutableError::NodeTableFull,
            )))?;
        let required_dentries =
            required_len
                .checked_add(extra_dentries)
                .ok_or(OverlayError::Mutable(RootedMutableError::Mutable(
                    MutableError::DirectoryEntryTableFull,
                )))?;
        self.upper
            .preflight_capacity(required_nodes, required_dentries)?;

        let reserved_required = required[..required_len]
            .iter()
            .flatten()
            .filter(|entry_id| {
                self.binding_index(**entry_id).is_some_and(|index| {
                    self.lower_bindings[index]
                        .is_some_and(|binding| !self.binding_reusable(binding))
                })
            })
            .count();
        let required_reusable = required_len
            .checked_sub(reserved_required)
            .ok_or(OverlayError::BindingTableFull)?;
        if self.reusable_binding_count() < required_reusable {
            return Err(OverlayError::BindingTableFull);
        }
        Ok(())
    }

    fn collect_lower_publication(
        &self,
        entry_id: EntryId,
        required: &mut [Option<EntryId>; NODES],
        required_len: &mut usize,
    ) -> Result<(), OverlayError> {
        let entry = self
            .lower
            .archive
            .entry_by_id(entry_id)
            .map_err(Error::from)?
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        let canonical = CanonicalPath::resolve_at(AT_FDCWD, entry.path())?;
        let relative = canonical.as_relative_bytes();

        for (separator, byte) in relative.iter().enumerate() {
            if *byte != b'/' {
                continue;
            }
            let prefix = CanonicalPath::resolve_at(AT_FDCWD, &relative[..separator])?;
            if let Some(node) = self.mutable_node_at(prefix)? {
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                continue;
            }

            let (parent_entry_id, parent_entry) = self
                .lower
                .archive
                .get_with_id(prefix.as_archive_bytes())
                .map_err(Error::from)?
                .ok_or(OverlayError::NotFound)?;
            if Node::from_entry(parent_entry).kind() != NodeKind::Directory {
                return Err(OverlayError::NotDirectory);
            }

            // Capacity planning follows VFS identity, not historical presentation. A lower
            // directory that already owns a valid Upper binding is already published even after
            // that Upper directory was renamed away from its CPIO pathname. Its old pathname may
            // legitimately be tombstoned; relative copy-up through the retained directory must use
            // the binding rather than treating that presentation tombstone as missing authority.
            if let Some(bound) = self.bound_upper_for_entry(parent_entry_id) {
                if self.upper.metadata(bound)?.kind() != MutableNodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                continue;
            }

            if self.is_tombstoned(prefix) {
                return Err(OverlayError::NotFound);
            }
            self.push_required_entry(parent_entry_id, required, required_len)?;
        }

        if self.mutable_node_at(canonical)?.is_none()
            && self.bound_upper_for_entry(entry_id).is_none()
        {
            self.push_required_entry(entry_id, required, required_len)?;
        }
        Ok(())
    }

    fn push_required_entry(
        &self,
        entry_id: EntryId,
        required: &mut [Option<EntryId>; NODES],
        required_len: &mut usize,
    ) -> Result<(), OverlayError> {
        if required[..*required_len].contains(&Some(entry_id)) {
            return Ok(());
        }
        if *required_len == NODES {
            return Err(OverlayError::Mutable(RootedMutableError::Mutable(
                MutableError::NodeTableFull,
            )));
        }
        required[*required_len] = Some(entry_id);
        *required_len += 1;
        Ok(())
    }

    pub(super) fn attach_lower_binding(
        &mut self,
        entry_id: EntryId,
        upper: MutableNodeHandle,
    ) -> Result<(), OverlayError> {
        self.validate_handle_root(OverlayNodeHandle::Mutable(upper))?;
        let index = match self.binding_index(entry_id) {
            Some(index) => index,
            None => {
                let index = self
                    .reusable_binding_index()
                    .ok_or(OverlayError::BindingTableFull)?;
                self.lower_bindings[index] = Some(LowerBinding::detached(entry_id));
                index
            }
        };
        let current =
            self.lower_bindings[index].ok_or(OverlayError::Path(Error::HandleMismatch))?;
        if let Some(existing) = current.upper
            && existing != upper
            && self.upper.metadata(existing).is_ok()
        {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }
        if current.open_references != 0 && current.upper != Some(upper) {
            self.upper.retain_open(upper)?;
        }
        let binding = self.lower_bindings[index]
            .as_mut()
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        binding.upper = Some(upper);
        Ok(())
    }

    pub(super) fn retain_lower_binding(&mut self, entry_id: EntryId) -> Result<(), OverlayError> {
        let index = match self.binding_index(entry_id) {
            Some(index) => index,
            None => {
                let index = self
                    .reusable_binding_index()
                    .ok_or(OverlayError::BindingTableFull)?;
                self.lower_bindings[index] = Some(LowerBinding::detached(entry_id));
                index
            }
        };
        let current =
            self.lower_bindings[index].ok_or(OverlayError::Path(Error::HandleMismatch))?;
        let next = current
            .open_references
            .checked_add(1)
            .ok_or(OverlayError::Mutable(RootedMutableError::Mutable(
                MutableError::OpenReferenceOverflow,
            )))?;
        if current.open_references == 0
            && let Some(upper) = current.upper
        {
            self.upper.retain_open(upper)?;
        }
        self.lower_bindings[index]
            .as_mut()
            .ok_or(OverlayError::Path(Error::HandleMismatch))?
            .open_references = next;
        Ok(())
    }

    pub(super) fn release_lower_binding(&mut self, entry_id: EntryId) -> Result<(), OverlayError> {
        let index = self
            .binding_index(entry_id)
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        let current =
            self.lower_bindings[index].ok_or(OverlayError::Path(Error::HandleMismatch))?;
        if current.open_references == 0 {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }
        let next = current.open_references - 1;
        if next == 0
            && let Some(upper) = current.upper
        {
            self.upper.release_open(upper)?;
        }

        let upper = current
            .upper
            .filter(|node| self.upper.metadata(*node).is_ok());
        if next == 0 && upper.is_none() {
            self.lower_bindings[index] = None;
        } else {
            self.lower_bindings[index] = Some(LowerBinding {
                entry_id,
                upper,
                open_references: next,
            });
        }
        Ok(())
    }

    fn binding_index(&self, entry_id: EntryId) -> Option<usize> {
        self.lower_bindings
            .iter()
            .position(|slot| slot.is_some_and(|binding| binding.entry_id == entry_id))
    }

    fn binding_for_entry(&self, entry_id: EntryId) -> Option<LowerBinding> {
        self.lower_bindings
            .iter()
            .flatten()
            .copied()
            .find(|binding| binding.entry_id == entry_id)
    }

    fn reusable_binding_index(&self) -> Option<usize> {
        self.lower_bindings.iter().position(|slot| match slot {
            None => true,
            Some(binding) => self.binding_reusable(*binding),
        })
    }

    fn reusable_binding_count(&self) -> usize {
        self.lower_bindings
            .iter()
            .filter(|slot| match slot {
                None => true,
                Some(binding) => self.binding_reusable(*binding),
            })
            .count()
    }

    fn binding_reusable(&self, binding: LowerBinding) -> bool {
        if binding.open_references != 0 {
            return false;
        }
        match binding.upper {
            None => true,
            Some(node) => self.upper.metadata(node).is_err(),
        }
    }

    /// Validates whether immutable CPIO fallback is still authorized. The archive bytes are directly
    /// usable only while the lower object's own pathname still resolves to this exact logical handle.
    /// If that path was unlinked, renamed away, or replaced by another object, CPIO fallback remains
    /// available only to an already-retained detached LowerBinding. Final release removes that
    /// binding, so a stale EntryId can no longer resurrect bytes or metadata even if a replacement
    /// later clears the old tombstone.
    pub(super) fn validate_lower_fallback(&self, entry_id: EntryId) -> Result<bool, OverlayError> {
        let entry = self
            .lower
            .archive
            .entry_by_id(entry_id)
            .map_err(Error::from)?
            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
        let binding = self.binding_for_entry(entry_id);
        if let Some(binding) = binding
            && binding.upper.is_some()
            && self.bound_upper_for_entry(entry_id).is_none()
        {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }

        let canonical = CanonicalPath::resolve_at(AT_FDCWD, entry.path())?;
        let logical = self.logical_handle_for_entry(entry_id)?;
        if self.lookup_canonical(canonical)? == Some(logical) {
            return Ok(false);
        }

        let binding = binding.ok_or(OverlayError::NotFound)?;
        if binding.upper.is_some() || binding.open_references == 0 {
            return Err(OverlayError::NotFound);
        }
        Ok(true)
    }

    /// Current namespace-local metadata for an exact union object. This is suitable for pathname
    /// stat and read-only immutable objects. Writable retained descriptors use
    /// `retained_regular_metadata`, which additionally validates the exact backing owner/generation.
    pub fn metadata(&self, handle: OverlayNodeHandle) -> Result<OverlayMetadata, OverlayError> {
        self.validate_handle_root(handle)?;
        match handle {
            OverlayNodeHandle::Root { .. } => {
                let entry = self
                    .lower
                    .archive
                    .get(b".")
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                self.metadata_from_lower(handle, entry)
            }
            OverlayNodeHandle::Mutable(node) => {
                let metadata = self.upper.metadata(node)?;
                self.metadata_from_upper(handle, metadata)
            }
            OverlayNodeHandle::Immutable { entry_id, .. } => {
                if self.logical_handle_for_entry(entry_id)? != handle {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                if let Some(upper) = self.bound_upper_for_entry(entry_id) {
                    return self.metadata_from_upper(handle, self.upper.metadata(upper)?);
                }
                let detached = self.validate_lower_fallback(entry_id)?;
                let entry = self
                    .lower
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let mut metadata = self.metadata_from_lower(handle, entry)?;
                if detached {
                    metadata.links = metadata.links.saturating_sub(1);
                }
                Ok(metadata)
            }
        }
    }

    /// Resolves, prepares and retains one writable regular in one VFS handoff. The returned opaque
    /// token binds stable logical identity to the exact mutable namespace/generation witness without
    /// exposing that backing identity to the future linux-fd owner.
    pub fn prepare_and_retain_writable_regular_at(
        &mut self,
        path: &[u8],
    ) -> Result<RetainedRegularHandle, OverlayError> {
        let (logical, _) = self.resolve_following_at(path)?;
        self.prepare_writable_regular(logical)?;
        let backing = self.writable_regular_backing(logical)?;
        self.retain_open(logical)?;
        Ok(RetainedRegularHandle { logical, backing })
    }

    /// Prepares and retains one writable regular relative to an already-open directory identity. For
    /// lower-backed direct children, copy-up is published beneath the live parent object rather than
    /// through the child's historical archive pathname.
    pub fn prepare_and_retain_writable_regular_from(
        &mut self,
        base: crate::OverlayDirectoryHandle,
        path: &[u8],
    ) -> Result<RetainedRegularHandle, OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.prepare_and_retain_writable_regular_at(path);
        }
        let (logical, backing) = self.materialize_regular_for_relative_owner(base, path)?;
        self.retain_open(logical)?;
        Ok(RetainedRegularHandle { logical, backing })
    }

    pub fn retained_regular_metadata(
        &self,
        retained: RetainedRegularHandle,
    ) -> Result<OverlayMetadata, OverlayError> {
        let (logical, backing) = self.validate_retained_regular(retained)?;
        self.metadata_from_upper(logical, self.upper.metadata(backing)?)
    }

    pub fn read_retained_regular(
        &self,
        retained: RetainedRegularHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, OverlayError> {
        let (_, backing) = self.validate_retained_regular(retained)?;
        self.upper.read(backing, offset, output).map_err(Into::into)
    }

    pub fn write_retained_regular(
        &mut self,
        retained: RetainedRegularHandle,
        offset: u64,
        input: &[u8],
        now: MutableTimestamp,
    ) -> Result<usize, OverlayError> {
        let (_, backing) = self.validate_retained_regular(retained)?;
        self.upper
            .write(backing, offset, input, now)
            .map_err(Into::into)
    }

    pub fn append_retained_regular(
        &mut self,
        retained: RetainedRegularHandle,
        input: &[u8],
        now: MutableTimestamp,
    ) -> Result<(u64, usize), OverlayError> {
        let (_, backing) = self.validate_retained_regular(retained)?;
        let metadata = self.upper.metadata(backing)?;
        let offset = u64::try_from(metadata.size())
            .map_err(|_| OverlayError::Path(Error::OffsetOverflow))?;
        let count = self.upper.write(backing, offset, input, now)?;
        Ok((offset, count))
    }

    pub fn truncate_retained_regular(
        &mut self,
        retained: RetainedRegularHandle,
        length: u64,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let (_, backing) = self.validate_retained_regular(retained)?;
        self.upper
            .truncate(backing, length, now)
            .map_err(Into::into)
    }

    pub fn chmod_retained_regular(
        &mut self,
        retained: RetainedRegularHandle,
        mode: u32,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let (_, backing) = self.validate_retained_regular(retained)?;
        self.upper.chmod(backing, mode, now).map_err(Into::into)
    }

    pub fn chown_retained_regular(
        &mut self,
        retained: RetainedRegularHandle,
        uid: Option<u32>,
        gid: Option<u32>,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let (_, backing) = self.validate_retained_regular(retained)?;
        self.upper.chown(backing, uid, gid, now).map_err(Into::into)
    }

    pub fn set_times_retained_regular(
        &mut self,
        retained: RetainedRegularHandle,
        atime: MutableTimestamp,
        mtime: MutableTimestamp,
        ctime: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let (_, backing) = self.validate_retained_regular(retained)?;
        self.upper
            .set_times(backing, atime, mtime, ctime)
            .map_err(Into::into)
    }

    pub fn release_retained_regular(
        &mut self,
        retained: RetainedRegularHandle,
    ) -> Result<(), OverlayError> {
        let (logical, _) = self.validate_retained_regular(retained)?;
        self.release_open(logical)
    }

    fn prepare_writable_regular(&mut self, handle: OverlayNodeHandle) -> Result<(), OverlayError> {
        self.validate_handle_root(handle)?;
        match handle {
            OverlayNodeHandle::Root { .. } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Mutable(node) => match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => Ok(()),
                MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
            },
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Regular,
                ..
            } => {
                if self.logical_handle_for_entry(entry_id)? != handle {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                if self.bound_upper_for_entry(entry_id).is_some() {
                    return Ok(());
                }
                let entry = self
                    .lower
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let canonical = CanonicalPath::resolve_at(AT_FDCWD, entry.path())?;
                if self.lookup_canonical(canonical)? != Some(handle) {
                    return Err(OverlayError::NotFound);
                }
                self.copy_up_regular_canonical(canonical)?;
                if self.bound_upper_for_entry(entry_id).is_none() {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Ok(())
            }
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotRegular),
        }
    }

    fn writable_regular_backing(
        &self,
        logical: OverlayNodeHandle,
    ) -> Result<MutableNodeHandle, OverlayError> {
        match logical {
            OverlayNodeHandle::Root { .. } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Mutable(node) => {
                self.validate_handle_root(logical)?;
                match self.upper.metadata(node)?.kind() {
                    MutableNodeKind::Regular => Ok(node),
                    MutableNodeKind::Directory => Err(OverlayError::IsDirectory),
                    MutableNodeKind::Symlink => Err(OverlayError::NotRegular),
                }
            }
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Regular,
                ..
            } => {
                self.validate_handle_root(logical)?;
                if self.logical_handle_for_entry(entry_id)? != logical {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                self.bound_upper_for_entry(entry_id)
                    .ok_or(OverlayError::Path(Error::HandleMismatch))
            }
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotRegular),
        }
    }

    fn validate_retained_regular(
        &self,
        retained: RetainedRegularHandle,
    ) -> Result<(OverlayNodeHandle, MutableNodeHandle), OverlayError> {
        let logical = retained.logical;
        let backing = retained.backing;
        self.validate_handle_root(logical)?;
        let metadata = self.upper.metadata(backing)?;
        if metadata.kind() != MutableNodeKind::Regular {
            return Err(OverlayError::NotRegular);
        }
        match logical {
            OverlayNodeHandle::Mutable(node) if node == backing => Ok((logical, backing)),
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Regular,
                ..
            } if self.logical_handle_for_entry(entry_id)? == logical
                && self.bound_upper_for_entry(entry_id) == Some(backing) =>
            {
                Ok((logical, backing))
            }
            OverlayNodeHandle::Root { .. }
            | OverlayNodeHandle::Mutable(_)
            | OverlayNodeHandle::Immutable { .. } => Err(OverlayError::Path(Error::HandleMismatch)),
        }
    }

    fn source_provenance_for_object(
        &self,
        object: OverlayNodeHandle,
    ) -> Result<SourceProvenance, OverlayError> {
        let entry = match object {
            OverlayNodeHandle::Mutable(_) => return Ok((None, None, None)),
            OverlayNodeHandle::Root { .. } => self
                .lower
                .archive
                .get(b".")
                .map_err(Error::from)?
                .ok_or(OverlayError::Path(Error::HandleMismatch))?,
            OverlayNodeHandle::Immutable { entry_id, .. } => self
                .lower
                .archive
                .entry_by_id(entry_id)
                .map_err(Error::from)?
                .ok_or(OverlayError::Path(Error::HandleMismatch))?,
        };
        Ok((
            Some(entry.ino()),
            Some((entry.dev_major(), entry.dev_minor())),
            Some((entry.rdev_major(), entry.rdev_minor())),
        ))
    }

    fn metadata_from_upper(
        &self,
        object: OverlayNodeHandle,
        metadata: crate::MutableMetadata,
    ) -> Result<OverlayMetadata, OverlayError> {
        let kind = match metadata.kind() {
            MutableNodeKind::Regular => NodeKind::Regular,
            MutableNodeKind::Directory => NodeKind::Directory,
            MutableNodeKind::Symlink => NodeKind::Symlink,
        };
        let size = u64::try_from(metadata.size())
            .map_err(|_| OverlayError::Path(Error::OffsetOverflow))?;
        let (source_ino, source_device, source_rdev) = self.source_provenance_for_object(object)?;
        Ok(OverlayMetadata {
            object,
            kind,
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            links: metadata.links(),
            size,
            source_ino,
            source_device,
            source_rdev,
            atime: metadata.atime(),
            mtime: metadata.mtime(),
            ctime: metadata.ctime(),
        })
    }

    fn metadata_from_lower(
        &self,
        object: OverlayNodeHandle,
        entry: kernal_cpio::Entry<'a>,
    ) -> Result<OverlayMetadata, OverlayError> {
        let node = Node::from_entry(entry);
        let time = MutableTimestamp {
            seconds: i64::from(entry.mtime()),
            nanoseconds: 0,
        };
        Ok(OverlayMetadata {
            object,
            kind: node.kind(),
            mode: node.mode(),
            uid: entry.uid(),
            gid: entry.gid(),
            links: entry.nlink(),
            size: node.size(),
            source_ino: Some(entry.ino()),
            source_device: Some((entry.dev_major(), entry.dev_minor())),
            source_rdev: Some((entry.rdev_major(), entry.rdev_minor())),
            atime: time,
            mtime: time,
            ctime: time,
        })
    }
}
