// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{
    AT_FDCWD, CanonicalPath, DirectoryHandle, Error, FsContext, LINUX_NAME_MAX,
    MutableDirectoryHandle, MutableNodeKind, Node, NodeKind, OverlayError, OverlayNamespace,
    OverlayNodeHandle, ReadOnlyDirectory, RootId,
};
use kernal_cpio::EntryId;

const DOT_ENTRIES: usize = 2;

/// Persistent overlay directory identity suitable for one FD/OFD object.
///
/// Mutable directories retain their generation-safe node identity across rename. Immutable
/// directories retain their stable CPIO EntryId. No pathname is authoritative in the handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverlayDirectoryHandle {
    object: OverlayNodeHandle,
}

impl OverlayDirectoryHandle {
    pub const fn object(self) -> OverlayNodeHandle {
        self.object
    }

    pub const fn root_id(self) -> RootId {
        self.object.root_id()
    }
}

/// Owned Linux-visible directory-entry facts. The name is copied into a NAME_MAX-sized buffer so a
/// scan witness never borrows a mutable dentry slot across later mutation/usercopy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverlayDirectoryEntry {
    object: OverlayNodeHandle,
    name: [u8; LINUX_NAME_MAX],
    name_len: u8,
    kind: NodeKind,
    mode: u32,
    size: u64,
}

impl OverlayDirectoryEntry {
    fn new(
        object: OverlayNodeHandle,
        name: &[u8],
        kind: NodeKind,
        mode: u32,
        size: u64,
    ) -> Result<Self, OverlayError> {
        if name.is_empty() || name.len() > LINUX_NAME_MAX {
            return Err(OverlayError::Path(Error::PathTooLong));
        }
        let mut bytes = [0u8; LINUX_NAME_MAX];
        bytes[..name.len()].copy_from_slice(name);
        let name_len =
            u8::try_from(name.len()).map_err(|_| OverlayError::Path(Error::PathTooLong))?;
        Ok(Self {
            object,
            name: bytes,
            name_len,
            kind,
            mode,
            size,
        })
    }

    pub const fn object(self) -> OverlayNodeHandle {
        self.object
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_len)]
    }

    pub const fn kind(self) -> NodeKind {
        self.kind
    }

    pub const fn mode(self) -> u32 {
        self.mode
    }

    pub const fn size(self) -> u64 {
        self.size
    }
}

/// Deterministic cursor transition for the merged upper/lower directory view.
///
/// Cursor 0/1 are `.`/`..`. The next `DENTRIES` cursor positions belong to the bounded mutable
/// dentry table. The remaining positions map to immutable CPIO entry ordinals. Skipped upper slots,
/// lower descendants, tombstones and lower names shadowed by upper objects still advance within
/// their own cursor domain, so no hidden name can be resurrected by retrying a stale cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverlayDirectoryScan {
    entry: OverlayDirectoryEntry,
    directory: OverlayDirectoryHandle,
    start_cursor: usize,
    next_cursor: usize,
}

impl OverlayDirectoryScan {
    pub const fn entry(self) -> OverlayDirectoryEntry {
        self.entry
    }

    pub const fn directory(self) -> OverlayDirectoryHandle {
        self.directory
    }

    pub const fn start_cursor(self) -> usize {
        self.start_cursor
    }

    pub const fn next_cursor(self) -> usize {
        self.next_cursor
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
    /// Opens one directory through the canonical merged resolver. The returned identity remains
    /// valid across mutable rename because it contains the VFS object identity, not a path string.
    pub fn open_directory_at(&self, path: &[u8]) -> Result<OverlayDirectoryHandle, OverlayError> {
        let (object, _) = self.resolve_following_at(path)?;
        if self.object_facts(object)?.0 != NodeKind::Directory {
            return Err(OverlayError::NotDirectory);
        }
        Ok(OverlayDirectoryHandle { object })
    }

    /// Opens one directory relative to a retained Overlay directory identity without reconstructing
    /// the base directory's absolute pathname. Absolute operands preserve the established path API.
    pub fn open_directory_from(
        &self,
        base: OverlayDirectoryHandle,
        path: &[u8],
    ) -> Result<OverlayDirectoryHandle, OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.open_directory_at(path);
        }
        let object = self.resolve_following_from(base, path)?;
        if self.object_facts(object)?.0 != NodeKind::Directory {
            return Err(OverlayError::NotDirectory);
        }
        Ok(OverlayDirectoryHandle { object })
    }

    /// Resolves a directory from retained authority and acquires the OFD/cwd lifetime hold in the
    /// same VFS handoff. Rollback remains the caller's responsibility only after later FD publish.
    pub fn open_and_retain_directory_from(
        &mut self,
        base: OverlayDirectoryHandle,
        path: &[u8],
    ) -> Result<OverlayDirectoryHandle, OverlayError> {
        if path.first().copied() == Some(b'/') {
            return self.open_and_retain_directory_at(path);
        }
        let directory = self.open_directory_from(base, path)?;
        self.retain_directory(directory)?;
        Ok(directory)
    }

    /// Materializes Linux-visible pathname text only at the owning Overlay presentation boundary.
    /// Immutable directories normally re-derive text from authenticated EntryId provenance. If that
    /// same logical lower EntryId already owns an Upper directory binding, presentation follows the
    /// live mutable ancestry instead; private lower provenance remains unchanged for merge/copy-up.
    pub fn directory_canonical_path(
        &self,
        directory: OverlayDirectoryHandle,
    ) -> Result<CanonicalPath, OverlayError> {
        self.validate_handle_root(directory.object())?;
        match directory.object() {
            OverlayNodeHandle::Mutable(node) => {
                let mutable = self.upper().directory_handle_from_node(node)?;
                self.upper()
                    .directory_canonical_path(mutable)
                    .map_err(Into::into)
            }
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Directory,
                ..
            } => {
                if let Some(node) = self.bound_upper_for_entry(entry_id) {
                    if self.upper().metadata(node)?.kind() != MutableNodeKind::Directory {
                        return Err(OverlayError::Path(Error::HandleMismatch));
                    }
                    let mutable = self.upper().directory_handle_from_node(node)?;
                    return self
                        .upper()
                        .directory_canonical_path(mutable)
                        .map_err(Into::into);
                }
                self.directory_canonical(directory)
            }
            OverlayNodeHandle::Root { .. } | OverlayNodeHandle::Immutable { .. } => {
                self.directory_canonical(directory)
            }
        }
    }

    /// Publishes an Overlay-owned directory into one process filesystem context. The conversion is
    /// owner-qualified: lower immutable cwd state retains only EntryId/mode plus the private
    /// Upper-root witness, while mutable cwd state delegates its independent lifetime hold to the
    /// existing rooted-mutable owner through `FsContext::set_cwd`.
    pub fn set_context_cwd(
        &mut self,
        context: &mut FsContext,
        directory: OverlayDirectoryHandle,
    ) -> Result<(), OverlayError> {
        if context.root() != self.root_id() {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }
        let cwd = self.context_directory_handle(directory)?;
        context.set_cwd(self.upper_mut(), cwd).map_err(Into::into)
    }

    /// Releases the process-owned cwd hold through the same private Upper owner and restores the
    /// context to its bound generic root identity. Revalidation is mandatory before teardown so a
    /// same-RootId plain immutable handle cannot bypass the Overlay owner witness on the release path.
    pub fn release_context_cwd(&mut self, context: &mut FsContext) -> Result<(), OverlayError> {
        if context.root() != self.root_id() {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }
        self.revalidate_directory_handle(context.cwd_handle())?;
        context.release_cwd(self.upper_mut()).map_err(Into::into)
    }

    /// Re-enters an opaque process cwd handle through the exact Overlay owner. A same-RootId sibling
    /// cannot rebind an Overlay-published immutable cwd because the compact handle also carries this
    /// Overlay's private Upper-root witness. Plain immutable-root handles are deliberately rejected:
    /// callers must publish them through `set_context_cwd` to acquire Overlay ownership first.
    pub fn revalidate_directory_handle(
        &self,
        handle: DirectoryHandle,
    ) -> Result<OverlayDirectoryHandle, OverlayError> {
        if handle.root_id() != self.root_id() {
            return Err(OverlayError::Path(Error::HandleMismatch));
        }

        if handle.is_root() {
            if let Some(owner) = handle.mutable_directory_identity() {
                let owner = self.upper().refresh_directory(owner)?;
                if owner != self.upper().root_directory() {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                return Ok(OverlayDirectoryHandle {
                    object: OverlayNodeHandle::Root {
                        root: self.root_id(),
                        owner,
                    },
                });
            }
            return Ok(OverlayDirectoryHandle {
                object: OverlayNodeHandle::Root {
                    root: self.root_id(),
                    owner: self.upper().root_directory(),
                },
            });
        }

        if let Some((directory, owner)) = handle.overlay_immutable_parts() {
            let owner = self.upper().refresh_directory(owner)?;
            if owner != self.upper().root_directory() || directory.root_id() != self.root_id() {
                return Err(OverlayError::Path(Error::HandleMismatch));
            }
            let entry = self
                .lower()
                .archive
                .entry_by_id(directory.entry_id())
                .map_err(Error::from)?
                .ok_or(OverlayError::Path(Error::HandleMismatch))?;
            let node = Node::from_entry(entry);
            if node.kind() != NodeKind::Directory || node.mode() != directory.mode() {
                return Err(OverlayError::Path(Error::HandleMismatch));
            }
            let object = self.logical_handle_for_entry(directory.entry_id())?;
            let expected = OverlayNodeHandle::Immutable {
                root: self.root_id(),
                owner,
                entry_id: directory.entry_id(),
                kind: NodeKind::Directory,
                file: None,
            };
            if object != expected {
                return Err(OverlayError::Path(Error::HandleMismatch));
            }
            return Ok(OverlayDirectoryHandle { object });
        }

        if let Some(directory) = handle.mutable_directory_identity() {
            let directory = self.upper().refresh_directory(directory)?;
            let object = match self.upper().directory_node_handle(directory)? {
                None => OverlayNodeHandle::Root {
                    root: self.root_id(),
                    owner: self.upper().root_directory(),
                },
                Some(node) => self.logical_handle_for_upper(node)?,
            };
            if self.object_facts(object)?.0 != NodeKind::Directory {
                return Err(OverlayError::NotDirectory);
            }
            return Ok(OverlayDirectoryHandle { object });
        }

        Err(OverlayError::Path(Error::HandleMismatch))
    }

    fn context_directory_handle(
        &self,
        directory: OverlayDirectoryHandle,
    ) -> Result<DirectoryHandle, OverlayError> {
        self.validate_handle_root(directory.object())?;
        match directory.object() {
            OverlayNodeHandle::Root { root, owner } => {
                let owner = self.upper().refresh_directory(owner)?;
                if root != self.root_id() || owner != self.upper().root_directory() {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Ok(DirectoryHandle::mutable_root(owner))
            }
            OverlayNodeHandle::Immutable {
                root,
                owner,
                entry_id,
                kind,
                ..
            } => {
                if root != self.root_id() || kind != NodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                let expected = self.logical_handle_for_entry(entry_id)?;
                if expected != directory.object() {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                let entry = self
                    .lower()
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let node = Node::from_entry(entry);
                if node.kind() != NodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Ok(DirectoryHandle::overlay_immutable(
                    ReadOnlyDirectory::new(root, entry_id, node.mode()),
                    owner,
                ))
            }
            OverlayNodeHandle::Mutable(node) => {
                let directory = self.upper().directory_handle_from_node(node)?;
                if directory == self.upper().root_directory() {
                    Ok(DirectoryHandle::mutable_root(directory))
                } else {
                    Ok(DirectoryHandle::mutable(directory))
                }
            }
        }
    }

    /// Returns the next visible entry in the merged mutable-upper/immutable-lower namespace.
    pub fn directory_entry_from(
        &self,
        directory: OverlayDirectoryHandle,
        cursor: usize,
    ) -> Result<Option<OverlayDirectoryScan>, OverlayError> {
        self.validate_handle_root(directory.object())?;

        // A pure upper object has no immutable pathname provenance at all. Enumerate its dentry
        // identity directly and stop after the upper cursor domain; do not reconstruct an absolute
        // path merely to discover that there is no CPIO directory to merge.
        if matches!(directory.object(), OverlayNodeHandle::Mutable(_)) {
            return self.directory_entry_from_upper_only(directory, cursor);
        }

        let canonical = self.directory_canonical(directory)?;
        let lower_base = DOT_ENTRIES
            .checked_add(DENTRIES)
            .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
        let end_cursor = lower_base
            .checked_add(self.lower().archive.entry_count())
            .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
        if cursor > end_cursor {
            return Err(OverlayError::Path(Error::OffsetOverflow));
        }

        if cursor == 0 {
            let entry = self.directory_entry_for(directory.object(), b".")?;
            return Ok(Some(OverlayDirectoryScan {
                entry,
                directory,
                start_cursor: 0,
                next_cursor: 1,
            }));
        }
        if cursor == 1 {
            let mut parent = canonical;
            parent.pop_component();
            let object = self
                .lookup_canonical(parent)?
                .ok_or(OverlayError::Path(Error::HandleMismatch))?;
            let entry = self.directory_entry_for(object, b"..")?;
            return Ok(Some(OverlayDirectoryScan {
                entry,
                directory,
                start_cursor: 1,
                next_cursor: DOT_ENTRIES,
            }));
        }

        if cursor < lower_base
            && let Some(upper_directory) = self.mutable_directory_for(directory)?
        {
            let mutable_cursor = cursor
                .checked_sub(DOT_ENTRIES)
                .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
            if let Some(scan) = self
                .upper()
                .directory_entry_from(upper_directory, mutable_cursor)?
            {
                let mutable_entry = scan.entry();
                let object = self.logical_handle_for_upper(mutable_entry.node())?;
                let metadata = mutable_entry.metadata();
                let kind = mutable_kind(metadata.kind());
                let entry = OverlayDirectoryEntry::new(
                    object,
                    mutable_entry.name(),
                    kind,
                    metadata.mode(),
                    u64::try_from(metadata.size())
                        .map_err(|_| OverlayError::Path(Error::OffsetOverflow))?,
                )?;
                let next_cursor = DOT_ENTRIES
                    .checked_add(scan.next_cursor())
                    .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
                return Ok(Some(OverlayDirectoryScan {
                    entry,
                    directory,
                    start_cursor: cursor,
                    next_cursor,
                }));
            }
        }

        let mut index = cursor.saturating_sub(lower_base);
        while index < self.lower().archive.entry_count() {
            let entry_id = EntryId::from_index(
                u16::try_from(index).map_err(|_| OverlayError::Path(Error::OffsetOverflow))?,
            );
            let lower_entry = self
                .lower()
                .archive
                .entry_by_id(entry_id)
                .map_err(Error::from)?
                .ok_or(OverlayError::Path(Error::HandleMismatch))?;
            let next_index = index
                .checked_add(1)
                .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
            if let Some(name) =
                immediate_child_name(canonical.as_relative_bytes(), lower_entry.path())
            {
                if self.upper_contains_name(directory, name)? {
                    index = next_index;
                    continue;
                }
                let child = CanonicalPath::resolve_from(canonical, name)?;
                match self.lookup_canonical(child)? {
                    Some(OverlayNodeHandle::Immutable {
                        entry_id: visible_id,
                        ..
                    }) if visible_id == entry_id => {
                        let object = self
                            .lookup_canonical(child)?
                            .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                        let (kind, mode, size) = self.object_facts(object)?;
                        let entry = OverlayDirectoryEntry::new(object, name, kind, mode, size)?;
                        let next_cursor = lower_base
                            .checked_add(next_index)
                            .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
                        return Ok(Some(OverlayDirectoryScan {
                            entry,
                            directory,
                            start_cursor: cursor,
                            next_cursor,
                        }));
                    }
                    // Upper-only shadow or tombstone: the lower name is intentionally invisible.
                    Some(_) | None => {}
                }
            }
            index = next_index;
        }
        Ok(None)
    }

    fn directory_entry_from_upper_only(
        &self,
        directory: OverlayDirectoryHandle,
        cursor: usize,
    ) -> Result<Option<OverlayDirectoryScan>, OverlayError> {
        let upper_directory = self
            .mutable_directory_for(directory)?
            .ok_or(OverlayError::NotDirectory)?;
        let end_cursor = DOT_ENTRIES
            .checked_add(DENTRIES)
            .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
        if cursor > end_cursor {
            return Err(OverlayError::Path(Error::OffsetOverflow));
        }

        if cursor == 0 {
            let entry = self.directory_entry_for(directory.object(), b".")?;
            return Ok(Some(OverlayDirectoryScan {
                entry,
                directory,
                start_cursor: 0,
                next_cursor: 1,
            }));
        }
        if cursor == 1 {
            let parent = self.upper().parent_directory(upper_directory)?;
            let object = match self.upper().directory_node_handle(parent)? {
                None => OverlayNodeHandle::Root {
                    root: self.root_id(),
                    owner: self.upper().root_directory(),
                },
                Some(node) => self.logical_handle_for_upper(node)?,
            };
            let entry = self.directory_entry_for(object, b"..")?;
            return Ok(Some(OverlayDirectoryScan {
                entry,
                directory,
                start_cursor: 1,
                next_cursor: DOT_ENTRIES,
            }));
        }

        let mutable_cursor = cursor
            .checked_sub(DOT_ENTRIES)
            .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
        let Some(scan) = self
            .upper()
            .directory_entry_from(upper_directory, mutable_cursor)?
        else {
            return Ok(None);
        };
        let mutable_entry = scan.entry();
        let object = self.logical_handle_for_upper(mutable_entry.node())?;
        let metadata = mutable_entry.metadata();
        let entry = OverlayDirectoryEntry::new(
            object,
            mutable_entry.name(),
            mutable_kind(metadata.kind()),
            metadata.mode(),
            u64::try_from(metadata.size())
                .map_err(|_| OverlayError::Path(Error::OffsetOverflow))?,
        )?;
        let next_cursor = DOT_ENTRIES
            .checked_add(scan.next_cursor())
            .ok_or(OverlayError::Path(Error::OffsetOverflow))?;
        Ok(Some(OverlayDirectoryScan {
            entry,
            directory,
            start_cursor: cursor,
            next_cursor,
        }))
    }

    fn upper_contains_name(
        &self,
        directory: OverlayDirectoryHandle,
        name: &[u8],
    ) -> Result<bool, OverlayError> {
        let Some(upper_directory) = self.mutable_directory_for(directory)? else {
            return Ok(false);
        };
        let mut cursor = 0usize;
        while let Some(scan) = self.upper().directory_entry_from(upper_directory, cursor)? {
            if scan.entry().name() == name {
                return Ok(true);
            }
            cursor = scan.next_cursor();
        }
        Ok(false)
    }

    fn mutable_directory_for(
        &self,
        directory: OverlayDirectoryHandle,
    ) -> Result<Option<MutableDirectoryHandle>, OverlayError> {
        match directory.object() {
            OverlayNodeHandle::Root { .. } => Ok(Some(self.upper().root_directory())),
            OverlayNodeHandle::Mutable(node) => {
                Ok(Some(self.upper().directory_handle_from_node(node)?))
            }
            OverlayNodeHandle::Immutable { entry_id, kind, .. } => {
                if kind != NodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                self.bound_upper_for_entry(entry_id)
                    .map(|node| self.upper().directory_handle_from_node(node))
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }

    fn directory_canonical(
        &self,
        directory: OverlayDirectoryHandle,
    ) -> Result<CanonicalPath, OverlayError> {
        self.validate_handle_root(directory.object())?;
        match directory.object() {
            OverlayNodeHandle::Root { root, .. } => {
                if root != self.root_id() {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Ok(CanonicalPath::root())
            }
            OverlayNodeHandle::Mutable(_) => {
                // Pure upper directories have no lower pathname provenance and are handled by the
                // identity-only scan path before this helper is called.
                Err(OverlayError::Path(Error::HandleMismatch))
            }
            OverlayNodeHandle::Immutable {
                root,
                entry_id,
                kind,
                ..
            } => {
                if root != self.root_id() || kind != NodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                let entry = self
                    .lower()
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let node = Node::from_entry(entry);
                if node.kind() != NodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Ok(CanonicalPath::resolve_at(AT_FDCWD, entry.path())?)
            }
        }
    }

    fn directory_entry_for(
        &self,
        object: OverlayNodeHandle,
        name: &[u8],
    ) -> Result<OverlayDirectoryEntry, OverlayError> {
        let (kind, mode, size) = self.object_facts(object)?;
        OverlayDirectoryEntry::new(object, name, kind, mode, size)
    }

    fn object_facts(
        &self,
        object: OverlayNodeHandle,
    ) -> Result<(NodeKind, u32, u64), OverlayError> {
        self.validate_handle_root(object)?;
        match object {
            OverlayNodeHandle::Root { .. } => {
                let node = self.lower().lookup_at(AT_FDCWD, b"/")?;
                Ok((node.kind(), node.mode(), node.size()))
            }
            OverlayNodeHandle::Mutable(node) => {
                let metadata = self.upper().metadata(node)?;
                Ok((
                    mutable_kind(metadata.kind()),
                    metadata.mode(),
                    u64::try_from(metadata.size())
                        .map_err(|_| OverlayError::Path(Error::OffsetOverflow))?,
                ))
            }
            OverlayNodeHandle::Immutable { entry_id, kind, .. } => {
                if let Some(upper) = self.bound_upper_for_entry(entry_id) {
                    let metadata = self.upper().metadata(upper)?;
                    let current_kind = mutable_kind(metadata.kind());
                    if current_kind != kind {
                        return Err(OverlayError::Path(Error::HandleMismatch));
                    }
                    return Ok((
                        current_kind,
                        metadata.mode(),
                        u64::try_from(metadata.size())
                            .map_err(|_| OverlayError::Path(Error::OffsetOverflow))?,
                    ));
                }
                let entry = self
                    .lower()
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let node = Node::from_entry(entry);
                if node.kind() != kind {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Ok((kind, node.mode(), node.size()))
            }
        }
    }
}

const fn mutable_kind(kind: MutableNodeKind) -> NodeKind {
    match kind {
        MutableNodeKind::Regular => NodeKind::Regular,
        MutableNodeKind::Directory => NodeKind::Directory,
        MutableNodeKind::Symlink => NodeKind::Symlink,
    }
}

fn immediate_child_name<'a>(directory: &[u8], candidate: &'a [u8]) -> Option<&'a [u8]> {
    if candidate == b"." {
        return None;
    }
    let relative = if directory.is_empty() {
        candidate
    } else {
        if candidate.len() <= directory.len()
            || !candidate.starts_with(directory)
            || candidate.get(directory.len()) != Some(&b'/')
        {
            return None;
        }
        &candidate[directory.len() + 1..]
    };
    if relative.is_empty() || relative.len() > LINUX_NAME_MAX || relative.contains(&b'/') {
        return None;
    }
    Some(relative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_cpio::Archive;

    const HEADER_LEN: usize = 110;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const ROOT: RootId = RootId::new(91);
    const T: super::super::MutableTimestamp = super::super::MutableTimestamp {
        seconds: 1,
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
        entry(&mut out, b"etc/hidden", S_IFREG | 0o644, b"hidden");
        entry(&mut out, b"lower-only", S_IFREG | 0o644, b"lower");
        entry(&mut out, b"TRAILER!!!", 0, b"");
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        out
    }

    fn overlay(bytes: &[u8]) -> Overlay<'_> {
        Overlay::new(super::super::InitramfsRoot::new(
            Archive::parse(bytes).unwrap(),
            ROOT,
        ))
    }

    #[test]
    fn merged_scan_emits_upper_once_and_suppresses_tombstoned_lower_name() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.write_at(b"/etc/base", 0, b"UP", T).unwrap();
        overlay
            .create_regular_at(b"/etc/upper-only", 0o600, 0, 0, T)
            .unwrap();
        overlay.unlink_at(b"/etc/hidden", false).unwrap();

        let directory = overlay.open_directory_at(b"/etc").unwrap();
        let mut cursor = 0usize;
        let mut names = Vec::new();
        let mut base_count = 0usize;
        while let Some(scan) = overlay.directory_entry_from(directory, cursor).unwrap() {
            let entry = scan.entry();
            names.push(entry.name().to_vec());
            if entry.name() == b"base" {
                base_count += 1;
                assert!(matches!(
                    entry.object(),
                    OverlayNodeHandle::Immutable { .. }
                ));
            }
            assert!(scan.next_cursor() > cursor);
            cursor = scan.next_cursor();
        }

        assert_eq!(names.first().map(Vec::as_slice), Some(b".".as_slice()));
        assert_eq!(names.get(1).map(Vec::as_slice), Some(b"..".as_slice()));
        assert_eq!(base_count, 1);
        assert!(names.iter().any(|name| name.as_slice() == b"upper-only"));
        assert!(!names.iter().any(|name| name.as_slice() == b"hidden"));
    }

    #[test]
    fn retained_lower_directory_handle_sees_later_upper_children() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        let directory = overlay.open_directory_at(b"/etc").unwrap();
        assert!(matches!(
            directory.object(),
            OverlayNodeHandle::Immutable { .. }
        ));

        overlay
            .create_regular_at(b"/etc/after-open", 0o600, 0, 0, T)
            .unwrap();

        let mut cursor = 0usize;
        let mut saw_child = false;
        while let Some(scan) = overlay.directory_entry_from(directory, cursor).unwrap() {
            if scan.entry().name() == b"after-open" {
                saw_child = true;
                break;
            }
            cursor = scan.next_cursor();
        }
        assert!(saw_child);
        assert!(matches!(
            directory.object(),
            OverlayNodeHandle::Immutable { .. }
        ));
    }

    #[test]
    fn root_scan_keeps_lower_only_entry_and_upper_shadow_single() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.create_regular_at(b"/new", 0o600, 0, 0, T).unwrap();

        let root = overlay.open_directory_at(b"/").unwrap();
        let mut cursor = 0usize;
        let mut saw_new = 0usize;
        let mut saw_lower = 0usize;
        while let Some(scan) = overlay.directory_entry_from(root, cursor).unwrap() {
            match scan.entry().name() {
                b"new" => saw_new += 1,
                b"lower-only" => saw_lower += 1,
                _ => {}
            }
            cursor = scan.next_cursor();
        }
        assert_eq!(saw_new, 1);
        assert_eq!(saw_lower, 1);
    }

    #[test]
    fn pure_upper_scan_uses_live_parent_identity_after_rename() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.mkdir_at(b"/parent", 0o755, 0, 0, T).unwrap();
        overlay.mkdir_at(b"/parent/child", 0o755, 0, 0, T).unwrap();
        overlay
            .create_regular_at(b"/parent/child/upper", 0o600, 0, 0, T)
            .unwrap();

        let child = overlay.open_directory_at(b"/parent/child").unwrap();
        overlay.rename_at(b"/parent", b"/moved", false).unwrap();
        let moved = overlay.open_directory_at(b"/moved").unwrap();
        let parent = overlay.directory_entry_from(child, 1).unwrap().unwrap();
        assert_eq!(parent.entry().name(), b"..");
        assert_eq!(parent.entry().object(), moved.object());

        let mut cursor = DOT_ENTRIES;
        let mut names = Vec::new();
        while let Some(scan) = overlay.directory_entry_from(child, cursor).unwrap() {
            names.push(scan.entry().name().to_vec());
            cursor = scan.next_cursor();
        }
        assert_eq!(names, vec![b"upper".to_vec()]);
    }
}
