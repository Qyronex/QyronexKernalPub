// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Linux component-name limit used by the bounded mutable namespace.
pub const LINUX_NAME_MAX: usize = 255;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const MODE_MUTABLE_BITS: u32 = 0o7777;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutableError {
    NodeTableFull,
    DirectoryEntryTableFull,
    InvalidName,
    PathTooLong,
    NotFound,
    AlreadyExists,
    BadNode,
    NotDirectory,
    IsDirectory,
    DirectoryNotEmpty,
    NotRegular,
    NotSymlink,
    FileTooLarge,
    InvalidOffset,
    LinkOverflow,
    OpenReferenceOverflow,
    DirectoryCycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutableNodeId {
    index: usize,
    generation: u64,
}

impl MutableNodeId {
    pub const fn index(self) -> usize {
        self.index
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutableDirectoryId {
    Root,
    Node(MutableNodeId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutableNodeKind {
    Regular,
    Directory,
    Symlink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutableTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl MutableTimestamp {
    pub const ZERO: Self = Self {
        seconds: 0,
        nanoseconds: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutableMetadata {
    kind: MutableNodeKind,
    mode: u32,
    uid: u32,
    gid: u32,
    size: usize,
    links: u32,
    atime: MutableTimestamp,
    mtime: MutableTimestamp,
    ctime: MutableTimestamp,
}

impl MutableMetadata {
    pub const fn kind(self) -> MutableNodeKind {
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

    pub const fn size(self) -> usize {
        self.size
    }

    pub const fn links(self) -> u32 {
        self.links
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Name {
    bytes: [u8; LINUX_NAME_MAX],
    len: u8,
}

impl Name {
    const EMPTY: Self = Self {
        bytes: [0; LINUX_NAME_MAX],
        len: 0,
    };

    fn new(bytes: &[u8]) -> Result<Self, MutableError> {
        if bytes.is_empty()
            || bytes.len() > LINUX_NAME_MAX
            || bytes.contains(&0)
            || bytes.contains(&b'/')
            || bytes == b"."
            || bytes == b".."
        {
            return Err(MutableError::InvalidName);
        }
        let mut name = Self::EMPTY;
        name.bytes[..bytes.len()].copy_from_slice(bytes);
        name.len = u8::try_from(bytes.len()).map_err(|_| MutableError::InvalidName)?;
        Ok(name)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy)]
struct CreateSpec<'a> {
    kind: MutableNodeKind,
    mode: u32,
    uid: u32,
    gid: u32,
    now: MutableTimestamp,
    initial_data: &'a [u8],
}

#[derive(Clone, Copy)]
struct NodeState<const FILE_BYTES: usize> {
    metadata: MutableMetadata,
    open_references: u32,
    data: [u8; FILE_BYTES],
}

impl<const FILE_BYTES: usize> NodeState<FILE_BYTES> {
    const EMPTY: Self = Self {
        metadata: MutableMetadata {
            kind: MutableNodeKind::Regular,
            mode: S_IFREG,
            uid: 0,
            gid: 0,
            size: 0,
            links: 0,
            atime: MutableTimestamp::ZERO,
            mtime: MutableTimestamp::ZERO,
            ctime: MutableTimestamp::ZERO,
        },
        open_references: 0,
        data: [0; FILE_BYTES],
    };
}

#[derive(Clone, Copy)]
struct NodeSlot<const FILE_BYTES: usize> {
    generation: u64,
    retired: bool,
    state: Option<NodeState<FILE_BYTES>>,
}

impl<const FILE_BYTES: usize> NodeSlot<FILE_BYTES> {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        state: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryEntry {
    parent: MutableDirectoryId,
    name: Name,
    node: MutableNodeId,
}

#[derive(Clone, Copy)]
struct DirectoryEntrySlot {
    state: Option<DirectoryEntry>,
}

impl DirectoryEntrySlot {
    const EMPTY: Self = Self { state: None };
}

/// Bounded mutable namespace owner for the final Step-29 filesystem slice.
///
/// This owner stores generation-safe inode identities separately from directory entries so hard
/// links and rename never duplicate file data. It deliberately accepts only already-resolved parent
/// directory identities plus one validated component name: canonical path traversal remains owned by
/// the existing VFS resolver. Protected initramfs bytes are never referenced or mutated here.
pub struct MutableNamespace<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize> {
    nodes: [NodeSlot<FILE_BYTES>; NODES],
    dentries: [DirectoryEntrySlot; DENTRIES],
}

impl<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>
    MutableNamespace<NODES, DENTRIES, FILE_BYTES>
{
    pub const fn new() -> Self {
        Self {
            nodes: [NodeSlot::EMPTY; NODES],
            dentries: [DirectoryEntrySlot::EMPTY; DENTRIES],
        }
    }

    pub fn lookup(
        &self,
        parent: MutableDirectoryId,
        name: &[u8],
    ) -> Result<MutableNodeId, MutableError> {
        self.validate_parent(parent)?;
        let name = Name::new(name)?;
        self.find_dentry(parent, name)
            .map(|(_, entry)| entry.node)
            .ok_or(MutableError::NotFound)
    }

    pub fn metadata(&self, node: MutableNodeId) -> Result<MutableMetadata, MutableError> {
        Ok(self.node_state(node)?.metadata)
    }

    pub fn create_regular(
        &mut self,
        parent: MutableDirectoryId,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeId, MutableError> {
        self.create_node(
            parent,
            name,
            CreateSpec {
                kind: MutableNodeKind::Regular,
                mode,
                uid,
                gid,
                now,
                initial_data: &[],
            },
        )
    }

    pub fn create_directory(
        &mut self,
        parent: MutableDirectoryId,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeId, MutableError> {
        self.create_node(
            parent,
            name,
            CreateSpec {
                kind: MutableNodeKind::Directory,
                mode,
                uid,
                gid,
                now,
                initial_data: &[],
            },
        )
    }

    pub fn create_symlink(
        &mut self,
        parent: MutableDirectoryId,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeId, MutableError> {
        if target.len() > FILE_BYTES {
            return Err(MutableError::FileTooLarge);
        }
        self.create_node(
            parent,
            name,
            CreateSpec {
                kind: MutableNodeKind::Symlink,
                mode: 0o777,
                uid,
                gid,
                now,
                initial_data: target,
            },
        )
    }

    pub fn link(
        &mut self,
        node: MutableNodeId,
        parent: MutableDirectoryId,
        name: &[u8],
    ) -> Result<(), MutableError> {
        self.validate_parent(parent)?;
        let name = Name::new(name)?;
        if self.find_dentry(parent, name).is_some() {
            return Err(MutableError::AlreadyExists);
        }
        if self.node_state(node)?.metadata.kind == MutableNodeKind::Directory {
            return Err(MutableError::IsDirectory);
        }
        let dentry_index = self.dentry_candidate()?;
        let links = self
            .node_state(node)?
            .metadata
            .links
            .checked_add(1)
            .ok_or(MutableError::LinkOverflow)?;

        self.node_state_mut(node)?.metadata.links = links;
        self.dentries[dentry_index].state = Some(DirectoryEntry { parent, name, node });
        Ok(())
    }

    pub fn rename(
        &mut self,
        old_parent: MutableDirectoryId,
        old_name: &[u8],
        new_parent: MutableDirectoryId,
        new_name: &[u8],
        no_replace: bool,
    ) -> Result<(), MutableError> {
        self.validate_parent(old_parent)?;
        self.validate_parent(new_parent)?;
        let old_name = Name::new(old_name)?;
        let new_name = Name::new(new_name)?;
        let (old_index, old_entry) = self
            .find_dentry(old_parent, old_name)
            .ok_or(MutableError::NotFound)?;
        let source_kind = self.node_state(old_entry.node)?.metadata.kind;

        if source_kind == MutableNodeKind::Directory {
            self.validate_directory_move(old_entry.node, new_parent)?;
        }

        if let Some((target_index, target_entry)) = self.find_dentry(new_parent, new_name) {
            if target_entry.node == old_entry.node {
                return Ok(());
            }
            if no_replace {
                return Err(MutableError::AlreadyExists);
            }
            let target_kind = self.node_state(target_entry.node)?.metadata.kind;
            match (source_kind, target_kind) {
                (MutableNodeKind::Directory, MutableNodeKind::Directory) => {
                    if !self.directory_is_empty(target_entry.node)? {
                        return Err(MutableError::DirectoryNotEmpty);
                    }
                }
                (MutableNodeKind::Directory, _) => return Err(MutableError::NotDirectory),
                (_, MutableNodeKind::Directory) => return Err(MutableError::IsDirectory),
                _ => {}
            }

            self.dentries[target_index].state = Some(DirectoryEntry {
                parent: new_parent,
                name: new_name,
                node: old_entry.node,
            });
            self.dentries[old_index].state = None;
            self.drop_link(target_entry.node)?;
            return Ok(());
        }

        self.dentries[old_index].state = Some(DirectoryEntry {
            parent: new_parent,
            name: new_name,
            node: old_entry.node,
        });
        Ok(())
    }

    pub fn unlink(
        &mut self,
        parent: MutableDirectoryId,
        name: &[u8],
        remove_directory: bool,
    ) -> Result<MutableNodeId, MutableError> {
        self.validate_parent(parent)?;
        let name = Name::new(name)?;
        let (index, entry) = self
            .find_dentry(parent, name)
            .ok_or(MutableError::NotFound)?;
        let kind = self.node_state(entry.node)?.metadata.kind;
        match (kind, remove_directory) {
            (MutableNodeKind::Directory, false) => return Err(MutableError::IsDirectory),
            (MutableNodeKind::Directory, true) => {
                if !self.directory_is_empty(entry.node)? {
                    return Err(MutableError::DirectoryNotEmpty);
                }
            }
            (_, true) => return Err(MutableError::NotDirectory),
            _ => {}
        }

        self.dentries[index].state = None;
        self.drop_link(entry.node)?;
        Ok(entry.node)
    }

    pub fn retain_open(&mut self, node: MutableNodeId) -> Result<(), MutableError> {
        let state = self.node_state_mut(node)?;
        state.open_references = state
            .open_references
            .checked_add(1)
            .ok_or(MutableError::OpenReferenceOverflow)?;
        Ok(())
    }

    pub fn release_open(&mut self, node: MutableNodeId) -> Result<(), MutableError> {
        let state = self.node_state_mut(node)?;
        if state.open_references == 0 {
            return Err(MutableError::BadNode);
        }
        state.open_references -= 1;
        self.reclaim_if_unlinked(node)
    }

    pub fn read(
        &self,
        node: MutableNodeId,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, MutableError> {
        let state = self.node_state(node)?;
        if state.metadata.kind != MutableNodeKind::Regular {
            return Err(MutableError::NotRegular);
        }
        let start = usize::try_from(offset).map_err(|_| MutableError::InvalidOffset)?;
        if start >= state.metadata.size {
            return Ok(0);
        }
        let count = core::cmp::min(output.len(), state.metadata.size - start);
        output[..count].copy_from_slice(&state.data[start..start + count]);
        Ok(count)
    }

    pub fn write(
        &mut self,
        node: MutableNodeId,
        offset: u64,
        input: &[u8],
        now: MutableTimestamp,
    ) -> Result<usize, MutableError> {
        let state = self.node_state_mut(node)?;
        if state.metadata.kind != MutableNodeKind::Regular {
            return Err(MutableError::NotRegular);
        }
        let start = usize::try_from(offset).map_err(|_| MutableError::InvalidOffset)?;
        if start > FILE_BYTES {
            return Err(MutableError::FileTooLarge);
        }
        if input.is_empty() {
            return Ok(0);
        }
        let end = start
            .checked_add(input.len())
            .ok_or(MutableError::FileTooLarge)?;
        if end > FILE_BYTES {
            return Err(MutableError::FileTooLarge);
        }
        if start > state.metadata.size {
            state.data[state.metadata.size..start].fill(0);
        }
        state.data[start..end].copy_from_slice(input);
        state.metadata.size = core::cmp::max(state.metadata.size, end);
        state.metadata.mtime = now;
        state.metadata.ctime = now;
        Ok(input.len())
    }

    pub fn truncate(
        &mut self,
        node: MutableNodeId,
        length: u64,
        now: MutableTimestamp,
    ) -> Result<(), MutableError> {
        let state = self.node_state_mut(node)?;
        if state.metadata.kind != MutableNodeKind::Regular {
            return Err(MutableError::NotRegular);
        }
        let length = usize::try_from(length).map_err(|_| MutableError::FileTooLarge)?;
        if length > FILE_BYTES {
            return Err(MutableError::FileTooLarge);
        }
        if length > state.metadata.size {
            state.data[state.metadata.size..length].fill(0);
        } else {
            state.data[length..state.metadata.size].fill(0);
        }
        state.metadata.size = length;
        state.metadata.mtime = now;
        state.metadata.ctime = now;
        Ok(())
    }

    pub fn readlink(&self, node: MutableNodeId, output: &mut [u8]) -> Result<usize, MutableError> {
        let state = self.node_state(node)?;
        if state.metadata.kind != MutableNodeKind::Symlink {
            return Err(MutableError::NotSymlink);
        }
        let count = core::cmp::min(output.len(), state.metadata.size);
        output[..count].copy_from_slice(&state.data[..count]);
        Ok(count)
    }

    pub fn chmod(
        &mut self,
        node: MutableNodeId,
        mode: u32,
        now: MutableTimestamp,
    ) -> Result<(), MutableError> {
        let state = self.node_state_mut(node)?;
        state.metadata.mode = (state.metadata.mode & S_IFMT) | (mode & MODE_MUTABLE_BITS);
        state.metadata.ctime = now;
        Ok(())
    }

    pub fn chown(
        &mut self,
        node: MutableNodeId,
        uid: Option<u32>,
        gid: Option<u32>,
        now: MutableTimestamp,
    ) -> Result<(), MutableError> {
        let state = self.node_state_mut(node)?;
        if let Some(uid) = uid {
            state.metadata.uid = uid;
        }
        if let Some(gid) = gid {
            state.metadata.gid = gid;
        }
        state.metadata.ctime = now;
        Ok(())
    }

    pub fn set_times(
        &mut self,
        node: MutableNodeId,
        atime: MutableTimestamp,
        mtime: MutableTimestamp,
        ctime: MutableTimestamp,
    ) -> Result<(), MutableError> {
        let state = self.node_state_mut(node)?;
        state.metadata.atime = atime;
        state.metadata.mtime = mtime;
        state.metadata.ctime = ctime;
        Ok(())
    }

    pub fn directory_is_empty(&self, node: MutableNodeId) -> Result<bool, MutableError> {
        if self.node_state(node)?.metadata.kind != MutableNodeKind::Directory {
            return Err(MutableError::NotDirectory);
        }
        Ok(!self.dentries.iter().any(|slot| {
            slot.state
                .is_some_and(|entry| entry.parent == MutableDirectoryId::Node(node))
        }))
    }

    /// Reconstructs the current absolute pathname of a live mutable directory from its generation-
    /// safe identity and the current dentry graph. Rename of the directory or any ancestor is
    /// reflected immediately. A retained-but-unlinked directory has no dentry path and fails with
    /// `BadNode` rather than returning a stale pathname.
    pub(crate) fn write_directory_path(
        &self,
        mut directory: MutableDirectoryId,
        output: &mut [u8],
    ) -> Result<usize, MutableError> {
        let mut chain = [Name::EMPTY; NODES];
        let mut depth = 0usize;

        for _ in 0..=NODES {
            match directory {
                MutableDirectoryId::Root => break,
                MutableDirectoryId::Node(node) => {
                    if self.node_state(node)?.metadata.kind != MutableNodeKind::Directory {
                        return Err(MutableError::NotDirectory);
                    }
                    let entry = self
                        .dentries
                        .iter()
                        .find_map(|slot| slot.state.filter(|entry| entry.node == node))
                        .ok_or(MutableError::BadNode)?;
                    if depth == NODES {
                        return Err(MutableError::DirectoryCycle);
                    }
                    chain[depth] = entry.name;
                    depth += 1;
                    directory = entry.parent;
                }
            }
        }
        if directory != MutableDirectoryId::Root {
            return Err(MutableError::DirectoryCycle);
        }

        let mut required = 1usize;
        for index in (0..depth).rev() {
            if index != depth - 1 {
                required = required.checked_add(1).ok_or(MutableError::PathTooLong)?;
            }
            required = required
                .checked_add(chain[index].as_bytes().len())
                .ok_or(MutableError::PathTooLong)?;
        }
        if output.len() < required {
            return Err(MutableError::PathTooLong);
        }

        output[0] = b'/';
        let mut cursor = 1usize;
        for index in (0..depth).rev() {
            if cursor != 1 {
                output[cursor] = b'/';
                cursor += 1;
            }
            let name = chain[index].as_bytes();
            let end = cursor
                .checked_add(name.len())
                .ok_or(MutableError::PathTooLong)?;
            output[cursor..end].copy_from_slice(name);
            cursor = end;
        }
        Ok(cursor)
    }

    fn create_node(
        &mut self,
        parent: MutableDirectoryId,
        name: &[u8],
        spec: CreateSpec<'_>,
    ) -> Result<MutableNodeId, MutableError> {
        self.validate_parent(parent)?;
        let name = Name::new(name)?;
        if self.find_dentry(parent, name).is_some() {
            return Err(MutableError::AlreadyExists);
        }
        if spec.initial_data.len() > FILE_BYTES {
            return Err(MutableError::FileTooLarge);
        }
        let node = self.node_candidate()?;
        let dentry_index = self.dentry_candidate()?;
        let file_type = match spec.kind {
            MutableNodeKind::Regular => S_IFREG,
            MutableNodeKind::Directory => S_IFDIR,
            MutableNodeKind::Symlink => S_IFLNK,
        };
        let slot = &mut self.nodes[node.index];
        slot.generation = node.generation;
        let mut state = NodeState::EMPTY;
        state.metadata = MutableMetadata {
            kind: spec.kind,
            mode: file_type | (spec.mode & MODE_MUTABLE_BITS),
            uid: spec.uid,
            gid: spec.gid,
            size: spec.initial_data.len(),
            links: 1,
            atime: spec.now,
            mtime: spec.now,
            ctime: spec.now,
        };
        state.data[..spec.initial_data.len()].copy_from_slice(spec.initial_data);
        slot.state = Some(state);
        self.dentries[dentry_index].state = Some(DirectoryEntry { parent, name, node });
        Ok(node)
    }

    fn validate_parent(&self, parent: MutableDirectoryId) -> Result<(), MutableError> {
        if let MutableDirectoryId::Node(node) = parent
            && self.node_state(node)?.metadata.kind != MutableNodeKind::Directory
        {
            return Err(MutableError::NotDirectory);
        }
        Ok(())
    }

    fn validate_directory_move(
        &self,
        source: MutableNodeId,
        mut destination: MutableDirectoryId,
    ) -> Result<(), MutableError> {
        for _ in 0..=NODES {
            match destination {
                MutableDirectoryId::Root => return Ok(()),
                MutableDirectoryId::Node(node) if node == source => {
                    return Err(MutableError::DirectoryCycle);
                }
                MutableDirectoryId::Node(node) => {
                    destination = self.directory_parent(node)?;
                }
            }
        }
        Err(MutableError::DirectoryCycle)
    }

    fn directory_parent(&self, node: MutableNodeId) -> Result<MutableDirectoryId, MutableError> {
        if self.node_state(node)?.metadata.kind != MutableNodeKind::Directory {
            return Err(MutableError::NotDirectory);
        }
        self.dentries
            .iter()
            .find_map(|slot| {
                slot.state
                    .filter(|entry| entry.node == node)
                    .map(|entry| entry.parent)
            })
            .ok_or(MutableError::BadNode)
    }

    fn find_dentry(
        &self,
        parent: MutableDirectoryId,
        name: Name,
    ) -> Option<(usize, DirectoryEntry)> {
        self.dentries.iter().enumerate().find_map(|(index, slot)| {
            slot.state
                .filter(|entry| entry.parent == parent && entry.name == name)
                .map(|entry| (index, entry))
        })
    }

    fn node_candidate(&self) -> Result<MutableNodeId, MutableError> {
        self.nodes
            .iter()
            .enumerate()
            .find_map(|(index, slot)| {
                if slot.retired || slot.state.is_some() {
                    return None;
                }
                slot.generation
                    .checked_add(1)
                    .map(|generation| MutableNodeId { index, generation })
            })
            .ok_or(MutableError::NodeTableFull)
    }

    fn dentry_candidate(&self) -> Result<usize, MutableError> {
        self.dentries
            .iter()
            .position(|slot| slot.state.is_none())
            .ok_or(MutableError::DirectoryEntryTableFull)
    }

    fn node_state(&self, node: MutableNodeId) -> Result<&NodeState<FILE_BYTES>, MutableError> {
        let slot = self.nodes.get(node.index).ok_or(MutableError::BadNode)?;
        if slot.retired || slot.generation != node.generation {
            return Err(MutableError::BadNode);
        }
        slot.state.as_ref().ok_or(MutableError::BadNode)
    }

    fn node_state_mut(
        &mut self,
        node: MutableNodeId,
    ) -> Result<&mut NodeState<FILE_BYTES>, MutableError> {
        let slot = self
            .nodes
            .get_mut(node.index)
            .ok_or(MutableError::BadNode)?;
        if slot.retired || slot.generation != node.generation {
            return Err(MutableError::BadNode);
        }
        slot.state.as_mut().ok_or(MutableError::BadNode)
    }

    fn drop_link(&mut self, node: MutableNodeId) -> Result<(), MutableError> {
        let state = self.node_state_mut(node)?;
        if state.metadata.links == 0 {
            return Err(MutableError::BadNode);
        }
        state.metadata.links -= 1;
        self.reclaim_if_unlinked(node)
    }

    fn reclaim_if_unlinked(&mut self, node: MutableNodeId) -> Result<(), MutableError> {
        let reclaim = {
            let state = self.node_state(node)?;
            state.metadata.links == 0 && state.open_references == 0
        };
        if !reclaim {
            return Ok(());
        }
        let slot = &mut self.nodes[node.index];
        slot.state = None;
        if slot.generation == u64::MAX {
            slot.retired = true;
        }
        Ok(())
    }
}

impl<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize> Default
    for MutableNamespace<NODES, DENTRIES, FILE_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Namespace = MutableNamespace<8, 12, 32>;
    const T1: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 2,
    };
    const T2: MutableTimestamp = MutableTimestamp {
        seconds: 3,
        nanoseconds: 4,
    };

    #[test]
    fn create_write_truncate_and_generation_reuse_are_bounded() {
        let mut ns = Namespace::new();
        let file = ns
            .create_regular(MutableDirectoryId::Root, b"file", 0o640, 10, 20, T1)
            .unwrap();
        assert_eq!(file.generation(), 1);
        assert_eq!(ns.write(file, 2, b"xy", T2), Ok(2));
        let mut bytes = [0xaa; 4];
        assert_eq!(ns.read(file, 0, &mut bytes), Ok(4));
        assert_eq!(&bytes, b"\0\0xy");
        ns.truncate(file, 2, T2).unwrap();
        let mut short = [0xaa; 4];
        assert_eq!(ns.read(file, 0, &mut short), Ok(2));
        assert_eq!(&short[..2], b"\0\0");

        ns.unlink(MutableDirectoryId::Root, b"file", false).unwrap();
        assert_eq!(ns.metadata(file), Err(MutableError::BadNode));
        let reused = ns
            .create_regular(MutableDirectoryId::Root, b"next", 0o600, 0, 0, T1)
            .unwrap();
        assert_eq!(reused.index(), file.index());
        assert_eq!(reused.generation(), file.generation() + 1);
    }

    #[test]
    fn zero_length_write_beyond_eof_is_a_true_noop() {
        let mut ns = Namespace::new();
        let file = ns
            .create_regular(MutableDirectoryId::Root, b"file", 0o640, 10, 20, T1)
            .unwrap();
        assert_eq!(ns.write(file, 0, b"abc", T1), Ok(3));
        let before = ns.metadata(file).unwrap();
        let mut bytes_before = [0u8; 3];
        assert_eq!(ns.read(file, 0, &mut bytes_before), Ok(3));

        assert_eq!(ns.write(file, 16, b"", T2), Ok(0));
        assert_eq!(ns.metadata(file), Ok(before));
        let mut bytes_after = [0u8; 3];
        assert_eq!(ns.read(file, 0, &mut bytes_after), Ok(3));
        assert_eq!(bytes_after, bytes_before);
    }

    #[test]
    fn live_directory_path_tracks_rename_and_rejects_unreachable_snapshot() {
        let mut ns = Namespace::new();
        let parent = ns
            .create_directory(MutableDirectoryId::Root, b"parent", 0o755, 0, 0, T1)
            .unwrap();
        let child = ns
            .create_directory(MutableDirectoryId::Node(parent), b"child", 0o755, 0, 0, T1)
            .unwrap();
        let mut path = [0u8; 64];
        assert_eq!(
            ns.write_directory_path(MutableDirectoryId::Node(child), &mut path),
            Ok(13)
        );
        assert_eq!(&path[..13], b"/parent/child");

        ns.rename(
            MutableDirectoryId::Root,
            b"parent",
            MutableDirectoryId::Root,
            b"moved",
            false,
        )
        .unwrap();
        assert_eq!(
            ns.write_directory_path(MutableDirectoryId::Node(child), &mut path),
            Ok(12)
        );
        assert_eq!(&path[..12], b"/moved/child");

        ns.retain_open(child).unwrap();
        ns.unlink(MutableDirectoryId::Node(parent), b"child", true)
            .unwrap();
        assert_eq!(
            ns.write_directory_path(MutableDirectoryId::Node(child), &mut path),
            Err(MutableError::BadNode)
        );
        ns.release_open(child).unwrap();
    }

    #[test]
    fn open_reference_keeps_unlinked_inode_live_until_release() {
        let mut ns = Namespace::new();
        let file = ns
            .create_regular(MutableDirectoryId::Root, b"file", 0o600, 0, 0, T1)
            .unwrap();
        ns.retain_open(file).unwrap();
        ns.unlink(MutableDirectoryId::Root, b"file", false).unwrap();
        assert_eq!(ns.metadata(file).unwrap().links(), 0);
        ns.write(file, 0, b"live", T2).unwrap();
        ns.release_open(file).unwrap();
        assert_eq!(ns.metadata(file), Err(MutableError::BadNode));
    }

    #[test]
    fn hard_links_share_one_inode_and_rename_preserves_identity() {
        let mut ns = Namespace::new();
        let file = ns
            .create_regular(MutableDirectoryId::Root, b"alpha", 0o644, 0, 0, T1)
            .unwrap();
        ns.link(file, MutableDirectoryId::Root, b"hard").unwrap();
        assert_eq!(ns.metadata(file).unwrap().links(), 2);
        ns.rename(
            MutableDirectoryId::Root,
            b"hard",
            MutableDirectoryId::Root,
            b"renamed",
            false,
        )
        .unwrap();
        assert_eq!(ns.lookup(MutableDirectoryId::Root, b"renamed"), Ok(file));
        ns.unlink(MutableDirectoryId::Root, b"alpha", false)
            .unwrap();
        assert_eq!(ns.metadata(file).unwrap().links(), 1);
        assert_eq!(ns.lookup(MutableDirectoryId::Root, b"renamed"), Ok(file));
    }

    #[test]
    fn directory_removal_requires_empty_and_rename_rejects_cycles() {
        let mut ns = Namespace::new();
        let parent = ns
            .create_directory(MutableDirectoryId::Root, b"parent", 0o755, 0, 0, T1)
            .unwrap();
        let child = ns
            .create_directory(MutableDirectoryId::Node(parent), b"child", 0o755, 0, 0, T1)
            .unwrap();
        assert_eq!(
            ns.unlink(MutableDirectoryId::Root, b"parent", true),
            Err(MutableError::DirectoryNotEmpty)
        );
        assert_eq!(
            ns.rename(
                MutableDirectoryId::Root,
                b"parent",
                MutableDirectoryId::Node(child),
                b"moved",
                false,
            ),
            Err(MutableError::DirectoryCycle)
        );
        ns.unlink(MutableDirectoryId::Node(parent), b"child", true)
            .unwrap();
        ns.unlink(MutableDirectoryId::Root, b"parent", true)
            .unwrap();
    }

    #[test]
    fn symlink_target_and_metadata_mutations_are_inode_owned() {
        let mut ns = Namespace::new();
        let link = ns
            .create_symlink(MutableDirectoryId::Root, b"link", b"../target", 7, 8, T1)
            .unwrap();
        let mut target = [0u8; 16];
        assert_eq!(ns.readlink(link, &mut target), Ok(9));
        assert_eq!(&target[..9], b"../target");
        ns.chmod(link, 0o700, T2).unwrap();
        ns.chown(link, Some(9), None, T2).unwrap();
        let metadata = ns.metadata(link).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), 9);
        assert_eq!(metadata.gid(), 8);
        assert_eq!(metadata.ctime(), T2);
    }

    #[test]
    fn creation_preflights_both_capacity_domains_without_partial_publish() {
        type Tiny = MutableNamespace<2, 1, 8>;
        let mut ns = Tiny::new();
        let first = ns
            .create_regular(MutableDirectoryId::Root, b"a", 0o600, 0, 0, T1)
            .unwrap();
        assert_eq!(
            ns.create_regular(MutableDirectoryId::Root, b"b", 0o600, 0, 0, T1),
            Err(MutableError::DirectoryEntryTableFull)
        );
        assert_eq!(ns.metadata(first).unwrap().links(), 1);
        assert_eq!(ns.lookup(MutableDirectoryId::Root, b"a"), Ok(first));
    }
}
