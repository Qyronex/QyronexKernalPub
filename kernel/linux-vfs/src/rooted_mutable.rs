// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::sync::atomic::{AtomicU64, Ordering};

use super::mutable::{
    MutableDirectoryId, MutableError, MutableMetadata, MutableNamespace, MutableNodeId,
    MutableNodeKind, MutableTimestamp,
};
use super::{AT_FDCWD, CanonicalPath, MAX_PATH_BYTES, RootId};

static NEXT_MUTABLE_NAMESPACE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MutableNamespaceId(u64);

fn allocate_namespace_id() -> MutableNamespaceId {
    let id = NEXT_MUTABLE_NAMESPACE_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .unwrap_or_else(|_| panic!("mutable namespace id space exhausted"));
    MutableNamespaceId(id)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootedMutableError {
    RootMismatch,
    NamespaceMismatch,
    Path(super::Error),
    Mutable(MutableError),
}

impl From<MutableError> for RootedMutableError {
    fn from(value: MutableError) -> Self {
        Self::Mutable(value)
    }
}

impl From<super::Error> for RootedMutableError {
    fn from(value: super::Error) -> Self {
        Self::Path(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutableNodeHandle {
    root: RootId,
    namespace: MutableNamespaceId,
    node: MutableNodeId,
}

impl MutableNodeHandle {
    pub const fn root_id(self) -> RootId {
        self.root
    }

    pub const fn slot(self) -> usize {
        self.node.index()
    }

    pub const fn generation(self) -> u64 {
        self.node.generation()
    }
}

/// Root-qualified, generation-safe mutable directory identity.
///
/// No pathname text is part of the authority. This keeps traversal valid even when the directory's
/// absolute pathname exceeds Linux PATH_MAX. Text reconstruction is an explicit presentation step
/// through [`RootedMutableNamespace::directory_canonical_path`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutableDirectoryHandle {
    root: RootId,
    namespace: MutableNamespaceId,
    directory: MutableDirectoryId,
}

impl MutableDirectoryHandle {
    pub const fn root_id(self) -> RootId {
        self.root
    }
}

pub struct RootedMutableNamespace<
    const NODES: usize,
    const DENTRIES: usize,
    const FILE_BYTES: usize,
> {
    root: RootId,
    namespace: AtomicU64,
    inner: MutableNamespace<NODES, DENTRIES, FILE_BYTES>,
}

impl<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>
    RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>
{
    pub const fn new(root: RootId) -> Self {
        Self {
            root,
            namespace: AtomicU64::new(0),
            inner: MutableNamespace::new(),
        }
    }

    pub const fn root_id(&self) -> RootId {
        self.root
    }

    pub fn root_directory(&self) -> MutableDirectoryHandle {
        MutableDirectoryHandle {
            root: self.root,
            namespace: self.namespace_id(),
            directory: MutableDirectoryId::Root,
        }
    }

    /// Opens one child directory strictly from the live parent identity. No absolute path is
    /// reconstructed, so a legal component walk is independent of the textual depth of the cwd.
    pub fn open_directory(
        &self,
        parent: MutableDirectoryHandle,
        name: &[u8],
    ) -> Result<MutableDirectoryHandle, RootedMutableError> {
        let parent_id = self.checked_live_directory(parent)?;
        let node = self.inner.lookup(parent_id, name)?;
        if self.inner.metadata(node)?.kind() != MutableNodeKind::Directory {
            return Err(MutableError::NotDirectory.into());
        }
        Ok(MutableDirectoryHandle {
            root: self.root,
            namespace: self.namespace_id(),
            directory: MutableDirectoryId::Node(node),
        })
    }

    /// Revalidates a directory identity without materializing its pathname.
    pub fn refresh_directory(
        &self,
        handle: MutableDirectoryHandle,
    ) -> Result<MutableDirectoryHandle, RootedMutableError> {
        self.checked_live_directory(handle)?;
        Ok(handle)
    }

    /// Reconstructs the current absolute pathname only for presentation/getcwd-style consumers.
    /// Identity-based namespace work does not call this method. A reachable directory whose text
    /// exceeds the bounded PATH_MAX representation returns the public pathname error while stale or
    /// unreachable identity failures retain their structured mutable-namespace error.
    pub fn directory_canonical_path(
        &self,
        handle: MutableDirectoryHandle,
    ) -> Result<CanonicalPath, RootedMutableError> {
        let directory = self.checked_live_directory(handle)?;
        let mut absolute = [0u8; MAX_PATH_BYTES + 1];
        let len = match self.inner.write_directory_path(directory, &mut absolute) {
            Ok(len) => len,
            Err(MutableError::PathTooLong) => {
                return Err(RootedMutableError::Path(super::Error::PathTooLong));
            }
            Err(error) => return Err(error.into()),
        };
        CanonicalPath::resolve_at(AT_FDCWD, &absolute[..len]).map_err(Into::into)
    }

    pub fn lookup(
        &self,
        parent: MutableDirectoryHandle,
        name: &[u8],
    ) -> Result<MutableNodeHandle, RootedMutableError> {
        let parent = self.checked_live_directory(parent)?;
        let node = self.inner.lookup(parent, name)?;
        Ok(self.wrap_node(node))
    }

    pub fn metadata(&self, node: MutableNodeHandle) -> Result<MutableMetadata, RootedMutableError> {
        Ok(self.inner.metadata(self.checked_node(node)?)?)
    }

    pub fn create_regular(
        &mut self,
        parent: MutableDirectoryHandle,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, RootedMutableError> {
        let parent = self.checked_live_directory(parent)?;
        let node = self
            .inner
            .create_regular(parent, name, mode, uid, gid, now)?;
        Ok(self.wrap_node(node))
    }

    pub fn create_directory(
        &mut self,
        parent: MutableDirectoryHandle,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, RootedMutableError> {
        let parent = self.checked_live_directory(parent)?;
        let node = self
            .inner
            .create_directory(parent, name, mode, uid, gid, now)?;
        Ok(self.wrap_node(node))
    }

    pub fn create_symlink(
        &mut self,
        parent: MutableDirectoryHandle,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, RootedMutableError> {
        let parent = self.checked_live_directory(parent)?;
        let node = self
            .inner
            .create_symlink(parent, name, target, uid, gid, now)?;
        Ok(self.wrap_node(node))
    }

    pub fn link(
        &mut self,
        node: MutableNodeHandle,
        parent: MutableDirectoryHandle,
        name: &[u8],
    ) -> Result<(), RootedMutableError> {
        let node = self.checked_node(node)?;
        let parent = self.checked_live_directory(parent)?;
        Ok(self.inner.link(node, parent, name)?)
    }

    pub fn rename(
        &mut self,
        old_parent: MutableDirectoryHandle,
        old_name: &[u8],
        new_parent: MutableDirectoryHandle,
        new_name: &[u8],
        no_replace: bool,
    ) -> Result<(), RootedMutableError> {
        let old_parent = self.checked_live_directory(old_parent)?;
        let new_parent = self.checked_live_directory(new_parent)?;
        Ok(self
            .inner
            .rename(old_parent, old_name, new_parent, new_name, no_replace)?)
    }

    pub fn unlink(
        &mut self,
        parent: MutableDirectoryHandle,
        name: &[u8],
        remove_directory: bool,
    ) -> Result<MutableNodeHandle, RootedMutableError> {
        let parent = self.checked_live_directory(parent)?;
        let node = self.inner.unlink(parent, name, remove_directory)?;
        Ok(self.wrap_node(node))
    }

    pub fn retain_open(&mut self, node: MutableNodeHandle) -> Result<(), RootedMutableError> {
        let node = self.checked_node(node)?;
        Ok(self.inner.retain_open(node)?)
    }

    pub fn release_open(&mut self, node: MutableNodeHandle) -> Result<(), RootedMutableError> {
        let node = self.checked_node(node)?;
        Ok(self.inner.release_open(node)?)
    }

    pub(crate) fn retain_directory(
        &mut self,
        directory: MutableDirectoryHandle,
    ) -> Result<(), RootedMutableError> {
        match self.checked_live_directory(directory)? {
            MutableDirectoryId::Root => Ok(()),
            MutableDirectoryId::Node(node) => Ok(self.inner.retain_open(node)?),
        }
    }

    pub(crate) fn release_directory(
        &mut self,
        directory: MutableDirectoryHandle,
    ) -> Result<(), RootedMutableError> {
        match self.checked_directory(directory)? {
            MutableDirectoryId::Root => Ok(()),
            MutableDirectoryId::Node(node) => {
                if self.inner.metadata(node)?.kind() != MutableNodeKind::Directory {
                    return Err(MutableError::NotDirectory.into());
                }
                Ok(self.inner.release_open(node)?)
            }
        }
    }

    pub fn read(
        &self,
        node: MutableNodeHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, RootedMutableError> {
        Ok(self.inner.read(self.checked_node(node)?, offset, output)?)
    }

    pub fn write(
        &mut self,
        node: MutableNodeHandle,
        offset: u64,
        input: &[u8],
        now: MutableTimestamp,
    ) -> Result<usize, RootedMutableError> {
        let node = self.checked_node(node)?;
        Ok(self.inner.write(node, offset, input, now)?)
    }

    pub fn truncate(
        &mut self,
        node: MutableNodeHandle,
        length: u64,
        now: MutableTimestamp,
    ) -> Result<(), RootedMutableError> {
        let node = self.checked_node(node)?;
        Ok(self.inner.truncate(node, length, now)?)
    }

    pub fn readlink(
        &self,
        node: MutableNodeHandle,
        output: &mut [u8],
    ) -> Result<usize, RootedMutableError> {
        Ok(self.inner.readlink(self.checked_node(node)?, output)?)
    }

    pub fn chmod(
        &mut self,
        node: MutableNodeHandle,
        mode: u32,
        now: MutableTimestamp,
    ) -> Result<(), RootedMutableError> {
        let node = self.checked_node(node)?;
        Ok(self.inner.chmod(node, mode, now)?)
    }

    pub fn chown(
        &mut self,
        node: MutableNodeHandle,
        uid: Option<u32>,
        gid: Option<u32>,
        now: MutableTimestamp,
    ) -> Result<(), RootedMutableError> {
        let node = self.checked_node(node)?;
        Ok(self.inner.chown(node, uid, gid, now)?)
    }

    pub fn set_times(
        &mut self,
        node: MutableNodeHandle,
        atime: MutableTimestamp,
        mtime: MutableTimestamp,
        ctime: MutableTimestamp,
    ) -> Result<(), RootedMutableError> {
        let node = self.checked_node(node)?;
        Ok(self.inner.set_times(node, atime, mtime, ctime)?)
    }

    pub fn directory_is_empty(&self, node: MutableNodeHandle) -> Result<bool, RootedMutableError> {
        Ok(self.inner.directory_is_empty(self.checked_node(node)?)?)
    }

    fn namespace_id(&self) -> MutableNamespaceId {
        let current = self.namespace.load(Ordering::Relaxed);
        if current != 0 {
            return MutableNamespaceId(current);
        }

        let candidate = allocate_namespace_id().0;
        match self
            .namespace
            .compare_exchange(0, candidate, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => MutableNamespaceId(candidate),
            Err(existing) => MutableNamespaceId(existing),
        }
    }

    fn checked_node(&self, handle: MutableNodeHandle) -> Result<MutableNodeId, RootedMutableError> {
        if handle.root != self.root {
            return Err(RootedMutableError::RootMismatch);
        }
        if handle.namespace != self.namespace_id() {
            return Err(RootedMutableError::NamespaceMismatch);
        }
        Ok(handle.node)
    }

    fn checked_directory(
        &self,
        handle: MutableDirectoryHandle,
    ) -> Result<MutableDirectoryId, RootedMutableError> {
        if handle.root != self.root {
            return Err(RootedMutableError::RootMismatch);
        }
        if handle.namespace != self.namespace_id() {
            return Err(RootedMutableError::NamespaceMismatch);
        }
        Ok(handle.directory)
    }

    fn checked_live_directory(
        &self,
        handle: MutableDirectoryHandle,
    ) -> Result<MutableDirectoryId, RootedMutableError> {
        let directory = self.checked_directory(handle)?;
        if let MutableDirectoryId::Node(node) = directory
            && self.inner.metadata(node)?.kind() != MutableNodeKind::Directory
        {
            return Err(MutableError::NotDirectory.into());
        }
        Ok(directory)
    }

    fn wrap_node(&self, node: MutableNodeId) -> MutableNodeHandle {
        MutableNodeHandle {
            root: self.root,
            namespace: self.namespace_id(),
            node,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Namespace = RootedMutableNamespace<8, 12, 32>;
    const ROOT_A: RootId = RootId::new(31);
    const ROOT_B: RootId = RootId::new(32);
    const T: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 2,
    };

    #[test]
    fn same_slot_generation_from_foreign_root_is_rejected_before_inner_lookup() {
        let mut a = Namespace::new(ROOT_A);
        let mut b = Namespace::new(ROOT_B);
        let file_a = a
            .create_regular(a.root_directory(), b"file", 0o600, 0, 0, T)
            .unwrap();
        let file_b = b
            .create_regular(b.root_directory(), b"file", 0o600, 0, 0, T)
            .unwrap();

        assert_ne!(file_a, file_b);
        assert_eq!(file_a.root_id(), ROOT_A);
        assert_eq!(file_b.root_id(), ROOT_B);
        assert_eq!(file_a.slot(), file_b.slot());
        assert_eq!(file_a.generation(), file_b.generation());
        assert_eq!(b.metadata(file_a), Err(RootedMutableError::RootMismatch));
        assert_eq!(a.metadata(file_b), Err(RootedMutableError::RootMismatch));
    }

    #[test]
    fn same_root_same_slot_generation_from_foreign_namespace_is_rejected() {
        let mut a = Namespace::new(ROOT_A);
        let mut b = Namespace::new(ROOT_A);
        let root_a = a.root_directory();
        let root_b = b.root_directory();
        let file_a = a
            .create_regular(root_a, b"file", 0o600, 0, 0, T)
            .unwrap();
        let file_b = b
            .create_regular(root_b, b"file", 0o600, 0, 0, T)
            .unwrap();

        assert_ne!(root_a, root_b);
        assert_ne!(file_a, file_b);
        assert_eq!(file_a.root_id(), ROOT_A);
        assert_eq!(file_b.root_id(), ROOT_A);
        assert_eq!(file_a.slot(), file_b.slot());
        assert_eq!(file_a.generation(), file_b.generation());
        assert_eq!(
            b.metadata(file_a),
            Err(RootedMutableError::NamespaceMismatch)
        );
        assert_eq!(
            a.metadata(file_b),
            Err(RootedMutableError::NamespaceMismatch)
        );

        let mut output = [0u8; 1];
        assert_eq!(
            b.read(file_a, 0, &mut output),
            Err(RootedMutableError::NamespaceMismatch)
        );
        assert_eq!(
            b.write(file_a, 0, b"x", T),
            Err(RootedMutableError::NamespaceMismatch)
        );
        assert_eq!(
            b.refresh_directory(root_a),
            Err(RootedMutableError::NamespaceMismatch)
        );
        assert_eq!(
            b.create_regular(root_a, b"escape", 0o600, 0, 0, T),
            Err(RootedMutableError::NamespaceMismatch)
        );
        assert_eq!(
            b.lookup(root_b, b"escape"),
            Err(RootedMutableError::Mutable(MutableError::NotFound))
        );
    }

    #[test]
    fn foreign_root_directory_handle_cannot_publish_a_dentry() {
        let a = Namespace::new(ROOT_A);
        let mut b = Namespace::new(ROOT_B);
        let foreign_root = a.root_directory();

        assert_eq!(
            b.create_regular(foreign_root, b"escape", 0o600, 0, 0, T),
            Err(RootedMutableError::RootMismatch)
        );
        assert_eq!(
            b.lookup(b.root_directory(), b"escape"),
            Err(RootedMutableError::Mutable(MutableError::NotFound))
        );
    }

    #[test]
    fn directory_handles_are_identity_first_and_type_checked() {
        let mut ns = Namespace::new(ROOT_A);
        let root = ns.root_directory();
        assert_eq!(ns.directory_canonical_path(root), Ok(CanonicalPath::root()));

        let directory = ns.create_directory(root, b"dir", 0o755, 0, 0, T).unwrap();
        let parent = ns.open_directory(root, b"dir").unwrap();
        assert_eq!(
            ns.directory_canonical_path(parent)
                .unwrap()
                .as_relative_bytes(),
            b"dir"
        );
        let file = ns.create_regular(parent, b"child", 0o644, 0, 0, T).unwrap();
        assert_eq!(ns.lookup(parent, b"child"), Ok(file));
        assert_eq!(
            ns.open_directory(parent, b"child"),
            Err(RootedMutableError::Mutable(MutableError::NotDirectory))
        );
        assert_eq!(
            ns.metadata(directory).unwrap().kind(),
            MutableNodeKind::Directory
        );
    }

    #[test]
    fn presentation_path_tracks_live_ancestor_rename() {
        let mut ns = Namespace::new(ROOT_A);
        let root = ns.root_directory();
        ns.create_directory(root, b"parent", 0o755, 0, 0, T)
            .unwrap();
        let parent = ns.open_directory(root, b"parent").unwrap();
        ns.create_directory(parent, b"child", 0o755, 0, 0, T)
            .unwrap();
        let child = ns.open_directory(parent, b"child").unwrap();

        ns.rename(root, b"parent", root, b"moved", false).unwrap();
        let refreshed = ns.refresh_directory(child).unwrap();
        assert_eq!(refreshed, child);
        assert_eq!(
            ns.directory_canonical_path(refreshed)
                .unwrap()
                .as_relative_bytes(),
            b"moved/child"
        );
    }
}
