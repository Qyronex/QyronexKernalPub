// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::rooted_mutable::{MutableDirectoryHandle, RootedMutableError, RootedMutableNamespace};
use super::{CanonicalPath, Error, InitramfsRoot, NodeKind, ReadOnlyDirectory, RootId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryIdentity {
    /// Generic process/root identity without a mutable namespace-instance witness.
    Root {
        root: RootId,
    },
    /// Mutable namespace root. The embedded mutable handle carries the exact namespace owner even
    /// though the root itself has no inode slot or generation to retain.
    MutableRoot(MutableDirectoryHandle),
    /// Compact immutable directory authority owned directly by an immutable root. Pathname text is
    /// re-derived only by that immutable owner and is never stored in the persistent handle.
    Immutable(ReadOnlyDirectory),
    /// Compact immutable directory authority published by an Overlay owner. The lower EntryId stays
    /// the object identity while the private Upper-root handle is retained only as an opaque owner
    /// witness, so same-RootId sibling overlays cannot launder cwd authority through EntryId alone.
    OverlayImmutable {
        directory: ReadOnlyDirectory,
        owner: MutableDirectoryHandle,
    },
    Mutable(MutableDirectoryHandle),
}

/// Opaque cwd/fchdir identity. Persistent authority is compact object identity; no PATH_MAX pathname
/// snapshot is stored in the handle. Text is reconstructed only by the owning namespace when needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryHandle {
    identity: DirectoryIdentity,
}

impl DirectoryHandle {
    pub(crate) const fn root(root: RootId) -> Self {
        Self {
            identity: DirectoryIdentity::Root { root },
        }
    }

    pub(crate) const fn mutable_root(directory: MutableDirectoryHandle) -> Self {
        Self {
            identity: DirectoryIdentity::MutableRoot(directory),
        }
    }

    pub(crate) const fn immutable(directory: ReadOnlyDirectory) -> Self {
        Self {
            identity: DirectoryIdentity::Immutable(directory),
        }
    }

    pub(crate) const fn overlay_immutable(
        directory: ReadOnlyDirectory,
        owner: MutableDirectoryHandle,
    ) -> Self {
        Self {
            identity: DirectoryIdentity::OverlayImmutable { directory, owner },
        }
    }

    pub(crate) const fn mutable(directory: MutableDirectoryHandle) -> Self {
        Self {
            identity: DirectoryIdentity::Mutable(directory),
        }
    }

    pub const fn root_id(self) -> RootId {
        match self.identity {
            DirectoryIdentity::Root { root } => root,
            DirectoryIdentity::MutableRoot(directory) | DirectoryIdentity::Mutable(directory) => {
                directory.root_id()
            }
            DirectoryIdentity::Immutable(directory)
            | DirectoryIdentity::OverlayImmutable { directory, .. } => directory.root_id(),
        }
    }

    pub const fn is_root(self) -> bool {
        matches!(
            self.identity,
            DirectoryIdentity::Root { .. } | DirectoryIdentity::MutableRoot(_)
        )
    }

    pub(crate) const fn overlay_immutable_parts(
        self,
    ) -> Option<(ReadOnlyDirectory, MutableDirectoryHandle)> {
        match self.identity {
            DirectoryIdentity::OverlayImmutable { directory, owner } => Some((directory, owner)),
            _ => None,
        }
    }

    pub(crate) const fn mutable_directory_identity(self) -> Option<MutableDirectoryHandle> {
        match self.identity {
            DirectoryIdentity::MutableRoot(directory) | DirectoryIdentity::Mutable(directory) => {
                Some(directory)
            }
            DirectoryIdentity::Root { .. }
            | DirectoryIdentity::Immutable(_)
            | DirectoryIdentity::OverlayImmutable { .. } => None,
        }
    }

    /// Materializes the current pathname for the rooted mutable owner only. Immutable handles stay
    /// compact and must be materialized by `InitramfsRoot`/Overlay, which owns their EntryId->path
    /// provenance. This prevents a persistent PATH_MAX snapshot from becoming cwd authority.
    pub fn canonical_path_in<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        self,
        namespace: &RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
    ) -> Result<CanonicalPath, RootedMutableError> {
        if self.root_id() != namespace.root_id() {
            return Err(RootedMutableError::RootMismatch);
        }
        match self.identity {
            DirectoryIdentity::Root { .. } => Ok(CanonicalPath::root()),
            DirectoryIdentity::Immutable(_) | DirectoryIdentity::OverlayImmutable { .. } => {
                Err(RootedMutableError::Path(Error::HandleMismatch))
            }
            DirectoryIdentity::MutableRoot(directory) | DirectoryIdentity::Mutable(directory) => {
                namespace.directory_canonical_path(directory)
            }
        }
    }

    pub(crate) fn retain_in<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        self,
        namespace: &mut RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
    ) -> Result<(), RootedMutableError> {
        if self.root_id() != namespace.root_id() {
            return Err(RootedMutableError::RootMismatch);
        }
        match self.identity {
            DirectoryIdentity::Root { .. } => Ok(()),
            DirectoryIdentity::Immutable(_) => Err(RootedMutableError::Path(Error::HandleMismatch)),
            DirectoryIdentity::OverlayImmutable { owner, .. } => {
                validate_overlay_owner(owner, namespace)
            }
            DirectoryIdentity::MutableRoot(directory) | DirectoryIdentity::Mutable(directory) => {
                namespace.retain_directory(directory)
            }
        }
    }

    pub(crate) fn release_in<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        self,
        namespace: &mut RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
    ) -> Result<(), RootedMutableError> {
        if self.root_id() != namespace.root_id() {
            return Err(RootedMutableError::RootMismatch);
        }
        match self.identity {
            DirectoryIdentity::Root { .. } => Ok(()),
            DirectoryIdentity::Immutable(_) => Err(RootedMutableError::Path(Error::HandleMismatch)),
            DirectoryIdentity::OverlayImmutable { owner, .. } => {
                validate_overlay_owner(owner, namespace)
            }
            DirectoryIdentity::MutableRoot(directory) | DirectoryIdentity::Mutable(directory) => {
                namespace.release_directory(directory)
            }
        }
    }

    /// Revalidates the live identity without requiring pathname materialization.
    pub fn refresh_in<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        self,
        namespace: &RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
    ) -> Result<Self, RootedMutableError> {
        if self.root_id() != namespace.root_id() {
            return Err(RootedMutableError::RootMismatch);
        }
        match self.identity {
            DirectoryIdentity::Root { .. } => Ok(self),
            DirectoryIdentity::Immutable(_) => Err(RootedMutableError::Path(Error::HandleMismatch)),
            DirectoryIdentity::OverlayImmutable { owner, .. } => {
                validate_overlay_owner(owner, namespace)?;
                Ok(self)
            }
            DirectoryIdentity::MutableRoot(directory) => namespace
                .refresh_directory(directory)
                .map(DirectoryHandle::mutable_root),
            DirectoryIdentity::Mutable(directory) => namespace
                .refresh_directory(directory)
                .map(DirectoryHandle::mutable),
        }
    }
}

fn validate_overlay_owner<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
    owner: MutableDirectoryHandle,
    namespace: &RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
) -> Result<(), RootedMutableError> {
    let refreshed = namespace.refresh_directory(owner)?;
    if refreshed != namespace.root_directory() {
        return Err(RootedMutableError::Path(Error::HandleMismatch));
    }
    Ok(())
}

impl<'a> InitramfsRoot<'a> {
    pub fn directory_handle_at(self, dirfd: i32, path: &[u8]) -> Result<DirectoryHandle, Error> {
        let (entry_id, node, _) = self.resolve_following_at(dirfd, path)?;
        match node.kind() {
            NodeKind::Directory => Ok(DirectoryHandle::immutable(ReadOnlyDirectory::new(
                self.root_id(),
                entry_id,
                node.mode(),
            ))),
            NodeKind::Regular | NodeKind::Symlink => Err(Error::NotDirectory),
            NodeKind::Other(_) => Err(Error::UnsupportedNode),
        }
    }
}

impl<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>
    RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>
{
    /// Returns the exact mutable namespace root identity. Unlike the generic process root used by
    /// `FsContext::new`, this handle carries the namespace-instance witness and cannot be replayed
    /// against a same-RootId sibling namespace.
    pub fn root_directory_handle(&self) -> DirectoryHandle {
        self.wrap_mutable_directory_handle(self.root_directory())
    }

    pub fn directory_handle(
        &self,
        parent: MutableDirectoryHandle,
        name: &[u8],
    ) -> Result<DirectoryHandle, RootedMutableError> {
        self.open_directory(parent, name)
            .map(|directory| self.wrap_mutable_directory_handle(directory))
    }

    fn wrap_mutable_directory_handle(&self, directory: MutableDirectoryHandle) -> DirectoryHandle {
        if directory == self.root_directory() {
            DirectoryHandle::mutable_root(directory)
        } else {
            DirectoryHandle::mutable(directory)
        }
    }

    /// Resolves one mutable-cwd directory component from opaque identity only. No pathname text is
    /// reconstructed: `.` revalidates the current identity, `..` follows the live parent dentry with
    /// root clamp, and an ordinary component performs the current child-directory lookup.
    ///
    /// Immutable directory identities belong to the immutable/overlay resolver and are rejected at
    /// this mutable-owner boundary rather than being silently converted into pathname authority.
    pub fn resolve_mutable_directory_component(
        &self,
        directory: DirectoryHandle,
        component: &[u8],
    ) -> Result<DirectoryHandle, RootedMutableError> {
        if directory.root_id() != self.root_id() {
            return Err(RootedMutableError::RootMismatch);
        }

        match directory.identity {
            DirectoryIdentity::Root { .. } => match component {
                b"." | b".." => Ok(directory),
                name => self
                    .open_directory(self.root_directory(), name)
                    .map(|child| self.wrap_mutable_directory_handle(child)),
            },
            DirectoryIdentity::MutableRoot(current) => match component {
                b"." | b".." => self
                    .refresh_directory(current)
                    .map(|root| self.wrap_mutable_directory_handle(root)),
                name => self
                    .open_directory(current, name)
                    .map(|child| self.wrap_mutable_directory_handle(child)),
            },
            DirectoryIdentity::Mutable(current) => match component {
                b"." => self
                    .refresh_directory(current)
                    .map(|same| self.wrap_mutable_directory_handle(same)),
                b".." => self
                    .parent_directory(current)
                    .map(|parent| self.wrap_mutable_directory_handle(parent)),
                name => self
                    .open_directory(current, name)
                    .map(|child| self.wrap_mutable_directory_handle(child)),
            },
            DirectoryIdentity::Immutable(_) | DirectoryIdentity::OverlayImmutable { .. } => {
                Err(RootedMutableError::Path(Error::HandleMismatch))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{MutableTimestamp, RootedMutableNamespace};
    use super::*;

    type Namespace = RootedMutableNamespace<8, 12, 32>;
    const ROOT_A: RootId = RootId::new(41);
    const ROOT_B: RootId = RootId::new(42);
    const T: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 0,
    };

    #[test]
    fn mutable_directory_identity_carries_root_and_separate_vfs_path() {
        let mut namespace = Namespace::new(ROOT_A);
        let root = namespace.root_directory();
        namespace
            .create_directory(root, b"work", 0o755, 0, 0, T)
            .unwrap();
        let handle = namespace.directory_handle(root, b"work").unwrap();
        assert_eq!(handle.root_id(), ROOT_A);
        assert_eq!(
            handle
                .canonical_path_in(&namespace)
                .unwrap()
                .as_relative_bytes(),
            b"work"
        );
        assert!(!handle.is_root());
    }

    #[test]
    fn mutable_directory_identity_refreshes_after_ancestor_rename() {
        let mut namespace = Namespace::new(ROOT_A);
        let root = namespace.root_directory();
        namespace
            .create_directory(root, b"parent", 0o755, 0, 0, T)
            .unwrap();
        let parent = namespace.open_directory(root, b"parent").unwrap();
        namespace
            .create_directory(parent, b"child", 0o755, 0, 0, T)
            .unwrap();
        let child = namespace.directory_handle(parent, b"child").unwrap();

        namespace
            .rename(root, b"parent", root, b"moved", false)
            .unwrap();
        let refreshed = child.refresh_in(&namespace).unwrap();
        assert_eq!(refreshed, child);
        assert_eq!(
            refreshed
                .canonical_path_in(&namespace)
                .unwrap()
                .as_relative_bytes(),
            b"moved/child"
        );
    }

    #[test]
    fn identity_relative_mutable_component_walk_handles_dot_parent_child_and_root_clamp() {
        let mut namespace = Namespace::new(ROOT_A);
        let root = namespace.root_directory();
        let root_handle = namespace.root_directory_handle();
        namespace
            .create_directory(root, b"parent", 0o755, 0, 0, T)
            .unwrap();
        let parent_raw = namespace.open_directory(root, b"parent").unwrap();
        let parent = namespace.directory_handle(root, b"parent").unwrap();
        namespace
            .create_directory(parent_raw, b"child", 0o755, 0, 0, T)
            .unwrap();
        let child_raw = namespace.open_directory(parent_raw, b"child").unwrap();
        let child = namespace.directory_handle(parent_raw, b"child").unwrap();
        namespace
            .create_directory(child_raw, b"leaf", 0o755, 0, 0, T)
            .unwrap();
        let leaf = namespace.directory_handle(child_raw, b"leaf").unwrap();

        assert_eq!(
            namespace.resolve_mutable_directory_component(child, b"."),
            Ok(child)
        );
        assert_eq!(
            namespace.resolve_mutable_directory_component(child, b".."),
            Ok(parent)
        );
        assert_eq!(
            namespace.resolve_mutable_directory_component(child, b"leaf"),
            Ok(leaf)
        );
        assert_eq!(
            namespace.resolve_mutable_directory_component(root_handle, b".."),
            Ok(root_handle)
        );
        assert!(root_handle.is_root());
    }

    #[test]
    fn identity_relative_dot_revalidates_same_root_namespace_instance() {
        let mut a = Namespace::new(ROOT_A);
        let b = Namespace::new(ROOT_A);
        let root = a.root_directory();
        a.create_directory(root, b"held", 0o755, 0, 0, T).unwrap();
        let held = a.directory_handle(root, b"held").unwrap();

        assert_eq!(
            b.resolve_mutable_directory_component(held, b"."),
            Err(RootedMutableError::NamespaceMismatch)
        );
    }

    #[test]
    fn refresh_rejects_foreign_root_namespace() {
        let handle = Namespace::new(ROOT_A).root_directory_handle();
        let foreign = Namespace::new(ROOT_B);
        assert_eq!(
            handle.refresh_in(&foreign),
            Err(RootedMutableError::RootMismatch)
        );
    }

    #[test]
    fn independently_minted_roots_remain_distinct() {
        let a = Namespace::new(ROOT_A).root_directory_handle();
        let b = Namespace::new(ROOT_B).root_directory_handle();
        assert_ne!(a, b);
        assert_eq!(a.root_id(), ROOT_A);
        assert_eq!(b.root_id(), ROOT_B);
        assert!(a.is_root());
        assert!(b.is_root());
    }
}
