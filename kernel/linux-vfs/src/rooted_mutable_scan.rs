// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Root-qualified mutable directory entry returned by the VFS-owned scan cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutableDirectoryEntry<'a> {
    name: &'a [u8],
    node: MutableNodeHandle,
    metadata: MutableMetadata,
}

impl<'a> MutableDirectoryEntry<'a> {
    pub const fn name(self) -> &'a [u8] {
        self.name
    }

    pub const fn node(self) -> MutableNodeHandle {
        self.node
    }

    pub const fn metadata(self) -> MutableMetadata {
        self.metadata
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutableDirectoryScan<'a> {
    entry: MutableDirectoryEntry<'a>,
    directory: MutableDirectoryHandle,
    start_cursor: usize,
    next_cursor: usize,
}

impl<'a> MutableDirectoryScan<'a> {
    pub const fn entry(self) -> MutableDirectoryEntry<'a> {
        self.entry
    }

    pub const fn directory(self) -> MutableDirectoryHandle {
        self.directory
    }

    pub const fn start_cursor(self) -> usize {
        self.start_cursor
    }

    pub const fn next_cursor(self) -> usize {
        self.next_cursor
    }
}

impl<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>
    RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>
{
    pub(crate) fn preflight_capacity(
        &self,
        required_nodes: usize,
        required_dentries: usize,
    ) -> Result<(), RootedMutableError> {
        self.inner
            .preflight_capacity(required_nodes, required_dentries)
            .map_err(Into::into)
    }

    /// Re-mints a directory identity from a generation-safe mutable node without reconstructing its
    /// absolute pathname. Directory enumeration remains valid beyond PATH_MAX and across rename.
    pub fn directory_handle_from_node(
        &self,
        node: MutableNodeHandle,
    ) -> Result<MutableDirectoryHandle, RootedMutableError> {
        let raw = self.checked_node(node)?;
        if self.inner.metadata(raw)?.kind() != MutableNodeKind::Directory {
            return Err(MutableError::NotDirectory.into());
        }
        Ok(MutableDirectoryHandle {
            root: self.root,
            namespace: self.namespace_id(),
            directory: MutableDirectoryId::Node(raw),
        })
    }

    /// Follows the current parent dentry from a live directory identity. Root clamps to itself.
    /// This is the authoritative `..` primitive for relative traversal and never reconstructs an
    /// absolute pathname.
    pub fn parent_directory(
        &self,
        directory: MutableDirectoryHandle,
    ) -> Result<MutableDirectoryHandle, RootedMutableError> {
        let raw = self.checked_live_directory(directory)?;
        let parent = self.inner.parent_directory_raw(raw)?;
        Ok(MutableDirectoryHandle {
            root: self.root,
            namespace: self.namespace_id(),
            directory: parent,
        })
    }

    /// Converts one live mutable directory identity back to its generation-safe node identity.
    /// Root is represented as `None`; all non-root parents can then pass through the overlay's
    /// logical identity mapper without ever reconstructing pathname text.
    pub(crate) fn directory_node_handle(
        &self,
        directory: MutableDirectoryHandle,
    ) -> Result<Option<MutableNodeHandle>, RootedMutableError> {
        match self.checked_live_directory(directory)? {
            MutableDirectoryId::Root => Ok(None),
            MutableDirectoryId::Node(node) => Ok(Some(self.wrap_node(node))),
        }
    }

    pub fn directory_entry_from(
        &self,
        directory: MutableDirectoryHandle,
        cursor: usize,
    ) -> Result<Option<MutableDirectoryScan<'_>>, RootedMutableError> {
        let raw_directory = self.checked_live_directory(directory)?;
        let Some(scan) = self.inner.directory_entry_from_raw(raw_directory, cursor)? else {
            return Ok(None);
        };
        Ok(Some(MutableDirectoryScan {
            entry: MutableDirectoryEntry {
                name: scan.name(),
                node: self.wrap_node(scan.node()),
                metadata: scan.metadata(),
            },
            directory,
            start_cursor: scan.start_cursor(),
            next_cursor: scan.next_cursor(),
        }))
    }
}

#[cfg(test)]
mod rooted_scan_tests {
    use super::*;

    type Namespace = RootedMutableNamespace<8, 8, 32>;
    const ROOT: RootId = RootId::new(63);
    const T: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 0,
    };

    #[test]
    fn directory_scan_tracks_live_identity_after_rename() {
        let mut ns = Namespace::new(ROOT);
        let root = ns.root_directory();
        let dir_node = ns
            .create_directory(root, b"dir", 0o755, 0, 0, T)
            .unwrap();
        let dir = ns.directory_handle_from_node(dir_node).unwrap();
        let child = ns
            .create_regular(dir, b"child", 0o600, 0, 0, T)
            .unwrap();

        ns.rename(root, b"dir", root, b"renamed", false).unwrap();
        let scan = ns.directory_entry_from(dir, 0).unwrap().unwrap();
        assert_eq!(scan.entry().name(), b"child");
        assert_eq!(scan.entry().node(), child);
        assert_eq!(scan.directory(), dir);
        assert_eq!(
            ns.directory_canonical_path(scan.directory())
                .unwrap()
                .as_relative_bytes(),
            b"renamed"
        );
    }

    #[test]
    fn parent_directory_walk_is_identity_first_and_root_confined() {
        let mut ns = Namespace::new(ROOT);
        let root = ns.root_directory();
        let parent_node = ns
            .create_directory(root, b"parent", 0o755, 0, 0, T)
            .unwrap();
        let parent = ns.directory_handle_from_node(parent_node).unwrap();
        let child_node = ns
            .create_directory(parent, b"child", 0o755, 0, 0, T)
            .unwrap();
        let child = ns.directory_handle_from_node(child_node).unwrap();

        assert_eq!(ns.parent_directory(root), Ok(root));
        assert_eq!(ns.parent_directory(child), Ok(parent));
        assert_eq!(ns.directory_node_handle(root), Ok(None));
        assert_eq!(ns.directory_node_handle(parent), Ok(Some(parent_node)));
    }
}
