// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Borrowed scan witness for one live mutable dentry slot.
///
/// The cursor is deliberately the bounded dentry-table position rather than a pathname or inode
/// number. Directory mutation may change which entries are observed across calls, as Linux permits,
/// but a cursor can never escape the fixed table or forge a node identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawDirectoryScan<'a> {
    name: &'a [u8],
    node: MutableNodeId,
    metadata: MutableMetadata,
    start_cursor: usize,
    next_cursor: usize,
}

impl<'a> RawDirectoryScan<'a> {
    pub(crate) const fn name(self) -> &'a [u8] {
        self.name
    }

    pub(crate) const fn node(self) -> MutableNodeId {
        self.node
    }

    pub(crate) const fn metadata(self) -> MutableMetadata {
        self.metadata
    }

    pub(crate) const fn start_cursor(self) -> usize {
        self.start_cursor
    }

    pub(crate) const fn next_cursor(self) -> usize {
        self.next_cursor
    }
}

impl<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>
    MutableNamespace<NODES, DENTRIES, FILE_BYTES>
{
    /// Proves that one compound VFS publication has enough bounded inode and dentry capacity before
    /// the first namespace mutation occurs. Node exhaustion is reported first because every newly
    /// published object requires a node; only then is dentry capacity considered.
    pub(crate) fn preflight_capacity(
        &self,
        required_nodes: usize,
        required_dentries: usize,
    ) -> Result<(), MutableError> {
        let available_nodes = self
            .nodes
            .iter()
            .filter(|slot| {
                !slot.retired && slot.state.is_none() && slot.generation.checked_add(1).is_some()
            })
            .count();
        if available_nodes < required_nodes {
            return Err(MutableError::NodeTableFull);
        }

        let available_dentries = self
            .dentries
            .iter()
            .filter(|slot| slot.state.is_none())
            .count();
        if available_dentries < required_dentries {
            return Err(MutableError::DirectoryEntryTableFull);
        }
        Ok(())
    }

    /// Returns the live parent identity for one mutable directory without reconstructing pathname
    /// text. Root clamps to itself, matching Linux `..` traversal at the process root. A retained but
    /// unlinked directory has no live parent dentry and therefore returns `BadNode` while the inode
    /// identity itself remains retained and usable for direct child operations.
    pub(crate) fn parent_directory_raw(
        &self,
        directory: MutableDirectoryId,
    ) -> Result<MutableDirectoryId, MutableError> {
        match directory {
            MutableDirectoryId::Root => Ok(MutableDirectoryId::Root),
            MutableDirectoryId::Node(node) => self.directory_parent(node),
        }
    }

    /// Returns the next immediate child of one validated mutable directory.
    ///
    /// `cursor` is a dentry-slot cursor in `0..=DENTRIES`. Empty slots and entries belonging to
    /// another parent are skipped. The returned node is revalidated before metadata/name exposure,
    /// so a stale generation can never be laundered through directory enumeration.
    pub(crate) fn directory_entry_from_raw(
        &self,
        parent: MutableDirectoryId,
        cursor: usize,
    ) -> Result<Option<RawDirectoryScan<'_>>, MutableError> {
        self.validate_parent(parent)?;
        if cursor > DENTRIES {
            return Err(MutableError::InvalidOffset);
        }

        for index in cursor..DENTRIES {
            let Some(entry) = self.dentries[index].state.as_ref() else {
                continue;
            };
            if entry.parent != parent {
                continue;
            }
            let metadata = self.node_state(entry.node)?.metadata;
            return Ok(Some(RawDirectoryScan {
                name: entry.name.as_bytes(),
                node: entry.node,
                metadata,
                start_cursor: cursor,
                next_cursor: index + 1,
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    type Namespace = MutableNamespace<8, 8, 32>;
    const T: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 0,
    };

    #[test]
    fn capacity_preflight_is_non_mutating_and_reports_node_exhaustion_first() {
        let mut ns: MutableNamespace<1, 1, 8> = MutableNamespace::new();
        assert_eq!(ns.preflight_capacity(1, 1), Ok(()));
        assert_eq!(ns.preflight_capacity(2, 1), Err(MutableError::NodeTableFull));

        ns.create_regular(MutableDirectoryId::Root, b"x", 0o600, 0, 0, T)
            .unwrap();
        assert_eq!(ns.preflight_capacity(1, 1), Err(MutableError::NodeTableFull));
    }

    #[test]
    fn parent_identity_walk_clamps_root_and_tracks_rename() {
        let mut ns = Namespace::new();
        let parent = ns
            .create_directory(MutableDirectoryId::Root, b"parent", 0o755, 0, 0, T)
            .unwrap();
        let child = ns
            .create_directory(MutableDirectoryId::Node(parent), b"child", 0o755, 0, 0, T)
            .unwrap();

        assert_eq!(
            ns.parent_directory_raw(MutableDirectoryId::Root),
            Ok(MutableDirectoryId::Root)
        );
        assert_eq!(
            ns.parent_directory_raw(MutableDirectoryId::Node(child)),
            Ok(MutableDirectoryId::Node(parent))
        );

        ns.rename(
            MutableDirectoryId::Root,
            b"parent",
            MutableDirectoryId::Root,
            b"moved",
            false,
        )
        .unwrap();
        assert_eq!(
            ns.parent_directory_raw(MutableDirectoryId::Node(child)),
            Ok(MutableDirectoryId::Node(parent))
        );
    }

    #[test]
    fn mutable_directory_scan_is_parent_scoped_bounded_and_generation_checked() {
        let mut ns = Namespace::new();
        let left = ns
            .create_directory(MutableDirectoryId::Root, b"left", 0o755, 0, 0, T)
            .unwrap();
        let right = ns
            .create_directory(MutableDirectoryId::Root, b"right", 0o755, 0, 0, T)
            .unwrap();
        let a = ns
            .create_regular(MutableDirectoryId::Node(left), b"a", 0o600, 0, 0, T)
            .unwrap();
        ns.create_regular(MutableDirectoryId::Node(right), b"other", 0o600, 0, 0, T)
            .unwrap();
        let b = ns
            .create_regular(MutableDirectoryId::Node(left), b"b", 0o600, 0, 0, T)
            .unwrap();

        let first = ns
            .directory_entry_from_raw(MutableDirectoryId::Node(left), 0)
            .unwrap()
            .unwrap();
        assert_eq!(first.name(), b"a");
        assert_eq!(first.node(), a);
        assert!(first.next_cursor() > first.start_cursor());

        let second = ns
            .directory_entry_from_raw(MutableDirectoryId::Node(left), first.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(second.name(), b"b");
        assert_eq!(second.node(), b);
        assert_eq!(
            ns.directory_entry_from_raw(MutableDirectoryId::Node(left), second.next_cursor()),
            Ok(None)
        );
        assert_eq!(
            ns.directory_entry_from_raw(MutableDirectoryId::Node(left), 9),
            Err(MutableError::InvalidOffset)
        );
    }
}
