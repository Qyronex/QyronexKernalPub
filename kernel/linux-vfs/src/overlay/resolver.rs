// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{OverlayError, OverlayNamespace, OverlayNodeHandle};
use crate::{
    AT_FDCWD, CanonicalPath, Error, LINUX_NAME_MAX, MAX_PATH_BYTES, MutableDirectoryHandle,
    MutableError, MutableNodeKind, Node, NodeKind, OverlayDirectoryHandle, RootedMutableError,
};

mod mutation;
mod relative_mutation;

/// Keep the union resolver pinned to the already accepted Step-29 symlink policy.
const MAX_UNION_SYMLINK_FOLLOWS: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FinalSymlinkPolicy {
    Follow,
    NoFollow,
}

#[derive(Clone, Copy)]
struct PendingPath {
    bytes: [u8; MAX_PATH_BYTES],
    len: usize,
}

impl PendingPath {
    fn from_path(path: &[u8]) -> Result<Self, Error> {
        if path.is_empty() {
            return Err(Error::EmptyPath);
        }
        if path.len() > MAX_PATH_BYTES {
            return Err(Error::PathTooLong);
        }
        if path.contains(&0) {
            return Err(Error::EmbeddedNul);
        }
        let mut pending = Self {
            bytes: [0; MAX_PATH_BYTES],
            len: path.len(),
        };
        pending.bytes[..path.len()].copy_from_slice(path);
        Ok(pending)
    }

    fn replace_with_symlink(&mut self, target: &[u8], suffix: &[u8]) -> Result<(), Error> {
        if target.is_empty() {
            return Err(Error::EmptyPath);
        }
        if target.contains(&0) {
            return Err(Error::EmbeddedNul);
        }
        let len = target
            .len()
            .checked_add(suffix.len())
            .ok_or(Error::PathTooLong)?;
        if len > MAX_PATH_BYTES {
            return Err(Error::PathTooLong);
        }
        let mut next = [0u8; MAX_PATH_BYTES];
        next[..target.len()].copy_from_slice(target);
        next[target.len()..len].copy_from_slice(suffix);
        self.bytes = next;
        self.len = len;
        Ok(())
    }

    fn requires_directory(&self) -> bool {
        self.len != 0 && self.bytes[self.len - 1] == b'/'
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
    pub fn resolve_following_at(
        &self,
        path: &[u8],
    ) -> Result<(OverlayNodeHandle, CanonicalPath), OverlayError> {
        self.resolve_components(CanonicalPath::root(), path, FinalSymlinkPolicy::Follow)
    }

    pub fn resolve_nofollow_at(
        &self,
        path: &[u8],
    ) -> Result<(OverlayNodeHandle, CanonicalPath), OverlayError> {
        self.resolve_components(CanonicalPath::root(), path, FinalSymlinkPolicy::NoFollow)
    }

    /// Resolves one raw pathname from an already-open Overlay directory identity without rebuilding
    /// that directory's absolute pathname. Absolute paths ignore `base`, matching Linux `*at`
    /// semantics. Relative paths process `.`, live `..`, lower/upper objects and symlinks strictly in
    /// component order, so symlink expansion occurs before any following `..` component.
    pub fn resolve_following_from(
        &self,
        base: OverlayDirectoryHandle,
        path: &[u8],
    ) -> Result<OverlayNodeHandle, OverlayError> {
        self.resolve_components_from_directory(base, path, FinalSymlinkPolicy::Follow)
    }

    /// Resolves one raw pathname from an already-open Overlay directory identity without following
    /// the final symlink component. Intermediate symlinks still follow Linux component order, and
    /// absolute input ignores `base`, matching the companion `resolve_following_from` semantics.
    pub fn resolve_nofollow_from(
        &self,
        base: OverlayDirectoryHandle,
        path: &[u8],
    ) -> Result<OverlayNodeHandle, OverlayError> {
        self.resolve_components_from_directory(base, path, FinalSymlinkPolicy::NoFollow)
    }

    pub(super) fn lookup_exact_canonical(
        &self,
        canonical: CanonicalPath,
    ) -> Result<Option<OverlayNodeHandle>, OverlayError> {
        self.lookup_canonical(canonical)
    }

    fn resolve_components(
        &self,
        base: CanonicalPath,
        path: &[u8],
        final_policy: FinalSymlinkPolicy,
    ) -> Result<(OverlayNodeHandle, CanonicalPath), OverlayError> {
        let mut pending = PendingPath::from_path(path)?;
        let mut canonical = if path.first().copied() == Some(b'/') {
            CanonicalPath::root()
        } else {
            base
        };
        let mut cursor = 0usize;
        let mut followed = 0usize;
        let mut must_be_directory = pending.requires_directory();

        loop {
            while cursor < pending.len && pending.bytes[cursor] == b'/' {
                cursor += 1;
            }
            if cursor == pending.len {
                let handle = self
                    .lookup_exact_canonical(canonical)?
                    .ok_or(OverlayError::NotFound)?;
                if self.node_kind(handle)? != NodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                return Ok((handle, canonical));
            }

            let start = cursor;
            while cursor < pending.len && pending.bytes[cursor] != b'/' {
                cursor += 1;
            }
            let end = cursor;
            let component = &pending.bytes[start..end];
            let mut next_component = cursor;
            while next_component < pending.len && pending.bytes[next_component] == b'/' {
                next_component += 1;
            }
            let final_component = next_component == pending.len;

            if component == b"." {
                if final_component {
                    cursor = pending.len;
                }
                continue;
            }
            if component == b".." {
                canonical.pop_component();
                if final_component {
                    cursor = pending.len;
                }
                continue;
            }
            if component.len() > LINUX_NAME_MAX {
                return Err(OverlayError::Path(Error::PathTooLong));
            }

            let mut candidate = canonical;
            candidate.push_component(component)?;
            let handle = self
                .lookup_exact_canonical(candidate)?
                .ok_or(OverlayError::NotFound)?;
            let kind = self.node_kind(handle)?;
            let follow_symlink = kind == NodeKind::Symlink
                && (!final_component
                    || final_policy == FinalSymlinkPolicy::Follow
                    || must_be_directory);

            if follow_symlink {
                if followed == MAX_UNION_SYMLINK_FOLLOWS {
                    return Err(OverlayError::Path(Error::SymlinkUnsupported));
                }
                followed += 1;

                let mut target = [0u8; MAX_PATH_BYTES];
                let target_len = self.read_symlink_target(handle, &mut target)?;
                let target = &target[..target_len];
                let target_is_absolute = target.first().copied() == Some(b'/');
                let suffix_len = pending.len - end;
                let mut suffix = [0u8; MAX_PATH_BYTES];
                suffix[..suffix_len].copy_from_slice(&pending.bytes[end..pending.len]);
                pending.replace_with_symlink(target, &suffix[..suffix_len])?;
                must_be_directory = pending.requires_directory();
                if target_is_absolute {
                    canonical = CanonicalPath::root();
                }
                cursor = 0;
                continue;
            }

            if !final_component && kind != NodeKind::Directory {
                return Err(OverlayError::NotDirectory);
            }
            if final_component {
                if must_be_directory && kind != NodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                return Ok((handle, candidate));
            }
            canonical = candidate;
        }
    }

    /// Identity-first counterpart to `resolve_components`. The current traversal base is the exact
    /// union directory object, never a reconstructed pathname. Lower immutable directories can still
    /// derive their immutable CPIO path for lower fallback, while pure mutable directories use only
    /// generation-safe Upper identities for child and parent traversal.
    fn resolve_components_from_directory(
        &self,
        base: OverlayDirectoryHandle,
        path: &[u8],
        final_policy: FinalSymlinkPolicy,
    ) -> Result<OverlayNodeHandle, OverlayError> {
        let mut pending = PendingPath::from_path(path)?;
        let mut directory = if path.first().copied() == Some(b'/') {
            self.root_object()?
        } else {
            let object = base.object();
            self.validate_directory_object(object)?;
            object
        };
        let mut cursor = 0usize;
        let mut followed = 0usize;
        let mut must_be_directory = pending.requires_directory();

        loop {
            while cursor < pending.len && pending.bytes[cursor] == b'/' {
                cursor += 1;
            }
            if cursor == pending.len {
                self.validate_directory_object(directory)?;
                return Ok(directory);
            }

            let start = cursor;
            while cursor < pending.len && pending.bytes[cursor] != b'/' {
                cursor += 1;
            }
            let end = cursor;
            let component = &pending.bytes[start..end];
            let mut next_component = cursor;
            while next_component < pending.len && pending.bytes[next_component] == b'/' {
                next_component += 1;
            }
            let final_component = next_component == pending.len;

            if component == b"." {
                if final_component {
                    return Ok(directory);
                }
                continue;
            }
            if component == b".." {
                directory = self.parent_directory_object(directory)?;
                if final_component {
                    return Ok(directory);
                }
                continue;
            }
            if component.len() > LINUX_NAME_MAX {
                return Err(OverlayError::Path(Error::PathTooLong));
            }

            let handle = self.lookup_child_from_directory_object(directory, component)?;
            let kind = self.node_kind(handle)?;
            let follow_symlink = kind == NodeKind::Symlink
                && (!final_component
                    || final_policy == FinalSymlinkPolicy::Follow
                    || must_be_directory);

            if follow_symlink {
                if followed == MAX_UNION_SYMLINK_FOLLOWS {
                    return Err(OverlayError::Path(Error::SymlinkUnsupported));
                }
                followed += 1;

                let mut target = [0u8; MAX_PATH_BYTES];
                let target_len = self.read_symlink_target(handle, &mut target)?;
                let target = &target[..target_len];
                let target_is_absolute = target.first().copied() == Some(b'/');
                let suffix_len = pending.len - end;
                let mut suffix = [0u8; MAX_PATH_BYTES];
                suffix[..suffix_len].copy_from_slice(&pending.bytes[end..pending.len]);
                pending.replace_with_symlink(target, &suffix[..suffix_len])?;
                must_be_directory = pending.requires_directory();
                if target_is_absolute {
                    directory = self.root_object()?;
                }
                cursor = 0;
                continue;
            }

            if !final_component {
                if kind != NodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                directory = handle;
                continue;
            }
            if must_be_directory && kind != NodeKind::Directory {
                return Err(OverlayError::NotDirectory);
            }
            return Ok(handle);
        }
    }

    fn root_object(&self) -> Result<OverlayNodeHandle, OverlayError> {
        self.lookup_canonical(CanonicalPath::root())?
            .ok_or(OverlayError::Path(Error::HandleMismatch))
    }

    fn validate_directory_object(&self, object: OverlayNodeHandle) -> Result<(), OverlayError> {
        if self.node_kind(object)? == NodeKind::Directory {
            Ok(())
        } else {
            Err(OverlayError::NotDirectory)
        }
    }

    fn mutable_directory_for_object(
        &self,
        directory: OverlayNodeHandle,
    ) -> Result<Option<MutableDirectoryHandle>, OverlayError> {
        self.validate_handle_root(directory)?;
        match directory {
            OverlayNodeHandle::Root { .. } => Ok(Some(self.upper.root_directory())),
            OverlayNodeHandle::Mutable(node) => {
                Ok(Some(self.upper.directory_handle_from_node(node)?))
            }
            OverlayNodeHandle::Immutable { entry_id, kind, .. } => {
                if kind != NodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                self.bound_upper_for_entry(entry_id)
                    .map(|node| self.upper.directory_handle_from_node(node))
                    .transpose()
                    .map_err(Into::into)
            }
        }
    }

    fn lookup_child_from_directory_object(
        &self,
        directory: OverlayNodeHandle,
        name: &[u8],
    ) -> Result<OverlayNodeHandle, OverlayError> {
        self.validate_directory_object(directory)?;

        if let Some(upper_directory) = self.mutable_directory_for_object(directory)? {
            match self.upper.lookup(upper_directory, name) {
                Ok(node) => return self.logical_handle_for_upper(node),
                Err(RootedMutableError::Mutable(MutableError::NotFound)) => {}
                Err(error) => return Err(error.into()),
            }
        }

        let parent = match directory {
            OverlayNodeHandle::Mutable(_) => return Err(OverlayError::NotFound),
            OverlayNodeHandle::Root { .. } => CanonicalPath::root(),
            OverlayNodeHandle::Immutable { entry_id, kind, .. } => {
                if kind != NodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                let entry = self
                    .lower
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let node = Node::from_entry(entry);
                if node.kind() != NodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                CanonicalPath::resolve_at(AT_FDCWD, entry.path())?
            }
        };
        let child = CanonicalPath::resolve_from(parent, name)?;
        self.lookup_canonical(child)?.ok_or(OverlayError::NotFound)
    }

    fn parent_directory_object(
        &self,
        directory: OverlayNodeHandle,
    ) -> Result<OverlayNodeHandle, OverlayError> {
        self.validate_directory_object(directory)?;
        match directory {
            OverlayNodeHandle::Root { .. } => Ok(directory),
            OverlayNodeHandle::Mutable(node) => {
                let current = self.upper.directory_handle_from_node(node)?;
                let parent = self.upper.parent_directory(current)?;
                match self.upper.directory_node_handle(parent)? {
                    None => self.root_object(),
                    Some(parent_node) => self.logical_handle_for_upper(parent_node),
                }
            }
            OverlayNodeHandle::Immutable { entry_id, kind, .. } => {
                if kind != NodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                let entry = self
                    .lower
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let node = Node::from_entry(entry);
                if node.kind() != NodeKind::Directory {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                let mut parent = CanonicalPath::resolve_at(AT_FDCWD, entry.path())?;
                parent.pop_component();
                let object = self
                    .lookup_canonical(parent)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                self.validate_directory_object(object)?;
                Ok(object)
            }
        }
    }

    pub(super) fn node_kind(&self, handle: OverlayNodeHandle) -> Result<NodeKind, OverlayError> {
        self.validate_handle_root(handle)?;
        Ok(match handle {
            OverlayNodeHandle::Root { .. } => NodeKind::Directory,
            OverlayNodeHandle::Immutable { kind, .. } => kind,
            OverlayNodeHandle::Mutable(node) => match self.upper.metadata(node)?.kind() {
                MutableNodeKind::Regular => NodeKind::Regular,
                MutableNodeKind::Directory => NodeKind::Directory,
                MutableNodeKind::Symlink => NodeKind::Symlink,
            },
        })
    }

    fn read_symlink_target(
        &self,
        handle: OverlayNodeHandle,
        output: &mut [u8; MAX_PATH_BYTES],
    ) -> Result<usize, OverlayError> {
        self.validate_handle_root(handle)?;
        match handle {
            OverlayNodeHandle::Mutable(node) => {
                let metadata = self.upper.metadata(node)?;
                if metadata.kind() != MutableNodeKind::Symlink {
                    return Err(OverlayError::NotRegular);
                }
                if metadata.size() > output.len() {
                    return Err(OverlayError::Path(Error::PathTooLong));
                }
                let copied = self.upper.readlink(node, output)?;
                if copied != metadata.size() {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Ok(copied)
            }
            OverlayNodeHandle::Immutable { entry_id, kind, .. } => {
                if kind != NodeKind::Symlink {
                    return Err(OverlayError::NotRegular);
                }
                let entry = self
                    .lower
                    .archive
                    .entry_by_id(entry_id)
                    .map_err(Error::from)?
                    .ok_or(OverlayError::Path(Error::HandleMismatch))?;
                let node = Node::from_entry(entry);
                if node.kind() != NodeKind::Symlink {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                let target = node.data();
                if target.len() > output.len() {
                    return Err(OverlayError::Path(Error::PathTooLong));
                }
                output[..target.len()].copy_from_slice(target);
                Ok(target.len())
            }
            OverlayNodeHandle::Root { .. } => Err(OverlayError::NotRegular),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AT_FDCWD, InitramfsRoot, MutableTimestamp, RootId};
    use kernal_cpio::Archive;

    const HEADER_LEN: usize = 110;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const ROOT: RootId = RootId::new(73);
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
        entry(&mut out, b"target", S_IFREG | 0o644, b"target");
        entry(&mut out, b"alias", S_IFLNK | 0o777, b"target");
        entry(&mut out, b"diralias", S_IFLNK | 0o777, b"etc");
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
    fn lower_symlink_target_observes_upper_shadow() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.write_at(b"/target", 0, b"UP", T2).unwrap();

        let (handle, path) = overlay.resolve_following_at(b"/alias").unwrap();
        assert!(matches!(handle, OverlayNodeHandle::Immutable { .. }));
        assert_eq!(path.as_relative_bytes(), b"target");
    }

    #[test]
    fn mutable_relative_and_absolute_symlinks_can_target_lower_objects() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        let root = overlay.upper.root_directory();
        overlay
            .upper
            .create_symlink(root, b"abs", b"/etc/base", 0, 0, T1)
            .unwrap();
        let etc_path = CanonicalPath::resolve_at(AT_FDCWD, b"/etc").unwrap();
        let etc = overlay.ensure_upper_directory(etc_path).unwrap();
        overlay
            .upper
            .create_symlink(etc, b"rel", b"base", 0, 0, T1)
            .unwrap();

        let (absolute, absolute_path) = overlay.resolve_following_at(b"/abs").unwrap();
        assert!(matches!(absolute, OverlayNodeHandle::Immutable { .. }));
        assert_eq!(absolute_path.as_relative_bytes(), b"etc/base");

        let (relative, relative_path) = overlay.resolve_following_at(b"/etc/rel").unwrap();
        assert!(matches!(relative, OverlayNodeHandle::Immutable { .. }));
        assert_eq!(relative_path.as_relative_bytes(), b"etc/base");
    }

    #[test]
    fn final_nofollow_returns_symlink_and_trailing_slash_forces_directory() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        let root = overlay.upper.root_directory();
        overlay
            .upper
            .create_symlink(root, b"mutable-alias", b"/etc/base", 0, 0, T1)
            .unwrap();

        let (nofollow, nofollow_path) = overlay.resolve_nofollow_at(b"/mutable-alias").unwrap();
        assert_eq!(overlay.node_kind(nofollow).unwrap(), NodeKind::Symlink);
        assert_eq!(nofollow_path.as_relative_bytes(), b"mutable-alias");

        let (directory, directory_path) = overlay.resolve_nofollow_at(b"/diralias/").unwrap();
        assert_eq!(overlay.node_kind(directory).unwrap(), NodeKind::Directory);
        assert_eq!(directory_path.as_relative_bytes(), b"etc");
    }

    #[test]
    fn upper_non_directory_component_blocks_lower_fallback() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        let root = overlay.upper.root_directory();
        overlay
            .upper
            .create_regular(root, b"etc", 0o600, 0, 0, T1)
            .unwrap();

        assert_eq!(
            overlay.lookup_at(b"/etc/base"),
            Err(OverlayError::NotDirectory)
        );
    }

    #[test]
    fn symlink_cycle_uses_accepted_forty_follow_limit() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        let root = overlay.upper.root_directory();
        overlay
            .upper
            .create_symlink(root, b"loop", b"loop", 0, 0, T1)
            .unwrap();

        assert_eq!(
            overlay.resolve_following_at(b"/loop"),
            Err(OverlayError::Path(Error::SymlinkUnsupported))
        );
    }
}
