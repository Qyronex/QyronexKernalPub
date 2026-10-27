// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{OverlayError, OverlayNamespace, OverlayNodeHandle};
use crate::{
    CanonicalPath, Error, LINUX_NAME_MAX, MAX_PATH_BYTES, MutableDirectoryHandle, MutableError,
    MutableNodeHandle, MutableNodeKind, MutableTimestamp, Node, NodeKind, OverlayDirectoryHandle,
    RootedMutableError,
};

impl<
    'a,
    const NODES: usize,
    const DENTRIES: usize,
    const FILE_BYTES: usize,
    const TOMBSTONES: usize,
> OverlayNamespace<'a, NODES, DENTRIES, FILE_BYTES, TOMBSTONES>
{
    /// Opens one directory for a future OFD owner and acquires its initial lifetime hold as the
    /// same VFS operation. Root and immutable lower directories use validated mounted-archive
    /// lifetime, while mutable directories retain the exact generation-safe Upper identity.
    pub fn open_and_retain_directory_at(
        &mut self,
        path: &[u8],
    ) -> Result<OverlayDirectoryHandle, OverlayError> {
        let directory = self.open_directory_at(path)?;
        self.retain_directory(directory)?;
        Ok(directory)
    }

    /// Acquires one independent directory lifetime hold suitable for an OFD or cwd/fchdir owner.
    pub fn retain_directory(
        &mut self,
        directory: OverlayDirectoryHandle,
    ) -> Result<(), OverlayError> {
        self.validate_handle_root(directory.object())?;
        match directory.object() {
            OverlayNodeHandle::Root { .. } => Ok(()),
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => Ok(()),
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotDirectory),
            OverlayNodeHandle::Mutable(node) => {
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                let directory = self.upper.directory_handle_from_node(node)?;
                self.upper.retain_directory(directory).map_err(Into::into)
            }
        }
    }

    /// Releases one directory lifetime hold previously acquired by this Overlay owner.
    pub fn release_directory(
        &mut self,
        directory: OverlayDirectoryHandle,
    ) -> Result<(), OverlayError> {
        self.validate_handle_root(directory.object())?;
        match directory.object() {
            OverlayNodeHandle::Root { .. } => Ok(()),
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => Ok(()),
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotDirectory),
            OverlayNodeHandle::Mutable(node) => {
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                let directory = self.upper.directory_handle_from_node(node)?;
                self.upper.release_directory(directory).map_err(Into::into)
            }
        }
    }

    pub fn mkdir_at(
        &mut self,
        path: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, OverlayError> {
        self.require_absent_nofollow(path)?;
        let (parent, parent_path, name) = self.resolve_mutation_parent(path)?;
        let canonical = CanonicalPath::resolve_from(parent_path, name)?;
        let node = self
            .upper
            .create_directory(parent, name, mode, uid, gid, now)?;
        self.clear_tombstone(canonical);
        Ok(node)
    }

    pub fn rmdir_at(&mut self, path: &[u8]) -> Result<(), OverlayError> {
        let (handle, canonical) = self.resolve_nofollow_at(path)?;
        let node = match handle {
            OverlayNodeHandle::Root { .. } => return Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => {
                return Err(OverlayError::Mutable(RootedMutableError::Mutable(
                    MutableError::DirectoryNotEmpty,
                )));
            }
            OverlayNodeHandle::Immutable { .. } => return Err(OverlayError::NotDirectory),
            OverlayNodeHandle::Mutable(node) => {
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Directory {
                    return Err(OverlayError::NotDirectory);
                }
                node
            }
        };

        let lower_kind = self.lower_kind(canonical)?;
        if lower_kind.is_some() {
            self.preflight_tombstone(canonical)?;
        }
        let (parent_path, name_start) = super::super::split_parent(canonical)?;
        let parent = self.upper_directory_existing(parent_path)?;
        let name = &canonical.as_relative_bytes()[name_start..];
        self.upper.unlink(parent, name, true)?;
        let _ = node;
        if lower_kind.is_some() {
            self.insert_tombstone(canonical)?;
        }
        Ok(())
    }

    pub fn unlink_at(&mut self, path: &[u8], remove_directory: bool) -> Result<(), OverlayError> {
        if remove_directory {
            self.rmdir_at(path)
        } else {
            self.unlink_regular_at(path)
        }
    }

    pub fn symlink_at(
        &mut self,
        target: &[u8],
        link_path: &[u8],
        uid: u32,
        gid: u32,
        now: MutableTimestamp,
    ) -> Result<MutableNodeHandle, OverlayError> {
        self.require_absent_nofollow(link_path)?;
        if target.len() > FILE_BYTES {
            return Err(OverlayError::Mutable(RootedMutableError::Mutable(
                MutableError::FileTooLarge,
            )));
        }
        let (parent, parent_path, name) = self.resolve_mutation_parent(link_path)?;
        let canonical = CanonicalPath::resolve_from(parent_path, name)?;
        let node = self
            .upper
            .create_symlink(parent, name, target, uid, gid, now)?;
        self.clear_tombstone(canonical);
        Ok(node)
    }

    pub fn readlink_at(&self, path: &[u8], output: &mut [u8]) -> Result<usize, OverlayError> {
        let (handle, _canonical) = self.resolve_nofollow_at(path)?;
        match handle {
            OverlayNodeHandle::Root { .. } => Err(OverlayError::NotRegular),
            OverlayNodeHandle::Mutable(node) => {
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Symlink {
                    return Err(OverlayError::NotRegular);
                }
                self.upper.readlink(node, output).map_err(Into::into)
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
                let copied = core::cmp::min(target.len(), output.len());
                output[..copied].copy_from_slice(&target[..copied]);
                Ok(copied)
            }
        }
    }

    /// Creates a second name for one regular inode. Time updates for the hard-link mutation itself
    /// are intentionally not modeled here yet; pure lower copy-up preserves CPIO time provenance and
    /// the atomic link/parent ctime policy belongs to the mutable namespace mutation transaction.
    pub fn link_regular_at(
        &mut self,
        old_path: &[u8],
        new_path: &[u8],
    ) -> Result<(), OverlayError> {
        self.require_absent_nofollow(new_path)?;
        let (source_handle, source_path) = self.resolve_nofollow_at(old_path)?;
        let (source, source_entry) = match source_handle {
            OverlayNodeHandle::Mutable(node) => {
                if self.upper.metadata(node)?.kind() != MutableNodeKind::Regular {
                    return Err(OverlayError::NotRegular);
                }
                (Some(node), None)
            }
            OverlayNodeHandle::Immutable {
                entry_id,
                kind: NodeKind::Regular,
                ..
            } => (None, Some(entry_id)),
            OverlayNodeHandle::Root { .. }
            | OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => return Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable { .. } => return Err(OverlayError::NotRegular),
        };

        // Validate the destination parent through the union before a lower-only source is copied up.
        // Then reserve source copy-up, destination-parent materialization and the final hard-link
        // dentry as one additive transaction so no earlier phase can consume capacity needed later.
        let (raw_parent, name) = split_raw_parent(new_path)?;
        let parent_path = self.resolve_existing_mutation_parent(raw_parent)?;
        let canonical = CanonicalPath::resolve_from(parent_path, name)?;
        self.preflight_compound_publication(source_entry, parent_path, 1)?;

        let source = match source {
            Some(node) => node,
            None => self.copy_up_regular_canonical(source_path)?,
        };
        let parent = self.ensure_upper_directory(parent_path)?;
        self.upper.link(source, parent, name)?;
        self.clear_tombstone(canonical);
        Ok(())
    }

    /// Renames one union name. As with hard-link, timestamp mutation is deliberately not conflated
    /// with lower copy-up; the later atomic namespace mutation owner must commit inode/parent times.
    pub fn rename_at(
        &mut self,
        old_path: &[u8],
        new_path: &[u8],
        no_replace: bool,
    ) -> Result<(), OverlayError> {
        let (source_handle, source_path) = self.resolve_nofollow_at(old_path)?;
        let source_kind = self.node_kind(source_handle)?;
        if matches!(source_handle, OverlayNodeHandle::Root { .. }) {
            return Err(OverlayError::NotDirectory);
        }

        // Target existence is decided before source mutation support. RENAME_NOREPLACE retains its
        // EEXIST-style precedence even when both names already identify the same logical object.
        let target = match self.resolve_nofollow_at(new_path) {
            Ok((handle, canonical)) => Some((handle, canonical)),
            Err(OverlayError::NotFound) => None,
            Err(error) => return Err(error),
        };
        if no_replace && target.is_some() {
            return Err(OverlayError::AlreadyExists);
        }

        // POSIX/Linux rename of two names for the same object is a successful no-op. Stable logical
        // OverlayNodeHandle equality makes this representation-neutral across mutable hard links and
        // lower objects that later acquire an upper backing. Return before copy-up, capacity plans or
        // tombstones so the no-op cannot consume bounded namespace resources.
        if target.is_some_and(|(target_handle, _)| target_handle == source_handle) {
            return Ok(());
        }

        // A pure lower directory remains outside the Step-29 rename policy. Once that exact lower
        // EntryId already owns an Upper directory binding, however, the VFS has a real mutable dentry
        // to move and the logical handle deliberately remains Immutable to preserve stable identity.
        // Re-enter that existing binding instead of mistaking the logical representation for a
        // lower-only object.
        let source_entry = match source_handle {
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
            } => Some(entry_id),
            OverlayNodeHandle::Mutable(_) => None,
            OverlayNodeHandle::Immutable { .. } => return Err(OverlayError::NotRegular),
            OverlayNodeHandle::Root { .. } => unreachable!(),
        };

        if let Some((target_handle, _)) = target {
            match (source_kind, self.node_kind(target_handle)?) {
                (NodeKind::Directory, NodeKind::Directory) => {
                    if matches!(target_handle, OverlayNodeHandle::Immutable { .. }) {
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

        let (raw_new_parent, new_name) = split_raw_parent(new_path)?;
        let new_parent_path = self.resolve_existing_mutation_parent(raw_new_parent)?;
        let target_path = CanonicalPath::resolve_from(new_parent_path, new_name)?;
        let source_lower = self.lower_kind(source_path)?.is_some();
        // The destination becomes a live upper dentry when rename commits. It must therefore remain
        // visible and must not consume a tombstone slot merely because an older lower object exists
        // at the same pathname. If the replacement is later removed, unlink will install the target
        // tombstone at that time to prevent lower fallback from resurrecting the old object.
        self.preflight_tombstone_set(source_path, target_path, source_lower, false)?;
        // Mutable rename reuses the source dentry (or an existing target dentry), so only lower
        // source/destination-parent publications need aggregate capacity; no extra dentry is needed.
        self.preflight_compound_publication(source_entry, new_parent_path, 0)?;

        match source_handle {
            OverlayNodeHandle::Mutable(_) => {}
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
            }
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Regular,
                ..
            } => {
                self.copy_up_regular_canonical(source_path)?;
            }
            OverlayNodeHandle::Root { .. } | OverlayNodeHandle::Immutable { .. } => unreachable!(),
        }

        let (old_parent_path, old_name_start) = super::super::split_parent(source_path)?;
        let old_parent = self.upper_directory_existing(old_parent_path)?;
        let old_name = &source_path.as_relative_bytes()[old_name_start..];

        // A bound lower directory keeps its immutable EntryId as logical provenance, but the rename
        // commit must target the exact live Upper dentry that owns that binding. Revalidate both the
        // binding and old-parent dentry immediately before publishing the move so stale or mismatched
        // ownership fails closed instead of renaming an unrelated mutable directory.
        if let OverlayNodeHandle::Immutable {
            entry_id,
            kind: NodeKind::Directory,
            ..
        } = source_handle
        {
            let expected = self
                .bound_upper_for_entry(entry_id)
                .ok_or(OverlayError::Path(Error::HandleMismatch))?;
            if self.upper.metadata(expected)?.kind() != MutableNodeKind::Directory {
                return Err(OverlayError::Path(Error::HandleMismatch));
            }
            match self.upper.lookup(old_parent, old_name) {
                Ok(node) if node == expected => {}
                Ok(_) | Err(RootedMutableError::Mutable(MutableError::NotFound)) => {
                    return Err(OverlayError::Path(Error::HandleMismatch));
                }
                Err(error) => return Err(error.into()),
            }
        }

        let new_parent = self.ensure_upper_directory(new_parent_path)?;

        self.upper
            .rename(old_parent, old_name, new_parent, new_name, no_replace)?;
        if source_lower {
            self.insert_tombstone(source_path)?;
        }
        self.clear_tombstone(target_path);
        Ok(())
    }

    pub fn chmod_at(
        &mut self,
        path: &[u8],
        mode: u32,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let node = self.mutable_regular_for_metadata(path)?;
        self.upper.chmod(node, mode, now).map_err(Into::into)
    }

    pub fn chown_at(
        &mut self,
        path: &[u8],
        uid: Option<u32>,
        gid: Option<u32>,
        now: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let node = self.mutable_regular_for_metadata(path)?;
        self.upper.chown(node, uid, gid, now).map_err(Into::into)
    }

    pub fn set_times_at(
        &mut self,
        path: &[u8],
        atime: MutableTimestamp,
        mtime: MutableTimestamp,
        ctime: MutableTimestamp,
    ) -> Result<(), OverlayError> {
        let node = self.mutable_regular_for_metadata(path)?;
        self.upper
            .set_times(node, atime, mtime, ctime)
            .map_err(Into::into)
    }

    fn mutable_regular_for_metadata(
        &mut self,
        path: &[u8],
    ) -> Result<MutableNodeHandle, OverlayError> {
        let (handle, canonical) = self.resolve_following_at(path)?;
        match handle {
            OverlayNodeHandle::Mutable(node) => {
                if self.upper.metadata(node)?.kind() == MutableNodeKind::Directory {
                    return Err(OverlayError::IsDirectory);
                }
                Ok(node)
            }
            OverlayNodeHandle::Immutable {
                kind: NodeKind::Regular,
                ..
            } => self.copy_up_regular_canonical(canonical),
            OverlayNodeHandle::Root { .. }
            | OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => Err(OverlayError::IsDirectory),
            OverlayNodeHandle::Immutable { .. } => Err(OverlayError::NotRegular),
        }
    }

    fn require_absent_nofollow(&self, path: &[u8]) -> Result<(), OverlayError> {
        match self.resolve_nofollow_at(path) {
            Ok(_) => Err(OverlayError::AlreadyExists),
            Err(OverlayError::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn resolve_existing_mutation_parent(
        &self,
        raw_parent: &[u8],
    ) -> Result<CanonicalPath, OverlayError> {
        if raw_parent.is_empty() || raw_parent.iter().all(|byte| *byte == b'/') {
            return Ok(CanonicalPath::root());
        }
        let (parent, canonical) = self.resolve_following_at(raw_parent)?;
        if self.node_kind(parent)? != NodeKind::Directory {
            return Err(OverlayError::NotDirectory);
        }
        Ok(canonical)
    }

    fn resolve_mutation_parent<'p>(
        &mut self,
        path: &'p [u8],
    ) -> Result<(MutableDirectoryHandle, CanonicalPath, &'p [u8]), OverlayError> {
        let (raw_parent, name) = split_raw_parent(path)?;
        let parent_path = self.resolve_existing_mutation_parent(raw_parent)?;
        self.preflight_parent_final_publication(parent_path)?;
        let parent = self.ensure_upper_directory(parent_path)?;
        Ok((parent, parent_path, name))
    }

    fn preflight_tombstone_set(
        &self,
        first: CanonicalPath,
        second: CanonicalPath,
        first_needed: bool,
        second_needed: bool,
    ) -> Result<(), OverlayError> {
        let mut needed = 0usize;
        if first_needed && !self.is_tombstoned(first) {
            needed += 1;
        }
        if second_needed && second != first && !self.is_tombstoned(second) {
            needed += 1;
        }
        let free = self.tombstones.iter().filter(|slot| slot.is_none()).count();
        if free < needed {
            return Err(OverlayError::TombstoneTableFull);
        }
        Ok(())
    }
}

fn split_raw_parent(path: &[u8]) -> Result<(&[u8], &[u8]), OverlayError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InitramfsRoot, RootId};
    use kernal_cpio::Archive;

    const HEADER_LEN: usize = 110;
    const S_IFDIR: u32 = 0o040000;
    const ROOT: RootId = RootId::new(79);
    const T1: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 0,
    };
    const T2: MutableTimestamp = MutableTimestamp {
        seconds: 2,
        nanoseconds: 0,
    };
    type Overlay<'a> = OverlayNamespace<'a, 24, 32, 128, 12>;

    fn hex(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32) {
        let start = out.len();
        out.extend_from_slice(b"070701");
        for value in [
            1,
            mode,
            0,
            0,
            1,
            0,
            0,
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
    }

    fn archive_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        entry(&mut out, b".", S_IFDIR | 0o755);
        entry(&mut out, b"lower-dir", S_IFDIR | 0o755);
        entry(&mut out, b"TRAILER!!!", 0);
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
        out
    }

    fn overlay(bytes: &[u8]) -> Overlay<'_> {
        Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
    }

    #[test]
    fn fixture_style_mutation_lifecycle_preserves_identity() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay.mkdir_at(b"/work", 0o755, 0, 0, T1).unwrap();
        overlay
            .create_regular_at(b"/work/alpha", 0o640, 0, 0, T1)
            .unwrap();
        overlay.write_at(b"/work/alpha", 0, b"abcdef", T1).unwrap();
        overlay
            .link_regular_at(b"/work/alpha", b"/work/hard")
            .unwrap();
        overlay
            .symlink_at(b"alpha", b"/work/sym", 0, 0, T1)
            .unwrap();

        let mut target = [0u8; 5];
        assert_eq!(overlay.readlink_at(b"/work/sym", &mut target), Ok(5));
        assert_eq!(&target, b"alpha");

        let alpha = overlay.resolve_following_at(b"/work/alpha").unwrap().0;
        let hard = overlay.resolve_following_at(b"/work/hard").unwrap().0;
        assert_eq!(alpha, hard);

        overlay
            .rename_at(b"/work/hard", b"/work/renamed", false)
            .unwrap();
        assert!(matches!(
            overlay.resolve_nofollow_at(b"/work/hard"),
            Err(OverlayError::NotFound)
        ));
        overlay.chmod_at(b"/work/alpha", 0o604, T2).unwrap();
        let atime = MutableTimestamp {
            seconds: 123,
            nanoseconds: 456_000_000,
        };
        let mtime = MutableTimestamp {
            seconds: 789,
            nanoseconds: 123_000_000,
        };
        overlay
            .set_times_at(b"/work/alpha", atime, mtime, T2)
            .unwrap();

        overlay.unlink_at(b"/work/sym", false).unwrap();
        overlay.unlink_at(b"/work/renamed", false).unwrap();
        overlay.unlink_at(b"/work/alpha", false).unwrap();
        overlay.unlink_at(b"/work", true).unwrap();
        assert!(matches!(
            overlay.resolve_nofollow_at(b"/work"),
            Err(OverlayError::NotFound)
        ));
    }

    #[test]
    fn rename_noreplace_preserves_both_names() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay
            .create_regular_at(b"/source", 0o600, 0, 0, T1)
            .unwrap();
        overlay
            .create_regular_at(b"/target", 0o600, 0, 0, T1)
            .unwrap();
        assert_eq!(
            overlay.rename_at(b"/source", b"/target", true),
            Err(OverlayError::AlreadyExists)
        );
        assert!(overlay.lookup_at(b"/source").unwrap().is_some());
        assert!(overlay.lookup_at(b"/target").unwrap().is_some());
    }

    #[test]
    fn rename_same_object_is_noop_but_noreplace_still_reports_existing_target() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);

        // A lower-only directory is not otherwise mutable in the Step-29 policy, but renaming a name
        // onto itself changes nothing and must therefore succeed without requiring copy-up support.
        assert_eq!(
            overlay.rename_at(b"/lower-dir", b"/lower-dir", false),
            Ok(())
        );
        assert!(overlay.lookup_at(b"/lower-dir").unwrap().is_some());
        assert_eq!(
            overlay.rename_at(b"/lower-dir", b"/lower-dir", true),
            Err(OverlayError::AlreadyExists)
        );

        // Two upper names for one inode are the same object as well. A normal rename is a no-op and
        // must leave both hard links intact; RENAME_NOREPLACE still rejects the existing target.
        overlay
            .create_regular_at(b"/file", 0o600, 0, 0, T1)
            .unwrap();
        overlay.link_regular_at(b"/file", b"/alias").unwrap();
        let file = overlay.lookup_at(b"/file").unwrap().unwrap();
        let alias = overlay.lookup_at(b"/alias").unwrap().unwrap();
        assert_eq!(file, alias);

        assert_eq!(overlay.rename_at(b"/file", b"/alias", false), Ok(()));
        assert_eq!(overlay.lookup_at(b"/file").unwrap(), Some(file));
        assert_eq!(overlay.lookup_at(b"/alias").unwrap(), Some(alias));
        assert_eq!(
            overlay.rename_at(b"/file", b"/alias", true),
            Err(OverlayError::AlreadyExists)
        );
    }

    #[test]
    fn readlink_returns_bounded_prefix_without_nul() {
        let bytes = archive_bytes();
        let mut overlay = overlay(&bytes);
        overlay
            .symlink_at(b"long-target", b"/sym", 0, 0, T1)
            .unwrap();
        let mut tiny = [0u8; 4];
        assert_eq!(overlay.readlink_at(b"/sym", &mut tiny), Ok(4));
        assert_eq!(&tiny, b"long");
    }
}
