// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{
    AT_FDCWD, CanonicalPath, Error, InitramfsRoot, LINUX_NAME_MAX, MAX_PATH_BYTES, Node, NodeKind,
    RootId,
};
use kernal_cpio::EntryId;

const MAX_SYMLINK_FOLLOWS: usize = 40;
const DIRECTORY_DOT_ENTRIES: usize = 2;

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

/// Compact borrow-free identity for one immutable directory in the validated initramfs root.
///
/// Root identity plus stable CPIO entry ordinal is the persistent authority. The exact path is
/// re-derived from that immutable entry and validated on every directory operation instead of being
/// copied into each descriptor. This keeps FD state bounded independently of Linux `PATH_MAX`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyDirectory {
    root_id: RootId,
    entry_id: EntryId,
    mode: u32,
}

impl ReadOnlyDirectory {
    /// Constructs a non-authoritative directory identity. Every operation revalidates root, entry
    /// identity, type and mode against the scoped `InitramfsRoot` before exposing archive state.
    pub const fn new(root_id: RootId, entry_id: EntryId, mode: u32) -> Self {
        Self {
            root_id,
            entry_id,
            mode,
        }
    }

    pub const fn root_id(self) -> RootId {
        self.root_id
    }

    pub const fn entry_id(self) -> EntryId {
        self.entry_id
    }

    pub const fn mode(self) -> u32 {
        self.mode
    }
}

/// One directory entry emitted by the deterministic Linux directory cursor policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntry<'a> {
    entry_id: EntryId,
    name: &'a [u8],
    kind: NodeKind,
    mode: u32,
    size: u64,
}

impl<'a> DirectoryEntry<'a> {
    pub const fn entry_id(self) -> EntryId {
        self.entry_id
    }

    pub const fn name(self) -> &'a [u8] {
        self.name
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

/// Result and proof of one bounded, root-validated directory scan step.
///
/// All fields are private and there is no public constructor, so safe callers can only obtain this
/// value from [`InitramfsRoot::directory_entry_from`]. Besides the delivered child it carries the
/// exact directory identity and cursor transition that an FD owner may commit after successful
/// usercopy. Linux-visible cursor 0 is `.`, cursor 1 is `..`, and archive scanning starts at cursor
/// 2 with CPIO ordinal `cursor - 2`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryScan<'a> {
    entry: DirectoryEntry<'a>,
    directory: ReadOnlyDirectory,
    start_cursor: usize,
    next_cursor: usize,
}

impl<'a> DirectoryScan<'a> {
    pub const fn entry(self) -> DirectoryEntry<'a> {
        self.entry
    }

    pub const fn directory(self) -> ReadOnlyDirectory {
        self.directory
    }

    pub const fn start_cursor(self) -> usize {
        self.start_cursor
    }

    pub const fn next_cursor(self) -> usize {
        self.next_cursor
    }
}

impl<'a> InitramfsRoot<'a> {
    /// Resolves one pathname component-by-component and follows the final symlink.
    /// Absolute paths ignore `dirfd`, matching Linux `*at` behavior.
    pub fn resolve_following_at(
        self,
        dirfd: i32,
        path: &[u8],
    ) -> Result<(EntryId, Node<'a>, CanonicalPath), Error> {
        let absolute = path.first().copied() == Some(b'/');
        if !absolute && dirfd != AT_FDCWD {
            return Err(Error::UnsupportedDirFd);
        }
        let root = CanonicalPath::resolve_at(AT_FDCWD, b"/")?;
        self.resolve_components(root, path, FinalSymlinkPolicy::Follow)
    }

    /// Resolves one pathname component-by-component but returns a final symlink itself unless a
    /// trailing slash makes directory resolution mandatory. Intermediate symlinks are always
    /// followed. This is the shared policy boundary for later `AT_SYMLINK_NOFOLLOW`/`O_NOFOLLOW`.
    pub fn resolve_nofollow_at(
        self,
        dirfd: i32,
        path: &[u8],
    ) -> Result<(EntryId, Node<'a>, CanonicalPath), Error> {
        let absolute = path.first().copied() == Some(b'/');
        if !absolute && dirfd != AT_FDCWD {
            return Err(Error::UnsupportedDirFd);
        }
        let root = CanonicalPath::resolve_at(AT_FDCWD, b"/")?;
        self.resolve_components(root, path, FinalSymlinkPolicy::NoFollow)
    }

    /// Resolves a relative path beneath an already-open, root-bound directory. Absolute paths ignore
    /// the supplied directory, exactly as Linux ignores `dirfd` for absolute `*at` pathnames.
    pub fn resolve_from_directory_following(
        self,
        directory: ReadOnlyDirectory,
        path: &[u8],
    ) -> Result<(EntryId, Node<'a>, CanonicalPath), Error> {
        if path.first().copied() == Some(b'/') {
            return self.resolve_following_at(AT_FDCWD, path);
        }
        let prefix = self.validate_directory(directory)?;
        let base = if prefix.is_empty() {
            CanonicalPath::resolve_at(AT_FDCWD, b"/")?
        } else {
            CanonicalPath::resolve_at(AT_FDCWD, prefix)?
        };
        self.resolve_components(base, path, FinalSymlinkPolicy::Follow)
    }

    /// No-follow counterpart of [`InitramfsRoot::resolve_from_directory_following`].
    pub fn resolve_from_directory_nofollow(
        self,
        directory: ReadOnlyDirectory,
        path: &[u8],
    ) -> Result<(EntryId, Node<'a>, CanonicalPath), Error> {
        if path.first().copied() == Some(b'/') {
            return self.resolve_nofollow_at(AT_FDCWD, path);
        }
        let prefix = self.validate_directory(directory)?;
        let base = if prefix.is_empty() {
            CanonicalPath::resolve_at(AT_FDCWD, b"/")?
        } else {
            CanonicalPath::resolve_at(AT_FDCWD, prefix)?
        };
        self.resolve_components(base, path, FinalSymlinkPolicy::NoFollow)
    }

    fn resolve_components(
        self,
        base: CanonicalPath,
        path: &[u8],
        final_policy: FinalSymlinkPolicy,
    ) -> Result<(EntryId, Node<'a>, CanonicalPath), Error> {
        let mut pending = PendingPath::from_path(path)?;
        let mut canonical = if path.first().copied() == Some(b'/') {
            CanonicalPath::resolve_at(AT_FDCWD, b"/")?
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
                let (entry_id, node) = self.lookup_canonical(canonical)?;
                if node.kind() != NodeKind::Directory {
                    return Err(Error::NotDirectory);
                }
                return Ok((entry_id, node, canonical));
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
                return Err(Error::PathTooLong);
            }

            let mut candidate = canonical;
            candidate.push_component(component)?;
            let (entry_id, node) = self.lookup_canonical(candidate)?;
            let follow_symlink = node.kind() == NodeKind::Symlink
                && (!final_component
                    || final_policy == FinalSymlinkPolicy::Follow
                    || must_be_directory);

            if follow_symlink {
                if followed == MAX_SYMLINK_FOLLOWS {
                    return Err(Error::SymlinkUnsupported);
                }
                followed += 1;
                let target = node.data();
                let target_is_absolute = target.first().copied() == Some(b'/');
                let suffix_len = pending.len - end;
                let mut suffix = [0u8; MAX_PATH_BYTES];
                suffix[..suffix_len].copy_from_slice(&pending.bytes[end..pending.len]);
                pending.replace_with_symlink(target, &suffix[..suffix_len])?;
                must_be_directory = pending.requires_directory();
                if target_is_absolute {
                    canonical = CanonicalPath::resolve_at(AT_FDCWD, b"/")?;
                }
                cursor = 0;
                continue;
            }

            if !final_component && node.kind() != NodeKind::Directory {
                return Err(Error::NotDirectory);
            }
            if final_component {
                if must_be_directory && node.kind() != NodeKind::Directory {
                    return Err(Error::NotDirectory);
                }
                return Ok((entry_id, node, candidate));
            }
            canonical = candidate;
        }
    }

    /// Opens one directory through the shared component-wise symlink resolver.
    pub fn open_directory_at(self, dirfd: i32, path: &[u8]) -> Result<ReadOnlyDirectory, Error> {
        let (entry_id, node, _) = self.resolve_following_at(dirfd, path)?;
        match node.kind() {
            NodeKind::Directory => Ok(ReadOnlyDirectory::new(self.root_id, entry_id, node.mode())),
            NodeKind::Regular | NodeKind::Symlink => Err(Error::NotDirectory),
            NodeKind::Other(_) => Err(Error::UnsupportedNode),
        }
    }

    /// Returns the next Linux directory record from the VFS-owned cursor state.
    ///
    /// Cursor 0 emits synthetic `.`, cursor 1 emits synthetic `..`, and cursor values at or above 2
    /// scan the immutable CPIO archive from ordinal `cursor - 2`. Every emitted transition remains a
    /// private-constructor [`DirectoryScan`] witness, so the FD owner can commit only VFS-produced
    /// cursor transitions after successful usercopy.
    pub fn directory_entry_from(
        self,
        directory: ReadOnlyDirectory,
        cursor: usize,
    ) -> Result<Option<DirectoryScan<'a>>, Error> {
        let prefix = self.validate_directory(directory)?;
        let end_cursor = self
            .archive
            .entry_count()
            .checked_add(DIRECTORY_DOT_ENTRIES)
            .ok_or(Error::OffsetOverflow)?;
        if cursor > end_cursor {
            return Err(Error::OffsetOverflow);
        }

        if cursor == 0 {
            return Ok(Some(DirectoryScan {
                entry: DirectoryEntry {
                    entry_id: directory.entry_id(),
                    name: b".",
                    kind: NodeKind::Directory,
                    mode: directory.mode(),
                    size: 0,
                },
                directory,
                start_cursor: 0,
                next_cursor: 1,
            }));
        }

        if cursor == 1 {
            let parent = self.parent_directory(directory, prefix)?;
            return Ok(Some(DirectoryScan {
                entry: DirectoryEntry {
                    entry_id: parent.entry_id(),
                    name: b"..",
                    kind: NodeKind::Directory,
                    mode: parent.mode(),
                    size: 0,
                },
                directory,
                start_cursor: 1,
                next_cursor: DIRECTORY_DOT_ENTRIES,
            }));
        }

        let mut index = cursor
            .checked_sub(DIRECTORY_DOT_ENTRIES)
            .ok_or(Error::OffsetOverflow)?;
        while index < self.archive.entry_count() {
            let entry_id =
                EntryId::from_index(u16::try_from(index).map_err(|_| Error::OffsetOverflow)?);
            let entry = self
                .archive
                .entry_by_id(entry_id)?
                .ok_or(Error::HandleMismatch)?;
            let path = entry.path();
            if let Some(name) = immediate_child_name(prefix, path) {
                let node = Node::from_entry(entry);
                let next_cursor = index
                    .checked_add(1)
                    .and_then(|value| value.checked_add(DIRECTORY_DOT_ENTRIES))
                    .ok_or(Error::OffsetOverflow)?;
                return Ok(Some(DirectoryScan {
                    entry: DirectoryEntry {
                        entry_id,
                        name,
                        kind: node.kind(),
                        mode: node.mode(),
                        size: node.size(),
                    },
                    directory,
                    start_cursor: cursor,
                    next_cursor,
                }));
            }
            index = index.checked_add(1).ok_or(Error::OffsetOverflow)?;
        }
        Ok(None)
    }

    /// Revalidates and resolves the parent identity used by synthetic `..`.
    fn parent_directory(
        self,
        directory: ReadOnlyDirectory,
        prefix: &'a [u8],
    ) -> Result<ReadOnlyDirectory, Error> {
        if prefix.is_empty() {
            return Ok(directory);
        }
        let parent_path = match prefix.iter().rposition(|byte| *byte == b'/') {
            Some(separator) => &prefix[..separator],
            None => b".",
        };
        let (entry_id, entry) = self
            .archive
            .get_with_id(parent_path)?
            .ok_or(Error::HandleMismatch)?;
        let node = Node::from_entry(entry);
        if node.kind() != NodeKind::Directory {
            return Err(Error::HandleMismatch);
        }
        Ok(ReadOnlyDirectory::new(self.root_id, entry_id, node.mode()))
    }

    /// Revalidates the persistent directory identity and returns its exact root-relative byte prefix.
    fn validate_directory(self, directory: ReadOnlyDirectory) -> Result<&'a [u8], Error> {
        if directory.root_id != self.root_id {
            return Err(Error::HandleMismatch);
        }
        let entry = self
            .archive
            .entry_by_id(directory.entry_id)?
            .ok_or(Error::HandleMismatch)?;
        let node = Node::from_entry(entry);
        if node.kind() != NodeKind::Directory || node.mode() != directory.mode {
            return Err(Error::HandleMismatch);
        }
        if entry.path() == b"." {
            Ok(b"")
        } else {
            Ok(entry.path())
        }
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

    if relative.is_empty() || relative.len() > MAX_PATH_BYTES || relative.contains(&b'/') {
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
    const S_IFLNK: u32 = 0o120000;
    const ROOT_A: RootId = RootId::new(11);
    const ROOT_B: RootId = RootId::new(12);

    fn hex(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn push_entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
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

    fn finish_archive(out: &mut Vec<u8>) {
        push_entry(out, b"TRAILER!!!", 0, b"");
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
    }

    fn archive_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        push_entry(&mut out, b".", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"etc", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"etc/hosts", S_IFREG | 0o644, b"127.0.0.1\n");
        push_entry(&mut out, b"etc/ssl", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"etc/ssl/cert.pem", S_IFREG | 0o644, b"cert");
        push_entry(
            &mut out,
            b"etc/localtime",
            S_IFLNK | 0o777,
            b"../usr/share/zoneinfo/UTC",
        );
        push_entry(&mut out, b"usr", S_IFDIR | 0o755, b"");
        finish_archive(&mut out);
        out
    }

    fn symlink_archive_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        push_entry(&mut out, b".", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"bin", S_IFLNK | 0o777, b"usr/bin");
        push_entry(&mut out, b"usr", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"usr/bin", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"usr/bin/sh", S_IFLNK | 0o777, b"dash");
        push_entry(&mut out, b"usr/bin/dash", S_IFREG | 0o755, b"dash");
        push_entry(&mut out, b"usr/share", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"usr/share/zoneinfo", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"usr/share/zoneinfo/UTC", S_IFREG | 0o644, b"UTC");
        push_entry(&mut out, b"etc", S_IFDIR | 0o755, b"");
        push_entry(
            &mut out,
            b"etc/localtime",
            S_IFLNK | 0o777,
            b"../usr/share/zoneinfo/UTC",
        );
        push_entry(&mut out, b"etc/os-release", S_IFREG | 0o644, b"debian");
        push_entry(&mut out, b"alias", S_IFLNK | 0o777, b"/etc/os-release");
        push_entry(
            &mut out,
            b"rootup",
            S_IFLNK | 0o777,
            b"../../etc/os-release",
        );
        push_entry(&mut out, b"a", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"a/link", S_IFLNK | 0o777, b"target/deep");
        push_entry(&mut out, b"a/target", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"a/target/deep", S_IFDIR | 0o755, b"");
        push_entry(&mut out, b"a/target/x", S_IFREG | 0o644, b"x");
        push_entry(&mut out, b"loop-a", S_IFLNK | 0o777, b"loop-b");
        push_entry(&mut out, b"loop-b", S_IFLNK | 0o777, b"loop-a");
        push_entry(&mut out, b"linkdir", S_IFLNK | 0o777, b"etc");
        push_entry(&mut out, b"linkfile", S_IFLNK | 0o777, b"etc/os-release");
        finish_archive(&mut out);
        out
    }

    #[test]
    fn opens_directory_with_compact_borrow_free_identity() {
        let bytes = archive_bytes();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let directory = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();
        assert_eq!(directory.root_id(), ROOT_A);
        assert_eq!(directory.entry_id().index(), 1);
        assert_eq!(directory.mode() & 0o777, 0o755);
        assert_eq!(
            root.open_directory_at(AT_FDCWD, b"/etc/hosts"),
            Err(Error::NotDirectory)
        );
    }

    #[test]
    fn component_resolver_follows_relative_absolute_and_intermediate_links() {
        let bytes = symlink_archive_bytes();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);

        let (_, shell, canonical) = root.resolve_following_at(AT_FDCWD, b"/bin/sh").unwrap();
        assert_eq!(shell.kind(), NodeKind::Regular);
        assert_eq!(shell.data(), b"dash");
        assert_eq!(canonical.as_relative_bytes(), b"usr/bin/dash");

        let (_, timezone, canonical) = root
            .resolve_following_at(AT_FDCWD, b"/etc/localtime")
            .unwrap();
        assert_eq!(timezone.data(), b"UTC");
        assert_eq!(canonical.as_relative_bytes(), b"usr/share/zoneinfo/UTC");

        let (_, release, canonical) = root.resolve_following_at(AT_FDCWD, b"/alias").unwrap();
        assert_eq!(release.data(), b"debian");
        assert_eq!(canonical.as_relative_bytes(), b"etc/os-release");

        let (_, confined, _) = root.resolve_following_at(AT_FDCWD, b"/rootup").unwrap();
        assert_eq!(confined.data(), b"debian");
    }

    #[test]
    fn component_resolver_processes_dotdot_after_symlink_substitution() {
        let bytes = symlink_archive_bytes();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let (_, node, canonical) = root
            .resolve_following_at(AT_FDCWD, b"/a/link/../x")
            .unwrap();
        assert_eq!(node.data(), b"x");
        assert_eq!(canonical.as_relative_bytes(), b"a/target/x");
    }

    #[test]
    fn component_resolver_bounds_loops_expansion_and_trailing_slash() {
        let bytes = symlink_archive_bytes();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        assert_eq!(
            root.resolve_following_at(AT_FDCWD, b"/loop-a"),
            Err(Error::SymlinkUnsupported)
        );
        assert_eq!(
            root.resolve_following_at(AT_FDCWD, b"/linkfile/"),
            Err(Error::NotDirectory)
        );
        assert_eq!(
            root.resolve_following_at(AT_FDCWD, b"/linkdir/")
                .unwrap()
                .1
                .kind(),
            NodeKind::Directory
        );

        let mut overflow = Vec::new();
        push_entry(&mut overflow, b".", S_IFDIR | 0o755, b"");
        let long_target = vec![b'a'; MAX_PATH_BYTES];
        push_entry(&mut overflow, b"long", S_IFLNK | 0o777, &long_target);
        finish_archive(&mut overflow);
        let overflow_root = InitramfsRoot::new(Archive::parse(&overflow).unwrap(), ROOT_A);
        assert_eq!(
            overflow_root.resolve_following_at(AT_FDCWD, b"/long/x"),
            Err(Error::PathTooLong)
        );
    }

    #[test]
    fn component_resolver_has_explicit_final_nofollow_policy() {
        let bytes = symlink_archive_bytes();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let (_, link, canonical) = root.resolve_nofollow_at(AT_FDCWD, b"/alias").unwrap();
        assert_eq!(link.kind(), NodeKind::Symlink);
        assert_eq!(canonical.as_relative_bytes(), b"alias");

        let (_, target, _) = root.resolve_nofollow_at(AT_FDCWD, b"/linkdir/").unwrap();
        assert_eq!(target.kind(), NodeKind::Directory);
    }

    #[test]
    fn relative_at_resolution_uses_root_bound_directory_identity() {
        let bytes = symlink_archive_bytes();
        let root_a = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let root_b = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_B);
        let etc = root_a.open_directory_at(AT_FDCWD, b"/etc").unwrap();
        let (_, node, canonical) = root_a
            .resolve_from_directory_following(etc, b"os-release")
            .unwrap();
        assert_eq!(node.data(), b"debian");
        assert_eq!(canonical.as_relative_bytes(), b"etc/os-release");
        assert_eq!(
            root_b.resolve_from_directory_following(etc, b"os-release"),
            Err(Error::HandleMismatch)
        );
    }

    #[test]
    fn scans_dot_dotdot_then_immediate_children_in_archive_order() {
        let bytes = archive_bytes();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let directory = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();

        let dot = root.directory_entry_from(directory, 0).unwrap().unwrap();
        assert_eq!(dot.entry().name(), b".");
        assert_eq!(dot.entry().entry_id(), directory.entry_id());
        assert_eq!(dot.entry().kind(), NodeKind::Directory);
        assert_eq!(dot.next_cursor(), 1);

        let dotdot = root
            .directory_entry_from(directory, dot.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(dotdot.entry().name(), b"..");
        assert_eq!(dotdot.entry().entry_id().index(), 0);
        assert_eq!(dotdot.entry().kind(), NodeKind::Directory);
        assert_eq!(dotdot.next_cursor(), DIRECTORY_DOT_ENTRIES);

        let first = root
            .directory_entry_from(directory, dotdot.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(first.entry().name(), b"hosts");
        assert_eq!(first.entry().kind(), NodeKind::Regular);
        assert_eq!(first.directory(), directory);
        assert_eq!(first.start_cursor(), DIRECTORY_DOT_ENTRIES);

        let second = root
            .directory_entry_from(directory, first.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(second.entry().name(), b"ssl");
        assert_eq!(second.entry().kind(), NodeKind::Directory);
        assert_eq!(second.start_cursor(), first.next_cursor());

        let third = root
            .directory_entry_from(directory, second.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(third.entry().name(), b"localtime");
        assert_eq!(third.entry().kind(), NodeKind::Symlink);
        assert!(
            root.directory_entry_from(directory, third.next_cursor())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn nested_dotdot_uses_parent_directory_identity() {
        let bytes = archive_bytes();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let etc = root.open_directory_at(AT_FDCWD, b"/etc").unwrap();
        let ssl = root.open_directory_at(AT_FDCWD, b"/etc/ssl").unwrap();
        let dotdot = root.directory_entry_from(ssl, 1).unwrap().unwrap();
        assert_eq!(dotdot.entry().name(), b"..");
        assert_eq!(dotdot.entry().entry_id(), etc.entry_id());
        assert_eq!(dotdot.entry().mode(), etc.mode());
    }

    #[test]
    fn root_dotdot_points_to_root_and_archive_scan_reaches_eof() {
        let bytes = archive_bytes();
        let archive = Archive::parse(&bytes).unwrap();
        let root = InitramfsRoot::new(archive, ROOT_A);
        let directory = root.open_directory_at(AT_FDCWD, b"/").unwrap();

        let dot = root.directory_entry_from(directory, 0).unwrap().unwrap();
        let dotdot = root
            .directory_entry_from(directory, dot.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(dot.entry().entry_id(), directory.entry_id());
        assert_eq!(dotdot.entry().entry_id(), directory.entry_id());

        let first = root
            .directory_entry_from(directory, dotdot.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(first.entry().name(), b"etc");
        let second = root
            .directory_entry_from(directory, first.next_cursor())
            .unwrap()
            .unwrap();
        assert_eq!(second.entry().name(), b"usr");
        assert!(
            root.directory_entry_from(directory, second.next_cursor())
                .unwrap()
                .is_none()
        );

        let eof_cursor = archive
            .entry_count()
            .checked_add(DIRECTORY_DOT_ENTRIES)
            .unwrap();
        assert!(
            root.directory_entry_from(directory, eof_cursor)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn directory_identity_is_root_bound_and_cursor_checked() {
        let bytes = archive_bytes();
        let root_a = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let root_b = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_B);
        let directory = root_a.open_directory_at(AT_FDCWD, b"/etc").unwrap();
        assert_eq!(
            root_b.directory_entry_from(directory, 0),
            Err(Error::HandleMismatch)
        );
        assert_eq!(
            root_a.directory_entry_from(directory, usize::MAX),
            Err(Error::OffsetOverflow)
        );
    }
}
