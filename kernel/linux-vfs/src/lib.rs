// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub use kernal_cpio::EntryId;
use kernal_cpio::{Archive, Entry, FileType};

mod context;
pub use context::{DEFAULT_UMASK, FsContext};
mod cwd;
pub use cwd::DirectoryHandle;
mod directory;
pub use directory::{DirectoryEntry, DirectoryScan, ReadOnlyDirectory};
mod mutable {
    include!("mutable.rs");
    include!("mutable_scan.rs");
}
pub use mutable::{
    LINUX_NAME_MAX, MutableError, MutableMetadata, MutableNodeKind, MutableTimestamp,
};
mod rooted_mutable {
    include!("rooted_mutable.rs");
    include!("rooted_mutable_scan.rs");
}
pub use rooted_mutable::{
    MutableDirectoryEntry, MutableDirectoryHandle, MutableDirectoryScan, MutableNodeHandle,
    RootedMutableError, RootedMutableNamespace,
};
mod overlay;
pub use overlay::{
    OverlayError, OverlayMetadata, OverlayNamespace, OverlayNodeHandle, RetainedRegularHandle,
};
mod overlay_directory;
pub use overlay_directory::{OverlayDirectoryEntry, OverlayDirectoryHandle, OverlayDirectoryScan};

/// Linux `AT_FDCWD`. Step 29 initially resolves relative paths against the process root/cwd `/`.
pub const AT_FDCWD: i32 = -100;
/// Linux pathname window, including the terminating NUL, for the pinned Debian/Linux target.
pub const LINUX_PATH_MAX: usize = 4096;
/// Maximum non-NUL pathname bytes accepted by the Linux/VFS owner.
/// This is intentionally independent from `kernal-cpio`'s stored archive-name bound.
pub const MAX_PATH_BYTES: usize = LINUX_PATH_MAX - 1;
const _: () = assert!(MAX_PATH_BYTES > kernal_cpio::MAX_PATH_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPath,
    EmbeddedNul,
    PathTooLong,
    UnsupportedDirFd,
    Archive(kernal_cpio::Error),
    NotFound,
    NotDirectory,
    IsDirectory,
    SymlinkUnsupported,
    UnsupportedNode,
    HandleMismatch,
    OffsetOverflow,
}

impl From<kernal_cpio::Error> for Error {
    fn from(value: kernal_cpio::Error) -> Self {
        Self::Archive(value)
    }
}

/// Runtime-owned identity/generation for one immutable mounted initramfs root.
///
/// The protected-initrd/runtime owner chooses this value and must change it whenever the mounted
/// root identity changes. VFS file identities include it so an entry ordinal from another root can
/// never be accepted merely because mode/size happen to match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootId(u64);

impl RootId {
    pub const fn new(generation: u64) -> Self {
        Self(generation)
    }

    pub const fn generation(self) -> u64 {
        self.0
    }
}

/// Root-confined canonical path used by the Step-29 VFS owner.
///
/// The representation is relative to the process root: `/` is stored as an empty path and
/// `/etc/os-release` as `etc/os-release`. Repeated separators and `.` are removed. `..` is resolved
/// without ever escaping the root; at root it remains at root, matching normal chroot/root lookup
/// semantics. Path components are exact non-NUL bytes; no Unicode conversion or normalization is
/// performed. No allocation is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalPath {
    bytes: [u8; MAX_PATH_BYTES],
    len: usize,
}

impl CanonicalPath {
    pub fn resolve_at(dirfd: i32, path: &[u8]) -> Result<Self, Error> {
        if path.is_empty() {
            return Err(Error::EmptyPath);
        }
        if path.len() > MAX_PATH_BYTES {
            return Err(Error::PathTooLong);
        }
        if path.contains(&0) {
            return Err(Error::EmbeddedNul);
        }

        let absolute = path[0] == b'/';
        if !absolute && dirfd != AT_FDCWD {
            return Err(Error::UnsupportedDirFd);
        }

        let mut canonical = Self {
            bytes: [0; MAX_PATH_BYTES],
            len: 0,
        };

        for component in path.split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." {
                continue;
            }
            if component == b".." {
                canonical.pop_component();
                continue;
            }
            canonical.push_component(component)?;
        }
        Ok(canonical)
    }

    pub const fn is_root(&self) -> bool {
        self.len == 0
    }

    pub fn as_relative_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Exact CPIO/VFS lookup representation. The process root `/` maps to the validated CPIO root
    /// record `.`; every non-root path is already stored root-relative.
    pub fn as_archive_bytes(&self) -> &[u8] {
        if self.is_root() {
            b"."
        } else {
            self.as_relative_bytes()
        }
    }

    fn push_component(&mut self, component: &[u8]) -> Result<(), Error> {
        let separator = usize::from(self.len != 0);
        let new_len = self
            .len
            .checked_add(separator)
            .and_then(|value| value.checked_add(component.len()))
            .ok_or(Error::PathTooLong)?;
        if new_len > MAX_PATH_BYTES {
            return Err(Error::PathTooLong);
        }
        if separator != 0 {
            self.bytes[self.len] = b'/';
            self.len += 1;
        }
        let end = self.len + component.len();
        self.bytes[self.len..end].copy_from_slice(component);
        self.len = end;
        Ok(())
    }

    fn pop_component(&mut self) {
        if self.len == 0 {
            return;
        }
        let mut index = self.len;
        while index > 0 {
            index -= 1;
            if self.bytes[index] == b'/' {
                self.len = index;
                return;
            }
        }
        self.len = 0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Regular,
    Directory,
    Symlink,
    Other(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node<'a> {
    kind: NodeKind,
    mode: u32,
    data: &'a [u8],
}

impl<'a> Node<'a> {
    fn from_entry(entry: Entry<'a>) -> Self {
        let kind = match entry.file_type() {
            FileType::Regular => NodeKind::Regular,
            FileType::Directory => NodeKind::Directory,
            FileType::Symlink => NodeKind::Symlink,
            FileType::Other(value) => NodeKind::Other(value),
        };
        Self {
            kind,
            mode: entry.mode(),
            data: entry.data(),
        }
    }

    pub const fn kind(self) -> NodeKind {
        self.kind
    }

    pub const fn mode(self) -> u32 {
        self.mode
    }

    pub const fn data(self) -> &'a [u8] {
        self.data
    }

    pub fn size(self) -> u64 {
        self.data.len() as u64
    }
}

/// Persistent identity for one immutable regular file in a validated initramfs root.
///
/// This value is intentionally borrow-free and compact: root generation + bounded CPIO entry
/// ordinal + immutable metadata. It grants no byte access by itself; [`InitramfsRoot::read_at`]
/// re-enters the scoped archive, checks the root identity, resolves the ordinal through the existing
/// CPIO owner and revalidates type/mode/size before exposing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyFile {
    root_id: RootId,
    entry_id: EntryId,
    mode: u32,
    size: u64,
}

impl ReadOnlyFile {
    pub const fn new(root_id: RootId, entry_id: EntryId, mode: u32, size: u64) -> Self {
        Self {
            root_id,
            entry_id,
            mode,
            size,
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

    pub const fn size(self) -> u64 {
        self.size
    }
}

/// Read-only Step-29 root backed by one already fully validated Step-28 CPIO archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitramfsRoot<'a> {
    archive: Archive<'a>,
    root_id: RootId,
}

impl<'a> InitramfsRoot<'a> {
    pub const fn new(archive: Archive<'a>, root_id: RootId) -> Self {
        Self { archive, root_id }
    }

    pub const fn root_id(self) -> RootId {
        self.root_id
    }

    /// Resolves the normal Linux path-following policy through the shared component resolver.
    pub fn lookup_at(self, dirfd: i32, path: &[u8]) -> Result<Node<'a>, Error> {
        let (_, node, _) = self.resolve_following_at(dirfd, path)?;
        Ok(node)
    }

    /// Opens a regular file after following the shared component/symlink resolver.
    pub fn open_readonly_at(self, dirfd: i32, path: &[u8]) -> Result<ReadOnlyFile, Error> {
        let (entry_id, node, _) = self.resolve_following_at(dirfd, path)?;
        match node.kind() {
            NodeKind::Regular => Ok(ReadOnlyFile::new(
                self.root_id,
                entry_id,
                node.mode(),
                node.size(),
            )),
            NodeKind::Directory => Err(Error::IsDirectory),
            NodeKind::Symlink => Err(Error::SymlinkUnsupported),
            NodeKind::Other(_) => Err(Error::UnsupportedNode),
        }
    }

    pub fn read_at(
        self,
        file: ReadOnlyFile,
        offset: u64,
        max_len: usize,
    ) -> Result<&'a [u8], Error> {
        if file.root_id() != self.root_id {
            return Err(Error::HandleMismatch);
        }

        let entry = self
            .archive
            .entry_by_id(file.entry_id())?
            .ok_or(Error::HandleMismatch)?;
        let node = Node::from_entry(entry);
        if node.kind() != NodeKind::Regular
            || node.mode() != file.mode()
            || node.size() != file.size()
        {
            return Err(Error::HandleMismatch);
        }

        let start = usize::try_from(offset).map_err(|_| Error::OffsetOverflow)?;
        if start > node.data().len() {
            return Err(Error::OffsetOverflow);
        }
        let remaining = node.data().len() - start;
        let count = core::cmp::min(remaining, max_len);
        let end = start.checked_add(count).ok_or(Error::OffsetOverflow)?;
        Ok(&node.data()[start..end])
    }

    fn lookup_canonical(self, canonical: CanonicalPath) -> Result<(EntryId, Node<'a>), Error> {
        let relative = canonical.as_archive_bytes();
        self.validate_parent_components(relative)?;
        let (entry_id, entry) = self.archive.get_with_id(relative)?.ok_or(Error::NotFound)?;
        Ok((entry_id, Node::from_entry(entry)))
    }

    fn validate_parent_components(self, relative: &[u8]) -> Result<(), Error> {
        for (separator, byte) in relative.iter().enumerate() {
            if *byte != b'/' {
                continue;
            }
            let parent = &relative[..separator];
            let entry = self.archive.get(parent)?.ok_or(Error::NotFound)?;
            match entry.file_type() {
                FileType::Directory => {}
                FileType::Symlink => return Err(Error::SymlinkUnsupported),
                FileType::Regular | FileType::Other(_) => return Err(Error::NotDirectory),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_LEN: usize = 110;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const ROOT_A: RootId = RootId::new(1);
    const ROOT_B: RootId = RootId::new(2);

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

    fn finish_archive(out: &mut Vec<u8>) {
        entry(out, b"TRAILER!!!", 0, &[]);
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
    }

    fn archive() -> Vec<u8> {
        let mut out = Vec::new();
        entry(&mut out, b".", S_IFDIR | 0o755, &[]);
        entry(&mut out, b"etc", S_IFDIR | 0o755, &[]);
        entry(
            &mut out,
            b"etc/os-release",
            S_IFREG | 0o644,
            b"PRETTY_NAME=Debian GNU/Linux 13\n",
        );
        entry(&mut out, b"link", S_IFLNK | 0o777, b"etc/os-release");
        finish_archive(&mut out);
        out
    }

    #[test]
    fn canonicalizes_absolute_and_at_fdcwd_paths_inside_root() {
        let absolute = CanonicalPath::resolve_at(77, b"//etc/./../etc/os-release").unwrap();
        assert_eq!(absolute.as_relative_bytes(), b"etc/os-release");

        let clamped = CanonicalPath::resolve_at(AT_FDCWD, b"/../../etc/os-release").unwrap();
        assert_eq!(clamped.as_relative_bytes(), b"etc/os-release");

        let relative = CanonicalPath::resolve_at(AT_FDCWD, b"etc/os-release").unwrap();
        assert_eq!(relative.as_relative_bytes(), b"etc/os-release");
        assert_eq!(
            CanonicalPath::resolve_at(9, b"etc/os-release"),
            Err(Error::UnsupportedDirFd)
        );
    }

    #[test]
    fn linux_path_limit_is_independent_from_cpio_name_bound() {
        assert_eq!(LINUX_PATH_MAX, 4096);

        let exact = vec![b'a'; MAX_PATH_BYTES];
        let canonical = CanonicalPath::resolve_at(AT_FDCWD, &exact).unwrap();
        assert_eq!(canonical.as_relative_bytes().len(), MAX_PATH_BYTES);

        let too_long = vec![b'a'; MAX_PATH_BYTES + 1];
        assert_eq!(
            CanonicalPath::resolve_at(AT_FDCWD, &too_long),
            Err(Error::PathTooLong)
        );

        let collapsible_but_too_long = vec![b'/'; MAX_PATH_BYTES + 1];
        assert_eq!(
            CanonicalPath::resolve_at(AT_FDCWD, &collapsible_but_too_long),
            Err(Error::PathTooLong)
        );
    }

    #[test]
    fn malformed_paths_fail_closed() {
        assert_eq!(
            CanonicalPath::resolve_at(AT_FDCWD, b""),
            Err(Error::EmptyPath)
        );
        assert_eq!(
            CanonicalPath::resolve_at(AT_FDCWD, b"/etc/\0passwd"),
            Err(Error::EmbeddedNul)
        );
    }

    #[test]
    fn immutable_root_opens_regular_file_and_reports_node_types() {
        let bytes = archive();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let file = root.open_readonly_at(AT_FDCWD, b"/etc/os-release").unwrap();
        assert_eq!(file.root_id(), ROOT_A);
        assert_eq!(file.entry_id().index(), 2);
        assert_eq!(file.mode() & 0o777, 0o644);
        assert_eq!(file.size(), 32);

        assert_eq!(
            root.open_readonly_at(AT_FDCWD, b"/etc"),
            Err(Error::IsDirectory)
        );
        let linked = root.open_readonly_at(AT_FDCWD, b"/link").unwrap();
        assert_eq!(linked.entry_id(), file.entry_id());
        assert_eq!(
            root.lookup_at(AT_FDCWD, b"/link").unwrap().kind(),
            NodeKind::Regular
        );
        assert_eq!(root.lookup_at(AT_FDCWD, b"/missing"), Err(Error::NotFound));
    }

    #[test]
    fn non_utf8_user_path_resolves_exact_archive_entry() {
        let mut bytes = Vec::new();
        entry(&mut bytes, b".", S_IFDIR | 0o755, &[]);
        entry(&mut bytes, b"dir", S_IFDIR | 0o755, &[]);
        entry(&mut bytes, b"dir/\xffname", S_IFREG | 0o644, b"exact-bytes");
        finish_archive(&mut bytes);
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);

        let file = root.open_readonly_at(AT_FDCWD, b"/dir/\xffname").unwrap();
        assert_eq!(root.read_at(file, 0, usize::MAX).unwrap(), b"exact-bytes");
        assert_eq!(
            root.lookup_at(AT_FDCWD, b"/dir/\xfename"),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn persistent_handle_revalidates_root_entry_and_scoped_bytes() {
        let bytes = archive();
        let root_a = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        let root_b = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_B);
        let file = root_a
            .open_readonly_at(AT_FDCWD, b"/etc/os-release")
            .unwrap();

        assert_eq!(root_a.read_at(file, 0, 6).unwrap(), b"PRETTY");
        assert_eq!(
            root_a.read_at(file, 7, usize::MAX).unwrap(),
            b"NAME=Debian GNU/Linux 13\n"
        );
        assert_eq!(root_a.read_at(file, file.size(), 1).unwrap(), b"");
        assert_eq!(root_b.read_at(file, 0, 1), Err(Error::HandleMismatch));
        assert_eq!(
            root_a.read_at(file, file.size() + 1, 1),
            Err(Error::OffsetOverflow)
        );
    }

    #[test]
    fn validates_every_parent_component_before_final_lookup() {
        let mut regular_parent = Vec::new();
        entry(&mut regular_parent, b".", S_IFDIR | 0o755, &[]);
        entry(&mut regular_parent, b"regular", S_IFREG | 0o644, b"parent");
        entry(
            &mut regular_parent,
            b"regular/child",
            S_IFREG | 0o644,
            b"child",
        );
        finish_archive(&mut regular_parent);
        let root = InitramfsRoot::new(Archive::parse(&regular_parent).unwrap(), ROOT_A);
        assert_eq!(
            root.lookup_at(AT_FDCWD, b"/regular/child"),
            Err(Error::NotDirectory)
        );

        let mut symlink_parent = Vec::new();
        entry(&mut symlink_parent, b".", S_IFDIR | 0o755, &[]);
        entry(&mut symlink_parent, b"target", S_IFDIR | 0o755, &[]);
        entry(
            &mut symlink_parent,
            b"target/child",
            S_IFREG | 0o644,
            b"child",
        );
        entry(&mut symlink_parent, b"symlink", S_IFLNK | 0o777, b"target");
        finish_archive(&mut symlink_parent);
        let root = InitramfsRoot::new(Archive::parse(&symlink_parent).unwrap(), ROOT_A);
        assert_eq!(
            root.lookup_at(AT_FDCWD, b"/symlink/child").unwrap().data(),
            b"child"
        );

        let mut missing_parent = Vec::new();
        entry(&mut missing_parent, b".", S_IFDIR | 0o755, &[]);
        entry(
            &mut missing_parent,
            b"missing/child",
            S_IFREG | 0o644,
            b"child",
        );
        finish_archive(&mut missing_parent);
        let root = InitramfsRoot::new(Archive::parse(&missing_parent).unwrap(), ROOT_A);
        assert_eq!(
            root.lookup_at(AT_FDCWD, b"/missing/child"),
            Err(Error::NotFound)
        );

        let mut nested = Vec::new();
        entry(&mut nested, b".", S_IFDIR | 0o755, &[]);
        entry(&mut nested, b"a", S_IFDIR | 0o755, &[]);
        entry(&mut nested, b"a/b", S_IFDIR | 0o755, &[]);
        entry(&mut nested, b"a/b/file", S_IFREG | 0o644, b"ok");
        finish_archive(&mut nested);
        let root = InitramfsRoot::new(Archive::parse(&nested).unwrap(), ROOT_A);
        assert_eq!(
            root.lookup_at(AT_FDCWD, b"/a/b/file").unwrap().kind(),
            NodeKind::Regular
        );
    }

    #[test]
    fn root_path_resolves_to_archive_root_directory() {
        let bytes = archive();
        let root = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT_A);
        assert_eq!(
            root.lookup_at(AT_FDCWD, b"/").unwrap().kind(),
            NodeKind::Directory
        );
    }
}
