// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::{
    CanonicalPath, DirectoryHandle, Error, LINUX_PATH_MAX, MAX_PATH_BYTES, RootId,
    RootedMutableError, RootedMutableNamespace,
};

/// Linux's conventional initial process umask. The runtime may replace this value during process
/// construction, but the VFS owner keeps the mask bounded to the permission bits Linux actually
/// applies during object creation.
pub const DEFAULT_UMASK: u32 = 0o022;
const UMASK_BITS: u32 = 0o777;

/// Bounded process filesystem context for Step 29.
///
/// `root` is the exact generation-safe [`RootId`] already owned by the accepted VFS. `cwd` is an
/// opaque [`DirectoryHandle`] minted only after the namespace owner validates directory provenance.
/// Keeping the identity rather than only a [`CanonicalPath`] prevents callers from laundering an
/// arbitrary root/path scalar pair into process cwd state.
///
/// A mutable cwd owns one namespace lifetime hold, so this context is intentionally not `Copy` or
/// implicitly `Clone`. Context duplication must acquire a distinct VFS-owned hold explicitly.
#[derive(Debug, Eq, PartialEq)]
pub struct FsContext {
    root: RootId,
    cwd: DirectoryHandle,
    umask: u32,
}

impl FsContext {
    pub const fn new(root: RootId) -> Self {
        Self {
            root,
            cwd: DirectoryHandle::root(root),
            umask: DEFAULT_UMASK,
        }
    }

    pub const fn root(&self) -> RootId {
        self.root
    }

    /// Returns the VFS-produced cwd identity retained by this process context.
    pub const fn cwd_handle(&self) -> DirectoryHandle {
        self.cwd
    }

    pub const fn umask(&self) -> u32 {
        self.umask
    }

    /// Applies Linux `umask(2)` low permission-bit semantics and returns the previous mask.
    pub fn replace_umask(&mut self, requested: u32) -> u32 {
        let previous = self.umask;
        self.umask = requested & UMASK_BITS;
        previous
    }

    /// Applies the current process umask to one caller-supplied create mode. Special mode bits are
    /// preserved; only the rwx permission bits selected by the process mask are cleared.
    pub const fn apply_creation_mode(&self, mode: u32) -> u32 {
        mode & !self.umask
    }

    /// Replaces cwd as one VFS-owned lifetime transaction.
    ///
    /// Mutable directories acquire their independent cwd hold before publication. Only after the new
    /// identity is published is the old hold released. If old-hold release fails, the previous cwd is
    /// restored and the newly acquired hold is rolled back. Root and immutable directory identities
    /// require no mutable-node lifetime reference.
    pub fn set_cwd<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        &mut self,
        namespace: &mut RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
        cwd: DirectoryHandle,
    ) -> Result<(), RootedMutableError> {
        if cwd.root_id() != self.root || namespace.root_id() != self.root {
            return Err(RootedMutableError::Path(Error::HandleMismatch));
        }

        // Even a value-equal cwd must be revalidated against the supplied namespace owner before
        // taking the no-op path. Two mutable namespaces may intentionally share one RootId while
        // carrying distinct namespace-instance witnesses; equality with the process's current token
        // must never let a foreign owner bypass that validation. `refresh_in` is identity-only for
        // mutable directories and acquires no lifetime hold, so a true same-owner no-op stays inert.
        let cwd = cwd.refresh_in(namespace)?;
        if cwd == self.cwd {
            return Ok(());
        }

        cwd.retain_in(namespace)?;
        let previous = self.cwd;
        self.cwd = cwd;
        if let Err(error) = previous.release_in(namespace) {
            self.cwd = previous;
            let _ = cwd.release_in(namespace);
            return Err(error);
        }
        Ok(())
    }

    /// Releases the process-owned cwd hold and returns the context to its bound root. This explicit
    /// teardown is required because `Drop` cannot borrow the external mutable namespace owner.
    pub fn release_cwd<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        &mut self,
        namespace: &mut RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
    ) -> Result<(), RootedMutableError> {
        if namespace.root_id() != self.root {
            return Err(RootedMutableError::Path(Error::HandleMismatch));
        }
        let previous = self.cwd;
        previous.release_in(namespace)?;
        self.cwd = DirectoryHandle::root(self.root);
        Ok(())
    }

    /// Revalidates the cwd identity and materializes its current pathname only for a caller that
    /// actually needs text. Identity-based namespace work does not require this operation.
    pub fn refresh_cwd<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        &mut self,
        namespace: &RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
    ) -> Result<CanonicalPath, RootedMutableError> {
        let refreshed = self.cwd.refresh_in(namespace)?;
        let canonical = refreshed.canonical_path_in(namespace)?;
        self.cwd = refreshed;
        Ok(canonical)
    }

    /// Resolves one Linux pathname to bounded canonical text using cwd only when the pathname is
    /// relative. This is a textual compatibility helper; identity-relative namespace operations
    /// should consume [`Self::cwd_handle`] directly and therefore remain valid beyond PATH_MAX.
    pub fn resolve_live<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        &mut self,
        namespace: &RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
        path: &[u8],
    ) -> Result<CanonicalPath, RootedMutableError> {
        if path.first().copied() == Some(b'/') {
            return CanonicalPath::resolve_from(CanonicalPath::root(), path)
                .map_err(RootedMutableError::Path);
        }
        let base = self.refresh_cwd(namespace)?;
        CanonicalPath::resolve_from(base, path).map_err(RootedMutableError::Path)
    }

    /// Materializes the raw Linux `getcwd(2)` result from the current live cwd identity, including
    /// its terminating NUL, and returns the NUL-inclusive success length.
    ///
    /// `RootedMutableError::Path(Error::PathTooLong)` maps to `ENAMETOOLONG` and
    /// `RootedMutableError::Path(Error::OffsetOverflow)` maps to `ERANGE` at the syscall boundary.
    /// A mutable directory that no longer has a live dentry path returns its namespace error rather
    /// than a stale pathname.
    pub fn write_getcwd_live<const NODES: usize, const DENTRIES: usize, const FILE_BYTES: usize>(
        &mut self,
        namespace: &RootedMutableNamespace<NODES, DENTRIES, FILE_BYTES>,
        output: &mut [u8],
    ) -> Result<usize, RootedMutableError> {
        let canonical = self.refresh_cwd(namespace)?;
        write_getcwd_path(canonical, output).map_err(RootedMutableError::Path)
    }
}

fn write_getcwd_path(path: CanonicalPath, output: &mut [u8]) -> Result<usize, Error> {
    let required = getcwd_required_len(path)?;
    if output.len() < required {
        return Err(Error::OffsetOverflow);
    }
    let path_len = path
        .write_absolute(&mut output[..required - 1])
        .ok_or(Error::OffsetOverflow)?;
    output[path_len] = 0;
    Ok(required)
}

fn getcwd_required_len(path: CanonicalPath) -> Result<usize, Error> {
    let absolute_len = path
        .as_relative_bytes()
        .len()
        .checked_add(1)
        .ok_or(Error::PathTooLong)?;
    let required = absolute_len.checked_add(1).ok_or(Error::PathTooLong)?;
    if required > LINUX_PATH_MAX {
        return Err(Error::PathTooLong);
    }
    Ok(required)
}

impl CanonicalPath {
    pub const fn root() -> Self {
        Self {
            bytes: [0; MAX_PATH_BYTES],
            len: 0,
        }
    }

    /// Resolves a path from one already-canonical, root-confined base. Absolute paths ignore the
    /// base; relative paths begin at it. Repeated separators, `.` and `..` use the same canonical
    /// rules as the accepted Step-29 root resolver and `..` can never escape above `/`.
    pub fn resolve_from(base: Self, path: &[u8]) -> Result<Self, Error> {
        if path.is_empty() {
            return Err(Error::EmptyPath);
        }
        if path.len() > MAX_PATH_BYTES {
            return Err(Error::PathTooLong);
        }
        if path.contains(&0) {
            return Err(Error::EmbeddedNul);
        }

        let mut canonical = if path[0] == b'/' { Self::root() } else { base };
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

    /// Writes `/` for the root and `/<relative>` for every other canonical path.
    pub fn write_absolute(self, output: &mut [u8]) -> Option<usize> {
        let required = self.len.checked_add(1)?;
        if output.len() < required {
            return None;
        }
        output[0] = b'/';
        if self.len != 0 {
            output[1..required].copy_from_slice(self.as_relative_bytes());
        }
        Some(required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MutableError, MutableTimestamp, RootedMutableNamespace};

    type Namespace = RootedMutableNamespace<8, 12, 32>;
    const ROOT_A: RootId = RootId::new(7);
    const ROOT_B: RootId = RootId::new(8);
    const T: MutableTimestamp = MutableTimestamp {
        seconds: 1,
        nanoseconds: 0,
    };

    fn bytes(path: CanonicalPath) -> Vec<u8> {
        let mut out = [0u8; MAX_PATH_BYTES + 1];
        let len = path.write_absolute(&mut out).unwrap();
        out[..len].to_vec()
    }

    fn nested_cwd(
        namespace: &mut Namespace,
    ) -> (DirectoryHandle, super::super::MutableDirectoryHandle) {
        let root = namespace.root_directory();
        namespace
            .create_directory(root, b"work", 0o755, 0, 0, T)
            .unwrap();
        let work = namespace.open_directory(root, b"work").unwrap();
        namespace
            .create_directory(work, b"sub", 0o755, 0, 0, T)
            .unwrap();
        (namespace.directory_handle(work, b"sub").unwrap(), work)
    }

    #[test]
    fn new_context_starts_at_bound_root_with_linux_default_umask() {
        let context = FsContext::new(ROOT_A);
        assert_eq!(context.root(), ROOT_A);
        assert_eq!(context.cwd_handle().root_id(), ROOT_A);
        assert!(context.cwd_handle().is_root());
        assert_eq!(context.umask(), 0o022);
    }

    #[test]
    fn live_relative_resolution_tracks_ancestor_rename_and_dotdot_stays_confined() {
        let mut namespace = Namespace::new(ROOT_A);
        let root = namespace.root_directory();
        let (cwd, _work) = nested_cwd(&mut namespace);
        let mut context = FsContext::new(ROOT_A);
        context.set_cwd(&mut namespace, cwd).unwrap();

        assert_eq!(
            bytes(context.resolve_live(&namespace, b"child").unwrap()),
            b"/work/sub/child"
        );
        namespace
            .rename(root, b"work", root, b"moved", false)
            .unwrap();
        assert_eq!(
            bytes(context.resolve_live(&namespace, b"../peer").unwrap()),
            b"/moved/peer"
        );
        assert_eq!(
            bytes(context.resolve_live(&namespace, b"../../../etc").unwrap()),
            b"/etc"
        );
        context.release_cwd(&mut namespace).unwrap();
    }

    #[test]
    fn absolute_live_resolution_ignores_cwd_after_refresh() {
        let mut namespace = Namespace::new(ROOT_A);
        let (cwd, _) = nested_cwd(&mut namespace);
        let mut context = FsContext::new(ROOT_A);
        context.set_cwd(&mut namespace, cwd).unwrap();
        assert_eq!(
            bytes(context.resolve_live(&namespace, b"/etc/./hosts").unwrap()),
            b"/etc/hosts"
        );
        context.release_cwd(&mut namespace).unwrap();
    }

    #[test]
    fn absolute_live_resolution_ignores_unreachable_retained_cwd() {
        let mut namespace = Namespace::new(ROOT_A);
        let root = namespace.root_directory();
        namespace
            .create_directory(root, b"gone", 0o755, 0, 0, T)
            .unwrap();
        let cwd = namespace.directory_handle(root, b"gone").unwrap();
        let held = namespace.lookup(root, b"gone").unwrap();
        namespace.retain_open(held).unwrap();

        let mut context = FsContext::new(ROOT_A);
        context.set_cwd(&mut namespace, cwd).unwrap();
        namespace.unlink(root, b"gone", true).unwrap();

        let mut getcwd = [0u8; 16];
        assert_eq!(
            context.write_getcwd_live(&namespace, &mut getcwd),
            Err(RootedMutableError::Mutable(MutableError::BadNode))
        );
        assert_eq!(
            bytes(context.resolve_live(&namespace, b"/etc/hosts").unwrap()),
            b"/etc/hosts"
        );

        // Closing the directory-FD-style hold used to select cwd must not invalidate cwd ownership.
        namespace.release_open(held).unwrap();
        assert_eq!(context.cwd_handle(), cwd);
        context.release_cwd(&mut namespace).unwrap();
    }

    #[test]
    fn foreign_root_directory_identity_cannot_commit_cwd_and_state_is_unchanged() {
        let mut foreign_namespace = Namespace::new(ROOT_B);
        let (foreign, _) = nested_cwd(&mut foreign_namespace);
        let mut context = FsContext::new(ROOT_A);
        assert_eq!(
            context.set_cwd(&mut foreign_namespace, foreign),
            Err(RootedMutableError::Path(Error::HandleMismatch))
        );
        assert_eq!(context.root(), ROOT_A);
        assert!(context.cwd_handle().is_root());
    }

    #[test]
    fn live_getcwd_tracks_ancestor_rename_and_includes_nul() {
        let mut namespace = Namespace::new(ROOT_A);
        let root = namespace.root_directory();
        let (cwd, _) = nested_cwd(&mut namespace);
        let mut context = FsContext::new(ROOT_A);
        context.set_cwd(&mut namespace, cwd).unwrap();

        let mut before = [0xaa; 10];
        assert_eq!(context.write_getcwd_live(&namespace, &mut before), Ok(10));
        assert_eq!(&before, b"/work/sub\0");

        namespace
            .rename(root, b"work", root, b"moved", false)
            .unwrap();
        let mut after = [0xaa; 11];
        assert_eq!(context.write_getcwd_live(&namespace, &mut after), Ok(11));
        assert_eq!(&after, b"/moved/sub\0");
        context.release_cwd(&mut namespace).unwrap();
    }

    #[test]
    fn cwd_write_is_bounded_and_has_no_hidden_nul() {
        let mut context = FsContext::new(ROOT_A);
        let mut namespace = Namespace::new(ROOT_A);
        let root = namespace.root_directory();
        namespace
            .create_directory(root, b"abc", 0o755, 0, 0, T)
            .unwrap();
        let cwd = namespace.directory_handle(root, b"abc").unwrap();
        context.set_cwd(&mut namespace, cwd).unwrap();
        let canonical = context.cwd_handle().canonical_path_in(&namespace).unwrap();
        let mut exact = [0u8; 4];
        assert_eq!(canonical.write_absolute(&mut exact), Some(4));
        assert_eq!(&exact, b"/abc");
        let mut short = [0u8; 3];
        assert_eq!(canonical.write_absolute(&mut short), None);
        context.release_cwd(&mut namespace).unwrap();
    }

    #[test]
    fn getcwd_writes_nul_and_returns_nul_inclusive_length() {
        let mut root_buffer = [0xaa; 2];
        assert_eq!(
            write_getcwd_path(CanonicalPath::root(), &mut root_buffer),
            Ok(2)
        );
        assert_eq!(&root_buffer, b"/\0");

        let mut context = FsContext::new(ROOT_A);
        let mut namespace = Namespace::new(ROOT_A);
        let namespace_root = namespace.root_directory();
        namespace
            .create_directory(namespace_root, b"abc", 0o755, 0, 0, T)
            .unwrap();
        let cwd = namespace.directory_handle(namespace_root, b"abc").unwrap();
        context.set_cwd(&mut namespace, cwd).unwrap();
        let canonical = context.cwd_handle().canonical_path_in(&namespace).unwrap();
        let mut exact = [0xaa; 5];
        assert_eq!(write_getcwd_path(canonical, &mut exact), Ok(5));
        assert_eq!(&exact, b"/abc\0");
        let mut short = [0xaa; 4];
        assert_eq!(
            write_getcwd_path(canonical, &mut short),
            Err(Error::OffsetOverflow)
        );
        context.release_cwd(&mut namespace).unwrap();
    }

    #[test]
    fn getcwd_distinguishes_path_max_from_small_user_buffer() {
        let success_path = vec![b'a'; MAX_PATH_BYTES - 1];
        let success = CanonicalPath::resolve_from(CanonicalPath::root(), &success_path).unwrap();
        assert_eq!(getcwd_required_len(success), Ok(LINUX_PATH_MAX));

        let too_long_path = vec![b'a'; MAX_PATH_BYTES];
        let too_long = CanonicalPath::resolve_from(CanonicalPath::root(), &too_long_path).unwrap();
        assert_eq!(getcwd_required_len(too_long), Err(Error::PathTooLong));
    }

    #[test]
    fn umask_is_permission_bounded_and_preserves_special_create_bits() {
        let mut context = FsContext::new(ROOT_A);
        assert_eq!(context.replace_umask(0o7027), 0o022);
        assert_eq!(context.umask(), 0o027);
        assert_eq!(context.apply_creation_mode(0o10666), 0o10640);
        assert_eq!(context.replace_umask(0), 0o027);
        assert_eq!(context.apply_creation_mode(0o10666), 0o10666);
    }

    #[test]
    fn invalid_relative_inputs_reuse_existing_path_errors() {
        let namespace = Namespace::new(ROOT_A);
        let context = &mut FsContext::new(ROOT_A);
        assert_eq!(
            context.resolve_live(&namespace, b""),
            Err(RootedMutableError::Path(Error::EmptyPath))
        );
        assert_eq!(
            context.resolve_live(&namespace, b"a\0b"),
            Err(RootedMutableError::Path(Error::EmbeddedNul))
        );
        let too_long = [b'a'; MAX_PATH_BYTES + 1];
        assert_eq!(
            context.resolve_live(&namespace, &too_long),
            Err(RootedMutableError::Path(Error::PathTooLong))
        );
    }
}
