// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_capability::ObjectId;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_abi::Errno;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_exec::ExecLookupPlan;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_fd::Error as ExecFdError;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_vfs::{
    AT_FDCWD, Error as ExecVfsError, InitramfsRoot, NodeKind, OverlayError, OverlayNodeHandle,
    ReadOnlyFile, RootId,
};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_protected_boot_aarch64::ProtectedInitrd;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExecSourceError {
    Linux(Errno),
    Invariant,
}

/// Exact immutable executable source selected while the old Process-local Step29 owner is active.
///
/// No pathname survives selection. `ReadOnlyFile` carries the generation-qualified CPIO RootId,
/// EntryId, mode and size; `root_id` is the independently retained mounted-root generation from the
/// exact process-local runtime. `with_image_bytes` re-enters the protected initrd and requires both
/// identities to match before the canonical VFS exposes bytes.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExecImageSource {
    initrd: ProtectedInitrd,
    root_id: RootId,
    file: ReadOnlyFile,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl ExecImageSource {
    pub(super) fn with_image_bytes<R>(
        self,
        operation: impl for<'a> FnOnce(&'a [u8]) -> R,
    ) -> Result<R, ExecSourceError> {
        if self.file.root_id() != self.root_id {
            return Err(ExecSourceError::Invariant);
        }
        self.initrd.with_bytes(|archive_bytes| {
            let archive = kernal_cpio::Archive::parse(archive_bytes)
                .map_err(|_| ExecSourceError::Invariant)?;
            let root = InitramfsRoot::new(archive, self.root_id);
            let image = root
                .read_at(self.file, 0, usize::MAX)
                .map_err(map_vfs_error)?;
            if image.len()
                != usize::try_from(self.file.size()).map_err(|_| ExecSourceError::Invariant)?
            {
                return Err(ExecSourceError::Invariant);
            }
            Ok(operation(image))
        })
    }
}

/// Resolves and authorizes one Step-30 exec source through the exact current Process-local Step29
/// FD/Fs/Overlay owner and returns only generation-qualified immutable initramfs authority.
///
/// The bounded Step30 acceptance slice deliberately allows direct protected-initrd loading only for
/// a Lower immutable file whose size is greater than the mutable Upper's complete per-file capacity.
/// `copy_up_regular_canonical` rejects such a file before attaching an Upper binding, so this exact
/// `ReadOnlyFile` cannot be shadowed by mutable bytes. Smaller immutable files and every Mutable
/// executable fail closed until a later current-Overlay streaming image owner exists.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn select_exec_image_source(
    process: ObjectId,
    plan: ExecLookupPlan,
    path: &[u8],
) -> Result<ExecImageSource, ExecSourceError> {
    super::step29_runtime::with_process(process, |runtime| {
        // Copy only immutable provenance values out of the broad legacy parts tuple, then end those
        // descriptor borrows before entering the Overlay/FsContext selection below.
        let (initrd, root_id) = {
            let (initrd, root_id, _fds) = runtime.parts();
            (initrd, root_id)
        };

        let handle = if plan.path_is_empty() {
            if plan.dirfd() == AT_FDCWD || !plan.allows_empty_path() {
                return Err(ExecSourceError::Linux(Errno::EBADF));
            }
            match runtime.fds().retained_readonly(plan.dirfd()) {
                Ok(handle) => handle,
                Err(ExecFdError::BadFd) => return Err(ExecSourceError::Linux(Errno::EBADF)),
                Err(ExecFdError::NotFile | ExecFdError::NotDirectory) => {
                    return Err(ExecSourceError::Linux(Errno::EACCES));
                }
                Err(_) => return Err(ExecSourceError::Invariant),
            }
        } else {
            let base = if plan.dirfd() == AT_FDCWD {
                let cwd = runtime.fs_context().cwd_handle();
                let overlay = runtime.overlay();
                overlay
                    .revalidate_directory_handle(cwd)
                    .map_err(map_overlay_error)?
            } else {
                match runtime.overlay_directory_for_fd(plan.dirfd()) {
                    Ok(Some(directory)) => directory,
                    Ok(None) => match runtime.fds().token(plan.dirfd()) {
                        Ok(_) => return Err(ExecSourceError::Linux(Errno::ENOTDIR)),
                        Err(ExecFdError::BadFd) => {
                            return Err(ExecSourceError::Linux(Errno::EBADF));
                        }
                        Err(_) => return Err(ExecSourceError::Invariant),
                    },
                    Err(_) => return Err(ExecSourceError::Invariant),
                }
            };

            if plan.follows_final_symlink() {
                runtime
                    .overlay()
                    .resolve_following_from(base, path)
                    .map_err(map_overlay_error)?
            } else {
                runtime
                    .overlay()
                    .resolve_nofollow_from(base, path)
                    .map_err(map_overlay_error)?
            }
        };

        // Exact handle shape supplies the immutable source token. Mode authorization is checked from
        // the same ReadOnlyFile metadata later revalidated by InitramfsRoot::read_at.
        let file = match handle {
            OverlayNodeHandle::Immutable {
                root,
                kind: NodeKind::Regular,
                file: Some(file),
                ..
            } if root == root_id => file,
            OverlayNodeHandle::Root { .. }
            | OverlayNodeHandle::Immutable {
                kind: NodeKind::Directory,
                ..
            } => return Err(ExecSourceError::Linux(Errno::EACCES)),
            OverlayNodeHandle::Immutable { .. } | OverlayNodeHandle::Mutable(_) => {
                return Err(ExecSourceError::Linux(Errno::EACCES));
            }
        };
        if file.mode() & 0o111 == 0 {
            return Err(ExecSourceError::Linux(Errno::EACCES));
        }
        let upper_capacity = u64::try_from(super::step29_runtime::STEP29_RUNTIME_FS_FILE_BYTES)
            .map_err(|_| ExecSourceError::Invariant)?;
        if file.size() <= upper_capacity {
            return Err(ExecSourceError::Linux(Errno::EACCES));
        }

        // A zero-length read forces the Overlay owner to revalidate root/handle/lower-fallback
        // authority without copying image bytes or changing any offset. The >Upper-capacity proof
        // above guarantees no copy-up backing can exist for this Lower file.
        let mut empty = [];
        runtime
            .overlay()
            .read_regular(handle, 0, &mut empty)
            .map_err(map_overlay_error)?;

        Ok(ExecImageSource {
            initrd,
            root_id,
            file,
        })
    })
    .map_err(|_| ExecSourceError::Invariant)?
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_overlay_error(error: OverlayError) -> ExecSourceError {
    match error {
        OverlayError::NotFound => ExecSourceError::Linux(Errno::ENOENT),
        OverlayError::NotDirectory => ExecSourceError::Linux(Errno::ENOTDIR),
        OverlayError::IsDirectory | OverlayError::NotRegular => {
            ExecSourceError::Linux(Errno::EACCES)
        }
        OverlayError::Path(error) => map_vfs_error(error),
        OverlayError::Mutable(_)
        | OverlayError::AlreadyExists
        | OverlayError::TombstoneTableFull
        | OverlayError::BindingTableFull
        | OverlayError::FileTooLarge => ExecSourceError::Invariant,
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_vfs_error(error: ExecVfsError) -> ExecSourceError {
    match error {
        ExecVfsError::NotFound => ExecSourceError::Linux(Errno::ENOENT),
        ExecVfsError::NotDirectory | ExecVfsError::UnsupportedDirFd => {
            ExecSourceError::Linux(Errno::ENOTDIR)
        }
        ExecVfsError::IsDirectory | ExecVfsError::UnsupportedNode => {
            ExecSourceError::Linux(Errno::EACCES)
        }
        ExecVfsError::PathTooLong => ExecSourceError::Linux(Errno::ENAMETOOLONG),
        ExecVfsError::SymlinkUnsupported => ExecSourceError::Linux(Errno::ELOOP),
        ExecVfsError::EmptyPath => ExecSourceError::Linux(Errno::ENOENT),
        ExecVfsError::EmbeddedNul
        | ExecVfsError::Archive(_)
        | ExecVfsError::HandleMismatch
        | ExecVfsError::OffsetOverflow => ExecSourceError::Invariant,
    }
}
