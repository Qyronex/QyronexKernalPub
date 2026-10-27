// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::{classify_fs, classify_path_fd};
use kernal_linux_abi::{
    Errno, FsCall, PathFdCall, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_fd::OpenObjectKind;
use kernal_linux_pipe::{End as PipeEnd, PipeId};
use kernal_linux_vfs::{
    AT_FDCWD, Error as VfsError, MutableTimestamp, NodeKind, OverlayDirectoryHandle, OverlayError,
    OverlayNodeHandle,
};

use super::Error;

const OPEN_HOW_V0_BYTES: usize = 24;
const OPEN_HOW_MAX_BYTES: usize = 4096;
const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0x40;
const O_EXCL: u64 = 0x80;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
const O_NONBLOCK: u64 = 0x800;
const O_DIRECTORY: u64 = 0x4000;
const O_NOFOLLOW: u64 = 0x8000;
const O_CLOEXEC: u64 = 0x80000;
const OFD_STATUS_FLAGS: u64 = O_ACCMODE | O_APPEND | O_NONBLOCK;
const EXTRA_CHUNK_BYTES: usize = 16;

pub(super) fn handle(request: SyscallRequest, frame: &mut ExceptionFrame) -> Result<bool, ()> {
    // read(2), including the Step-30 blocking-pipe transition, is intentionally not intercepted
    // here. The canonical Step-29 path/FD owner below this adapter owns the full read lifecycle and
    // propagates Restarted versus SignalFrameCommitted as a typed HandleOutcome to Step15.

    // Ordinary Step-29 close remains the fallback for every non-pipe descriptor. For a pipe, this
    // adapter preserves OFD reference semantics and publishes EOF only if close_with_release proves
    // that the final writer OFD lease was actually released.
    if let Some(PathFdCall::Close { fd }) = classify_path_fd(request) {
        let process = super::super::current_process().map_err(|_| ())?;
        match close_pipe_owned(process, fd) {
            Ok(Some(value)) => return finish(Ok(value), frame),
            Ok(None) => {}
            Err(error) => return finish(Err(error), frame),
        }
    }

    if let Some(PathFdCall::OpenAt {
        dirfd,
        user_path,
        flags,
        mode,
    }) = classify_path_fd(request)
    {
        let flags = u64::from(linux_unsigned_int(flags));
        match openat_owned(dirfd, user_path, flags, mode) {
            Ok(Some(value)) => return finish(Ok(value), frame),
            Ok(None) => return Ok(false),
            Err(error) => return finish(Err(error), frame),
        }
    }

    let Some(call) = classify_fs(request) else {
        return Ok(false);
    };
    match call {
        FsCall::MkdirAt {
            dirfd,
            user_path,
            mode,
        } => finish(mkdirat(dirfd, user_path, mode), frame),
        FsCall::Chdir { user_path } => finish(chdir(user_path), frame),
        FsCall::OpenAt2 {
            dirfd,
            user_path,
            user_open_how,
            size,
        } => finish(openat2(dirfd, user_path, user_open_how, size), frame),
        _ => Ok(false),
    }
}

fn close_pipe_owned(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    let outcome = super::super::super::step29_runtime::with_process(
        process,
        |runtime| -> Result<Option<Option<PipeId>>, Error> {
            let (fds, pipes) = runtime.fd_pipe_parts();
            match fds.object_kind(fd) {
                Ok(OpenObjectKind::Pipe) => {}
                Ok(_) | Err(_) => return Ok(None),
            }

            let mut final_writer = None;
            let closed: Result<(), Error> = fds
                .close_with_release(fd, |released| {
                    let endpoint = released.pipe_endpoint();
                    pipes.close(endpoint).map_err(|_| Error::Invariant)?;
                    if endpoint.end() == PipeEnd::Write {
                        final_writer = Some(endpoint.pipe());
                    }
                    Ok(())
                })
                .map_err(super::super::map_fd_error)?;
            closed?;
            Ok(Some(final_writer))
        },
    )
    .map_err(|_| Error::Invariant)??;

    let Some(final_writer) = outcome else {
        return Ok(None);
    };
    if let Some(pipe) = final_writer {
        super::super::super::futex::pipe_blocking::notify_after_writer_close(pipe)
            .map_err(|_| Error::Invariant)?;
    }
    Ok(Some(0))
}

fn finish(result: Result<u64, Error>, frame: &mut ExceptionFrame) -> Result<bool, ()> {
    match result {
        Ok(value) => {
            frame.x[0] = SyscallReturn::success(value as i64)
                .ok_or(())?
                .as_u64_bits();
            Ok(true)
        }
        Err(Error::Linux(errno)) => {
            frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
            Ok(true)
        }
        Err(Error::Invariant) => Err(()),
    }
}

fn base_for_path(
    runtime: &mut super::super::super::step29_runtime::Step29PathRuntime<'_>,
    raw_dirfd: u64,
    path: &[u8],
) -> Result<OverlayDirectoryHandle, Error> {
    if path.first().copied() == Some(b'/') {
        return runtime
            .overlay()
            .open_directory_at(b"/")
            .map_err(super::map_overlay_error);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    if dirfd == AT_FDCWD {
        let cwd = runtime.fs_context().cwd_handle();
        return runtime
            .overlay()
            .revalidate_directory_handle(cwd)
            .map_err(super::map_overlay_error);
    }
    let Some(directory) = runtime
        .overlay_directory_for_fd(dirfd)
        .map_err(|_| Error::Invariant)?
    else {
        runtime
            .fds()
            .token(dirfd)
            .map_err(super::super::map_fd_error)?;
        return Err(Error::Linux(Errno::ENOTDIR));
    };
    Ok(directory)
}

fn mkdirat(raw_dirfd: u64, user_path: u64, raw_mode: u64) -> Result<u64, Error> {
    let path = super::super::copy_user_path(user_path)?;
    let process = super::super::current_process()?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        let mode = runtime
            .fs_context()
            .apply_creation_mode(linux_unsigned_int(raw_mode));
        runtime
            .overlay()
            .mkdir_from(base, path.as_bytes(), mode, 0, 0, MutableTimestamp::ZERO)
            .map_err(super::map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn chdir(user_path: u64) -> Result<u64, Error> {
    let path = super::super::copy_user_path(user_path)?;
    let process = super::super::current_process()?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, AT_FDCWD as u64, path.as_bytes())?;
        let directory = runtime
            .overlay()
            .open_directory_from(base, path.as_bytes())
            .map_err(super::map_overlay_error)?;
        let (overlay, context) = runtime.overlay_context_parts();
        overlay
            .set_context_cwd(context, directory)
            .map_err(super::map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

/// Identity-relative open owner for every Step-29 flag combination the Overlay advertises. A plain
/// `O_RDONLY` directory open is deliberately retained by VFS even for an untouched lower directory;
/// it must remain valid when a later copy-up/rename changes the directory's visible ancestry.
fn openat_owned(
    raw_dirfd: u64,
    user_path: u64,
    flags: u64,
    raw_mode: u64,
) -> Result<Option<u64>, Error> {
    let access = flags & O_ACCMODE;
    if access == O_ACCMODE {
        return Err(Error::Linux(Errno::EINVAL));
    }
    if flags & !super::SUPPORTED_OVERLAY_OPEN_FLAGS != 0 {
        return Ok(None);
    }
    if flags & O_DIRECTORY != 0 && flags & (O_CREAT | O_TRUNC) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }

    let path = super::super::copy_user_path(user_path)?;
    let process = super::super::current_process()?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        let nofollow = flags & O_NOFOLLOW != 0;

        let existing = if nofollow {
            resolve_existing(runtime, base, path.as_bytes(), true)?
        } else {
            resolve_existing(runtime, base, path.as_bytes(), false)?
        };

        if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) && existing.is_some() {
            return Err(Error::Linux(Errno::EEXIST));
        }
        if nofollow
            && existing
                .map(|logical| {
                    runtime
                        .overlay()
                        .metadata(logical)
                        .map(|metadata| metadata.kind() == NodeKind::Symlink)
                })
                .transpose()
                .map_err(super::map_overlay_error)?
                .unwrap_or(false)
        {
            return Err(Error::Linux(Errno::ELOOP));
        }

        let logical = if let Some(logical) = existing {
            logical
        } else if flags & O_CREAT != 0 {
            let mode = runtime
                .fs_context()
                .apply_creation_mode(linux_unsigned_int(raw_mode));
            runtime
                .overlay()
                .create_regular_from(base, path.as_bytes(), mode, 0, 0, MutableTimestamp::ZERO)
                .map_err(super::map_overlay_error)?;
            runtime
                .overlay()
                .resolve_following_from(base, path.as_bytes())
                .map_err(super::map_overlay_error)?
        } else {
            return Err(Error::Linux(Errno::ENOENT));
        };

        let kind = runtime
            .overlay()
            .metadata(logical)
            .map_err(super::map_overlay_error)?
            .kind();
        let close_on_exec = flags & O_CLOEXEC != 0;
        let status_flags = flags & OFD_STATUS_FLAGS;

        if kind == NodeKind::Directory {
            if access != O_RDONLY || flags & (O_CREAT | O_TRUNC) != 0 {
                return Err(Error::Linux(Errno::EISDIR));
            }
            let directory = runtime
                .overlay()
                .open_and_retain_directory_from(base, path.as_bytes())
                .map_err(super::map_overlay_error)?;
            let token = match runtime.fds().open_retained_directory_linux_with_flags(
                directory,
                close_on_exec,
                status_flags,
            ) {
                Ok(token) => token,
                Err(error) => {
                    runtime
                        .overlay()
                        .release_directory(directory)
                        .map_err(super::map_overlay_error)?;
                    return Err(super::super::map_fd_error(error));
                }
            };
            match logical {
                OverlayNodeHandle::Root { .. } => super::super::record_directory_open(
                    kernal_linux_vfs::EntryId::from_index(0),
                    kind,
                    token,
                ),
                OverlayNodeHandle::Immutable { entry_id, .. } => {
                    super::super::record_directory_open(entry_id, kind, token)
                }
                OverlayNodeHandle::Mutable(_) => {}
            }
            return Ok(Some(
                u64::try_from(token.fd()).map_err(|_| Error::Invariant)?,
            ));
        }
        if flags & O_DIRECTORY != 0 {
            return Err(Error::Linux(Errno::ENOTDIR));
        }
        match kind {
            NodeKind::Regular => {}
            NodeKind::Symlink => return Err(Error::Linux(Errno::ELOOP)),
            NodeKind::Other(_) => return Err(Error::Linux(Errno::EACCES)),
            NodeKind::Directory => unreachable!(),
        }

        let token = if access == O_RDONLY {
            runtime
                .overlay()
                .retain_open(logical)
                .map_err(super::map_overlay_error)?;
            match runtime.fds().open_retained_readonly_linux_with_flags(
                logical,
                close_on_exec,
                status_flags,
            ) {
                Ok(token) => token,
                Err(error) => {
                    runtime
                        .overlay()
                        .release_open(logical)
                        .map_err(super::map_overlay_error)?;
                    return Err(super::super::map_fd_error(error));
                }
            }
        } else if matches!(access, O_WRONLY | O_RDWR) {
            let retained = runtime
                .overlay()
                .prepare_and_retain_writable_regular_from(base, path.as_bytes())
                .map_err(super::map_overlay_error)?;
            if flags & O_TRUNC != 0 {
                if let Err(error) =
                    runtime
                        .overlay()
                        .truncate_retained_regular(retained, 0, MutableTimestamp::ZERO)
                {
                    runtime
                        .overlay()
                        .release_retained_regular(retained)
                        .map_err(super::map_overlay_error)?;
                    return Err(super::map_overlay_error(error));
                }
            }
            match runtime.fds().open_writable_linux_with_flags(
                retained,
                close_on_exec,
                status_flags,
            ) {
                Ok(token) => token,
                Err(error) => {
                    runtime
                        .overlay()
                        .release_retained_regular(retained)
                        .map_err(super::map_overlay_error)?;
                    return Err(super::super::map_fd_error(error));
                }
            }
        } else {
            return Err(Error::Linux(Errno::EINVAL));
        };
        if access == O_RDONLY {
            if let OverlayNodeHandle::Immutable { entry_id, .. } = logical {
                super::super::record_proof_open(path.as_bytes(), entry_id, token);
            }
        }
        Ok(Some(
            u64::try_from(token.fd()).map_err(|_| Error::Invariant)?,
        ))
    })
    .map_err(|_| Error::Invariant)?
}

fn resolve_existing(
    runtime: &mut super::super::super::step29_runtime::Step29PathRuntime<'_>,
    base: OverlayDirectoryHandle,
    path: &[u8],
    nofollow: bool,
) -> Result<Option<OverlayNodeHandle>, Error> {
    let resolved = if nofollow {
        runtime.overlay().resolve_nofollow_from(base, path)
    } else {
        runtime.overlay().resolve_following_from(base, path)
    };
    match resolved {
        Ok(logical) => Ok(Some(logical)),
        Err(OverlayError::NotFound | OverlayError::Path(VfsError::NotFound)) => Ok(None),
        Err(error) => Err(super::map_overlay_error(error)),
    }
}

fn openat2(raw_dirfd: u64, user_path: u64, user_how: u64, raw_how_size: u64) -> Result<u64, Error> {
    let how_size = usize::try_from(raw_how_size).unwrap_or(usize::MAX);
    if how_size < OPEN_HOW_V0_BYTES {
        return Err(Error::Linux(Errno::EINVAL));
    }
    if how_size > OPEN_HOW_MAX_BYTES {
        return Err(Error::Linux(Errno::E2BIG));
    }

    let mut how = [0u8; OPEN_HOW_V0_BYTES];
    kernal_usercopy_aarch64::copy_from_user(&mut how, user_how)
        .map_err(super::super::map_usercopy_error)?;
    validate_zero_extension(user_how, how_size)?;

    let flags = u64::from_le_bytes(how[0..8].try_into().map_err(|_| Error::Invariant)?);
    let mode = u64::from_le_bytes(how[8..16].try_into().map_err(|_| Error::Invariant)?);
    let resolve = u64::from_le_bytes(how[16..24].try_into().map_err(|_| Error::Invariant)?);

    if resolve != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    if mode != 0 && flags & O_CREAT == 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }

    openat_owned(raw_dirfd, user_path, flags, mode)?.ok_or_else(|| Error::Linux(Errno::EINVAL))
}

fn validate_zero_extension(user_how: u64, how_size: usize) -> Result<(), Error> {
    let mut offset = OPEN_HOW_V0_BYTES;
    let mut scratch = [0u8; EXTRA_CHUNK_BYTES];
    while offset < how_size {
        let count = core::cmp::min(EXTRA_CHUNK_BYTES, how_size - offset);
        let address = user_how
            .checked_add(u64::try_from(offset).map_err(|_| Error::Invariant)?)
            .ok_or_else(|| Error::Linux(Errno::EFAULT))?;
        kernal_usercopy_aarch64::copy_from_user(&mut scratch[..count], address)
            .map_err(super::super::map_usercopy_error)?;
        if scratch[..count].iter().any(|byte| *byte != 0) {
            return Err(Error::Linux(Errno::E2BIG));
        }
        offset = offset.checked_add(count).ok_or(Error::Invariant)?;
    }
    Ok(())
}
