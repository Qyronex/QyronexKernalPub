// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::{classify_fd_io, classify_fs, classify_path_fd};
use kernal_linux_abi::{
    Errno, FdIoCall, FsCall, PathFdCall, SyscallRequest, SyscallReturn, linux_signed_int,
    linux_signed_off_t, linux_unsigned_int,
};
use kernal_linux_fd::{Error as FdError, ReleasedObject, SeekWhence};
use kernal_linux_vfs::{
    AT_FDCWD, CanonicalPath, Error as VfsError, LINUX_PATH_MAX, MutableError, MutableTimestamp,
    NodeKind, OverlayError, OverlayNodeHandle, RootedMutableError,
};
use kernal_usercopy::MAX_USERCOPY_BYTES;

use super::Error;

#[path = "step29_final_fs/metadata_ops.rs"]
mod metadata_ops;
#[path = "step29_final_fs/namespace_ops.rs"]
mod namespace_ops;
#[path = "step29_final_fs/openat2_ops.rs"]
mod openat2_ops;
#[path = "step29_final_fs/overlay_stat.rs"]
mod overlay_stat;

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
const O_LARGEFILE: u64 = 0x20000;
const O_CLOEXEC: u64 = 0x80000;
const SUPPORTED_OVERLAY_OPEN_FLAGS: u64 = O_ACCMODE
    | O_CREAT
    | O_EXCL
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_DIRECTORY
    | O_NOFOLLOW
    | O_LARGEFILE
    | O_CLOEXEC;
const OFD_STATUS_FLAGS: u64 = O_ACCMODE | O_APPEND | O_NONBLOCK;
const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;
const USER_PAGE_BYTES: u64 = 4096;
const WRITE_CHUNK_BYTES: usize = 256;

/// Handles final Step-29 filesystem calls owned by the persistent Overlay runtime. Operations that
/// still belong to the already-accepted immutable/pipe/stdio path return false without mutation.
pub(super) fn handle(request: SyscallRequest, frame: &mut ExceptionFrame) -> Result<bool, ()> {
    if openat2_ops::handle(request, frame)? {
        return Ok(true);
    }
    if namespace_ops::handle(request, frame)? {
        return Ok(true);
    }
    if metadata_ops::handle(request, frame)? {
        return Ok(true);
    }

    if request.number == 64 {
        let process = super::current_process().map_err(|_| ())?;
        match write_retained(process, request.args[0], request.args[1], request.args[2]) {
            Ok(Some(value)) => return finish(Ok(value), frame),
            Ok(None) => {}
            Err(error) => return finish(Err(error), frame),
        }
    }

    if let Some(call) = classify_fs(request) {
        let process = super::current_process().map_err(|_| ())?;
        let result = match call {
            FsCall::Getcwd { user_buffer, size } => getcwd(process, user_buffer, size),
            FsCall::Umask { mask } => umask(process, mask),
            FsCall::MkdirAt {
                dirfd,
                user_path,
                mode,
            } => mkdirat(process, dirfd, user_path, mode),
            FsCall::Chdir { user_path } => chdir(process, user_path),
            FsCall::Fchdir { fd } => fchdir(process, fd),
            FsCall::Pwrite64 {
                fd,
                user_buffer,
                count,
                offset,
            } => pwrite64_retained(process, fd, user_buffer, count, offset),
            _ => return Ok(false),
        };
        return finish(result, frame);
    }

    if let Some(call) = classify_fd_io(request) {
        let process = super::current_process().map_err(|_| ())?;
        match call {
            FdIoCall::Lseek { fd, offset, whence } => {
                match lseek_retained(process, fd, offset, whence) {
                    Ok(Some(value)) => return finish(Ok(value), frame),
                    Ok(None) => {}
                    Err(error) => return finish(Err(error), frame),
                }
            }
            FdIoCall::Pread64 {
                fd,
                user_buffer,
                count,
                offset,
            } => match pread64_retained(process, fd, user_buffer, count, offset) {
                Ok(Some(value)) => return finish(Ok(value), frame),
                Ok(None) => {}
                Err(error) => return finish(Err(error), frame),
            },
            _ => {}
        }
    }

    let Some(call) = classify_path_fd(request) else {
        return Ok(false);
    };
    let process = super::current_process().map_err(|_| ())?;
    match call {
        PathFdCall::OpenAt {
            dirfd,
            user_path,
            flags,
            mode,
        } => match openat(process, dirfd, user_path, flags, mode) {
            Ok(Some(value)) => finish(Ok(value), frame),
            Ok(None) => Ok(false),
            Err(error) => finish(Err(error), frame),
        },
        PathFdCall::Close { fd } => match close(process, fd) {
            Ok(Some(value)) => finish(Ok(value), frame),
            Ok(None) => Ok(false),
            Err(error) => finish(Err(error), frame),
        },
        _ => Ok(false),
    }
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

fn getcwd(
    process: kernal_capability::ObjectId,
    user_buffer: u64,
    raw_size: u64,
) -> Result<u64, Error> {
    let size = usize::try_from(raw_size).unwrap_or(usize::MAX);
    super::super::step29_runtime::with_process(process, |runtime| {
        let cwd = runtime.fs_context().cwd_handle();
        let directory = runtime
            .overlay()
            .revalidate_directory_handle(cwd)
            .map_err(map_overlay_error)?;
        let canonical = runtime
            .overlay()
            .directory_canonical_path(directory)
            .map_err(map_overlay_error)?;
        let mut output = [0u8; LINUX_PATH_MAX];
        let path_len = canonical
            .write_absolute(&mut output[..LINUX_PATH_MAX - 1])
            .ok_or_else(|| Error::Linux(Errno::ENAMETOOLONG))?;
        let required = path_len.checked_add(1).ok_or(Error::Invariant)?;
        if size < required {
            return Err(Error::Linux(errno(34)?));
        }
        output[path_len] = 0;
        kernal_usercopy_aarch64::copy_to_user(user_buffer, &output[..required])
            .map_err(super::map_usercopy_error)?;
        total_u64(required)
    })
    .map_err(|_| Error::Invariant)?
}

fn umask(process: kernal_capability::ObjectId, raw_mask: u64) -> Result<u64, Error> {
    super::super::step29_runtime::with_process(process, |runtime| {
        Ok(u64::from(
            runtime
                .fs_context()
                .replace_umask(linux_unsigned_int(raw_mask)),
        ))
    })
    .map_err(|_| Error::Invariant)?
}

fn mkdirat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_mode: u64,
) -> Result<u64, Error> {
    let path = super::copy_user_path(user_path)?;
    super::super::step29_runtime::with_process(process, |runtime| {
        let canonical = canonical_at(runtime, raw_dirfd, path.as_bytes())?;
        let mode = runtime
            .fs_context()
            .apply_creation_mode(linux_unsigned_int(raw_mode));
        runtime
            .overlay()
            .mkdir_at(
                canonical_lookup_bytes(&canonical),
                mode,
                0,
                0,
                MutableTimestamp::ZERO,
            )
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn chdir(process: kernal_capability::ObjectId, user_path: u64) -> Result<u64, Error> {
    let path = super::copy_user_path(user_path)?;
    super::super::step29_runtime::with_process(process, |runtime| {
        let canonical = canonical_at(runtime, AT_FDCWD as u64, path.as_bytes())?;
        let directory = runtime
            .overlay()
            .open_directory_at(canonical_lookup_bytes(&canonical))
            .map_err(map_overlay_error)?;
        let (overlay, context) = runtime.overlay_context_parts();
        overlay
            .set_context_cwd(context, directory)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn fchdir(process: kernal_capability::ObjectId, raw_fd: u64) -> Result<u64, Error> {
    let fd = linux_signed_int(raw_fd);
    super::super::step29_runtime::with_process(process, |runtime| {
        let Some(directory) = runtime
            .overlay_directory_for_fd(fd)
            .map_err(|_| Error::Invariant)?
        else {
            runtime.fds().token(fd).map_err(super::map_fd_error)?;
            return Err(Error::Linux(Errno::ENOTDIR));
        };
        let (overlay, context) = runtime.overlay_context_parts();
        overlay
            .set_context_cwd(context, directory)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn openat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_flags: u64,
    raw_mode: u64,
) -> Result<Option<u64>, Error> {
    let flags = u64::from(linux_unsigned_int(raw_flags));
    let access = flags & O_ACCMODE;
    if access == O_ACCMODE {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let path = super::copy_user_path(user_path)?;
    super::super::step29_runtime::with_process(process, |runtime| {
        let force_overlay = overlay_base_required(runtime, raw_dirfd, path.as_bytes())?
            || flags & (O_CREAT | O_TRUNC) != 0
            || matches!(access, O_WRONLY | O_RDWR);
        if !force_overlay {
            let canonical = canonical_at_root_only(path.as_bytes())?;
            let Some(logical) = runtime
                .overlay()
                .lookup_at(canonical_lookup_bytes(&canonical))
                .map_err(map_overlay_error)?
            else {
                return Ok(None);
            };
            if !matches!(logical, OverlayNodeHandle::Mutable(_)) {
                return Ok(None);
            }
        }
        if flags & !SUPPORTED_OVERLAY_OPEN_FLAGS != 0 {
            return Err(Error::Linux(Errno::EINVAL));
        }
        if flags & O_DIRECTORY != 0 && flags & (O_CREAT | O_TRUNC) != 0 {
            return Err(Error::Linux(Errno::EINVAL));
        }

        let canonical = canonical_at(runtime, raw_dirfd, path.as_bytes())?;
        let lookup_path = canonical_lookup_bytes(&canonical);
        let close_on_exec = flags & O_CLOEXEC != 0;
        let status_flags = flags & OFD_STATUS_FLAGS;
        if flags & O_DIRECTORY != 0 {
            let directory = runtime
                .overlay()
                .open_and_retain_directory_at(lookup_path)
                .map_err(map_overlay_error)?;
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
                        .map_err(map_overlay_error)?;
                    return Err(super::map_fd_error(error));
                }
            };
            return Ok(Some(
                u64::try_from(token.fd()).map_err(|_| Error::Invariant)?,
            ));
        }

        let mut logical = runtime
            .overlay()
            .lookup_at(lookup_path)
            .map_err(map_overlay_error)?;
        if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
            let mode = runtime
                .fs_context()
                .apply_creation_mode(linux_unsigned_int(raw_mode));
            runtime
                .overlay()
                .create_regular_at(lookup_path, mode, 0, 0, MutableTimestamp::ZERO)
                .map_err(map_overlay_error)?;
            logical = runtime
                .overlay()
                .lookup_at(lookup_path)
                .map_err(map_overlay_error)?;
        } else if flags & O_CREAT != 0 && logical.is_none() {
            let mode = runtime
                .fs_context()
                .apply_creation_mode(linux_unsigned_int(raw_mode));
            runtime
                .overlay()
                .create_regular_at(lookup_path, mode, 0, 0, MutableTimestamp::ZERO)
                .map_err(map_overlay_error)?;
            logical = runtime
                .overlay()
                .lookup_at(lookup_path)
                .map_err(map_overlay_error)?;
        }
        let logical = logical.ok_or_else(|| Error::Linux(Errno::ENOENT))?;
        match runtime
            .overlay()
            .metadata(logical)
            .map_err(map_overlay_error)?
            .kind()
        {
            NodeKind::Directory => return Err(Error::Linux(Errno::EISDIR)),
            NodeKind::Symlink => return Err(Error::Linux(Errno::ELOOP)),
            NodeKind::Other(_) => return Err(Error::Linux(Errno::EACCES)),
            NodeKind::Regular => {}
        }

        let token = if access == O_RDONLY {
            runtime
                .overlay()
                .retain_open(logical)
                .map_err(map_overlay_error)?;
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
                        .map_err(map_overlay_error)?;
                    return Err(super::map_fd_error(error));
                }
            }
        } else {
            let retained = runtime
                .overlay()
                .prepare_and_retain_writable_regular_at(lookup_path)
                .map_err(map_overlay_error)?;
            if flags & O_TRUNC != 0 {
                if let Err(error) =
                    runtime
                        .overlay()
                        .truncate_retained_regular(retained, 0, MutableTimestamp::ZERO)
                {
                    runtime
                        .overlay()
                        .release_retained_regular(retained)
                        .map_err(map_overlay_error)?;
                    return Err(map_overlay_error(error));
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
                        .map_err(map_overlay_error)?;
                    return Err(super::map_fd_error(error));
                }
            }
        };
        Ok(Some(
            u64::try_from(token.fd()).map_err(|_| Error::Invariant)?,
        ))
    })
    .map_err(|_| Error::Invariant)?
}

fn close(process: kernal_capability::ObjectId, raw_fd: u64) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    super::super::step29_runtime::with_process(process, |runtime| {
        let retained_directory = runtime.fds().retained_directory(fd).ok();
        let legacy_directory =
            retained_directory.is_none() && runtime.fds().prepare_directory(fd).is_ok();
        let retained_readonly = runtime.fds().retained_readonly(fd).is_ok();
        let writable = runtime.fds().writable_regular(fd).is_ok();
        if retained_directory.is_none() && !legacy_directory && !retained_readonly && !writable {
            return Ok(None);
        }

        if let Some(directory) = retained_directory {
            let (fds, overlay) = runtime.fd_overlay_parts();
            let closed = fds
                .close_with_release(fd, |released| match released {
                    ReleasedObject::RetainedDirectory(released) if released == directory => overlay
                        .release_directory(released)
                        .map_err(map_overlay_error),
                    _ => Err(Error::Invariant),
                })
                .map_err(super::map_fd_error)?;
            closed?;
            return Ok(Some(0));
        }

        // Legacy immutable directory OFDs do not own an Overlay lifetime hold. They are retained only
        // as an additive compatibility path, so closing the descriptor requires no VFS release.
        if legacy_directory {
            runtime.fds().close(fd).map_err(super::map_fd_error)?;
            return Ok(Some(0));
        }

        let (fds, overlay) = runtime.fd_overlay_parts();
        let closed = fds
            .close_with_release(fd, |released| match released {
                ReleasedObject::RetainedReadOnly(logical) => {
                    overlay.release_open(logical).map_err(map_overlay_error)
                }
                ReleasedObject::WritableRegular(retained) => overlay
                    .release_retained_regular(retained)
                    .map_err(map_overlay_error),
                ReleasedObject::RetainedDirectory(_) | ReleasedObject::Pipe(_) => {
                    Err(Error::Invariant)
                }
            })
            .map_err(super::map_fd_error)?;
        closed?;
        Ok(Some(0))
    })
    .map_err(|_| Error::Invariant)?
}

fn write_retained(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    let requested = usize::try_from(count).unwrap_or(usize::MAX);
    super::super::step29_runtime::with_process(process, |runtime| {
        match runtime.fds().writable_regular(fd) {
            Ok(_) => {}
            Err(FdError::BadFd | FdError::NotFile) => return Ok(None),
            Err(error) => return Err(super::map_fd_error(error)),
        }
        if requested == 0 {
            runtime
                .fds()
                .prepare_write(fd, 0)
                .map_err(super::map_fd_error)?;
            return Ok(Some(0));
        }
        let mut scratch = [0u8; WRITE_CHUNK_BYTES];
        let mut total = 0usize;
        while total < requested {
            let user_address = checked_user_progress(user_buffer, total)?;
            let chunk_len = source_chunk_len(user_address, requested - total);
            let plan = runtime
                .fds()
                .prepare_write(fd, chunk_len)
                .map_err(super::map_fd_error)?;
            if let Err(error) =
                kernal_usercopy_aarch64::copy_from_user(&mut scratch[..chunk_len], user_address)
            {
                return partial_usercopy_result(total, super::map_usercopy_error(error)).map(Some);
            }
            let (_, _, retained, expected_offset, _, append) = plan;
            let mutation = if append {
                runtime
                    .overlay()
                    .append_retained_regular(
                        retained,
                        &scratch[..chunk_len],
                        MutableTimestamp::ZERO,
                    )
                    .map_err(map_overlay_error)
            } else {
                runtime
                    .overlay()
                    .write_retained_regular(
                        retained,
                        expected_offset,
                        &scratch[..chunk_len],
                        MutableTimestamp::ZERO,
                    )
                    .map(|written| (expected_offset, written))
                    .map_err(map_overlay_error)
            };
            let (actual_start, written) = match mutation {
                Ok(result) => result,
                Err(_) if total != 0 => return Ok(Some(total_u64(total)?)),
                Err(error) => return Err(error),
            };
            runtime
                .fds()
                .commit_write(plan, actual_start, written)
                .map_err(super::map_fd_error)?;
            total = total.checked_add(written).ok_or(Error::Invariant)?;
            if written < chunk_len {
                break;
            }
        }
        Ok(Some(total_u64(total)?))
    })
    .map_err(|_| Error::Invariant)?
}

fn pwrite64_retained(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
    raw_offset: u64,
) -> Result<u64, Error> {
    let offset = linux_signed_off_t(raw_offset);
    if offset < 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let fd = linux_signed_int(raw_fd);
    let requested = usize::try_from(count).unwrap_or(usize::MAX);
    super::super::step29_runtime::with_process(process, |runtime| {
        if requested == 0 {
            runtime
                .fds()
                .prepare_pwrite(fd, offset, 0)
                .map_err(super::map_fd_error)?;
            return Ok(0);
        }
        let mut scratch = [0u8; WRITE_CHUNK_BYTES];
        let mut total = 0usize;
        while total < requested {
            let user_address = checked_user_progress(user_buffer, total)?;
            let chunk_len = source_chunk_len(user_address, requested - total);
            let current_offset = offset
                .checked_add(i64::try_from(total).map_err(|_| Error::Linux(Errno::EOVERFLOW))?)
                .ok_or_else(|| Error::Linux(Errno::EOVERFLOW))?;
            let plan = runtime
                .fds()
                .prepare_pwrite(fd, current_offset, chunk_len)
                .map_err(super::map_fd_error)?;
            if let Err(error) =
                kernal_usercopy_aarch64::copy_from_user(&mut scratch[..chunk_len], user_address)
            {
                return partial_usercopy_result(total, super::map_usercopy_error(error));
            }
            runtime
                .fds()
                .validate_pwrite(plan)
                .map_err(super::map_fd_error)?;
            let (_, _, retained, explicit_offset, _, append) = plan;
            let mutation = if append {
                runtime
                    .overlay()
                    .append_retained_regular(
                        retained,
                        &scratch[..chunk_len],
                        MutableTimestamp::ZERO,
                    )
                    .map(|(_, written)| written)
                    .map_err(map_overlay_error)
            } else {
                runtime
                    .overlay()
                    .write_retained_regular(
                        retained,
                        explicit_offset,
                        &scratch[..chunk_len],
                        MutableTimestamp::ZERO,
                    )
                    .map_err(map_overlay_error)
            };
            let written = match mutation {
                Ok(written) => written,
                Err(_) if total != 0 => return total_u64(total),
                Err(error) => return Err(error),
            };
            total = total.checked_add(written).ok_or(Error::Invariant)?;
            if written < chunk_len {
                break;
            }
        }
        total_u64(total)
    })
    .map_err(|_| Error::Invariant)?
}

fn pread64_retained(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
    raw_offset: u64,
) -> Result<Option<u64>, Error> {
    let offset = linux_signed_off_t(raw_offset);
    if offset < 0 {
        return Ok(None);
    }
    let fd = linux_signed_int(raw_fd);
    let requested = core::cmp::min(
        usize::try_from(count).unwrap_or(usize::MAX),
        MAX_USERCOPY_BYTES,
    );
    super::super::step29_runtime::with_process(process, |runtime| {
        let writable = runtime.fds().writable_regular(fd).ok();
        let readonly = runtime.fds().retained_readonly(fd).ok();
        if writable.is_none() && readonly.is_none() {
            return Ok(None);
        }
        if writable.is_some()
            && runtime
                .fds()
                .status_flags(fd)
                .map_err(super::map_fd_error)?
                & O_ACCMODE
                != O_RDWR
        {
            return Err(Error::Linux(Errno::EBADF));
        }
        if requested == 0 {
            runtime.fds().token(fd).map_err(super::map_fd_error)?;
            return Ok(Some(0));
        }
        let mut scratch = [0u8; WRITE_CHUNK_BYTES];
        let mut total = 0usize;
        while total < requested {
            let chunk_len = core::cmp::min(WRITE_CHUNK_BYTES, requested - total);
            let explicit = u64::try_from(offset)
                .map_err(|_| Error::Linux(Errno::EINVAL))?
                .checked_add(u64::try_from(total).map_err(|_| Error::Invariant)?)
                .ok_or_else(|| Error::Linux(Errno::EOVERFLOW))?;
            let user_address = checked_user_progress(user_buffer, total)?;
            let read = if let Some(retained) = writable {
                let token = runtime.fds().token(fd).map_err(super::map_fd_error)?;
                let open_file = runtime
                    .fds()
                    .open_file_id(fd)
                    .map_err(super::map_fd_error)?;
                let read = runtime
                    .overlay()
                    .read_retained_regular(retained, explicit, &mut scratch[..chunk_len])
                    .map_err(map_overlay_error)?;
                let progress =
                    kernal_usercopy_aarch64::copy_to_user_progress(user_address, &scratch[..read])
                        .map_err(super::map_usercopy_error)?;
                if !runtime.fds().token_is_live(token)
                    || runtime.fds().open_file_id(fd) != Ok(open_file)
                    || runtime.fds().writable_regular(fd) != Ok(retained)
                {
                    return Err(Error::Invariant);
                }
                let copied = progress.copied();
                total = total.checked_add(copied).ok_or(Error::Invariant)?;
                if progress.faulted() {
                    return if total == 0 {
                        Err(Error::Linux(Errno::EFAULT))
                    } else {
                        Ok(Some(total_u64(total)?))
                    };
                }
                if copied < read {
                    return Ok(Some(total_u64(total)?));
                }
                read
            } else {
                let current = u64::try_from(offset)
                    .map_err(|_| Error::Linux(Errno::EINVAL))?
                    .checked_add(u64::try_from(total).map_err(|_| Error::Invariant)?)
                    .ok_or_else(|| Error::Linux(Errno::EOVERFLOW))?;
                let plan = runtime
                    .fds()
                    .prepare_retained_pread(
                        fd,
                        i64::try_from(current).map_err(|_| Error::Linux(Errno::EOVERFLOW))?,
                        chunk_len,
                    )
                    .map_err(super::map_fd_error)?;
                let read = runtime
                    .overlay()
                    .read_regular(plan.2, explicit, &mut scratch[..chunk_len])
                    .map_err(map_overlay_error)?;
                let progress =
                    kernal_usercopy_aarch64::copy_to_user_progress(user_address, &scratch[..read])
                        .map_err(super::map_usercopy_error)?;
                runtime
                    .fds()
                    .validate_retained_pread(plan)
                    .map_err(super::map_fd_error)?;
                let copied = progress.copied();
                total = total.checked_add(copied).ok_or(Error::Invariant)?;
                if progress.faulted() {
                    return if total == 0 {
                        Err(Error::Linux(Errno::EFAULT))
                    } else {
                        Ok(Some(total_u64(total)?))
                    };
                }
                if copied < read {
                    return Ok(Some(total_u64(total)?));
                }
                read
            };
            if read < chunk_len {
                break;
            }
        }
        Ok(Some(total_u64(total)?))
    })
    .map_err(|_| Error::Invariant)?
}

fn lseek_retained(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    raw_offset: u64,
    raw_whence: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    let offset = linux_signed_off_t(raw_offset);
    super::super::step29_runtime::with_process(process, |runtime| {
        let writable = runtime.fds().writable_regular(fd).ok();
        let readonly = runtime.fds().retained_readonly(fd).ok();
        if writable.is_none() && readonly.is_none() {
            return Ok(None);
        }
        runtime.fds().token(fd).map_err(super::map_fd_error)?;
        let whence = decode_whence(raw_whence)?;
        let file_end = if let Some(retained) = writable {
            runtime
                .overlay()
                .retained_regular_metadata(retained)
                .map_err(map_overlay_error)?
                .size()
        } else {
            runtime
                .overlay()
                .metadata(readonly.ok_or(Error::Invariant)?)
                .map_err(map_overlay_error)?
                .size()
        };
        let position = if writable.is_some() {
            runtime
                .fds()
                .seek_writable(fd, offset, whence, file_end)
                .map_err(super::map_fd_error)?
        } else {
            runtime
                .fds()
                .seek_retained_readonly(fd, offset, whence, file_end)
                .map_err(super::map_fd_error)?
        };
        Ok(Some(position))
    })
    .map_err(|_| Error::Invariant)?
}

fn source_chunk_len(user_address: u64, remaining: usize) -> usize {
    let in_page = user_address & (USER_PAGE_BYTES - 1);
    let page_remaining = usize::try_from(USER_PAGE_BYTES - in_page).unwrap_or(WRITE_CHUNK_BYTES);
    core::cmp::min(remaining, core::cmp::min(WRITE_CHUNK_BYTES, page_remaining))
}

fn checked_user_progress(base: u64, copied: usize) -> Result<u64, Error> {
    base.checked_add(u64::try_from(copied).map_err(|_| Error::Invariant)?)
        .ok_or_else(|| Error::Linux(Errno::EFAULT))
}

fn partial_usercopy_result(copied: usize, error: Error) -> Result<u64, Error> {
    match error {
        Error::Linux(Errno::EFAULT) if copied != 0 => total_u64(copied),
        other => Err(other),
    }
}

fn total_u64(total: usize) -> Result<u64, Error> {
    u64::try_from(total).map_err(|_| Error::Invariant)
}

fn decode_whence(raw: u64) -> Result<SeekWhence, Error> {
    match linux_unsigned_int(raw) {
        SEEK_SET => Ok(SeekWhence::Set),
        SEEK_CUR => Ok(SeekWhence::Current),
        SEEK_END => Ok(SeekWhence::End),
        _ => Err(Error::Linux(Errno::EINVAL)),
    }
}

fn overlay_base_required(
    runtime: &mut super::super::step29_runtime::Step29PathRuntime<'_>,
    raw_dirfd: u64,
    path: &[u8],
) -> Result<bool, Error> {
    if path.first().copied() == Some(b'/') {
        return Ok(false);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    if dirfd != AT_FDCWD {
        return runtime
            .overlay_directory_for_fd(dirfd)
            .map(|directory| directory.is_some())
            .map_err(|_| Error::Invariant);
    }
    let cwd = runtime.fs_context().cwd_handle();
    let directory = runtime
        .overlay()
        .revalidate_directory_handle(cwd)
        .map_err(map_overlay_error)?;
    Ok(!matches!(
        directory.object(),
        OverlayNodeHandle::Root { .. }
    ))
}

fn canonical_at_root_only(path: &[u8]) -> Result<CanonicalPath, Error> {
    CanonicalPath::resolve_from(CanonicalPath::root(), path).map_err(map_path_error)
}

fn canonical_at(
    runtime: &mut super::super::step29_runtime::Step29PathRuntime<'_>,
    raw_dirfd: u64,
    path: &[u8],
) -> Result<CanonicalPath, Error> {
    if path.first().copied() == Some(b'/') {
        return CanonicalPath::resolve_from(CanonicalPath::root(), path).map_err(map_path_error);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    let base_directory = if dirfd == AT_FDCWD {
        let cwd = runtime.fs_context().cwd_handle();
        runtime
            .overlay()
            .revalidate_directory_handle(cwd)
            .map_err(map_overlay_error)?
    } else {
        let Some(directory) = runtime
            .overlay_directory_for_fd(dirfd)
            .map_err(|_| Error::Invariant)?
        else {
            runtime.fds().token(dirfd).map_err(super::map_fd_error)?;
            return Err(Error::Linux(Errno::ENOTDIR));
        };
        directory
    };
    let base = runtime
        .overlay()
        .directory_canonical_path(base_directory)
        .map_err(map_overlay_error)?;
    CanonicalPath::resolve_from(base, path).map_err(map_path_error)
}

fn canonical_lookup_bytes(canonical: &CanonicalPath) -> &[u8] {
    if canonical.is_root() {
        b"/"
    } else {
        canonical.as_relative_bytes()
    }
}

fn map_overlay_error(error: OverlayError) -> Error {
    match error {
        OverlayError::Path(error) => map_path_error(error),
        OverlayError::Mutable(error) => map_rooted_mutable_error(error),
        OverlayError::NotFound => Error::Linux(Errno::ENOENT),
        OverlayError::AlreadyExists => Error::Linux(Errno::EEXIST),
        OverlayError::NotRegular => Error::Linux(Errno::EINVAL),
        OverlayError::NotDirectory => Error::Linux(Errno::ENOTDIR),
        OverlayError::IsDirectory => Error::Linux(Errno::EISDIR),
        OverlayError::TombstoneTableFull | OverlayError::BindingTableFull => {
            Error::Linux(Errno::ENOSPC)
        }
        OverlayError::FileTooLarge => errno_error(27),
    }
}

fn map_rooted_mutable_error(error: RootedMutableError) -> Error {
    match error {
        RootedMutableError::RootMismatch | RootedMutableError::NamespaceMismatch => {
            Error::Invariant
        }
        RootedMutableError::Path(error) => map_path_error(error),
        RootedMutableError::Mutable(error) => map_mutable_error(error),
    }
}

fn map_mutable_error(error: MutableError) -> Error {
    match error {
        MutableError::NodeTableFull | MutableError::DirectoryEntryTableFull => {
            Error::Linux(Errno::ENOSPC)
        }
        MutableError::InvalidName | MutableError::InvalidOffset => Error::Linux(Errno::EINVAL),
        MutableError::PathTooLong => Error::Linux(Errno::ENAMETOOLONG),
        MutableError::NotFound => Error::Linux(Errno::ENOENT),
        MutableError::AlreadyExists => Error::Linux(Errno::EEXIST),
        MutableError::BadNode => Error::Invariant,
        MutableError::NotDirectory => Error::Linux(Errno::ENOTDIR),
        MutableError::IsDirectory => Error::Linux(Errno::EISDIR),
        MutableError::DirectoryNotEmpty => Error::Linux(Errno::ENOTEMPTY),
        MutableError::NotRegular | MutableError::NotSymlink => Error::Linux(Errno::EINVAL),
        MutableError::FileTooLarge => errno_error(27),
        MutableError::LinkOverflow => errno_error(31),
        MutableError::OpenReferenceOverflow => Error::Linux(Errno::EMFILE),
        MutableError::DirectoryCycle => Error::Linux(Errno::ELOOP),
    }
}

fn map_path_error(error: VfsError) -> Error {
    match error {
        VfsError::EmptyPath => Error::Linux(Errno::ENOENT),
        VfsError::EmbeddedNul => Error::Linux(Errno::EINVAL),
        VfsError::PathTooLong => Error::Linux(Errno::ENAMETOOLONG),
        VfsError::UnsupportedDirFd => Error::Linux(Errno::EBADF),
        VfsError::NotFound => Error::Linux(Errno::ENOENT),
        VfsError::NotDirectory => Error::Linux(Errno::ENOTDIR),
        VfsError::IsDirectory => Error::Linux(Errno::EISDIR),
        VfsError::SymlinkUnsupported => Error::Linux(Errno::ELOOP),
        VfsError::UnsupportedNode => Error::Linux(Errno::EACCES),
        VfsError::Archive(_) | VfsError::HandleMismatch | VfsError::OffsetOverflow => {
            Error::Invariant
        }
    }
}

fn errno(value: u16) -> Result<Errno, Error> {
    Errno::new(value).ok_or(Error::Invariant)
}

fn errno_error(value: u16) -> Error {
    match Errno::new(value) {
        Some(errno) => Error::Linux(errno),
        None => Error::Invariant,
    }
}
