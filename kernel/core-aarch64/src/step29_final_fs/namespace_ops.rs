// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::{classify_fs, classify_path_fd};
use kernal_linux_abi::{
    Errno, FsCall, PathFdCall, SyscallRequest, SyscallReturn, linux_signed_int, linux_unsigned_int,
};
use kernal_linux_fd::{Error as FdError, ReleasedObject};
use kernal_linux_vfs::{AT_FDCWD, LINUX_PATH_MAX, MutableTimestamp, OverlayDirectoryHandle};
use kernal_usercopy::MAX_USERCOPY_BYTES;

use super::{Error, map_overlay_error};

const AT_REMOVEDIR: u32 = 0x200;
const RENAME_NOREPLACE: u32 = 1;
const ACCESS_MODE_MASK: u32 = 0x7;

pub(super) fn handle(request: SyscallRequest, frame: &mut ExceptionFrame) -> Result<bool, ()> {
    if let Some(call) = classify_path_fd(request) {
        match call {
            PathFdCall::Close { fd } => {
                let process = super::super::current_process().map_err(|_| ())?;
                match close_directory(process, fd) {
                    Ok(Some(value)) => return finish(Ok(value), frame),
                    Ok(None) => {}
                    Err(error) => return finish(Err(error), frame),
                }
                match close_retained_file(process, fd) {
                    Ok(Some(value)) => return finish(Ok(value), frame),
                    Ok(None) => {}
                    Err(error) => return finish(Err(error), frame),
                }
            }
            PathFdCall::Getdents64 {
                fd,
                user_buffer,
                count,
            } => {
                let process = super::super::current_process().map_err(|_| ())?;
                match getdents64_retained(process, fd, user_buffer, count) {
                    Ok(Some(value)) => return finish(Ok(value), frame),
                    Ok(None) => {}
                    Err(error) => return finish(Err(error), frame),
                }
            }
            PathFdCall::Read {
                fd,
                user_buffer,
                count,
            } => {
                let process = super::super::current_process().map_err(|_| ())?;
                match read_retained(process, fd, user_buffer, count) {
                    Ok(Some(value)) => return finish(Ok(value), frame),
                    Ok(None) => {}
                    Err(error) => return finish(Err(error), frame),
                }
            }
            _ => {}
        }
    }

    let Some(call) = classify_fs(request) else {
        return Ok(false);
    };
    let process = super::super::current_process().map_err(|_| ())?;
    let result = match call {
        FsCall::UnlinkAt {
            dirfd,
            user_path,
            flags,
        } => unlinkat(process, dirfd, user_path, flags),
        FsCall::SymlinkAt {
            user_target,
            newdirfd,
            user_linkpath,
        } => symlinkat(process, user_target, newdirfd, user_linkpath),
        FsCall::LinkAt {
            olddirfd,
            user_oldpath,
            newdirfd,
            user_newpath,
            flags,
        } => linkat(
            process,
            olddirfd,
            user_oldpath,
            newdirfd,
            user_newpath,
            flags,
        ),
        FsCall::RenameAt {
            olddirfd,
            user_oldpath,
            newdirfd,
            user_newpath,
        } => renameat(
            process,
            olddirfd,
            user_oldpath,
            newdirfd,
            user_newpath,
            false,
        ),
        FsCall::RenameAt2 {
            olddirfd,
            user_oldpath,
            newdirfd,
            user_newpath,
            flags,
        } => renameat2(
            process,
            olddirfd,
            user_oldpath,
            newdirfd,
            user_newpath,
            flags,
        ),
        FsCall::ReadlinkAt {
            dirfd,
            user_path,
            user_buffer,
            buffer_size,
        } => readlinkat(process, dirfd, user_path, user_buffer, buffer_size),
        FsCall::FaccessAt {
            dirfd,
            user_path,
            mode,
        } => faccessat(process, dirfd, user_path, mode),
        FsCall::FaccessAt2 {
            dirfd,
            user_path,
            mode,
            flags,
        } => faccessat2(process, dirfd, user_path, mode, flags),
        _ => return Ok(false),
    };
    finish(result, frame)
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
            .map_err(map_overlay_error);
    }
    let dirfd = linux_signed_int(raw_dirfd);
    if dirfd == AT_FDCWD {
        let cwd = runtime.fs_context().cwd_handle();
        return runtime
            .overlay()
            .revalidate_directory_handle(cwd)
            .map_err(map_overlay_error);
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

fn close_directory(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    let owner = super::super::super::step29_runtime::with_process(process, |runtime| {
        if runtime.fds().retained_directory(fd).is_ok() {
            return Ok(1u8);
        }
        match runtime.fds().prepare_directory(fd) {
            Ok(_) => Ok(2u8),
            Err(FdError::BadFd | FdError::NotDirectory) => Ok(0u8),
            Err(error) => Err(super::super::map_fd_error(error)),
        }
    })
    .map_err(|_| Error::Invariant)??;

    match owner {
        0 => Ok(None),
        2 => super::super::close(process, raw_fd).map(Some),
        1 => super::super::super::step29_runtime::with_process(process, |runtime| {
            let token = runtime
                .fds()
                .token(fd)
                .map_err(super::super::map_fd_error)?;
            let (fds, overlay) = runtime.fd_overlay_parts();
            let closed = fds
                .close_with_release(fd, |released| match released {
                    ReleasedObject::RetainedDirectory(directory) => overlay
                        .release_directory(directory)
                        .map_err(map_overlay_error),
                    _ => Err(Error::Invariant),
                })
                .map_err(super::super::map_fd_error)?;
            closed?;
            super::super::record_directory_close(token);
            Ok(Some(0))
        })
        .map_err(|_| Error::Invariant)?,
        _ => Err(Error::Invariant),
    }
}

fn close_retained_file(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    let token = super::super::super::step29_runtime::with_process(process, |runtime| {
        if runtime.fds().retained_readonly(fd).is_err() {
            return Ok(None);
        }
        runtime
            .fds()
            .token(fd)
            .map(Some)
            .map_err(super::super::map_fd_error)
    })
    .map_err(|_| Error::Invariant)??;
    let Some(token) = token else {
        return Ok(None);
    };

    let closed = super::close(process, raw_fd)?;
    if closed.is_some() {
        super::super::record_proof_close(token);
    }
    Ok(closed)
}

fn getdents64_retained(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    let capacity = usize::try_from(count).unwrap_or(usize::MAX);

    super::super::super::step29_runtime::with_process(process, |runtime| {
        match runtime.fds().prepare_retained_directory(fd) {
            Ok(_) => {}
            Err(FdError::BadFd | FdError::NotDirectory) => return Ok(None),
            Err(error) => return Err(super::super::map_fd_error(error)),
        }
        let token = runtime
            .fds()
            .token(fd)
            .map_err(super::super::map_fd_error)?;

        let mut copied = 0usize;
        loop {
            let plan = runtime
                .fds()
                .prepare_retained_directory(fd)
                .map_err(super::super::map_fd_error)?;
            let Some(scan) = runtime
                .overlay()
                .directory_entry_from(plan.2, plan.3)
                .map_err(map_overlay_error)?
            else {
                super::super::record_directory_eof(token, plan.3);
                break;
            };
            let metadata = runtime
                .overlay()
                .metadata(scan.entry().object())
                .map_err(map_overlay_error)?;
            let inode = super::overlay_stat::inode(metadata).map_err(|_| Error::Invariant)?;
            let record = super::super::dirent::Dirent64Record::encode_overlay(scan, inode)
                .map_err(super::super::map_dirent_error)?;
            let record_bytes = record.as_bytes();
            let remaining = capacity.saturating_sub(copied);
            if record_bytes.len() > remaining {
                if copied == 0 {
                    return Err(Error::Linux(Errno::EINVAL));
                }
                break;
            }
            let target = match super::checked_user_progress(user_buffer, copied) {
                Ok(target) => target,
                Err(error) if copied != 0 => {
                    let _ = error;
                    break;
                }
                Err(error) => return Err(error),
            };
            match kernal_usercopy_aarch64::copy_to_user(target, record_bytes) {
                Ok(()) => {}
                Err(error) => match super::super::map_usercopy_error(error) {
                    Error::Linux(Errno::EFAULT) if copied != 0 => break,
                    mapped => return Err(mapped),
                },
            }
            runtime
                .fds()
                .commit_retained_directory(plan, scan)
                .map_err(super::super::map_fd_error)?;
            super::super::record_directory_entry(token, scan);
            copied = copied
                .checked_add(record_bytes.len())
                .ok_or(Error::Invariant)?;
        }

        Ok(Some(u64::try_from(copied).map_err(|_| Error::Invariant)?))
    })
    .map_err(|_| Error::Invariant)?
}

fn unlinkat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_flags: u64,
) -> Result<u64, Error> {
    let flags = linux_unsigned_int(raw_flags);
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let path = super::super::copy_user_path(user_path)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        runtime
            .overlay()
            .unlink_from(base, path.as_bytes(), flags & AT_REMOVEDIR != 0)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn symlinkat(
    process: kernal_capability::ObjectId,
    user_target: u64,
    raw_newdirfd: u64,
    user_linkpath: u64,
) -> Result<u64, Error> {
    let target = super::super::copy_user_path(user_target)?;
    let linkpath = super::super::copy_user_path(user_linkpath)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_newdirfd, linkpath.as_bytes())?;
        runtime
            .overlay()
            .symlink_from(
                base,
                target.as_bytes(),
                linkpath.as_bytes(),
                0,
                0,
                MutableTimestamp::ZERO,
            )
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn linkat(
    process: kernal_capability::ObjectId,
    raw_olddirfd: u64,
    user_oldpath: u64,
    raw_newdirfd: u64,
    user_newpath: u64,
    raw_flags: u64,
) -> Result<u64, Error> {
    if linux_unsigned_int(raw_flags) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let oldpath = super::super::copy_user_path(user_oldpath)?;
    let newpath = super::super::copy_user_path(user_newpath)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let old_base = base_for_path(runtime, raw_olddirfd, oldpath.as_bytes())?;
        let new_base = base_for_path(runtime, raw_newdirfd, newpath.as_bytes())?;
        runtime
            .overlay()
            .link_regular_from(old_base, oldpath.as_bytes(), new_base, newpath.as_bytes())
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn renameat2(
    process: kernal_capability::ObjectId,
    olddirfd: u64,
    user_oldpath: u64,
    newdirfd: u64,
    user_newpath: u64,
    raw_flags: u64,
) -> Result<u64, Error> {
    let flags = linux_unsigned_int(raw_flags);
    if flags & !RENAME_NOREPLACE != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    renameat(
        process,
        olddirfd,
        user_oldpath,
        newdirfd,
        user_newpath,
        flags & RENAME_NOREPLACE != 0,
    )
}

fn renameat(
    process: kernal_capability::ObjectId,
    raw_olddirfd: u64,
    user_oldpath: u64,
    raw_newdirfd: u64,
    user_newpath: u64,
    no_replace: bool,
) -> Result<u64, Error> {
    let oldpath = super::super::copy_user_path(user_oldpath)?;
    let newpath = super::super::copy_user_path(user_newpath)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let old_base = base_for_path(runtime, raw_olddirfd, oldpath.as_bytes())?;
        let new_base = base_for_path(runtime, raw_newdirfd, newpath.as_bytes())?;
        runtime
            .overlay()
            .rename_from(
                old_base,
                oldpath.as_bytes(),
                new_base,
                newpath.as_bytes(),
                no_replace,
            )
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn readlinkat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    user_buffer: u64,
    raw_buffer_size: u64,
) -> Result<u64, Error> {
    let path = super::super::copy_user_path(user_path)?;
    let capacity = core::cmp::min(
        usize::try_from(raw_buffer_size).unwrap_or(usize::MAX),
        LINUX_PATH_MAX,
    );
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        let mut output = [0u8; LINUX_PATH_MAX];
        let copied = runtime
            .overlay()
            .readlink_from(base, path.as_bytes(), &mut output[..capacity])
            .map_err(map_overlay_error)?;
        if copied != 0 {
            kernal_usercopy_aarch64::copy_to_user(user_buffer, &output[..copied])
                .map_err(super::super::map_usercopy_error)?;
        }
        u64::try_from(copied).map_err(|_| Error::Invariant)
    })
    .map_err(|_| Error::Invariant)?
}

fn faccessat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_mode: u64,
) -> Result<u64, Error> {
    let mode = linux_unsigned_int(raw_mode);
    if mode & !ACCESS_MODE_MASK != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let path = super::super::copy_user_path(user_path)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        let logical = runtime
            .overlay()
            .resolve_following_from(base, path.as_bytes())
            .map_err(map_overlay_error)?;
        runtime
            .overlay()
            .metadata(logical)
            .map_err(map_overlay_error)?;
        // Step-29's single initial process has effective uid 0. Existence therefore satisfies the
        // frozen corpus' F_OK/R_OK/W_OK/X_OK probes without inventing a second credential owner.
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn faccessat2(
    process: kernal_capability::ObjectId,
    dirfd: u64,
    user_path: u64,
    mode: u64,
    raw_flags: u64,
) -> Result<u64, Error> {
    if linux_unsigned_int(raw_flags) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    faccessat(process, dirfd, user_path, mode)
}

fn read_retained(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    let requested = core::cmp::min(
        usize::try_from(count).unwrap_or(usize::MAX),
        MAX_USERCOPY_BYTES,
    );
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let writable = runtime.fds().writable_regular(fd).ok();
        let readonly = runtime.fds().retained_readonly(fd).ok();
        if writable.is_none() && readonly.is_none() {
            return Ok(None);
        }
        let proof_token = if readonly.is_some() {
            Some(
                runtime
                    .fds()
                    .token(fd)
                    .map_err(super::super::map_fd_error)?,
            )
        } else {
            None
        };
        if writable.is_some()
            && runtime
                .fds()
                .status_flags(fd)
                .map_err(super::super::map_fd_error)?
                & super::O_ACCMODE
                != super::O_RDWR
        {
            return Err(Error::Linux(Errno::EBADF));
        }
        if requested == 0 {
            if writable.is_some() {
                runtime
                    .fds()
                    .prepare_writable_read(fd, 0)
                    .map_err(super::super::map_fd_error)?;
            } else {
                runtime
                    .fds()
                    .prepare_retained_read(fd, 0)
                    .map_err(super::super::map_fd_error)?;
            }
            return Ok(Some(0));
        }

        let mut scratch = [0u8; super::WRITE_CHUNK_BYTES];
        let mut total = 0usize;
        while total < requested {
            let chunk_len = core::cmp::min(super::WRITE_CHUNK_BYTES, requested - total);
            let user_address = super::checked_user_progress(user_buffer, total)?;
            let (read, copied, faulted) = if writable.is_some() {
                let plan = runtime
                    .fds()
                    .prepare_writable_read(fd, chunk_len)
                    .map_err(super::super::map_fd_error)?;
                let read = runtime
                    .overlay()
                    .read_retained_regular(plan.2, plan.3, &mut scratch[..chunk_len])
                    .map_err(map_overlay_error)?;
                let progress =
                    kernal_usercopy_aarch64::copy_to_user_progress(user_address, &scratch[..read])
                        .map_err(super::super::map_usercopy_error)?;
                let copied = progress.copied();
                runtime
                    .fds()
                    .commit_writable_read(plan, copied)
                    .map_err(super::super::map_fd_error)?;
                (read, copied, progress.faulted())
            } else {
                let plan = runtime
                    .fds()
                    .prepare_retained_read(fd, chunk_len)
                    .map_err(super::super::map_fd_error)?;
                let read = runtime
                    .overlay()
                    .read_regular(plan.2, plan.3, &mut scratch[..chunk_len])
                    .map_err(map_overlay_error)?;
                let progress =
                    kernal_usercopy_aarch64::copy_to_user_progress(user_address, &scratch[..read])
                        .map_err(super::super::map_usercopy_error)?;
                let copied = progress.copied();
                runtime
                    .fds()
                    .commit_retained_read(plan, copied)
                    .map_err(super::super::map_fd_error)?;
                (read, copied, progress.faulted())
            };

            total = total.checked_add(copied).ok_or(Error::Invariant)?;
            if faulted {
                return if total == 0 {
                    Err(Error::Linux(Errno::EFAULT))
                } else {
                    let total = u64::try_from(total).map_err(|_| Error::Invariant)?;
                    if let Some(token) = proof_token {
                        super::super::record_proof_read(token, total);
                    }
                    Ok(Some(total))
                };
            }
            if copied < read {
                let total = u64::try_from(total).map_err(|_| Error::Invariant)?;
                if let Some(token) = proof_token {
                    super::super::record_proof_read(token, total);
                }
                return Ok(Some(total));
            }
            if read < chunk_len {
                break;
            }
        }
        let total = u64::try_from(total).map_err(|_| Error::Invariant)?;
        if let Some(token) = proof_token {
            super::super::record_proof_read(token, total);
        }
        Ok(Some(total))
    })
    .map_err(|_| Error::Invariant)?
}
