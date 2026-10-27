// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::{classify_fs, classify_path_fd};
use kernal_linux_abi::{
    Errno, FsCall, PathFdCall, SyscallRequest, SyscallReturn, linux_signed_int, linux_signed_off_t,
    linux_unsigned_int,
};
use kernal_linux_fd::Error as FdError;
use kernal_linux_vfs::{AT_FDCWD, MutableTimestamp, OverlayDirectoryHandle, OverlayMetadata};

use super::{Error, map_overlay_error};

const TIMESPEC_BYTES: usize = 16;
const UTIMENS_PAIR_BYTES: usize = TIMESPEC_BYTES * 2;
const NSEC_PER_SECOND: i64 = 1_000_000_000;
const UID_GID_UNCHANGED: u32 = u32::MAX;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_NO_AUTOMOUNT: u32 = 0x800;
const FSTATAT_SUPPORTED_FLAGS: u32 = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;
const STATX_SUPPORTED_FLAGS: u32 = 0;

pub(super) fn handle(request: SyscallRequest, frame: &mut ExceptionFrame) -> Result<bool, ()> {
    if let Some(call) = classify_fs(request) {
        let process = super::super::current_process().map_err(|_| ())?;
        let result = match call {
            FsCall::Truncate { user_path, length } => {
                truncate(process, user_path, length).map(Some)
            }
            FsCall::Ftruncate { fd, length } => ftruncate(process, fd, length).map(Some),
            FsCall::Fchmod { fd, mode } => fchmod(process, fd, mode).map(Some),
            FsCall::FchmodAt {
                dirfd,
                user_path,
                mode,
            } => fchmodat(process, dirfd, user_path, mode).map(Some),
            FsCall::FchownAt {
                dirfd,
                user_path,
                owner,
                group,
                flags,
            } => fchownat(process, dirfd, user_path, owner, group, flags).map(Some),
            FsCall::Fchown { fd, owner, group } => fchown(process, fd, owner, group).map(Some),
            FsCall::UtimensAt {
                dirfd,
                user_path,
                user_times,
                flags,
            } => utimensat(process, dirfd, user_path, user_times, flags).map(Some),
            FsCall::Statx {
                dirfd,
                user_path,
                flags,
                mask,
                user_statx,
            } => statx(process, dirfd, user_path, flags, mask, user_statx).map(Some),
            _ => Ok(None),
        };
        if let Some(result) = transpose(result)? {
            return finish(result, frame);
        }
    }

    let Some(call) = classify_path_fd(request) else {
        return Ok(false);
    };
    let process = super::super::current_process().map_err(|_| ())?;
    match call {
        PathFdCall::Fstat { fd, user_stat } => match fstat(process, fd, user_stat) {
            Ok(Some(value)) => finish(Ok(value), frame),
            Ok(None) => Ok(false),
            Err(error) => finish(Err(error), frame),
        },
        PathFdCall::Newfstatat {
            dirfd,
            user_path,
            user_stat,
            flags,
        } => {
            let flags = linux_unsigned_int(flags);
            if flags & !FSTATAT_SUPPORTED_FLAGS != 0 {
                return finish(Err(Error::Linux(Errno::EINVAL)), frame);
            }
            finish(
                newfstatat(process, dirfd, user_path, user_stat, flags),
                frame,
            )
        }
        _ => Ok(false),
    }
}

fn transpose(value: Result<Option<u64>, Error>) -> Result<Option<Result<u64, Error>>, ()> {
    match value {
        Ok(Some(value)) => Ok(Some(Ok(value))),
        Ok(None) => Ok(None),
        Err(error) => Ok(Some(Err(error))),
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

fn fstat(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    user_stat: u64,
) -> Result<Option<u64>, Error> {
    let fd = linux_signed_int(raw_fd);
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let token = runtime
            .fds()
            .token(fd)
            .map_err(super::super::map_fd_error)?;
        let metadata = if let Ok(retained) = runtime.fds().writable_regular(fd) {
            runtime
                .overlay()
                .retained_regular_metadata(retained)
                .map_err(map_overlay_error)?
        } else if let Ok(logical) = runtime.fds().retained_readonly(fd) {
            runtime
                .overlay()
                .metadata(logical)
                .map_err(map_overlay_error)?
        } else if let Some(directory) = runtime
            .overlay_directory_for_fd(fd)
            .map_err(|_| Error::Invariant)?
        {
            runtime
                .overlay()
                .metadata(directory.object())
                .map_err(map_overlay_error)?
        } else {
            return Ok(None);
        };

        write_stat(user_stat, metadata)?;
        super::super::record_proof_fstat(token);
        Ok(Some(0))
    })
    .map_err(|_| Error::Invariant)?
}

fn newfstatat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    user_stat: u64,
    flags: u32,
) -> Result<u64, Error> {
    let path = super::super::copy_user_path(user_path)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        let logical = if flags & AT_SYMLINK_NOFOLLOW != 0 {
            runtime
                .overlay()
                .resolve_nofollow_from(base, path.as_bytes())
        } else {
            runtime
                .overlay()
                .resolve_following_from(base, path.as_bytes())
        }
        .map_err(map_overlay_error)?;
        let metadata = runtime
            .overlay()
            .metadata(logical)
            .map_err(map_overlay_error)?;
        write_stat(user_stat, metadata)
    })
    .map_err(|_| Error::Invariant)?
}

fn write_stat(user_stat: u64, metadata: OverlayMetadata) -> Result<u64, Error> {
    let bytes = super::overlay_stat::encode(metadata).map_err(|_| Error::Invariant)?;
    kernal_usercopy_aarch64::copy_to_user(user_stat, &bytes)
        .map_err(super::super::map_usercopy_error)?;
    Ok(0)
}

fn truncate(
    process: kernal_capability::ObjectId,
    user_path: u64,
    raw_length: u64,
) -> Result<u64, Error> {
    let length = decode_nonnegative_length(raw_length)?;
    let path = super::super::copy_user_path(user_path)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, AT_FDCWD as u64, path.as_bytes())?;
        runtime
            .overlay()
            .truncate_from(base, path.as_bytes(), length, MutableTimestamp::ZERO)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn ftruncate(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    raw_length: u64,
) -> Result<u64, Error> {
    let fd = linux_signed_int(raw_fd);
    let length = decode_nonnegative_length(raw_length)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let retained = match runtime.fds().writable_regular(fd) {
            Ok(retained) => retained,
            Err(FdError::BadFd) => return Err(Error::Linux(Errno::EBADF)),
            Err(_) => return Err(Error::Linux(Errno::EINVAL)),
        };
        runtime
            .overlay()
            .truncate_retained_regular(retained, length, MutableTimestamp::ZERO)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn fchmod(process: kernal_capability::ObjectId, raw_fd: u64, raw_mode: u64) -> Result<u64, Error> {
    let fd = linux_signed_int(raw_fd);
    let mode = linux_unsigned_int(raw_mode);
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let retained = match runtime.fds().writable_regular(fd) {
            Ok(retained) => retained,
            Err(_) if runtime.fds().retained_readonly(fd).is_ok() => {
                return Err(Error::Linux(Errno::EBADF));
            }
            Err(error) => return Err(super::super::map_fd_error(error)),
        };
        runtime
            .overlay()
            .chmod_retained_regular(retained, mode, MutableTimestamp::ZERO)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn fchmodat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_mode: u64,
) -> Result<u64, Error> {
    let mode = linux_unsigned_int(raw_mode);
    let path = super::super::copy_user_path(user_path)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        runtime
            .overlay()
            .chmod_from(base, path.as_bytes(), mode, MutableTimestamp::ZERO)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn fchownat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_owner: u64,
    raw_group: u64,
    raw_flags: u64,
) -> Result<u64, Error> {
    if linux_unsigned_int(raw_flags) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let owner = optional_uid_gid(raw_owner);
    let group = optional_uid_gid(raw_group);
    let path = super::super::copy_user_path(user_path)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        runtime
            .overlay()
            .chown_from(base, path.as_bytes(), owner, group, MutableTimestamp::ZERO)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn fchown(
    process: kernal_capability::ObjectId,
    raw_fd: u64,
    raw_owner: u64,
    raw_group: u64,
) -> Result<u64, Error> {
    let fd = linux_signed_int(raw_fd);
    let owner = optional_uid_gid(raw_owner);
    let group = optional_uid_gid(raw_group);
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let retained = match runtime.fds().writable_regular(fd) {
            Ok(retained) => retained,
            Err(_) if runtime.fds().retained_readonly(fd).is_ok() => {
                return Err(Error::Linux(Errno::EBADF));
            }
            Err(error) => return Err(super::super::map_fd_error(error)),
        };
        runtime
            .overlay()
            .chown_retained_regular(retained, owner, group, MutableTimestamp::ZERO)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn utimensat(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    user_times: u64,
    raw_flags: u64,
) -> Result<u64, Error> {
    if linux_unsigned_int(raw_flags) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    if user_times == 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let path = super::super::copy_user_path(user_path)?;
    let (atime, mtime) = copy_explicit_times(user_times)?;

    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        runtime
            .overlay()
            .set_times_from(base, path.as_bytes(), atime, mtime, MutableTimestamp::ZERO)
            .map_err(map_overlay_error)?;
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn statx(
    process: kernal_capability::ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_flags: u64,
    raw_mask: u64,
    user_statx: u64,
) -> Result<u64, Error> {
    if linux_unsigned_int(raw_flags) & !STATX_SUPPORTED_FLAGS != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let _requested_mask = linux_unsigned_int(raw_mask);
    let path = super::super::copy_user_path(user_path)?;
    super::super::super::step29_runtime::with_process(process, |runtime| {
        let base = base_for_path(runtime, raw_dirfd, path.as_bytes())?;
        let logical = runtime
            .overlay()
            .resolve_following_from(base, path.as_bytes())
            .map_err(map_overlay_error)?;
        let metadata = runtime
            .overlay()
            .metadata(logical)
            .map_err(map_overlay_error)?;
        write_statx(user_statx, metadata)
    })
    .map_err(|_| Error::Invariant)?
}

fn write_statx(user_statx: u64, metadata: OverlayMetadata) -> Result<u64, Error> {
    let bytes = super::overlay_stat::encode_statx(metadata).map_err(|_| Error::Invariant)?;
    kernal_usercopy_aarch64::copy_to_user(user_statx, &bytes)
        .map_err(super::super::map_usercopy_error)?;
    Ok(0)
}

fn decode_nonnegative_length(raw: u64) -> Result<u64, Error> {
    let length = linux_signed_off_t(raw);
    if length < 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    u64::try_from(length).map_err(|_| Error::Invariant)
}

fn optional_uid_gid(raw: u64) -> Option<u32> {
    let value = linux_unsigned_int(raw);
    (value != UID_GID_UNCHANGED).then_some(value)
}

fn copy_explicit_times(user_times: u64) -> Result<(MutableTimestamp, MutableTimestamp), Error> {
    let mut bytes = [0u8; UTIMENS_PAIR_BYTES];
    kernal_usercopy_aarch64::copy_from_user(&mut bytes, user_times)
        .map_err(super::super::map_usercopy_error)?;
    let atime = decode_timespec(&bytes[..TIMESPEC_BYTES])?;
    let mtime = decode_timespec(&bytes[TIMESPEC_BYTES..])?;
    Ok((atime, mtime))
}

fn decode_timespec(bytes: &[u8]) -> Result<MutableTimestamp, Error> {
    let seconds = i64::from_le_bytes(bytes[..8].try_into().map_err(|_| Error::Invariant)?);
    let nanoseconds = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| Error::Invariant)?);
    if !(0..NSEC_PER_SECOND).contains(&nanoseconds) {
        return Err(Error::Linux(Errno::EINVAL));
    }
    Ok(MutableTimestamp {
        seconds,
        nanoseconds: u32::try_from(nanoseconds).map_err(|_| Error::Invariant)?,
    })
}
