// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_capability::ObjectId;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::classify_fd_io;
use kernal_linux_abi::{
    Errno, FdIoCall, SyscallRequest, SyscallReturn, linux_signed_int, linux_signed_off_t,
    linux_unsigned_int,
};
use kernal_linux_bootstrap::OutputFd;
use kernal_linux_fd::{
    Error as FdError, ExternalObject, OpenObjectKind, ReleasedObject, SeekWhence,
};
use kernal_linux_pipe::{Error as PipeError, PipeId};
use kernal_linux_vfs::{Error as VfsError, InitramfsRoot};
use kernal_usercopy::{Error as UsercopyError, MAX_USERCOPY_BYTES};

const O_ACCMODE: u64 = 0x3;
const O_NONBLOCK: u32 = 0x0000_0800;
const O_CLOEXEC: u32 = 0x0008_0000;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_DUPFD_CLOEXEC: u32 = 1030;
const FD_CLOEXEC: i32 = 1;
const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Error {
    Linux(Errno),
    Invariant,
}

enum WriteOutcome {
    Returned {
        value: u64,
        wake_pipe: Option<PipeId>,
    },
    External(OutputFd),
}

/// Routes the Step-29 descriptor-I/O extension backed by the accepted FD/OFD and pipe owners.
pub(super) fn handle(request: SyscallRequest, frame: &mut ExceptionFrame) -> Result<bool, ()> {
    // write(2) must be intercepted before the legacy Step-15 numeric fd==1/2 fallback. The
    // canonical FD/OFD object decides whether this is a pipe, an inherited External stream, or an
    // invalid write target, so dup/dup3 aliases never gain or lose authority based on their number.
    if request.number == 64 {
        let process = current_process().map_err(|_| ())?;
        match write(process, frame.x[0], frame.x[1], frame.x[2]) {
            Ok(WriteOutcome::Returned { value, wake_pipe }) => {
                // `write()` has returned, so its Step29 Runtime/FD/Pipe borrow is fully released.
                // Only now may normal pipe readiness route an exact scheduler wake.
                if let Some(pipe) = wake_pipe {
                    super::futex::pipe_blocking::notify_after_write(pipe)?;
                }
                frame.x[0] = SyscallReturn::success(value as i64)
                    .ok_or(())?
                    .as_u64_bits();
                return Ok(true);
            }
            Ok(WriteOutcome::External(output)) => {
                super::write::handle_bound_output(frame, output)?;
                return Ok(true);
            }
            Err(Error::Linux(errno)) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                return Ok(true);
            }
            Err(Error::Invariant) => return Err(()),
        }
    }

    let Some(call) = classify_fd_io(request) else {
        return Ok(false);
    };

    let process = current_process().map_err(|_| ())?;
    let result = match call {
        FdIoCall::Dup { oldfd } => dup(process, oldfd),
        FdIoCall::Dup3 {
            oldfd,
            newfd,
            flags,
        } => dup3(process, oldfd, newfd, flags),
        FdIoCall::Fcntl { fd, cmd, arg } => fcntl(process, fd, cmd, arg),
        FdIoCall::Pipe2 { user_pipefd, flags } => pipe2(process, user_pipefd, flags),
        FdIoCall::Lseek { fd, offset, whence } => lseek(process, fd, offset, whence),
        FdIoCall::Pread64 {
            fd,
            user_buffer,
            count,
            offset,
        } => pread64(process, fd, user_buffer, count, offset),
    };

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

fn current_process() -> Result<ObjectId, Error> {
    let current_cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS
        .get(current_cpu)
        .ok_or(Error::Invariant)?;
    // SAFETY: a lower-EL synchronous SVC owns the current PE's IRQ-masked scheduler window.
    let current =
        unsafe { scheduler.bootstrap_current_global_thread() }.map_err(|_| Error::Invariant)?;

    super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _tid) = state
            .process_parts_for_scheduler_thread(current)
            .map_err(|_| Error::Invariant)?;
        address_space
            .current_owner(process)
            .map_err(|_| Error::Invariant)?;
        Ok(process.id())
    })
    .map_err(|_| Error::Invariant)?
}

fn write(
    process: ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
) -> Result<WriteOutcome, Error> {
    let fd = decoded_fd(raw_fd);
    super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes) = runtime.fd_pipe_parts();
        match fds.object_kind(fd).map_err(map_fd_error)? {
            OpenObjectKind::Pipe => {
                let status = fds.status_flags(fd).map_err(map_fd_error)?;
                if status & O_ACCMODE != O_WRONLY {
                    return Err(Error::Linux(Errno::EBADF));
                }
                // object_kind already proved this OFD is a pipe; failure to recover the exact
                // endpoint from the same generation-safe descriptor is an internal invariant.
                let endpoint = fds.pipe_endpoint(fd).map_err(|_| Error::Invariant)?;
                let nonblocking = status & u64::from(O_NONBLOCK) != 0;
                let written =
                    super::step29_pipe_io::write(pipes, endpoint, user_buffer, count, nonblocking)
                        .map_err(map_pipe_io_error)?;
                Ok(WriteOutcome::Returned {
                    value: written,
                    wake_pipe: (written != 0).then_some(endpoint.pipe()),
                })
            }
            OpenObjectKind::External(ExternalObject::Stdout) => {
                Ok(WriteOutcome::External(OutputFd::Stdout))
            }
            OpenObjectKind::External(ExternalObject::Stderr) => {
                Ok(WriteOutcome::External(OutputFd::Stderr))
            }
            OpenObjectKind::External(ExternalObject::Stdin)
            | OpenObjectKind::File
            | OpenObjectKind::Directory => Err(Error::Linux(Errno::EBADF)),
        }
    })
    .map_err(|_| Error::Invariant)?
}

fn dup(process: ObjectId, raw_oldfd: u64) -> Result<u64, Error> {
    let oldfd = decoded_fd(raw_oldfd);
    super::step29_runtime::with_process(process, |runtime| {
        let token = runtime
            .fds()
            .duplicate_lowest(oldfd, false)
            .map_err(map_fd_error)?;
        u64::try_from(token.fd()).map_err(|_| Error::Invariant)
    })
    .map_err(|_| Error::Invariant)?
}

fn dup3(process: ObjectId, raw_oldfd: u64, raw_newfd: u64, raw_flags: u64) -> Result<u64, Error> {
    // Linux validates the flag mask before any descriptor lookup.
    let close_on_exec = decode_dup3_flags(raw_flags)?;
    let oldfd = decoded_fd(raw_oldfd);
    let newfd = decoded_fd(raw_newfd);
    if oldfd == newfd {
        return Err(Error::Linux(Errno::EINVAL));
    }
    validate_exact_target(newfd)?;

    super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes, overlay) = runtime.fd_pipe_overlay_parts();
        let duplicated = fds
            .duplicate_exact_with_release(oldfd, newfd, close_on_exec, |released| match released {
                ReleasedObject::Pipe(endpoint) => pipes.close(endpoint).map_err(map_pipe_error),
                ReleasedObject::RetainedDirectory(directory) => overlay
                    .release_directory(directory)
                    .map_err(|_| Error::Invariant),
                ReleasedObject::RetainedReadOnly(logical) => {
                    overlay.release_open(logical).map_err(|_| Error::Invariant)
                }
                ReleasedObject::WritableRegular(retained) => overlay
                    .release_retained_regular(retained)
                    .map_err(|_| Error::Invariant),
            })
            .map_err(map_fd_error)?;
        let token = duplicated?;
        u64::try_from(token.fd()).map_err(|_| Error::Invariant)
    })
    .map_err(|_| Error::Invariant)?
}

fn fcntl(process: ObjectId, raw_fd: u64, raw_cmd: u64, raw_arg: u64) -> Result<u64, Error> {
    let fd = decoded_fd(raw_fd);
    let cmd = linux_unsigned_int(raw_cmd);
    let argi = linux_signed_int(raw_arg);

    super::step29_runtime::with_process(process, |runtime| {
        let fds = runtime.fds();
        match cmd {
            F_DUPFD => {
                let token = fds.duplicate_from(fd, argi, false).map_err(map_fd_error)?;
                u64::try_from(token.fd()).map_err(|_| Error::Invariant)
            }
            F_DUPFD_CLOEXEC => {
                let token = fds.duplicate_from(fd, argi, true).map_err(map_fd_error)?;
                u64::try_from(token.fd()).map_err(|_| Error::Invariant)
            }
            F_GETFD => Ok(if fds.close_on_exec(fd).map_err(map_fd_error)? {
                FD_CLOEXEC as u64
            } else {
                0
            }),
            F_SETFD => {
                fds.set_close_on_exec(fd, argi & FD_CLOEXEC != 0)
                    .map_err(map_fd_error)?;
                Ok(0)
            }
            F_GETFL => fds.status_flags(fd).map_err(map_fd_error),
            _ => Err(Error::Linux(Errno::EINVAL)),
        }
    })
    .map_err(|_| Error::Invariant)?
}

fn pipe2(process: ObjectId, user_pipefd: u64, raw_flags: u64) -> Result<u64, Error> {
    // Frozen precedence: reject unsupported flags before pointer validation or resource lookup.
    let (close_on_exec, status_nonblock) = decode_pipe2_flags(raw_flags)?;

    super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes) = runtime.fd_pipe_parts();

        // Global pipe exhaustion is ENFILE and wins before per-process descriptor exhaustion.
        let pair = pipes.create().map_err(map_pipe_error)?;
        let descriptors = match fds.install_pipe_pair(
            pair.reader,
            pair.writer,
            close_on_exec,
            O_RDONLY | status_nonblock,
            O_WRONLY | status_nonblock,
        ) {
            Ok(descriptors) => descriptors,
            Err(error) => {
                // `install_pipe_pair` validates both descriptor/OFD candidates before mutation, so on
                // failure only the freshly-created PipeTable endpoint leases need rollback.
                pipes.close(pair.reader).map_err(|_| Error::Invariant)?;
                pipes.close(pair.writer).map_err(|_| Error::Invariant)?;
                return Err(map_fd_error(error));
            }
        };

        let mut encoded = [0u8; 8];
        encoded[..4].copy_from_slice(&descriptors.reader().fd().to_le_bytes());
        encoded[4..].copy_from_slice(&descriptors.writer().fd().to_le_bytes());

        if let Err(copy_error) = kernal_usercopy_aarch64::copy_to_user(user_pipefd, &encoded) {
            // A failed userspace result publication must leave neither descriptor nor pipe object
            // reachable. Each freshly-installed pipe OFD has one descriptor, so closing both exact
            // descriptors releases the corresponding endpoint lease exactly once.
            let reader_close = fds
                .close_with_release(descriptors.reader().fd(), |released| {
                    pipes
                        .close(released.pipe_endpoint())
                        .map_err(map_pipe_error)
                })
                .map_err(map_fd_error)?;
            reader_close?;
            let writer_close = fds
                .close_with_release(descriptors.writer().fd(), |released| {
                    pipes
                        .close(released.pipe_endpoint())
                        .map_err(map_pipe_error)
                })
                .map_err(map_fd_error)?;
            writer_close?;
            return Err(map_usercopy_error(copy_error));
        }

        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn lseek(process: ObjectId, raw_fd: u64, raw_offset: u64, raw_whence: u64) -> Result<u64, Error> {
    let fd = decoded_fd(raw_fd);
    let offset = linux_signed_off_t(raw_offset);

    super::step29_runtime::with_process(process, |runtime| {
        let fds = runtime.fds();
        // The frozen Step-29 contract requires EBADF to win over an invalid whence value.
        fds.token(fd).map_err(map_fd_error)?;
        let whence = decode_whence(raw_whence)?;
        fds.seek(fd, offset, whence).map_err(map_fd_error)
    })
    .map_err(|_| Error::Invariant)?
}

fn pread64(
    process: ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
    raw_offset: u64,
) -> Result<u64, Error> {
    // The frozen ABI requires a negative position to win over any descriptor lookup failure.
    let offset = decode_pread_offset(raw_offset)?;
    let fd = decoded_fd(raw_fd);
    let bounded = bounded_usercopy_len(count);

    super::step29_runtime::with_process(process, |runtime| {
        let (initrd, root_id, fds) = runtime.parts();

        // `prepare_pread()` deliberately reports both directories and pipes as NotFile. Linux
        // requires positional I/O on a pipe to be ESPIPE, so distinguish a live pipe endpoint before
        // entering the immutable-file path while still leaving directory handling as EISDIR.
        match fds.pipe_endpoint(fd) {
            Ok(_) => return Err(Error::Linux(Errno::ESPIPE)),
            Err(FdError::NotFile) => {}
            Err(error) => return Err(map_fd_error(error)),
        }

        let plan = fds
            .prepare_pread(fd, offset, bounded)
            .map_err(map_fd_error)?;
        if plan.is_empty() {
            return Ok(0);
        }

        let progress = initrd.with_bytes(|bytes| {
            let archive = kernal_cpio::Archive::parse(bytes).map_err(|_| Error::Invariant)?;
            let root = InitramfsRoot::new(archive, root_id);
            let source = root
                .read_at(plan.file(), plan.offset(), plan.len())
                .map_err(map_vfs_error)?;
            kernal_usercopy_aarch64::copy_to_user_progress(user_buffer, source)
                .map_err(map_usercopy_error)
        })?;

        // Revalidate the generation-safe descriptor/OFD/file identity after the bounded usercopy.
        // Unlike read(2), pread64 never commits or otherwise mutates the shared OFD position.
        fds.validate_pread(plan).map_err(map_fd_error)?;
        linux_read_result(progress.copied(), progress.faulted())
    })
    .map_err(|_| Error::Invariant)?
}

fn decoded_fd(raw: u64) -> i32 {
    linux_unsigned_int(raw) as i32
}

fn decode_dup3_flags(raw: u64) -> Result<bool, Error> {
    let flags = linux_signed_int(raw) as u32;
    if flags & !O_CLOEXEC != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    Ok(flags & O_CLOEXEC != 0)
}

fn decode_pipe2_flags(raw: u64) -> Result<(bool, u64), Error> {
    let flags = linux_signed_int(raw) as u32;
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    Ok((flags & O_CLOEXEC != 0, u64::from(flags & O_NONBLOCK)))
}

fn validate_exact_target(fd: i32) -> Result<(), Error> {
    let index = usize::try_from(fd).map_err(|_| Error::Linux(Errno::EBADF))?;
    if index >= super::step29_runtime::STEP29_RUNTIME_FDS {
        return Err(Error::Linux(Errno::EBADF));
    }
    Ok(())
}

fn decode_whence(raw: u64) -> Result<SeekWhence, Error> {
    match linux_unsigned_int(raw) {
        SEEK_SET => Ok(SeekWhence::Set),
        SEEK_CUR => Ok(SeekWhence::Current),
        SEEK_END => Ok(SeekWhence::End),
        _ => Err(Error::Linux(Errno::EINVAL)),
    }
}

fn decode_pread_offset(raw: u64) -> Result<i64, Error> {
    let offset = linux_signed_off_t(raw);
    if offset < 0 {
        Err(Error::Linux(Errno::EINVAL))
    } else {
        Ok(offset)
    }
}

fn bounded_usercopy_len(count: u64) -> usize {
    let requested = usize::try_from(count).unwrap_or(usize::MAX);
    core::cmp::min(requested, MAX_USERCOPY_BYTES)
}

fn linux_read_result(copied: usize, faulted: bool) -> Result<u64, Error> {
    if copied == 0 && faulted {
        return Err(Error::Linux(Errno::EFAULT));
    }
    u64::try_from(copied).map_err(|_| Error::Invariant)
}

fn map_usercopy_error(error: UsercopyError) -> Error {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::TooLarge
        | UsercopyError::Fault => Error::Linux(Errno::EFAULT),
        UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => Error::Invariant,
    }
}

fn map_vfs_error(error: VfsError) -> Error {
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

fn map_fd_error(error: FdError) -> Error {
    match error {
        FdError::BadFd | FdError::InvalidTargetFd => Error::Linux(Errno::EBADF),
        FdError::TableFull => Error::Linux(Errno::EMFILE),
        FdError::NotFile => Error::Linux(Errno::EISDIR),
        FdError::NotDirectory => Error::Linux(Errno::ENOTDIR),
        FdError::InvalidMinimumFd
        | FdError::SameDescriptor
        | FdError::InvalidSeek
        | FdError::InvalidPreadOffset => Error::Linux(Errno::EINVAL),
        FdError::SeekOverflow => Error::Linux(Errno::EOVERFLOW),
        FdError::NotSeekable => Error::Linux(Errno::ESPIPE),
        FdError::OffsetOverflow
        | FdError::StaleRead
        | FdError::InvalidReadLength
        | FdError::StaleDirectory
        | FdError::InvalidDirectoryCursor
        | FdError::StaleOpenFile
        | FdError::ReferenceOverflow
        | FdError::StalePread => Error::Invariant,
    }
}

fn map_pipe_error(error: PipeError) -> Error {
    match error {
        PipeError::TableFull => Error::Linux(Errno::ENFILE),
        PipeError::WouldBlock => Error::Linux(Errno::EAGAIN),
        PipeError::BrokenPipe => Error::Linux(Errno::EPIPE),
        PipeError::BadEndpoint
        | PipeError::StaleEndpoint
        | PipeError::StalePlan
        | PipeError::InvalidLength
        | PipeError::CapacityZero
        | PipeError::EpochExhausted => Error::Invariant,
    }
}

fn map_pipe_io_error(error: super::step29_pipe_io::Error) -> Error {
    match error {
        super::step29_pipe_io::Error::Linux(errno) => Error::Linux(errno),
        super::step29_pipe_io::Error::BlockingWaitRequired
        | super::step29_pipe_io::Error::Invariant => Error::Invariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_decode_uses_only_low_linux_int_bits() {
        assert_eq!(decoded_fd(3), 3);
        assert_eq!(decoded_fd(0xffff_ffff_0000_0003), 3);
        assert_eq!(decoded_fd(0xffff_ffff_ffff_ffff), -1);
    }

    #[test]
    fn dup3_flags_are_low32_and_only_cloexec() {
        assert_eq!(decode_dup3_flags(0), Ok(false));
        assert_eq!(decode_dup3_flags(O_CLOEXEC as u64), Ok(true));
        assert_eq!(
            decode_dup3_flags(0xaaaa_aaaa_0008_0000),
            Ok(true),
            "hostile upper register bits must be ignored"
        );
        assert_eq!(decode_dup3_flags(1), Err(Error::Linux(Errno::EINVAL)));
    }

    #[test]
    fn pipe2_flags_are_low32_and_only_nonblock_or_cloexec() {
        assert_eq!(decode_pipe2_flags(0), Ok((false, 0)));
        assert_eq!(
            decode_pipe2_flags(O_NONBLOCK as u64),
            Ok((false, O_NONBLOCK as u64))
        );
        assert_eq!(
            decode_pipe2_flags(0xffff_ffff_0008_0800),
            Ok((true, O_NONBLOCK as u64)),
            "hostile upper register bits must be ignored"
        );
        assert_eq!(decode_pipe2_flags(1), Err(Error::Linux(Errno::EINVAL)));
    }

    #[test]
    fn exact_dup3_target_rejects_negative_and_limit() {
        assert_eq!(validate_exact_target(-1), Err(Error::Linux(Errno::EBADF)));
        assert_eq!(validate_exact_target(0), Ok(()));
        assert_eq!(
            validate_exact_target(super::super::step29_runtime::STEP29_RUNTIME_FDS as i32),
            Err(Error::Linux(Errno::EBADF))
        );
    }

    #[test]
    fn lseek_whence_is_low32_and_exact() {
        assert_eq!(decode_whence(0), Ok(SeekWhence::Set));
        assert_eq!(
            decode_whence(0xffff_ffff_0000_0001),
            Ok(SeekWhence::Current)
        );
        assert_eq!(decode_whence(2), Ok(SeekWhence::End));
        assert_eq!(decode_whence(3), Err(Error::Linux(Errno::EINVAL)));
    }

    #[test]
    fn pread_offset_is_full_signed_off_t_and_rejects_negative() {
        assert_eq!(decode_pread_offset(0), Ok(0));
        assert_eq!(decode_pread_offset(i64::MAX as u64), Ok(i64::MAX));
        assert_eq!(
            decode_pread_offset((-1_i64) as u64),
            Err(Error::Linux(Errno::EINVAL))
        );
    }

    #[test]
    fn pread_count_uses_existing_usercopy_bound() {
        assert_eq!(bounded_usercopy_len(0), 0);
        assert_eq!(
            bounded_usercopy_len(MAX_USERCOPY_BYTES as u64),
            MAX_USERCOPY_BYTES
        );
        assert_eq!(bounded_usercopy_len(u64::MAX), MAX_USERCOPY_BYTES);
    }

    #[test]
    fn positional_read_fault_progress_matches_linux_read_rule() {
        assert_eq!(linux_read_result(0, true), Err(Error::Linux(Errno::EFAULT)));
        assert_eq!(linux_read_result(5, true), Ok(5));
        assert_eq!(linux_read_result(8, false), Ok(8));
    }
}
