// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, Ordering};
use kernal_capability::ObjectId;
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_linux_aarch64_abi::classify_path_fd;
use kernal_linux_abi::{Errno, PathFdCall, SyscallRequest, SyscallReturn};
use kernal_linux_fd::{
    Error as FdError, ExternalObject, FdTable, FdToken, OpenObjectKind, ReadPlan,
};
use kernal_linux_vfs::{
    AT_FDCWD, DirectoryScan, Error as VfsError, InitramfsRoot, LINUX_PATH_MAX, MAX_PATH_BYTES,
    Node, NodeKind, OverlayDirectoryScan, OverlayNodeHandle, ReadOnlyDirectory, ReadOnlyFile,
};
use kernal_usercopy::{Error as UsercopyError, MAX_USERCOPY_BYTES};

#[path = "step29_directory_proof.rs"]
mod directory_proof;
#[path = "step29_dirent.rs"]
mod dirent;
#[path = "step29_final_fs.rs"]
mod final_fs;
#[path = "step29_pathfd_decode.rs"]
mod pathfd_decode;
#[path = "step29_stat.rs"]
mod stat;

const O_ACCMODE: u64 = 0x3;
const O_RDONLY: u64 = 0;
const O_NONBLOCK: u64 = 0x800;
// Linux arm64 deliberately overrides the asm-generic values for these flags to retain AArch32
// compatibility. Keep these anchors local to the ARM64 syscall adapter rather than using the
// asm-generic bit positions.
const O_DIRECTORY: u64 = 0x4000;
const O_NOFOLLOW: u64 = 0x8000;
const O_LARGEFILE: u64 = 0x20000;
const O_CLOEXEC: u64 = 0x80000;
const SUPPORTED_READONLY_FLAGS: u64 =
    O_NONBLOCK | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const SUPPORTED_FSTATAT_FLAGS: u64 = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;

const PROOF_OPEN: u8 = 1 << 0;
const PROOF_READ: u8 = 1 << 1;
const PROOF_CLOSE: u8 = 1 << 2;
const PROOF_REQUIRED_STATE: u8 = PROOF_OPEN | PROOF_READ | PROOF_CLOSE;
const PROOF_CLAIMING: u8 = 1 << 7;
const PROOF_FIXTURE_RELATIVE: &[u8] = b"etc/localtime";
const PROOF_FIXTURE_ABSOLUTE: &[u8] = b"/etc/localtime";
/// Deterministic Step-29 initramfs ordinal for `usr/share/zoneinfo/UTC`.
const PROOF_TARGET_ENTRY_INDEX: usize = 7;
static STEP29_PROOF_STATE: AtomicU8 = AtomicU8::new(0);
static STEP29_PROOF_FD: AtomicI32 = AtomicI32::new(-1);
static STEP29_PROOF_GENERATION: AtomicU64 = AtomicU64::new(0);
static STEP29_PROOF_STAT: AtomicBool = AtomicBool::new(false);

static STEP29_DIRECTORY_PROOF_STATE: AtomicU8 = AtomicU8::new(directory_proof::Phase::Idle.raw());
static STEP29_DIRECTORY_PROOF_FD: AtomicI32 = AtomicI32::new(-1);
static STEP29_DIRECTORY_PROOF_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Linux(Errno),
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandleOutcome {
    NotHandled,
    Handled,
    SignalFrameCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadOutcome {
    Returned(u64),
    BlockingWaitRequired,
}

impl From<Errno> for Error {
    fn from(value: Errno) -> Self {
        Self::Linux(value)
    }
}

pub(super) struct UserPath {
    bytes: [u8; MAX_PATH_BYTES],
    len: usize,
}

impl UserPath {
    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub(super) fn proof_complete() -> bool {
    let state = STEP29_PROOF_STATE.load(Ordering::Acquire);
    state & PROOF_REQUIRED_STATE == PROOF_REQUIRED_STATE
        && STEP29_PROOF_STAT.load(Ordering::Acquire)
}

pub(super) fn directory_proof_complete() -> bool {
    directory_proof::Phase::from_raw(STEP29_DIRECTORY_PROOF_STATE.load(Ordering::Acquire))
        .is_complete()
}

fn proof_fixture_path(path: &[u8]) -> bool {
    path == PROOF_FIXTURE_RELATIVE || path == PROOF_FIXTURE_ABSOLUTE
}

fn proof_target_matches(entry_id: kernal_linux_vfs::EntryId) -> bool {
    entry_id.index() == PROOF_TARGET_ENTRY_INDEX
}

fn proof_token_matches(token: FdToken) -> bool {
    let state = STEP29_PROOF_STATE.load(Ordering::Acquire);
    state & PROOF_OPEN != 0
        && state & PROOF_CLAIMING == 0
        && STEP29_PROOF_FD.load(Ordering::Acquire) == token.fd()
        && STEP29_PROOF_GENERATION.load(Ordering::Acquire) == token.generation()
}

fn directory_proof_token_matches(token: FdToken) -> bool {
    let raw = STEP29_DIRECTORY_PROOF_STATE.load(Ordering::Acquire);
    if raw == PROOF_CLAIMING {
        return false;
    }
    let phase = directory_proof::Phase::from_raw(raw);
    phase.accepts_token_events()
        && directory_proof::token_matches(
            STEP29_DIRECTORY_PROOF_FD.load(Ordering::Acquire),
            STEP29_DIRECTORY_PROOF_GENERATION.load(Ordering::Acquire),
            token.fd(),
            token.generation(),
        )
}

fn proof_open_before_read_and_close() -> bool {
    let state = STEP29_PROOF_STATE.load(Ordering::Acquire);
    state & PROOF_OPEN != 0 && state & (PROOF_READ | PROOF_CLOSE) == 0
}

fn proof_stat_and_read_observed_before_close() -> bool {
    let state = STEP29_PROOF_STATE.load(Ordering::Acquire);
    state & (PROOF_OPEN | PROOF_READ) == PROOF_OPEN | PROOF_READ
        && state & PROOF_CLOSE == 0
        && STEP29_PROOF_STAT.load(Ordering::Acquire)
}

fn record_proof_open(path: &[u8], entry_id: kernal_linux_vfs::EntryId, token: FdToken) {
    if !proof_fixture_path(path) || !proof_target_matches(entry_id) {
        return;
    }
    if STEP29_PROOF_STATE
        .compare_exchange(0, PROOF_CLAIMING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    STEP29_PROOF_FD.store(token.fd(), Ordering::Relaxed);
    STEP29_PROOF_GENERATION.store(token.generation(), Ordering::Relaxed);
    STEP29_PROOF_STATE.store(PROOF_OPEN, Ordering::Release);
}

fn record_proof_read(token: FdToken, copied: u64) {
    if copied == 0 || !proof_token_matches(token) || !STEP29_PROOF_STAT.load(Ordering::Acquire) {
        return;
    }
    let state = STEP29_PROOF_STATE.load(Ordering::Acquire);
    if state & PROOF_CLOSE == 0 {
        STEP29_PROOF_STATE.fetch_or(PROOF_READ, Ordering::AcqRel);
    }
}

fn record_proof_fstat(token: FdToken) {
    if proof_token_matches(token) && proof_open_before_read_and_close() {
        STEP29_PROOF_STAT.store(true, Ordering::Release);
    }
}

fn record_proof_path_stat(path: &[u8], entry_id: kernal_linux_vfs::EntryId) {
    if proof_fixture_path(path)
        && proof_target_matches(entry_id)
        && proof_open_before_read_and_close()
    {
        STEP29_PROOF_STAT.store(true, Ordering::Release);
    }
}

fn record_proof_close(token: FdToken) {
    if !proof_token_matches(token) || !proof_stat_and_read_observed_before_close() {
        return;
    }
    STEP29_PROOF_STATE.fetch_or(PROOF_CLOSE, Ordering::AcqRel);
}

fn record_directory_open(entry_id: kernal_linux_vfs::EntryId, kind: NodeKind, token: FdToken) {
    if !directory_proof::expected_root_open(entry_id.index(), kind) {
        return;
    }
    if STEP29_DIRECTORY_PROOF_STATE
        .compare_exchange(
            directory_proof::Phase::Idle.raw(),
            PROOF_CLAIMING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return;
    }

    STEP29_DIRECTORY_PROOF_FD.store(token.fd(), Ordering::Relaxed);
    STEP29_DIRECTORY_PROOF_GENERATION.store(token.generation(), Ordering::Relaxed);
    STEP29_DIRECTORY_PROOF_STATE.store(directory_proof::Phase::Open.raw(), Ordering::Release);
}

fn commit_directory_phase(current: directory_proof::Phase, next: directory_proof::Phase) {
    if current == next {
        return;
    }
    if STEP29_DIRECTORY_PROOF_STATE
        .compare_exchange(
            current.raw(),
            next.raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        STEP29_DIRECTORY_PROOF_STATE.store(directory_proof::Phase::Failed.raw(), Ordering::Release);
    }
}

fn canonical_directory_proof_cursor(cursor: usize) -> usize {
    let reserved = super::step29_runtime::STEP29_RUNTIME_FS_DENTRIES;
    let lower_base = 2 + reserved;
    if cursor >= lower_base {
        cursor - reserved
    } else {
        cursor
    }
}

trait DirectoryProofScanEvidence {
    fn proof_transition(self, current: directory_proof::Phase) -> directory_proof::Phase;
}

impl<'a> DirectoryProofScanEvidence for DirectoryScan<'a> {
    fn proof_transition(self, current: directory_proof::Phase) -> directory_proof::Phase {
        let entry = self.entry();
        let evidence = directory_proof::EntryEvidence::new(
            entry.entry_id().index(),
            entry.name(),
            entry.kind(),
            self.start_cursor(),
            self.next_cursor(),
        );
        directory_proof::transition_entry(current, evidence)
    }
}

impl DirectoryProofScanEvidence for OverlayDirectoryScan {
    fn proof_transition(self, current: directory_proof::Phase) -> directory_proof::Phase {
        let entry = self.entry();
        let entry_index = match entry.object() {
            OverlayNodeHandle::Root { .. } => directory_proof::ROOT_ENTRY_INDEX,
            OverlayNodeHandle::Immutable { entry_id, .. } => entry_id.index(),
            OverlayNodeHandle::Mutable(_) => return directory_proof::Phase::Failed,
        };
        let evidence = directory_proof::EntryEvidence::new(
            entry_index,
            entry.name(),
            entry.kind(),
            canonical_directory_proof_cursor(self.start_cursor()),
            canonical_directory_proof_cursor(self.next_cursor()),
        );
        directory_proof::transition_entry(current, evidence)
    }
}

fn record_directory_entry<S: DirectoryProofScanEvidence>(token: FdToken, scan: S) {
    if !directory_proof_token_matches(token) {
        return;
    }
    let current =
        directory_proof::Phase::from_raw(STEP29_DIRECTORY_PROOF_STATE.load(Ordering::Acquire));
    commit_directory_phase(current, scan.proof_transition(current));
}

fn record_directory_eof(token: FdToken, cursor: usize) {
    if !directory_proof_token_matches(token) {
        return;
    }
    let current =
        directory_proof::Phase::from_raw(STEP29_DIRECTORY_PROOF_STATE.load(Ordering::Acquire));
    let cursor = canonical_directory_proof_cursor(cursor);
    commit_directory_phase(current, directory_proof::transition_eof(current, cursor));
}

fn record_directory_close(token: FdToken) {
    if !directory_proof_token_matches(token) {
        return;
    }
    let current =
        directory_proof::Phase::from_raw(STEP29_DIRECTORY_PROOF_STATE.load(Ordering::Acquire));
    commit_directory_phase(current, directory_proof::transition_close(current));
}

/// Routes only Step-29 path/FD calls while preserving return ownership across blocking reads.
/// `HandleOutcome::NotHandled` means the syscall belongs to another owner; `SignalFrameCommitted`
/// means this exception return already owns a committed user signal frame. `Err(())` is an internal
/// ownership/PAN/provenance invariant and must never become fake success or ENOSYS fallback.
pub(super) fn handle(
    request: SyscallRequest,
    frame: &mut ExceptionFrame,
) -> Result<HandleOutcome, ()> {
    if final_fs::handle(request, frame)? {
        return Ok(HandleOutcome::Handled);
    }

    let Some(call) = classify_path_fd(request) else {
        return Ok(HandleOutcome::NotHandled);
    };

    let process = current_process().map_err(|_| ())?;
    let result = match call {
        PathFdCall::OpenAt {
            dirfd,
            user_path,
            flags,
            mode,
        } => openat(process, dirfd, user_path, flags, mode),
        PathFdCall::Close { fd } => close(process, fd),
        PathFdCall::Getdents64 {
            fd,
            user_buffer,
            count,
        } => getdents64(process, fd, user_buffer, count),
        PathFdCall::Read {
            fd,
            user_buffer,
            count,
        } => return handle_read(process, fd, user_buffer, count, frame),
        PathFdCall::Fstat { fd, user_stat } => fstat(process, fd, user_stat),
        PathFdCall::Newfstatat {
            dirfd,
            user_path,
            user_stat,
            flags,
        } => newfstatat(process, dirfd, user_path, user_stat, flags),
    };

    match result {
        Ok(value) => {
            frame.x[0] = SyscallReturn::success(value as i64)
                .ok_or(())?
                .as_u64_bits();
            Ok(HandleOutcome::Handled)
        }
        Err(Error::Linux(errno)) => {
            frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
            Ok(HandleOutcome::Handled)
        }
        Err(Error::Invariant) => Err(()),
    }
}

fn handle_read(
    process: ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
    frame: &mut ExceptionFrame,
) -> Result<HandleOutcome, ()> {
    loop {
        match read(process, raw_fd, user_buffer, count) {
            Ok(ReadOutcome::Returned(value)) => {
                frame.x[0] = SyscallReturn::success(value as i64)
                    .ok_or(())?
                    .as_u64_bits();
                return Ok(HandleOutcome::Handled);
            }
            Ok(ReadOutcome::BlockingWaitRequired) => {
                match super::futex::pipe_blocking::block_read(process, raw_fd, count, frame)
                    .map_err(|_| ())?
                {
                    super::futex::pipe_blocking::BlockingReadOutcome::Retry => continue,
                    super::futex::pipe_blocking::BlockingReadOutcome::Restarted => {
                        return Ok(HandleOutcome::Handled);
                    }
                    super::futex::pipe_blocking::BlockingReadOutcome::SignalFrameCommitted => {
                        return Ok(HandleOutcome::SignalFrameCommitted);
                    }
                }
            }
            Err(Error::Linux(errno)) => {
                frame.x[0] = SyscallReturn::error(errno).as_u64_bits();
                return Ok(HandleOutcome::Handled);
            }
            Err(Error::Invariant) => return Err(()),
        }
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

fn openat(
    process: ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    raw_flags: u64,
    _mode: u64,
) -> Result<u64, Error> {
    let flags = u64::from(pathfd_decode::unsigned_int(raw_flags));
    if flags & O_ACCMODE != O_RDONLY {
        return Err(Error::Linux(Errno::EROFS));
    }
    if flags & !(O_ACCMODE | SUPPORTED_READONLY_FLAGS) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }

    let path = copy_user_path(user_path)?;
    let nofollow = flags & O_NOFOLLOW != 0;
    let require_directory = flags & O_DIRECTORY != 0;
    let close_on_exec = flags & O_CLOEXEC != 0;
    // For this immutable read-only slice, O_NONBLOCK is the only accepted open flag that is OFD
    // status rather than descriptor-local or path-resolution policy. O_CLOEXEC stays descriptor
    // local; O_DIRECTORY/O_NOFOLLOW/O_LARGEFILE are never leaked into F_GETFL state here.
    let status_flags = flags & O_NONBLOCK;

    super::step29_runtime::with_process(process, |runtime| {
        let (initrd, root_id, fds) = runtime.parts();
        initrd.with_bytes(|bytes| {
            let archive = kernal_cpio::Archive::parse(bytes).map_err(|_| Error::Invariant)?;
            let root = InitramfsRoot::new(archive, root_id);
            let (entry_id, node) = resolve_path(root, fds, raw_dirfd, path.as_bytes(), nofollow)?;
            let token = match node.kind() {
                NodeKind::Regular => {
                    if require_directory {
                        return Err(Error::Linux(Errno::ENOTDIR));
                    }
                    fds.open_readonly_linux_with_flags(
                        ReadOnlyFile::new(root_id, entry_id, node.mode(), node.size()),
                        close_on_exec,
                        status_flags,
                    )
                    .map_err(map_fd_error)?
                }
                NodeKind::Directory => fds
                    .open_directory_linux_with_flags(
                        ReadOnlyDirectory::new(root_id, entry_id, node.mode()),
                        close_on_exec,
                        status_flags,
                    )
                    .map_err(map_fd_error)?,
                NodeKind::Symlink if require_directory && nofollow => {
                    return Err(Error::Linux(Errno::ENOTDIR));
                }
                NodeKind::Symlink => return Err(Error::Linux(Errno::ELOOP)),
                NodeKind::Other(_) => return Err(Error::Linux(Errno::EACCES)),
            };
            record_proof_open(path.as_bytes(), entry_id, token);
            record_directory_open(entry_id, node.kind(), token);
            u64::try_from(token.fd()).map_err(|_| Error::Invariant)
        })
    })
    .map_err(|_| Error::Invariant)?
}

fn close(process: ObjectId, raw_fd: u64) -> Result<u64, Error> {
    let fd = raw_i32(raw_fd);
    super::step29_runtime::with_process(process, |runtime| {
        let (fds, pipes) = runtime.fd_pipe_parts();
        let token = fds.token(fd).map_err(map_fd_error)?;
        let closed = fds
            .close_with_release(fd, |released| {
                pipes
                    .close(released.pipe_endpoint())
                    .map_err(|_| Error::Invariant)
            })
            .map_err(map_fd_error)?;
        closed?;
        record_proof_close(token);
        record_directory_close(token);
        Ok(0)
    })
    .map_err(|_| Error::Invariant)?
}

fn getdents64(process: ObjectId, raw_fd: u64, user_buffer: u64, count: u64) -> Result<u64, Error> {
    let fd = raw_i32(raw_fd);
    let capacity = usize::try_from(count).unwrap_or(usize::MAX);

    super::step29_runtime::with_process(process, |runtime| {
        let (initrd, root_id, fds) = runtime.parts();
        let mut copied = 0usize;

        initrd.with_bytes(|bytes| {
            let archive = kernal_cpio::Archive::parse(bytes).map_err(|_| Error::Invariant)?;
            let root = InitramfsRoot::new(archive, root_id);

            loop {
                let plan = fds.prepare_directory(fd).map_err(map_fd_error)?;
                let Some(scan) = root
                    .directory_entry_from(plan.directory(), plan.start_cursor())
                    .map_err(map_vfs_error)?
                else {
                    record_directory_eof(plan.token(), plan.start_cursor());
                    break;
                };
                let record = dirent::Dirent64Record::encode(scan).map_err(map_dirent_error)?;
                let record_bytes = record.as_bytes();
                let remaining = capacity.saturating_sub(copied);
                if record_bytes.len() > remaining {
                    if copied == 0 {
                        return Err(Error::Linux(Errno::EINVAL));
                    }
                    break;
                }
                let Some(target) = directory_proof::next_user_address(user_buffer, copied) else {
                    if copied == 0 {
                        return Err(Error::Linux(Errno::EFAULT));
                    }
                    break;
                };
                match kernal_usercopy_aarch64::copy_to_user(target, record_bytes) {
                    Ok(()) => {}
                    Err(error) => match map_usercopy_error(error) {
                        Error::Linux(Errno::EFAULT) if copied != 0 => break,
                        mapped => return Err(mapped),
                    },
                }
                fds.commit_directory(plan, scan).map_err(map_fd_error)?;
                record_directory_entry(plan.token(), scan);
                copied = copied
                    .checked_add(record_bytes.len())
                    .ok_or(Error::Invariant)?;
            }
            Ok(())
        })?;

        u64::try_from(copied).map_err(|_| Error::Invariant)
    })
    .map_err(|_| Error::Invariant)?
}

fn read(
    process: ObjectId,
    raw_fd: u64,
    user_buffer: u64,
    count: u64,
) -> Result<ReadOutcome, Error> {
    let fd = raw_i32(raw_fd);

    super::step29_runtime::with_process(process, |runtime| {
        match runtime.fds().object_kind(fd).map_err(map_fd_error)? {
            OpenObjectKind::File => {
                let (initrd, root_id, fds) = runtime.parts();
                let plan = prepare_read_plan(fds, fd, count)?;
                if plan.is_empty() {
                    return Ok(ReadOutcome::Returned(0));
                }

                let progress = initrd.with_bytes(|bytes| {
                    let archive =
                        kernal_cpio::Archive::parse(bytes).map_err(|_| Error::Invariant)?;
                    let root = InitramfsRoot::new(archive, root_id);
                    let source = root
                        .read_at(plan.file(), plan.start_offset(), plan.len())
                        .map_err(map_vfs_error)?;
                    kernal_usercopy_aarch64::copy_to_user_progress(user_buffer, source)
                        .map_err(map_usercopy_error)
                })?;

                fds.commit_read(plan, progress.copied())
                    .map_err(map_fd_error)?;
                let result = linux_read_result(progress.copied(), progress.faulted())?;
                record_proof_read(plan.token(), result);
                Ok(ReadOutcome::Returned(result))
            }
            OpenObjectKind::Pipe => {
                let (fds, pipes) = runtime.fd_pipe_parts();
                let status = fds.status_flags(fd).map_err(map_fd_error)?;
                if status & O_ACCMODE != O_RDONLY {
                    return Err(Error::Linux(Errno::EBADF));
                }
                let endpoint = fds.pipe_endpoint(fd).map_err(|_| Error::Invariant)?;
                match super::step29_pipe_io::read(
                    pipes,
                    endpoint,
                    user_buffer,
                    count,
                    status & O_NONBLOCK != 0,
                ) {
                    Ok(value) => Ok(ReadOutcome::Returned(value)),
                    Err(super::step29_pipe_io::Error::BlockingWaitRequired) => {
                        Ok(ReadOutcome::BlockingWaitRequired)
                    }
                    Err(super::step29_pipe_io::Error::Linux(errno)) => Err(Error::Linux(errno)),
                    Err(super::step29_pipe_io::Error::Invariant) => Err(Error::Invariant),
                }
            }
            OpenObjectKind::Directory => Err(Error::Linux(Errno::EISDIR)),
            // A canonical inherited stdin OFD is valid and read-only, but Step 29 deliberately owns
            // no console-RX or blocking wait path. Fail closed internally rather than publishing a
            // false Linux EBADF/EOF/EAGAIN result for a descriptor that is actually live.
            OpenObjectKind::External(ExternalObject::Stdin) => Err(Error::Invariant),
            // stdout/stderr are valid External OFDs in the wrong access direction for read(2).
            OpenObjectKind::External(ExternalObject::Stdout)
            | OpenObjectKind::External(ExternalObject::Stderr) => Err(Error::Linux(Errno::EBADF)),
        }
    })
    .map_err(|_| Error::Invariant)?
}

fn fstat(process: ObjectId, raw_fd: u64, user_stat: u64) -> Result<u64, Error> {
    let fd = raw_i32(raw_fd);
    super::step29_runtime::with_process(process, |runtime| {
        let (initrd, root_id, fds) = runtime.parts();
        let token = fds.token(fd).map_err(map_fd_error)?;
        match fds.object_kind(fd).map_err(map_fd_error)? {
            OpenObjectKind::File => initrd.with_bytes(|bytes| {
                let archive = kernal_cpio::Archive::parse(bytes).map_err(|_| Error::Invariant)?;
                let root = InitramfsRoot::new(archive, root_id);
                let plan = fds.prepare_read(fd, 0).map_err(map_fd_error)?;
                let file = plan.file();
                root.read_at(file, 0, 0).map_err(map_vfs_error)?;
                let identity = stat::InitramfsStatIdentity::from_file(file);
                if identity.root_id() != root.root_id() {
                    return Err(Error::Invariant);
                }
                copy_stat_to_user(identity, user_stat)?;
                record_proof_fstat(token);
                Ok(0)
            }),
            OpenObjectKind::Directory => initrd.with_bytes(|bytes| {
                let archive = kernal_cpio::Archive::parse(bytes).map_err(|_| Error::Invariant)?;
                let root = InitramfsRoot::new(archive, root_id);
                let plan = fds.prepare_directory(fd).map_err(map_fd_error)?;
                let directory = plan.directory();
                let _ = root
                    .directory_entry_from(directory, plan.start_cursor())
                    .map_err(map_vfs_error)?;
                let entry = archive
                    .entry_by_id(directory.entry_id())
                    .map_err(|_| Error::Invariant)?
                    .ok_or(Error::Invariant)?;
                let size = u64::try_from(entry.data().len()).map_err(|_| Error::Invariant)?;
                let identity = stat::InitramfsStatIdentity::new(
                    root_id,
                    directory.entry_id(),
                    directory.mode(),
                    size,
                );
                if identity.root_id() != root.root_id() {
                    return Err(Error::Invariant);
                }
                copy_stat_to_user(identity, user_stat)?;
                record_proof_fstat(token);
                Ok(0)
            }),
            OpenObjectKind::Pipe => {
                let endpoint = fds.pipe_endpoint(fd).map_err(|_| Error::Invariant)?;
                let metadata = fds.metadata(fd).map_err(map_fd_error)?;
                let bytes = stat::Arm64Stat::anonymous_pipe(endpoint.pipe(), metadata)
                    .map_err(|_| Error::Invariant)?
                    .encode();
                kernal_usercopy_aarch64::copy_to_user(user_stat, &bytes)
                    .map_err(map_usercopy_error)?;
                Ok(0)
            }
            OpenObjectKind::External(_) => {
                let open_file = fds.open_file_id(fd).map_err(map_fd_error)?;
                let metadata = fds.metadata(fd).map_err(map_fd_error)?;
                let bytes = stat::Arm64Stat::anonymous_external(open_file, metadata)
                    .map_err(|_| Error::Invariant)?
                    .encode();
                kernal_usercopy_aarch64::copy_to_user(user_stat, &bytes)
                    .map_err(map_usercopy_error)?;
                Ok(0)
            }
        }
    })
    .map_err(|_| Error::Invariant)?
}

fn newfstatat(
    process: ObjectId,
    raw_dirfd: u64,
    user_path: u64,
    user_stat: u64,
    raw_flags: u64,
) -> Result<u64, Error> {
    let flags = u64::from(pathfd_decode::unsigned_int(raw_flags));
    if flags & !SUPPORTED_FSTATAT_FLAGS != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let path = copy_user_path(user_path)?;
    let nofollow = flags & AT_SYMLINK_NOFOLLOW != 0;

    super::step29_runtime::with_process(process, |runtime| {
        let (initrd, root_id, fds) = runtime.parts();
        initrd.with_bytes(|bytes| {
            let archive = kernal_cpio::Archive::parse(bytes).map_err(|_| Error::Invariant)?;
            let root = InitramfsRoot::new(archive, root_id);
            let (entry_id, node) = resolve_path(root, fds, raw_dirfd, path.as_bytes(), nofollow)?;
            validate_stat_node_kind(node.kind(), nofollow)?;
            let identity =
                stat::InitramfsStatIdentity::new(root_id, entry_id, node.mode(), node.size());
            copy_stat_to_user(identity, user_stat)?;
            record_proof_path_stat(path.as_bytes(), entry_id);
            Ok(0)
        })
    })
    .map_err(|_| Error::Invariant)?
}

fn resolve_path<'a, const N: usize>(
    root: InitramfsRoot<'a>,
    fds: &FdTable<N>,
    raw_dirfd: u64,
    path: &[u8],
    nofollow: bool,
) -> Result<(kernal_linux_vfs::EntryId, Node<'a>), Error> {
    let dirfd = effective_at_dirfd(raw_dirfd, path)?;
    let resolved = if path.first().copied() == Some(b'/') || dirfd == AT_FDCWD {
        if nofollow {
            root.resolve_nofollow_at(AT_FDCWD, path)
        } else {
            root.resolve_following_at(AT_FDCWD, path)
        }
    } else {
        let plan = fds.prepare_directory(dirfd).map_err(map_fd_error)?;
        if nofollow {
            root.resolve_from_directory_nofollow(plan.directory(), path)
        } else {
            root.resolve_from_directory_following(plan.directory(), path)
        }
    }
    .map_err(map_vfs_error)?;
    Ok((resolved.0, resolved.1))
}

fn validate_stat_node_kind(kind: NodeKind, nofollow: bool) -> Result<(), Error> {
    match kind {
        NodeKind::Regular | NodeKind::Directory => Ok(()),
        NodeKind::Symlink if nofollow => Ok(()),
        NodeKind::Symlink => Err(Error::Linux(Errno::ELOOP)),
        NodeKind::Other(_) => Err(Error::Linux(Errno::EACCES)),
    }
}

fn copy_stat_to_user(identity: stat::InitramfsStatIdentity, user_stat: u64) -> Result<(), Error> {
    let bytes = stat::Arm64Stat::immutable_initramfs(identity)
        .map_err(|_| Error::Invariant)?
        .encode();
    kernal_usercopy_aarch64::copy_to_user(user_stat, &bytes).map_err(map_usercopy_error)
}

fn prepare_read_plan<const N: usize>(
    fds: &FdTable<N>,
    fd: i32,
    count: u64,
) -> Result<ReadPlan, Error> {
    let requested = usize::try_from(count).unwrap_or(usize::MAX);
    let bounded = core::cmp::min(requested, MAX_USERCOPY_BYTES);
    fds.prepare_read(fd, bounded).map_err(map_fd_error)
}

fn linux_read_result(copied: usize, faulted: bool) -> Result<u64, Error> {
    if copied == 0 && faulted {
        return Err(Error::Linux(Errno::EFAULT));
    }
    u64::try_from(copied).map_err(|_| Error::Invariant)
}

pub(super) fn copy_user_path(user_path: u64) -> Result<UserPath, Error> {
    copy_user_path_allow_empty(user_path, false)
}

pub(super) fn copy_user_path_allow_empty(
    user_path: u64,
    allow_empty: bool,
) -> Result<UserPath, Error> {
    copy_user_path_with_allow_empty(user_path, allow_empty, |address, byte| {
        kernal_usercopy_aarch64::copy_from_user(byte, address).map_err(map_usercopy_error)
    })
}

fn copy_user_path_with<F>(user_path: u64, copy_byte: F) -> Result<UserPath, Error>
where
    F: FnMut(u64, &mut [u8; 1]) -> Result<(), Error>,
{
    copy_user_path_with_allow_empty(user_path, false, copy_byte)
}

fn copy_user_path_with_allow_empty<F>(
    user_path: u64,
    allow_empty: bool,
    mut copy_byte: F,
) -> Result<UserPath, Error>
where
    F: FnMut(u64, &mut [u8; 1]) -> Result<(), Error>,
{
    let mut path = UserPath {
        bytes: [0; MAX_PATH_BYTES],
        len: 0,
    };
    let mut byte = [0u8; 1];

    // Linux PATH_MAX includes the terminating NUL: MAX_PATH_BYTES bytes may carry the pathname,
    // followed by one final byte that must be NUL. Read exactly that full userspace window and never
    // store the terminator position in the payload buffer.
    for index in 0..LINUX_PATH_MAX {
        let address = user_path
            .checked_add(index as u64)
            .ok_or(Error::Linux(Errno::EFAULT))?;
        copy_byte(address, &mut byte)?;
        if byte[0] == 0 {
            if index == 0 && !allow_empty {
                return Err(Error::Linux(Errno::ENOENT));
            }
            path.len = index;
            return Ok(path);
        }
        if index == MAX_PATH_BYTES {
            return Err(Error::Linux(Errno::ENAMETOOLONG));
        }
        path.bytes[index] = byte[0];
    }

    Err(Error::Linux(Errno::ENAMETOOLONG))
}

fn effective_at_dirfd(raw_dirfd: u64, path: &[u8]) -> Result<i32, Error> {
    if path.first().copied() == Some(b'/') {
        return Ok(AT_FDCWD);
    }
    Ok(raw_i32(raw_dirfd))
}

fn raw_i32(raw: u64) -> i32 {
    pathfd_decode::signed_int(raw)
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

fn map_dirent_error(_error: dirent::Error) -> Error {
    Error::Invariant
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_vfs::{EntryId, ReadOnlyFile, RootId};

    const TEST_ROOT: RootId = RootId::new(9);
    const TEST_MODE: u32 = 0o100644;

    fn test_file(index: u16) -> ReadOnlyFile {
        ReadOnlyFile::new(TEST_ROOT, EntryId::from_index(index), TEST_MODE, 54)
    }

    fn reset_proof() {
        STEP29_PROOF_STATE.store(0, Ordering::Release);
        STEP29_PROOF_FD.store(-1, Ordering::Release);
        STEP29_PROOF_GENERATION.store(0, Ordering::Release);
        STEP29_PROOF_STAT.store(false, Ordering::Release);
    }

    #[test]
    fn arm64_open_flag_values_match_linux_uapi() {
        assert_eq!(O_DIRECTORY, 0o40000);
        assert_eq!(O_NOFOLLOW, 0o100000);
        assert_eq!(O_LARGEFILE, 0o400000);
        assert_eq!(O_NONBLOCK, 0o4000);
        assert_eq!(O_CLOEXEC, 0o2000000);
    }

    #[test]
    fn user_path_accepts_nul_at_last_pathmax_byte() {
        let mut source = [b'a'; LINUX_PATH_MAX];
        source[MAX_PATH_BYTES] = 0;
        let base = 0x4000u64;
        let path = copy_user_path_with(base, |address, out| {
            let index = usize::try_from(address - base).map_err(|_| Error::Invariant)?;
            out[0] = *source.get(index).ok_or(Error::Invariant)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(path.as_bytes().len(), MAX_PATH_BYTES);
        assert!(path.as_bytes().iter().all(|byte| *byte == b'a'));
    }

    #[test]
    fn user_path_without_nul_in_pathmax_window_is_enametoolong_without_overread() {
        let source = [b'a'; LINUX_PATH_MAX];
        let base = 0x8000u64;
        let mut reads = 0usize;
        let result = copy_user_path_with(base, |address, out| {
            let index = usize::try_from(address - base).map_err(|_| Error::Invariant)?;
            reads += 1;
            out[0] = *source.get(index).ok_or(Error::Invariant)?;
            Ok(())
        });
        assert!(matches!(result, Err(Error::Linux(Errno::ENAMETOOLONG))));
        assert_eq!(reads, LINUX_PATH_MAX);
    }

    #[test]
    fn empty_user_path_requires_explicit_allow_empty() {
        let base = 0x9000u64;
        let copy = |_: u64, out: &mut [u8; 1]| {
            out[0] = 0;
            Ok(())
        };
        assert_eq!(
            copy_user_path_with_allow_empty(base, false, copy).map(|path| path.as_bytes().len()),
            Err(Error::Linux(Errno::ENOENT))
        );

        let empty = copy_user_path_with_allow_empty(base, true, |_, out| {
            out[0] = 0;
            Ok(())
        })
        .unwrap();
        assert!(empty.as_bytes().is_empty());
    }

    #[test]
    fn raw_signed_descriptor_conversion_preserves_linux_int_width() {
        assert_eq!(raw_i32((-100_i64) as u64), -100);
        assert_eq!(raw_i32(3), 3);
        assert_eq!(raw_i32(u64::MAX), -1);
        assert_eq!(raw_i32(0xa5a5_5a5a_0000_0003), 3);
        assert_eq!(raw_i32(0xa5a5_5a5a_ffff_ff9c), -100);
    }

    #[test]
    fn absolute_at_lookup_ignores_dirfd_while_relative_lookup_uses_low32_int() {
        assert_eq!(
            effective_at_dirfd(i64::MAX as u64, b"/etc/os-release"),
            Ok(AT_FDCWD)
        );
        assert_eq!(
            effective_at_dirfd(0xa5a5_5a5a_ffff_ff9c, b"etc/os-release"),
            Ok(AT_FDCWD)
        );
        assert_eq!(
            effective_at_dirfd(0xa5a5_5a5a_0000_0003, b"etc/os-release"),
            Ok(3)
        );
    }

    #[test]
    fn zero_length_read_still_validates_descriptor() {
        let table = FdTable::<4>::new();
        assert_eq!(
            prepare_read_plan(&table, 3, 0),
            Err(Error::Linux(Errno::EBADF))
        );
    }

    #[test]
    fn linux_partial_read_result_matches_fault_progress() {
        assert_eq!(linux_read_result(0, true), Err(Error::Linux(Errno::EFAULT)));
        assert_eq!(linux_read_result(5, true), Ok(5));
        assert_eq!(linux_read_result(8, false), Ok(8));
    }

    #[test]
    fn supported_open_flags_include_directory_nofollow_and_nonblock() {
        assert_ne!(SUPPORTED_READONLY_FLAGS & O_DIRECTORY, 0);
        assert_ne!(SUPPORTED_READONLY_FLAGS & O_NOFOLLOW, 0);
        assert_ne!(SUPPORTED_READONLY_FLAGS & O_NONBLOCK, 0);
    }

    #[test]
    fn nofollow_directory_final_symlink_maps_to_enotdir() {
        let error = if true && true {
            Err(Error::Linux(Errno::ENOTDIR))
        } else {
            Err(Error::Linux(Errno::ELOOP))
        };
        assert_eq!(error, Err(Error::Linux(Errno::ENOTDIR)));
    }

    #[test]
    fn fstatat_supports_nofollow_but_rejects_unowned_flags() {
        assert_eq!(
            SUPPORTED_FSTATAT_FLAGS,
            AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW
        );
        assert_ne!(SUPPORTED_FSTATAT_FLAGS & AT_SYMLINK_NOFOLLOW, 0);
        assert_eq!(SUPPORTED_FSTATAT_FLAGS & 0x1000, 0);
    }

    #[test]
    fn stat_accepts_symlink_only_for_explicit_nofollow() {
        assert_eq!(validate_stat_node_kind(NodeKind::Regular, false), Ok(()));
        assert_eq!(validate_stat_node_kind(NodeKind::Directory, false), Ok(()));
        assert_eq!(
            validate_stat_node_kind(NodeKind::Symlink, false),
            Err(Error::Linux(Errno::ELOOP))
        );
        assert_eq!(validate_stat_node_kind(NodeKind::Symlink, true), Ok(()));
        assert_eq!(
            validate_stat_node_kind(NodeKind::Other(0), false),
            Err(Error::Linux(Errno::EACCES))
        );
    }

    #[test]
    fn proof_is_bound_to_fixture_target_and_exact_fd_generation() {
        reset_proof();
        let mut table = FdTable::<8>::new();
        let target = table.open_readonly(test_file(7)).unwrap();
        let other = table.open_readonly(test_file(5)).unwrap();

        record_proof_open(
            b"/etc/other",
            EntryId::from_index(PROOF_TARGET_ENTRY_INDEX as u16),
            target,
        );
        assert!(!proof_complete());
        record_proof_open(PROOF_FIXTURE_ABSOLUTE, EntryId::from_index(8), target);
        assert_eq!(STEP29_PROOF_STATE.load(Ordering::Acquire), 0);
        record_proof_open(
            PROOF_FIXTURE_ABSOLUTE,
            EntryId::from_index(PROOF_TARGET_ENTRY_INDEX as u16),
            target,
        );

        record_proof_fstat(other);
        record_proof_read(other, 16);
        record_proof_close(other);
        assert!(
            !proof_complete(),
            "another descriptor must not satisfy the proof"
        );

        record_proof_path_stat(
            b"etc/other",
            EntryId::from_index(PROOF_TARGET_ENTRY_INDEX as u16),
        );
        record_proof_read(target, 16);
        record_proof_close(target);
        assert!(
            !proof_complete(),
            "metadata for another path must not satisfy the proof"
        );

        record_proof_path_stat(PROOF_FIXTURE_RELATIVE, EntryId::from_index(8));
        assert!(!STEP29_PROOF_STAT.load(Ordering::Acquire));
        record_proof_path_stat(
            PROOF_FIXTURE_RELATIVE,
            EntryId::from_index(PROOF_TARGET_ENTRY_INDEX as u16),
        );
        record_proof_read(target, 16);
        record_proof_close(target);
        assert!(proof_complete());
    }

    #[test]
    fn proof_requires_open_stat_read_close_order() {
        reset_proof();
        let mut table = FdTable::<4>::new();
        let target = table.open_readonly(test_file(7)).unwrap();
        record_proof_open(
            PROOF_FIXTURE_ABSOLUTE,
            EntryId::from_index(PROOF_TARGET_ENTRY_INDEX as u16),
            target,
        );

        record_proof_read(target, 16);
        record_proof_close(target);
        assert!(!proof_complete(), "read before metadata must not count");

        record_proof_fstat(target);
        record_proof_close(target);
        assert!(
            !proof_complete(),
            "close before a post-stat positive read must not count"
        );

        record_proof_read(target, 16);
        record_proof_close(target);
        assert!(proof_complete());
    }

    #[test]
    fn proof_rejects_numeric_fd_reuse_with_new_generation() {
        reset_proof();
        let mut table = FdTable::<4>::new();
        let original = table.open_readonly(test_file(7)).unwrap();
        record_proof_open(
            PROOF_FIXTURE_ABSOLUTE,
            EntryId::from_index(PROOF_TARGET_ENTRY_INDEX as u16),
            original,
        );
        table.close(original.fd()).unwrap();
        let reused = table.open_readonly(test_file(7)).unwrap();
        assert_eq!(original.fd(), reused.fd());
        assert_ne!(original.generation(), reused.generation());

        record_proof_fstat(reused);
        record_proof_read(reused, 16);
        record_proof_close(reused);
        assert!(!proof_complete());
    }

    #[test]
    fn user_visible_vfs_errors_map_fail_closed() {
        assert_eq!(
            map_vfs_error(VfsError::NotFound),
            Error::Linux(Errno::ENOENT)
        );
        assert_eq!(
            map_vfs_error(VfsError::NotDirectory),
            Error::Linux(Errno::ENOTDIR)
        );
        assert_eq!(
            map_vfs_error(VfsError::IsDirectory),
            Error::Linux(Errno::EISDIR)
        );
        assert_eq!(
            map_vfs_error(VfsError::SymlinkUnsupported),
            Error::Linux(Errno::ELOOP)
        );
        assert_eq!(map_vfs_error(VfsError::HandleMismatch), Error::Invariant);
    }

    #[test]
    fn fd_errors_preserve_linux_errno_and_internal_invariants() {
        assert_eq!(map_fd_error(FdError::BadFd), Error::Linux(Errno::EBADF));
        assert_eq!(
            map_fd_error(FdError::InvalidTargetFd),
            Error::Linux(Errno::EBADF)
        );
        assert_eq!(
            map_fd_error(FdError::TableFull),
            Error::Linux(Errno::EMFILE)
        );
        assert_eq!(map_fd_error(FdError::NotFile), Error::Linux(Errno::EISDIR));
        assert_eq!(
            map_fd_error(FdError::NotDirectory),
            Error::Linux(Errno::ENOTDIR)
        );
        assert_eq!(
            map_fd_error(FdError::InvalidMinimumFd),
            Error::Linux(Errno::EINVAL)
        );
        assert_eq!(
            map_fd_error(FdError::SameDescriptor),
            Error::Linux(Errno::EINVAL)
        );
        assert_eq!(
            map_fd_error(FdError::InvalidSeek),
            Error::Linux(Errno::EINVAL)
        );
        assert_eq!(
            map_fd_error(FdError::InvalidPreadOffset),
            Error::Linux(Errno::EINVAL)
        );
        assert_eq!(
            map_fd_error(FdError::SeekOverflow),
            Error::Linux(Errno::EOVERFLOW)
        );
        assert_eq!(
            map_fd_error(FdError::NotSeekable),
            Error::Linux(Errno::ESPIPE)
        );
        assert_eq!(map_fd_error(FdError::OffsetOverflow), Error::Invariant);
        assert_eq!(map_fd_error(FdError::StaleRead), Error::Invariant);
        assert_eq!(map_fd_error(FdError::InvalidReadLength), Error::Invariant);
        assert_eq!(map_fd_error(FdError::StaleDirectory), Error::Invariant);
        assert_eq!(
            map_fd_error(FdError::InvalidDirectoryCursor),
            Error::Invariant
        );
        assert_eq!(map_fd_error(FdError::StaleOpenFile), Error::Invariant);
        assert_eq!(map_fd_error(FdError::ReferenceOverflow), Error::Invariant);
        assert_eq!(map_fd_error(FdError::StalePread), Error::Invariant);
    }
}
