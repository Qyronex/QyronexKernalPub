// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_capability::ObjectId;
use kernal_linux_abi::Errno;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_abi::{Step30RuntimeCall, linux_signed_int};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_exec::ExecLookupPlan;
use kernal_linux_exec::{Error as LinuxExecError, ExecArgumentStaging, ExecStringVector};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_scheduler_smp::GlobalThreadId;
use kernal_user_elf_runtime_aarch64::{
    LinuxProcessStart, MAX_ARGC, MAX_ARGV0_BYTES, MAX_ENVC, MAX_STRING_BYTES,
};
use kernal_usercopy::Error as ExecUsercopyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExecInputError {
    Linux(Errno),
    Invariant,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReversibleExecError {
    Input(ExecInputError),
    Source(super::step30_exec_source::ExecSourceError),
    Stage(super::live_vm::ExecStageError),
    Invariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecScratchEntry {
    start: usize,
    len: usize,
}

/// Complete bounded argv/envp copy captured while the old userspace image is still active.
///
/// The sole byte buffer is sized from the canonical Linux initial-stack owner. Entry metadata stores
/// only offsets into that buffer, so the value is not self-referential and can safely cross the later
/// fresh-AddressSpace staging boundary. Pointer/range validation remains owned by `ExecStringVector`;
/// this type only owns the copied bytes needed after the old TTBR0 is no longer usable.
pub(super) struct StagedExecVectors {
    bytes: [u8; MAX_STRING_BYTES],
    used: usize,
    argv: [Option<ExecScratchEntry>; MAX_ARGC],
    argc: usize,
    envp: [Option<ExecScratchEntry>; MAX_ENVC],
    envc: usize,
}

impl StagedExecVectors {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_STRING_BYTES],
            used: 0,
            argv: [None; MAX_ARGC],
            argc: 0,
            envp: [None; MAX_ENVC],
            envc: 0,
        }
    }

    /// Builds the canonical borrowed Linux process-start view only for one synchronous operation.
    ///
    /// Slice arrays are temporary stack metadata over this owned scratch buffer. They never escape the
    /// callback, so no self-referential storage or heap allocation is introduced.
    pub(super) fn with_linux_start<R>(
        &self,
        random: [u8; 16],
        operation: impl FnOnce(LinuxProcessStart<'_>) -> R,
    ) -> Result<R, ExecInputError> {
        if self.argc == 0 {
            // The accepted bounded Linux stack owner requires a concrete argv[0]. Do not synthesize
            // one from the pathname or silently widen that contract in Core.
            return Err(ExecInputError::Linux(Errno::EINVAL));
        }

        let mut argv_refs: [&[u8]; MAX_ARGC] = [&[]; MAX_ARGC];
        for (index, slot) in self.argv.iter().copied().enumerate().take(self.argc) {
            let entry = slot.ok_or(ExecInputError::Invariant)?;
            argv_refs[index] = self.entry_bytes(entry)?;
        }
        let mut env_refs: [&[u8]; MAX_ENVC] = [&[]; MAX_ENVC];
        for (index, slot) in self.envp.iter().copied().enumerate().take(self.envc) {
            let entry = slot.ok_or(ExecInputError::Invariant)?;
            env_refs[index] = self.entry_bytes(entry)?;
        }

        let start = LinuxProcessStart::with_vectors(
            argv_refs[0],
            &argv_refs[1..self.argc],
            &env_refs[..self.envc],
            random,
        );
        Ok(operation(start))
    }

    fn entry_bytes(&self, entry: ExecScratchEntry) -> Result<&[u8], ExecInputError> {
        let end = entry
            .start
            .checked_add(entry.len)
            .ok_or(ExecInputError::Invariant)?;
        self.bytes
            .get(entry.start..end)
            .ok_or(ExecInputError::Invariant)
    }
}

/// Successfully staged replacement-image receipt returned at the final ordinary recoverable boundary.
///
/// `process` is observation only: it was obtained from the exact current scheduler generation through
/// the canonical LinuxIdentity relation and is retained solely to select that Process's Step-29 FD/VFS
/// view later. `staged` remains unpublished replacement-image authority until the final runtime owner
/// activates and swaps it. Returning this receipt means every ordinary Linux-visible preparation step
/// succeeded; later owner failures are invariant/fail-stop rather than recoverable exec errors.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct PreparedExecImage {
    process: ObjectId,
    staged: super::live_vm::StagedExecImage,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl PreparedExecImage {
    pub(super) const fn process(&self) -> ObjectId {
        self.process
    }

    pub(super) fn into_staged(self) -> super::live_vm::StagedExecImage {
        self.staged
    }
}

/// Copies argv/envp through the canonical AArch64 usercopy owner while the old image is active.
///
/// Every pointer-table slot is first derived by `ExecStringVector::next_pointer_slot`. Every non-null
/// C string is copied into one aggregate scratch budget and then committed back to the same metadata
/// owner with `push_validated_c_string`; the final null pointer is proved through `finish(0)`. No user
/// address is retained as byte authority after this function returns.
pub(super) fn stage_exec_vectors(
    argv_base: u64,
    envp_base: u64,
) -> Result<StagedExecVectors, ExecInputError> {
    let mut staged = StagedExecVectors::new();
    let argv = stage_one_vector::<MAX_ARGC>(
        argv_base,
        &mut staged.bytes,
        &mut staged.used,
        &mut staged.argv,
        true,
    )?;
    let envp = stage_one_vector::<MAX_ENVC>(
        envp_base,
        &mut staged.bytes,
        &mut staged.used,
        &mut staged.envp,
        false,
    )?;
    let metadata =
        ExecArgumentStaging::new(argv, envp, MAX_STRING_BYTES).map_err(map_linux_exec_error)?;
    if metadata.total_bytes() != staged.used {
        return Err(ExecInputError::Invariant);
    }
    staged.argc = metadata.argv().len();
    staged.envc = metadata.envp().len();
    Ok(staged)
}

/// Performs every ordinary reversible live-exec preparation step using only existing canonical owners.
///
/// The caller supplies the second AT_RANDOM grant but retains ownership of the entropy transaction;
/// this helper never commits or consumes that grant itself. Path and vector usercopy, exact Process
/// selection, Process-local FD/VFS lookup and complete ELF/Linux-stack staging all finish while the old
/// image remains current. Error provenance stays typed so the final runtime owner can distinguish
/// input, VFS/source, and ELF/resource staging failures without fabricating a Linux errno.
///
/// # Safety
/// Caller must own the exact current lower-EL synchronous no-switch window for `current`. The supplied
/// `random` bytes must be the currently claimed exec AT_RANDOM grant. The successful typed staging result is the AT_RANDOM
/// transaction commit signal and the final ordinary recoverable exec failure boundary. After `Ok(PreparedExecImage)`,
/// every later owner failure must fail-stop rather than recover the old image.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) unsafe fn stage_exec_image_with_core_frames(
    call: Step30RuntimeCall,
    current: GlobalThreadId,
    random: [u8; 16],
) -> Result<PreparedExecImage, ReversibleExecError> {
    let (path, argv_base, envp_base, lookup) = match call {
        Step30RuntimeCall::Execve {
            filename,
            argv,
            envp,
        } => {
            let path = super::step29_fd::copy_user_path_allow_empty(filename, false)
                .map_err(map_step29_path_error)
                .map_err(ReversibleExecError::Input)?;
            let lookup = ExecLookupPlan::execve(path.as_bytes().is_empty())
                .map_err(map_exec_lookup_error)
                .map_err(ReversibleExecError::Input)?;
            (path, argv, envp, lookup)
        }
        Step30RuntimeCall::Execveat {
            dirfd,
            pathname,
            argv,
            envp,
            flags,
        } => {
            let path = super::step29_fd::copy_user_path_allow_empty(pathname, true)
                .map_err(map_step29_path_error)
                .map_err(ReversibleExecError::Input)?;
            let lookup = ExecLookupPlan::execveat(
                linux_signed_int(dirfd),
                path.as_bytes().is_empty(),
                flags,
            )
            .map_err(map_exec_lookup_error)
            .map_err(ReversibleExecError::Input)?;
            (path, argv, envp, lookup)
        }
        _ => return Err(ReversibleExecError::Invariant),
    };

    let vectors = stage_exec_vectors(argv_base, envp_base).map_err(ReversibleExecError::Input)?;

    // Resolve Process authority from the exact running scheduler generation. ObjectId is copied out
    // only after the retained Process/AddressSpace pair and current TTBR0 binding are revalidated.
    let process = super::runtime::with_linux_runtime(|state| {
        let (process, address_space, _tid) = state.process_parts_for_scheduler_thread(current)?;
        address_space
            .current_owner(process)
            .map_err(super::runtime::Error::AddressSpace)?;
        Ok::<ObjectId, super::runtime::Error>(process.id())
    })
    .map_err(|_| ReversibleExecError::Invariant)?
    .map_err(|_| ReversibleExecError::Invariant)?;

    let source =
        super::step30_exec_source::select_exec_image_source(process, lookup, path.as_bytes())
            .map_err(ReversibleExecError::Source)?;

    let staged = source
        .with_image_bytes(|image| {
            vectors.with_linux_start(random, |start| {
                // SAFETY: delegated caller contract owns the exact same lower-EL no-switch window;
                // image/start borrows remain valid for this complete synchronous staging call.
                unsafe { super::live_vm::stage_exec_image(current, image, start) }
            })
        })
        .map_err(ReversibleExecError::Source)?
        .map_err(ReversibleExecError::Input)?
        .map_err(ReversibleExecError::Stage)?;

    Ok(PreparedExecImage { process, staged })
}

fn stage_one_vector<const N: usize>(
    vector_base: u64,
    scratch: &mut [u8; MAX_STRING_BYTES],
    used: &mut usize,
    entries: &mut [Option<ExecScratchEntry>; N],
    enforce_argv0_limit: bool,
) -> Result<ExecStringVector<N>, ExecInputError> {
    let mut vector = ExecStringVector::<N>::new();
    loop {
        let slot = vector
            .next_pointer_slot(vector_base)
            .map_err(map_linux_exec_error)?;
        let pointer = copy_user_pointer(slot.start())?;
        if pointer == 0 {
            return vector.finish(0).map_err(map_linux_exec_error);
        }
        if vector.len() == N {
            return Err(ExecInputError::Linux(Errno::E2BIG));
        }

        let index = vector.len();
        let entry = copy_user_c_string(pointer, scratch, used, enforce_argv0_limit && index == 0)?;
        let len_with_nul = entry
            .len
            .checked_add(1)
            .ok_or(ExecInputError::Linux(Errno::E2BIG))?;
        vector
            .push_validated_c_string(pointer, len_with_nul)
            .map_err(map_linux_exec_error)?;
        let target = entries.get_mut(index).ok_or(ExecInputError::Invariant)?;
        if target.is_some() {
            return Err(ExecInputError::Invariant);
        }
        *target = Some(entry);
    }
}

fn copy_user_pointer(address: u64) -> Result<u64, ExecInputError> {
    let mut bytes = [0u8; core::mem::size_of::<u64>()];
    kernal_usercopy_aarch64::copy_from_user(&mut bytes, address).map_err(map_usercopy_error)?;
    Ok(u64::from_le_bytes(bytes))
}

fn copy_user_c_string(
    address: u64,
    scratch: &mut [u8; MAX_STRING_BYTES],
    used: &mut usize,
    enforce_argv0_limit: bool,
) -> Result<ExecScratchEntry, ExecInputError> {
    let start = *used;
    let remaining = MAX_STRING_BYTES
        .checked_sub(start)
        .ok_or(ExecInputError::Invariant)?;
    if remaining == 0 {
        return Err(ExecInputError::Linux(Errno::E2BIG));
    }

    let mut byte = [0u8; 1];
    for offset in 0..remaining {
        let user = address
            .checked_add(u64::try_from(offset).map_err(|_| ExecInputError::Linux(Errno::EFAULT))?)
            .ok_or(ExecInputError::Linux(Errno::EFAULT))?;
        kernal_usercopy_aarch64::copy_from_user(&mut byte, user).map_err(map_usercopy_error)?;
        if byte[0] == 0 {
            if enforce_argv0_limit && offset > MAX_ARGV0_BYTES {
                return Err(ExecInputError::Linux(Errno::E2BIG));
            }
            let len_with_nul = offset
                .checked_add(1)
                .ok_or(ExecInputError::Linux(Errno::E2BIG))?;
            let next = start
                .checked_add(len_with_nul)
                .ok_or(ExecInputError::Linux(Errno::E2BIG))?;
            let nul = scratch
                .get_mut(start + offset)
                .ok_or(ExecInputError::Invariant)?;
            *nul = 0;
            *used = next;
            return Ok(ExecScratchEntry { start, len: offset });
        }
        let destination = scratch
            .get_mut(start + offset)
            .ok_or(ExecInputError::Invariant)?;
        *destination = byte[0];
    }

    Err(ExecInputError::Linux(Errno::E2BIG))
}

fn map_linux_exec_error(error: LinuxExecError) -> ExecInputError {
    match error {
        LinuxExecError::TooManyVectorEntries | LinuxExecError::ArgumentBytesExceeded => {
            ExecInputError::Linux(Errno::E2BIG)
        }
        LinuxExecError::Usercopy(error) => map_usercopy_error(error),
        LinuxExecError::InvalidStringLength => ExecInputError::Invariant,
        LinuxExecError::UnsupportedExecveatFlags
        | LinuxExecError::EmptyPath
        | LinuxExecError::NotLinuxProcess
        | LinuxExecError::InactiveProcess
        | LinuxExecError::ProcessChanged
        | LinuxExecError::Fd(_) => ExecInputError::Invariant,
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_exec_lookup_error(error: LinuxExecError) -> ExecInputError {
    match error {
        LinuxExecError::UnsupportedExecveatFlags => ExecInputError::Linux(Errno::EINVAL),
        LinuxExecError::EmptyPath => ExecInputError::Linux(Errno::ENOENT),
        LinuxExecError::NotLinuxProcess
        | LinuxExecError::InactiveProcess
        | LinuxExecError::ProcessChanged
        | LinuxExecError::TooManyVectorEntries
        | LinuxExecError::ArgumentBytesExceeded
        | LinuxExecError::InvalidStringLength
        | LinuxExecError::Usercopy(_)
        | LinuxExecError::Fd(_) => ExecInputError::Invariant,
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn map_step29_path_error(error: super::step29_fd::Error) -> ExecInputError {
    match error {
        super::step29_fd::Error::Linux(errno) => ExecInputError::Linux(errno),
        super::step29_fd::Error::Invariant => ExecInputError::Invariant,
    }
}

fn map_usercopy_error(error: ExecUsercopyError) -> ExecInputError {
    match error {
        ExecUsercopyError::NullGuard
        | ExecUsercopyError::OutsideUserRange
        | ExecUsercopyError::Overflow
        | ExecUsercopyError::TooLarge
        | ExecUsercopyError::Fault => ExecInputError::Linux(Errno::EFAULT),
        ExecUsercopyError::PanUnavailable
        | ExecUsercopyError::PanStateLeak
        | ExecUsercopyError::FaultHandlerUnavailable => ExecInputError::Invariant,
    }
}
