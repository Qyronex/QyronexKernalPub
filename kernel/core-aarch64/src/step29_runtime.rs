// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_capability::ObjectId;
use kernal_cpio::Archive;
use kernal_linux_fd::{Error as FdError, FdTable, FdTableSet, FdViewId, ReleasedObject};
use kernal_linux_pipe::{PIPE_BUF, PipeTable};
use kernal_linux_vfs::{
    FsContext, InitramfsRoot, OverlayDirectoryHandle, OverlayNamespace, RootId,
};
use kernal_protected_boot_aarch64::ProtectedInitrd;

pub const STEP29_RUNTIME_FDS: usize = 32;
pub const STEP29_RUNTIME_PIPES: usize = STEP29_RUNTIME_FDS / 2;
pub const STEP29_RUNTIME_PIPE_CAPACITY: usize = PIPE_BUF;
/// Step 30 admits four simultaneous Linux Process generations. Each Process receives one exact
/// generation-bound descriptor view while every view shares this runtime's single canonical OFD pool.
pub const STEP29_RUNTIME_PROCESS_VIEWS: usize = 4;

// Final Step-29 filesystem integration owns one bounded mutable Overlay namespace. These capacities
// are deliberately process-local and finite: the VFS remains the sole namespace/data/lifetime owner
// while the FD table owns only Linux descriptor/OFD state. FILE_BYTES is per mutable inode.
pub const STEP29_RUNTIME_FS_NODES: usize = 8;
pub const STEP29_RUNTIME_FS_DENTRIES: usize = 16;
pub const STEP29_RUNTIME_FS_FILE_BYTES: usize = 4096;
pub const STEP29_RUNTIME_FS_TOMBSTONES: usize = 8;

pub type Step29Overlay = OverlayNamespace<
    'static,
    STEP29_RUNTIME_FS_NODES,
    STEP29_RUNTIME_FS_DENTRIES,
    STEP29_RUNTIME_FS_FILE_BYTES,
    STEP29_RUNTIME_FS_TOMBSTONES,
>;

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const READY: u8 = 2;
const BORROWED: u8 = 3;
const POISONED: u8 = 4;

// The Step-29 runtime is one-shot and owns exactly one protected initramfs root plus one mutable
// Overlay namespace layered over it. If remount/root replacement is introduced later, that owner
// must allocate a fresh generation instead of reusing this identity.
const INITRAMFS_ROOT_ID: RootId = RootId::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized,
    Unavailable,
    Busy,
    Poisoned,
    InvalidState,
    WrongProcess,
    ProcessSlotsFull,
    DescriptorInitialization,
    FilesystemInitialization,
    FilesystemContext,
    DirectoryBacking,
    Fd(FdError),
    ResourceRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessFdBinding {
    process: ObjectId,
    view: FdViewId,
}

/// Borrow-scoped view of the Step-29 process-local filesystem/descriptor owner.
pub struct Step29PathRuntime<'a> {
    process: ObjectId,
    initrd: ProtectedInitrd,
    root_id: RootId,
    fds: &'a mut FdTable<STEP29_RUNTIME_FDS>,
    pipes: &'a mut PipeTable<STEP29_RUNTIME_PIPES, STEP29_RUNTIME_PIPE_CAPACITY>,
    overlay: &'a mut Step29Overlay,
    fs_context: &'a mut FsContext,
}

impl Step29PathRuntime<'_> {
    pub const fn process(&self) -> ObjectId {
        self.process
    }

    pub const fn initrd(&self) -> ProtectedInitrd {
        self.initrd
    }

    pub const fn root_id(&self) -> RootId {
        self.root_id
    }

    pub fn fds(&mut self) -> &mut FdTable<STEP29_RUNTIME_FDS> {
        self.fds
    }

    pub fn pipes(&mut self) -> &mut PipeTable<STEP29_RUNTIME_PIPES, STEP29_RUNTIME_PIPE_CAPACITY> {
        self.pipes
    }

    pub fn overlay(&mut self) -> &mut Step29Overlay {
        self.overlay
    }

    pub fn fs_context(&mut self) -> &mut FsContext {
        self.fs_context
    }

    /// Resolves a descriptor to the exact generation-qualified Overlay directory identity.
    ///
    /// Canonical retained Overlay directories come directly from the FD owner. Legacy immutable
    /// `ReadOnlyDirectory` descriptors remain an additive compatibility authority: revalidate them
    /// through the sole protected initramfs owner, derive their canonical lower directory, and
    /// re-enter the same persistent Overlay namespace. No pathname or directory lifetime is stored
    /// in an ARM64-side shadow table.
    pub fn overlay_directory_for_fd(
        &self,
        fd: i32,
    ) -> Result<Option<OverlayDirectoryHandle>, Error> {
        if let Ok(directory) = self.fds.retained_directory(fd) {
            return Ok(Some(directory));
        }

        let legacy_directory = match self.fds.prepare_directory(fd) {
            Ok(plan) => plan.directory(),
            Err(FdError::BadFd | FdError::NotDirectory) => return Ok(None),
            Err(_) => return Err(Error::DirectoryBacking),
        };
        let canonical = self.initrd.with_bytes(|bytes| {
            let archive = Archive::parse(bytes).map_err(|_| Error::DirectoryBacking)?;
            let root = InitramfsRoot::new(archive, self.root_id);
            root.resolve_from_directory_following(legacy_directory, b".")
                .map(|(_, _, canonical)| canonical)
                .map_err(|_| Error::DirectoryBacking)
        })?;
        let lookup = if canonical.is_root() {
            b"/".as_slice()
        } else {
            canonical.as_relative_bytes()
        };
        self.overlay
            .open_directory_at(lookup)
            .map(Some)
            .map_err(|_| Error::DirectoryBacking)
    }

    /// Borrows the descriptor and pipe owners together for transactional `pipe2`, pipe-aware close,
    /// and exact-target duplication.
    pub fn fd_pipe_parts(
        &mut self,
    ) -> (
        &mut FdTable<STEP29_RUNTIME_FDS>,
        &mut PipeTable<STEP29_RUNTIME_PIPES, STEP29_RUNTIME_PIPE_CAPACITY>,
    ) {
        (&mut *self.fds, &mut *self.pipes)
    }

    pub fn fd_overlay_parts(&mut self) -> (&mut FdTable<STEP29_RUNTIME_FDS>, &mut Step29Overlay) {
        (&mut *self.fds, &mut *self.overlay)
    }

    pub fn overlay_context_parts(&mut self) -> (&mut Step29Overlay, &mut FsContext) {
        (&mut *self.overlay, &mut *self.fs_context)
    }

    pub fn fd_overlay_context_parts(
        &mut self,
    ) -> (
        &mut FdTable<STEP29_RUNTIME_FDS>,
        &mut Step29Overlay,
        &mut FsContext,
    ) {
        (&mut *self.fds, &mut *self.overlay, &mut *self.fs_context)
    }

    pub fn fd_pipe_overlay_parts(
        &mut self,
    ) -> (
        &mut FdTable<STEP29_RUNTIME_FDS>,
        &mut PipeTable<STEP29_RUNTIME_PIPES, STEP29_RUNTIME_PIPE_CAPACITY>,
        &mut Step29Overlay,
    ) {
        (&mut *self.fds, &mut *self.pipes, &mut *self.overlay)
    }

    /// Legacy immutable-initramfs compatibility view. Final mutable filesystem syscalls should use
    /// the Overlay-specific split borrows above instead of manufacturing another namespace owner.
    pub fn parts(&mut self) -> (ProtectedInitrd, RootId, &mut FdTable<STEP29_RUNTIME_FDS>) {
        (self.initrd, self.root_id, &mut *self.fds)
    }
}

struct RuntimeCell {
    state: AtomicU8,
    processes: UnsafeCell<[Option<ProcessFdBinding>; STEP29_RUNTIME_PROCESS_VIEWS]>,
    initrd: UnsafeCell<MaybeUninit<ProtectedInitrd>>,
    fds: UnsafeCell<FdTableSet<STEP29_RUNTIME_PROCESS_VIEWS, STEP29_RUNTIME_FDS>>,
    pipes: UnsafeCell<PipeTable<STEP29_RUNTIME_PIPES, STEP29_RUNTIME_PIPE_CAPACITY>>,
    overlay: UnsafeCell<MaybeUninit<Step29Overlay>>,
    /// One process-local Linux filesystem context per process binding slot.
    ///
    /// Inactive slots stay at the generic root/default umask. A live slot may own an independent
    /// mutable cwd lifetime hold. The `processes` array remains the sole occupancy authority, so a
    /// scalar slot cannot select a context without first matching the exact Process ObjectId binding.
    fs_contexts: UnsafeCell<[FsContext; STEP29_RUNTIME_PROCESS_VIEWS]>,
}

// SAFETY: all owner storage is initialized before READY. Only READY -> BORROWED exposes mutable
// references and each borrow is scoped to one synchronous lower-EL syscall/protected-boot closure.
unsafe impl Sync for RuntimeCell {}

impl RuntimeCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            processes: UnsafeCell::new([None; STEP29_RUNTIME_PROCESS_VIEWS]),
            initrd: UnsafeCell::new(MaybeUninit::uninit()),
            fds: UnsafeCell::new(FdTableSet::new()),
            pipes: UnsafeCell::new(PipeTable::new()),
            overlay: UnsafeCell::new(MaybeUninit::uninit()),
            fs_contexts: UnsafeCell::new(
                [const { FsContext::new(INITRAMFS_ROOT_ID) }; STEP29_RUNTIME_PROCESS_VIEWS],
            ),
        }
    }

    fn initialize(&self, process: ObjectId, initrd: ProtectedInitrd) -> Result<(), Error> {
        match self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(INSTALLING | READY) => return Err(Error::AlreadyInitialized),
            Err(BORROWED) => return Err(Error::Busy),
            Err(POISONED) => return Err(Error::Poisoned),
            Err(_) => return Err(Error::InvalidState),
        }

        // SAFETY: successful EMPTY -> INSTALLING grants this path exclusive initialization access.
        unsafe {
            (*self.initrd.get()).write(initrd);
        }

        let bytes = protected_initrd_static_bytes(initrd);
        let archive = match Archive::parse(bytes) {
            Ok(archive) => archive,
            Err(_) => {
                self.state.store(POISONED, Ordering::Release);
                return Err(Error::FilesystemInitialization);
            }
        };
        let lower = InitramfsRoot::new(archive, INITRAMFS_ROOT_ID);
        // SAFETY: INSTALLING grants unique access to the uninitialized static Overlay slot. The
        // namespace is written directly to its final location before READY is published.
        unsafe {
            (*self.overlay.get()).write(OverlayNamespace::new(lower));
        }

        // SAFETY: INSTALLING still grants unique access and no READY borrower can exist yet.
        let fds = unsafe { &mut *self.fds.get() };
        let initial_view = match fds.create_view() {
            Ok(view) => view,
            Err(_) => {
                self.state.store(POISONED, Ordering::Release);
                return Err(Error::DescriptorInitialization);
            }
        };
        match fds.with_view(initial_view, |table| table.seed_standard_descriptors()) {
            Ok(Ok(_)) => {}
            _ => {
                self.state.store(POISONED, Ordering::Release);
                return Err(Error::DescriptorInitialization);
            }
        }
        // SAFETY: INSTALLING grants unique access; no process binding is observable before READY.
        unsafe {
            (*self.processes.get())[0] = Some(ProcessFdBinding {
                process,
                view: initial_view,
            });
        }

        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    fn with_process<R>(
        &self,
        process: ObjectId,
        operation: impl FnOnce(&mut Step29PathRuntime<'_>) -> R,
    ) -> Result<R, Error> {
        self.begin_borrow()?;

        // SAFETY: BORROWED proves installation completed and grants this closure exclusive access to
        // all runtime owners. Bindings and owner storage remain live until READY is restored below.
        let binding_index = unsafe {
            (&*self.processes.get())
                .iter()
                .position(|binding| binding.is_some_and(|binding| binding.process == process))
        };
        let Some(binding_index) = binding_index else {
            self.state.store(READY, Ordering::Release);
            return Err(Error::WrongProcess);
        };
        // SAFETY: `binding_index` was found in the same BORROWED binding table above.
        let binding = unsafe { (&*self.processes.get())[binding_index] };
        let Some(binding) = binding else {
            self.state.store(POISONED, Ordering::Release);
            return Err(Error::InvalidState);
        };
        let initrd = unsafe { *(&*self.initrd.get()).assume_init_ref() };
        let fds = unsafe { &mut *self.fds.get() };
        let pipes = unsafe { &mut *self.pipes.get() };
        let overlay = unsafe { (&mut *self.overlay.get()).assume_init_mut() };
        // SAFETY: BORROWED grants exclusive access and the context slot is paired with the exact
        // Process binding index selected above. Inactive slots are never exposed.
        let fs_context = unsafe { &mut (&mut *self.fs_contexts.get())[binding_index] };

        let result = fds
            .with_view(binding.view, |table| {
                let mut runtime = Step29PathRuntime {
                    process: binding.process,
                    initrd,
                    root_id: INITRAMFS_ROOT_ID,
                    fds: table,
                    pipes,
                    overlay,
                    fs_context,
                };
                operation(&mut runtime)
            })
            .map_err(Error::Fd);
        self.state.store(READY, Ordering::Release);
        result
    }

    /// Publishes a child Process descriptor/filesystem view by sharing the parent's exact canonical
    /// OFDs while duplicating process-local cwd/umask state with an independent VFS lifetime hold.
    ///
    /// The child ObjectId is a selector only. The generation-bound FdViewId and FsContext slot remain
    /// private to this owner. Mutable cwd duplication re-enters the sole Overlay owner and acquires a
    /// distinct hold before either child binding is published. If FD-view creation then fails, that
    /// hold is rolled back; rollback failure poisons the one-shot runtime rather than leaking a
    /// seemingly reusable process slot.
    fn fork_process(&self, parent: ObjectId, child: ObjectId) -> Result<(), Error> {
        if parent == child {
            return Err(Error::InvalidState);
        }
        self.begin_borrow()?;

        // SAFETY: BORROWED grants exclusive access to all binding, context, VFS and FD owner state.
        let processes = unsafe { &mut *self.processes.get() };
        if processes
            .iter()
            .flatten()
            .any(|binding| binding.process == child)
        {
            self.state.store(READY, Ordering::Release);
            return Err(Error::InvalidState);
        }
        let Some(parent_index) = processes
            .iter()
            .position(|binding| binding.is_some_and(|binding| binding.process == parent))
        else {
            self.state.store(READY, Ordering::Release);
            return Err(Error::WrongProcess);
        };
        let Some(parent_binding) = processes[parent_index] else {
            self.state.store(POISONED, Ordering::Release);
            return Err(Error::InvalidState);
        };
        let Some(binding_slot) = processes.iter().position(Option::is_none) else {
            self.state.store(READY, Ordering::Release);
            return Err(Error::ProcessSlotsFull);
        };

        let fs_contexts = unsafe { &mut *self.fs_contexts.get() };
        let parent_context = &fs_contexts[parent_index];
        if parent_context.root() != INITRAMFS_ROOT_ID {
            self.state.store(POISONED, Ordering::Release);
            return Err(Error::InvalidState);
        }
        let parent_cwd = parent_context.cwd_handle();
        let parent_umask = parent_context.umask();
        let overlay = unsafe { (&mut *self.overlay.get()).assume_init_mut() };
        let directory = match overlay.revalidate_directory_handle(parent_cwd) {
            Ok(directory) => directory,
            Err(_) => {
                self.state.store(READY, Ordering::Release);
                return Err(Error::FilesystemContext);
            }
        };
        let mut child_context = FsContext::new(INITRAMFS_ROOT_ID);
        child_context.replace_umask(parent_umask);
        if overlay
            .set_context_cwd(&mut child_context, directory)
            .is_err()
        {
            self.state.store(READY, Ordering::Release);
            return Err(Error::FilesystemContext);
        }

        let fds = unsafe { &mut *self.fds.get() };
        let child_view = match fds.fork_view(parent_binding.view) {
            Ok(view) => view,
            Err(error) => {
                if overlay.release_context_cwd(&mut child_context).is_err() {
                    self.state.store(POISONED, Ordering::Release);
                    return Err(Error::ResourceRelease);
                }
                self.state.store(READY, Ordering::Release);
                return Err(Error::Fd(error));
            }
        };

        fs_contexts[binding_slot] = child_context;
        processes[binding_slot] = Some(ProcessFdBinding {
            process: child,
            view: child_view,
        });
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    /// Retires one exact Process descriptor/filesystem view and releases every final shared backing
    /// through the already-canonical Pipe/Overlay owners.
    ///
    /// Descriptor retirement is the first commit edge. The process-local cwd hold is released next
    /// through the sole Overlay owner. Any failure after FD retirement poisons this one-shot runtime:
    /// no stale Process binding may be reused after its descriptor generation has already retired.
    fn retire_process(&self, process: ObjectId) -> Result<(), Error> {
        self.begin_borrow()?;

        // SAFETY: BORROWED grants exclusive access to bindings, contexts, FD/OFD state, PipeTable and
        // the sole Overlay namespace for this complete teardown transaction.
        let processes = unsafe { &mut *self.processes.get() };
        let Some(binding_index) = processes
            .iter()
            .position(|binding| binding.is_some_and(|binding| binding.process == process))
        else {
            self.state.store(READY, Ordering::Release);
            return Err(Error::WrongProcess);
        };
        let Some(binding) = processes[binding_index] else {
            self.state.store(POISONED, Ordering::Release);
            return Err(Error::InvalidState);
        };
        let fds = unsafe { &mut *self.fds.get() };
        let released = match fds.retire_view(binding.view) {
            Ok(released) => released,
            Err(error) => {
                self.state.store(READY, Ordering::Release);
                return Err(Error::Fd(error));
            }
        };

        let overlay = unsafe { (&mut *self.overlay.get()).assume_init_mut() };
        let fs_contexts = unsafe { &mut *self.fs_contexts.get() };
        if overlay
            .release_context_cwd(&mut fs_contexts[binding_index])
            .is_err()
        {
            self.state.store(POISONED, Ordering::Release);
            return Err(Error::ResourceRelease);
        }

        let pipes = unsafe { &mut *self.pipes.get() };
        for object in released.into_iter().flatten() {
            let release_ok = match object {
                ReleasedObject::Pipe(endpoint) => pipes.close(endpoint).is_ok(),
                ReleasedObject::RetainedDirectory(directory) => {
                    overlay.release_directory(directory).is_ok()
                }
                ReleasedObject::RetainedReadOnly(logical) => overlay.release_open(logical).is_ok(),
                ReleasedObject::WritableRegular(retained) => {
                    overlay.release_retained_regular(retained).is_ok()
                }
            };
            if !release_ok {
                self.state.store(POISONED, Ordering::Release);
                return Err(Error::ResourceRelease);
            }
        }

        fs_contexts[binding_index] = FsContext::new(INITRAMFS_ROOT_ID);
        processes[binding_index] = None;
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    fn begin_borrow(&self) -> Result<(), Error> {
        match self
            .state
            .compare_exchange(READY, BORROWED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(EMPTY | INSTALLING) => Err(Error::Unavailable),
            Err(BORROWED) => Err(Error::Busy),
            Err(POISONED) => Err(Error::Poisoned),
            Err(_) => Err(Error::InvalidState),
        }
    }
}

/// Extends the exact protected-initrd byte mapping to the lifetime of the one-shot Step-29 runtime.
///
/// `ProtectedInitrd` is constructed only after the complete payload is mapped read-only/NX in the
/// permanent final TTBR1 root and architecturally probed. The mapping is never unmapped while this
/// runtime can be READY. This private architecture-TCB boundary therefore turns that permanent
/// mapping into the stable lower backing for exactly one persistent VFS Overlay owner; no reference
/// is exposed outside this module/runtime.
fn protected_initrd_static_bytes(initrd: ProtectedInitrd) -> &'static [u8] {
    // SAFETY: the `ProtectedInitrd` mapping contract described above proves the address is valid for
    // `len` bytes and remains mapped for the complete lifetime of the one-shot Step-29 runtime.
    unsafe { core::slice::from_raw_parts(initrd.virtual_start() as *const u8, initrd.len()) }
}

static STEP29_PATH_RUNTIME: RuntimeCell = RuntimeCell::new();

pub fn initialize(process: ObjectId, initrd: ProtectedInitrd) -> Result<(), Error> {
    STEP29_PATH_RUNTIME.initialize(process, initrd)
}

pub fn with_process<R>(
    process: ObjectId,
    operation: impl FnOnce(&mut Step29PathRuntime<'_>) -> R,
) -> Result<R, Error> {
    STEP29_PATH_RUNTIME.with_process(process, operation)
}

/// Adds one fork child to the existing path runtime without creating a second VFS/OFD owner.
pub fn fork_process(parent: ObjectId, child: ObjectId) -> Result<(), Error> {
    STEP29_PATH_RUNTIME.fork_process(parent, child)
}

/// Removes one exact Process descriptor/filesystem view after process lifecycle ownership has ended.
pub fn retire_process(process: ObjectId) -> Result<(), Error> {
    STEP29_PATH_RUNTIME.retire_process(process)
}
