// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_frame_allocator::{Error as FrameError, ExtentAllocator, FrameRange};
use kernal_memory::PhysFrame;
use kernal_user_elf_aarch64::Error as MappingError;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use super::memory::{STEP15_RESERVED_RANGES, Step15FramePool};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_object::ObjectTable;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_page_table_aarch64::Backend;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_process::Process;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_process_aarch64::BoundProcessAddressSpace;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_user_elf_aarch64::required_pages;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_user_elf_runtime_aarch64::{
    LinuxProcessStart, LoadedImage, load_aarch64_linux_elf, plan_aarch64_elf,
    plan_aarch64_linux_initial_stack,
};

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    FrameCapacity {
        required: usize,
        capacity: usize,
    },
    Frame(FrameError),
    FrameRollbackFailed,
    InvalidAllocatedFrame,
    Mapping(MappingError),
    InitialBreak,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    Loader(kernal_user_elf_runtime_aarch64::Error),
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    LoaderFramesQuarantined(kernal_user_elf_runtime_aarch64::Error),
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadedInitialLinuxImage {
    pub loaded: LoadedImage,
    pub initial_break: u64,
}

/// Fixed-capacity ownership record for physical frames removed from the sole live allocator.
///
/// Every allocation is exactly one page, so the stored [`PhysFrame`] is also the complete rollback
/// journal: the matching [`FrameRange`] can be reconstructed losslessly from its page-aligned start
/// address and `pages=1`. Keeping a second `FrameRange[N]` array would duplicate that information and
/// consume 16*N additional bytes in the protected BSP loader stack.
///
/// There is deliberately no `Drop` reclamation: after a successful ELF load the exact frames are
/// owned by the process mappings. Before that commit, callers explicitly reclaim the prefix on an
/// allocation failure. If the boot loader itself reports an error, the production wrapper quarantines
/// the whole batch because boot has no recoverable prior userspace image. Live exec instead retains
/// the complete batch in a linear failure receipt so mapped leaves and never-mapped reservations can
/// be returned exactly after the old image is restored and staging is terminally discarded.
struct InitialFrameBatch<const N: usize> {
    frames: [PhysFrame; N],
    len: usize,
}

impl<const N: usize> InitialFrameBatch<N> {
    const fn new() -> Self {
        Self {
            frames: [PhysFrame::containing_address(0); N],
            len: 0,
        }
    }

    fn frames(&self) -> &[PhysFrame] {
        &self.frames[..self.len]
    }

    fn allocate<const EXTENTS: usize>(
        allocator: &mut ExtentAllocator<EXTENTS>,
        required: usize,
    ) -> Result<Self, Error> {
        if required > N {
            return Err(Error::FrameCapacity {
                required,
                capacity: N,
            });
        }

        let mut batch = Self::new();
        while batch.len < required {
            let range = match allocator.allocate(1, 1) {
                Ok(range) => range,
                Err(error) => {
                    batch.reclaim(allocator)?;
                    return Err(Error::Frame(error));
                }
            };

            let Some(frame) = PhysFrame::from_start_address(range.start) else {
                if allocator.free(range).is_err() {
                    return Err(Error::FrameRollbackFailed);
                }
                batch.reclaim(allocator)?;
                return Err(Error::InvalidAllocatedFrame);
            };
            batch.frames[batch.len] = frame;
            batch.len += 1;
        }
        Ok(batch)
    }

    /// Returns one exact frame from this still-linear batch to the allocator and removes it from the
    /// receipt. This is used only after the canonical staging-discard owner has removed the matching
    /// PTE and handed that exact physical frame back to Core.
    fn reclaim_exact<const EXTENTS: usize>(
        &mut self,
        allocator: &mut ExtentAllocator<EXTENTS>,
        frame: PhysFrame,
    ) -> Result<(), Error> {
        let index = self.frames[..self.len]
            .iter()
            .position(|candidate| *candidate == frame)
            .ok_or(Error::InvalidAllocatedFrame)?;
        let range = FrameRange::new(frame.start_address(), 1).map_err(Error::Frame)?;
        if allocator.free(range).is_err() {
            return Err(Error::FrameRollbackFailed);
        }

        let last = self.len - 1;
        self.frames[index] = self.frames[last];
        self.frames[last] = PhysFrame::containing_address(0);
        self.len = last;
        Ok(())
    }

    fn reclaim<const EXTENTS: usize>(
        &mut self,
        allocator: &mut ExtentAllocator<EXTENTS>,
    ) -> Result<(), Error> {
        while self.len != 0 {
            let index = self.len - 1;
            let range =
                FrameRange::new(self.frames[index].start_address(), 1).map_err(Error::Frame)?;
            if allocator.free(range).is_err() {
                return Err(Error::FrameRollbackFailed);
            }
            self.frames[index] = PhysFrame::containing_address(0);
            self.len = index;
        }
        Ok(())
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) struct ExecLoadFailure<const N: usize> {
    error: Error,
    batch: InitialFrameBatch<N>,
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl<const N: usize> ExecLoadFailure<N> {
    fn new(error: Error, batch: InitialFrameBatch<N>) -> Self {
        Self { error, batch }
    }

    /// Returns one frame just removed from the failed staging binding to the same sole live allocator.
    /// A foreign or duplicate frame fails closed instead of freeing memory outside this receipt.
    pub(super) fn release_discarded_frame(
        &mut self,
        pool: &mut Step15FramePool,
        frame: PhysFrame,
    ) -> bool {
        let (allocator, _) = pool.split();
        self.batch.reclaim_exact(allocator, frame).is_ok()
    }

    /// After the staging binding has no anonymous leaves left, returns every batch frame that was
    /// allocated but never mapped (or was already rolled back by the lower loader). The original
    /// semantic loader error is returned only after the ownership journal is empty.
    pub(super) fn reclaim_remaining(self, pool: &mut Step15FramePool) -> Result<Error, Error> {
        let Self { error, mut batch } = self;
        let (allocator, _) = pool.split();
        batch.reclaim(allocator)?;
        Ok(error)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn plan_initial_linux_load<const SEGMENTS: usize>(
    image: &[u8],
    start: LinuxProcessStart<'_>,
) -> Result<(usize, u64), Error> {
    plan_aarch64_linux_initial_stack::<SEGMENTS>(image, Default::default(), start)
        .map_err(Error::Loader)?;
    let plan = plan_aarch64_elf::<SEGMENTS>(image, Default::default()).map_err(Error::Loader)?;
    let required = required_pages(&plan)
        .map_err(Error::Mapping)?
        .checked_add(1)
        .ok_or(Error::InitialBreak)?;

    // Linux initializes brk at the exact end of the highest PT_LOAD memory image, not at the end of
    // its rounded mapping page. All arithmetic below uses fields from the already validated canonical
    // plan and runs before any allocator/page-table mutation.
    let mut initial_break = None;
    for segment in plan.segments() {
        let in_page = u64::try_from(segment.in_page_offset).map_err(|_| Error::InitialBreak)?;
        let memory = u64::try_from(segment.memory_size).map_err(|_| Error::InitialBreak)?;
        let segment_start = segment
            .virtual_page_start
            .checked_add(in_page)
            .ok_or(Error::InitialBreak)?;
        let segment_end = segment_start
            .checked_add(memory)
            .ok_or(Error::InitialBreak)?;
        initial_break =
            Some(initial_break.map_or(segment_end, |current: u64| current.max(segment_end)));
    }
    let initial_break = initial_break.ok_or(Error::InitialBreak)?;
    Ok((required, initial_break))
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn preflight_exec_linux_load<const SEGMENTS: usize>(
    image: &[u8],
    start: LinuxProcessStart<'_>,
) -> Result<(), Error> {
    plan_initial_linux_load::<SEGMENTS>(image, start).map(|_| ())
}

/// Allocates the exact initial image/stack frame batch from Core's sole live pool and invokes the
/// already integrated Linux AArch64 ELF loader.
///
/// All parser/Linux-stack checks run before the first physical allocation. Partial allocation failure
/// returns every already-removed frame to the same allocator. Once the canonical loader is invoked,
/// any loader error is treated as a quarantine boundary: the process address space is poisoned and
/// the frame batch remains absent from the allocator, because the existing loader error enum does not
/// distinguish every rollback-proven failure from every unproven mapping-cleanup failure. Boot may
/// fail, but a still-mapped physical page can never be recycled under another owner.
///
/// On success the allocator remains short by exactly the mapped image/stack pages, which are now
/// process-owned. The exact Linux program-break base is retained from this same canonical load plan,
/// so the later `LinuxVmRuntime::register_process_break` call does not reparse or guess segment state.
/// The surrounding [`super::memory::with_live_frame_pool`] borrow ends normally so the same allocator
/// can later service the canonical Linux VM runtime.
///
/// # Safety
/// The caller must satisfy `load_aarch64_linux_elf`'s complete current-PE address-space mutation
/// contract. The supplied `pool`, Process, address-space binding and page-table backend must all be
/// the unique live owners for this transaction; no context switch or blocking operation may occur.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub unsafe fn load_initial_linux_elf_with_core_frames<
    const FRAMES: usize,
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    B: Backend,
>(
    image: &[u8],
    start: LinuxProcessStart<'_>,
    pool: &mut Step15FramePool,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
) -> Result<LoadedInitialLinuxImage, Error> {
    let (required, initial_break) = plan_initial_linux_load::<SEGMENTS>(image, start)?;
    let (allocator, reservations) = pool.split();
    let batch = InitialFrameBatch::<FRAMES>::allocate(allocator, required)?;

    // SAFETY: delegated caller contract is exactly the canonical loader's owner/quiescence contract;
    // the batch contains distinct pages removed from this same pool and the reservation reference is
    // the exact metadata used to construct its persistent allocator exclusions.
    match unsafe {
        load_aarch64_linux_elf::<SEGMENTS, CAPS, OBJECTS, VMAS, STEP15_RESERVED_RANGES, B>(
            image,
            Default::default(),
            start,
            batch.frames(),
            process,
            objects,
            space,
            backend,
            reservations,
        )
    } {
        Ok(loaded) => Ok(LoadedInitialLinuxImage {
            loaded,
            initial_break,
        }),
        Err(error) => {
            // Conservatively quarantine the binding and keep all batch frames allocated. This is
            // intentionally stronger than guessing that one opaque loader error was reclaim-safe.
            space.poison();
            Err(Error::LoaderFramesQuarantined(error))
        }
    }
}

/// Live-exec variant of the canonical Core ELF loader.
///
/// It uses the same parser, stack policy, frame allocator, canonical lower loader and reservation
/// owner as boot. The only difference is failure ownership: exec still has a valid old image, so the
/// complete removed frame batch is returned in [`ExecLoadFailure`] instead of being forgotten behind
/// boot's fail-stop quarantine boundary. Staging is poisoned before that receipt escapes; the caller
/// must restore the old binding, terminally discard staging, release every unmapped leaf through the
/// receipt and finally reclaim all never-mapped batch frames before returning a recoverable exec error.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn load_exec_linux_elf_with_core_frames<
    const FRAMES: usize,
    const SEGMENTS: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    B: Backend,
>(
    image: &[u8],
    start: LinuxProcessStart<'_>,
    pool: &mut Step15FramePool,
    process: &Process<CAPS>,
    objects: &ObjectTable<OBJECTS>,
    space: &mut BoundProcessAddressSpace<VMAS>,
    backend: &mut B,
) -> Result<LoadedInitialLinuxImage, ExecLoadFailure<FRAMES>> {
    let (required, initial_break) = match plan_initial_linux_load::<SEGMENTS>(image, start) {
        Ok(plan) => plan,
        Err(error) => return Err(ExecLoadFailure::new(error, InitialFrameBatch::new())),
    };
    let (allocator, reservations) = pool.split();
    let batch = match InitialFrameBatch::<FRAMES>::allocate(allocator, required) {
        Ok(batch) => batch,
        Err(error) => return Err(ExecLoadFailure::new(error, InitialFrameBatch::new())),
    };

    // SAFETY: identical owner/quiescence contract to the boot wrapper above. The batch remains linear
    // Core authority until successful mapping publication; on error it is returned intact below.
    match unsafe {
        load_aarch64_linux_elf::<SEGMENTS, CAPS, OBJECTS, VMAS, STEP15_RESERVED_RANGES, B>(
            image,
            Default::default(),
            start,
            batch.frames(),
            process,
            objects,
            space,
            backend,
            reservations,
        )
    } {
        Ok(loaded) => Ok(LoadedInitialLinuxImage {
            loaded,
            initial_break,
        }),
        Err(error) => {
            space.poison();
            Err(ExecLoadFailure::new(Error::Loader(error), batch))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocator<const N: usize>(pages: u64) -> ExtentAllocator<N> {
        let mut allocator = ExtentAllocator::<N>::new();
        allocator
            .free(FrameRange::new(0x4100_0000, pages).unwrap())
            .unwrap();
        allocator
    }

    #[test]
    fn capacity_rejection_does_not_mutate_allocator() {
        let mut frames = allocator::<4>(8);
        let free = frames.free_pages();
        assert!(matches!(
            InitialFrameBatch::<3>::allocate(&mut frames, 4),
            Err(Error::FrameCapacity {
                required: 4,
                capacity: 3,
            })
        ));
        assert_eq!(frames.free_pages(), free);
    }

    #[test]
    fn partial_allocation_failure_reclaims_exact_prefix() {
        let mut frames = allocator::<4>(2);
        let before = frames.free_pages();
        assert!(matches!(
            InitialFrameBatch::<4>::allocate(&mut frames, 3),
            Err(Error::Frame(FrameError::NoMemory))
        ));
        assert_eq!(frames.free_pages(), before);
        assert_eq!(frames.extent_count(), 1);
    }

    #[test]
    fn successful_batch_is_distinct_and_remains_owned_until_explicit_reclaim() {
        let mut frames = allocator::<4>(6);
        let before = frames.free_pages();
        let mut batch = InitialFrameBatch::<4>::allocate(&mut frames, 3).unwrap();
        assert_eq!(batch.frames().len(), 3);
        assert_eq!(frames.free_pages(), before - 3);
        assert_ne!(batch.frames()[0], batch.frames()[1]);
        assert_ne!(batch.frames()[1], batch.frames()[2]);

        batch.reclaim(&mut frames).unwrap();
        assert_eq!(frames.extent_count(), 1);
        assert_eq!(frames.free_pages(), before);
    }

    #[test]
    fn exact_frame_release_removes_only_that_batch_member() {
        let mut frames = allocator::<4>(6);
        let before = frames.free_pages();
        let mut batch = InitialFrameBatch::<4>::allocate(&mut frames, 3).unwrap();
        let released = batch.frames()[1];

        batch.reclaim_exact(&mut frames, released).unwrap();
        assert_eq!(frames.free_pages(), before - 2);
        assert_eq!(batch.frames().len(), 2);
        assert!(!batch.frames().contains(&released));

        batch.reclaim(&mut frames).unwrap();
        assert_eq!(frames.free_pages(), before);
        assert_eq!(frames.extent_count(), 1);
    }

    #[test]
    fn exact_frame_release_rejects_foreign_frame_without_mutation() {
        let mut frames = allocator::<4>(6);
        let before = frames.free_pages();
        let mut batch = InitialFrameBatch::<4>::allocate(&mut frames, 2).unwrap();
        let foreign = PhysFrame::from_start_address(0x4200_0000).unwrap();

        assert_eq!(
            batch.reclaim_exact(&mut frames, foreign),
            Err(Error::InvalidAllocatedFrame)
        );
        assert_eq!(frames.free_pages(), before - 2);
        batch.reclaim(&mut frames).unwrap();
        assert_eq!(frames.free_pages(), before);
    }
}
