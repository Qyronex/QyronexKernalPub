// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::ptr::{copy_nonoverlapping, write_bytes};
use core::sync::atomic::{AtomicBool, Ordering};
use kernal_kmap::KmapWindow;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_kmap::{CachePolicy, MappingRequest};
use kernal_page_table_aarch64::Backend;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_page_table_aarch64::{Mapper, MemoryType};
use kernal_paging::PAGE_SIZE;

pub const KMAP_REGION_BASE: u64 = 0xffff_ff80_0100_0000;
pub const KMAP_CPU_STRIDE: u64 = 2 * 1024 * 1024;
pub const KMAP_SLOTS_PER_CPU: usize = 64;
pub const MAX_CPU_WINDOWS: usize = 256;

const ROOT_ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    CpuIndexOutOfRange,
    AddressOverflow,
    InvalidRoot,
    Window(kernal_kmap::Error),
    PageTable(kernal_page_table_aarch64::Error),
    Poisoned,
    CleanupFailed,
    SameFrame,
    UnsupportedHostArchitecture,
}

impl From<kernal_kmap::Error> for Error {
    fn from(value: kernal_kmap::Error) -> Self {
        Self::Window(value)
    }
}

impl From<kernal_page_table_aarch64::Error> for Error {
    fn from(value: kernal_page_table_aarch64::Error) -> Self {
        Self::PageTable(value)
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn map_failure_requires_poison(error: kernal_page_table_aarch64::Error) -> bool {
    matches!(
        error,
        kernal_page_table_aarch64::Error::AlreadyMapped
            | kernal_page_table_aarch64::Error::BackendFailure
            | kernal_page_table_aarch64::Error::InvalidDescriptor
            | kernal_page_table_aarch64::Error::InvalidTableAddress
    )
}

pub fn window_base(cpu_index: usize) -> Result<u64, Error> {
    if cpu_index >= MAX_CPU_WINDOWS {
        return Err(Error::CpuIndexOutOfRange);
    }
    let offset = (cpu_index as u64)
        .checked_mul(KMAP_CPU_STRIDE)
        .ok_or(Error::AddressOverflow)?;
    KMAP_REGION_BASE
        .checked_add(offset)
        .ok_or(Error::AddressOverflow)
}

/// CPU-local temporary supervisor mapping used to initialize or copy physical frames before user
/// exposure.
///
/// The software slot policy is shared with the existing x86_64 kmap implementation. AArch64 leaf
/// creation is delegated to the canonical page-table mapper, which keeps every mapping supervisor
/// only and executable-never. This controller exposes only bounded frame zeroing and exact-page copy
/// operations; it deliberately does not expose a persistent or typed mapping API.
pub struct KmapController {
    window: KmapWindow,
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    root_table: u64,
    poisoned: AtomicBool,
}

impl KmapController {
    /// Creates a controller for one already-active TTBR1 root.
    ///
    /// # Safety
    /// `root_table` must be the active kernel TTBR1 root for this PE. The caller must keep this
    /// controller CPU-local, prevent migration while a temporary mapping is live, and pass a
    /// [`Backend`] that reads/writes this exact root hierarchy and allocates table pages owned by it.
    /// The selected kmap window must not be used by another mapping owner.
    pub unsafe fn assume_active(cpu_index: usize, root_table: u64) -> Result<Self, Error> {
        if root_table == 0
            || root_table & (PAGE_SIZE - 1) != 0
            || root_table & !ROOT_ADDRESS_MASK != 0
        {
            return Err(Error::InvalidRoot);
        }
        Ok(Self {
            window: KmapWindow::new(window_base(cpu_index)?, KMAP_SLOTS_PER_CPU)?,
            #[cfg(all(target_arch = "aarch64", target_os = "none"))]
            root_table,
            poisoned: AtomicBool::new(false),
        })
    }

    pub const fn base(&self) -> u64 {
        self.window.base()
    }

    pub fn occupied_slots(&self) -> u32 {
        self.window.occupied_slots()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Zeroes exactly one physical 4-KiB frame through a temporary supervisor-only RW-NX alias.
    ///
    /// The temporary PTE is installed and invalidated before the first store. After zeroing, the PTE
    /// is removed and the VA is invalidated again before this function returns. The final TLBI's DSB
    /// also orders the zero stores before a caller can publish the frame through a user PTE.
    ///
    /// If cleanup cannot prove that the exact frame was unmapped, the controller is poisoned and the
    /// call fails. The caller must quarantine that frame and must not map it to EL0 or return it to a
    /// general allocator; a residual writable kernel alias is never treated as recoverable success.
    ///
    /// # Safety
    /// The caller must hold globally exclusive mutation authority for the active TTBR1 hierarchy
    /// represented by `backend` and `self.root_table` from before this call until it returns. Local
    /// IRQ/preemption must be quiesced and the executing thread must not migrate CPUs during that
    /// interval. No other page-table or kmap owner may create/remove leaves or intermediate tables in
    /// the same hierarchy concurrently. This is required because the canonical `Mapper` may allocate
    /// and publish missing intermediate tables and does not internally serialize those mutations.
    pub unsafe fn zero_frame<B: Backend>(
        &self,
        backend: &mut B,
        physical_address: u64,
    ) -> Result<(), Error> {
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        {
            let _ = (backend, physical_address);
            Err(Error::UnsupportedHostArchitecture)
        }

        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            if self.is_poisoned() {
                return Err(Error::Poisoned);
            }

            let request = MappingRequest {
                physical_address,
                writable: true,
                cache: CachePolicy::WriteBack,
            };
            kernal_page_table_aarch64::leaf_descriptor(
                physical_address,
                request.page_flags(),
                MemoryType::NormalWriteBack,
            )?;

            let lease = self.window.claim(request)?;
            let virtual_address = lease.virtual_address();

            let map_result = match Mapper::new(backend, self.root_table) {
                Ok(mut mapper) => mapper.map_page_with_type(
                    virtual_address,
                    physical_address,
                    request.page_flags(),
                    MemoryType::NormalWriteBack,
                ),
                Err(error) => Err(error),
            };
            if let Err(error) = map_result {
                if map_failure_requires_poison(error) {
                    self.poisoned.store(true, Ordering::Release);
                    drop(lease);
                    return Err(Error::CleanupFailed);
                }
                drop(lease);
                return Err(Error::PageTable(error));
            }

            // SAFETY: the caller's hierarchy-mutation contract owns this active TTBR1 root and this
            // lease exclusively owns the newly published supervisor kmap leaf.
            unsafe { kernal_page_table_aarch64::invalidate_page_el1(virtual_address) };

            // SAFETY: the leaf above maps exactly one writable Normal-memory physical frame at this
            // CPU-local supervisor VA. The mapping is NX and inaccessible to EL0.
            unsafe { write_bytes(virtual_address as *mut u8, 0, PAGE_SIZE as usize) };

            let cleanup = match Mapper::new(backend, self.root_table) {
                Ok(mut mapper) => mapper.unmap_page(virtual_address),
                Err(error) => Err(error),
            };

            match cleanup {
                Ok(unmapped) if unmapped == physical_address => {
                    // SAFETY: the exact kmap leaf was cleared. This broadcast invalidation completes
                    // the break-before-reuse boundary and orders the preceding zero stores.
                    unsafe { kernal_page_table_aarch64::invalidate_page_el1(virtual_address) };
                    drop(lease);
                    Ok(())
                }
                Ok(_) | Err(_) => {
                    self.poisoned.store(true, Ordering::Release);
                    drop(lease);
                    Err(Error::CleanupFailed)
                }
            }
        }
    }

    /// Copies exactly one physical 4-KiB frame through two temporary supervisor-only aliases.
    ///
    /// The source alias is read-only and the destination alias is writable. Both aliases are NX,
    /// inaccessible to EL0, Normal Write-Back memory, and invalidated after publication before the
    /// first load/store. Both leaves are removed and invalidated before success is returned.
    ///
    /// If any installed alias cannot be proven removed from the active hierarchy, the controller is
    /// poisoned and the call fails closed. This primitive grants no frame lifetime, refcount, COW, or
    /// user-mapping authority; callers retain ownership of both physical frames.
    ///
    /// # Safety
    /// The caller must satisfy the same exclusive active-TTBR1 mutation, local quiescence, and
    /// non-migration contract as [`Self::zero_frame`]. `source_physical_address` and
    /// `destination_physical_address` must designate caller-owned normal-memory frames whose contents
    /// may be read and overwritten respectively for the full duration of this call.
    pub unsafe fn copy_frame<B: Backend>(
        &self,
        backend: &mut B,
        source_physical_address: u64,
        destination_physical_address: u64,
    ) -> Result<(), Error> {
        if source_physical_address == destination_physical_address {
            return Err(Error::SameFrame);
        }

        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        {
            let _ = (
                backend,
                source_physical_address,
                destination_physical_address,
            );
            Err(Error::UnsupportedHostArchitecture)
        }

        #[cfg(all(target_arch = "aarch64", target_os = "none"))]
        {
            if self.is_poisoned() {
                return Err(Error::Poisoned);
            }

            let source_request = MappingRequest {
                physical_address: source_physical_address,
                writable: false,
                cache: CachePolicy::WriteBack,
            };
            let destination_request = MappingRequest {
                physical_address: destination_physical_address,
                writable: true,
                cache: CachePolicy::WriteBack,
            };

            kernal_page_table_aarch64::leaf_descriptor(
                source_physical_address,
                source_request.page_flags(),
                MemoryType::NormalWriteBack,
            )?;
            kernal_page_table_aarch64::leaf_descriptor(
                destination_physical_address,
                destination_request.page_flags(),
                MemoryType::NormalWriteBack,
            )?;

            // Claim both slots before publishing either leaf. A claim failure therefore needs no
            // page-table cleanup and the already-held lease is released by normal unwinding.
            let source_lease = self.window.claim(source_request)?;
            let destination_lease = self.window.claim(destination_request)?;
            let source_virtual_address = source_lease.virtual_address();
            let destination_virtual_address = destination_lease.virtual_address();

            let source_map = match Mapper::new(backend, self.root_table) {
                Ok(mut mapper) => mapper.map_page_with_type(
                    source_virtual_address,
                    source_physical_address,
                    source_request.page_flags(),
                    MemoryType::NormalWriteBack,
                ),
                Err(error) => Err(error),
            };
            if let Err(error) = source_map {
                if map_failure_requires_poison(error) {
                    self.poisoned.store(true, Ordering::Release);
                    drop(destination_lease);
                    drop(source_lease);
                    return Err(Error::CleanupFailed);
                }
                drop(destination_lease);
                drop(source_lease);
                return Err(Error::PageTable(error));
            }

            // SAFETY: the source lease exclusively owns the newly published supervisor-only source
            // alias in the active hierarchy covered by the caller's mutation contract.
            unsafe { kernal_page_table_aarch64::invalidate_page_el1(source_virtual_address) };

            // From this point onward the source leaf is published, so no error may return without an
            // explicit attempt to prove its removal.
            let destination_map = match Mapper::new(backend, self.root_table) {
                Ok(mut mapper) => mapper.map_page_with_type(
                    destination_virtual_address,
                    destination_physical_address,
                    destination_request.page_flags(),
                    MemoryType::NormalWriteBack,
                ),
                Err(error) => Err(error),
            };

            let cleanup_alias = |backend: &mut B,
                                 virtual_address: u64,
                                 expected_physical_address: u64|
             -> bool {
                let cleanup = match Mapper::new(backend, self.root_table) {
                    Ok(mut mapper) => mapper.unmap_page(virtual_address),
                    Err(error) => Err(error),
                };
                match cleanup {
                    Ok(unmapped) => {
                        // SAFETY: `unmap_page` reported that a leaf was removed at this VA. The
                        // caller's quiescence contract still covers the active hierarchy, so the
                        // EL1 invalidation is the required break-before-reuse completion step.
                        unsafe { kernal_page_table_aarch64::invalidate_page_el1(virtual_address) };
                        unmapped == expected_physical_address
                    }
                    Err(_) => false,
                }
            };

            if let Err(error) = destination_map {
                let source_removed =
                    cleanup_alias(backend, source_virtual_address, source_physical_address);
                let destination_state_untrusted = map_failure_requires_poison(error);
                drop(destination_lease);
                drop(source_lease);
                if !source_removed || destination_state_untrusted {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(Error::CleanupFailed);
                }
                return Err(Error::PageTable(error));
            }

            // SAFETY: the destination lease exclusively owns the newly published supervisor-only
            // destination alias. It is invalidated before the first store through that VA.
            unsafe { kernal_page_table_aarch64::invalidate_page_el1(destination_virtual_address) };

            // SAFETY: the two leases are distinct, source and destination physical frames are
            // distinct, the source leaf is RO, the destination leaf is RW, both cover exactly one
            // PAGE_SIZE Normal-memory frame, and neither alias is accessible to EL0.
            unsafe {
                copy_nonoverlapping(
                    source_virtual_address as *const u8,
                    destination_virtual_address as *mut u8,
                    PAGE_SIZE as usize,
                )
            };

            // Attempt both removals independently even if the first proof fails. A cleanup mismatch
            // poisons the controller monotonically; success is returned only when both exact physical
            // leaves were removed and invalidated.
            let destination_removed = cleanup_alias(
                backend,
                destination_virtual_address,
                destination_physical_address,
            );
            let source_removed =
                cleanup_alias(backend, source_virtual_address, source_physical_address);
            drop(destination_lease);
            drop(source_lease);

            if destination_removed && source_removed {
                Ok(())
            } else {
                self.poisoned.store(true, Ordering::Release);
                Err(Error::CleanupFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_kmap::{CachePolicy, MappingRequest};

    #[test]
    fn cpu_windows_are_distinct_and_bounded() {
        assert_eq!(window_base(0).unwrap(), KMAP_REGION_BASE);
        assert_eq!(window_base(1).unwrap(), KMAP_REGION_BASE + KMAP_CPU_STRIDE);
        assert_eq!(window_base(MAX_CPU_WINDOWS), Err(Error::CpuIndexOutOfRange));
        assert!((KMAP_SLOTS_PER_CPU as u64) * PAGE_SIZE <= KMAP_CPU_STRIDE);
    }

    #[test]
    fn temporary_frame_flags_are_supervisor_only_and_nx() {
        let request = MappingRequest {
            physical_address: 0x20_0000,
            writable: true,
            cache: CachePolicy::WriteBack,
        };
        let flags = request.page_flags();
        assert!(flags.writable());
        assert!(!flags.user());
        assert!(!flags.executable());
    }

    #[test]
    fn frame_copy_flags_are_directional_supervisor_only_and_nx() {
        let source = MappingRequest {
            physical_address: 0x20_0000,
            writable: false,
            cache: CachePolicy::WriteBack,
        };
        let destination = MappingRequest {
            physical_address: 0x21_0000,
            writable: true,
            cache: CachePolicy::WriteBack,
        };
        let source_flags = source.page_flags();
        let destination_flags = destination.page_flags();
        assert!(!source_flags.writable());
        assert!(destination_flags.writable());
        assert!(!source_flags.user());
        assert!(!destination_flags.user());
        assert!(!source_flags.executable());
        assert!(!destination_flags.executable());
    }

    #[test]
    fn residual_alias_map_failures_require_poisoning() {
        use kernal_page_table_aarch64::Error as PageTableError;

        assert!(map_failure_requires_poison(PageTableError::AlreadyMapped));
        assert!(map_failure_requires_poison(PageTableError::BackendFailure));
        assert!(map_failure_requires_poison(
            PageTableError::InvalidDescriptor
        ));
        assert!(map_failure_requires_poison(
            PageTableError::InvalidTableAddress
        ));
        assert!(!map_failure_requires_poison(PageTableError::NullPage));
        assert!(!map_failure_requires_poison(
            PageTableError::ExecutableDevice
        ));
    }

    #[test]
    fn controller_rejects_unaligned_or_out_of_range_roots() {
        // SAFETY: construction validation fails before any privileged state or mapping is touched.
        assert!(matches!(
            unsafe { KmapController::assume_active(0, 3) },
            Err(Error::InvalidRoot)
        ));
        // SAFETY: same validation-only path as above.
        assert!(matches!(
            unsafe { KmapController::assume_active(0, 1_u64 << 52) },
            Err(Error::InvalidRoot)
        ));
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    struct HostBackend;

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    impl Backend for HostBackend {
        fn allocate_zeroed_table(&mut self) -> Option<u64> {
            panic!("host kmap data operation must not mutate page tables")
        }

        fn read_entry(&self, _table_phys: u64, _index: usize) -> Option<u64> {
            panic!("host kmap data operation must not read page tables")
        }

        fn write_entry(&mut self, _table_phys: u64, _index: usize, _value: u64) -> bool {
            panic!("host kmap data operation must not mutate page tables")
        }
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    #[test]
    fn host_zeroing_fails_before_claiming_a_mapping_slot() {
        // SAFETY: this host-only test never executes privileged code; zero_frame rejects the host
        // before consulting the supplied backend or claiming a kmap slot. The dummy hierarchy cannot
        // be mutated on this host-only rejection path.
        let controller = unsafe { KmapController::assume_active(0, 0x1000) }.unwrap();
        let mut backend = HostBackend;
        assert_eq!(
            unsafe { controller.zero_frame(&mut backend, 0x20_0000) },
            Err(Error::UnsupportedHostArchitecture)
        );
        assert_eq!(controller.occupied_slots(), 0);
        assert!(!controller.is_poisoned());
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    #[test]
    fn host_copy_rejects_before_claiming_slots_or_touching_backend() {
        // SAFETY: copy_frame rejects this host before consulting the supplied backend or claiming a
        // kmap slot, and SameFrame is a pure precondition rejection with the same property.
        let controller = unsafe { KmapController::assume_active(0, 0x1000) }.unwrap();
        let mut backend = HostBackend;
        assert_eq!(
            unsafe { controller.copy_frame(&mut backend, 0x20_0000, 0x20_0000) },
            Err(Error::SameFrame)
        );
        assert_eq!(controller.occupied_slots(), 0);
        assert!(!controller.is_poisoned());
        assert_eq!(
            unsafe { controller.copy_frame(&mut backend, 0x20_0000, 0x21_0000) },
            Err(Error::UnsupportedHostArchitecture)
        );
        assert_eq!(controller.occupied_slots(), 0);
        assert!(!controller.is_poisoned());
    }
}
