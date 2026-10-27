// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod freestanding {
    use core::{marker::PhantomData, ptr::NonNull};
    use kernal_exceptions_aarch64::ExceptionFrame;
    use kernal_linux_abi::MinimumRuntimeCall;
    use kernal_linux_exit_lifecycle::ExitCoordinator;
    use kernal_linux_identity::LinuxIdentityTable;
    use kernal_linux_minimum_runtime_aarch64::CloneDriver;
    use kernal_object::ObjectTable;
    use kernal_process::{Process, ThreadObjectBindings};
    use kernal_process_aarch64::BoundProcessAddressSpace;
    use kernal_scheduler_cpu::CpuSchedulerCell;

    /// Thin Core-owned implementation of the Step-15 minimum-runtime clone port.
    ///
    /// The driver deliberately stores no Rust references to runtime owners. A minimum-runtime context
    /// may be suspended inside an unrelated FUTEX_WAIT while another thread accesses the same binding,
    /// identity or exit owners; keeping `&mut`/`&` fields here would therefore reintroduce the aliasing
    /// bug that the general composer avoids. The driver stores non-owning raw handles and materializes
    /// exactly the references required only while the synchronous clone transaction is executing.
    ///
    /// This value owns no clone semantics. The actual transaction, protected stack allocation and
    /// rollback remain in the already integrated Core/clone owners.
    pub struct CoreCloneDriver<
        const BINDINGS: usize,
        const PROCESSES: usize,
        const IDS: usize,
        const GROUPS: usize,
    > {
        bindings: NonNull<ThreadObjectBindings<BINDINGS>>,
        identities: NonNull<LinuxIdentityTable<PROCESSES, IDS>>,
        exits: NonNull<ExitCoordinator<GROUPS>>,
        priority: u8,
        _not_send_sync_contract: PhantomData<*mut ()>,
    }

    impl<const BINDINGS: usize, const PROCESSES: usize, const IDS: usize, const GROUPS: usize>
        CoreCloneDriver<BINDINGS, PROCESSES, IDS, GROUPS>
    {
        /// Binds the existing Core clone owners without retaining Rust references.
        ///
        /// # Safety
        /// `bindings`, `identities` and `exits` must remain allocated at the same addresses for every
        /// future use of this driver. Whenever `dispatch_clone` is invoked, the caller must additionally
        /// provide the canonical Core clone owner/quiescence contract and exclusive mutable authority for
        /// `bindings` and `identities` for that synchronous call. No such authority is claimed while the
        /// driver merely exists or while a surrounding minimum-runtime context is suspended in FUTEX_WAIT.
        pub unsafe fn new(
            bindings: &mut ThreadObjectBindings<BINDINGS>,
            identities: &mut LinuxIdentityTable<PROCESSES, IDS>,
            exits: &ExitCoordinator<GROUPS>,
            priority: u8,
        ) -> Self {
            Self {
                bindings: NonNull::from(bindings),
                identities: NonNull::from(identities),
                exits: NonNull::from(exits),
                priority,
                _not_send_sync_contract: PhantomData,
            }
        }
    }

    impl<
        const CAPS: usize,
        const VMAS: usize,
        const OBJECTS: usize,
        const SCHED_THREADS: usize,
        const WAKES: usize,
        const BINDINGS: usize,
        const PROCESSES: usize,
        const IDS: usize,
        const GROUPS: usize,
    > CloneDriver<CAPS, VMAS, OBJECTS, SCHED_THREADS, WAKES>
        for CoreCloneDriver<BINDINGS, PROCESSES, IDS, GROUPS>
    {
        type Error = kernal_core_aarch64::CloneDispatchError;

        unsafe fn dispatch_clone(
            &mut self,
            call: MinimumRuntimeCall,
            frame: &mut ExceptionFrame,
            process: &mut Process<CAPS>,
            address_space: &BoundProcessAddressSpace<VMAS>,
            objects: &mut ObjectTable<OBJECTS>,
            scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
        ) -> Result<(), Self::Error> {
            let bindings = self.bindings;
            let identities = self.identities;
            let exits = self.exits;

            // SAFETY: delegated caller contract is exactly the Core clone transaction contract. The
            // constructor contract guarantees these raw handles still identify the same owners. The
            // references below exist only for this synchronous clone transaction and are dropped before
            // returning; they cannot survive an unrelated FUTEX_WAIT suspension.
            unsafe {
                kernal_core_aarch64::dispatch_clone_with_core_stacks(
                    call,
                    frame,
                    process,
                    address_space,
                    objects,
                    &mut *bindings.as_ptr(),
                    &mut *identities.as_ptr(),
                    &*exits.as_ptr(),
                    scheduler,
                    self.priority,
                )
            }
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use freestanding::CoreCloneDriver;
