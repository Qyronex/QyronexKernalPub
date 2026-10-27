// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{marker::PhantomData, ptr::NonNull};
use kernal_exceptions_aarch64::ExceptionFrame;
use kernal_frame_allocator::ExtentAllocator;
use kernal_linux_abi::{MinimumRuntimeCall, SyscallReturn};
use kernal_linux_bootstrap_aarch64::{MinimumDispatchOutcome, time::ClockGettimeError};
#[cfg(target_arch = "aarch64")]
use kernal_linux_bootstrap_aarch64::{MinimumRuntimeContext, time::clock_gettime};
use kernal_linux_futex_runtime::SerializedFutexTable;
use kernal_linux_futex_trap_aarch64::Error as FutexTrapError;
use kernal_linux_vm::{Error as VmError, LinuxVmRuntime};
use kernal_linux_vm_aarch64::AnonymousPageZeroer;
use kernal_memory::ReservationSet;
use kernal_object::ObjectTable;
use kernal_page_table_aarch64::Backend;
use kernal_process::Process;
use kernal_process_aarch64::BoundProcessAddressSpace;
use kernal_scheduler_cpu::CpuSchedulerCell;
#[cfg(target_arch = "aarch64")]
use kernal_scheduler_smp::GlobalThreadId;

/// Narrow owner port for the already-integrated AArch64 clone transaction.
///
/// Providers must be `'static`: the outer composer may be suspended by FUTEX_WAIT, so a provider
/// must not smuggle a shorter-lived Rust reference across a context switch. Concrete providers keep
/// runtime owners behind stable raw/static handles and materialize borrows only for the synchronous
/// clone transaction.
pub trait CloneDriver<
    const CAPS: usize,
    const VMAS: usize,
    const OBJECTS: usize,
    const SCHED_THREADS: usize,
    const WAKES: usize,
>: 'static
{
    type Error;

    /// Executes one already-classified clone call and commits its Linux-visible frame result.
    ///
    /// # Safety
    /// The caller must retain the owner/quiescence and current Process/TTBR0 contract required by
    /// the concrete clone transaction for the complete call. The implementation must not switch the
    /// current parent or retain any reference received by this method.
    unsafe fn dispatch_clone(
        &mut self,
        call: MinimumRuntimeCall,
        frame: &mut ExceptionFrame,
        process: &mut Process<CAPS>,
        address_space: &BoundProcessAddressSpace<VMAS>,
        objects: &mut ObjectTable<OBJECTS>,
        scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
    ) -> Result<(), Self::Error>;
}

/// Fatal runtime failures that must not be downgraded to Linux errno.
#[derive(Debug, Eq, PartialEq)]
pub enum Error<WAKE, CLONE> {
    Vm(VmError),
    Clock(ClockGettimeError),
    Futex(FutexTrapError<WAKE>),
    Clone(CLONE),
    Invariant,
}

/// Concrete AArch64 implementation of the accepted minimum-runtime dispatcher boundary.
///
/// The context stores non-owning raw owner handles rather than long-lived Rust references. This is
/// required because FUTEX_WAIT can suspend this stack frame while another thread runs. Each
/// synchronous branch materializes only the references it needs and drops them before returning.
/// The futex branch forwards raw Process/address-space/frame handles to the accepted raw-owner trap
/// boundary, so no Process/address-space Rust borrow remains live while the current thread blocks.
///
/// A context value is per invocation or per thread; it must never be reused concurrently as a shared
/// process-global mutable object. It owns no subsystem state and introduces no second VM, scheduler,
/// futex queue, clone lifecycle, Process/TID registry, or usercopy path.
pub struct Aarch64MinimumRuntimeContext<
    const BREAKS: usize,
    const TX_PAGES: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    const EXTENTS: usize,
    const SCHED_THREADS: usize,
    const WAKES: usize,
    const FUTEX_BUCKETS: usize,
    const FUTEX_WAITERS: usize,
    B,
    Z,
    D,
    C,
> {
    vm: NonNull<LinuxVmRuntime<BREAKS, TX_PAGES>>,
    process: NonNull<Process<CAPS>>,
    objects: NonNull<ObjectTable<OBJECTS>>,
    address_space: NonNull<BoundProcessAddressSpace<VMAS>>,
    page_tables: NonNull<B>,
    reserved: NonNull<ReservationSet<RESERVED>>,
    frames: NonNull<ExtentAllocator<EXTENTS>>,
    zeroer: NonNull<Z>,
    scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
    futexes: NonNull<SerializedFutexTable<FUTEX_BUCKETS, FUTEX_WAITERS>>,
    deliver_wake: NonNull<D>,
    clone: NonNull<C>,
    _not_send_sync_contract: PhantomData<*mut ()>,
}

impl<
    const BREAKS: usize,
    const TX_PAGES: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    const EXTENTS: usize,
    const SCHED_THREADS: usize,
    const WAKES: usize,
    const FUTEX_BUCKETS: usize,
    const FUTEX_WAITERS: usize,
    B,
    Z,
    D,
    C,
>
    Aarch64MinimumRuntimeContext<
        BREAKS,
        TX_PAGES,
        CAPS,
        OBJECTS,
        VMAS,
        RESERVED,
        EXTENTS,
        SCHED_THREADS,
        WAKES,
        FUTEX_BUCKETS,
        FUTEX_WAITERS,
        B,
        Z,
        D,
        C,
    >
where
    B: Backend + 'static,
    Z: AnonymousPageZeroer<B> + 'static,
    D: 'static,
    C: 'static,
{
    /// Binds the canonical Step-15 owners as stable non-owning handles.
    ///
    /// No Rust reference passed here is retained. Generic provider types are also required to be
    /// `'static`, preventing them from transitively retaining shorter-lived references.
    ///
    /// # Safety
    /// Every referent must remain allocated at the same address until this context is retired. Before
    /// each dispatch, the caller must provide the owner/quiescence contract required by the selected
    /// canonical handler: local IRQ delivery masked, `irq_depth=0`, `preempt_count=0`, migration
    /// suppressed, and the current Process/TTBR0 binding stable where required. VM and clone calls
    /// additionally require exclusive access to their exact mutable owners for the synchronous call.
    /// FUTEX_WAIT deliberately claims none of those unrelated owners while blocked. The wake route
    /// must be uniquely callable during nonblocking FUTEX_WAKE delivery.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        vm: &mut LinuxVmRuntime<BREAKS, TX_PAGES>,
        process: &mut Process<CAPS>,
        objects: &mut ObjectTable<OBJECTS>,
        address_space: &mut BoundProcessAddressSpace<VMAS>,
        page_tables: &mut B,
        reserved: &ReservationSet<RESERVED>,
        frames: &mut ExtentAllocator<EXTENTS>,
        zeroer: &mut Z,
        scheduler: &'static CpuSchedulerCell<SCHED_THREADS, WAKES>,
        futexes: &SerializedFutexTable<FUTEX_BUCKETS, FUTEX_WAITERS>,
        deliver_wake: &mut D,
        clone: &mut C,
    ) -> Self {
        Self {
            vm: NonNull::from(vm),
            process: NonNull::from(process),
            objects: NonNull::from(objects),
            address_space: NonNull::from(address_space),
            page_tables: NonNull::from(page_tables),
            reserved: NonNull::from(reserved),
            frames: NonNull::from(frames),
            zeroer: NonNull::from(zeroer),
            scheduler,
            futexes: NonNull::from(futexes),
            deliver_wake: NonNull::from(deliver_wake),
            clone: NonNull::from(clone),
            _not_send_sync_contract: PhantomData,
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl<
    const BREAKS: usize,
    const TX_PAGES: usize,
    const CAPS: usize,
    const OBJECTS: usize,
    const VMAS: usize,
    const RESERVED: usize,
    const EXTENTS: usize,
    const SCHED_THREADS: usize,
    const WAKES: usize,
    const FUTEX_BUCKETS: usize,
    const FUTEX_WAITERS: usize,
    B,
    Z,
    D,
    WAKE,
    C,
> MinimumRuntimeContext
    for Aarch64MinimumRuntimeContext<
        BREAKS,
        TX_PAGES,
        CAPS,
        OBJECTS,
        VMAS,
        RESERVED,
        EXTENTS,
        SCHED_THREADS,
        WAKES,
        FUTEX_BUCKETS,
        FUTEX_WAITERS,
        B,
        Z,
        D,
        C,
    >
where
    B: Backend + 'static,
    Z: AnonymousPageZeroer<B> + 'static,
    D: FnMut(GlobalThreadId) -> Result<(), WAKE> + 'static,
    C: CloneDriver<CAPS, VMAS, OBJECTS, SCHED_THREADS, WAKES> + 'static,
{
    type Error = Error<WAKE, C::Error>;

    fn dispatch_minimum(
        &mut self,
        call: MinimumRuntimeCall,
        frame: &mut ExceptionFrame,
    ) -> Result<MinimumDispatchOutcome, Self::Error> {
        match call {
            MinimumRuntimeCall::Mmap { .. }
            | MinimumRuntimeCall::Munmap { .. }
            | MinimumRuntimeCall::Mprotect { .. }
            | MinimumRuntimeCall::Brk { .. } => {
                let vm = self.vm;
                let process = self.process;
                let objects = self.objects;
                let address_space = self.address_space;
                let page_tables = self.page_tables;
                let reserved = self.reserved;
                let frames = self.frames;
                let zeroer = self.zeroer;

                // SAFETY: constructor obligations keep every handle valid. This synchronous VM arm
                // exclusively reborrows exactly the mutable owners it needs; no reference escapes.
                let result = unsafe {
                    kernal_linux_vm_aarch64::handle_current(
                        &mut *vm.as_ptr(),
                        &*process.as_ptr(),
                        &*objects.as_ptr(),
                        &mut *address_space.as_ptr(),
                        &mut *page_tables.as_ptr(),
                        &*reserved.as_ptr(),
                        &mut *frames.as_ptr(),
                        &mut *zeroer.as_ptr(),
                        call,
                    )
                };
                map_vm_result(result)
            }
            MinimumRuntimeCall::ClockGettime {
                clock_id,
                user_timespec,
            } => map_clock_result(clock_gettime(clock_id, user_timespec)),
            MinimumRuntimeCall::Futex { .. } => {
                let process = self.process;
                let address_space = self.address_space;
                let futexes = self.futexes;
                let deliver = self.deliver_wake;
                let frame = NonNull::from(&mut *frame);

                // SAFETY: only stable raw handles cross a possible WAIT switch. The raw futex owner
                // creates Process/address-space/frame references solely in short synchronous windows.
                // The closure dereferences the wake route only during nonblocking FUTEX_WAKE.
                unsafe {
                    kernal_linux_futex_trap_aarch64::dispatch_private_futex_raw(
                        process,
                        address_space,
                        frame,
                        self.scheduler,
                        &*futexes.as_ptr(),
                        call,
                        move |target| (&mut *deliver.as_ptr())(target),
                    )
                }
                .map_err(Error::Futex)?;
                Ok(MinimumDispatchOutcome::FrameCommitted)
            }
            MinimumRuntimeCall::Clone { .. } => {
                let clone = self.clone;
                let process = self.process;
                let address_space = self.address_space;
                let objects = self.objects;

                // SAFETY: the references exist only for the synchronous accepted clone transaction;
                // the CloneDriver contract forbids retaining them or switching the current parent.
                unsafe {
                    (&mut *clone.as_ptr()).dispatch_clone(
                        call,
                        frame,
                        &mut *process.as_ptr(),
                        &*address_space.as_ptr(),
                        &mut *objects.as_ptr(),
                        self.scheduler,
                    )
                }
                .map_err(Error::Clone)?;
                Ok(MinimumDispatchOutcome::FrameCommitted)
            }
        }
    }
}

fn map_vm_result<WAKE, CLONE>(
    result: Result<u64, VmError>,
) -> Result<MinimumDispatchOutcome, Error<WAKE, CLONE>> {
    match result {
        Ok(value) => {
            let signed = i64::try_from(value).map_err(|_| Error::Invariant)?;
            let result = SyscallReturn::success(signed).ok_or(Error::Invariant)?;
            Ok(MinimumDispatchOutcome::Return(result))
        }
        Err(VmError::Linux(errno)) => {
            Ok(MinimumDispatchOutcome::Return(SyscallReturn::error(errno)))
        }
        Err(error) => Err(Error::Vm(error)),
    }
}

fn map_clock_result<WAKE, CLONE>(
    result: Result<SyscallReturn, ClockGettimeError>,
) -> Result<MinimumDispatchOutcome, Error<WAKE, CLONE>> {
    match result {
        Ok(result) => Ok(MinimumDispatchOutcome::Return(result)),
        Err(ClockGettimeError::Errno(errno)) => {
            Ok(MinimumDispatchOutcome::Return(SyscallReturn::error(errno)))
        }
        Err(error) => Err(Error::Clock(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_abi::Errno;

    #[test]
    fn vm_linux_errno_is_returned_but_backend_failure_stays_fatal() {
        assert_eq!(
            map_vm_result::<(), ()>(Err(VmError::Linux(Errno::EINVAL))),
            Ok(MinimumDispatchOutcome::Return(SyscallReturn::error(
                Errno::EINVAL
            )))
        );
        assert_eq!(
            map_vm_result::<(), ()>(Err(VmError::BackendInvariant)),
            Err(Error::Vm(VmError::BackendInvariant))
        );
    }

    #[test]
    fn vm_success_rejects_values_outside_signed_linux_success_domain() {
        assert_eq!(
            map_vm_result::<(), ()>(Ok(0x0000_7fff_ffff_f000)),
            Ok(MinimumDispatchOutcome::Return(
                SyscallReturn::success(0x0000_7fff_ffff_f000).unwrap()
            ))
        );
        assert_eq!(map_vm_result::<(), ()>(Ok(u64::MAX)), Err(Error::Invariant));
    }

    #[test]
    fn clock_request_errno_is_returned_without_hiding_privileged_failure() {
        assert_eq!(
            map_clock_result::<(), ()>(Err(ClockGettimeError::Errno(Errno::EFAULT))),
            Ok(MinimumDispatchOutcome::Return(SyscallReturn::error(
                Errno::EFAULT
            )))
        );
    }
}
