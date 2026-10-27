// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::{asm, global_asm};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_exceptions_aarch64::{CurrentElAarch64Synchronous, ExceptionFrame, ExceptionSource};
use kernal_usercopy::{Error, UserRange};

const ID_AA64MMFR1_PAN_SHIFT: u32 = 20;
const ID_AA64MMFR1_PAN_MASK: u64 = 0xf;
const ATOMIC_U32_BYTES: usize = core::mem::size_of::<u32>();
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const ATOMIC_U32_CAS_RETRIES: u32 = 64;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const PSTATE_PAN_BIT: u64 = 1 << 22;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const FAULT_HANDLER_UNINSTALLED: u8 = 0;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const FAULT_HANDLER_INSTALLING: u8 = 1;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const FAULT_HANDLER_INSTALLED: u8 = 2;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static FAULT_HANDLER_STATE: AtomicU8 = AtomicU8::new(FAULT_HANDLER_UNINSTALLED);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicU32LoadError {
    Unaligned,
    Usercopy(Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicU32CompareExchangeError {
    Unaligned,
    Contended,
    Usercopy(Error),
}

/// Successful fault-safe compare/exchange observation for one user u32.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicU32CompareExchange {
    observed: u32,
    exchanged: bool,
}

impl AtomicU32CompareExchange {
    pub const fn observed(self) -> u32 {
        self.observed
    }

    pub const fn exchanged(self) -> bool {
        self.exchanged
    }
}

/// Result of a bounded copy into userspace when the destination faults after a valid prefix.
///
/// A recoverable user destination fault is not itself an API error here: `copied` is the exact
/// prefix already transferred and `faulted` reports that the requested range was not completed.
/// PAN/fault-handler/range invariants remain ordinary [`Error`] failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyToUserProgress {
    copied: usize,
    faulted: bool,
}

impl CopyToUserProgress {
    pub const fn copied(self) -> usize {
        self.copied
    }

    pub const fn faulted(self) -> bool {
        self.faulted
    }

    pub const fn complete(self) -> bool {
        !self.faulted
    }
}

pub const fn pan_level_from_mmfr1(raw: u64) -> u8 {
    ((raw >> ID_AA64MMFR1_PAN_SHIFT) & ID_AA64MMFR1_PAN_MASK) as u8
}

pub const fn pan_level_supported(level: u8) -> bool {
    matches!(level, 1..=3)
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const fn pan_bit_set(raw: u64) -> bool {
    raw & PSTATE_PAN_BIT != 0
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const fn is_recoverable_usercopy_fault_status(fault_status: u8) -> bool {
    matches!(
        fault_status,
        0x04..=0x07 | 0x09..=0x0b | 0x0d..=0x0f
    )
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
const fn is_permission_fault_status(fault_status: u8) -> bool {
    matches!(fault_status, 0x0d..=0x0f)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn read_id_aa64mmfr1_el1() -> u64 {
    let value: u64;
    // SAFETY: ID_AA64MMFR1_EL1 is a read-only feature register available at EL1.
    unsafe {
        asm!(
            "mrs {value}, ID_AA64MMFR1_EL1",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn pan_supported() -> bool {
    pan_level_supported(pan_level_from_mmfr1(read_id_aa64mmfr1_el1()))
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub const fn pan_supported() -> bool {
    false
}

/// Enables Step-10 default-deny privileged user access for the current PE.
///
/// This establishes both halves of the policy: `SCTLR_EL1.SPAN=0` makes every later exception entry
/// to EL1 force `PSTATE.PAN=1`, and the explicit PAN write closes access immediately on the current
/// path. Every supported PE must call this before it may execute code that can observe a userspace
/// mapping. Intentional access is permitted only through the bounded helpers below.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn enable_pan_default() -> Result<(), Error> {
    if !pan_supported() {
        return Err(Error::PanUnavailable);
    }

    // SAFETY: FEAT_PAN was verified above, so SCTLR_EL1.SPAN is implemented and may be cleared.
    // The caller executes in the PE-local EL1 runtime before exposing normal user-access paths.
    unsafe { kernal_page_table_aarch64::enable_pan_exception_entry() };
    if !kernal_page_table_aarch64::pan_exception_entry_is_enabled() {
        return Err(Error::PanStateLeak);
    }

    // PAN is an Armv8.1 architectural extension. The freestanding target does not advertise the
    // `+pan` assembler feature, so use the architectural encoding instead of the feature-gated
    // `msr PAN, #1` alias. 0xd500419f == SET_PSTATE_PAN(1).
    unsafe { asm!(".inst 0xd500419f", "isb", options(nostack, preserves_flags)) };
    if !pan_enabled()? {
        return Err(Error::PanStateLeak);
    }
    Ok(())
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn enable_pan_default() -> Result<(), Error> {
    Err(Error::PanUnavailable)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn pan_enabled() -> Result<bool, Error> {
    if !pan_supported() {
        return Err(Error::PanUnavailable);
    }
    let value: u64;
    // 0xd5384269 is `mrs x9, PAN`. Hard-code the destination register so the raw encoding stays
    // independent from assembler feature aliases while Rust still reserves x9 for the output.
    unsafe {
        asm!(
            ".inst 0xd5384269",
            lateout("x9") value,
            options(nomem, nostack, preserves_flags)
        )
    };
    Ok(pan_bit_set(value))
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn pan_enabled() -> Result<bool, Error> {
    Err(Error::PanUnavailable)
}

/// Feature-gated runtime proof that a direct EL1 read of a valid EL0 mapping is denied while PAN is
/// in its default-on state. This is stronger than an `AT` preflight because it executes the actual
/// load and requires the current-EL data-abort path to redirect only the exact proof instruction.
///
/// # Safety
/// The caller must own the active EL0 address space and keep `user_address` mapped user-readable for
/// the duration of the probe. The caller must also keep scheduler migration and asynchronous entry
/// suppressed while the temporary proof address space is active.
#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
pub unsafe fn qemu_probe_pan_blocks_read(user_address: u64) -> Result<bool, Error> {
    let range = UserRange::new(user_address, 1)?;
    initialize_current_pe()?;
    if !pan_enabled()? || !kernal_page_table_aarch64::pan_exception_entry_is_enabled() {
        return Err(Error::PanStateLeak);
    }

    // SAFETY: delegated to the proof contract above. The assembly performs one direct user load
    // while PAN remains set and returns 1 only through the exact registered fault-fixup label.
    let faulted = unsafe { kernal_qemu_probe_pan_read_aarch64(range.start() as *const u8) };
    if !pan_enabled()? || !kernal_page_table_aarch64::pan_exception_entry_is_enabled() {
        return Err(Error::PanStateLeak);
    }
    Ok(faulted != 0)
}

/// Atomically loads one naturally aligned 32-bit value from the active EL0 address space.
///
/// The freestanding AArch64 implementation executes exactly one aligned `ldr wN, [user]` while the
/// existing Step-10 PAN window is open. A naturally aligned 32-bit load from normal user memory is
/// single-copy atomic, which is the minimum primitive required by Linux private futex value checks.
/// The exact load instruction is registered with the existing current-EL usercopy fault handler, so
/// an unmapped or permission-faulting source returns `Error::Fault` instead of escaping the policy.
pub fn load_atomic_u32_from_user(user_source: u64) -> Result<u32, AtomicU32LoadError> {
    if user_source & (ATOMIC_U32_BYTES as u64 - 1) != 0 {
        return Err(AtomicU32LoadError::Unaligned);
    }
    let range =
        UserRange::new(user_source, ATOMIC_U32_BYTES).map_err(AtomicU32LoadError::Usercopy)?;

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        initialize_current_pe().map_err(AtomicU32LoadError::Usercopy)?;
        let mut value = 0_u32;
        // SAFETY: the complete aligned four-byte user range was validated above. The raw helper has
        // exactly one user load fault site and stores only into this live kernel-local `value`.
        let faulted = unsafe {
            with_user_access_window(|| {
                kernal_load_atomic_u32_from_user_aarch64(
                    core::ptr::addr_of_mut!(value),
                    range.start() as *const u32,
                )
            })
            .map_err(AtomicU32LoadError::Usercopy)?
        };
        if !pan_enabled().map_err(AtomicU32LoadError::Usercopy)? {
            return Err(AtomicU32LoadError::Usercopy(Error::PanStateLeak));
        }
        if faulted != 0 {
            return Err(AtomicU32LoadError::Usercopy(Error::Fault));
        }
        Ok(value)
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = range;
        Err(AtomicU32LoadError::Usercopy(Error::PanUnavailable))
    }
}

/// Fault-safely compares and conditionally replaces one naturally aligned userspace u32.
///
/// The AArch64 implementation executes the complete owner-checked read/modify/write inside the
/// existing PAN window using `LDAXR`/`STLXR`. Both user-access instructions are registered exact
/// fault sites. A mismatched value is returned without a store; a matching value is replaced only
/// after the exclusive store succeeds. Exclusive-store contention is bounded so hostile userspace
/// cannot hold EL1 in an unbounded retry loop while interrupts are masked.
pub fn compare_exchange_atomic_u32_in_user(
    user_address: u64,
    expected: u32,
    replacement: u32,
) -> Result<AtomicU32CompareExchange, AtomicU32CompareExchangeError> {
    if user_address & (ATOMIC_U32_BYTES as u64 - 1) != 0 {
        return Err(AtomicU32CompareExchangeError::Unaligned);
    }
    let range = UserRange::new(user_address, ATOMIC_U32_BYTES)
        .map_err(AtomicU32CompareExchangeError::Usercopy)?;

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        initialize_current_pe().map_err(AtomicU32CompareExchangeError::Usercopy)?;
        let mut observed = 0_u32;
        // SAFETY: the complete aligned four-byte user range was validated above. The raw helper uses
        // only its registered LDAXR/STLXR fault sites and writes the observation to this live kernel
        // local before reporting success/mismatch.
        let status = unsafe {
            with_user_access_window(|| {
                kernal_compare_exchange_u32_in_user_aarch64(
                    core::ptr::addr_of_mut!(observed),
                    range.start() as *mut u32,
                    expected,
                    replacement,
                    ATOMIC_U32_CAS_RETRIES,
                )
            })
            .map_err(AtomicU32CompareExchangeError::Usercopy)?
        };
        if !pan_enabled().map_err(AtomicU32CompareExchangeError::Usercopy)? {
            return Err(AtomicU32CompareExchangeError::Usercopy(Error::PanStateLeak));
        }
        match status {
            0 => Ok(AtomicU32CompareExchange {
                observed,
                exchanged: observed == expected,
            }),
            1 => Err(AtomicU32CompareExchangeError::Usercopy(Error::Fault)),
            2 => Err(AtomicU32CompareExchangeError::Contended),
            _ => Err(AtomicU32CompareExchangeError::Usercopy(Error::Fault)),
        }
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = (range, expected, replacement);
        Err(AtomicU32CompareExchangeError::Usercopy(
            Error::PanUnavailable,
        ))
    }
}

/// Copies a bounded byte slice from the active EL0 address space into kernel memory.
///
/// The source range is validated before access. The exact user load instruction is a registered
/// current-EL fault site, so an unmapped/permission-faulting user source returns [`Error::Fault`]
/// while a fault on the kernel destination store remains an unrelated fatal kernel exception.
pub fn copy_from_user(destination: &mut [u8], user_source: u64) -> Result<(), Error> {
    let range = UserRange::new(user_source, destination.len())?;
    if range.is_empty() {
        return Ok(());
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        initialize_current_pe()?;
        // SAFETY: UserRange validated the complete source range and destination is a live unique
        // kernel slice. The raw helper exposes only its source load as a recoverable fault site.
        let faulted = unsafe {
            with_user_access_window(|| {
                kernal_copy_from_user_aarch64(
                    destination.as_mut_ptr(),
                    range.start() as *const u8,
                    range.len(),
                )
            })?
        };
        if !pan_enabled()? {
            return Err(Error::PanStateLeak);
        }
        if faulted != 0 {
            return Err(Error::Fault);
        }
        Ok(())
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = range;
        Err(Error::PanUnavailable)
    }
}

/// Copies a bounded kernel byte slice into the active EL0 address space and reports an exact
/// successfully transferred prefix when the destination faults.
///
/// The assembly loop keeps the not-yet-copied byte count in `x2`. The registered destination-store
/// fault site redirects before `x2` is decremented, so the fixup returns the exact remaining count.
/// This preserves the existing PAN/fault-site authority while allowing Linux `read(2)` to commit its
/// shared file offset by exactly the bytes userspace actually received.
pub fn copy_to_user_progress(
    user_destination: u64,
    source: &[u8],
) -> Result<CopyToUserProgress, Error> {
    let range = UserRange::new(user_destination, source.len())?;
    if range.is_empty() {
        return Ok(CopyToUserProgress {
            copied: 0,
            faulted: false,
        });
    }

    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        initialize_current_pe()?;
        // SAFETY: UserRange validated the complete destination range and source is a live kernel
        // slice. The raw helper returns zero on completion or the exact remaining byte count from
        // the registered user-store fault fixup.
        let remaining = unsafe {
            with_user_access_window(|| {
                kernal_copy_to_user_aarch64(range.start() as *mut u8, source.as_ptr(), range.len())
            })?
        };
        if !pan_enabled()? {
            return Err(Error::PanStateLeak);
        }
        let remaining = usize::try_from(remaining).map_err(|_| Error::Fault)?;
        progress_from_remaining(range.len(), remaining)
    }

    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        let _ = range;
        Err(Error::PanUnavailable)
    }
}

/// Copies a bounded kernel byte slice into the active EL0 address space.
///
/// This preserves the original all-or-error API for existing callers. New transactional callers
/// that must account for a successful prefix should use [`copy_to_user_progress`].
pub fn copy_to_user(user_destination: u64, source: &[u8]) -> Result<(), Error> {
    let progress = copy_to_user_progress(user_destination, source)?;
    if progress.faulted() {
        Err(Error::Fault)
    } else {
        Ok(())
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
fn progress_from_remaining(
    requested: usize,
    remaining: usize,
) -> Result<CopyToUserProgress, Error> {
    let copied = requested.checked_sub(remaining).ok_or(Error::Fault)?;
    Ok(CopyToUserProgress {
        copied,
        faulted: remaining != 0,
    })
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn initialize_current_pe() -> Result<(), Error> {
    enable_pan_default()?;
    ensure_fault_handler_installed()
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn ensure_fault_handler_installed() -> Result<(), Error> {
    loop {
        match FAULT_HANDLER_STATE.load(Ordering::Acquire) {
            FAULT_HANDLER_INSTALLED => return Ok(()),
            FAULT_HANDLER_UNINSTALLED => {
                if FAULT_HANDLER_STATE
                    .compare_exchange(
                        FAULT_HANDLER_UNINSTALLED,
                        FAULT_HANDLER_INSTALLING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }

                let installed = kernal_exceptions_aarch64::install_current_el_aarch64_handler(
                    usercopy_current_el_handler,
                )
                .is_ok();
                FAULT_HANDLER_STATE.store(
                    if installed {
                        FAULT_HANDLER_INSTALLED
                    } else {
                        FAULT_HANDLER_UNINSTALLED
                    },
                    Ordering::Release,
                );
                return if installed {
                    Ok(())
                } else {
                    Err(Error::FaultHandlerUnavailable)
                };
            }
            FAULT_HANDLER_INSTALLING => core::hint::spin_loop(),
            _ => return Err(Error::FaultHandlerUnavailable),
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
extern "C" fn usercopy_current_el_handler(frame: &mut ExceptionFrame) -> bool {
    if frame.source() != ExceptionSource::CurrentElSpx {
        return false;
    }
    let Some(CurrentElAarch64Synchronous::DataAbort {
        fault_status,
        write,
        fault_address: Some(fault_address),
    }) = frame.current_el_aarch64_synchronous()
    else {
        return false;
    };
    if UserRange::new(fault_address, 1).is_err() {
        return false;
    }

    let atomic_u32_site = symbol_address(core::ptr::addr_of!(kernal_load_atomic_u32_fault_site));
    let cas_load_site = symbol_address(core::ptr::addr_of!(
        kernal_compare_exchange_u32_load_fault_site
    ));
    let cas_store_site = symbol_address(core::ptr::addr_of!(
        kernal_compare_exchange_u32_store_fault_site
    ));
    let from_site = symbol_address(core::ptr::addr_of!(kernal_copy_from_user_fault_site));
    let to_site = symbol_address(core::ptr::addr_of!(kernal_copy_to_user_fault_site));
    let fixup = if !write
        && frame.elr_el1 == atomic_u32_site
        && is_recoverable_usercopy_fault_status(fault_status)
    {
        Some(symbol_address(core::ptr::addr_of!(
            kernal_load_atomic_u32_fault_fixup
        )))
    } else if ((!write && frame.elr_el1 == cas_load_site)
        || (write && frame.elr_el1 == cas_store_site))
        && is_recoverable_usercopy_fault_status(fault_status)
    {
        Some(symbol_address(core::ptr::addr_of!(
            kernal_compare_exchange_u32_fault_fixup
        )))
    } else if !write
        && frame.elr_el1 == from_site
        && is_recoverable_usercopy_fault_status(fault_status)
    {
        Some(symbol_address(core::ptr::addr_of!(
            kernal_copy_from_user_fault_fixup
        )))
    } else if write
        && frame.elr_el1 == to_site
        && is_recoverable_usercopy_fault_status(fault_status)
    {
        Some(symbol_address(core::ptr::addr_of!(
            kernal_copy_to_user_fault_fixup
        )))
    } else {
        #[cfg(feature = "qemu-proof")]
        {
            let pan_site = symbol_address(core::ptr::addr_of!(kernal_qemu_pan_read_fault_site));
            if !write
                && frame.elr_el1 == pan_site
                && is_permission_fault_status(fault_status)
                && frame.spsr_el1 & PSTATE_PAN_BIT != 0
            {
                Some(symbol_address(core::ptr::addr_of!(
                    kernal_qemu_pan_read_fault_fixup
                )))
            } else {
                None
            }
        }
        #[cfg(not(feature = "qemu-proof"))]
        {
            None
        }
    };
    let Some(fixup) = fixup else {
        return false;
    };

    // The fault happened at an explicitly registered user-access site. Protect the Rust exception
    // path immediately, and make ERET preserve PAN=1 while returning to the assembly fixup label.
    unsafe { asm!(".inst 0xd500419f", "isb", options(nostack, preserves_flags)) };
    frame.spsr_el1 |= PSTATE_PAN_BIT;
    frame.elr_el1 = fixup;
    true
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn symbol_address(symbol: *const u8) -> u64 {
    symbol as u64
}

/// Runs one bounded operation with EL1 access to EL0 mappings intentionally enabled.
///
/// # Safety
/// `operation` must access only the already validated user range owned by its caller. It must not
/// block, schedule, enable interrupts or call arbitrary code. The current-EL fixup handler restores
/// PAN in both current PSTATE and SPSR_EL1 before redirecting a known user-access fault to the raw
/// helper's recovery label.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe fn with_user_access_window<R>(operation: impl FnOnce() -> R) -> Result<R, Error> {
    if !pan_supported() {
        return Err(Error::PanUnavailable);
    }
    if !pan_enabled()? || !kernal_page_table_aarch64::pan_exception_entry_is_enabled() {
        return Err(Error::PanStateLeak);
    }

    let saved_daif: u64;
    // SAFETY: reading and then masking DAIF prevents timer/SGI scheduling entry while PAN is open.
    unsafe {
        asm!(
            "mrs {saved}, DAIF",
            "msr DAIFSet, #0xf",
            saved = out(reg) saved_daif,
            options(nostack, preserves_flags)
        )
    };

    // SAFETY: this is the one intentional Step-10 privileged user-access window.
    // 0xd500409f == SET_PSTATE_PAN(0).
    unsafe { asm!(".inst 0xd500409f", "isb", options(nostack, preserves_flags)) };

    let result = operation();

    // Restore default denial before any asynchronous exception or scheduler path can run again.
    unsafe {
        asm!(
            ".inst 0xd500419f",
            "isb",
            "msr DAIF, {saved}",
            "isb",
            saved = in(reg) saved_daif,
            options(nostack, preserves_flags)
        )
    };
    Ok(result)
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn kernal_load_atomic_u32_from_user_aarch64(destination: *mut u32, source: *const u32) -> u64;
    fn kernal_compare_exchange_u32_in_user_aarch64(
        observed: *mut u32,
        address: *mut u32,
        expected: u32,
        replacement: u32,
        retries: u32,
    ) -> u64;
    fn kernal_copy_from_user_aarch64(destination: *mut u8, source: *const u8, len: usize) -> u64;
    fn kernal_copy_to_user_aarch64(destination: *mut u8, source: *const u8, len: usize) -> u64;
    static kernal_load_atomic_u32_fault_site: u8;
    static kernal_load_atomic_u32_fault_fixup: u8;
    static kernal_compare_exchange_u32_load_fault_site: u8;
    static kernal_compare_exchange_u32_store_fault_site: u8;
    static kernal_compare_exchange_u32_fault_fixup: u8;
    static kernal_copy_from_user_fault_site: u8;
    static kernal_copy_from_user_fault_fixup: u8;
    static kernal_copy_to_user_fault_site: u8;
    static kernal_copy_to_user_fault_fixup: u8;
}

#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn kernal_qemu_probe_pan_read_aarch64(source: *const u8) -> u64;
    static kernal_qemu_pan_read_fault_site: u8;
    static kernal_qemu_pan_read_fault_fixup: u8;
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
global_asm!(
    r#"
    .section .text.kernal_usercopy_aarch64, "ax"
    .global kernal_load_atomic_u32_from_user_aarch64
    .type kernal_load_atomic_u32_from_user_aarch64, %function
kernal_load_atomic_u32_from_user_aarch64:
    .global kernal_load_atomic_u32_fault_site
kernal_load_atomic_u32_fault_site:
    ldr w2, [x1]
    str w2, [x0]
    mov x0, #0
    ret
    .global kernal_load_atomic_u32_fault_fixup
kernal_load_atomic_u32_fault_fixup:
    mov x0, #1
    ret

    .global kernal_compare_exchange_u32_in_user_aarch64
    .type kernal_compare_exchange_u32_in_user_aarch64, %function
kernal_compare_exchange_u32_in_user_aarch64:
.Lcas_retry:
    .global kernal_compare_exchange_u32_load_fault_site
kernal_compare_exchange_u32_load_fault_site:
    ldaxr w5, [x1]
    str w5, [x0]
    cmp w5, w2
    b.ne .Lcas_mismatch
    .global kernal_compare_exchange_u32_store_fault_site
kernal_compare_exchange_u32_store_fault_site:
    stlxr w6, w3, [x1]
    cbz w6, .Lcas_success
    subs w4, w4, #1
    b.ne .Lcas_retry
    clrex
    mov x0, #2
    ret
.Lcas_mismatch:
    clrex
.Lcas_success:
    mov x0, #0
    ret
    .global kernal_compare_exchange_u32_fault_fixup
kernal_compare_exchange_u32_fault_fixup:
    clrex
    mov x0, #1
    ret

    .global kernal_copy_from_user_aarch64
    .type kernal_copy_from_user_aarch64, %function
kernal_copy_from_user_aarch64:
    cbz x2, .Lcopy_from_success
.Lcopy_from_loop:
    .global kernal_copy_from_user_fault_site
kernal_copy_from_user_fault_site:
    ldrb w3, [x1], #1
    strb w3, [x0], #1
    subs x2, x2, #1
    b.ne .Lcopy_from_loop
.Lcopy_from_success:
    mov x0, #0
    ret
    .global kernal_copy_from_user_fault_fixup
kernal_copy_from_user_fault_fixup:
    mov x0, #1
    ret

    .global kernal_copy_to_user_aarch64
    .type kernal_copy_to_user_aarch64, %function
kernal_copy_to_user_aarch64:
    cbz x2, .Lcopy_to_success
.Lcopy_to_loop:
    ldrb w3, [x1], #1
    .global kernal_copy_to_user_fault_site
kernal_copy_to_user_fault_site:
    strb w3, [x0], #1
    subs x2, x2, #1
    b.ne .Lcopy_to_loop
.Lcopy_to_success:
    mov x0, #0
    ret
    .global kernal_copy_to_user_fault_fixup
kernal_copy_to_user_fault_fixup:
    mov x0, x2
    ret
"#
);

#[cfg(all(feature = "qemu-proof", target_arch = "aarch64", target_os = "none"))]
global_asm!(
    r#"
    .section .text.kernal_usercopy_pan_qemu_aarch64, "ax"
    .global kernal_qemu_probe_pan_read_aarch64
    .type kernal_qemu_probe_pan_read_aarch64, %function
kernal_qemu_probe_pan_read_aarch64:
    mov x1, x0
    mov x0, #0
    .global kernal_qemu_pan_read_fault_site
kernal_qemu_pan_read_fault_site:
    ldrb w2, [x1]
    ret
    .global kernal_qemu_pan_read_fault_fixup
kernal_qemu_pan_read_fault_fixup:
    mov x0, #1
    ret
"#
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pan_feature_field_is_decoded_fail_closed() {
        assert_eq!(pan_level_from_mmfr1(0), 0);
        assert!(!pan_level_supported(0));
        for level in 1..=3 {
            assert!(pan_level_supported(level));
            assert_eq!(
                pan_level_from_mmfr1((level as u64) << ID_AA64MMFR1_PAN_SHIFT),
                level
            );
        }
        assert!(!pan_level_supported(4));
        assert!(!pan_level_supported(0xf));
    }

    #[test]
    fn pan_register_readback_uses_architectural_bit_22() {
        assert!(!pan_bit_set(0));
        assert!(!pan_bit_set(1));
        assert!(pan_bit_set(PSTATE_PAN_BIT));
        assert!(pan_bit_set(PSTATE_PAN_BIT | 1));
    }

    #[test]
    fn usercopy_fault_status_classifier_is_fail_closed() {
        for status in 0x04..=0x07 {
            assert!(is_recoverable_usercopy_fault_status(status));
        }
        for status in 0x09..=0x0b {
            assert!(is_recoverable_usercopy_fault_status(status));
        }
        for status in 0x0d..=0x0f {
            assert!(is_recoverable_usercopy_fault_status(status));
        }
        for status in [0x00, 0x08, 0x0c, 0x10, 0x21, 0x3f] {
            assert!(!is_recoverable_usercopy_fault_status(status));
        }
    }

    #[test]
    fn pan_probe_requires_permission_fault_status() {
        for status in 0x0d..=0x0f {
            assert!(is_permission_fault_status(status));
        }
        for status in [0x00, 0x04, 0x0b, 0x0c, 0x10, 0x21, 0x3f] {
            assert!(!is_permission_fault_status(status));
        }
    }

    #[test]
    fn atomic_u32_load_rejects_unaligned_before_privileged_access() {
        assert_eq!(
            load_atomic_u32_from_user(0x0000_0000_0001_0001),
            Err(AtomicU32LoadError::Unaligned)
        );
    }

    #[test]
    fn atomic_u32_compare_exchange_rejects_unaligned_before_privileged_access() {
        assert_eq!(
            compare_exchange_atomic_u32_in_user(0x0000_0000_0001_0001, 1, 2),
            Err(AtomicU32CompareExchangeError::Unaligned)
        );
        assert_eq!(ATOMIC_U32_CAS_RETRIES, 64);
    }

    #[test]
    fn partial_copy_progress_is_exact_and_fail_closed() {
        assert_eq!(
            progress_from_remaining(8, 0),
            Ok(CopyToUserProgress {
                copied: 8,
                faulted: false,
            })
        );
        assert_eq!(
            progress_from_remaining(8, 3),
            Ok(CopyToUserProgress {
                copied: 5,
                faulted: true,
            })
        );
        assert_eq!(progress_from_remaining(8, 9), Err(Error::Fault));
    }

    #[test]
    fn host_never_claims_privileged_pan_runtime() {
        #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
        {
            assert!(!pan_supported());
            assert_eq!(enable_pan_default(), Err(Error::PanUnavailable));
            assert_eq!(pan_enabled(), Err(Error::PanUnavailable));
            assert_eq!(
                load_atomic_u32_from_user(0x0000_0000_0001_0000),
                Err(AtomicU32LoadError::Usercopy(Error::PanUnavailable))
            );
            assert_eq!(
                compare_exchange_atomic_u32_in_user(0x0000_0000_0001_0000, 1, 2),
                Err(AtomicU32CompareExchangeError::Usercopy(
                    Error::PanUnavailable
                ))
            );
        }
    }
}
