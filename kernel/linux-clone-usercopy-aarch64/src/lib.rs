// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::num::NonZeroU32;
use kernal_linux_abi::Errno;
use kernal_linux_clone::ClonePlan;
use kernal_process::Process;
use kernal_process_aarch64::{BoundProcessAddressSpace, current_user_switch_generation};
use kernal_usercopy::Error as UsercopyError;

pub const PARENT_TID_BYTES: usize = core::mem::size_of::<u32>();

/// Separates normal Linux clone request faults from privileged address-space/usercopy invariants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentTidWriteError {
    Errno(Errno),
    ProcessAddressSpaceInvariant(kernal_process_aarch64::Error),
    UserAccessInvariant(UsercopyError),
}

/// Stores the newly allocated Linux child TID into CLONE_PARENT_SETTID memory of the exact active
/// parent process/address-space generation.
///
/// `ClonePlan` has already structurally validated the complete aligned 4-byte parent-TID range. This
/// adapter owns only the fault-safe side effect. It captures the canonical TTBR0 switch generation,
/// validates it before the write, uses the accepted PAN/fault-fixup `copy_to_user` path, and validates
/// the same generation again afterwards. The generation checks are defense-in-depth; the caller must
/// prevent an address-space switch for the complete store because a write cannot be undone after a
/// post-check discovers that it targeted a different active TTBR0.
///
/// Runtime ordering matters: perform this write only after every fallible child
/// allocation/authority/TLS/clear-child-tid setup step has succeeded. If this write fails, cancel the
/// still-unpublished staged child. Once this write succeeds, the remaining child publication must be
/// infallible; rollback of child state alone cannot retract a parent-TID value already visible in
/// userspace.
///
/// # Safety
/// The caller must own the exact current parent scheduler/address-space generation and keep local
/// IRQ delivery, preemption, migration, and any TTBR0/address-space switch suppressed for the entire
/// call, including both switch-generation validations and `copy_to_user`. No other path may replace
/// the active parent address space until this function returns.
pub unsafe fn write_parent_tid<const CAPS: usize, const VMAS: usize>(
    process: &Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    plan: ClonePlan,
    child_tid: NonZeroU32,
) -> Result<(), ParentTidWriteError> {
    let active = address_space
        .current_owner(process)
        .map_err(ParentTidWriteError::ProcessAddressSpaceInvariant)?;
    let switch_generation = current_user_switch_generation().ok_or(
        ParentTidWriteError::ProcessAddressSpaceInvariant(
            kernal_process_aarch64::Error::NotCurrentProcess,
        ),
    )?;
    active
        .validate_entry_switch_generation(switch_generation)
        .map_err(ParentTidWriteError::ProcessAddressSpaceInvariant)?;

    let mut store = kernal_usercopy_aarch64::copy_to_user;
    let result = write_parent_tid_with(plan, child_tid, &mut store);

    // Revalidate even if the store faulted. Under the safety contract this generation must remain
    // unchanged; any mismatch is privileged invariant evidence and must not be disguised as EFAULT.
    active
        .validate_entry_switch_generation(switch_generation)
        .map_err(ParentTidWriteError::ProcessAddressSpaceInvariant)?;
    result
}

fn write_parent_tid_with<S>(
    plan: ClonePlan,
    child_tid: NonZeroU32,
    store: &mut S,
) -> Result<(), ParentTidWriteError>
where
    S: FnMut(u64, &[u8]) -> Result<(), UsercopyError>,
{
    let bytes = child_tid.get().to_le_bytes();
    store(plan.parent_tid(), &bytes).map_err(map_usercopy_error)
}

const fn map_usercopy_error(error: UsercopyError) -> ParentTidWriteError {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::Fault => ParentTidWriteError::Errno(Errno::EFAULT),
        UsercopyError::TooLarge
        | UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => ParentTidWriteError::UserAccessInvariant(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_clone::MUSL_PTHREAD_FLAGS;

    const STACK: u64 = 0x0000_0000_0002_0000;
    const PTID: u64 = 0x0000_0000_0003_0000;
    const TLS: u64 = 0x0000_0000_0004_0008;
    const CTID: u64 = 0x0000_0000_0005_0000;

    fn plan() -> ClonePlan {
        ClonePlan::validate(MUSL_PTHREAD_FLAGS, STACK, PTID, TLS, CTID).unwrap()
    }

    #[test]
    fn parent_tid_store_is_exactly_one_little_endian_u32_write() {
        let tid = NonZeroU32::new(0x1234_5678).unwrap();
        let mut calls = 0_usize;
        let mut observed = [0_u8; PARENT_TID_BYTES];

        write_parent_tid_with(plan(), tid, &mut |address: u64, bytes: &[u8]| {
            calls += 1;
            assert_eq!(address, PTID);
            assert_eq!(bytes.len(), PARENT_TID_BYTES);
            observed.copy_from_slice(bytes);
            Ok(())
        })
        .unwrap();

        assert_eq!(calls, 1);
        assert_eq!(observed, tid.get().to_le_bytes());
    }

    #[test]
    fn ordinary_user_faults_map_to_efault() {
        for error in [
            UsercopyError::NullGuard,
            UsercopyError::OutsideUserRange,
            UsercopyError::Overflow,
            UsercopyError::Fault,
        ] {
            let result = write_parent_tid_with(
                plan(),
                NonZeroU32::new(37).unwrap(),
                &mut |_: u64, _: &[u8]| Err(error),
            );
            assert_eq!(result, Err(ParentTidWriteError::Errno(Errno::EFAULT)));
        }
    }

    #[test]
    fn impossible_fixed_width_and_pan_failures_remain_kernel_invariants() {
        for error in [
            UsercopyError::TooLarge,
            UsercopyError::PanUnavailable,
            UsercopyError::PanStateLeak,
            UsercopyError::FaultHandlerUnavailable,
        ] {
            let result = write_parent_tid_with(
                plan(),
                NonZeroU32::new(37).unwrap(),
                &mut |_: u64, _: &[u8]| Err(error),
            );
            assert_eq!(result, Err(ParentTidWriteError::UserAccessInvariant(error)));
        }
    }
}
