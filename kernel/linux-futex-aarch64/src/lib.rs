// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_futex::FutexKey;
use kernal_linux_abi::Errno;
use kernal_process::Process;
use kernal_process_aarch64::{BoundProcessAddressSpace, current_user_switch_generation};
use kernal_usercopy::Error as UsercopyError;
use kernal_usercopy_aarch64::AtomicU32LoadError;

pub const FUTEX_WORD_BYTES: usize = core::mem::size_of::<u32>();

/// One private Linux futex word read from the exact active process address-space generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateFutexWord {
    pub key: FutexKey,
    pub value: u32,
}

/// Separates normal Linux request failures from privileged runtime-invariant failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FutexAccessError {
    Errno(Errno),
    ProcessAddressSpaceInvariant(kernal_process_aarch64::Error),
    FutexInvariant(kernal_futex::Error),
    UserAccessInvariant(UsercopyError),
}

/// Atomically reads one private Linux futex word from the current AArch64 process address space.
///
/// The private futex key is generation-bound to the existing AddressSpace ObjectId rather than a
/// TTBR value or caller-selected integer. One canonical TTBR0 switch generation is captured and
/// validated before and after the fault-safe Step-10 atomic u32 load, so a switch away and back to
/// the same process/address-space binding cannot be accepted as a successful read. Runtime callers
/// must still hold the normal scheduler/address-space switch serialization while performing a
/// FUTEX_WAIT compare-and-prepare transaction.
pub fn read_private_word<const CAPS: usize, const VMAS: usize>(
    process: &Process<CAPS>,
    address_space: &BoundProcessAddressSpace<VMAS>,
    user_address: u64,
) -> Result<PrivateFutexWord, FutexAccessError> {
    let address_space_id = address_space.address_space_object().0;
    let active = address_space
        .current_owner(process)
        .map_err(FutexAccessError::ProcessAddressSpaceInvariant)?;
    let switch_generation =
        current_user_switch_generation().ok_or(FutexAccessError::ProcessAddressSpaceInvariant(
            kernal_process_aarch64::Error::NotCurrentProcess,
        ))?;
    active
        .validate_entry_switch_generation(switch_generation)
        .map_err(FutexAccessError::ProcessAddressSpaceInvariant)?;

    let mut load = kernal_usercopy_aarch64::load_atomic_u32_from_user;
    let result = read_private_word_with(address_space_id, user_address, &mut load);

    // Revalidate even when the user access itself failed. A switch-generation change is a privileged
    // invariant failure and must not be disguised as a userspace EFAULT, even if the same logical
    // process/address-space binding became current again before this check.
    active
        .validate_entry_switch_generation(switch_generation)
        .map_err(FutexAccessError::ProcessAddressSpaceInvariant)?;
    result
}

fn read_private_word_with<L>(
    address_space_id: u64,
    user_address: u64,
    load: &mut L,
) -> Result<PrivateFutexWord, FutexAccessError>
where
    L: FnMut(u64) -> Result<u32, AtomicU32LoadError>,
{
    let key = FutexKey::new(address_space_id, user_address).map_err(map_futex_key_error)?;
    let value = load(user_address).map_err(map_atomic_load_error)?;
    Ok(PrivateFutexWord { key, value })
}

const fn map_futex_key_error(error: kernal_futex::Error) -> FutexAccessError {
    match error {
        kernal_futex::Error::Unaligned => FutexAccessError::Errno(Errno::EINVAL),
        _ => FutexAccessError::FutexInvariant(error),
    }
}

const fn map_atomic_load_error(error: AtomicU32LoadError) -> FutexAccessError {
    match error {
        AtomicU32LoadError::Unaligned => FutexAccessError::Errno(Errno::EINVAL),
        AtomicU32LoadError::Usercopy(error) => map_usercopy_error(error),
    }
}

const fn map_usercopy_error(error: UsercopyError) -> FutexAccessError {
    match error {
        UsercopyError::NullGuard
        | UsercopyError::OutsideUserRange
        | UsercopyError::Overflow
        | UsercopyError::Fault => FutexAccessError::Errno(Errno::EFAULT),
        UsercopyError::TooLarge
        | UsercopyError::PanUnavailable
        | UsercopyError::PanStateLeak
        | UsercopyError::FaultHandlerUnavailable => FutexAccessError::UserAccessInvariant(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS_SPACE_A: u64 = 0x1000_0001;
    const ADDRESS_SPACE_B: u64 = 0x1000_0002;
    const USER_WORD: u64 = 0x0000_0000_0001_2000;

    #[test]
    fn aligned_private_word_uses_address_space_generation_and_atomic_value() {
        let mut load_calls = 0_usize;
        let observed = read_private_word_with(ADDRESS_SPACE_A, USER_WORD, &mut |source: u64| {
            load_calls += 1;
            assert_eq!(source, USER_WORD);
            Ok(0x7856_3412)
        })
        .unwrap();

        assert_eq!(FUTEX_WORD_BYTES, 4);
        assert_eq!(load_calls, 1);
        assert_eq!(observed.value, 0x7856_3412);
        assert_eq!(observed.key.address_space, ADDRESS_SPACE_A);
        assert_eq!(observed.key.user_address, USER_WORD);
    }

    #[test]
    fn private_key_distinguishes_equal_virtual_addresses_across_address_spaces() {
        let mut load = |_: u64| Ok(0);
        let left = read_private_word_with(ADDRESS_SPACE_A, USER_WORD, &mut load).unwrap();
        let right = read_private_word_with(ADDRESS_SPACE_B, USER_WORD, &mut load).unwrap();

        assert_ne!(left.key, right.key);
        assert_eq!(left.key.user_address, right.key.user_address);
    }

    #[test]
    fn unaligned_word_fails_before_atomic_user_load() {
        let mut load_calls = 0_usize;
        let result = read_private_word_with(ADDRESS_SPACE_A, USER_WORD + 1, &mut |_: u64| {
            load_calls += 1;
            Ok(0)
        });

        assert_eq!(result, Err(FutexAccessError::Errno(Errno::EINVAL)));
        assert_eq!(load_calls, 0);
    }

    #[test]
    fn atomic_loader_unaligned_error_maps_to_einval() {
        let result = read_private_word_with(ADDRESS_SPACE_A, USER_WORD, &mut |_: u64| {
            Err(AtomicU32LoadError::Unaligned)
        });
        assert_eq!(result, Err(FutexAccessError::Errno(Errno::EINVAL)));
    }

    #[test]
    fn ordinary_user_faults_become_efault() {
        for error in [
            UsercopyError::NullGuard,
            UsercopyError::OutsideUserRange,
            UsercopyError::Overflow,
            UsercopyError::Fault,
        ] {
            let result = read_private_word_with(ADDRESS_SPACE_A, USER_WORD, &mut |_: u64| {
                Err(AtomicU32LoadError::Usercopy(error))
            });
            assert_eq!(result, Err(FutexAccessError::Errno(Errno::EFAULT)));
        }
    }

    #[test]
    fn pan_and_impossible_fixed_size_failures_remain_invariants() {
        for error in [
            UsercopyError::TooLarge,
            UsercopyError::PanUnavailable,
            UsercopyError::PanStateLeak,
            UsercopyError::FaultHandlerUnavailable,
        ] {
            let result = read_private_word_with(ADDRESS_SPACE_A, USER_WORD, &mut |_: u64| {
                Err(AtomicU32LoadError::Usercopy(error))
            });
            assert_eq!(result, Err(FutexAccessError::UserAccessInvariant(error)));
        }
    }
}
