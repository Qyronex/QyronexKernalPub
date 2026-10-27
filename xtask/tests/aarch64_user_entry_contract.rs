// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_user_entry_aarch64::{
    EL0T_SPSR_EL1, El0EntryState, Error, KERNEL_HALF_MIN, STACK_ALIGNMENT, USER_ENTRY_ALIGNMENT,
};
use kernal_vm::{USER_MAX_EXCLUSIVE, USER_MIN};

const ENTRY: u64 = USER_MIN + 0x20_000;
const USER_SP: u64 = USER_MIN + 0x80_000;
const KERNEL_SP: u64 = KERNEL_HALF_MIN + 0x10_000;

#[test]
fn canonical_verify_covers_aarch64_el0_entry_contract() {
    let state = El0EntryState::new(ENTRY, USER_SP, KERNEL_SP, 0x1234).unwrap();
    assert_eq!(state.entry(), ENTRY);
    assert_eq!(state.user_sp(), USER_SP);
    assert_eq!(state.kernel_exception_sp(), KERNEL_SP);
    assert_eq!(state.argument0(), 0x1234);
    assert_eq!(state.spsr_el1(), EL0T_SPSR_EL1);
    assert!(state.entry().is_multiple_of(USER_ENTRY_ALIGNMENT));
    assert!(state.user_sp().is_multiple_of(STACK_ALIGNMENT));
    assert!(state.kernel_exception_sp().is_multiple_of(STACK_ALIGNMENT));

    assert_eq!(
        El0EntryState::new(USER_MIN - USER_ENTRY_ALIGNMENT, USER_SP, KERNEL_SP, 0),
        Err(Error::EntryOutsideUserRange)
    );
    assert_eq!(
        El0EntryState::new(ENTRY + 2, USER_SP, KERNEL_SP, 0),
        Err(Error::EntryMisaligned)
    );
    assert_eq!(
        El0EntryState::new(ENTRY, USER_MAX_EXCLUSIVE, KERNEL_SP, 0),
        Err(Error::UserStackOutsideUserRange)
    );
    assert_eq!(
        El0EntryState::new(ENTRY, USER_SP + 8, KERNEL_SP, 0),
        Err(Error::UserStackMisaligned)
    );
    assert_eq!(
        El0EntryState::new(ENTRY, USER_SP, KERNEL_HALF_MIN - STACK_ALIGNMENT, 0),
        Err(Error::KernelStackOutsideKernelHalf)
    );
    assert_eq!(
        El0EntryState::new(ENTRY, USER_SP, KERNEL_SP + 8, 0),
        Err(Error::KernelStackMisaligned)
    );
}
