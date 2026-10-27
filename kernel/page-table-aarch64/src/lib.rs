// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

include!(concat!(env!("OUT_DIR"), "/implementation.rs"));

mod user_runtime;
pub use user_runtime::{
    UserTtbr0SwitchObserver, current_user_ttbr0, install_user_ttbr0_switch_observer,
    pan_exception_entry_enabled, sctlr_with_pan_exception_entry, tcr_with_ttbr0_disabled,
    tcr_with_ttbr0_enabled, tlbi_vae1is_operand,
};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use user_runtime::{
    activate_user_ttbr0, deactivate_user_ttbr0, enable_pan_exception_entry, invalidate_user_page,
    pan_exception_entry_is_enabled,
};
