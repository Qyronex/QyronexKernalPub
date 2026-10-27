// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod mmu {
    include!(concat!(env!("OUT_DIR"), "/mmu.rs"));
}

impl mmu::PageRange {
    /// Returns whether this range has no bytes. Reversed ranges remain invalid rather than empty.
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

pub mod transition_state {
    include!(concat!(env!("OUT_DIR"), "/transition_state.rs"));
}

include!(concat!(env!("OUT_DIR"), "/implementation.rs"));

mod runtime;
pub use runtime::{
    cpu_on_bootstrap_available, enter_runtime_protected_regime, runtime_mmio_region,
    runtime_protected_regime_ready, wait_for_runtime_protected_regime,
};

mod runtime_memory;
pub use runtime_memory::qemu_runtime_reserved_low_range;

mod runtime_metadata;
pub use runtime_metadata::runtime_ttbr1_root;

#[cfg(any(test, all(target_arch = "aarch64", target_os = "none")))]
#[cfg_attr(test, allow(dead_code))]
mod runtime_initrd;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use runtime_initrd::{ProtectedInitrd, ProtectedInitrdError, map_qemu_initrd_high_alias};

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod runtime_table;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use runtime_table::{RuntimeTablePool, claim_runtime_table_pool};

#[cfg(all(
    feature = "step14-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step15_callback;
#[cfg(all(
    feature = "step14-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
pub use step15_callback::{
    Step15ProofCallback, Step15ProofCallbackError, Step15ProofEntry, install_step15_proof_callback,
};

#[cfg(all(
    feature = "step7-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step7_qemu;

#[cfg(all(
    feature = "step8-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step8_qemu;
#[cfg(all(
    feature = "step8-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
pub use step8_qemu::{PreparedEl0Proof, prepared_el0_qemu_proof};

#[cfg(all(
    feature = "step9-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step9_qemu;

#[cfg(all(
    feature = "step10-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step10_qemu;

#[cfg(all(
    feature = "step11-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
#[path = "step11_qemu_step12.rs"]
mod step11_qemu;
#[cfg(all(
    feature = "step11-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step11_thread_qemu;

#[cfg(all(
    feature = "step12-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step12_qemu;

#[cfg(all(
    feature = "step13-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step13_qemu;

#[cfg(all(
    feature = "step14-qemu-proof",
    target_arch = "aarch64",
    target_os = "none"
))]
mod step14_qemu;
