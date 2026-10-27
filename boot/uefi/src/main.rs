// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(all(target_arch = "x86_64", target_os = "uefi"), no_std)]
#![cfg_attr(all(target_arch = "x86_64", target_os = "uefi"), no_main)]
#![cfg_attr(
    all(target_arch = "x86_64", target_os = "uefi"),
    deny(unsafe_op_in_unsafe_fn)
)]

#[cfg(all(target_arch = "x86_64", target_os = "uefi"))]
include!(concat!(env!("OUT_DIR"), "/freestanding.rs"));

#[cfg(not(all(target_arch = "x86_64", target_os = "uefi")))]
fn main() {}
