// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(all(target_arch = "x86_64", target_os = "none"), no_std)]
#![cfg_attr(all(target_arch = "x86_64", target_os = "none"), no_main)]
#![cfg_attr(
    all(target_arch = "x86_64", target_os = "none"),
    deny(unsafe_op_in_unsafe_fn)
)]

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
include!(concat!(env!("OUT_DIR"), "/freestanding.rs"));

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn main() {}
