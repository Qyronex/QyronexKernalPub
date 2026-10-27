// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// The production owners are wired into the freestanding Core qemu-proof binary (`test = false`).
// Include the exact sources from this library-only package so workspace-test exercises their host-
// visible ownership/state contracts without discovering/linking the Core binary.
#[allow(dead_code)]
#[path = "../../core-aarch64/src/step15_futex.rs"]
mod step15_futex;
#[allow(dead_code)]
#[path = "../../core-aarch64/src/step15_runtime.rs"]
mod step15_runtime;
