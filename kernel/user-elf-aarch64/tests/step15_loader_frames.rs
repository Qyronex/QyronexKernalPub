// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// The production adapter is wired into the freestanding Core qemu-proof binary (`test = false`).
// Include the exact source from this library-only package so workspace-test exercises allocation and
// rollback regressions without discovering/linking the Core binary on the host.
#[allow(dead_code)]
#[path = "../../core-aarch64/src/step15_loader_frames.rs"]
mod step15_loader_frames;
