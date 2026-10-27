// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Production capture is qemu-proof/freestanding only. Include the exact Core source from this
// library-only FDT package so workspace-test exercises path filtering, size/duplicate rejection and
// one-shot seed ownership without discovering/linking the freestanding Core binary on the host.
#[allow(dead_code)]
#[path = "../../../kernel/core-aarch64/src/step15_entropy.rs"]
mod step15_entropy;
