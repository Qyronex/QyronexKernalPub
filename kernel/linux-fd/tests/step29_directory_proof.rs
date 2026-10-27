// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Compile the exact pure reducer used by the freestanding ARM64 Step-29 proof owner inside this
// already host-safe integration-test crate. This adds negative proof coverage to `workspace-test`
// without creating a second filesystem/FD/proof implementation or host-building the kernel binary.
#[path = "../../core-aarch64/src/step29_directory_proof.rs"]
mod step29_directory_proof;
