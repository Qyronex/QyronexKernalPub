// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

// Host-only harness for the exact Core Step-15 frame-pool production source. Keeping this test
// outside the freestanding Core package prevents Cargo integration-test discovery from building the
// bare-metal Core binary for the macOS host, while still executing the regressions embedded in the
// production module under the canonical workspace-test and Clippy gates. Production-only entry
// points are intentionally unused by this host harness, so keep the allowance scoped to this module.
#[allow(dead_code)]
#[path = "../../core-aarch64/src/step15_memory.rs"]
mod step15_memory;
