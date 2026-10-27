// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use std::path::PathBuf;
use std::process::Command;

mod filesystem;
mod process_runtime;

pub(super) fn run() -> Result<(), String> {
    filesystem::run()?;
    process_runtime::run()
}

// Keep the proof modules focused on their acceptance logic while the generic
// workspace/build helpers remain owned by the xtask entry point.
pub(super) const AARCH64_CORE_TARGET: &str = super::AARCH64_CORE_TARGET;
pub(super) const AARCH64_CORE_PACKAGE: &str = super::AARCH64_CORE_PACKAGE;
pub(super) const AARCH64_QEMU_SUCCESS_STATUS: i32 = super::AARCH64_QEMU_SUCCESS_STATUS;
pub(super) const QEMU_TIMEOUT_SECS: u64 = super::QEMU_TIMEOUT_SECS;

pub(super) fn workspace_root() -> Result<PathBuf, String> {
    super::workspace_root()
}

pub(super) fn cargo() -> String {
    super::cargo()
}

pub(super) fn run_checked(command: &mut Command, label: &str) -> Result<(), String> {
    super::run_checked(command, label)
}
