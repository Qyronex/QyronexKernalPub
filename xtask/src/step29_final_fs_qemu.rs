// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Compatibility handoff for the transient top-level arm-qemu hook.
///
/// The canonical final-filesystem proof runner is now owned by `step28::run()` through
/// `step28::final_fs`, after the accepted date/ls and fd/pipe matrices. Keep this wrapper side-effect
/// free so a concurrently-added top-level hook cannot execute the same QEMU matrix twice.
pub fn run() -> Result<(), String> {
    Ok(())
}
