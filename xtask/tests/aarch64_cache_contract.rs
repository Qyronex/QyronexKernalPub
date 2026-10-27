// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cache_aarch64::{CacheGeometry, Error, sync_modified_code};

#[test]
fn canonical_verify_covers_aarch64_cache_geometry() {
    let raw = (5u64 << 16) | 4u64;
    let geometry = CacheGeometry::from_ctr_el0(raw);
    assert_eq!(geometry.data_line_bytes(), 128);
    assert_eq!(geometry.instruction_line_bytes(), 64);
}

#[test]
fn host_cache_maintenance_fails_closed() {
    // SAFETY: the host stub executes no privileged operation and is expected to reject the call.
    assert_eq!(
        unsafe { sync_modified_code(0x1000, 0x2000, 16) },
        Err(Error::UnsupportedHostArchitecture)
    );
}
