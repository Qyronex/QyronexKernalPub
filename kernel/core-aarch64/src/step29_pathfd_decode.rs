// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Decodes the low 32 bits of one raw AArch64 syscall register as a Linux `int`.
///
/// AArch64 Linux syscall callers are not required to clear the upper 32 register bits for
/// 32-bit integer arguments. Path/FD adapters therefore must not treat hostile upper bits as
/// descriptor or dirfd authority.
pub const fn signed_int(raw: u64) -> i32 {
    raw as u32 as i32
}

/// Decodes the low 32 bits of one raw AArch64 syscall register as an unsigned Linux `int` bitset.
///
/// This is used for `openat` and `newfstatat` flags so unsupported upper register noise cannot
/// create a false Linux flag error.
pub const fn unsigned_int(raw: u64) -> u32 {
    raw as u32
}
