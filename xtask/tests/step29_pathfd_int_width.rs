// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[path = "../../kernel/core-aarch64/src/step29_pathfd_decode.rs"]
mod pathfd_decode;

const HOSTILE_UPPER: u64 = 0xa5a5_5a5a_0000_0000;

#[test]
fn pathfd_signed_int_arguments_ignore_hostile_upper_register_bits() {
    // close/read/fstat/getdents64 all consume the same Linux `int fd` width.
    for low in [0u32, 3, 31, u32::MAX] {
        assert_eq!(
            pathfd_decode::signed_int(HOSTILE_UPPER | u64::from(low)),
            low as i32
        );
    }

    // Relative *at calls must preserve AT_FDCWD=-100 from the low 32 bits.
    let at_fdcwd = (-100_i32) as u32;
    assert_eq!(
        pathfd_decode::signed_int(HOSTILE_UPPER | u64::from(at_fdcwd)),
        -100
    );
}

#[test]
fn pathfd_flag_arguments_ignore_hostile_upper_register_bits() {
    // ARM64 openat O_NONBLOCK|O_CLOEXEC and newfstatat AT_SYMLINK_NOFOLLOW are Linux int bitsets.
    const O_NONBLOCK: u32 = 0x0000_0800;
    const O_CLOEXEC: u32 = 0x0008_0000;
    const AT_SYMLINK_NOFOLLOW: u32 = 0x0000_0100;

    assert_eq!(
        pathfd_decode::unsigned_int(HOSTILE_UPPER | u64::from(O_NONBLOCK | O_CLOEXEC)),
        O_NONBLOCK | O_CLOEXEC
    );
    assert_eq!(
        pathfd_decode::unsigned_int(HOSTILE_UPPER | u64::from(AT_SYMLINK_NOFOLLOW)),
        AT_SYMLINK_NOFOLLOW
    );
}
