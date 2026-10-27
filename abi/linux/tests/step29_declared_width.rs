use kernal_linux_abi::{linux_signed_int, linux_signed_off_t, linux_u64, linux_unsigned_int};

#[test]
fn declared_width_helpers_consume_only_the_linux_declared_bits() {
    let noisy = 0xaaaa_bbbb_ffff_fffeu64;
    assert_eq!(linux_unsigned_int(noisy), 0xffff_fffeu32);
    assert_eq!(linux_signed_int(noisy), -2);

    let negative_offset = (-17_i64) as u64;
    assert_eq!(linux_signed_off_t(negative_offset), -17);

    let pointer_or_size = 0x1234_5678_9abc_def0u64;
    assert_eq!(linux_u64(pointer_or_size), pointer_or_size);
}

#[test]
fn signed_and_unsigned_int_views_differ_without_touching_upper_register_bits() {
    let raw = 0xfeed_face_8000_0001u64;
    assert_eq!(linux_unsigned_int(raw), 0x8000_0001u32);
    assert_eq!(linux_signed_int(raw), -2_147_483_647);
}

#[test]
fn fcntl_command_arguments_decode_argi_only_after_raw_classification() {
    let hostile_negative = 0xdead_beef_ffff_fffeu64;
    assert_eq!(linux_u64(hostile_negative), hostile_negative);
    assert_eq!(linux_signed_int(hostile_negative), -2);

    let hostile_cloexec = 0xfeed_face_0000_0001u64;
    assert_eq!(linux_u64(hostile_cloexec), hostile_cloexec);
    assert_eq!(linux_signed_int(hostile_cloexec), 1);

    // Integration applies this signed low-32-bit `argi` view only for F_DUPFD,
    // F_DUPFD_CLOEXEC and F_SETFD. F_GETFD/F_GETFL ignore the raw arg entirely.
}
