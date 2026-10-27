// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::Errno;

/// Linux `struct open_how` version-0 byte size: three consecutive u64 fields.
pub const OPEN_HOW_V0_SIZE: u64 = 24;

/// All currently defined Linux `openat2` RESOLVE_* bits.
pub const OPENAT2_KNOWN_RESOLVE_MASK: u64 = 0x3f;
/// The pinned Debian-13 Step-29 corpus contains no observed nonzero RESOLVE use.
pub const OPENAT2_STEP29_SUPPORTED_RESOLVE_MASK: u64 = 0;

/// Authority-free scalar contract for the final Step-29 filesystem breadth.
///
/// Every field preserves the exact raw Linux register bits supplied by the architecture adapter.
/// Linux C integer width/sign decoding belongs to the semantic owner, consistent with the accepted
/// `PathFdCall` and `FdIoCall` layering. This type never dereferences user pointers and owns no VFS,
/// descriptor, usercopy, process or scheduler authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsCall {
    Getcwd {
        user_buffer: u64,
        size: u64,
    },
    MkdirAt {
        dirfd: u64,
        user_path: u64,
        mode: u64,
    },
    UnlinkAt {
        dirfd: u64,
        user_path: u64,
        flags: u64,
    },
    SymlinkAt {
        user_target: u64,
        newdirfd: u64,
        user_linkpath: u64,
    },
    LinkAt {
        olddirfd: u64,
        user_oldpath: u64,
        newdirfd: u64,
        user_newpath: u64,
        flags: u64,
    },
    RenameAt {
        olddirfd: u64,
        user_oldpath: u64,
        newdirfd: u64,
        user_newpath: u64,
    },
    Truncate {
        user_path: u64,
        length: u64,
    },
    Ftruncate {
        fd: u64,
        length: u64,
    },
    FaccessAt {
        dirfd: u64,
        user_path: u64,
        mode: u64,
    },
    Chdir {
        user_path: u64,
    },
    Fchdir {
        fd: u64,
    },
    Fchmod {
        fd: u64,
        mode: u64,
    },
    FchmodAt {
        dirfd: u64,
        user_path: u64,
        mode: u64,
    },
    FchownAt {
        dirfd: u64,
        user_path: u64,
        owner: u64,
        group: u64,
        flags: u64,
    },
    Fchown {
        fd: u64,
        owner: u64,
        group: u64,
    },
    Pwrite64 {
        fd: u64,
        user_buffer: u64,
        count: u64,
        offset: u64,
    },
    ReadlinkAt {
        dirfd: u64,
        user_path: u64,
        user_buffer: u64,
        buffer_size: u64,
    },
    UtimensAt {
        dirfd: u64,
        user_path: u64,
        user_times: u64,
        flags: u64,
    },
    Umask {
        mask: u64,
    },
    RenameAt2 {
        olddirfd: u64,
        user_oldpath: u64,
        newdirfd: u64,
        user_newpath: u64,
        flags: u64,
    },
    Statx {
        dirfd: u64,
        user_path: u64,
        flags: u64,
        mask: u64,
        user_statx: u64,
    },
    OpenAt2 {
        dirfd: u64,
        user_path: u64,
        user_open_how: u64,
        size: u64,
    },
    FaccessAt2 {
        dirfd: u64,
        user_path: u64,
        mode: u64,
        flags: u64,
    },
}

impl Errno {
    pub const EXDEV: Self = Self::from_step29_fs_value(18);
    pub const ENOTEMPTY: Self = Self::from_step29_fs_value(39);

    const fn from_step29_fs_value(value: u16) -> Self {
        // This module is part of the same crate as `Errno`; constants are pinned to Linux values and
        // stay inside the globally validated 1..=MAX_ERRNO window.
        Self(value)
    }
}

/// Validates only the extensible-size boundary of Linux `openat2(2)` version 0.
///
/// The integration owner first copies the known 24-byte prefix and, for a larger caller size,
/// determines whether any extension byte is nonzero. A short size is `EINVAL`; a larger struct with
/// a nonzero unknown extension is `E2BIG`; a larger zero-filled extension remains forward-compatible.
pub const fn validate_open_how_v0_size(
    size: u64,
    extension_has_nonzero_bytes: bool,
) -> Result<(), Errno> {
    if size < OPEN_HOW_V0_SIZE {
        return Err(Errno::EINVAL);
    }
    if size > OPEN_HOW_V0_SIZE && extension_has_nonzero_bytes {
        return Err(Errno::E2BIG);
    }
    Ok(())
}

/// Freezes the Step-29 `openat2` resolve-bit surface.
///
/// The pinned Debian-13 reference corpus contains no `openat2` RESOLVE observation, so Step 29
/// claims only ordinary lookup (`resolve == 0`). Every recognized nonzero RESOLVE bit and every
/// unknown bit fails closed with `EINVAL`; later milestones may widen this only with new evidence.
pub const fn validate_openat2_resolve(resolve: u64) -> Result<(), Errno> {
    if resolve & !OPENAT2_KNOWN_RESOLVE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if resolve != OPENAT2_STEP29_SUPPORTED_RESOLVE_MASK {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_call_keeps_hostile_register_bits_for_semantic_width_decoding() {
        let raw_dirfd = 0xfeed_beefffffff9c;
        let raw_mode = 0xdead_beef000001ed;
        assert_eq!(
            FsCall::MkdirAt {
                dirfd: raw_dirfd,
                user_path: 0x1234,
                mode: raw_mode,
            },
            FsCall::MkdirAt {
                dirfd: raw_dirfd,
                user_path: 0x1234,
                mode: raw_mode,
            }
        );
    }

    #[test]
    fn open_how_v0_size_contract_matches_extensible_linux_boundary() {
        assert_eq!(validate_open_how_v0_size(0, false), Err(Errno::EINVAL));
        assert_eq!(
            validate_open_how_v0_size(OPEN_HOW_V0_SIZE - 1, false),
            Err(Errno::EINVAL)
        );
        assert_eq!(validate_open_how_v0_size(OPEN_HOW_V0_SIZE, false), Ok(()));
        assert_eq!(validate_open_how_v0_size(32, false), Ok(()));
        assert_eq!(validate_open_how_v0_size(32, true), Err(Errno::E2BIG));
    }

    #[test]
    fn step29_openat2_resolve_subset_is_explicit_and_fail_closed() {
        assert_eq!(OPENAT2_STEP29_SUPPORTED_RESOLVE_MASK, 0);
        assert_eq!(validate_openat2_resolve(0), Ok(()));
        for unsupported in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20] {
            assert_eq!(validate_openat2_resolve(unsupported), Err(Errno::EINVAL));
        }
        assert_eq!(validate_openat2_resolve(1u64 << 63), Err(Errno::EINVAL));
    }

    #[test]
    fn final_filesystem_errno_anchors_match_linux() {
        assert_eq!(Errno::E2BIG.get(), 7);
        assert_eq!(Errno::EXDEV.get(), 18);
        assert_eq!(Errno::ENOTEMPTY.get(), 39);
    }
}
