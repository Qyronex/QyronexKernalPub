// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_abi::{FsCall, SyscallRequest};

/// Linux arm64 syscall numbers required by the final Step-29 filesystem breadth. Declaring a number
/// is classification only and grants no VFS/FD/usercopy authority.
pub mod fs_nr {
    pub const GETCWD: u64 = 17;
    pub const MKDIRAT: u64 = 34;
    pub const UNLINKAT: u64 = 35;
    pub const SYMLINKAT: u64 = 36;
    pub const LINKAT: u64 = 37;
    pub const RENAMEAT: u64 = 38;
    pub const TRUNCATE: u64 = 45;
    pub const FTRUNCATE: u64 = 46;
    pub const FACCESSAT: u64 = 48;
    pub const CHDIR: u64 = 49;
    pub const FCHDIR: u64 = 50;
    pub const FCHMOD: u64 = 52;
    pub const FCHMODAT: u64 = 53;
    pub const FCHOWNAT: u64 = 54;
    pub const FCHOWN: u64 = 55;
    pub const PWRITE64: u64 = 68;
    pub const READLINKAT: u64 = 78;
    pub const UTIMENSAT: u64 = 88;
    pub const UMASK: u64 = 166;
    pub const RENAMEAT2: u64 = 276;
    pub const STATX: u64 = 291;
    pub const OPENAT2: u64 = 437;
    pub const FACCESSAT2: u64 = 439;
}

/// Classifies only final Step-29 filesystem syscalls while preserving the exact x0..x5 register
/// values. Linux C integer width/sign decoding remains the semantic owner's responsibility, matching
/// the already accepted `PathFdCall` and `FdIoCall` boundary. Unknown numbers return `None` for the
/// existing shared ENOSYS fallback.
pub fn classify_fs(request: SyscallRequest) -> Option<FsCall> {
    let a = request.args;
    match request.number {
        fs_nr::GETCWD => Some(FsCall::Getcwd {
            user_buffer: a[0],
            size: a[1],
        }),
        fs_nr::MKDIRAT => Some(FsCall::MkdirAt {
            dirfd: a[0],
            user_path: a[1],
            mode: a[2],
        }),
        fs_nr::UNLINKAT => Some(FsCall::UnlinkAt {
            dirfd: a[0],
            user_path: a[1],
            flags: a[2],
        }),
        fs_nr::SYMLINKAT => Some(FsCall::SymlinkAt {
            user_target: a[0],
            newdirfd: a[1],
            user_linkpath: a[2],
        }),
        fs_nr::LINKAT => Some(FsCall::LinkAt {
            olddirfd: a[0],
            user_oldpath: a[1],
            newdirfd: a[2],
            user_newpath: a[3],
            flags: a[4],
        }),
        fs_nr::RENAMEAT => Some(FsCall::RenameAt {
            olddirfd: a[0],
            user_oldpath: a[1],
            newdirfd: a[2],
            user_newpath: a[3],
        }),
        fs_nr::TRUNCATE => Some(FsCall::Truncate {
            user_path: a[0],
            length: a[1],
        }),
        fs_nr::FTRUNCATE => Some(FsCall::Ftruncate {
            fd: a[0],
            length: a[1],
        }),
        fs_nr::FACCESSAT => Some(FsCall::FaccessAt {
            dirfd: a[0],
            user_path: a[1],
            mode: a[2],
        }),
        fs_nr::CHDIR => Some(FsCall::Chdir { user_path: a[0] }),
        fs_nr::FCHDIR => Some(FsCall::Fchdir { fd: a[0] }),
        fs_nr::FCHMOD => Some(FsCall::Fchmod {
            fd: a[0],
            mode: a[1],
        }),
        fs_nr::FCHMODAT => Some(FsCall::FchmodAt {
            dirfd: a[0],
            user_path: a[1],
            mode: a[2],
        }),
        fs_nr::FCHOWNAT => Some(FsCall::FchownAt {
            dirfd: a[0],
            user_path: a[1],
            owner: a[2],
            group: a[3],
            flags: a[4],
        }),
        fs_nr::FCHOWN => Some(FsCall::Fchown {
            fd: a[0],
            owner: a[1],
            group: a[2],
        }),
        fs_nr::PWRITE64 => Some(FsCall::Pwrite64 {
            fd: a[0],
            user_buffer: a[1],
            count: a[2],
            offset: a[3],
        }),
        fs_nr::READLINKAT => Some(FsCall::ReadlinkAt {
            dirfd: a[0],
            user_path: a[1],
            user_buffer: a[2],
            buffer_size: a[3],
        }),
        fs_nr::UTIMENSAT => Some(FsCall::UtimensAt {
            dirfd: a[0],
            user_path: a[1],
            user_times: a[2],
            flags: a[3],
        }),
        fs_nr::UMASK => Some(FsCall::Umask { mask: a[0] }),
        fs_nr::RENAMEAT2 => Some(FsCall::RenameAt2 {
            olddirfd: a[0],
            user_oldpath: a[1],
            newdirfd: a[2],
            user_newpath: a[3],
            flags: a[4],
        }),
        fs_nr::STATX => Some(FsCall::Statx {
            dirfd: a[0],
            user_path: a[1],
            flags: a[2],
            mask: a[3],
            user_statx: a[4],
        }),
        fs_nr::OPENAT2 => Some(FsCall::OpenAt2 {
            dirfd: a[0],
            user_path: a[1],
            user_open_how: a[2],
            size: a[3],
        }),
        fs_nr::FACCESSAT2 => Some(FsCall::FaccessAt2 {
            dirfd: a[0],
            user_path: a[1],
            mode: a[2],
            flags: a[3],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hostile_u32(low: u32) -> u64 {
        (0xfeed_beefu64 << 32) | u64::from(low)
    }

    #[test]
    fn final_filesystem_number_anchors_match_linux_arm64() {
        assert_eq!(fs_nr::GETCWD, 17);
        assert_eq!(fs_nr::MKDIRAT, 34);
        assert_eq!(fs_nr::UNLINKAT, 35);
        assert_eq!(fs_nr::SYMLINKAT, 36);
        assert_eq!(fs_nr::LINKAT, 37);
        assert_eq!(fs_nr::RENAMEAT, 38);
        assert_eq!(fs_nr::TRUNCATE, 45);
        assert_eq!(fs_nr::FTRUNCATE, 46);
        assert_eq!(fs_nr::FACCESSAT, 48);
        assert_eq!(fs_nr::CHDIR, 49);
        assert_eq!(fs_nr::FCHDIR, 50);
        assert_eq!(fs_nr::FCHMOD, 52);
        assert_eq!(fs_nr::FCHMODAT, 53);
        assert_eq!(fs_nr::FCHOWNAT, 54);
        assert_eq!(fs_nr::FCHOWN, 55);
        assert_eq!(fs_nr::PWRITE64, 68);
        assert_eq!(fs_nr::READLINKAT, 78);
        assert_eq!(fs_nr::UTIMENSAT, 88);
        assert_eq!(fs_nr::UMASK, 166);
        assert_eq!(fs_nr::RENAMEAT2, 276);
        assert_eq!(fs_nr::STATX, 291);
        assert_eq!(fs_nr::OPENAT2, 437);
        assert_eq!(fs_nr::FACCESSAT2, 439);
    }

    #[test]
    fn classifier_preserves_hostile_upper_register_bits_exactly() {
        let raw_dirfd = hostile_u32((-100_i32) as u32);
        let raw_mode = hostile_u32(0o755);
        assert_eq!(
            classify_fs(SyscallRequest::new(
                fs_nr::MKDIRAT,
                [raw_dirfd, 0x1000, raw_mode, 4, 5, 6],
            )),
            Some(FsCall::MkdirAt {
                dirfd: raw_dirfd,
                user_path: 0x1000,
                mode: raw_mode,
            })
        );

        let raw_owner = hostile_u32(u32::MAX);
        let raw_group = hostile_u32(1234);
        let raw_flags = hostile_u32(0x100);
        assert_eq!(
            classify_fs(SyscallRequest::new(
                fs_nr::FCHOWNAT,
                [raw_dirfd, 0x2000, raw_owner, raw_group, raw_flags, 6],
            )),
            Some(FsCall::FchownAt {
                dirfd: raw_dirfd,
                user_path: 0x2000,
                owner: raw_owner,
                group: raw_group,
                flags: raw_flags,
            })
        );
    }

    #[test]
    fn full_width_pointer_size_off_t_and_argument_order_are_preserved() {
        let pointer = 0xfedc_ba98_7654_3210;
        let count = 0x8000_0000_0000_1000;
        let negative_offset_bits = (-7_i64) as u64;
        let raw_fd = hostile_u32(3);
        assert_eq!(
            classify_fs(SyscallRequest::new(
                fs_nr::PWRITE64,
                [raw_fd, pointer, count, negative_offset_bits, 5, 6],
            )),
            Some(FsCall::Pwrite64 {
                fd: raw_fd,
                user_buffer: pointer,
                count,
                offset: negative_offset_bits,
            })
        );
        assert_eq!(
            classify_fs(SyscallRequest::new(
                fs_nr::OPENAT2,
                [raw_fd, pointer, pointer - 8, count, 5, 6],
            )),
            Some(FsCall::OpenAt2 {
                dirfd: raw_fd,
                user_path: pointer,
                user_open_how: pointer - 8,
                size: count,
            })
        );
    }

    #[test]
    fn final_fs_classifier_is_disjoint_from_accepted_path_and_fd_io_numbers() {
        assert_eq!(classify_fs(SyscallRequest::new(56, [u64::MAX; 6])), None);
        assert_eq!(classify_fs(SyscallRequest::new(23, [u64::MAX; 6])), None);
        assert_eq!(classify_fs(SyscallRequest::new(64, [u64::MAX; 6])), None);
        assert_eq!(
            classify_fs(SyscallRequest::new(u64::MAX, [u64::MAX; 6])),
            None
        );
    }
}
