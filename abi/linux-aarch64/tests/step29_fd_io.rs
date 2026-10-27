use kernal_linux_aarch64_abi::{classify_fd_io, classify_path_fd, nr};
use kernal_linux_abi::{FdIoCall, SyscallRequest};

#[test]
fn step29_fd_io_numbers_match_linux_arm64() {
    assert_eq!(nr::DUP, 23);
    assert_eq!(nr::DUP3, 24);
    assert_eq!(nr::FCNTL, 25);
    assert_eq!(nr::PIPE2, 59);
    assert_eq!(nr::LSEEK, 62);
    assert_eq!(nr::PREAD64, 67);
}

#[test]
fn fd_io_classifier_preserves_raw_register_bits() {
    let high = 0xffff_ffff_0000_0000u64;

    assert_eq!(
        classify_fd_io(SyscallRequest::new(nr::DUP, [high | 3, 2, 3, 4, 5, 6])),
        Some(FdIoCall::Dup { oldfd: high | 3 })
    );
    assert_eq!(
        classify_fd_io(SyscallRequest::new(
            nr::DUP3,
            [high | 4, high | 1, high | 0x80000, 4, 5, 6],
        )),
        Some(FdIoCall::Dup3 {
            oldfd: high | 4,
            newfd: high | 1,
            flags: high | 0x80000,
        })
    );
    assert_eq!(
        classify_fd_io(SyscallRequest::new(
            nr::FCNTL,
            [high | 5, high | 1030, u64::MAX - 7, 4, 5, 6],
        )),
        Some(FdIoCall::Fcntl {
            fd: high | 5,
            cmd: high | 1030,
            arg: u64::MAX - 7,
        })
    );
    assert_eq!(
        classify_fd_io(SyscallRequest::new(
            nr::PIPE2,
            [0x1234_5678_9abc_def0, high | 0x800, 3, 4, 5, 6],
        )),
        Some(FdIoCall::Pipe2 {
            user_pipefd: 0x1234_5678_9abc_def0,
            flags: high | 0x800,
        })
    );
    assert_eq!(
        classify_fd_io(SyscallRequest::new(
            nr::LSEEK,
            [high | 3, (-17_i64) as u64, high | 2, 4, 5, 6],
        )),
        Some(FdIoCall::Lseek {
            fd: high | 3,
            offset: (-17_i64) as u64,
            whence: high | 2,
        })
    );
    assert_eq!(
        classify_fd_io(SyscallRequest::new(
            nr::PREAD64,
            [high | 3, 0x2000, 4096, (-1_i64) as u64, 5, 6],
        )),
        Some(FdIoCall::Pread64 {
            fd: high | 3,
            user_buffer: 0x2000,
            count: 4096,
            offset: (-1_i64) as u64,
        })
    );
}

#[test]
fn fd_io_numbers_are_disjoint_from_existing_classifiers() {
    for number in [
        nr::DUP,
        nr::DUP3,
        nr::FCNTL,
        nr::PIPE2,
        nr::LSEEK,
        nr::PREAD64,
    ] {
        let request = SyscallRequest::new(number, [0; 6]);
        assert!(kernal_linux_aarch64_abi::classify_bootstrap(request).is_none());
        assert!(kernal_linux_aarch64_abi::classify_minimum_runtime(request).is_none());
        assert!(classify_path_fd(request).is_none());
        assert!(classify_fd_io(request).is_some());
    }
}
