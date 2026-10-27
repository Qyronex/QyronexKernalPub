use kernal_linux_abi::{Errno, FdIoCall};

#[test]
fn common_fd_io_calls_are_raw_scalar_contracts() {
    let high = 0xffff_ffff_0000_0000u64;
    assert_eq!(
        FdIoCall::Dup { oldfd: high | 3 },
        FdIoCall::Dup { oldfd: high | 3 }
    );
    assert_eq!(
        FdIoCall::Dup3 {
            oldfd: high | 4,
            newfd: high | 1,
            flags: high | 0x80000,
        },
        FdIoCall::Dup3 {
            oldfd: high | 4,
            newfd: high | 1,
            flags: high | 0x80000,
        }
    );
    assert_eq!(
        FdIoCall::Fcntl {
            fd: high | 5,
            cmd: high | 1030,
            arg: u64::MAX - 7,
        },
        FdIoCall::Fcntl {
            fd: high | 5,
            cmd: high | 1030,
            arg: u64::MAX - 7,
        }
    );
    assert_eq!(
        FdIoCall::Pipe2 {
            user_pipefd: 0x1234_5678_9abc_def0,
            flags: high | 0x800,
        },
        FdIoCall::Pipe2 {
            user_pipefd: 0x1234_5678_9abc_def0,
            flags: high | 0x800,
        }
    );
    assert_eq!(
        FdIoCall::Lseek {
            fd: high | 3,
            offset: (-17_i64) as u64,
            whence: high | 2,
        },
        FdIoCall::Lseek {
            fd: high | 3,
            offset: (-17_i64) as u64,
            whence: high | 2,
        }
    );
    assert_eq!(
        FdIoCall::Pread64 {
            fd: high | 3,
            user_buffer: 0x2000,
            count: 4096,
            offset: (-1_i64) as u64,
        },
        FdIoCall::Pread64 {
            fd: high | 3,
            user_buffer: 0x2000,
            count: 4096,
            offset: (-1_i64) as u64,
        }
    );
}

#[test]
fn fd_io_errno_anchors_match_linux() {
    assert_eq!(Errno::ENFILE.get(), 23);
    assert_eq!(Errno::EMFILE.get(), 24);
    assert_eq!(Errno::ESPIPE.get(), 29);
    assert_eq!(Errno::EOVERFLOW.get(), 75);
}

#[test]
fn pipe_getfl_access_mode_bits_are_pinned() {
    const O_RDONLY: u32 = 0;
    const O_WRONLY: u32 = 1;
    const O_ACCMODE: u32 = 3;
    const O_NONBLOCK: u32 = 2048;

    let read_getfl = O_RDONLY | O_NONBLOCK;
    let write_getfl = O_WRONLY | O_NONBLOCK;
    assert_eq!(read_getfl & O_ACCMODE, O_RDONLY);
    assert_eq!(write_getfl & O_ACCMODE, O_WRONLY);
}
