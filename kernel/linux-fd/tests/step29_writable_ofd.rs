// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{
    Error as FdError, ExternalObject, FdTable, OpenObjectKind, ReleasedObject, SeekWhence,
};
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(211);
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_APPEND: u64 = 1024;
const O_NONBLOCK: u64 = 2048;
const T1: MutableTimestamp = MutableTimestamp {
    seconds: 101,
    nanoseconds: 1,
};
const T2: MutableTimestamp = MutableTimestamp {
    seconds: 102,
    nanoseconds: 2,
};
const T3: MutableTimestamp = MutableTimestamp {
    seconds: 103,
    nanoseconds: 3,
};

type Overlay<'a> = OverlayNamespace<'a, 12, 20, 64, 8>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        0,
        0,
        1,
        7,
        u32::try_from(data.len()).unwrap(),
        0,
        0,
        0,
        0,
        u32::try_from(path.len() + 1).unwrap(),
        0,
    ] {
        hex(out, value);
    }
    assert_eq!(out.len() - start, HEADER_LEN);
    out.extend_from_slice(path);
    out.push(0);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn archive_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"base", S_IFREG | 0o640, b"abcde");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn read_retained(
    overlay: &Overlay<'_>,
    retained: kernal_linux_vfs::RetainedRegularHandle,
) -> Vec<u8> {
    let mut out = [0u8; 64];
    let count = overlay
        .read_retained_regular(retained, 0, &mut out)
        .unwrap();
    out[..count].to_vec()
}

#[test]
fn duplicated_writable_regular_shares_position_and_status_while_pwrite_is_positional() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let retained = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_writable_linux_with_flags(retained, false, O_RDWR)
        .unwrap();
    assert_eq!(fd.fd(), 3);
    assert_eq!(fds.object_kind(fd.fd()), Ok(OpenObjectKind::File));
    let alias = fds.duplicate_lowest(fd.fd(), false).unwrap();
    assert_eq!(alias.fd(), 4);
    assert_eq!(fds.open_file_id(fd.fd()), fds.open_file_id(alias.fd()));

    let write = fds.prepare_write(fd.fd(), 2).unwrap();
    assert_eq!(write.2, retained);
    assert_eq!(write.3, 0);
    assert!(!write.5);
    let written = overlay
        .write_retained_regular(write.2, write.3, b"XY", T1)
        .unwrap();
    assert_eq!(fds.commit_write(write, 0, written), Ok(2));
    assert_eq!(fds.prepare_write(alias.fd(), 0).unwrap().3, 2);
    assert_eq!(read_retained(&overlay, retained), b"XYcde");

    let pwrite = fds.prepare_pwrite(alias.fd(), 4, 1).unwrap();
    assert_eq!(pwrite.2, retained);
    assert_eq!(pwrite.3, 4);
    fds.validate_pwrite(pwrite).unwrap();
    assert_eq!(
        overlay.write_retained_regular(pwrite.2, pwrite.3, b"!", T2),
        Ok(1)
    );
    assert_eq!(fds.prepare_write(fd.fd(), 0).unwrap().3, 2);
    assert_eq!(read_retained(&overlay, retained), b"XYcd!");

    let flags = fds
        .set_mutable_status_flags(alias.fd(), O_APPEND | O_NONBLOCK)
        .unwrap();
    assert_eq!(flags & (O_APPEND | O_NONBLOCK), O_APPEND | O_NONBLOCK);
    assert_eq!(
        fds.status_flags(fd.fd()).unwrap() & (O_APPEND | O_NONBLOCK),
        O_APPEND | O_NONBLOCK
    );
    assert_eq!(fds.status_flags(fd.fd()).unwrap() & 3, O_RDWR);

    let append = fds.prepare_write(fd.fd(), 1).unwrap();
    assert_eq!(append.3, 2);
    assert!(append.5);
    let (append_start, appended) = overlay.append_retained_regular(append.2, b"+", T3).unwrap();
    assert_eq!(append_start, 5);
    assert_eq!(fds.commit_write(append, append_start, appended), Ok(6));
    assert_eq!(fds.prepare_write(alias.fd(), 0).unwrap().3, 6);
    assert_eq!(read_retained(&overlay, retained), b"XYcd!+");

    let live_end = overlay.retained_regular_metadata(retained).unwrap().size();
    assert_eq!(
        fds.seek_writable(alias.fd(), -1, SeekWhence::End, live_end),
        Ok(5)
    );
    assert_eq!(fds.prepare_write(fd.fd(), 0).unwrap().3, 5);

    assert_eq!(
        fds.close_with_release(alias.fd(), |_| -> Result<(), ()> {
            panic!("non-final duplicate must not release VFS authority")
        }),
        Ok(Ok(()))
    );
    assert_eq!(fds.writable_regular(fd.fd()), Ok(retained));
    assert_eq!(
        fds.close_with_release(fd.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::WritableRegular(released) = object else {
                panic!("final writable close returned the wrong authority kind");
            };
            assert_eq!(released, retained);
            overlay.release_retained_regular(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );
    assert!(!fds.token_is_live(fd));
}

#[test]
fn writable_access_and_close_on_exec_boundary_fail_closed() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let retained = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    assert_eq!(
        fds.open_writable_linux_with_flags(retained, false, O_RDONLY),
        Err(FdError::BadFd)
    );

    let fd = fds
        .open_writable_linux_with_flags(retained, true, O_WRONLY)
        .unwrap();
    assert_eq!(fds.prepare_writable_read(fd.fd(), 1), Err(FdError::BadFd));
    assert_eq!(
        fds.prepare_pwrite(fd.fd(), -1, 1),
        Err(FdError::InvalidPreadOffset)
    );

    let inherited_alias = fds.duplicate_lowest(fd.fd(), false).unwrap();
    assert_eq!(fds.next_close_on_exec(None), Some(fd));
    assert_eq!(fds.next_close_on_exec(Some(fd.fd())), None);

    assert_eq!(
        fds.close_token_with_release(fd, |_| -> Result<(), ()> {
            panic!("CLOEXEC alias is not the final OFD reference")
        }),
        Ok(Ok(()))
    );
    assert!(!fds.token_is_live(fd));
    assert!(fds.token_is_live(inherited_alias));
    assert_eq!(fds.next_close_on_exec(None), None);

    assert_eq!(
        fds.close_with_release(inherited_alias.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::WritableRegular(released) = object else {
                panic!("final inherited alias returned the wrong authority kind");
            };
            overlay.release_retained_regular(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );
}

#[test]
fn final_writable_release_and_exact_replacement_are_transactional_and_generation_safe() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let retained = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let target = fds
        .open_writable_linux_with_flags(retained, false, O_RDWR)
        .unwrap();
    let target_open_file = fds.open_file_id(target.fd()).unwrap();

    assert_eq!(fds.close(target.fd()), Err(FdError::StaleOpenFile));
    assert!(fds.token_is_live(target));
    assert_eq!(fds.open_file_id(target.fd()), Ok(target_open_file));
    assert_eq!(
        fds.duplicate_exact(1, target.fd(), false),
        Err(FdError::StaleOpenFile)
    );
    assert!(fds.token_is_live(target));
    assert_eq!(fds.open_file_id(target.fd()), Ok(target_open_file));

    assert_eq!(
        fds.close_with_release(target.fd(), |object| -> Result<(), ()> {
            assert_eq!(object.writable_regular(), Some(retained));
            Err(())
        }),
        Ok(Err(()))
    );
    assert!(fds.token_is_live(target));
    assert_eq!(fds.writable_regular(target.fd()), Ok(retained));
    assert_eq!(read_retained(&overlay, retained), b"abcde");

    assert_eq!(
        fds.duplicate_exact_with_release(1, target.fd(), false, |object| -> Result<(), ()> {
            assert_eq!(object.writable_regular(), Some(retained));
            Err(())
        }),
        Ok(Err(()))
    );
    assert!(fds.token_is_live(target));
    assert_eq!(fds.writable_regular(target.fd()), Ok(retained));

    let replacement = fds
        .duplicate_exact_with_release(1, target.fd(), false, |object| -> Result<(), ()> {
            let ReleasedObject::WritableRegular(released) = object else {
                panic!("exact replacement returned the wrong authority kind");
            };
            overlay.release_retained_regular(released).map_err(|_| ())
        })
        .unwrap()
        .unwrap();
    assert_eq!(replacement.fd(), target.fd());
    assert_ne!(replacement.generation(), target.generation());
    assert!(!fds.token_is_live(target));
    assert!(fds.token_is_live(replacement));
    assert_eq!(
        fds.object_kind(replacement.fd()),
        Ok(OpenObjectKind::External(ExternalObject::Stdout))
    );

    assert_eq!(
        fds.close_token_with_release(target, |_| -> Result<(), ()> {
            panic!("stale token must be rejected before external release")
        }),
        Err(FdError::StaleOpenFile)
    );
    assert!(fds.token_is_live(replacement));
}
