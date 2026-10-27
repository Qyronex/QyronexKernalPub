// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{Error as FdError, FdTable, ReleasedObject, SeekWhence};
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(212);
const O_RDWR: u64 = 2;
const O_APPEND: u64 = 1024;
const T1: MutableTimestamp = MutableTimestamp {
    seconds: 111,
    nanoseconds: 1,
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
fn linux_pwrite_append_uses_live_eof_without_moving_shared_ofd_offset() {
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
    let alias = fds.duplicate_lowest(fd.fd(), false).unwrap();

    let live_end = overlay.retained_regular_metadata(retained).unwrap().size();
    assert_eq!(
        fds.seek_writable(fd.fd(), 1, SeekWhence::Set, live_end),
        Ok(1)
    );
    assert_eq!(fds.prepare_write(alias.fd(), 0).unwrap().3, 1);

    fds.set_mutable_status_flags(alias.fd(), O_APPEND).unwrap();
    let pwrite = fds.prepare_pwrite(fd.fd(), 0, 1).unwrap();

    // Linux deviates from POSIX here: O_APPEND forces pwrite placement to live EOF even though
    // pwrite still must not mutate the shared OFD offset. The FD plan therefore has to carry the
    // snapshotted append state for the integration layer to select the VFS append primitive.
    assert_eq!(pwrite.3, 0);
    assert!(pwrite.5);
    fds.validate_pwrite(pwrite).unwrap();

    let (actual_start, written) = overlay.append_retained_regular(pwrite.2, b"!", T1).unwrap();
    assert_eq!(actual_start, 5);
    assert_eq!(written, 1);
    assert_eq!(read_retained(&overlay, retained), b"abcde!");

    // No pwrite commit exists by design: both the original fd and its dup alias retain the exact
    // same pre-pwrite OFD position.
    assert_eq!(fds.prepare_write(fd.fd(), 0).unwrap().3, 1);
    assert_eq!(fds.prepare_write(alias.fd(), 0).unwrap().3, 1);

    // Append is part of the placement authority snapshot. Changing it after planning must make the
    // plan stale before any VFS mutation can occur.
    let stale = fds.prepare_pwrite(fd.fd(), 0, 1).unwrap();
    assert!(stale.5);
    fds.set_mutable_status_flags(alias.fd(), 0).unwrap();
    assert_eq!(fds.validate_pwrite(stale), Err(FdError::StaleOpenFile));
    assert_eq!(read_retained(&overlay, retained), b"abcde!");

    assert_eq!(
        fds.close_with_release(alias.fd(), |_| -> Result<(), ()> {
            panic!("non-final alias must not release the retained VFS lease")
        }),
        Ok(Ok(()))
    );
    assert_eq!(
        fds.close_with_release(fd.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::WritableRegular(released) = object else {
                panic!("final close returned the wrong release authority")
            };
            overlay.release_retained_regular(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );
}
