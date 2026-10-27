// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{Error as FdError, FdTable, OpenObjectKind, ReleasedObject, SeekWhence};
use kernal_linux_vfs::{
    InitramfsRoot, MutableTimestamp, OverlayNamespace, OverlayNodeHandle, RootId,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(233);
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 233,
    nanoseconds: 9,
};

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 4>;

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

#[test]
fn retained_lower_readonly_ofd_tracks_copyup_and_survives_unlink_until_final_close() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let logical = overlay.lookup_at(b"/base").unwrap().unwrap();
    assert!(matches!(logical, OverlayNodeHandle::Immutable { .. }));

    // An O_RDONLY open retains only the logical Overlay identity. It must not allocate/copy-up
    // writable Upper backing merely to manufacture an FD authority.
    overlay.retain_open(logical).unwrap();
    assert_eq!(overlay.lookup_at(b"/base").unwrap(), Some(logical));

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_retained_readonly_linux_with_flags(logical, false, O_RDONLY)
        .unwrap();
    let alias = fds.duplicate_lowest(fd.fd(), false).unwrap();
    assert_eq!(fds.object_kind(fd.fd()), Ok(OpenObjectKind::File));
    assert_eq!(fds.open_file_id(fd.fd()), fds.open_file_id(alias.fd()));

    let first = fds.prepare_retained_read(fd.fd(), 5).unwrap();
    assert_eq!(first.2, logical);
    assert_eq!(first.3, 0);
    let mut out = [0u8; 5];
    let count = overlay.read_regular(first.2, first.3, &mut out).unwrap();
    assert_eq!(&out[..count], b"abcde");
    assert_eq!(fds.commit_retained_read(first, count), Ok(5));

    // A different OFD may materialize/copy-up and mutate the same logical object. The original
    // O_RDONLY OFD must keep the logical Overlay identity and therefore observe the live Upper
    // backing, never a stale ReadOnlyFile/CPIO byte snapshot.
    let writable = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();
    assert_eq!(writable.object(), logical);
    assert_eq!(
        overlay.write_retained_regular(writable, 0, b"XY", NOW),
        Ok(2)
    );

    let positional = fds.prepare_retained_pread(alias.fd(), 0, 5).unwrap();
    assert_eq!(positional.2, logical);
    let mut current = [0u8; 5];
    let count = overlay
        .read_regular(positional.2, positional.3, &mut current)
        .unwrap();
    assert_eq!(&current[..count], b"XYcde");
    assert_eq!(fds.validate_retained_pread(positional), Ok(()));
    overlay.release_retained_regular(writable).unwrap();

    // Linux open-file lifetime is object based: unlink removes the pathname, not an already-open
    // retained logical object. The retained read must remain usable until the final OFD close.
    overlay.unlink_regular_at(b"/base").unwrap();
    assert_eq!(overlay.lookup_at(b"/base").unwrap(), None);
    let after_unlink = fds.prepare_retained_pread(fd.fd(), 0, 5).unwrap();
    let mut held = [0u8; 5];
    let count = overlay
        .read_regular(after_unlink.2, after_unlink.3, &mut held)
        .unwrap();
    assert_eq!(&held[..count], b"XYcde");
    assert_eq!(fds.validate_retained_pread(after_unlink), Ok(()));

    assert_eq!(
        fds.close_with_release(alias.fd(), |_| -> Result<(), ()> {
            panic!("non-final duplicate must not release retained Overlay authority")
        }),
        Ok(Ok(()))
    );
    assert_eq!(fds.retained_readonly(fd.fd()), Ok(logical));
    assert_eq!(
        fds.close_with_release(fd.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::RetainedReadOnly(released) = object else {
                panic!("final O_RDONLY close returned the wrong authority kind");
            };
            assert_eq!(released, logical);
            overlay.release_open(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );
}

#[test]
fn upper_created_regular_can_be_reopened_as_retained_readonly_without_writable_capability() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay
        .create_regular_at(b"/upper-only", 0o640, 0, 0, NOW)
        .unwrap();
    overlay.write_at(b"/upper-only", 0, b"upper", NOW).unwrap();
    let logical = overlay.lookup_at(b"/upper-only").unwrap().unwrap();
    assert!(matches!(logical, OverlayNodeHandle::Mutable(_)));
    overlay.retain_open(logical).unwrap();

    let mut fds = FdTable::<6>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_retained_readonly_linux_with_flags(logical, false, O_RDONLY)
        .unwrap();
    assert_eq!(fds.retained_readonly(fd.fd()), Ok(logical));

    let plan = fds.prepare_retained_pread(fd.fd(), 0, 5).unwrap();
    let mut out = [0u8; 5];
    let count = overlay.read_regular(plan.2, plan.3, &mut out).unwrap();
    assert_eq!(&out[..count], b"upper");
    assert_eq!(fds.validate_retained_pread(plan), Ok(()));

    assert_eq!(
        fds.close_with_release(fd.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::RetainedReadOnly(released) = object else {
                panic!("final O_RDONLY close returned the wrong authority kind");
            };
            overlay.release_open(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );

    // The O_RDONLY FD never owns a writable retained token; a later independent O_RDWR open still
    // obtains the writable authority through the accepted VFS owner when explicitly requested.
    let writable = overlay
        .prepare_and_retain_writable_regular_at(b"/upper-only")
        .unwrap();
    let mut writable_fds = FdTable::<6>::new();
    writable_fds.seed_standard_descriptors().unwrap();
    let writable_fd = writable_fds
        .open_writable_linux_with_flags(writable, false, O_RDWR)
        .unwrap();
    assert_eq!(
        writable_fds.writable_regular(writable_fd.fd()),
        Ok(writable)
    );
    assert_eq!(
        writable_fds.close_with_release(writable_fd.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::WritableRegular(released) = object else {
                panic!("O_RDWR close returned the wrong authority kind");
            };
            overlay.release_retained_regular(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );
}

#[test]
fn retained_readonly_rejects_writable_access_and_seeks_against_live_vfs_eof() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let logical = overlay.lookup_at(b"/base").unwrap().unwrap();
    overlay.retain_open(logical).unwrap();

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    assert_eq!(
        fds.open_retained_readonly_linux_with_flags(logical, false, O_WRONLY),
        Err(FdError::BadFd)
    );
    assert_eq!(
        fds.open_retained_readonly_linux_with_flags(logical, false, O_RDWR),
        Err(FdError::BadFd)
    );

    let fd = fds
        .open_retained_readonly_linux_with_flags(logical, false, O_RDONLY)
        .unwrap();
    let alias = fds.duplicate_lowest(fd.fd(), false).unwrap();

    // Extend the object through an independently retained writable authority. The retained O_RDONLY
    // OFD must use the live EOF supplied by VFS, never the immutable lower size captured at open.
    let writable = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();
    assert_eq!(
        overlay.write_retained_regular(writable, 5, b"++", NOW),
        Ok(2)
    );
    let live_end = overlay.retained_regular_metadata(writable).unwrap().size();
    assert_eq!(live_end, 7);
    overlay.release_retained_regular(writable).unwrap();

    assert_eq!(
        fds.seek_retained_readonly(fd.fd(), 0, SeekWhence::End, live_end),
        Ok(live_end)
    );
    assert_eq!(
        fds.prepare_retained_read(alias.fd(), 1).unwrap().3,
        live_end
    );

    assert_eq!(
        fds.close_with_release(alias.fd(), |_| -> Result<(), ()> {
            panic!("non-final duplicate must not release retained Overlay authority")
        }),
        Ok(Ok(()))
    );
    assert_eq!(
        fds.close_with_release(fd.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::RetainedReadOnly(released) = object else {
                panic!("final O_RDONLY close returned the wrong authority kind");
            };
            overlay.release_open(released).map_err(|_| ())
        }),
        Ok(Ok(()))
    );
}
