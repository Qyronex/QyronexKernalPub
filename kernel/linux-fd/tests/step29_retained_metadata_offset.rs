// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{Error as FdError, FdTable, OpenObjectKind, ReleasedObject, SeekWhence};
use kernal_linux_vfs::{InitramfsRoot, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(239);
const O_RDONLY: u64 = 0;
const O_RDWR: u64 = 2;

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

#[test]
fn retained_regular_backings_keep_file_offset_and_never_synthesize_char_metadata() {
    let bytes = archive_bytes();
    let mut overlay = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));
    let logical = overlay.lookup_at(b"/base").unwrap().unwrap();
    overlay.retain_open(logical).unwrap();

    let mut readonly_fds = FdTable::<8>::new();
    readonly_fds.seed_standard_descriptors().unwrap();
    let readonly = readonly_fds
        .open_retained_readonly_linux_with_flags(logical, false, O_RDONLY)
        .unwrap();
    assert_eq!(
        readonly_fds.object_kind(readonly.fd()),
        Ok(OpenObjectKind::File)
    );
    assert_eq!(readonly_fds.metadata(readonly.fd()), Err(FdError::NotFile));
    assert_eq!(readonly_fds.offset(readonly.fd()), Ok(0));
    assert_eq!(
        readonly_fds.seek_retained_readonly(readonly.fd(), 3, SeekWhence::Set, 5),
        Ok(3)
    );
    assert_eq!(readonly_fds.offset(readonly.fd()), Ok(3));

    readonly_fds
        .close_with_release(readonly.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::RetainedReadOnly(released) = object else {
                panic!("expected retained-readonly release");
            };
            assert_eq!(released, logical);
            Ok(())
        })
        .unwrap()
        .unwrap();
    overlay.release_open(logical).unwrap();

    let retained = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();
    let live_end = overlay.retained_regular_metadata(retained).unwrap().size();
    let mut writable_fds = FdTable::<8>::new();
    writable_fds.seed_standard_descriptors().unwrap();
    let writable = writable_fds
        .open_writable_linux_with_flags(retained, false, O_RDWR)
        .unwrap();
    assert_eq!(
        writable_fds.object_kind(writable.fd()),
        Ok(OpenObjectKind::File)
    );
    assert_eq!(writable_fds.metadata(writable.fd()), Err(FdError::NotFile));
    assert_eq!(writable_fds.offset(writable.fd()), Ok(0));
    assert_eq!(
        writable_fds.seek_writable(writable.fd(), 2, SeekWhence::Set, live_end),
        Ok(2)
    );
    assert_eq!(writable_fds.offset(writable.fd()), Ok(2));

    writable_fds
        .close_with_release(writable.fd(), |object| -> Result<(), ()> {
            let ReleasedObject::WritableRegular(released) = object else {
                panic!("expected writable-regular release");
            };
            assert_eq!(released, retained);
            Ok(())
        })
        .unwrap()
        .unwrap();
    overlay.release_retained_regular(retained).unwrap();
}
