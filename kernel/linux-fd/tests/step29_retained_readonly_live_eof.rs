// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{FdTable, ReleasedObject, SeekWhence};
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(234);
const O_RDONLY: u64 = 0;
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 234,
    nanoseconds: 10,
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

#[test]
fn retained_readonly_seek_end_uses_live_overlay_size_after_other_ofd_mutation() {
    let bytes = archive_bytes();
    let mut overlay = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));
    let logical = overlay.lookup_at(b"/base").unwrap().unwrap();
    overlay.retain_open(logical).unwrap();

    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_retained_readonly_linux_with_flags(logical, false, O_RDONLY)
        .unwrap();
    let alias = fds.duplicate_lowest(fd.fd(), false).unwrap();

    // Initial immutable size is five bytes.
    let initial_end = overlay.metadata(logical).unwrap().size();
    assert_eq!(initial_end, 5);
    assert_eq!(
        fds.seek_retained_readonly(fd.fd(), 0, SeekWhence::End, initial_end),
        Ok(5)
    );

    // A distinct writable OFD materializes the same logical object and grows it. SEEK_END through
    // the already-open O_RDONLY OFD must consume the current VFS size, not the stale CPIO size.
    let writable = overlay
        .prepare_and_retain_writable_regular_at(b"/base")
        .unwrap();
    assert_eq!(
        overlay.write_retained_regular(writable, 5, b"XYZ", NOW),
        Ok(3)
    );
    let grown_end = overlay.metadata(logical).unwrap().size();
    assert_eq!(grown_end, 8);
    assert_eq!(
        fds.seek_retained_readonly(alias.fd(), 0, SeekWhence::End, grown_end),
        Ok(8)
    );

    // Truncation by that independent writable authority must also be visible immediately.
    overlay.truncate_retained_regular(writable, 2, NOW).unwrap();
    let truncated_end = overlay.metadata(logical).unwrap().size();
    assert_eq!(truncated_end, 2);
    assert_eq!(
        fds.seek_retained_readonly(fd.fd(), 0, SeekWhence::End, truncated_end),
        Ok(2)
    );
    overlay.release_retained_regular(writable).unwrap();

    assert_eq!(
        fds.close_with_release(alias.fd(), |_| -> Result<(), ()> {
            panic!("non-final alias must not release retained O_RDONLY authority")
        }),
        Ok(Ok(()))
    );
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
