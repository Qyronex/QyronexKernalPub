// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(81);
const LOWER_TIME: MutableTimestamp = MutableTimestamp {
    seconds: 31,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 4>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, uid: u32, gid: u32, mtime: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        uid,
        gid,
        1,
        mtime,
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
    entry(&mut out, b".", S_IFDIR | 0o755, 0, 0, 1, b"");
    entry(&mut out, b"etc", S_IFDIR | 0o755, 5, 6, 7, b"");
    entry(&mut out, b"etc/base", S_IFREG | 0o640, 17, 23, 31, b"base");
    entry(&mut out, b"TRAILER!!!", 0, 0, 0, 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

#[test]
fn lower_copy_up_preserves_available_newc_metadata_before_mutation() {
    let bytes = archive_bytes();
    let lower_before = bytes.clone();
    let lower = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT);
    let mut overlay = Overlay::new(lower);

    let node = overlay.copy_up_regular_at(b"/etc/base").unwrap();
    let metadata = overlay.upper().metadata(node).unwrap();

    assert_eq!(metadata.mode(), S_IFREG | 0o640);
    assert_eq!(metadata.uid(), 17);
    assert_eq!(metadata.gid(), 23);
    assert_eq!(metadata.size(), 4);
    assert_eq!(metadata.mtime(), LOWER_TIME);
    // newc has no independent atime/ctime. The bounded mutable copy deliberately initializes those
    // fields from the only source timestamp rather than inventing a second clock value.
    assert_eq!(metadata.atime(), LOWER_TIME);
    assert_eq!(metadata.ctime(), LOWER_TIME);
    assert_eq!(bytes, lower_before);
}
