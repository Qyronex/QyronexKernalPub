// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(103);

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
        23,
        24,
        1,
        17,
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
    entry(&mut out, b"source", S_IFREG | 0o644, b"source-bytes");
    entry(&mut out, b"target", S_IFREG | 0o600, b"target-bytes");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn read_all(overlay: &Overlay<'_>, path: &[u8]) -> Vec<u8> {
    let handle = overlay.lookup_at(path).unwrap().unwrap();
    let mut output = [0u8; 32];
    let count = overlay.read_regular(handle, 0, &mut output).unwrap();
    output[..count].to_vec()
}

#[test]
fn rename_replace_over_lower_target_keeps_new_upper_visible_until_unlink() {
    let bytes = archive_bytes();
    let mut overlay = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));

    assert_eq!(read_all(&overlay, b"/source"), b"source-bytes");
    assert_eq!(read_all(&overlay, b"/target"), b"target-bytes");

    overlay.rename_at(b"/source", b"/target", false).unwrap();

    assert!(overlay.lookup_at(b"/source").unwrap().is_none());
    assert_eq!(read_all(&overlay, b"/target"), b"source-bytes");

    // The replacement Upper dentry shadows the old lower target while it exists. Only when the
    // replacement is removed should unlink install the target tombstone, preventing lower fallback
    // from resurrecting the pre-rename target object.
    overlay.unlink_at(b"/target", false).unwrap();
    assert!(overlay.lookup_at(b"/target").unwrap().is_none());
}
