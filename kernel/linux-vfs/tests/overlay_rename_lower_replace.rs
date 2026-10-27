// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(103);

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 2>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        31,
        32,
        1,
        23,
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
    entry(&mut out, b"source", S_IFREG | 0o644, b"source");
    entry(&mut out, b"target", S_IFREG | 0o644, b"target");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn assert_bytes(overlay: &Overlay<'_>, path: &[u8], expected: &[u8]) {
    let handle = overlay.lookup_at(path).unwrap().unwrap();
    let mut output = [0u8; 16];
    let count = overlay.read_regular(handle, 0, &mut output).unwrap();
    assert_eq!(&output[..count], expected);
}

#[test]
fn lower_replace_keeps_live_target_visible_and_hides_old_lower_after_unlink() {
    let bytes = archive_bytes();
    let mut view = overlay(&bytes);

    // Rename needs to hide the immutable source name while the live renamed upper object shadows
    // the immutable destination. A later unlink must also hide that old destination, so this full
    // rename+unlink sequence requires two bounded tombstone slots.
    view.rename_at(b"/source", b"/target", false).unwrap();

    assert_eq!(view.lookup_at(b"/source"), Ok(None));
    assert_bytes(&view, b"/target", b"source");

    // Removing the replacement consumes the second tombstone and must not resurrect the old
    // immutable target into the live union namespace.
    view.unlink_regular_at(b"/target").unwrap();
    assert_eq!(view.lookup_at(b"/target"), Ok(None));

    // A fresh overlay proves the immutable archive itself was never modified by either operation.
    let fresh = overlay(&bytes);
    assert_bytes(&fresh, b"/source", b"source");
    assert_bytes(&fresh, b"/target", b"target");
}
