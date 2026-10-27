// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

//! Red Step-29 owner oracle for cwd/dirfd-relative open authority.
//!
//! Final ARM64 integration must not reconstruct an absolute pathname merely to open a directory,
//! prepare a writable regular OFD, or truncate a relative regular. These operations must remain
//! rooted in the exact retained `OverlayDirectoryHandle`, including after rename and when pathname
//! presentation exceeds PATH_MAX.

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(214);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 111,
    nanoseconds: 7,
};

type Overlay<'a> = OverlayNamespace<'a, 96, 144, 512, 32>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        0,
        0,
        1,
        0,
        0,
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
}

fn archive_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755);
    entry(&mut out, b"TRAILER!!!", 0);
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

#[test]
fn retained_directory_can_open_and_prepare_relative_objects_after_rename() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, NOW).unwrap();
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();
    overlay.rename_at(b"/held", b"/moved", false).unwrap();

    let reopened = overlay.open_directory_from(held, b".").unwrap();
    assert_eq!(reopened.object(), held.object());

    let retained_again = overlay.open_and_retain_directory_from(held, b".").unwrap();
    assert_eq!(retained_again.object(), held.object());
    overlay.release_directory(retained_again).unwrap();

    overlay
        .create_regular_from(held, b"file", 0o600, 1, 2, NOW)
        .unwrap();
    let writable = overlay
        .prepare_and_retain_writable_regular_from(held, b"file")
        .unwrap();
    assert_eq!(
        overlay
            .write_retained_regular(writable, 0, b"abcdef", NOW)
            .unwrap(),
        6
    );
    overlay.truncate_from(held, b"file", 3, NOW).unwrap();
    assert_eq!(
        overlay.retained_regular_metadata(writable).unwrap().size(),
        3
    );
    overlay.release_retained_regular(writable).unwrap();

    assert!(overlay.lookup_at(b"/held/file").unwrap().is_none());
    assert!(overlay.lookup_at(b"/moved/file").unwrap().is_some());
    overlay.release_directory(held).unwrap();
}

#[test]
fn relative_open_prepare_and_truncate_ignore_pathmax_presentation() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, NOW).unwrap();
    let held = overlay.open_and_retain_directory_at(b"/held").unwrap();

    let mut current_top = b"held".to_vec();
    for index in 0..18u8 {
        let mut wrapper = vec![b'a' + (index % 26); 240];
        wrapper[0] = b'a' + (index % 26);
        let mut absolute_wrapper = Vec::with_capacity(wrapper.len() + 1);
        absolute_wrapper.push(b'/');
        absolute_wrapper.extend_from_slice(&wrapper);
        overlay
            .mkdir_at(&absolute_wrapper, 0o755, 1, 2, NOW)
            .unwrap();

        let mut source = Vec::with_capacity(current_top.len() + 1);
        source.push(b'/');
        source.extend_from_slice(&current_top);
        let mut destination = Vec::with_capacity(wrapper.len() + current_top.len() + 2);
        destination.push(b'/');
        destination.extend_from_slice(&wrapper);
        destination.push(b'/');
        destination.extend_from_slice(&current_top);
        overlay.rename_at(&source, &destination, false).unwrap();
        current_top = wrapper;
    }

    assert!(overlay.directory_canonical_path(held).is_err());
    assert_eq!(
        overlay.open_directory_from(held, b".").unwrap().object(),
        held.object()
    );

    overlay
        .create_regular_from(held, b"file", 0o600, 1, 2, NOW)
        .unwrap();
    let writable = overlay
        .prepare_and_retain_writable_regular_from(held, b"file")
        .unwrap();
    overlay
        .write_retained_regular(writable, 0, b"123456", NOW)
        .unwrap();
    overlay.truncate_from(held, b"file", 2, NOW).unwrap();
    assert_eq!(
        overlay.retained_regular_metadata(writable).unwrap().size(),
        2
    );
    overlay.release_retained_regular(writable).unwrap();
    overlay.release_directory(held).unwrap();
}
