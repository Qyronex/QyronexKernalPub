// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    InitramfsRoot, MutableTimestamp, OverlayNamespace, OverlayNodeHandle, RootId,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(101);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 21,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 16, 24, 64, 8>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, path: &[u8], mode: u32, data: &[u8]) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        1,
        mode,
        7,
        8,
        1,
        19,
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
    entry(&mut out, b"etc", S_IFDIR | 0o755, b"");
    entry(&mut out, b"etc/base", S_IFREG | 0o644, b"base");
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
fn lower_regular_handle_remains_logical_identity_after_copyup() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let lower = overlay.lookup_at(b"/etc/base").unwrap().unwrap();
    assert!(matches!(lower, OverlayNodeHandle::Immutable { .. }));

    // Model an OFD that was opened before the first write caused copy-up.
    overlay.retain_open(lower).unwrap();
    overlay.write_at(b"/etc/base", 0, b"UP", NOW).unwrap();

    // A fresh lookup and the already-open logical handle must name the same VFS object. The mutable
    // backing is an implementation detail and must not replace the stable lower EntryId identity.
    let after = overlay.lookup_at(b"/etc/base").unwrap().unwrap();
    assert_eq!(after, lower);

    let mut output = [0u8; 8];
    let count = overlay.read_regular(lower, 0, &mut output).unwrap();
    assert_eq!(&output[..count], b"UPse");

    // Removing the name must not invalidate the already-open logical object.
    overlay.unlink_regular_at(b"/etc/base").unwrap();
    let mut after_unlink = [0u8; 8];
    let count = overlay.read_regular(lower, 0, &mut after_unlink).unwrap();
    assert_eq!(&after_unlink[..count], b"UPse");
    overlay.release_open(lower).unwrap();
}

#[test]
fn lower_directory_handle_sees_upper_children_materialized_later() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let directory = overlay.open_directory_at(b"/etc").unwrap();
    assert!(matches!(
        directory.object(),
        OverlayNodeHandle::Immutable { .. }
    ));

    // This materializes an upper backing for /etc after the directory handle was already opened.
    overlay
        .create_regular_at(b"/etc/new", 0o600, 0, 0, NOW)
        .unwrap();

    let mut cursor = 0usize;
    let mut saw_new = false;
    while let Some(scan) = overlay.directory_entry_from(directory, cursor).unwrap() {
        if scan.entry().name() == b"new" {
            saw_new = true;
            break;
        }
        assert!(scan.next_cursor() > cursor);
        cursor = scan.next_cursor();
    }
    assert!(
        saw_new,
        "retained lower directory handle hid later upper child"
    );
}
