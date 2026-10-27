// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(153);

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
        0,
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
    entry(&mut out, b"base", S_IFREG | 0o640, b"lower");
    entry(&mut out, b"dir", S_IFDIR | 0o755, b"");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn read_all(overlay: &Overlay<'_>, handle: kernal_linux_vfs::OverlayNodeHandle) -> Vec<u8> {
    let mut bytes = [0u8; 16];
    let count = overlay.read_regular(handle, 0, &mut bytes).unwrap();
    bytes[..count].to_vec()
}

#[test]
fn readonly_lower_handle_is_bound_to_its_overlay_owner() {
    let bytes = archive_bytes();
    let mut left = overlay(&bytes);
    let mut right = overlay(&bytes);
    let left_handle = left.lookup_at(b"/base").unwrap().unwrap();
    let right_handle = right.lookup_at(b"/base").unwrap().unwrap();

    assert_ne!(left_handle, right_handle);
    assert!(right.retain_open(left_handle).is_err());
    let mut foreign = [0u8; 8];
    assert!(right.read_regular(left_handle, 0, &mut foreign).is_err());
    assert!(right.metadata(left_handle).is_err());

    left.retain_open(left_handle).unwrap();
    assert_eq!(read_all(&left, left_handle), b"lower");
    left.release_open(left_handle).unwrap();

    right.retain_open(right_handle).unwrap();
    assert!(right.release_open(left_handle).is_err());
    assert_eq!(read_all(&right, right_handle), b"lower");
    right.release_open(right_handle).unwrap();
}

#[test]
fn readonly_directory_handle_is_bound_to_its_overlay_owner() {
    let bytes = archive_bytes();
    let left = overlay(&bytes);
    let right = overlay(&bytes);
    let left_directory = left.open_directory_at(b"/dir").unwrap();
    let right_directory = right.open_directory_at(b"/dir").unwrap();

    assert_ne!(left_directory, right_directory);
    assert!(right.directory_entry_from(left_directory, 0).is_err());
    assert!(
        right
            .directory_entry_from(right_directory, 0)
            .unwrap()
            .is_some()
    );
}
