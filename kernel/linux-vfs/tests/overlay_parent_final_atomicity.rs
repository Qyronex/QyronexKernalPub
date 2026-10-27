// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    InitramfsRoot, MutableError, MutableTimestamp, OverlayError, OverlayNamespace, RootId,
    RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(107);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 17,
    nanoseconds: 0,
};

type TinyOverlay<'a> = OverlayNamespace<'a, 1, 4, 64, 4>;

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
    entry(&mut out, b"dir", S_IFDIR | 0o755);
    entry(&mut out, b"TRAILER!!!", 0);
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> TinyOverlay<'_> {
    TinyOverlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn assert_no_upper_parent(overlay: &TinyOverlay<'_>) {
    let root = overlay.upper().root_directory();
    assert_eq!(
        overlay.upper().lookup(root, b"dir"),
        Err(RootedMutableError::Mutable(MutableError::NotFound))
    );
    assert!(overlay.lookup_at(b"/dir").unwrap().is_some());
}

fn node_full() -> OverlayError {
    OverlayError::Mutable(RootedMutableError::Mutable(MutableError::NodeTableFull))
}

#[test]
fn failed_create_regular_does_not_publish_lower_only_parent() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    // NODES=1 can materialize `/dir` or allocate the final regular file, but not both. The compound
    // create must reserve parent+final capacity before publishing either object.
    assert_eq!(
        overlay.create_regular_at(b"/dir/file", 0o600, 0, 0, NOW),
        Err(node_full())
    );
    assert_no_upper_parent(&overlay);
}

#[test]
fn failed_mkdir_does_not_publish_lower_only_parent() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    assert_eq!(
        overlay.mkdir_at(b"/dir/child", 0o755, 0, 0, NOW),
        Err(node_full())
    );
    assert_no_upper_parent(&overlay);
}

#[test]
fn failed_symlink_does_not_publish_lower_only_parent() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    assert_eq!(
        overlay.symlink_at(b"target", b"/dir/link", 0, 0, NOW),
        Err(node_full())
    );
    assert_no_upper_parent(&overlay);
}
