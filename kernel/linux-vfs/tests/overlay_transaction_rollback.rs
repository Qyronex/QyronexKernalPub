// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    InitramfsRoot, MutableError, MutableTimestamp, OverlayError, OverlayNamespace, RootId,
    RootedMutableError,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(97);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 11,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 4>;
type TinyOverlay<'a> = OverlayNamespace<'a, 1, 4, 64, 4>;
type TwoNodeOverlay<'a> = OverlayNamespace<'a, 2, 6, 64, 4>;

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
    entry(&mut out, b"base", S_IFREG | 0o644, b"lower");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn nested_archive_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"dir", S_IFDIR | 0o755, b"");
    entry(&mut out, b"dir/base", S_IFREG | 0o644, b"lower");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn compound_archive_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"old", S_IFDIR | 0o755, b"");
    entry(&mut out, b"old/base", S_IFREG | 0o644, b"lower");
    entry(&mut out, b"new", S_IFDIR | 0o755, b"");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn detached_binding_archive_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"held", S_IFREG | 0o644, b"held");
    entry(&mut out, b"dir", S_IFDIR | 0o755, b"");
    entry(&mut out, b"dir/base", S_IFREG | 0o644, b"lower");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn tiny_overlay(bytes: &[u8]) -> TinyOverlay<'_> {
    TinyOverlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn two_node_overlay(bytes: &[u8]) -> TwoNodeOverlay<'_> {
    TwoNodeOverlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn assert_lower_bytes<const NODES: usize, const DENTRIES: usize>(
    overlay: &OverlayNamespace<'_, NODES, DENTRIES, 64, 4>,
    path: &[u8],
    expected: &[u8],
) {
    let handle = overlay.lookup_at(path).unwrap().unwrap();
    let mut output = [0u8; 16];
    let count = overlay.read_regular(handle, 0, &mut output).unwrap();
    assert_eq!(&output[..count], expected);
}

#[test]
fn failed_lower_hardlink_does_not_publish_copyup() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let upper_root = overlay.upper().root_directory();

    // The source exists only in the immutable lower. The destination parent does not exist in
    // either layer. Linux-visible failure must be atomic: validating the source may not publish a
    // copy-up before the destination path is known to be usable.
    assert_eq!(
        overlay.link_regular_at(b"/base", b"/missing/link"),
        Err(OverlayError::NotFound)
    );

    assert_eq!(
        overlay.upper().lookup(upper_root, b"base"),
        Err(RootedMutableError::Mutable(MutableError::NotFound))
    );

    // Fresh union lookup must still resolve the untouched immutable object with its original bytes.
    assert_lower_bytes(&overlay, b"/base", b"lower");
}

#[test]
fn failed_lower_rename_noreplace_does_not_publish_copyup() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    let upper_root = overlay.upper().root_directory();

    overlay
        .create_regular_at(b"/occupied", 0o600, 0, 0, NOW)
        .unwrap();

    // RENAME_NOREPLACE must reject an existing target before a lower-only source is materialized.
    assert_eq!(
        overlay.rename_at(b"/base", b"/occupied", true),
        Err(OverlayError::AlreadyExists)
    );

    assert_eq!(
        overlay.upper().lookup(upper_root, b"base"),
        Err(RootedMutableError::Mutable(MutableError::NotFound))
    );

    assert_lower_bytes(&overlay, b"/base", b"lower");
}

#[test]
fn failed_copyup_rolls_back_materialized_lower_parent() {
    let bytes = nested_archive_bytes();
    let mut overlay = tiny_overlay(&bytes);
    let upper_root = overlay.upper().root_directory();

    // NODES=1 cannot hold both the lower-only parent and final regular file. The complete lower
    // publication must be rejected before either object is published.
    assert_eq!(
        overlay.copy_up_regular_at(b"/dir/base"),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::NodeTableFull,
        )))
    );

    assert_eq!(
        overlay.upper().lookup(upper_root, b"dir"),
        Err(RootedMutableError::Mutable(MutableError::NotFound))
    );
    assert_lower_bytes(&overlay, b"/dir/base", b"lower");
}

#[test]
fn failed_lower_hardlink_reserves_source_destination_parent_and_link_atomically() {
    let bytes = compound_archive_bytes();
    let mut overlay = two_node_overlay(&bytes);
    let upper_root = overlay.upper().root_directory();

    // Source copy-up alone needs exactly two nodes (`old` + `old/base`) and fits. The complete
    // hard-link transaction also needs the distinct lower-only destination parent `/new`; with only
    // two nodes available it must fail before publishing the source copy-up or destination parent.
    assert_eq!(
        overlay.link_regular_at(b"/old/base", b"/new/link"),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::NodeTableFull,
        )))
    );

    for name in [b"old".as_slice(), b"new".as_slice()] {
        assert_eq!(
            overlay.upper().lookup(upper_root, name),
            Err(RootedMutableError::Mutable(MutableError::NotFound))
        );
    }
    assert_lower_bytes(&overlay, b"/old/base", b"lower");
}

#[test]
fn failed_lower_rename_reserves_source_and_destination_parent_atomically() {
    let bytes = compound_archive_bytes();
    let mut overlay = two_node_overlay(&bytes);
    let upper_root = overlay.upper().root_directory();

    // As with hard-link, source copy-up fits by itself but source + distinct lower destination parent
    // does not. Rename must fail before either publication leg becomes visible.
    assert_eq!(
        overlay.rename_at(b"/old/base", b"/new/moved", false),
        Err(OverlayError::Mutable(RootedMutableError::Mutable(
            MutableError::NodeTableFull,
        )))
    );

    for name in [b"old".as_slice(), b"new".as_slice()] {
        assert_eq!(
            overlay.upper().lookup(upper_root, name),
            Err(RootedMutableError::Mutable(MutableError::NotFound))
        );
    }
    assert_lower_bytes(&overlay, b"/old/base", b"lower");
}

#[test]
fn detached_lower_openref_cannot_overbook_binding_capacity() {
    let bytes = detached_binding_archive_bytes();
    let mut overlay = two_node_overlay(&bytes);
    let upper_root = overlay.upper().root_directory();
    let held = overlay.lookup_at(b"/held").unwrap().unwrap();
    overlay.retain_open(held).unwrap();

    // The detached open occupies one of the two logical-binding slots without consuming a mutable
    // node. `/dir/base` has enough node+dentry capacity but requires two new lower bindings; that
    // aggregate binding demand must fail before `/dir` is published. Repeating the failure must not
    // consume capacity or disturb the held logical open.
    for _ in 0..2 {
        assert_eq!(
            overlay.copy_up_regular_at(b"/dir/base"),
            Err(OverlayError::BindingTableFull)
        );
        assert_eq!(
            overlay.upper().lookup(upper_root, b"dir"),
            Err(RootedMutableError::Mutable(MutableError::NotFound))
        );
        assert_lower_bytes(&overlay, b"/held", b"held");
        assert_lower_bytes(&overlay, b"/dir/base", b"lower");
    }

    overlay.release_open(held).unwrap();
}
