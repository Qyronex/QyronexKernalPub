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
    entry(&mut out, b"source", S_IFREG | 0o644, b"source-bytes");
    entry(&mut out, b"target", S_IFREG | 0o644, b"old-target");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

#[test]
fn lower_replace_target_stays_visible_until_replacement_is_unlinked() {
    let bytes = archive_bytes();
    let mut overlay = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));

    overlay.rename_at(b"/source", b"/target", false).unwrap();
    assert!(overlay.lookup_at(b"/source").unwrap().is_none());

    // The live renamed upper object must shadow the old immutable target. Tombstoning the target
    // here would hide the replacement itself because tombstone lookup precedes upper lookup.
    let target = overlay
        .lookup_at(b"/target")
        .unwrap()
        .expect("successful rename replacement must remain visible");
    let mut output = [0u8; 16];
    let count = overlay.read_regular(target, 0, &mut output).unwrap();
    assert_eq!(&output[..count], b"source-bytes");

    // Removing the replacement is the point where the old lower target must become hidden rather
    // than resurrecting. unlink already owns that tombstone transition.
    overlay.unlink_at(b"/target", false).unwrap();
    assert!(overlay.lookup_at(b"/target").unwrap().is_none());

    // Protected archive bytes are unchanged; a fresh overlay still exposes the original names.
    let fresh = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));
    let source = fresh.lookup_at(b"/source").unwrap().unwrap();
    let target = fresh.lookup_at(b"/target").unwrap().unwrap();
    let mut source_bytes = [0u8; 16];
    let mut target_bytes = [0u8; 16];
    let source_count = fresh.read_regular(source, 0, &mut source_bytes).unwrap();
    let target_count = fresh.read_regular(target, 0, &mut target_bytes).unwrap();
    assert_eq!(&source_bytes[..source_count], b"source-bytes");
    assert_eq!(&target_bytes[..target_count], b"old-target");
}
