// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const ROOT: RootId = RootId::new(161);
const T: MutableTimestamp = MutableTimestamp {
    seconds: 71,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 8, 16, 64, 8>;
type TinyOverlay<'a> = OverlayNamespace<'a, 2, 8, 64, 4>;

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
        1,
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
    entry(&mut out, b"real", S_IFDIR | 0o755, b"");
    entry(&mut out, b"alias", S_IFLNK | 0o777, b"real");
    entry(&mut out, b"lower", S_IFDIR | 0o755, b"");
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

#[test]
fn create_regular_follows_intermediate_union_symlink_parent() {
    let bytes = archive_bytes();
    let mut overlay = Overlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));

    overlay
        .create_regular_at(b"/alias/created", 0o600, 1, 2, T)
        .unwrap();

    let through_alias = overlay.lookup_at(b"/alias/created").unwrap().unwrap();
    let through_target = overlay.lookup_at(b"/real/created").unwrap().unwrap();
    assert_eq!(through_alias, through_target);
}

#[test]
fn oversized_final_name_fails_before_lower_parent_publication() {
    let bytes = archive_bytes();
    let mut overlay = TinyOverlay::new(InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT));

    let long_name = [b'x'; 256];
    let mut path = Vec::from(&b"/lower/"[..]);
    path.extend_from_slice(&long_name);
    assert!(overlay.create_regular_at(&path, 0o600, 1, 2, T).is_err());

    // NODES=2: if the failed operation materialized lower `/lower` before rejecting NAME_MAX,
    // only one root-level fresh file could be created. Both must fit when validation is read-only.
    overlay
        .create_regular_at(b"/fresh-a", 0o600, 1, 2, T)
        .unwrap();
    overlay
        .create_regular_at(b"/fresh-b", 0o600, 1, 2, T)
        .unwrap();
}
