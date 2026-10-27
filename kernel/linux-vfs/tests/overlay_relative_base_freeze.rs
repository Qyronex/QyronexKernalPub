// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    AT_FDCWD, CanonicalPath, InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const ROOT: RootId = RootId::new(163);
const T: MutableTimestamp = MutableTimestamp {
    seconds: 71,
    nanoseconds: 3,
};

type Overlay<'a> = OverlayNamespace<'a, 32, 48, 64, 8>;

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
    entry(&mut out, b"a", S_IFDIR | 0o755, b"");
    entry(&mut out, b"a/z", S_IFREG | 0o644, b"wrong");
    entry(&mut out, b"a/link", S_IFLNK | 0o777, b"/x/y");
    entry(&mut out, b"x", S_IFDIR | 0o755, b"");
    entry(&mut out, b"x/y", S_IFDIR | 0o755, b"");
    entry(&mut out, b"x/z", S_IFREG | 0o644, b"correct");
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
fn relative_union_path_follows_symlink_before_dotdot_from_directory_identity() {
    let bytes = archive_bytes();
    let overlay = overlay(&bytes);
    let base = overlay.open_directory_at(b"/a").unwrap();

    let resolved = overlay.resolve_following_from(base, b"link/../z").unwrap();
    let expected = overlay.lookup_at(b"/x/z").unwrap().unwrap();
    let wrong = overlay.lookup_at(b"/a/z").unwrap().unwrap();

    assert_eq!(resolved, expected);
    assert_ne!(resolved, wrong);

    let absolute = overlay.resolve_following_from(base, b"/a/z").unwrap();
    assert_eq!(absolute, wrong);
}

#[test]
fn relative_nofollow_uses_the_same_directory_identity_base() {
    let bytes = archive_bytes();
    let overlay = overlay(&bytes);
    let base = overlay.open_directory_at(b"/a").unwrap();

    let nofollow = overlay.resolve_nofollow_from(base, b"link").unwrap();
    let link_path = CanonicalPath::resolve_at(AT_FDCWD, b"a/link").unwrap();
    let link = overlay.lookup_canonical(link_path).unwrap().unwrap();
    assert_eq!(nofollow, link);

    let followed = overlay.resolve_following_from(base, b"link").unwrap();
    let target = overlay.lookup_at(b"/x/y").unwrap().unwrap();
    assert_eq!(followed, target);
}

#[test]
fn retained_mutable_directory_base_survives_rename_without_path_reconstruction() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, T).unwrap();
    overlay
        .create_regular_at(b"/held/child", 0o600, 1, 2, T)
        .unwrap();
    let held = overlay.open_directory_at(b"/held").unwrap();

    overlay.rename_at(b"/held", b"/moved", false).unwrap();
    assert_eq!(overlay.lookup_at(b"/held"), Ok(None));

    let resolved = overlay.resolve_following_from(held, b"child").unwrap();
    let expected = overlay.lookup_at(b"/moved/child").unwrap().unwrap();
    assert_eq!(resolved, expected);
}

#[test]
fn retained_mutable_base_beyond_path_max_still_resolves_short_relative_child() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);
    overlay.mkdir_at(b"/held", 0o755, 1, 2, T).unwrap();
    overlay
        .create_regular_at(b"/held/child", 0o600, 1, 2, T)
        .unwrap();
    let held = overlay.open_directory_at(b"/held").unwrap();
    let child = overlay.lookup_at(b"/held/child").unwrap().unwrap();

    let mut current_top = b"held".to_vec();
    for index in 0..18u8 {
        let mut wrapper = vec![b'a' + (index % 26); 240];
        wrapper[0] = b'a' + (index % 26);
        let mut absolute_wrapper = Vec::with_capacity(wrapper.len() + 1);
        absolute_wrapper.push(b'/');
        absolute_wrapper.extend_from_slice(&wrapper);
        overlay.mkdir_at(&absolute_wrapper, 0o755, 1, 2, T).unwrap();

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

    let resolved = overlay.resolve_following_from(held, b"child").unwrap();
    assert_eq!(resolved, child);
}
