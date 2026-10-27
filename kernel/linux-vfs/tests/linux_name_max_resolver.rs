// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    AT_FDCWD, Error, InitramfsRoot, MutableTimestamp, OverlayError, OverlayNamespace, RootId,
};

const HEADER_LEN: usize = 110;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const ROOT: RootId = RootId::new(181);
const T: MutableTimestamp = MutableTimestamp {
    seconds: 73,
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

fn joined(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = Vec::from(parent);
    if !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

fn archive_bytes() -> Vec<u8> {
    let name_255 = [b'a'; 255];
    let name_256 = [b'b'; 256];
    let accepted = joined(b"base", &name_255);
    let rejected = joined(b"base", &name_256);
    let lower = joined(b"lower", &name_256);

    let mut out = Vec::new();
    entry(&mut out, b".", S_IFDIR | 0o755, b"");
    entry(&mut out, b"base", S_IFDIR | 0o755, b"");
    entry(&mut out, &accepted, S_IFREG | 0o644, b"accepted");
    entry(&mut out, &rejected, S_IFREG | 0o644, b"must-not-resolve");
    entry(&mut out, b"lower", S_IFDIR | 0o755, b"");
    entry(&mut out, &lower, S_IFDIR | 0o755, b"");
    entry(&mut out, b"jump", S_IFLNK | 0o777, &rejected);
    entry(&mut out, b"TRAILER!!!", 0, b"");
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn root(bytes: &[u8]) -> InitramfsRoot<'_> {
    InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT)
}

#[test]
fn immutable_and_overlay_resolvers_accept_255_and_reject_256_byte_components() {
    let bytes = archive_bytes();
    let name_255 = [b'a'; 255];
    let name_256 = [b'b'; 256];
    let accepted = joined(b"/base", &name_255);
    let rejected = joined(b"/base", &name_256);

    let lower = root(&bytes);
    assert!(lower.resolve_following_at(AT_FDCWD, &accepted).is_ok());
    assert!(matches!(
        lower.resolve_following_at(AT_FDCWD, &rejected),
        Err(Error::PathTooLong)
    ));

    let overlay = Overlay::new(root(&bytes));
    assert!(overlay.lookup_at(&accepted).unwrap().is_some());
    assert!(matches!(
        overlay.lookup_at(&rejected),
        Err(OverlayError::Path(Error::PathTooLong))
    ));

    let base = overlay.open_directory_at(b"/base").unwrap();
    assert!(overlay.resolve_following_from(base, &name_255).is_ok());
    assert!(matches!(
        overlay.resolve_following_from(base, &name_256),
        Err(OverlayError::Path(Error::PathTooLong))
    ));
}

#[test]
fn symlink_expansion_cannot_bypass_name_max() {
    let bytes = archive_bytes();
    let lower = root(&bytes);
    assert!(matches!(
        lower.resolve_following_at(AT_FDCWD, b"/jump"),
        Err(Error::PathTooLong)
    ));

    let overlay = Overlay::new(root(&bytes));
    assert!(matches!(
        overlay.lookup_at(b"/jump"),
        Err(OverlayError::Path(Error::PathTooLong))
    ));
}

#[test]
fn overlong_intermediate_component_fails_before_lower_copyup() {
    let bytes = archive_bytes();
    let name_256 = [b'b'; 256];
    let mut path = joined(b"/lower", &name_256);
    path.extend_from_slice(b"/created");

    let mut overlay = TinyOverlay::new(root(&bytes));
    assert!(matches!(
        overlay.create_regular_at(&path, 0o600, 1, 2, T),
        Err(OverlayError::Path(Error::PathTooLong))
    ));

    // NODES=2: if rejecting the overlong intermediate component materialized either lower
    // directory into Upper, both fresh root-level objects would no longer fit.
    overlay
        .create_regular_at(b"/fresh-a", 0o600, 1, 2, T)
        .unwrap();
    overlay
        .create_regular_at(b"/fresh-b", 0o600, 1, 2, T)
        .unwrap();
}
