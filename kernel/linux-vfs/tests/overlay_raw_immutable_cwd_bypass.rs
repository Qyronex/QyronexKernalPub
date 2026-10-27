// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{
    AT_FDCWD, FsContext, InitramfsRoot, OverlayNamespace, RootId, RootedMutableNamespace,
};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(184);

type Overlay<'a> = OverlayNamespace<'a, 8, 12, 64, 8>;
type ForeignMutable = RootedMutableNamespace<4, 8, 16>;

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
        1,
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
    entry(&mut out, b"etc", S_IFDIR | 0o755);
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
fn raw_immutable_cwd_cannot_bypass_overlay_owned_process_publication() {
    let bytes = archive_bytes();

    // A direct immutable-root handle is intentionally compact and has no Overlay owner witness.
    // It may be useful to immutable APIs, but it must not become process cwd merely because an
    // unrelated mutable namespace happens to use the same RootId.
    let raw = InitramfsRoot::new(Archive::parse(&bytes).unwrap(), ROOT)
        .directory_handle_at(AT_FDCWD, b"/etc")
        .unwrap();
    let mut foreign_mutable = ForeignMutable::new(ROOT);
    let mut context = FsContext::new(ROOT);
    let original_cwd = context.cwd_handle();

    assert!(
        raw.refresh_in(&foreign_mutable).is_err(),
        "RootId equality must not revalidate an unbound immutable handle in a mutable owner"
    );
    assert!(
        context.set_cwd(&mut foreign_mutable, raw).is_err(),
        "RootId equality must not publish an unbound immutable handle as process cwd"
    );
    assert_eq!(context.cwd_handle(), original_cwd);

    // The exact Overlay owner is the only process-publication path for this immutable directory.
    let mut owner = overlay(&bytes);
    let owned = owner.open_directory_at(b"/etc").unwrap();
    owner.set_context_cwd(&mut context, owned).unwrap();
    assert_eq!(
        owner
            .revalidate_directory_handle(context.cwd_handle())
            .unwrap(),
        owned
    );

    // A same-RootId sibling still cannot launder the published process cwd authority.
    let sibling = overlay(&bytes);
    assert!(
        sibling
            .revalidate_directory_handle(context.cwd_handle())
            .is_err()
    );
}
