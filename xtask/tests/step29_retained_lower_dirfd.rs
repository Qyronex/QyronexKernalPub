// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_fd::{FdTable, ReleasedObject};
use kernal_linux_vfs::{InitramfsRoot, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(0x29fd);
const O_RDONLY: u64 = 0;
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 29,
    nanoseconds: 0,
};

type Overlay<'a> = OverlayNamespace<'a, 8, 16, 64, 8>;

fn hex(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(format!("{value:08x}").as_bytes());
}

fn entry(out: &mut Vec<u8>, ino: u32, path: &[u8], mode: u32) {
    let start = out.len();
    out.extend_from_slice(b"070701");
    for value in [
        ino,
        mode,
        0,
        0,
        1,
        0,
        0,
        7,
        3,
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
    entry(&mut out, 1, b".", S_IFDIR | 0o755);
    entry(&mut out, 2, b"ancestor", S_IFDIR | 0o755);
    entry(&mut out, 3, b"TRAILER!!!", 0);
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

#[test]
fn plain_rdonly_lower_dirfd_follows_retained_identity_after_bound_ancestor_move() {
    let bytes = archive_bytes();
    let archive = Archive::parse(&bytes).unwrap();
    let mut overlay = Overlay::new(InitramfsRoot::new(archive, ROOT));
    let root = overlay.open_directory_at(b"/").unwrap();

    // Open the pure-lower directory before any Upper binding exists. This is the ARM64 plain
    // O_RDONLY directory-open contract: VFS retains the directory identity and the shared Linux
    // OFD owns that retained handle even without O_DIRECTORY.
    let held = overlay
        .open_and_retain_directory_from(root, b"ancestor")
        .unwrap();
    let mut fds = FdTable::<8>::new();
    fds.seed_standard_descriptors().unwrap();
    let fd = fds
        .open_retained_directory_linux_with_flags(held, false, O_RDONLY)
        .unwrap();

    // Publishing through the retained lower directory creates its exact Upper binding without
    // replacing the retained logical identity. The now-bound lower ancestor can move while the
    // already-open plain O_RDONLY OFD remains authoritative.
    overlay
        .mkdir_from(held, b"binding", 0o755, 0, 0, NOW)
        .unwrap();
    overlay
        .rename_from(root, b"ancestor", root, b"moved", false)
        .unwrap();
    assert_eq!(overlay.lookup_at(b"/ancestor"), Ok(None));

    // Re-enter through the already-open fd. Relative mutation must follow retained identity to the
    // moved live location rather than reconstructing the stale pre-rename pathname.
    let fd_base = fds.retained_directory(fd.fd()).unwrap();
    assert_eq!(fd_base, held);
    overlay
        .mkdir_from(fd_base, b"after-move", 0o755, 0, 0, NOW)
        .unwrap();
    assert!(overlay.lookup_at(b"/moved/after-move").unwrap().is_some());
    assert_eq!(overlay.lookup_at(b"/ancestor/after-move"), Ok(None));

    fds.close_with_release(fd.fd(), |released| -> Result<(), ()> {
        let ReleasedObject::RetainedDirectory(directory) = released else {
            panic!("plain O_RDONLY directory fd released the wrong authority kind");
        };
        assert_eq!(directory, held);
        overlay.release_directory(directory).map_err(|_| ())
    })
    .unwrap()
    .unwrap();
}
