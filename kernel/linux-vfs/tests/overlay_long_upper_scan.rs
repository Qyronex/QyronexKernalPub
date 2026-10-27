// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::Archive;
use kernal_linux_vfs::{InitramfsRoot, LINUX_PATH_MAX, MutableTimestamp, OverlayNamespace, RootId};

const HEADER_LEN: usize = 110;
const S_IFDIR: u32 = 0o040000;
const ROOT: RootId = RootId::new(137);
const NOW: MutableTimestamp = MutableTimestamp {
    seconds: 23,
    nanoseconds: 0,
};
const COMPONENT_LEN: usize = 240;
const DEPTH: usize = 18;

type Overlay<'a> = OverlayNamespace<'a, 32, 40, 8, 8>;

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
    entry(&mut out, b"TRAILER!!!", 0);
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
    out
}

fn overlay(bytes: &[u8]) -> Overlay<'_> {
    Overlay::new(InitramfsRoot::new(Archive::parse(bytes).unwrap(), ROOT))
}

fn absolute(name: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(name.len() + 1);
    path.push(b'/');
    path.extend_from_slice(name);
    path
}

#[test]
fn retained_pure_upper_directory_scans_after_ancestors_exceed_path_max() {
    let bytes = archive_bytes();
    let mut overlay = overlay(&bytes);

    overlay.mkdir_at(b"/held", 0o755, 0, 0, NOW).unwrap();
    overlay
        .create_regular_at(b"/held/upper", 0o600, 0, 0, NOW)
        .unwrap();
    let held = overlay.open_directory_at(b"/held").unwrap();

    // Grow the held directory's ancestry without ever passing a long pathname to the mutation API.
    // Each step creates one short top-level wrapper, then moves the previous top-level subtree below
    // it. The retained directory handle therefore ends up beyond PATH_MAX while every rename request
    // itself stays bounded to two legal NAME_MAX-safe components.
    let mut current_top = b"held".to_vec();
    let mut relative_len = current_top.len();
    for index in 0..DEPTH {
        let byte = b'a' + u8::try_from(index).unwrap();
        let component = vec![byte; COMPONENT_LEN];
        let wrapper = absolute(&component);
        overlay.mkdir_at(&wrapper, 0o755, 0, 0, NOW).unwrap();

        let source = absolute(&current_top);
        let mut destination = Vec::with_capacity(2 + component.len() + current_top.len());
        destination.push(b'/');
        destination.extend_from_slice(&component);
        destination.push(b'/');
        destination.extend_from_slice(&current_top);
        overlay.rename_at(&source, &destination, false).unwrap();

        relative_len += 1 + component.len();
        current_top = component;
    }

    let absolute_len = 1 + relative_len;
    assert!(absolute_len > LINUX_PATH_MAX - 1);

    // The old path-backed implementation failed before even emitting `.` because it first tried to
    // reconstruct the now-too-long absolute pathname. The retained pure-upper identity must instead
    // enumerate `.` / live `..` / upper children without any pathname materialization or CPIO scan.
    let dot = overlay.directory_entry_from(held, 0).unwrap().unwrap();
    assert_eq!(dot.entry().name(), b".");

    let parent = overlay
        .directory_entry_from(held, dot.next_cursor())
        .unwrap()
        .unwrap();
    assert_eq!(parent.entry().name(), b"..");

    let mut cursor = parent.next_cursor();
    let mut names = Vec::new();
    while let Some(scan) = overlay.directory_entry_from(held, cursor).unwrap() {
        names.push(scan.entry().name().to_vec());
        cursor = scan.next_cursor();
    }
    assert_eq!(names, vec![b"upper".to_vec()]);
}
