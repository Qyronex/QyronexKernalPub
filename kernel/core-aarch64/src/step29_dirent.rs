// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_cpio::EntryId;
use kernal_linux_vfs::{DirectoryScan, NodeKind, OverlayDirectoryScan};

const DIRENT64_FIXED_BYTES: usize = 19;
const DIRENT64_ALIGNMENT: usize = 8;
const MAX_DIRENT64_BYTES: usize =
    (DIRENT64_FIXED_BYTES + kernal_cpio::MAX_PATH_BYTES + 1 + DIRENT64_ALIGNMENT - 1)
        & !(DIRENT64_ALIGNMENT - 1);

const DT_UNKNOWN: u8 = 0;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    NameTooLong,
    OffsetOverflow,
    RecordOverflow,
}

pub(super) struct Dirent64Record {
    bytes: [u8; MAX_DIRENT64_BYTES],
    len: usize,
}

impl Dirent64Record {
    pub(super) fn encode(scan: DirectoryScan<'_>) -> Result<Self, Error> {
        let entry = scan.entry();
        let ino = u64::try_from(entry.entry_id().index())
            .map_err(|_| Error::RecordOverflow)?
            .checked_add(1)
            .ok_or(Error::RecordOverflow)?;
        encode_parts_with_inode(ino, entry.name(), entry.kind(), scan.next_cursor())
    }

    pub(super) fn encode_overlay(scan: OverlayDirectoryScan, inode: u64) -> Result<Self, Error> {
        let entry = scan.entry();
        encode_parts_with_inode(inode, entry.name(), entry.kind(), scan.next_cursor())
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn encode_parts(
    entry_id: EntryId,
    name: &[u8],
    kind: NodeKind,
    next_cursor: usize,
) -> Result<Dirent64Record, Error> {
    let ino = u64::try_from(entry_id.index())
        .map_err(|_| Error::RecordOverflow)?
        .checked_add(1)
        .ok_or(Error::RecordOverflow)?;
    encode_parts_with_inode(ino, name, kind, next_cursor)
}

fn encode_parts_with_inode(
    ino: u64,
    name: &[u8],
    kind: NodeKind,
    next_cursor: usize,
) -> Result<Dirent64Record, Error> {
    if name.is_empty() || name.len() > kernal_cpio::MAX_PATH_BYTES || name.contains(&0) {
        return Err(Error::NameTooLong);
    }
    let unaligned = DIRENT64_FIXED_BYTES
        .checked_add(name.len())
        .and_then(|value| value.checked_add(1))
        .ok_or(Error::RecordOverflow)?;
    let len = unaligned
        .checked_add(DIRENT64_ALIGNMENT - 1)
        .map(|value| value & !(DIRENT64_ALIGNMENT - 1))
        .ok_or(Error::RecordOverflow)?;
    if len > MAX_DIRENT64_BYTES {
        return Err(Error::RecordOverflow);
    }
    let reclen = u16::try_from(len).map_err(|_| Error::RecordOverflow)?;
    let off = i64::try_from(next_cursor).map_err(|_| Error::OffsetOverflow)?;

    let mut bytes = [0u8; MAX_DIRENT64_BYTES];
    bytes[0..8].copy_from_slice(&ino.to_le_bytes());
    bytes[8..16].copy_from_slice(&off.to_le_bytes());
    bytes[16..18].copy_from_slice(&reclen.to_le_bytes());
    bytes[18] = linux_dtype(kind);
    bytes[DIRENT64_FIXED_BYTES..DIRENT64_FIXED_BYTES + name.len()].copy_from_slice(name);
    bytes[DIRENT64_FIXED_BYTES + name.len()] = 0;

    Ok(Dirent64Record { bytes, len })
}

const fn linux_dtype(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Directory => DT_DIR,
        NodeKind::Regular => DT_REG,
        NodeKind::Symlink => DT_LNK,
        NodeKind::Other(_) => DT_UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn i64_at(bytes: &[u8], offset: usize) -> i64 {
        i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    #[test]
    fn encodes_exact_linux_dirent64_layout_and_alignment() {
        let record = encode_parts(EntryId::from_index(4), b"hosts", NodeKind::Regular, 9).unwrap();
        let bytes = record.as_bytes();
        assert_eq!(bytes.len() % DIRENT64_ALIGNMENT, 0);
        assert_eq!(u64_at(bytes, 0), 5);
        assert_eq!(i64_at(bytes, 8), 9);
        assert_eq!(usize::from(u16_at(bytes, 16)), bytes.len());
        assert_eq!(bytes[18], DT_REG);
        assert_eq!(&bytes[19..24], b"hosts");
        assert_eq!(bytes[24], 0);
        assert!(bytes[25..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn dot_records_keep_directory_inode_identity_and_vfs_cookies() {
        let current = EntryId::from_index(4);
        let parent = EntryId::from_index(1);
        let dot = encode_parts(current, b".", NodeKind::Directory, 1).unwrap();
        let dotdot = encode_parts(parent, b"..", NodeKind::Directory, 2).unwrap();

        let dot_bytes = dot.as_bytes();
        assert_eq!(u64_at(dot_bytes, 0), 5);
        assert_eq!(i64_at(dot_bytes, 8), 1);
        assert_eq!(dot_bytes[18], DT_DIR);
        assert_eq!(&dot_bytes[19..21], b".\0");

        let dotdot_bytes = dotdot.as_bytes();
        assert_eq!(u64_at(dotdot_bytes, 0), 2);
        assert_eq!(i64_at(dotdot_bytes, 8), 2);
        assert_eq!(dotdot_bytes[18], DT_DIR);
        assert_eq!(&dotdot_bytes[19..22], b"..\0");
    }

    #[test]
    fn preserves_non_utf8_filename_bytes_without_transcoding() {
        let name = b"\xffname";
        let record = encode_parts(EntryId::from_index(7), name, NodeKind::Regular, 11).unwrap();
        let bytes = record.as_bytes();
        assert_eq!(
            &bytes[DIRENT64_FIXED_BYTES..DIRENT64_FIXED_BYTES + name.len()],
            name
        );
        assert_eq!(bytes[DIRENT64_FIXED_BYTES + name.len()], 0);
        assert_eq!(i64_at(bytes, 8), 11);
    }

    #[test]
    fn maximum_archive_name_still_forms_one_complete_aligned_record() {
        let name = vec![b'x'; kernal_cpio::MAX_PATH_BYTES];
        let record = encode_parts(EntryId::from_index(1), &name, NodeKind::Regular, 3).unwrap();
        let bytes = record.as_bytes();
        assert_eq!(bytes.len(), MAX_DIRENT64_BYTES);
        assert_eq!(bytes.len() % DIRENT64_ALIGNMENT, 0);
        assert_eq!(usize::from(u16_at(bytes, 16)), bytes.len());
        assert_eq!(
            &bytes[DIRENT64_FIXED_BYTES..DIRENT64_FIXED_BYTES + name.len()],
            name.as_slice()
        );
        assert_eq!(bytes[DIRENT64_FIXED_BYTES + name.len()], 0);
    }

    #[test]
    fn maps_directory_symlink_and_unknown_types_without_layout_changes() {
        for (kind, expected) in [
            (NodeKind::Directory, DT_DIR),
            (NodeKind::Symlink, DT_LNK),
            (NodeKind::Other(0x1234), DT_UNKNOWN),
        ] {
            let record = encode_parts(EntryId::from_index(0), b"x", kind, 1).unwrap();
            assert_eq!(record.as_bytes()[18], expected);
            assert_eq!(record.as_bytes().len() % DIRENT64_ALIGNMENT, 0);
        }
    }

    #[test]
    fn rejects_invalid_names_before_usercopy() {
        assert_eq!(
            encode_parts(EntryId::from_index(0), b"", NodeKind::Regular, 1)
                .err()
                .unwrap(),
            Error::NameTooLong
        );
        assert_eq!(
            encode_parts(EntryId::from_index(0), b"a\0b", NodeKind::Regular, 1)
                .err()
                .unwrap(),
            Error::NameTooLong
        );
        let oversized = vec![b'x'; kernal_cpio::MAX_PATH_BYTES + 1];
        assert_eq!(
            encode_parts(EntryId::from_index(0), &oversized, NodeKind::Regular, 1)
                .err()
                .unwrap(),
            Error::NameTooLong
        );
    }
}
