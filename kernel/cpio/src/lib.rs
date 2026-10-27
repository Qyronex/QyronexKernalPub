// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1024;
/// Maximum stored CPIO entry path bytes, excluding the terminating NUL.
/// This is an archive-parser bound, not the Linux userspace pathname limit.
pub const MAX_PATH_BYTES: usize = 1024;

const HEADER_LEN: usize = 110;
const MAGIC_NEWC: &[u8; 6] = b"070701";
const MAGIC_CRC: &[u8; 6] = b"070702";
const TRAILER: &[u8] = b"TRAILER!!!";
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyArchive,
    ArchiveTooLarge,
    TooManyEntries,
    TruncatedHeader,
    InvalidMagic,
    InvalidHex,
    InvalidNameSize,
    PathTooLong,
    NameOutOfBounds,
    NameNotNulTerminated,
    InvalidPath,
    OffsetOverflow,
    DataOutOfBounds,
    PaddingOutOfBounds,
    NonZeroPadding,
    ChecksumMismatch,
    DuplicatePath,
    TrailerHasData,
    MissingTrailer,
    TrailingGarbage,
    NotRegularFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Other(u32),
}

/// Stable bounded ordinal of one validated non-trailer archive entry.
///
/// `MAX_ENTRIES` is 1024, so a `u16` identity is sufficient and keeps persistent VFS metadata
/// compact. A synthesized out-of-range identity is harmless because `entry_by_id` always validates
/// it against the currently scoped archive before returning an entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryId(u16);

impl EntryId {
    pub const fn from_index(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// One fully validated non-trailer newc/CRC-newc entry.
///
/// The metadata fields below are the exact Linux filesystem values carried by the validated newc
/// header. They are data only: neither uid/gid nor a source inode/device tuple grants ambient Kernal
/// capability authority. `EntryId` remains the compact archive-ordinal lookup token and is deliberately
/// distinct from the source `(devmajor, devminor, ino)` identity. newc has no independent atime/ctime
/// fields, so this type deliberately does not synthesize them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    path: &'a [u8],
    data: &'a [u8],
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    dev_major: u32,
    dev_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
}

impl<'a> Entry<'a> {
    /// Exact validated archive pathname bytes. Linux-visible names are never UTF-8 decoded or
    /// lossily transcoded by the CPIO owner.
    pub const fn path(self) -> &'a [u8] {
        self.path
    }
    pub const fn data(self) -> &'a [u8] {
        self.data
    }
    /// Exact newc `c_ino`. This is source filesystem metadata, not the bounded archive ordinal.
    pub const fn ino(self) -> u32 {
        self.ino
    }
    pub const fn mode(self) -> u32 {
        self.mode
    }
    /// Exact newc `c_uid` metadata. This is not Kernal capability authority.
    pub const fn uid(self) -> u32 {
        self.uid
    }
    /// Exact newc `c_gid` metadata. This is not Kernal capability authority.
    pub const fn gid(self) -> u32 {
        self.gid
    }
    /// Exact newc `c_nlink` metadata.
    pub const fn nlink(self) -> u32 {
        self.nlink
    }
    /// Exact newc `c_mtime` value in whole Unix seconds.
    pub const fn mtime(self) -> u32 {
        self.mtime
    }
    /// Exact newc `c_devmajor` source-device metadata.
    pub const fn dev_major(self) -> u32 {
        self.dev_major
    }
    /// Exact newc `c_devminor` source-device metadata.
    pub const fn dev_minor(self) -> u32 {
        self.dev_minor
    }
    /// Exact newc `c_rdevmajor` special-device metadata.
    pub const fn rdev_major(self) -> u32 {
        self.rdev_major
    }
    /// Exact newc `c_rdevminor` special-device metadata.
    pub const fn rdev_minor(self) -> u32 {
        self.rdev_minor
    }
    pub const fn file_type(self) -> FileType {
        match self.mode & S_IFMT {
            S_IFREG => FileType::Regular,
            S_IFDIR => FileType::Directory,
            S_IFLNK => FileType::Symlink,
            other => FileType::Other(other),
        }
    }
    pub const fn is_regular_file(self) -> bool {
        matches!(self.file_type(), FileType::Regular)
    }
}

/// Allocation-free, immutable and fail-closed `newc`/CRC-newc archive view for Step 28.
/// The complete archive is validated before entries are exposed. This layer deliberately does not
/// follow symlinks, extract files, normalize paths or implement general VFS semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Archive<'a> {
    bytes: &'a [u8],
    entry_count: usize,
}

impl<'a> Archive<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyArchive);
        }
        if bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(Error::ArchiveTooLarge);
        }
        let mut offset = 0usize;
        let mut count = 0usize;
        loop {
            if offset == bytes.len() {
                return Err(Error::MissingTrailer);
            }
            let record = parse_record(bytes, offset)?;
            if record.trailer {
                if bytes[record.next..].iter().any(|byte| *byte != 0) {
                    return Err(Error::TrailingGarbage);
                }
                return Ok(Self {
                    bytes,
                    entry_count: count,
                });
            }
            count = count.checked_add(1).ok_or(Error::TooManyEntries)?;
            if count > MAX_ENTRIES {
                return Err(Error::TooManyEntries);
            }
            ensure_unique_path(bytes, offset, record.entry.path)?;
            offset = record.next;
        }
    }

    pub const fn entry_count(self) -> usize {
        self.entry_count
    }
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub fn get<P: AsRef<[u8]>>(self, path: P) -> Result<Option<Entry<'a>>, Error> {
        Ok(self.get_with_id(path)?.map(|(_, entry)| entry))
    }

    /// Resolves a structurally valid exact byte path and returns the stable archive-entry ordinal.
    /// `&str` remains accepted as an input convenience, but lookup authority is bytes. A valid
    /// lookup longer than the parser's stored-name bound is a clean miss, not a parser failure: no
    /// validated archive entry can have that name, while higher VFS layers may allow longer paths.
    pub fn get_with_id<P: AsRef<[u8]>>(
        self,
        path: P,
    ) -> Result<Option<(EntryId, Entry<'a>)>, Error> {
        let path = path.as_ref();
        validate_lookup_path(path)?;
        if path.len() > MAX_PATH_BYTES {
            return Ok(None);
        }
        let mut offset = 0usize;
        let mut index = 0u16;
        loop {
            let record = parse_record(self.bytes, offset)?;
            if record.trailer {
                return Ok(None);
            }
            if record.entry.path == path {
                return Ok(Some((EntryId(index), record.entry)));
            }
            index = index.checked_add(1).ok_or(Error::TooManyEntries)?;
            offset = record.next;
        }
    }

    /// Re-resolves one previously issued stable entry identity inside this exact validated archive.
    pub fn entry_by_id(self, id: EntryId) -> Result<Option<Entry<'a>>, Error> {
        let target = id.index();
        if target >= self.entry_count {
            return Ok(None);
        }

        let mut offset = 0usize;
        let mut index = 0usize;
        loop {
            let record = parse_record(self.bytes, offset)?;
            if record.trailer {
                return Ok(None);
            }
            if index == target {
                return Ok(Some(record.entry));
            }
            index = index.checked_add(1).ok_or(Error::TooManyEntries)?;
            offset = record.next;
        }
    }

    pub fn regular_file<P: AsRef<[u8]>>(self, path: P) -> Result<Option<&'a [u8]>, Error> {
        match self.get(path)? {
            Some(entry) if entry.is_regular_file() => Ok(Some(entry.data)),
            Some(_) => Err(Error::NotRegularFile),
            None => Ok(None),
        }
    }
}

#[derive(Clone, Copy)]
struct Record<'a> {
    entry: Entry<'a>,
    next: usize,
    trailer: bool,
}

fn parse_record(bytes: &[u8], offset: usize) -> Result<Record<'_>, Error> {
    let header_end = offset
        .checked_add(HEADER_LEN)
        .ok_or(Error::OffsetOverflow)?;
    if header_end > bytes.len() {
        return Err(Error::TruncatedHeader);
    }
    let header = &bytes[offset..header_end];
    let crc = if &header[..6] == MAGIC_NEWC {
        false
    } else if &header[..6] == MAGIC_CRC {
        true
    } else {
        return Err(Error::InvalidMagic);
    };
    let ino = field(header, 0)?;
    let mode = field(header, 1)?;
    let uid = field(header, 2)?;
    let gid = field(header, 3)?;
    let nlink = field(header, 4)?;
    let mtime = field(header, 5)?;
    let file_size = usize::try_from(field(header, 6)?).map_err(|_| Error::DataOutOfBounds)?;
    let dev_major = field(header, 7)?;
    let dev_minor = field(header, 8)?;
    let rdev_major = field(header, 9)?;
    let rdev_minor = field(header, 10)?;
    let name_size = usize::try_from(field(header, 11)?).map_err(|_| Error::InvalidNameSize)?;
    let check = field(header, 12)?;
    if name_size == 0 {
        return Err(Error::InvalidNameSize);
    }
    if name_size > MAX_PATH_BYTES + 1 {
        return Err(Error::PathTooLong);
    }

    let name_end = header_end
        .checked_add(name_size)
        .ok_or(Error::OffsetOverflow)?;
    if name_end > bytes.len() {
        return Err(Error::NameOutOfBounds);
    }
    let nul_name = &bytes[header_end..name_end];
    if nul_name.last().copied() != Some(0) {
        return Err(Error::NameNotNulTerminated);
    }
    let path = &nul_name[..nul_name.len() - 1];
    if path.contains(&0) {
        return Err(Error::InvalidPath);
    }
    let trailer = path == TRAILER;
    if !trailer {
        validate_archive_path(path)?;
    }

    let data_start = align4(name_end)?;
    zero_padding(bytes, name_end, data_start)?;
    let data_end = data_start
        .checked_add(file_size)
        .ok_or(Error::OffsetOverflow)?;
    if data_end > bytes.len() {
        return Err(Error::DataOutOfBounds);
    }
    let data = &bytes[data_start..data_end];
    let next = align4(data_end)?;
    zero_padding(bytes, data_end, next)?;

    if crc {
        let actual = data
            .iter()
            .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
        if actual != check {
            return Err(Error::ChecksumMismatch);
        }
    } else if check != 0 {
        return Err(Error::ChecksumMismatch);
    }
    if trailer && !data.is_empty() {
        return Err(Error::TrailerHasData);
    }
    Ok(Record {
        entry: Entry {
            path,
            data,
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            dev_major,
            dev_minor,
            rdev_major,
            rdev_minor,
        },
        next,
        trailer,
    })
}

fn field(header: &[u8], index: usize) -> Result<u32, Error> {
    let start = 6usize
        .checked_add(index.checked_mul(8).ok_or(Error::OffsetOverflow)?)
        .ok_or(Error::OffsetOverflow)?;
    let end = start.checked_add(8).ok_or(Error::OffsetOverflow)?;
    parse_hex(&header[start..end])
}

fn parse_hex(bytes: &[u8]) -> Result<u32, Error> {
    let mut value = 0u32;
    for byte in bytes {
        let digit = match *byte {
            b'0'..=b'9' => u32::from(*byte - b'0'),
            b'a'..=b'f' => u32::from(*byte - b'a') + 10,
            b'A'..=b'F' => u32::from(*byte - b'A') + 10,
            _ => return Err(Error::InvalidHex),
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(digit))
            .ok_or(Error::InvalidHex)?;
    }
    Ok(value)
}

fn align4(value: usize) -> Result<usize, Error> {
    value
        .checked_add(3)
        .map(|v| v & !3)
        .ok_or(Error::OffsetOverflow)
}

fn zero_padding(bytes: &[u8], start: usize, end: usize) -> Result<(), Error> {
    if start > end || end > bytes.len() {
        return Err(Error::PaddingOutOfBounds);
    }
    if bytes[start..end].iter().any(|byte| *byte != 0) {
        return Err(Error::NonZeroPadding);
    }
    Ok(())
}

fn validate_archive_path(path: &[u8]) -> Result<(), Error> {
    if path.len() > MAX_PATH_BYTES {
        return Err(Error::InvalidPath);
    }
    validate_lookup_path(path)
}

fn validate_lookup_path(path: &[u8]) -> Result<(), Error> {
    if path.is_empty()
        || path.contains(&0)
        || path.first() == Some(&b'/')
        || path.last() == Some(&b'/')
    {
        return Err(Error::InvalidPath);
    }
    if path == b"." {
        return Ok(());
    }
    if path
        .split(|byte| *byte == b'/')
        .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn ensure_unique_path(bytes: &[u8], current: usize, candidate: &[u8]) -> Result<(), Error> {
    let mut offset = 0usize;
    while offset < current {
        let record = parse_record(bytes, offset)?;
        if record.trailer {
            return Err(Error::TrailingGarbage);
        }
        if record.entry.path == candidate {
            return Err(Error::DuplicatePath);
        }
        offset = record.next;
    }
    if offset != current {
        return Err(Error::OffsetOverflow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct TestMetadata {
        ino: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        mtime: u32,
        dev_major: u32,
        dev_minor: u32,
        rdev_major: u32,
        rdev_minor: u32,
    }

    const DEFAULT_METADATA: TestMetadata = TestMetadata {
        ino: 1,
        uid: 0,
        gid: 0,
        nlink: 1,
        mtime: 0,
        dev_major: 0,
        dev_minor: 0,
        rdev_major: 0,
        rdev_minor: 0,
    };

    fn hex(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }

    fn entry(out: &mut Vec<u8>, magic: &[u8; 6], path: &[u8], mode: u32, data: &[u8]) {
        entry_with_metadata(out, magic, path, mode, DEFAULT_METADATA, data);
    }

    fn entry_with_metadata(
        out: &mut Vec<u8>,
        magic: &[u8; 6],
        path: &[u8],
        mode: u32,
        metadata: TestMetadata,
        data: &[u8],
    ) {
        let start = out.len();
        out.extend_from_slice(magic);
        for value in [
            metadata.ino,
            mode,
            metadata.uid,
            metadata.gid,
            metadata.nlink,
            metadata.mtime,
            u32::try_from(data.len()).unwrap(),
            metadata.dev_major,
            metadata.dev_minor,
            metadata.rdev_major,
            metadata.rdev_minor,
            u32::try_from(path.len() + 1).unwrap(),
        ] {
            hex(out, value);
        }
        let checksum = if magic == MAGIC_CRC {
            data.iter()
                .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
        } else {
            0
        };
        hex(out, checksum);
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

    fn finish(out: &mut Vec<u8>) {
        entry(out, MAGIC_NEWC, TRAILER, 0, &[]);
        while !out.len().is_multiple_of(512) {
            out.push(0);
        }
    }

    fn archive() -> Vec<u8> {
        let mut out = Vec::new();
        entry(&mut out, MAGIC_NEWC, b".", S_IFDIR | 0o755, &[]);
        entry(&mut out, MAGIC_NEWC, b"bin", S_IFDIR | 0o755, &[]);
        entry(
            &mut out,
            MAGIC_NEWC,
            b"bin/busybox",
            S_IFREG | 0o755,
            b"\x7fELF-arm64",
        );
        finish(&mut out);
        out
    }

    #[test]
    fn validates_and_returns_exact_file() {
        let bytes = archive();
        let parsed = Archive::parse(&bytes).unwrap();
        assert_eq!(parsed.entry_count(), 3);
        assert_eq!(
            parsed.regular_file("bin/busybox").unwrap(),
            Some(&b"\x7fELF-arm64"[..])
        );
        assert_eq!(
            parsed.get("bin").unwrap().unwrap().file_type(),
            FileType::Directory
        );

        let (busybox_id, busybox) = parsed.get_with_id(b"bin/busybox").unwrap().unwrap();
        assert_eq!(busybox_id.index(), 2);
        assert_eq!(busybox.path(), b"bin/busybox");
        assert_eq!(parsed.entry_by_id(busybox_id).unwrap(), Some(busybox));
        assert_eq!(
            parsed.entry_by_id(EntryId::from_index(u16::MAX)).unwrap(),
            None
        );
    }

    #[test]
    fn preserves_complete_validated_newc_metadata_by_path_and_entry_id() {
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_NEWC, b".", S_IFDIR | 0o755, &[]);
        entry_with_metadata(
            &mut bytes,
            MAGIC_NEWC,
            b"payload",
            S_IFREG | 0o640,
            TestMetadata {
                ino: 0x1234_5678,
                uid: 1000,
                gid: 1001,
                nlink: 3,
                mtime: 0x2345_6789,
                dev_major: 8,
                dev_minor: 17,
                rdev_major: 9,
                rdev_minor: 33,
            },
            b"data",
        );
        finish(&mut bytes);

        let archive = Archive::parse(&bytes).unwrap();
        let (id, entry) = archive.get_with_id(b"payload").unwrap().unwrap();
        assert_eq!(entry.ino(), 0x1234_5678);
        assert_eq!(entry.mode(), S_IFREG | 0o640);
        assert_eq!(entry.uid(), 1000);
        assert_eq!(entry.gid(), 1001);
        assert_eq!(entry.nlink(), 3);
        assert_eq!(entry.mtime(), 0x2345_6789);
        assert_eq!(entry.dev_major(), 8);
        assert_eq!(entry.dev_minor(), 17);
        assert_eq!(entry.rdev_major(), 9);
        assert_eq!(entry.rdev_minor(), 33);
        assert_eq!(archive.entry_by_id(id).unwrap(), Some(entry));
    }

    #[test]
    fn source_inode_identity_keeps_device_tuple_distinct_from_archive_ordinal() {
        let mut bytes = Vec::new();
        let first = TestMetadata {
            ino: 77,
            dev_major: 1,
            dev_minor: 2,
            ..DEFAULT_METADATA
        };
        let second = TestMetadata {
            ino: 77,
            dev_major: 3,
            dev_minor: 4,
            ..DEFAULT_METADATA
        };
        entry_with_metadata(
            &mut bytes,
            MAGIC_NEWC,
            b"first",
            S_IFREG | 0o644,
            first,
            b"a",
        );
        entry_with_metadata(
            &mut bytes,
            MAGIC_NEWC,
            b"second",
            S_IFREG | 0o644,
            second,
            b"b",
        );
        finish(&mut bytes);

        let archive = Archive::parse(&bytes).unwrap();
        let (first_id, first_entry) = archive.get_with_id(b"first").unwrap().unwrap();
        let (second_id, second_entry) = archive.get_with_id(b"second").unwrap().unwrap();
        assert_ne!(first_id, second_id);
        assert_eq!(first_entry.ino(), second_entry.ino());
        assert_ne!(
            (first_entry.dev_major(), first_entry.dev_minor()),
            (second_entry.dev_major(), second_entry.dev_minor())
        );
    }

    #[test]
    fn metadata_fields_use_the_existing_fail_closed_hex_parser() {
        let mut bytes = Vec::new();
        entry_with_metadata(
            &mut bytes,
            MAGIC_NEWC,
            b"payload",
            S_IFREG | 0o600,
            TestMetadata {
                ino: 41,
                uid: 42,
                gid: 43,
                nlink: 1,
                mtime: 44,
                dev_major: 45,
                dev_minor: 46,
                rdev_major: 47,
                rdev_minor: 48,
            },
            b"x",
        );
        finish(&mut bytes);

        // c_uid is field index 2 and therefore starts at byte 6 + 2*8.
        bytes[22] = b'g';
        assert_eq!(Archive::parse(&bytes), Err(Error::InvalidHex));

        let mut bytes = Vec::new();
        entry_with_metadata(
            &mut bytes,
            MAGIC_NEWC,
            b"payload",
            S_IFREG | 0o600,
            TestMetadata {
                ino: 41,
                uid: 42,
                gid: 43,
                nlink: 1,
                mtime: 44,
                dev_major: 45,
                dev_minor: 46,
                rdev_major: 47,
                rdev_minor: 48,
            },
            b"x",
        );
        finish(&mut bytes);
        // c_devmajor is field index 7 and is decoded through the same fail-closed field parser.
        bytes[62] = b'g';
        assert_eq!(Archive::parse(&bytes), Err(Error::InvalidHex));
    }

    #[test]
    fn non_utf8_paths_are_preserved_and_compared_exactly() {
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_NEWC, b".", S_IFDIR | 0o755, &[]);
        entry(&mut bytes, MAGIC_NEWC, b"dir", S_IFDIR | 0o755, &[]);
        entry(
            &mut bytes,
            MAGIC_NEWC,
            b"dir/\xffname",
            S_IFREG | 0o644,
            b"first",
        );
        entry(
            &mut bytes,
            MAGIC_NEWC,
            b"dir/\xfename",
            S_IFREG | 0o644,
            b"second",
        );
        finish(&mut bytes);

        let parsed = Archive::parse(&bytes).unwrap();
        let first = parsed.get(b"dir/\xffname").unwrap().unwrap();
        let second = parsed.get(b"dir/\xfename").unwrap().unwrap();
        assert_eq!(first.path(), b"dir/\xffname");
        assert_eq!(second.path(), b"dir/\xfename");
        assert_ne!(first.path(), second.path());
        assert_eq!(first.data(), b"first");
        assert_eq!(second.data(), b"second");
    }

    #[test]
    fn duplicate_detection_uses_exact_arbitrary_bytes() {
        let mut bytes = Vec::new();
        entry(
            &mut bytes,
            MAGIC_NEWC,
            b"dir/\xffname",
            S_IFREG | 0o644,
            b"a",
        );
        entry(
            &mut bytes,
            MAGIC_NEWC,
            b"dir/\xffname",
            S_IFREG | 0o644,
            b"b",
        );
        finish(&mut bytes);
        assert_eq!(Archive::parse(&bytes), Err(Error::DuplicatePath));
    }

    #[test]
    fn embedded_nul_is_still_rejected() {
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_NEWC, b"dir/\0name", S_IFREG | 0o644, b"x");
        finish(&mut bytes);
        assert_eq!(Archive::parse(&bytes), Err(Error::InvalidPath));

        let archive_bytes = archive();
        let parsed = Archive::parse(&archive_bytes).unwrap();
        assert_eq!(parsed.get(b"bin/\0busybox"), Err(Error::InvalidPath));
    }

    #[test]
    fn archive_path_bound_accepts_exact_limit_and_rejects_one_more() {
        let exact = vec![b'a'; MAX_PATH_BYTES];
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_NEWC, &exact, S_IFREG | 0o644, b"x");
        finish(&mut bytes);
        assert!(Archive::parse(&bytes).is_ok());

        let too_long = vec![b'a'; MAX_PATH_BYTES + 1];
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_NEWC, &too_long, S_IFREG | 0o644, b"x");
        finish(&mut bytes);
        assert_eq!(Archive::parse(&bytes), Err(Error::PathTooLong));
    }

    #[test]
    fn lookup_above_archive_name_bound_is_a_clean_miss() {
        let bytes = archive();
        let parsed = Archive::parse(&bytes).unwrap();
        let longer = vec![b'a'; MAX_PATH_BYTES + 1];
        assert_eq!(parsed.get(longer.as_slice()).unwrap(), None);
    }

    #[test]
    fn crc_must_match() {
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_CRC, b"payload", S_IFREG | 0o644, b"abc");
        finish(&mut bytes);
        assert!(Archive::parse(&bytes).is_ok());
        let data = align4(HEADER_LEN + b"payload".len() + 1).unwrap();
        bytes[data] ^= 1;
        assert_eq!(Archive::parse(&bytes), Err(Error::ChecksumMismatch));
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        assert_eq!(Archive::parse(b"070701"), Err(Error::TruncatedHeader));
        let mut bytes = archive();
        bytes[..6].copy_from_slice(b"070707");
        assert_eq!(Archive::parse(&bytes), Err(Error::InvalidMagic));
        let mut bytes = archive();
        bytes[HEADER_LEN + 1] = b'x';
        assert_eq!(Archive::parse(&bytes), Err(Error::NameNotNulTerminated));
    }

    #[test]
    fn unsafe_or_ambiguous_paths_fail() {
        for path in [
            &b"/bin/busybox"[..],
            &b"../x"[..],
            &b"bin/../x"[..],
            &b"bin//x"[..],
            &b"bin/./x"[..],
            &b"bin/"[..],
        ] {
            let mut bytes = Vec::new();
            entry(&mut bytes, MAGIC_NEWC, path, S_IFREG | 0o755, b"x");
            finish(&mut bytes);
            assert_eq!(Archive::parse(&bytes), Err(Error::InvalidPath), "{path:?}");
        }
    }

    #[test]
    fn duplicate_and_trailing_data_fail() {
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_NEWC, b"bin", S_IFDIR | 0o755, &[]);
        entry(&mut bytes, MAGIC_NEWC, b"bin", S_IFDIR | 0o755, &[]);
        finish(&mut bytes);
        assert_eq!(Archive::parse(&bytes), Err(Error::DuplicatePath));
        let mut bytes = archive();
        let last = bytes.len() - 1;
        bytes[last] = 1;
        assert_eq!(Archive::parse(&bytes), Err(Error::TrailingGarbage));
    }

    #[test]
    fn missing_trailer_and_wrong_type_fail() {
        let mut bytes = Vec::new();
        entry(&mut bytes, MAGIC_NEWC, b"bin", S_IFDIR | 0o755, &[]);
        assert_eq!(Archive::parse(&bytes), Err(Error::MissingTrailer));
        let bytes = archive();
        assert_eq!(
            Archive::parse(&bytes).unwrap().regular_file("bin"),
            Err(Error::NotRegularFile)
        );
    }
}
