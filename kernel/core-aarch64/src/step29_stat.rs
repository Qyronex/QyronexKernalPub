// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_fd::{Metadata, OpenFileId};
use kernal_linux_pipe::PipeId;
use kernal_linux_vfs::{EntryId, ReadOnlyFile, RootId};

/// Linux arm64 uses the asm-generic 64-bit `struct stat` layout.
///
/// Keep this explicit byte contract separate from Rust type layout: no `repr(C)` transmute or raw
/// pointer cast is used at the userspace ABI boundary.
pub(super) const ARM64_STAT_BYTES: usize = 128;
const BLOCK_SIZE: u32 = 4096;
const BLOCK_UNIT: u64 = 512;
const FILE_TYPE_MASK: u32 = 0o170000;
const FIFO_FILE_TYPE: u32 = 0o010000;
const CHARACTER_FILE_TYPE: u32 = 0o020000;
const SPECIAL_INODE_INDEX_MASK: u64 = (1_u64 << 62) - 1;
const PIPE_INODE_TAG: u64 = 1_u64 << 62;
const EXTERNAL_INODE_TAG: u64 = 2_u64 << 62;

/// Borrow-free identity/snapshot for immutable initramfs metadata.
///
/// This deliberately grants no read authority. The caller must obtain it only after the existing
/// VFS path/parent validation and keep it tied to the active immutable root generation. It can
/// represent both regular files and directories because the file type remains encoded in `mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InitramfsStatIdentity {
    root_id: RootId,
    entry_id: EntryId,
    mode: u32,
    size: u64,
}

impl InitramfsStatIdentity {
    pub(super) const fn new(root_id: RootId, entry_id: EntryId, mode: u32, size: u64) -> Self {
        Self {
            root_id,
            entry_id,
            mode,
            size,
        }
    }

    pub(super) const fn from_file(file: ReadOnlyFile) -> Self {
        Self::new(file.root_id(), file.entry_id(), file.mode(), file.size())
    }

    pub(super) const fn root_id(self) -> RootId {
        self.root_id
    }

    pub(super) const fn entry_id(self) -> EntryId {
        self.entry_id
    }

    pub(super) const fn mode(self) -> u32 {
        self.mode
    }

    pub(super) const fn size(self) -> u64 {
        self.size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Arm64Stat {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    size: i64,
    blksize: i32,
    blocks: i64,
    atime: i64,
    atime_nsec: u64,
    mtime: i64,
    mtime_nsec: u64,
    ctime: i64,
    ctime_nsec: u64,
}

impl Arm64Stat {
    /// Builds deterministic metadata for the immutable Step-29 initramfs root.
    ///
    /// The deterministic initramfs recipe assigns monotonically increasing CPIO inode numbers
    /// starting at one, uid/gid zero, nlink one and timestamp zero. `InitramfsStatIdentity` retains
    /// only root/entry identity plus mode/size, so this immutable backend reconstructs that metadata
    /// without retaining a borrowed CPIO header. Directory modes are preserved exactly, which is
    /// required by unchanged BusyBox `test -d` through `newfstatat`.
    pub(super) fn immutable_initramfs(node: InitramfsStatIdentity) -> Result<Self, ()> {
        let ino = u64::try_from(node.entry_id().index())
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or(())?;
        Self::from_parts(0, ino, node.mode(), node.size())
    }

    /// Builds metadata for one anonymous pipe object.
    ///
    /// The Pipe owner, not either endpoint OFD, is the object identity: read and write descriptors
    /// for the same pipe therefore report the same synthetic `(st_dev, st_ino)` pair. Pipe generation
    /// changes when a slot is reused, preventing a stale pipe identity from being silently recycled.
    pub(super) fn anonymous_pipe(pipe: PipeId, metadata: Metadata) -> Result<Self, ()> {
        if metadata.mode & FILE_TYPE_MASK != FIFO_FILE_TYPE || pipe.generation() == 0 {
            return Err(());
        }
        let ino = synthetic_inode(PIPE_INODE_TAG, pipe.slot())?;
        Self::from_parts(pipe.generation(), ino, metadata.mode, metadata.size)
    }

    /// Builds metadata for one inherited external character stream.
    ///
    /// External descriptors alias through the canonical OFD owner. Duplicated stdout/stderr
    /// descriptors therefore keep the same identity even if the numeric descriptor changes.
    pub(super) fn anonymous_external(
        open_file: OpenFileId,
        metadata: Metadata,
    ) -> Result<Self, ()> {
        if metadata.mode & FILE_TYPE_MASK != CHARACTER_FILE_TYPE || open_file.generation() == 0 {
            return Err(());
        }
        let ino = synthetic_inode(EXTERNAL_INODE_TAG, open_file.index())?;
        Self::from_parts(open_file.generation(), ino, metadata.mode, metadata.size)
    }

    fn from_parts(dev: u64, ino: u64, mode: u32, size: u64) -> Result<Self, ()> {
        let size_i64 = i64::try_from(size).map_err(|_| ())?;
        let blocks_u64 = size.checked_add(BLOCK_UNIT - 1).ok_or(())? / BLOCK_UNIT;
        let blocks = i64::try_from(blocks_u64).map_err(|_| ())?;
        Ok(Self {
            dev,
            ino,
            mode,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: size_i64,
            blksize: BLOCK_SIZE as i32,
            blocks,
            atime: 0,
            atime_nsec: 0,
            mtime: 0,
            mtime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
        })
    }

    pub(super) fn encode(self) -> [u8; ARM64_STAT_BYTES] {
        let mut out = [0u8; ARM64_STAT_BYTES];
        put_u64(&mut out, 0, self.dev);
        put_u64(&mut out, 8, self.ino);
        put_u32(&mut out, 16, self.mode);
        put_u32(&mut out, 20, self.nlink);
        put_u32(&mut out, 24, self.uid);
        put_u32(&mut out, 28, self.gid);
        put_u64(&mut out, 32, self.rdev);
        put_i64(&mut out, 48, self.size);
        put_i32(&mut out, 56, self.blksize);
        put_i64(&mut out, 64, self.blocks);
        put_i64(&mut out, 72, self.atime);
        put_u64(&mut out, 80, self.atime_nsec);
        put_i64(&mut out, 88, self.mtime);
        put_u64(&mut out, 96, self.mtime_nsec);
        put_i64(&mut out, 104, self.ctime);
        put_u64(&mut out, 112, self.ctime_nsec);
        out
    }
}

fn synthetic_inode(tag: u64, index: usize) -> Result<u64, ()> {
    let index = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(())?;
    if index > SPECIAL_INODE_INDEX_MASK {
        return Err(());
    }
    Ok(tag | index)
}

fn put_u64(out: &mut [u8; ARM64_STAT_BYTES], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i64(out: &mut [u8; ARM64_STAT_BYTES], offset: usize, value: i64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8; ARM64_STAT_BYTES], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(out: &mut [u8; ARM64_STAT_BYTES], offset: usize, value: i32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_fd::FdTable;
    use kernal_linux_pipe::{PIPE_BUF, PipeTable};

    fn stat_dev(bytes: &[u8; ARM64_STAT_BYTES]) -> u64 {
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    }

    fn stat_ino(bytes: &[u8; ARM64_STAT_BYTES]) -> u64 {
        u64::from_le_bytes(bytes[8..16].try_into().unwrap())
    }

    #[test]
    fn encodes_exact_asm_generic_arm64_offsets_without_rust_layout_dependency() {
        let node =
            InitramfsStatIdentity::new(RootId::new(7), EntryId::from_index(4), 0o100644, 513);
        let bytes = Arm64Stat::immutable_initramfs(node).unwrap().encode();
        assert_eq!(node.root_id(), RootId::new(7));
        assert_eq!(bytes.len(), 128);
        assert_eq!(stat_dev(&bytes), 0);
        assert_eq!(stat_ino(&bytes), 5);
        assert_eq!(
            u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            0o100644
        );
        assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[28..32].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(bytes[32..40].try_into().unwrap()), 0);
        assert_eq!(&bytes[40..48], &[0; 8]);
        assert_eq!(i64::from_le_bytes(bytes[48..56].try_into().unwrap()), 513);
        assert_eq!(i32::from_le_bytes(bytes[56..60].try_into().unwrap()), 4096);
        assert_eq!(&bytes[60..64], &[0; 4]);
        assert_eq!(i64::from_le_bytes(bytes[64..72].try_into().unwrap()), 2);
        assert_eq!(&bytes[72..120], &[0; 48]);
        assert_eq!(&bytes[120..128], &[0; 8]);
    }

    #[test]
    fn zero_length_file_uses_zero_blocks() {
        let node = InitramfsStatIdentity::new(RootId::new(1), EntryId::from_index(0), 0o100444, 0);
        let bytes = Arm64Stat::immutable_initramfs(node).unwrap().encode();
        assert_eq!(i64::from_le_bytes(bytes[64..72].try_into().unwrap()), 0);
    }

    #[test]
    fn directory_mode_is_preserved_for_busybox_test_d() {
        let directory =
            InitramfsStatIdentity::new(RootId::new(3), EntryId::from_index(2), 0o040755, 0);
        let bytes = Arm64Stat::immutable_initramfs(directory).unwrap().encode();
        assert_eq!(
            u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            0o040755
        );
        assert_eq!(i64::from_le_bytes(bytes[48..56].try_into().unwrap()), 0);
        assert_eq!(i64::from_le_bytes(bytes[64..72].try_into().unwrap()), 0);
    }

    #[test]
    fn external_stdio_aliases_keep_one_anonymous_stat_identity() {
        let mut fds = FdTable::<8>::new();
        let stdio = fds.seed_standard_descriptors().unwrap();
        let alias = fds.duplicate_lowest(stdio.stdout().fd(), false).unwrap();
        let original = fds.open_file_id(stdio.stdout().fd()).unwrap();
        let duplicate = fds.open_file_id(alias.fd()).unwrap();
        assert_eq!(original, duplicate);
        let metadata = fds.metadata(stdio.stdout().fd()).unwrap();
        let original_stat = Arm64Stat::anonymous_external(original, metadata)
            .unwrap()
            .encode();
        let alias_stat =
            Arm64Stat::anonymous_external(duplicate, fds.metadata(alias.fd()).unwrap())
                .unwrap()
                .encode();
        assert_eq!(stat_dev(&original_stat), stat_dev(&alias_stat));
        assert_eq!(stat_ino(&original_stat), stat_ino(&alias_stat));
        assert_eq!(
            u32::from_le_bytes(original_stat[16..20].try_into().unwrap()),
            0o020600
        );
    }

    #[test]
    fn both_pipe_ends_share_pipe_object_stat_identity() {
        let mut fds = FdTable::<8>::new();
        fds.seed_standard_descriptors().unwrap();
        let mut pipes = PipeTable::<1, PIPE_BUF>::new();
        let pair = pipes.create().unwrap();
        let descriptors = fds
            .install_pipe_pair(pair.reader, pair.writer, false, 0, 1)
            .unwrap();
        let reader = Arm64Stat::anonymous_pipe(
            pair.reader.pipe(),
            fds.metadata(descriptors.reader().fd()).unwrap(),
        )
        .unwrap()
        .encode();
        let writer = Arm64Stat::anonymous_pipe(
            pair.writer.pipe(),
            fds.metadata(descriptors.writer().fd()).unwrap(),
        )
        .unwrap()
        .encode();
        assert_eq!(stat_dev(&reader), stat_dev(&writer));
        assert_eq!(stat_ino(&reader), stat_ino(&writer));
        assert_eq!(
            u32::from_le_bytes(reader[16..20].try_into().unwrap()),
            0o010600
        );
        assert_ne!(stat_ino(&reader), EXTERNAL_INODE_TAG | 1);
    }

    #[test]
    fn special_stat_paths_reject_the_wrong_file_type() {
        let mut fds = FdTable::<4>::new();
        let stdio = fds.seed_standard_descriptors().unwrap();
        let open_file = fds.open_file_id(stdio.stdin().fd()).unwrap();
        let regular = Metadata {
            size: 1,
            mode: 0o100444,
        };
        assert_eq!(Arm64Stat::anonymous_external(open_file, regular), Err(()));
        let mut pipes = PipeTable::<1, PIPE_BUF>::new();
        let pair = pipes.create().unwrap();
        assert_eq!(
            Arm64Stat::anonymous_pipe(pair.reader.pipe(), regular),
            Err(())
        );
    }
}
