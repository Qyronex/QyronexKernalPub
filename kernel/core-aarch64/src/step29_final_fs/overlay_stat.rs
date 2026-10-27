// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use kernal_linux_vfs::{OverlayMetadata, OverlayNodeHandle};

pub(super) const ARM64_STAT_BYTES: usize = 128;
pub(super) const ARM64_STATX_BYTES: usize = 256;
const BLOCK_SIZE: u32 = 4096;
const BLOCK_UNIT: u64 = 512;
const LIVE_MOUNT_MAJOR: u32 = 0;
const LIVE_MOUNT_MINOR: u32 = 0;
const LOWER_INODE_TAG: u64 = 1_u64 << 62;
const MUTABLE_INODE_TAG: u64 = 3_u64 << 62;
const MUTABLE_SLOT_BITS: u32 = 16;
const MUTABLE_SLOT_MASK: u64 = (1_u64 << MUTABLE_SLOT_BITS) - 1;
const MUTABLE_GENERATION_MAX: u64 = (1_u64 << (62 - MUTABLE_SLOT_BITS)) - 1;
const STATX_BASIC_STATS: u32 = 0x0000_07ff;
const SOURCE_IDENTITY_SLOTS: usize = kernal_cpio::MAX_ENTRIES;

struct SourceIdentitySlot {
    occupied: AtomicBool,
    root_generation: AtomicU64,
    dev_major: AtomicU32,
    dev_minor: AtomicU32,
    ino: AtomicU32,
}

impl SourceIdentitySlot {
    const fn new() -> Self {
        Self {
            occupied: AtomicBool::new(false),
            root_generation: AtomicU64::new(0),
            dev_major: AtomicU32::new(0),
            dev_minor: AtomicU32::new(0),
            ino: AtomicU32::new(0),
        }
    }
}

static SOURCE_IDENTITY_LOCK: AtomicBool = AtomicBool::new(false);
static SOURCE_IDENTITIES: [SourceIdentitySlot; SOURCE_IDENTITY_SLOTS] =
    [const { SourceIdentitySlot::new() }; SOURCE_IDENTITY_SLOTS];

struct SourceIdentityGuard;

impl SourceIdentityGuard {
    fn lock() -> Self {
        while SOURCE_IDENTITY_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for SourceIdentityGuard {
    fn drop(&mut self) {
        SOURCE_IDENTITY_LOCK.store(false, Ordering::Release);
    }
}

/// Encodes one live VFS-owned Overlay metadata snapshot into Linux AArch64's asm-generic stat
/// layout. Immutable/root inode identity comes from the complete CPIO source identity retained by
/// VFS; Upper-only objects keep the generation-safe mutable identity. `st_dev` identifies this live
/// Overlay mount and deliberately does not reuse the archive's source-device tuple.
pub(super) fn encode(metadata: OverlayMetadata) -> Result<[u8; ARM64_STAT_BYTES], ()> {
    let dev = encode_dev_t(LIVE_MOUNT_MAJOR, LIVE_MOUNT_MINOR);
    let ino = inode(metadata)?;
    let rdev = metadata
        .source_rdev()
        .map(|(major, minor)| encode_dev_t(major, minor))
        .unwrap_or(0);
    let size = i64::try_from(metadata.size()).map_err(|_| ())?;
    let blocks_u64 = metadata.size().checked_add(BLOCK_UNIT - 1).ok_or(())? / BLOCK_UNIT;
    let blocks = i64::try_from(blocks_u64).map_err(|_| ())?;
    let atime = metadata.atime();
    let mtime = metadata.mtime();
    let ctime = metadata.ctime();

    let mut out = [0u8; ARM64_STAT_BYTES];
    put_u64(&mut out, 0, dev);
    put_u64(&mut out, 8, ino);
    put_u32(&mut out, 16, metadata.mode());
    put_u32(&mut out, 20, metadata.links());
    put_u32(&mut out, 24, metadata.uid());
    put_u32(&mut out, 28, metadata.gid());
    put_u64(&mut out, 32, rdev);
    put_i64(&mut out, 48, size);
    put_i32(&mut out, 56, BLOCK_SIZE as i32);
    put_i64(&mut out, 64, blocks);
    put_i64(&mut out, 72, atime.seconds);
    put_u64(&mut out, 80, u64::from(atime.nanoseconds));
    put_i64(&mut out, 88, mtime.seconds);
    put_u64(&mut out, 96, u64::from(mtime.nanoseconds));
    put_i64(&mut out, 104, ctime.seconds);
    put_u64(&mut out, 112, u64::from(ctime.nanoseconds));
    Ok(out)
}

/// Encodes the Step-29 live Overlay metadata subset into Linux `struct statx`.
pub(super) fn encode_statx(metadata: OverlayMetadata) -> Result<[u8; ARM64_STATX_BYTES], ()> {
    let ino = inode(metadata)?;
    let blocks = metadata.size().checked_add(BLOCK_UNIT - 1).ok_or(())? / BLOCK_UNIT;
    let mode = u16::try_from(metadata.mode() & u32::from(u16::MAX)).map_err(|_| ())?;
    let (rdev_major, rdev_minor) = metadata.source_rdev().unwrap_or((0, 0));

    let mut out = [0u8; ARM64_STATX_BYTES];
    put_u32_statx(&mut out, 0, STATX_BASIC_STATS);
    put_u32_statx(&mut out, 4, BLOCK_SIZE);
    put_u64_statx(&mut out, 8, 0);
    put_u32_statx(&mut out, 16, metadata.links());
    put_u32_statx(&mut out, 20, metadata.uid());
    put_u32_statx(&mut out, 24, metadata.gid());
    put_u16_statx(&mut out, 28, mode);
    put_u64_statx(&mut out, 32, ino);
    put_u64_statx(&mut out, 40, metadata.size());
    put_u64_statx(&mut out, 48, blocks);
    put_u64_statx(&mut out, 56, 0);
    put_statx_timestamp(&mut out, 64, metadata.atime());
    put_statx_timestamp(&mut out, 96, metadata.ctime());
    put_statx_timestamp(&mut out, 112, metadata.mtime());
    put_u32_statx(&mut out, 128, rdev_major);
    put_u32_statx(&mut out, 132, rdev_minor);
    put_u32_statx(&mut out, 136, LIVE_MOUNT_MAJOR);
    put_u32_statx(&mut out, 140, LIVE_MOUNT_MINOR);
    Ok(out)
}

/// Stable Linux-visible inode identity for one Overlay metadata snapshot.
///
/// CPIO's identity is the complete `(source-device, source-ino)` tuple, not `c_ino` alone and never
/// the archive EntryId ordinal. The validated archive is bounded to `MAX_ENTRIES`, so this table can
/// assign a collision-free mount-local rank after comparing the complete source tuple. Hard-link
/// aliases reuse the same rank, while equal `c_ino` values on different source devices stay distinct.
pub(super) fn inode(metadata: OverlayMetadata) -> Result<u64, ()> {
    match (metadata.source_ino(), metadata.source_device()) {
        (Some(ino), Some((dev_major, dev_minor))) => lower_inode(
            metadata.object().root_id().generation(),
            dev_major,
            dev_minor,
            ino,
        ),
        (None, None) => mutable_inode(metadata.object()),
        _ => Err(()),
    }
}

fn lower_inode(root_generation: u64, dev_major: u32, dev_minor: u32, ino: u32) -> Result<u64, ()> {
    let _guard = SourceIdentityGuard::lock();
    let mut first_free = None;

    for (index, slot) in SOURCE_IDENTITIES.iter().enumerate() {
        if !slot.occupied.load(Ordering::Relaxed) {
            if first_free.is_none() {
                first_free = Some(index);
            }
            continue;
        }
        if slot.root_generation.load(Ordering::Relaxed) == root_generation
            && slot.dev_major.load(Ordering::Relaxed) == dev_major
            && slot.dev_minor.load(Ordering::Relaxed) == dev_minor
            && slot.ino.load(Ordering::Relaxed) == ino
        {
            return tagged_lower_rank(index);
        }
    }

    let index = first_free.ok_or(())?;
    let slot = &SOURCE_IDENTITIES[index];
    slot.root_generation
        .store(root_generation, Ordering::Relaxed);
    slot.dev_major.store(dev_major, Ordering::Relaxed);
    slot.dev_minor.store(dev_minor, Ordering::Relaxed);
    slot.ino.store(ino, Ordering::Relaxed);
    slot.occupied.store(true, Ordering::Relaxed);
    tagged_lower_rank(index)
}

fn tagged_lower_rank(index: usize) -> Result<u64, ()> {
    let rank = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(())?;
    Ok(LOWER_INODE_TAG | rank)
}

fn mutable_inode(object: OverlayNodeHandle) -> Result<u64, ()> {
    let OverlayNodeHandle::Mutable(node) = object else {
        return Err(());
    };
    let slot = u64::try_from(node.slot())
        .ok()
        .and_then(|slot| slot.checked_add(1))
        .ok_or(())?;
    let generation = node.generation();
    if slot > MUTABLE_SLOT_MASK || generation == 0 || generation > MUTABLE_GENERATION_MAX {
        return Err(());
    }
    Ok(MUTABLE_INODE_TAG | (generation << MUTABLE_SLOT_BITS) | slot)
}

/// Linux's userspace `dev_t` bit layout is encoded explicitly at the AArch64 ABI boundary. Source
/// device tuples remain provenance; only `source_rdev` is converted to the special-device field.
fn encode_dev_t(major: u32, minor: u32) -> u64 {
    u64::from(minor & 0x0000_00ff)
        | (u64::from(major & 0x0000_0fff) << 8)
        | (u64::from(minor & 0xffff_ff00) << 12)
        | (u64::from(major & 0xffff_f000) << 32)
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

fn put_u64_statx(out: &mut [u8; ARM64_STATX_BYTES], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_statx(out: &mut [u8; ARM64_STATX_BYTES], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u16_statx(out: &mut [u8; ARM64_STATX_BYTES], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_statx_timestamp(
    out: &mut [u8; ARM64_STATX_BYTES],
    offset: usize,
    value: kernal_linux_vfs::MutableTimestamp,
) {
    out[offset..offset + 8].copy_from_slice(&value.seconds.to_le_bytes());
    out[offset + 8..offset + 12].copy_from_slice(&value.nanoseconds.to_le_bytes());
}
