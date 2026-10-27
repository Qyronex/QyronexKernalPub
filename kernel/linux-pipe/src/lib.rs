// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Linux atomic pipe-write bound used by the Step-29 nonblocking planning contract.
pub const PIPE_BUF: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TableFull,
    BadEndpoint,
    StaleEndpoint,
    StalePlan,
    WouldBlock,
    BrokenPipe,
    InvalidLength,
    CapacityZero,
    EpochExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum End {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipeId {
    slot: u16,
    generation: u64,
}

impl PipeId {
    pub const fn slot(self) -> usize {
        self.slot as usize
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Non-owning value naming one live endpoint lease.
///
/// Copying this value does not create another lifetime reference. A pipe has exactly one read-end
/// lease and one write-end lease in this owner. Descriptor duplication aliases the owning OFD and
/// therefore must not retain this endpoint again. Closing either end invalidates every copied value
/// naming that same lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pipe: PipeId,
    end: End,
}

impl Endpoint {
    pub const fn pipe(self) -> PipeId {
        self.pipe
    }

    pub const fn end(self) -> End {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pair {
    pub reader: Endpoint,
    pub writer: Endpoint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadState {
    Ready(usize),
    Eof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadPlan {
    endpoint: Endpoint,
    mutation_epoch: u64,
    read_pos: usize,
    len: usize,
    available: usize,
}

impl ReadPlan {
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }

    pub const fn len(self) -> usize {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub const fn available(self) -> usize {
        self.available
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritePlan {
    endpoint: Endpoint,
    mutation_epoch: u64,
    write_pos: usize,
    len: usize,
    occupied: usize,
}

impl WritePlan {
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }

    pub const fn len(self) -> usize {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy)]
struct PipeSlot<const CAP: usize> {
    generation: u64,
    retired: bool,
    live: bool,
    reader_open: bool,
    writer_open: bool,
    mutation_epoch: u64,
    read_pos: usize,
    write_pos: usize,
    len: usize,
    bytes: [u8; CAP],
}

impl<const CAP: usize> PipeSlot<CAP> {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        live: false,
        reader_open: false,
        writer_open: false,
        mutation_epoch: 0,
        read_pos: 0,
        write_pos: 0,
        len: 0,
        bytes: [0; CAP],
    };
}

/// Bounded architecture-neutral Linux pipe owner.
///
/// Each slot owns one fixed-capacity ring buffer. Pipe generation rejects stale whole-object
/// handles. A monotonic mutation epoch additionally binds transfer plans to the exact ring/lifetime
/// state that authorized them, preventing drain/wrap/refill ABA from making an old `(pos,len)` pair
/// appear current again. Reads/writes are two-phase and mutate only during commit.
pub struct PipeTable<const N: usize, const CAP: usize> {
    slots: [PipeSlot<CAP>; N],
}

impl<const N: usize, const CAP: usize> PipeTable<N, CAP> {
    pub const fn new() -> Self {
        Self {
            slots: [PipeSlot::EMPTY; N],
        }
    }

    pub fn create(&mut self) -> Result<Pair, Error> {
        if CAP == 0 {
            return Err(Error::CapacityZero);
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.retired || slot.live {
                continue;
            }
            let Some(generation) = slot.generation.checked_add(1) else {
                slot.retired = true;
                continue;
            };
            let Ok(slot_index) = u16::try_from(index) else {
                slot.retired = true;
                continue;
            };
            slot.generation = generation;
            slot.live = true;
            slot.reader_open = true;
            slot.writer_open = true;
            slot.mutation_epoch = 1;
            slot.read_pos = 0;
            slot.write_pos = 0;
            slot.len = 0;
            let pipe = PipeId {
                slot: slot_index,
                generation,
            };
            return Ok(Pair {
                reader: Endpoint {
                    pipe,
                    end: End::Read,
                },
                writer: Endpoint {
                    pipe,
                    end: End::Write,
                },
            });
        }
        Err(Error::TableFull)
    }

    /// Releases the single lifetime lease represented by this end.
    ///
    /// A copied `Endpoint` value does not own an additional lease, so closing the same logical end
    /// twice returns `BadEndpoint` rather than decrementing an aggregate reference count.
    pub fn close(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        let slot = self.slot_mut(endpoint)?;
        match endpoint.end {
            End::Read if slot.reader_open => {
                Self::advance_epoch(slot)?;
                slot.reader_open = false;
            }
            End::Write if slot.writer_open => {
                Self::advance_epoch(slot)?;
                slot.writer_open = false;
            }
            End::Read | End::Write => return Err(Error::BadEndpoint),
        }
        if !slot.reader_open && !slot.writer_open {
            slot.live = false;
            slot.read_pos = 0;
            slot.write_pos = 0;
            slot.len = 0;
        }
        Ok(())
    }

    pub fn prepare_read(&self, reader: Endpoint, requested: usize) -> Result<ReadState, Error> {
        let slot = self.read_slot(reader)?;
        if requested == 0 {
            return Ok(ReadState::Ready(0));
        }
        if slot.len == 0 {
            return if slot.writer_open {
                Err(Error::WouldBlock)
            } else {
                Ok(ReadState::Eof)
            };
        }
        Ok(ReadState::Ready(core::cmp::min(requested, slot.len)))
    }

    pub fn read_plan(&self, reader: Endpoint, requested: usize) -> Result<ReadPlan, Error> {
        let slot = self.read_slot(reader)?;
        if requested != 0 && slot.len == 0 && slot.writer_open {
            return Err(Error::WouldBlock);
        }
        Ok(ReadPlan {
            endpoint: reader,
            mutation_epoch: slot.mutation_epoch,
            read_pos: slot.read_pos,
            len: core::cmp::min(requested, slot.len),
            available: slot.len,
        })
    }

    /// Copies a prepared chunk into a kernel buffer without consuming pipe bytes.
    pub fn copy_read(&self, plan: ReadPlan, out: &mut [u8]) -> Result<usize, Error> {
        let slot = self.read_slot(plan.endpoint)?;
        self.validate_read_plan(slot, plan)?;
        let count = core::cmp::min(plan.len, out.len());
        for (index, target) in out[..count].iter_mut().enumerate() {
            *target = slot.bytes[(plan.read_pos + index) % CAP];
        }
        Ok(count)
    }

    /// Publishes one prepared read chunk exactly, or aborts without mutation.
    ///
    /// `consumed == 0` is a validated no-op. Any other value must equal the entire prepared chunk;
    /// positive short publication is rejected so a faulting current usercopy chunk remains hidden.
    pub fn commit_read(&mut self, plan: ReadPlan, consumed: usize) -> Result<(), Error> {
        if consumed != 0 && consumed != plan.len {
            return Err(Error::InvalidLength);
        }
        let slot = self.slot_mut(plan.endpoint)?;
        if plan.endpoint.end != End::Read || !slot.reader_open {
            return Err(Error::StalePlan);
        }
        Self::validate_read_plan_inner(slot, plan)?;
        if consumed == 0 {
            return Ok(());
        }
        Self::advance_epoch(slot)?;
        slot.read_pos = (slot.read_pos + consumed) % CAP;
        slot.len -= consumed;
        Ok(())
    }

    /// Blocking-style bounded write planning. Linux preserves PIPE_BUF atomicity here too: a
    /// request up to PIPE_BUF either fits completely or the caller must wait/retry. Larger requests
    /// may expose a currently available positive prefix.
    pub fn prepare_write(&self, writer: Endpoint, requested: usize) -> Result<WritePlan, Error> {
        let slot = self.write_slot(writer)?;
        self.prepare_write_from_slot(writer, slot, requested, requested <= PIPE_BUF)
    }

    /// Nonblocking Linux pipe planning without storing `O_NONBLOCK` in the pipe owner.
    ///
    /// Requests up to and including `PIPE_BUF` are atomic: insufficient free capacity yields
    /// `WouldBlock` rather than a partial plan. Larger requests may return a positive partial plan.
    pub fn prepare_nonblocking_write(
        &self,
        writer: Endpoint,
        requested: usize,
    ) -> Result<WritePlan, Error> {
        let slot = self.write_slot(writer)?;
        self.prepare_write_from_slot(writer, slot, requested, requested <= PIPE_BUF)
    }

    /// Publishes one prepared write chunk exactly, or aborts without mutation.
    ///
    /// An empty slice is a validated no-op. A nonempty slice must match the entire prepared chunk;
    /// positive short publication is rejected before ring mutation or byte publication.
    pub fn commit_write(&mut self, plan: WritePlan, bytes: &[u8]) -> Result<(), Error> {
        if !bytes.is_empty() && bytes.len() != plan.len {
            return Err(Error::InvalidLength);
        }
        let slot = self.slot_mut(plan.endpoint)?;
        if plan.endpoint.end != End::Write || !slot.writer_open {
            return Err(Error::StalePlan);
        }
        Self::validate_write_plan_inner(slot, plan)?;
        if bytes.is_empty() {
            return Ok(());
        }
        if !slot.reader_open {
            return Err(Error::BrokenPipe);
        }
        Self::advance_epoch(slot)?;
        for (index, byte) in bytes.iter().copied().enumerate() {
            slot.bytes[(plan.write_pos + index) % CAP] = byte;
        }
        slot.write_pos = (slot.write_pos + bytes.len()) % CAP;
        slot.len += bytes.len();
        Ok(())
    }

    pub fn len(&self, endpoint: Endpoint) -> Result<usize, Error> {
        Ok(self.slot(endpoint)?.len)
    }

    pub fn is_empty(&self, endpoint: Endpoint) -> Result<bool, Error> {
        Ok(self.slot(endpoint)?.len == 0)
    }

    pub fn free_capacity(&self, endpoint: Endpoint) -> Result<usize, Error> {
        Ok(CAP - self.slot(endpoint)?.len)
    }

    pub fn reader_count(&self, endpoint: Endpoint) -> Result<u32, Error> {
        Ok(u32::from(self.slot(endpoint)?.reader_open))
    }

    pub fn writer_count(&self, endpoint: Endpoint) -> Result<u32, Error> {
        Ok(u32::from(self.slot(endpoint)?.writer_open))
    }

    fn prepare_write_from_slot(
        &self,
        writer: Endpoint,
        slot: &PipeSlot<CAP>,
        requested: usize,
        atomic: bool,
    ) -> Result<WritePlan, Error> {
        if requested == 0 {
            return Ok(Self::write_plan(writer, slot, 0));
        }
        if !slot.reader_open {
            return Err(Error::BrokenPipe);
        }
        let free = CAP - slot.len;
        if free == 0 || (atomic && free < requested) {
            return Err(Error::WouldBlock);
        }
        Ok(Self::write_plan(
            writer,
            slot,
            core::cmp::min(requested, free),
        ))
    }

    fn write_plan(writer: Endpoint, slot: &PipeSlot<CAP>, len: usize) -> WritePlan {
        WritePlan {
            endpoint: writer,
            mutation_epoch: slot.mutation_epoch,
            write_pos: slot.write_pos,
            len,
            occupied: slot.len,
        }
    }

    fn validate_read_plan(&self, slot: &PipeSlot<CAP>, plan: ReadPlan) -> Result<(), Error> {
        Self::validate_read_plan_inner(slot, plan)
    }

    fn validate_read_plan_inner(slot: &PipeSlot<CAP>, plan: ReadPlan) -> Result<(), Error> {
        if slot.mutation_epoch != plan.mutation_epoch
            || slot.read_pos != plan.read_pos
            || slot.len != plan.available
        {
            return Err(Error::StalePlan);
        }
        Ok(())
    }

    fn validate_write_plan_inner(slot: &PipeSlot<CAP>, plan: WritePlan) -> Result<(), Error> {
        if slot.mutation_epoch != plan.mutation_epoch
            || slot.write_pos != plan.write_pos
            || slot.len != plan.occupied
        {
            return Err(Error::StalePlan);
        }
        Ok(())
    }

    fn advance_epoch(slot: &mut PipeSlot<CAP>) -> Result<(), Error> {
        let next = slot
            .mutation_epoch
            .checked_add(1)
            .ok_or(Error::EpochExhausted)?;
        slot.mutation_epoch = next;
        Ok(())
    }

    fn read_slot(&self, endpoint: Endpoint) -> Result<&PipeSlot<CAP>, Error> {
        let slot = self.slot(endpoint)?;
        if endpoint.end != End::Read || !slot.reader_open {
            return Err(Error::BadEndpoint);
        }
        Ok(slot)
    }

    fn write_slot(&self, endpoint: Endpoint) -> Result<&PipeSlot<CAP>, Error> {
        let slot = self.slot(endpoint)?;
        if endpoint.end != End::Write || !slot.writer_open {
            return Err(Error::BadEndpoint);
        }
        Ok(slot)
    }

    fn slot(&self, endpoint: Endpoint) -> Result<&PipeSlot<CAP>, Error> {
        let slot = self
            .slots
            .get(endpoint.pipe.slot())
            .ok_or(Error::BadEndpoint)?;
        if !slot.live || slot.generation != endpoint.pipe.generation() {
            return Err(Error::StaleEndpoint);
        }
        Ok(slot)
    }

    fn slot_mut(&mut self, endpoint: Endpoint) -> Result<&mut PipeSlot<CAP>, Error> {
        let slot = self
            .slots
            .get_mut(endpoint.pipe.slot())
            .ok_or(Error::BadEndpoint)?;
        if !slot.live || slot.generation != endpoint.pipe.generation() {
            return Err(Error::StaleEndpoint);
        }
        Ok(slot)
    }
}

impl<const N: usize, const CAP: usize> Default for PipeTable<N, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_write_read_and_chunk_commit() {
        let mut table = PipeTable::<2, 8>::new();
        let pair = table.create().unwrap();
        let write = table.prepare_write(pair.writer, 6).unwrap();
        table.commit_write(write, b"abcdef").unwrap();
        assert_eq!(table.len(pair.reader), Ok(6));

        let read = table.read_plan(pair.reader, 2).unwrap();
        let mut scratch = [0u8; 2];
        assert_eq!(table.copy_read(read, &mut scratch), Ok(2));
        assert_eq!(&scratch, b"ab");
        table.commit_read(read, 2).unwrap();
        assert_eq!(table.len(pair.reader), Ok(4));

        let next = table.read_plan(pair.reader, 8).unwrap();
        let mut scratch = [0u8; 8];
        assert_eq!(table.copy_read(next, &mut scratch), Ok(4));
        assert_eq!(&scratch[..4], b"cdef");
    }

    #[test]
    fn rejected_short_read_commit_leaves_plan_live_and_state_unchanged() {
        let mut table = PipeTable::<1, 4>::new();
        let pair = table.create().unwrap();
        let write = table.prepare_write(pair.writer, 2).unwrap();
        table.commit_write(write, b"xy").unwrap();
        let read = table.read_plan(pair.reader, 2).unwrap();
        let mut scratch = [0u8; 2];
        table.copy_read(read, &mut scratch).unwrap();
        assert_eq!(table.len(pair.reader), Ok(2));
        assert_eq!(table.commit_read(read, 1), Err(Error::InvalidLength));
        assert_eq!(table.len(pair.reader), Ok(2));
        assert_eq!(table.copy_read(read, &mut scratch), Ok(2));
        table.commit_read(read, 2).unwrap();
        assert_eq!(table.len(pair.reader), Ok(0));
        assert_eq!(table.commit_read(read, 2), Err(Error::StalePlan));
    }

    #[test]
    fn rejected_short_write_commit_leaves_plan_live_and_state_unchanged() {
        let mut table = PipeTable::<1, 4>::new();
        let pair = table.create().unwrap();
        let write = table.prepare_write(pair.writer, 4).unwrap();
        assert_eq!(table.commit_write(write, b"ab"), Err(Error::InvalidLength));
        assert_eq!(table.len(pair.reader), Ok(0));
        assert_eq!(table.free_capacity(pair.writer), Ok(4));
        table.commit_write(write, b"abcd").unwrap();
        assert_eq!(table.len(pair.reader), Ok(4));
    }

    #[test]
    fn ring_wrap_preserves_byte_order() {
        let mut table = PipeTable::<1, 4>::new();
        let pair = table.create().unwrap();
        let first = table.prepare_write(pair.writer, 4).unwrap();
        table.commit_write(first, b"abcd").unwrap();
        let read = table.read_plan(pair.reader, 3).unwrap();
        table.commit_read(read, 3).unwrap();
        let second = table.prepare_write(pair.writer, 3).unwrap();
        table.commit_write(second, b"XYZ").unwrap();

        let read = table.read_plan(pair.reader, 4).unwrap();
        let mut out = [0u8; 4];
        table.copy_read(read, &mut out).unwrap();
        assert_eq!(&out, b"dXYZ");
    }

    #[test]
    fn empty_with_writer_would_block_then_eof_after_writer_closes() {
        let mut table = PipeTable::<1, 8>::new();
        let pair = table.create().unwrap();
        assert_eq!(table.prepare_read(pair.reader, 1), Err(Error::WouldBlock));
        table.close(pair.writer).unwrap();
        assert_eq!(table.prepare_read(pair.reader, 1), Ok(ReadState::Eof));
        assert!(table.read_plan(pair.reader, 1).unwrap().is_empty());
    }

    #[test]
    fn write_without_reader_is_broken_pipe() {
        let mut table = PipeTable::<1, 8>::new();
        let pair = table.create().unwrap();
        table.close(pair.reader).unwrap();
        assert_eq!(table.prepare_write(pair.writer, 1), Err(Error::BrokenPipe));
        assert!(table.prepare_write(pair.writer, 0).unwrap().is_empty());
    }

    #[test]
    fn copied_endpoint_does_not_create_another_lease() {
        let mut table = PipeTable::<1, 8>::new();
        let pair = table.create().unwrap();
        let copied = pair.reader;
        table.close(pair.reader).unwrap();
        assert_eq!(table.close(copied), Err(Error::BadEndpoint));
        assert_eq!(table.reader_count(pair.writer), Ok(0));
    }

    #[test]
    fn stale_endpoints_cannot_reach_reused_slot() {
        let mut table = PipeTable::<1, 4>::new();
        let old = table.create().unwrap();
        table.close(old.reader).unwrap();
        table.close(old.writer).unwrap();
        let new = table.create().unwrap();
        assert_eq!(old.reader.pipe().slot(), new.reader.pipe().slot());
        assert_ne!(
            old.reader.pipe().generation(),
            new.reader.pipe().generation()
        );
        assert_eq!(table.len(old.reader), Err(Error::StaleEndpoint));
    }

    #[test]
    fn endpoint_close_invalidates_prepared_plan_even_if_pipe_stays_live() {
        let mut table = PipeTable::<1, 8>::new();
        let pair = table.create().unwrap();
        let write = table.prepare_write(pair.writer, 1).unwrap();
        table.commit_write(write, b"x").unwrap();
        let read = table.read_plan(pair.reader, 1).unwrap();
        table.close(pair.reader).unwrap();
        let mut out = [0u8; 1];
        assert_eq!(table.copy_read(read, &mut out), Err(Error::BadEndpoint));
        assert_eq!(table.commit_read(read, 1), Err(Error::StalePlan));
    }

    #[test]
    fn mutation_epoch_rejects_drain_wrap_refill_aba() {
        let mut table = PipeTable::<1, 2>::new();
        let pair = table.create().unwrap();
        let first = table.prepare_write(pair.writer, 2).unwrap();
        table.commit_write(first, b"ab").unwrap();
        let stale = table.read_plan(pair.reader, 2).unwrap();
        table.commit_read(stale, 2).unwrap();
        let refill = table.prepare_write(pair.writer, 2).unwrap();
        table.commit_write(refill, b"cd").unwrap();
        let mut out = [0u8; 2];
        assert_eq!(table.copy_read(stale, &mut out), Err(Error::StalePlan));
    }

    #[test]
    fn mutation_epoch_exhaustion_fails_closed() {
        let mut table = PipeTable::<1, 8>::new();
        let pair = table.create().unwrap();
        table.slots[0].mutation_epoch = u64::MAX;

        let write = table.prepare_write(pair.writer, 1).unwrap();
        assert_eq!(table.commit_write(write, b"x"), Err(Error::EpochExhausted));
        assert_eq!(table.len(pair.reader), Ok(0));
        assert_eq!(table.free_capacity(pair.writer), Ok(8));
        assert_eq!(table.reader_count(pair.writer), Ok(1));
        assert_eq!(table.writer_count(pair.reader), Ok(1));
        assert_eq!(table.slots[0].mutation_epoch, u64::MAX);

        assert_eq!(table.close(pair.reader), Err(Error::EpochExhausted));
        assert_eq!(table.reader_count(pair.writer), Ok(1));
        assert_eq!(table.writer_count(pair.reader), Ok(1));
        assert_eq!(table.slots[0].mutation_epoch, u64::MAX);
        assert!(table.is_empty(pair.reader).unwrap());
    }

    #[test]
    fn nonblocking_pipe_buf_write_is_all_or_would_block() {
        let mut table = PipeTable::<1, 8>::new();
        let pair = table.create().unwrap();
        let seed = table.prepare_write(pair.writer, 6).unwrap();
        table.commit_write(seed, b"abcdef").unwrap();
        assert_eq!(table.free_capacity(pair.writer), Ok(2));
        assert_eq!(
            table.prepare_nonblocking_write(pair.writer, 3),
            Err(Error::WouldBlock)
        );
        let exact = table.prepare_nonblocking_write(pair.writer, 2).unwrap();
        assert_eq!(exact.len(), 2);
    }

    #[test]
    fn nonblocking_write_above_pipe_buf_may_plan_partial_prefix() {
        let mut table = PipeTable::<1, 8192>::new();
        let pair = table.create().unwrap();
        let seed = table.prepare_write(pair.writer, 5000).unwrap();
        table.commit_write(seed, &[7; 5000]).unwrap();
        let plan = table
            .prepare_nonblocking_write(pair.writer, PIPE_BUF + 1000)
            .unwrap();
        assert_eq!(plan.len(), 3192);
    }
}
