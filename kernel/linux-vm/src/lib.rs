// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_capability::ObjectId;
use kernal_linux_abi::{Errno, MinimumRuntimeCall};
use kernal_vm::{Backing, PAGE_SIZE, USER_MAX_EXCLUSIVE, USER_MIN, VmPerms, Vma};

pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const STEP15_ANON_FLAGS: u64 = MAP_PRIVATE | MAP_ANONYMOUS;
pub const DEFAULT_MMAP_CEILING: u64 = USER_MAX_EXCLUSIVE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendFailure {
    NoMemory,
    NotMapped,
    Invariant,
}

/// Minimal mutation surface required by the architecture-neutral Step-15 Linux VM transaction.
///
/// Implementations must route mapping through the already-authorized process/address-space owner
/// and reclaim physical pages through the existing reclaimable frame allocator. `poison()` is the
/// fail-closed quarantine path when rollback can no longer prove a coherent mapping/ownership state.
pub trait PageBackend {
    fn range_is_free(&mut self, start: u64, len: u64) -> Result<bool, BackendFailure>;
    fn find_gap_top_down(&mut self, len: u64, ceiling: u64) -> Result<u64, BackendFailure>;
    fn page_is_mapped(&mut self, virtual_address: u64) -> Result<bool, BackendFailure>;
    fn allocate_page(&mut self) -> Result<u64, BackendFailure>;
    fn map_page(
        &mut self,
        virtual_address: u64,
        physical_address: u64,
        perms: VmPerms,
    ) -> Result<(), BackendFailure>;
    fn protect_page(&mut self, virtual_address: u64, perms: VmPerms) -> Result<(), BackendFailure>;
    fn unmap_page(&mut self, virtual_address: u64) -> Result<u64, BackendFailure>;
    fn free_page(&mut self, physical_address: u64) -> Result<(), BackendFailure>;
    fn poison(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Linux(Errno),
    BackendInvariant,
    BreakStateCapacity,
    MissingBreakState,
    NotVmCall,
}

#[derive(Clone, Copy)]
struct BreakSlot {
    occupied: bool,
    process: ObjectId,
    base: u64,
    current: u64,
}

impl BreakSlot {
    const EMPTY: Self = Self {
        occupied: false,
        process: ObjectId(0),
        base: 0,
        current: 0,
    };
}

/// Generation-safe process-owned Linux program-break state.
///
/// The key is the existing generation-safe process ObjectId. Slot reuse therefore cannot let an old
/// process generation discover or mutate the break state of a newer process generation.
pub struct BreakTable<const N: usize> {
    slots: [BreakSlot; N],
}

impl<const N: usize> BreakTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [BreakSlot::EMPTY; N],
        }
    }

    pub fn register(&mut self, process: ObjectId, initial_break: u64) -> Result<(), Error> {
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&initial_break) {
            return Err(Error::BackendInvariant);
        }
        if self
            .slots
            .iter()
            .any(|slot| slot.occupied && slot.process == process)
        {
            return Err(Error::BackendInvariant);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| !slot.occupied)
            .ok_or(Error::BreakStateCapacity)?;
        *slot = BreakSlot {
            occupied: true,
            process,
            base: initial_break,
            current: initial_break,
        };
        Ok(())
    }

    /// Copies the exact parent's Linux break metadata into one distinct child generation.
    ///
    /// Fork duplicates the userspace image before either process can mutate it, so both the
    /// immutable break base and the current break cursor must be inherited. The child ObjectId is
    /// generation-qualified and receives its own bounded slot; no scalar PID or address-space token
    /// participates in this ownership relation.
    pub fn inherit(&mut self, parent: ObjectId, child: ObjectId) -> Result<(), Error> {
        if parent == child
            || self
                .slots
                .iter()
                .any(|slot| slot.occupied && slot.process == child)
        {
            return Err(Error::BackendInvariant);
        }
        let inherited = *self.resolve(parent)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| !slot.occupied)
            .ok_or(Error::BreakStateCapacity)?;
        *slot = BreakSlot {
            occupied: true,
            process: child,
            base: inherited.base,
            current: inherited.current,
        };
        Ok(())
    }

    pub fn remove(&mut self, process: ObjectId) -> Result<(), Error> {
        let slot = self.resolve_mut(process)?;
        *slot = BreakSlot::EMPTY;
        Ok(())
    }

    pub fn current(&self, process: ObjectId) -> Result<u64, Error> {
        Ok(self.resolve(process)?.current)
    }

    fn resolve(&self, process: ObjectId) -> Result<&BreakSlot, Error> {
        self.slots
            .iter()
            .find(|slot| slot.occupied && slot.process == process)
            .ok_or(Error::MissingBreakState)
    }

    fn resolve_mut(&mut self, process: ObjectId) -> Result<&mut BreakSlot, Error> {
        self.slots
            .iter_mut()
            .find(|slot| slot.occupied && slot.process == process)
            .ok_or(Error::MissingBreakState)
    }
}

impl<const N: usize> Default for BreakTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Allocation-free Step-15 Linux anonymous-VM runtime.
///
/// `BREAKS` bounds process break metadata. `TX_PAGES` bounds temporary mutation work so a hostile
/// request cannot turn one syscall into an unbounded transaction. mmap growth rollback does not
/// require a frame list: exact frames are recovered from the accepted unmap owner before reuse.
pub struct LinuxVmRuntime<const BREAKS: usize, const TX_PAGES: usize> {
    breaks: BreakTable<BREAKS>,
}

impl<const BREAKS: usize, const TX_PAGES: usize> LinuxVmRuntime<BREAKS, TX_PAGES> {
    pub const fn new() -> Self {
        Self {
            breaks: BreakTable::new(),
        }
    }

    pub fn register_process_break(
        &mut self,
        process: ObjectId,
        initial_break: u64,
    ) -> Result<(), Error> {
        self.breaks.register(process, initial_break)
    }

    /// Inherits the exact parent Process generation's program break for fork.
    ///
    /// The caller must first prove the real parent/child Process relation through the canonical
    /// Process/Linux-identity owners. This VM owner intentionally accepts only the resulting exact
    /// ObjectIds and copies its own bounded metadata; it creates no second process registry.
    pub fn inherit_process_break(
        &mut self,
        parent: ObjectId,
        child: ObjectId,
    ) -> Result<(), Error> {
        self.breaks.inherit(parent, child)
    }

    pub fn remove_process_break(&mut self, process: ObjectId) -> Result<(), Error> {
        self.breaks.remove(process)
    }

    pub fn current_break(&self, process: ObjectId) -> Result<u64, Error> {
        self.breaks.current(process)
    }

    /// Replaces the program-break state of the exact existing Process generation after exec.
    ///
    /// This is deliberately an in-place owner update: successful exec keeps the same Process
    /// ObjectId, so freeing and re-registering the slot would introduce a fallible capacity edge
    /// after the old address space is no longer authoritative.
    pub fn replace_process_break_for_exec(
        &mut self,
        process: ObjectId,
        initial_break: u64,
    ) -> Result<(), Error> {
        if !(USER_MIN..USER_MAX_EXCLUSIVE).contains(&initial_break) {
            return Err(Error::BackendInvariant);
        }
        let slot = self.breaks.resolve_mut(process)?;
        slot.base = initial_break;
        slot.current = initial_break;
        Ok(())
    }

    /// Handles only the Step-15 VM subset of the canonical `MinimumRuntimeCall` contract.
    pub fn handle<B: PageBackend>(
        &mut self,
        process: ObjectId,
        call: MinimumRuntimeCall,
        backend: &mut B,
    ) -> Result<u64, Error> {
        match call {
            MinimumRuntimeCall::Mmap {
                address,
                length,
                protection,
                flags,
                fd,
                offset,
            } => self.mmap(address, length, protection, flags, fd, offset, backend),
            MinimumRuntimeCall::Munmap { address, length } => {
                self.munmap(address, length, backend)?;
                Ok(0)
            }
            MinimumRuntimeCall::Mprotect {
                address,
                length,
                protection,
            } => {
                self.mprotect(address, length, protection, backend)?;
                Ok(0)
            }
            MinimumRuntimeCall::Brk { address } => self.brk(process, address, backend),
            _ => Err(Error::NotVmCall),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mmap<B: PageBackend>(
        &mut self,
        address: u64,
        length: u64,
        protection: u64,
        flags: u64,
        fd: u64,
        offset: u64,
        backend: &mut B,
    ) -> Result<u64, Error> {
        if flags != STEP15_ANON_FLAGS || fd != u64::MAX || offset != 0 {
            return Err(Error::Linux(Errno::EINVAL));
        }
        let perms = parse_step15_perms(protection)?;
        let len = page_rounded_length(length).ok_or(Error::Linux(Errno::EINVAL))?;

        let start = if address == 0 {
            find_gap(backend, len)?
        } else {
            validate_page_range(address, len)?;
            match backend.range_is_free(address, len) {
                Ok(true) => address,
                Ok(false) => find_gap(backend, len)?,
                Err(BackendFailure::NoMemory) => return Err(no_memory_error()),
                Err(_) => return Err(Error::BackendInvariant),
            }
        };
        validate_page_range(start, len)?;
        match backend.range_is_free(start, len) {
            Ok(true) => {}
            Ok(false) => return Err(Error::BackendInvariant),
            Err(BackendFailure::NoMemory) => return Err(no_memory_error()),
            Err(_) => return Err(Error::BackendInvariant),
        }

        match map_range(backend, start, len, perms) {
            Ok(()) => Ok(start),
            Err(TxFailure::NoMemory) => Err(no_memory_error()),
            Err(TxFailure::Invariant) => Err(Error::BackendInvariant),
        }
    }

    pub fn munmap<B: PageBackend>(
        &mut self,
        address: u64,
        length: u64,
        backend: &mut B,
    ) -> Result<(), Error> {
        let len = page_rounded_length(length).ok_or(Error::Linux(Errno::EINVAL))?;
        validate_page_range(address, len)?;
        let pages = len / PAGE_SIZE;
        let mut mutated = false;
        for page in 0..pages {
            let va = address + page * PAGE_SIZE;
            match backend.unmap_page(va) {
                Ok(frame) => {
                    mutated = true;
                    if backend.free_page(frame).is_err() {
                        backend.poison();
                        return Err(Error::BackendInvariant);
                    }
                }
                Err(BackendFailure::NotMapped) => {}
                Err(_) => {
                    if mutated {
                        backend.poison();
                    }
                    return Err(Error::BackendInvariant);
                }
            }
        }
        Ok(())
    }

    /// Changes permissions on one bounded, fully mapped page range.
    ///
    /// The complete range is probed before the first page-table mutation, so an ordinary unmapped
    /// page returns Linux ENOMEM without partially changing protection. Architecture failures after
    /// mutation begin are not recoverable without retaining the exact old permission vector; the
    /// bounded Step-15 owner therefore poisons the address space rather than returning to EL0 with a
    /// partially changed contract. W+X and unsupported protection bits fail before mutation.
    pub fn mprotect<B: PageBackend>(
        &mut self,
        address: u64,
        length: u64,
        protection: u64,
        backend: &mut B,
    ) -> Result<(), Error> {
        let perms = parse_step15_perms(protection)?;
        let len = page_rounded_length(length).ok_or(Error::Linux(Errno::EINVAL))?;
        validate_page_range(address, len)?;
        let pages = usize::try_from(len / PAGE_SIZE).map_err(|_| no_memory_error())?;
        if pages > TX_PAGES {
            return Err(no_memory_error());
        }

        for page in 0..pages {
            let va = address + page as u64 * PAGE_SIZE;
            match backend.page_is_mapped(va) {
                Ok(true) => {}
                Ok(false) | Err(BackendFailure::NotMapped | BackendFailure::NoMemory) => {
                    return Err(no_memory_error());
                }
                Err(BackendFailure::Invariant) => return Err(Error::BackendInvariant),
            }
        }

        let mut mutated = false;
        for page in 0..pages {
            let va = address + page as u64 * PAGE_SIZE;
            match backend.protect_page(va, perms) {
                Ok(()) => mutated = true,
                Err(_) => {
                    if mutated {
                        backend.poison();
                    }
                    return Err(Error::BackendInvariant);
                }
            }
        }
        Ok(())
    }

    pub fn brk<B: PageBackend>(
        &mut self,
        process: ObjectId,
        requested: u64,
        backend: &mut B,
    ) -> Result<u64, Error> {
        let state = *self.breaks.resolve(process)?;
        if requested == 0 {
            return Ok(state.current);
        }
        if requested < state.base || requested >= USER_MAX_EXCLUSIVE {
            return Ok(state.current);
        }
        if requested == state.current {
            return Ok(requested);
        }

        let old_page_end = align_up_page(state.current).ok_or(Error::BackendInvariant)?;
        let new_page_end = align_up_page(requested).ok_or(Error::BackendInvariant)?;
        if new_page_end > USER_MAX_EXCLUSIVE {
            return Ok(state.current);
        }

        if new_page_end > old_page_end {
            let len = new_page_end - old_page_end;
            match backend.range_is_free(old_page_end, len) {
                Ok(true) => {}
                Ok(false) | Err(BackendFailure::NoMemory) => return Ok(state.current),
                Err(_) => return Err(Error::BackendInvariant),
            }
            let perms = VmPerms::READ.union(VmPerms::WRITE);
            match map_range(backend, old_page_end, len, perms) {
                Ok(()) => {}
                Err(TxFailure::NoMemory) => return Ok(state.current),
                Err(TxFailure::Invariant) => return Err(Error::BackendInvariant),
            }
        } else if new_page_end < old_page_end {
            let len = old_page_end - new_page_end;
            let pages = (len / PAGE_SIZE) as usize;
            if pages > TX_PAGES {
                return Ok(state.current);
            }
            let mut frames = [0u64; TX_PAGES];
            let mut unmapped = 0usize;
            for page in 0..pages {
                let va = new_page_end + page as u64 * PAGE_SIZE;
                match backend.unmap_page(va) {
                    Ok(frame) => {
                        frames[page] = frame;
                        unmapped += 1;
                    }
                    Err(_) => {
                        if !rollback_unmapped_brk(backend, new_page_end, &frames[..unmapped]) {
                            backend.poison();
                        }
                        return Err(Error::BackendInvariant);
                    }
                }
            }
            for frame in &frames[..pages] {
                if backend.free_page(*frame).is_err() {
                    backend.poison();
                    return Err(Error::BackendInvariant);
                }
            }
        }

        self.breaks.resolve_mut(process)?.current = requested;
        Ok(requested)
    }
}

impl<const BREAKS: usize, const TX_PAGES: usize> Default for LinuxVmRuntime<BREAKS, TX_PAGES> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TxFailure {
    NoMemory,
    Invariant,
}

fn map_range<B: PageBackend>(
    backend: &mut B,
    start: u64,
    len: u64,
    perms: VmPerms,
) -> Result<(), TxFailure> {
    let pages = len / PAGE_SIZE;
    for (mapped, page) in (0..pages).enumerate() {
        let mapped = mapped as u64;
        let va = start + page * PAGE_SIZE;
        let frame = match backend.allocate_page() {
            Ok(frame) => frame,
            Err(BackendFailure::NoMemory) => {
                if !rollback_mapped(backend, start, mapped) {
                    backend.poison();
                    return Err(TxFailure::Invariant);
                }
                return Err(TxFailure::NoMemory);
            }
            Err(_) => {
                if !rollback_mapped(backend, start, mapped) {
                    backend.poison();
                }
                return Err(TxFailure::Invariant);
            }
        };
        if let Err(error) = backend.map_page(va, frame, perms) {
            let current_reclaimed = backend.free_page(frame).is_ok();
            let prior_reclaimed = rollback_mapped(backend, start, mapped);
            if !current_reclaimed || !prior_reclaimed {
                backend.poison();
                return Err(TxFailure::Invariant);
            }
            return match error {
                BackendFailure::NoMemory => Err(TxFailure::NoMemory),
                _ => Err(TxFailure::Invariant),
            };
        }
    }
    Ok(())
}

fn rollback_mapped<B: PageBackend>(backend: &mut B, start: u64, pages: u64) -> bool {
    let mut complete = true;
    let mut page = pages;
    while page > 0 {
        page -= 1;
        let va = start + page * PAGE_SIZE;
        match backend.unmap_page(va) {
            Ok(frame) => {
                if backend.free_page(frame).is_err() {
                    complete = false;
                }
            }
            Err(_) => complete = false,
        }
    }
    complete
}

fn rollback_unmapped_brk<B: PageBackend>(backend: &mut B, start: u64, frames: &[u64]) -> bool {
    let perms = VmPerms::READ.union(VmPerms::WRITE);
    let mut complete = true;
    for (page, frame) in frames.iter().copied().enumerate() {
        let va = start + page as u64 * PAGE_SIZE;
        if backend.map_page(va, frame, perms).is_err() {
            complete = false;
        }
    }
    complete
}

fn parse_step15_perms(protection: u64) -> Result<VmPerms, Error> {
    if protection & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(Error::Linux(Errno::EINVAL));
    }
    let mut perms = VmPerms::NONE;
    if protection & PROT_READ != 0 {
        perms = perms.union(VmPerms::READ);
    }
    if protection & PROT_WRITE != 0 {
        perms = perms.union(VmPerms::WRITE);
    }
    if protection & PROT_EXEC != 0 {
        perms = perms.union(VmPerms::EXECUTE);
    }
    if !perms.readable() || perms.validate().is_err() {
        return Err(Error::Linux(Errno::EINVAL));
    }
    Ok(perms)
}

fn find_gap<B: PageBackend>(backend: &mut B, len: u64) -> Result<u64, Error> {
    match backend.find_gap_top_down(len, DEFAULT_MMAP_CEILING) {
        Ok(start) => Ok(start),
        Err(BackendFailure::NoMemory) => Err(no_memory_error()),
        Err(_) => Err(Error::BackendInvariant),
    }
}

fn validate_page_range(start: u64, len: u64) -> Result<(), Error> {
    Vma::new(start, len, VmPerms::READ, Backing::Anonymous)
        .map(|_| ())
        .map_err(|_| Error::Linux(Errno::EINVAL))
}

fn page_rounded_length(length: u64) -> Option<u64> {
    if length == 0 {
        return None;
    }
    align_up_page(length)
}

fn align_up_page(value: u64) -> Option<u64> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|aligned| aligned & !(PAGE_SIZE - 1))
}

fn no_memory_error() -> Error {
    match Errno::new(12) {
        Some(errno) => Error::Linux(errno),
        None => Error::BackendInvariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_PAGES: usize = 64;

    #[derive(Clone, Copy)]
    struct Page {
        used: bool,
        va: u64,
        frame: u64,
        perms: VmPerms,
    }

    impl Page {
        const EMPTY: Self = Self {
            used: false,
            va: 0,
            frame: 0,
            perms: VmPerms::NONE,
        };
    }

    struct MockBackend {
        pages: [Page; MAX_PAGES],
        next_frame: u64,
        allocate_calls: usize,
        map_calls: usize,
        fail_allocate_at: Option<usize>,
        fail_map_at: Option<(usize, BackendFailure)>,
        fail_unmap_at: Option<u64>,
        fail_free: bool,
        poisoned: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                pages: [Page::EMPTY; MAX_PAGES],
                next_frame: 0x20_0000,
                allocate_calls: 0,
                map_calls: 0,
                fail_allocate_at: None,
                fail_map_at: None,
                fail_unmap_at: None,
                fail_free: false,
                poisoned: false,
            }
        }

        fn mapped_count(&self) -> usize {
            self.pages.iter().filter(|page| page.used).count()
        }

        fn is_free(&self, start: u64, len: u64) -> bool {
            let end = start + len;
            !self
                .pages
                .iter()
                .any(|page| page.used && page.va < end && page.va + PAGE_SIZE > start)
        }

        fn perms_at(&self, address: u64) -> Option<VmPerms> {
            self.pages
                .iter()
                .find(|page| page.used && page.va == address)
                .map(|page| page.perms)
        }
    }

    impl PageBackend for MockBackend {
        fn range_is_free(&mut self, start: u64, len: u64) -> Result<bool, BackendFailure> {
            Ok(self.is_free(start, len))
        }

        fn find_gap_top_down(&mut self, len: u64, ceiling: u64) -> Result<u64, BackendFailure> {
            let mut start = (ceiling - len) & !(PAGE_SIZE - 1);
            while start >= USER_MIN {
                if self.is_free(start, len) {
                    return Ok(start);
                }
                if start < USER_MIN + PAGE_SIZE {
                    break;
                }
                start -= PAGE_SIZE;
            }
            Err(BackendFailure::NoMemory)
        }

        fn page_is_mapped(&mut self, virtual_address: u64) -> Result<bool, BackendFailure> {
            Ok(self
                .pages
                .iter()
                .any(|page| page.used && page.va == virtual_address))
        }

        fn allocate_page(&mut self) -> Result<u64, BackendFailure> {
            let call = self.allocate_calls;
            self.allocate_calls += 1;
            if self.fail_allocate_at == Some(call) {
                return Err(BackendFailure::NoMemory);
            }
            let frame = self.next_frame;
            self.next_frame += PAGE_SIZE;
            Ok(frame)
        }

        fn map_page(
            &mut self,
            virtual_address: u64,
            physical_address: u64,
            perms: VmPerms,
        ) -> Result<(), BackendFailure> {
            let call = self.map_calls;
            self.map_calls += 1;
            if let Some((at, error)) = self.fail_map_at
                && at == call
            {
                return Err(error);
            }
            if !self.is_free(virtual_address, PAGE_SIZE) {
                return Err(BackendFailure::Invariant);
            }
            let slot = self
                .pages
                .iter_mut()
                .find(|page| !page.used)
                .ok_or(BackendFailure::NoMemory)?;
            *slot = Page {
                used: true,
                va: virtual_address,
                frame: physical_address,
                perms,
            };
            Ok(())
        }

        fn protect_page(
            &mut self,
            virtual_address: u64,
            perms: VmPerms,
        ) -> Result<(), BackendFailure> {
            let page = self
                .pages
                .iter_mut()
                .find(|page| page.used && page.va == virtual_address)
                .ok_or(BackendFailure::NotMapped)?;
            page.perms = perms;
            Ok(())
        }

        fn unmap_page(&mut self, virtual_address: u64) -> Result<u64, BackendFailure> {
            if self.fail_unmap_at == Some(virtual_address) {
                return Err(BackendFailure::Invariant);
            }
            let page = self
                .pages
                .iter_mut()
                .find(|page| page.used && page.va == virtual_address)
                .ok_or(BackendFailure::NotMapped)?;
            let frame = page.frame;
            *page = Page::EMPTY;
            Ok(frame)
        }

        fn free_page(&mut self, _physical_address: u64) -> Result<(), BackendFailure> {
            if self.fail_free {
                Err(BackendFailure::Invariant)
            } else {
                Ok(())
            }
        }

        fn poison(&mut self) {
            self.poisoned = true;
        }
    }

    fn anon_call(length: u64) -> MinimumRuntimeCall {
        MinimumRuntimeCall::Mmap {
            address: 0,
            length,
            protection: PROT_READ | PROT_WRITE,
            flags: STEP15_ANON_FLAGS,
            fd: u64::MAX,
            offset: 0,
        }
    }

    #[test]
    fn anonymous_private_mmap_rounds_length_and_maps_pages() {
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        let mut backend = MockBackend::new();
        let start = runtime
            .handle(ObjectId(1), anon_call(PAGE_SIZE + 7), &mut backend)
            .unwrap();
        assert!(start >= USER_MIN);
        assert_eq!(backend.mapped_count(), 2);
    }

    #[test]
    fn mprotect_changes_a_fully_mapped_range_without_widening_wx() {
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        let mut backend = MockBackend::new();
        let start = runtime
            .handle(ObjectId(1), anon_call(2 * PAGE_SIZE), &mut backend)
            .unwrap();
        assert_eq!(
            runtime.handle(
                ObjectId(1),
                MinimumRuntimeCall::Mprotect {
                    address: start,
                    length: 2 * PAGE_SIZE,
                    protection: PROT_READ,
                },
                &mut backend,
            ),
            Ok(0)
        );
        assert_eq!(backend.perms_at(start), Some(VmPerms::READ));
        assert_eq!(backend.perms_at(start + PAGE_SIZE), Some(VmPerms::READ));
        assert!(!backend.poisoned);

        assert_eq!(
            runtime.handle(
                ObjectId(1),
                MinimumRuntimeCall::Mprotect {
                    address: start,
                    length: PAGE_SIZE,
                    protection: PROT_WRITE | PROT_EXEC,
                },
                &mut backend,
            ),
            Err(Error::Linux(Errno::EINVAL))
        );
        assert_eq!(backend.perms_at(start), Some(VmPerms::READ));
    }

    #[test]
    fn mprotect_unmapped_range_returns_enomem_before_mutation() {
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        let mut backend = MockBackend::new();
        let start = runtime
            .handle(ObjectId(1), anon_call(PAGE_SIZE), &mut backend)
            .unwrap();
        let protect_start = start.checked_sub(PAGE_SIZE).unwrap();
        assert_eq!(
            runtime.handle(
                ObjectId(1),
                MinimumRuntimeCall::Mprotect {
                    address: protect_start,
                    length: 2 * PAGE_SIZE,
                    protection: PROT_READ,
                },
                &mut backend,
            ),
            Err(no_memory_error())
        );
        assert_eq!(backend.perms_at(protect_start), None);
        assert_eq!(
            backend.perms_at(start),
            Some(VmPerms::READ.union(VmPerms::WRITE))
        );
        assert!(!backend.poisoned);
    }

    #[test]
    fn allocation_exhaustion_rolls_back_without_partial_mapping() {
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        let mut backend = MockBackend::new();
        backend.fail_allocate_at = Some(1);
        let result = runtime.handle(ObjectId(1), anon_call(2 * PAGE_SIZE), &mut backend);
        assert_eq!(result, Err(no_memory_error()));
        assert_eq!(backend.mapped_count(), 0);
        assert!(!backend.poisoned);
    }

    #[test]
    fn late_map_oom_rolls_back_and_returns_enomem() {
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        let mut backend = MockBackend::new();
        backend.fail_map_at = Some((1, BackendFailure::NoMemory));
        let result = runtime.handle(ObjectId(1), anon_call(2 * PAGE_SIZE), &mut backend);
        assert_eq!(result, Err(no_memory_error()));
        assert_eq!(backend.mapped_count(), 0);
        assert!(!backend.poisoned);
    }

    #[test]
    fn munmap_free_failure_poison_quarantines_unprovable_cleanup() {
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        let mut backend = MockBackend::new();
        let start = runtime
            .handle(ObjectId(1), anon_call(PAGE_SIZE), &mut backend)
            .unwrap();
        backend.fail_free = true;
        let result = runtime.handle(
            ObjectId(1),
            MinimumRuntimeCall::Munmap {
                address: start,
                length: PAGE_SIZE,
            },
            &mut backend,
        );
        assert_eq!(result, Err(Error::BackendInvariant));
        assert!(backend.poisoned);
    }

    #[test]
    fn brk_growth_failure_keeps_old_break_and_rolls_back() {
        let process = ObjectId(0x101);
        let base = USER_MIN + 0x20_123;
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        runtime.register_process_break(process, base).unwrap();
        let mut backend = MockBackend::new();
        backend.fail_map_at = Some((1, BackendFailure::NoMemory));
        let requested = base + 3 * PAGE_SIZE;
        assert_eq!(runtime.brk(process, requested, &mut backend), Ok(base));
        assert_eq!(runtime.current_break(process), Ok(base));
        assert_eq!(backend.mapped_count(), 0);
    }

    #[test]
    fn brk_shrink_failure_restores_unmapped_prefix_and_keeps_break() {
        let process = ObjectId(0x202);
        let base = USER_MIN + 0x40_123;
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        runtime.register_process_break(process, base).unwrap();
        let mut backend = MockBackend::new();
        let grown = base + 3 * PAGE_SIZE;
        assert_eq!(runtime.brk(process, grown, &mut backend), Ok(grown));
        let mapped_before = backend.mapped_count();
        let first = align_up_page(base).unwrap();
        backend.fail_unmap_at = Some(first + PAGE_SIZE);
        assert_eq!(
            runtime.brk(process, base, &mut backend),
            Err(Error::BackendInvariant)
        );
        assert_eq!(runtime.current_break(process), Ok(grown));
        assert_eq!(backend.mapped_count(), mapped_before);
        assert!(!backend.poisoned);
    }

    #[test]
    fn unsupported_mapping_contract_fails_with_einval_before_mutation() {
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        let mut backend = MockBackend::new();
        let result = runtime.handle(
            ObjectId(1),
            MinimumRuntimeCall::Mmap {
                address: 0,
                length: PAGE_SIZE,
                protection: PROT_READ | PROT_WRITE,
                flags: MAP_PRIVATE,
                fd: u64::MAX,
                offset: 0,
            },
            &mut backend,
        );
        assert_eq!(result, Err(Error::Linux(Errno::EINVAL)));
        assert_eq!(backend.mapped_count(), 0);
    }

    #[test]
    fn fork_inherits_break_base_and_current_into_distinct_child_slot() {
        let parent = ObjectId(0x301);
        let child = ObjectId(0x302);
        let base = USER_MIN + 0x60_123;
        let mut runtime = LinuxVmRuntime::<4, 16>::new();
        runtime.register_process_break(parent, base).unwrap();
        let mut backend = MockBackend::new();
        let grown = base + 2 * PAGE_SIZE;
        assert_eq!(runtime.brk(parent, grown, &mut backend), Ok(grown));

        runtime.inherit_process_break(parent, child).unwrap();
        let inherited = runtime.breaks.resolve(child).unwrap();
        assert_eq!(inherited.base, base);
        assert_eq!(inherited.current, grown);
        assert_eq!(runtime.current_break(parent), Ok(grown));
        assert_eq!(runtime.current_break(child), Ok(grown));

        runtime.remove_process_break(child).unwrap();
        assert_eq!(runtime.current_break(child), Err(Error::MissingBreakState));
        assert_eq!(runtime.current_break(parent), Ok(grown));
    }

    #[test]
    fn fork_break_inheritance_rejects_alias_duplicate_and_missing_parent() {
        let parent = ObjectId(0x401);
        let child = ObjectId(0x402);
        let missing = ObjectId(0x403);
        let mut runtime = LinuxVmRuntime::<2, 4>::new();
        runtime
            .register_process_break(parent, USER_MIN + 0x1000)
            .unwrap();
        assert_eq!(
            runtime.inherit_process_break(parent, parent),
            Err(Error::BackendInvariant)
        );
        assert_eq!(
            runtime.inherit_process_break(missing, child),
            Err(Error::MissingBreakState)
        );
        runtime.inherit_process_break(parent, child).unwrap();
        assert_eq!(
            runtime.inherit_process_break(parent, child),
            Err(Error::BackendInvariant)
        );
    }

    #[test]
    fn process_generation_keys_isolate_break_state() {
        let mut runtime = LinuxVmRuntime::<2, 4>::new();
        let old = ObjectId(7);
        let new = ObjectId(8);
        runtime
            .register_process_break(old, USER_MIN + 0x1000)
            .unwrap();
        runtime.remove_process_break(old).unwrap();
        runtime
            .register_process_break(new, USER_MIN + 0x2000)
            .unwrap();
        assert_eq!(runtime.current_break(old), Err(Error::MissingBreakState));
        assert_eq!(runtime.current_break(new), Ok(USER_MIN + 0x2000));
    }
}
