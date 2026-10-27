// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use super::*;

/// Generation-bound identity of one process-local descriptor view.
///
/// This identity is internal Linux-FD owner metadata only. It is never a Process/PID authority and
/// callers must bind it to an exact Process through the canonical runtime owner before selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdViewId {
    index: usize,
    generation: u64,
}

impl FdViewId {
    pub const fn index(self) -> usize {
        self.index
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy)]
struct FdViewSlot<const N: usize> {
    generation: u64,
    retired: bool,
    live: bool,
    descriptors: [DescriptorSlot; N],
}

impl<const N: usize> FdViewSlot<N> {
    const EMPTY: Self = Self {
        generation: 0,
        retired: false,
        live: false,
        descriptors: [DescriptorSlot::EMPTY; N],
    };
}

/// Bounded process-local descriptor views over one canonical [`FdTable`] OFD engine.
///
/// Only descriptor slots are parked per view. The single embedded `FdTable` permanently owns the
/// generation-safe open-file-description pool, so fork never copies OFD offset/status/object state.
/// `with_view` temporarily swaps exactly one descriptor set into that engine, executes the existing
/// accepted `FdTable` API, and parks the set again before returning. No descriptor/OFD reference can
/// escape the borrow-scoped closure.
///
/// Descriptor generations are partitioned into disjoint residue classes while selected: view index
/// `i` uses origin `i + 1` and stride `VIEWS`. Thus a copied `FdToken` from another Process view can
/// never validate even when it names the same numeric fd. The ordinary single-process `FdTable`
/// remains origin/stride 1/1 and therefore preserves all accepted Step-29 generation values.
pub struct FdTableSet<const VIEWS: usize, const N: usize> {
    engine: FdTable<N>,
    views: [FdViewSlot<N>; VIEWS],
}

impl<const VIEWS: usize, const N: usize> FdTableSet<VIEWS, N> {
    pub const fn new() -> Self {
        Self {
            engine: FdTable::new(),
            views: [FdViewSlot::EMPTY; VIEWS],
        }
    }

    /// Allocates one empty process-local descriptor view.
    pub fn create_view(&mut self) -> Result<FdViewId, Error> {
        if VIEWS == 0 || u64::try_from(VIEWS).is_err() {
            return Err(Error::TableFull);
        }
        for (index, slot) in self.views.iter_mut().enumerate() {
            if slot.retired || slot.live {
                continue;
            }
            let generation = if slot.generation == 0 {
                1
            } else {
                slot.generation
            };
            slot.live = true;
            slot.generation = generation;
            return Ok(FdViewId { index, generation });
        }
        Err(Error::TableFull)
    }

    /// Executes an existing `FdTable` operation against exactly one live view.
    ///
    /// The descriptor array is returned to its generation-bound view before this method returns;
    /// only the canonical OFD pool remains in the engine. Nested selection is impossible because the
    /// closure holds the unique `&mut self` borrow through the selected `FdTable`.
    pub fn with_view<R>(
        &mut self,
        view: FdViewId,
        operation: impl FnOnce(&mut FdTable<N>) -> R,
    ) -> Result<R, Error> {
        let index = self.validate_view(view)?;
        let stride = u64::try_from(VIEWS).map_err(|_| Error::TableFull)?;
        if stride == 0 {
            return Err(Error::TableFull);
        }
        let origin = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::TableFull)?;
        if origin > stride
            || self
                .engine
                .descriptors
                .iter()
                .any(|slot| slot.retired || slot.state.is_some() || slot.generation != 0)
        {
            return Err(Error::StaleOpenFile);
        }

        core::mem::swap(
            &mut self.engine.descriptors,
            &mut self.views[index].descriptors,
        );
        let previous_origin = self.engine.descriptor_generation_origin;
        let previous_stride = self.engine.descriptor_generation_stride;
        self.engine.descriptor_generation_origin = origin;
        self.engine.descriptor_generation_stride = stride;

        let result = operation(&mut self.engine);

        self.engine.descriptor_generation_origin = previous_origin;
        self.engine.descriptor_generation_stride = previous_stride;
        core::mem::swap(
            &mut self.engine.descriptors,
            &mut self.views[index].descriptors,
        );
        Ok(result)
    }

    /// Transactionally creates a child descriptor view sharing the parent's exact OFDs.
    ///
    /// Every live parent descriptor increments the referenced canonical OFD exactly once. All
    /// descriptor generations and all OFD refcount additions are preflighted before the first
    /// mutation. A failure therefore leaves both the parent view and shared refcounts unchanged.
    pub fn fork_view(&mut self, parent: FdViewId) -> Result<FdViewId, Error> {
        let parent_index = self.validate_view(parent)?;
        let child_index = self
            .views
            .iter()
            .enumerate()
            .find(|(index, slot)| *index != parent_index && !slot.retired && !slot.live)
            .map(|(index, _)| index)
            .ok_or(Error::TableFull)?;
        let stride = u64::try_from(VIEWS).map_err(|_| Error::TableFull)?;
        if stride == 0 {
            return Err(Error::TableFull);
        }
        let child_origin = u64::try_from(child_index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::TableFull)?;

        let parent_descriptors = self.views[parent_index].descriptors;
        let child_slot = self.views[child_index];
        let child_generation = if child_slot.generation == 0 {
            1
        } else {
            child_slot.generation
        };
        let mut child_descriptors = child_slot.descriptors;
        let mut selected_refs = [0usize; N];
        let mut selected_open_files = [None; N];

        for index in 0..N {
            let Some(state) = parent_descriptors[index].state else {
                continue;
            };
            if child_descriptors[index].retired || child_descriptors[index].state.is_some() {
                return Err(Error::TableFull);
            }
            let generation = next_descriptor_generation(
                child_descriptors[index].generation,
                child_origin,
                stride,
            )
            .ok_or(Error::TableFull)?;
            let open_file = state.open_file;
            self.engine.open_file_slot(open_file)?;
            let count = selected_refs
                .get_mut(open_file.index)
                .ok_or(Error::StaleOpenFile)?;
            *count = count.checked_add(1).ok_or(Error::ReferenceOverflow)?;
            let selected = selected_open_files
                .get_mut(open_file.index)
                .ok_or(Error::StaleOpenFile)?;
            match *selected {
                None => *selected = Some(open_file),
                Some(existing) if existing == open_file => {}
                Some(_) => return Err(Error::StaleOpenFile),
            }
            child_descriptors[index].generation = generation;
            child_descriptors[index].state = Some(state);
        }

        for index in 0..N {
            let count = selected_refs[index];
            if count == 0 {
                continue;
            }
            let open_file = selected_open_files[index].ok_or(Error::StaleOpenFile)?;
            self.engine
                .open_file_slot(open_file)?
                .refs
                .checked_add(count)
                .ok_or(Error::ReferenceOverflow)?;
        }

        // All fallible work ended above. Publish shared references first, then the child view.
        for index in 0..N {
            let count = selected_refs[index];
            if count == 0 {
                continue;
            }
            let open_file = selected_open_files[index].expect("preflight selected open file");
            let slot = self
                .engine
                .open_file_slot_mut(open_file)
                .expect("preflight retained open file");
            slot.refs += count;
        }
        self.views[child_index].generation = child_generation;
        self.views[child_index].live = true;
        self.views[child_index].descriptors = child_descriptors;
        Ok(FdViewId {
            index: child_index,
            generation: child_generation,
        })
    }

    /// Retires one exact Process descriptor view and returns final shared-object releases.
    ///
    /// The returned array is indexed by canonical OFD slot. Existing Pipe/VFS owners perform the
    /// actual external release after this infallible FD-owner commit. All live descriptors in the
    /// retiring view are removed together, global OFD references are decremented by their exact
    /// multiplicity, and the view generation advances before the slot can be reused.
    pub fn retire_view(&mut self, view: FdViewId) -> Result<[Option<ReleasedObject>; N], Error> {
        let index = self.validate_view(view)?;
        let descriptors = self.views[index].descriptors;
        let mut selected_refs = [0usize; N];
        let mut selected_open_files = [None; N];

        for descriptor in descriptors.iter().filter_map(|slot| slot.state) {
            let open_file = descriptor.open_file;
            self.engine.open_file_slot(open_file)?;
            let count = selected_refs
                .get_mut(open_file.index)
                .ok_or(Error::StaleOpenFile)?;
            *count = count.checked_add(1).ok_or(Error::ReferenceOverflow)?;
            let selected = selected_open_files
                .get_mut(open_file.index)
                .ok_or(Error::StaleOpenFile)?;
            match *selected {
                None => *selected = Some(open_file),
                Some(existing) if existing == open_file => {}
                Some(_) => return Err(Error::StaleOpenFile),
            }
        }

        let mut released = [None; N];
        for ofd_index in 0..N {
            let count = selected_refs[ofd_index];
            if count == 0 {
                continue;
            }
            let open_file = selected_open_files[ofd_index].ok_or(Error::StaleOpenFile)?;
            let slot = *self.engine.open_file_slot(open_file)?;
            if count > slot.refs {
                return Err(Error::StaleOpenFile);
            }
            if count == slot.refs {
                released[ofd_index] =
                    pipe::released_object(slot.state.ok_or(Error::StaleOpenFile)?.object);
            }
        }

        // The complete release set and every reference decrement are now proven.
        for ofd_index in 0..N {
            let count = selected_refs[ofd_index];
            if count == 0 {
                continue;
            }
            let open_file = selected_open_files[ofd_index].expect("preflight selected open file");
            let slot = self
                .engine
                .open_file_slot_mut(open_file)
                .expect("preflight retained open file");
            slot.refs -= count;
            if slot.refs == 0 {
                slot.state = None;
            }
        }
        for descriptor in &mut self.views[index].descriptors {
            descriptor.state = None;
        }
        let slot = &mut self.views[index];
        slot.live = false;
        match slot.generation.checked_add(1) {
            Some(next) => slot.generation = next,
            None => slot.retired = true,
        }
        Ok(released)
    }

    pub fn view_is_live(&self, view: FdViewId) -> bool {
        self.validate_view(view).is_ok()
    }

    fn validate_view(&self, view: FdViewId) -> Result<usize, Error> {
        let slot = self.views.get(view.index).ok_or(Error::BadFd)?;
        if slot.retired || !slot.live || slot.generation != view.generation {
            return Err(Error::BadFd);
        }
        Ok(view.index)
    }
}

impl<const VIEWS: usize, const N: usize> Default for FdTableSet<VIEWS, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_vfs::{EntryId, RootId};

    const ROOT: RootId = RootId::new(9);

    fn file(entry: u16, size: u64) -> ReadOnlyFile {
        ReadOnlyFile::new(ROOT, EntryId::from_index(entry), 0o100644, size)
    }

    #[test]
    fn fork_shares_ofd_but_not_descriptor_token_or_cloexec_authority() {
        let mut set = FdTableSet::<3, 8>::new();
        let parent = set.create_view().unwrap();
        let parent_token = set
            .with_view(parent, |fds| {
                fds.open_readonly_with_flags(file(1, 16), true, 0x800)
                    .unwrap()
            })
            .unwrap();
        let parent_ofd = set
            .with_view(parent, |fds| fds.open_file_id(parent_token.fd()).unwrap())
            .unwrap();

        let child = set.fork_view(parent).unwrap();
        let child_token = set
            .with_view(child, |fds| fds.token(parent_token.fd()).unwrap())
            .unwrap();
        assert_ne!(child_token.generation(), parent_token.generation());
        assert!(
            !set.with_view(child, |fds| fds.token_is_live(parent_token))
                .unwrap()
        );
        assert_eq!(
            set.with_view(child, |fds| fds.open_file_id(child_token.fd()).unwrap())
                .unwrap(),
            parent_ofd
        );
        set.with_view(child, |fds| {
            fds.set_close_on_exec(child_token.fd(), false).unwrap();
            assert_eq!(fds.seek(child_token.fd(), 7, SeekWhence::Set), Ok(7));
        })
        .unwrap();
        assert_eq!(
            set.with_view(parent, |fds| fds.offset(parent_token.fd()))
                .unwrap(),
            Ok(7)
        );
        assert_eq!(
            set.with_view(parent, |fds| fds.close_on_exec(parent_token.fd()))
                .unwrap(),
            Ok(true)
        );
        assert_eq!(
            set.with_view(child, |fds| fds.close_on_exec(child_token.fd()))
                .unwrap(),
            Ok(false)
        );
    }

    #[test]
    fn child_close_keeps_parent_ofd_live_and_retire_invalidates_view_generation() {
        let mut set = FdTableSet::<2, 6>::new();
        let parent = set.create_view().unwrap();
        let parent_token = set
            .with_view(parent, |fds| fds.open_readonly(file(2, 4)).unwrap())
            .unwrap();
        let child = set.fork_view(parent).unwrap();
        set.with_view(child, |fds| fds.close(parent_token.fd()).unwrap())
            .unwrap();
        assert!(
            set.with_view(parent, |fds| fds.token_is_live(parent_token))
                .unwrap()
        );
        assert_eq!(set.retire_view(child).unwrap(), [None; 6]);
        assert!(!set.view_is_live(child));
        let reused = set.create_view().unwrap();
        assert_eq!(reused.index(), child.index());
        assert_ne!(reused.generation(), child.generation());
    }

    #[test]
    fn failed_fork_preflight_leaves_parent_and_refs_unchanged() {
        let mut set = FdTableSet::<2, 5>::new();
        let parent = set.create_view().unwrap();
        let token = set
            .with_view(parent, |fds| fds.open_readonly(file(3, 3)).unwrap())
            .unwrap();
        let child = set.fork_view(parent).unwrap();
        assert_eq!(set.fork_view(parent), Err(Error::TableFull));
        assert!(
            set.with_view(parent, |fds| fds.token_is_live(token))
                .unwrap()
        );
        set.with_view(child, |fds| fds.close(token.fd()).unwrap())
            .unwrap();
        assert!(
            set.with_view(parent, |fds| fds.token_is_live(token))
                .unwrap()
        );
    }
}
