// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const MAX_TRANSITION_PES: usize = 256;
const BITMAP_WORDS: usize = MAX_TRANSITION_PES / 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionStateError {
    InvalidExpectedPes,
    AlreadyConfigured,
    NotConfigured,
    PeOutOfRange,
    DuplicateArrival,
    WrongGlobalOwner,
    NotAllHigh,
    LowAliasesNotRemoved,
    LowAliasesAlreadyRemoved,
}

/// One-shot Step-6 SMP barrier for the shared low-to-high translation transition.
///
/// This does not replace the kernel's CPU lifecycle state. It owns only the temporary MMU handoff:
/// every expected PE must publish that PC/SP/runtime pointers are high, PE0 may then remove the
/// shared low leaves once, and only after that publication may each PE retire its local TTBR0 state.
pub struct TransitionCoordinator {
    expected_pes: AtomicU32,
    high: [AtomicU64; BITMAP_WORDS],
    low_aliases_removed: AtomicBool,
    protected: [AtomicU64; BITMAP_WORDS],
}

impl TransitionCoordinator {
    pub const fn new() -> Self {
        Self {
            expected_pes: AtomicU32::new(0),
            high: [const { AtomicU64::new(0) }; BITMAP_WORDS],
            low_aliases_removed: AtomicBool::new(false),
            protected: [const { AtomicU64::new(0) }; BITMAP_WORDS],
        }
    }

    /// Configures the one-shot barrier before any secondary PE is started.
    pub fn configure(&self, expected_pes: usize) -> Result<(), TransitionStateError> {
        if expected_pes == 0 || expected_pes > MAX_TRANSITION_PES {
            return Err(TransitionStateError::InvalidExpectedPes);
        }
        let expected = u32::try_from(expected_pes)
            .map_err(|_| TransitionStateError::InvalidExpectedPes)?;
        self.expected_pes
            .compare_exchange(0, expected, Ordering::Release, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| TransitionStateError::AlreadyConfigured)
    }

    pub fn mark_high(&self, pe_index: usize) -> Result<(), TransitionStateError> {
        let expected = self.expected_pes()?;
        mark_once(&self.high, pe_index, expected)
    }

    pub fn all_high(&self) -> Result<bool, TransitionStateError> {
        let expected = self.expected_pes()?;
        Ok(all_marked(&self.high, expected))
    }

    /// Publishes the single BSP-owned global page-table mutation/TLBI phase.
    pub fn publish_low_aliases_removed(
        &self,
        owner_pe_index: usize,
    ) -> Result<(), TransitionStateError> {
        if owner_pe_index != 0 {
            return Err(TransitionStateError::WrongGlobalOwner);
        }
        if !self.all_high()? {
            return Err(TransitionStateError::NotAllHigh);
        }
        self.low_aliases_removed
            .compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| TransitionStateError::LowAliasesAlreadyRemoved)
    }

    pub fn low_aliases_removed(&self) -> bool {
        self.low_aliases_removed.load(Ordering::Acquire)
    }

    /// Records that one PE has locally disabled/cleared TTBR0 after observing the BSP publication.
    pub fn mark_protected(&self, pe_index: usize) -> Result<(), TransitionStateError> {
        let expected = self.expected_pes()?;
        if !self.low_aliases_removed.load(Ordering::Acquire) {
            return Err(TransitionStateError::LowAliasesNotRemoved);
        }
        mark_once(&self.protected, pe_index, expected)
    }

    pub fn all_protected(&self) -> Result<bool, TransitionStateError> {
        let expected = self.expected_pes()?;
        Ok(self.low_aliases_removed.load(Ordering::Acquire)
            && all_marked(&self.protected, expected))
    }

    fn expected_pes(&self) -> Result<usize, TransitionStateError> {
        let expected = self.expected_pes.load(Ordering::Acquire);
        if expected == 0 {
            Err(TransitionStateError::NotConfigured)
        } else {
            Ok(expected as usize)
        }
    }
}

impl Default for TransitionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

fn mark_once(
    bitmap: &[AtomicU64; BITMAP_WORDS],
    pe_index: usize,
    expected: usize,
) -> Result<(), TransitionStateError> {
    if pe_index >= expected {
        return Err(TransitionStateError::PeOutOfRange);
    }
    let word = pe_index / 64;
    let mask = 1u64 << (pe_index % 64);
    let previous = bitmap[word].fetch_or(mask, Ordering::AcqRel);
    if previous & mask != 0 {
        Err(TransitionStateError::DuplicateArrival)
    } else {
        Ok(())
    }
}

fn all_marked(bitmap: &[AtomicU64; BITMAP_WORDS], expected: usize) -> bool {
    let full_words = expected / 64;
    for word in bitmap.iter().take(full_words) {
        if word.load(Ordering::Acquire) != u64::MAX {
            return false;
        }
    }

    let remainder = expected % 64;
    if remainder == 0 {
        return true;
    }
    let required = (1u64 << remainder) - 1;
    bitmap[full_words].load(Ordering::Acquire) & required == required
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_every_high_pe_before_bsp_global_phase() {
        let state = TransitionCoordinator::new();
        state.configure(4).unwrap();
        state.mark_high(2).unwrap();
        state.mark_high(0).unwrap();
        state.mark_high(3).unwrap();
        assert_eq!(
            state.publish_low_aliases_removed(0),
            Err(TransitionStateError::NotAllHigh)
        );
        state.mark_high(1).unwrap();
        assert!(state.all_high().unwrap());
        state.publish_low_aliases_removed(0).unwrap();
        assert!(state.low_aliases_removed());
    }

    #[test]
    fn only_bsp_can_publish_global_low_alias_removal() {
        let state = TransitionCoordinator::new();
        state.configure(2).unwrap();
        state.mark_high(0).unwrap();
        state.mark_high(1).unwrap();
        assert_eq!(
            state.publish_low_aliases_removed(1),
            Err(TransitionStateError::WrongGlobalOwner)
        );
        state.publish_low_aliases_removed(0).unwrap();
        assert_eq!(
            state.publish_low_aliases_removed(0),
            Err(TransitionStateError::LowAliasesAlreadyRemoved)
        );
    }

    #[test]
    fn protected_phase_cannot_race_ahead_of_global_tlbi() {
        let state = TransitionCoordinator::new();
        state.configure(2).unwrap();
        state.mark_high(0).unwrap();
        state.mark_high(1).unwrap();
        assert_eq!(
            state.mark_protected(1),
            Err(TransitionStateError::LowAliasesNotRemoved)
        );
        state.publish_low_aliases_removed(0).unwrap();
        state.mark_protected(1).unwrap();
        assert!(!state.all_protected().unwrap());
        state.mark_protected(0).unwrap();
        assert!(state.all_protected().unwrap());
    }

    #[test]
    fn duplicate_and_out_of_range_publication_fail_closed() {
        let state = TransitionCoordinator::new();
        state.configure(1).unwrap();
        state.mark_high(0).unwrap();
        assert_eq!(
            state.mark_high(0),
            Err(TransitionStateError::DuplicateArrival)
        );
        assert_eq!(
            state.mark_high(1),
            Err(TransitionStateError::PeOutOfRange)
        );
    }

    #[test]
    fn supports_full_256_pe_bitmap_without_shift_overflow() {
        let state = TransitionCoordinator::new();
        state.configure(MAX_TRANSITION_PES).unwrap();
        for pe in 0..MAX_TRANSITION_PES {
            state.mark_high(pe).unwrap();
        }
        assert!(state.all_high().unwrap());
        state.publish_low_aliases_removed(0).unwrap();
        for pe in 0..MAX_TRANSITION_PES {
            state.mark_protected(pe).unwrap();
        }
        assert!(state.all_protected().unwrap());
    }
}
