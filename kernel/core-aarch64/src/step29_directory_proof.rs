// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use kernal_linux_vfs::NodeKind;

pub const ROOT_ENTRY_INDEX: usize = 0;
pub const BIN_ENTRY_INDEX: usize = 1;
pub const ETC_ENTRY_INDEX: usize = 2;
pub const USR_ENTRY_INDEX: usize = 3;
pub const PROOF_LINK_ENTRY_INDEX: usize = 9;
pub const EOF_CURSOR: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Idle = 0,
    Open = 1,
    Dot = 2,
    DotDot = 3,
    Bin = 4,
    Etc = 5,
    Usr = 6,
    ProofLink = 7,
    Eof = 8,
    Closed = 9,
    Failed = 10,
}

impl Phase {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Idle,
            1 => Self::Open,
            2 => Self::Dot,
            3 => Self::DotDot,
            4 => Self::Bin,
            5 => Self::Etc,
            6 => Self::Usr,
            7 => Self::ProofLink,
            8 => Self::Eof,
            9 => Self::Closed,
            10 => Self::Failed,
            _ => Self::Failed,
        }
    }

    pub const fn raw(self) -> u8 {
        self as u8
    }

    pub const fn accepts_token_events(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Dot
                | Self::DotDot
                | Self::Bin
                | Self::Etc
                | Self::Usr
                | Self::ProofLink
                | Self::Eof
        )
    }

    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Closed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryEvidence<'a> {
    pub entry_index: usize,
    pub name: &'a [u8],
    pub kind: NodeKind,
    pub start_cursor: usize,
    pub next_cursor: usize,
}

impl<'a> EntryEvidence<'a> {
    pub const fn new(
        entry_index: usize,
        name: &'a [u8],
        kind: NodeKind,
        start_cursor: usize,
        next_cursor: usize,
    ) -> Self {
        Self {
            entry_index,
            name,
            kind,
            start_cursor,
            next_cursor,
        }
    }
}

pub const fn expected_root_open(entry_index: usize, kind: NodeKind) -> bool {
    entry_index == ROOT_ENTRY_INDEX && matches!(kind, NodeKind::Directory)
}

pub const fn token_matches(
    expected_fd: i32,
    expected_generation: u64,
    actual_fd: i32,
    actual_generation: u64,
) -> bool {
    expected_fd == actual_fd && expected_generation == actual_generation
}

fn matches_entry(
    evidence: EntryEvidence<'_>,
    entry_index: usize,
    name: &[u8],
    kind: NodeKind,
    start_cursor: usize,
    next_cursor: usize,
) -> bool {
    evidence.entry_index == entry_index
        && evidence.name == name
        && evidence.kind == kind
        && evidence.start_cursor == start_cursor
        && evidence.next_cursor == next_cursor
}

/// Advances the deterministic directory-proof phase using one already copied and committed VFS
/// witness. Any unexpected committed record on the claimed proof descriptor permanently fails the
/// proof; a later replay therefore cannot hide a cursor/order regression.
pub fn transition_entry(phase: Phase, evidence: EntryEvidence<'_>) -> Phase {
    match phase {
        Phase::Open
            if matches_entry(evidence, ROOT_ENTRY_INDEX, b".", NodeKind::Directory, 0, 1) =>
        {
            Phase::Dot
        }
        Phase::Dot
            if matches_entry(evidence, ROOT_ENTRY_INDEX, b"..", NodeKind::Directory, 1, 2) =>
        {
            Phase::DotDot
        }
        Phase::DotDot
            if matches_entry(evidence, BIN_ENTRY_INDEX, b"bin", NodeKind::Directory, 2, 4) =>
        {
            Phase::Bin
        }
        Phase::Bin
            if matches_entry(evidence, ETC_ENTRY_INDEX, b"etc", NodeKind::Directory, 4, 5) =>
        {
            Phase::Etc
        }
        Phase::Etc
            if matches_entry(evidence, USR_ENTRY_INDEX, b"usr", NodeKind::Directory, 5, 6) =>
        {
            Phase::Usr
        }
        Phase::Usr
            if matches_entry(
                evidence,
                PROOF_LINK_ENTRY_INDEX,
                b"proof-link",
                NodeKind::Symlink,
                6,
                EOF_CURSOR,
            ) =>
        {
            Phase::ProofLink
        }
        Phase::Failed => Phase::Failed,
        _ => Phase::Failed,
    }
}

/// Records stable EOF for the exact deterministic root cursor. EOF is idempotent, but observing EOF
/// before the required committed sequence permanently fails the proof.
pub const fn transition_eof(phase: Phase, cursor: usize) -> Phase {
    match phase {
        Phase::ProofLink if cursor == EOF_CURSOR => Phase::Eof,
        Phase::Eof if cursor == EOF_CURSOR => Phase::Eof,
        Phase::Failed => Phase::Failed,
        _ => Phase::Failed,
    }
}

/// Only an EOF-complete proof may close successfully. Premature close is terminal failure.
pub const fn transition_close(phase: Phase) -> Phase {
    match phase {
        Phase::Eof => Phase::Closed,
        Phase::Closed => Phase::Closed,
        Phase::Failed => Phase::Failed,
        _ => Phase::Failed,
    }
}

/// Computes the userspace address for the next dirent record. `None` means the address would wrap;
/// callers with a committed prefix must return that positive prefix without committing another
/// record.
pub fn next_user_address(base: u64, copied: usize) -> Option<u64> {
    let offset = u64::try_from(copied).ok()?;
    base.checked_add(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dot() -> EntryEvidence<'static> {
        EntryEvidence::new(ROOT_ENTRY_INDEX, b".", NodeKind::Directory, 0, 1)
    }

    fn dotdot() -> EntryEvidence<'static> {
        EntryEvidence::new(ROOT_ENTRY_INDEX, b"..", NodeKind::Directory, 1, 2)
    }

    fn bin() -> EntryEvidence<'static> {
        EntryEvidence::new(BIN_ENTRY_INDEX, b"bin", NodeKind::Directory, 2, 4)
    }

    fn etc() -> EntryEvidence<'static> {
        EntryEvidence::new(ETC_ENTRY_INDEX, b"etc", NodeKind::Directory, 4, 5)
    }

    fn usr() -> EntryEvidence<'static> {
        EntryEvidence::new(USR_ENTRY_INDEX, b"usr", NodeKind::Directory, 5, 6)
    }

    fn proof_link() -> EntryEvidence<'static> {
        EntryEvidence::new(
            PROOF_LINK_ENTRY_INDEX,
            b"proof-link",
            NodeKind::Symlink,
            6,
            EOF_CURSOR,
        )
    }

    fn through_entries() -> Phase {
        let mut phase = Phase::Open;
        for evidence in [dot(), dotdot(), bin(), etc(), usr(), proof_link()] {
            phase = transition_entry(phase, evidence);
        }
        phase
    }

    #[test]
    fn phase_encoding_and_token_event_window_are_stable() {
        assert_eq!(Phase::from_raw(Phase::Idle.raw()), Phase::Idle);
        assert!(!Phase::Idle.accepts_token_events());

        for phase in [
            Phase::Open,
            Phase::Dot,
            Phase::DotDot,
            Phase::Bin,
            Phase::Etc,
            Phase::Usr,
            Phase::ProofLink,
            Phase::Eof,
        ] {
            assert_eq!(Phase::from_raw(phase.raw()), phase);
            assert!(phase.accepts_token_events());
        }

        for phase in [Phase::Closed, Phase::Failed] {
            assert_eq!(Phase::from_raw(phase.raw()), phase);
            assert!(!phase.accepts_token_events());
        }
        assert_eq!(Phase::from_raw(u8::MAX), Phase::Failed);
    }

    #[test]
    fn exact_root_sequence_requires_eof_then_close() {
        assert!(expected_root_open(ROOT_ENTRY_INDEX, NodeKind::Directory));
        let phase = through_entries();
        assert_eq!(phase, Phase::ProofLink);
        assert_eq!(transition_close(phase), Phase::Failed);
        let phase = transition_eof(phase, EOF_CURSOR);
        assert_eq!(phase, Phase::Eof);
        assert_eq!(transition_eof(phase, EOF_CURSOR), Phase::Eof);
        assert!(transition_close(phase).is_complete());
    }

    #[test]
    fn early_required_record_poison_cannot_recover() {
        let phase = transition_entry(Phase::Open, proof_link());
        assert_eq!(phase, Phase::Failed);
        assert_eq!(transition_entry(phase, dot()), Phase::Failed);
        assert_eq!(transition_eof(phase, EOF_CURSOR), Phase::Failed);
        assert_eq!(transition_close(phase), Phase::Failed);
    }

    #[test]
    fn duplicate_or_wrong_cursor_poison_is_terminal() {
        let phase = transition_entry(Phase::Open, dot());
        assert_eq!(phase, Phase::Dot);
        assert_eq!(transition_entry(phase, dot()), Phase::Failed);

        let wrong = EntryEvidence::new(ROOT_ENTRY_INDEX, b"..", NodeKind::Directory, 1, 3);
        assert_eq!(transition_entry(Phase::Dot, wrong), Phase::Failed);
    }

    #[test]
    fn eof_before_required_sequence_fails_and_close_cannot_recover() {
        let phase = transition_eof(Phase::Bin, EOF_CURSOR);
        assert_eq!(phase, Phase::Failed);
        assert_eq!(transition_close(phase), Phase::Failed);
    }

    #[test]
    fn token_identity_rejects_generation_or_fd_reuse() {
        assert!(token_matches(3, 7, 3, 7));
        assert!(!token_matches(3, 7, 3, 8));
        assert!(!token_matches(3, 7, 4, 7));
    }

    #[test]
    fn later_user_address_overflow_is_detectable_without_consuming_record() {
        assert_eq!(next_user_address(0x1000, 24), Some(0x1018));
        assert_eq!(next_user_address(u64::MAX, 0), Some(u64::MAX));
        assert_eq!(next_user_address(u64::MAX, 1), None);
    }
}
