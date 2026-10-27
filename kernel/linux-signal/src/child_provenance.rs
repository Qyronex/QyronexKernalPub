// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::num::NonZeroU32;

use crate::{SIGCONT, Signal};

/// Linux SIGCHLD child-status class retained in the canonical pending-signal receipt.
///
/// This is provenance metadata only. It carries no Process, credential, WaitTable or scheduler
/// authority and is deliberately independent of architecture-specific `siginfo_t` layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildSignalCode {
    Exited,
    Killed,
    Dumped,
    Stopped,
    Continued,
}

/// Immutable child-status observations required for truthful caught-SIGCHLD delivery.
///
/// The value is created while the exact child/parent relationship and final wait/job-control cause
/// are still owned by the runtime transaction, then travels only inside the existing canonical
/// PendingSignal record. Keeping the observation here prevents later owner transitions from
/// destroying the information before a parent handler consumes the pending SIGCHLD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildSignalProvenance {
    child_pid: NonZeroU32,
    child_uid: u32,
    code: ChildSignalCode,
    status: u8,
}

impl ChildSignalProvenance {
    pub const fn exited(child_pid: NonZeroU32, child_uid: u32, exit_status: u8) -> Self {
        Self {
            child_pid,
            child_uid,
            code: ChildSignalCode::Exited,
            status: exit_status,
        }
    }

    pub fn signaled(
        child_pid: NonZeroU32,
        child_uid: u32,
        termination_signal: u8,
        core_dumped: bool,
    ) -> Option<Self> {
        Signal::new(termination_signal)?;
        Some(Self {
            child_pid,
            child_uid,
            code: if core_dumped {
                ChildSignalCode::Dumped
            } else {
                ChildSignalCode::Killed
            },
            status: termination_signal,
        })
    }

    /// Retains one real scheduler-completed child stop for CLD_STOPPED delivery.
    pub fn stopped(child_pid: NonZeroU32, child_uid: u32, stop_signal: u8) -> Option<Self> {
        Signal::new(stop_signal)?;
        Some(Self {
            child_pid,
            child_uid,
            code: ChildSignalCode::Stopped,
            status: stop_signal,
        })
    }

    /// Retains one real scheduler-completed child continue for CLD_CONTINUED delivery.
    /// Linux exposes SIGCONT as si_status for this class.
    pub const fn continued(child_pid: NonZeroU32, child_uid: u32) -> Self {
        Self {
            child_pid,
            child_uid,
            code: ChildSignalCode::Continued,
            status: SIGCONT,
        }
    }

    pub const fn child_pid(self) -> NonZeroU32 {
        self.child_pid
    }

    pub const fn child_uid(self) -> u32 {
        self.child_uid
    }

    pub const fn code(self) -> ChildSignalCode {
        self.code
    }

    pub const fn status(self) -> u8 {
        self.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_exit_retains_exact_child_observations() {
        let pid = NonZeroU32::new(41).unwrap();
        let provenance = ChildSignalProvenance::exited(pid, 1000, 23);
        assert_eq!(provenance.child_pid(), pid);
        assert_eq!(provenance.child_uid(), 1000);
        assert_eq!(provenance.code(), ChildSignalCode::Exited);
        assert_eq!(provenance.status(), 23);
    }

    #[test]
    fn signaled_exit_validates_signal_and_retains_core_dump_class() {
        let pid = NonZeroU32::new(43).unwrap();
        let killed = ChildSignalProvenance::signaled(pid, 7, 15, false).unwrap();
        assert_eq!(killed.code(), ChildSignalCode::Killed);
        assert_eq!(killed.status(), 15);

        let dumped = ChildSignalProvenance::signaled(pid, 7, 11, true).unwrap();
        assert_eq!(dumped.code(), ChildSignalCode::Dumped);
        assert_eq!(dumped.status(), 11);

        assert_eq!(ChildSignalProvenance::signaled(pid, 7, 0, false), None);
        assert_eq!(ChildSignalProvenance::signaled(pid, 7, 65, false), None);
    }

    #[test]
    fn job_control_provenance_retains_linux_child_status_classes() {
        let pid = NonZeroU32::new(47).unwrap();
        let stopped = ChildSignalProvenance::stopped(pid, 1000, 19).unwrap();
        assert_eq!(stopped.child_pid(), pid);
        assert_eq!(stopped.child_uid(), 1000);
        assert_eq!(stopped.code(), ChildSignalCode::Stopped);
        assert_eq!(stopped.status(), 19);

        let continued = ChildSignalProvenance::continued(pid, 1000);
        assert_eq!(continued.child_pid(), pid);
        assert_eq!(continued.child_uid(), 1000);
        assert_eq!(continued.code(), ChildSignalCode::Continued);
        assert_eq!(continued.status(), SIGCONT);

        assert_eq!(ChildSignalProvenance::stopped(pid, 0, 0), None);
        assert_eq!(ChildSignalProvenance::stopped(pid, 0, 65), None);
    }
}
