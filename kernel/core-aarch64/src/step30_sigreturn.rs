// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_context_aarch64::El0FpsimdState;
use kernal_exceptions_aarch64::ExceptionFrame;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_aarch64_abi::{MinimalAarch64RtSignalFrame, RT_SIGFRAME_BYTES};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_linux_signal::{MaskHow, SignalSet};
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use kernal_user_entry_aarch64::El0ReturnState;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const SS_DISABLE: i32 = 2;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const SIGSEGV: u8 = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestoreError {
    /// The userspace rt-signal frame, pointer, return PC/SP or mapping shape is invalid.
    BadFrame,
    /// Kernel ownership, PAN/usercopy infrastructure or canonical runtime state is inconsistent.
    Invariant,
}

fn classify_usercopy_error(error: kernal_usercopy::Error) -> RestoreError {
    match error {
        kernal_usercopy::Error::NullGuard
        | kernal_usercopy::Error::OutsideUserRange
        | kernal_usercopy::Error::Overflow
        | kernal_usercopy::Error::TooLarge
        | kernal_usercopy::Error::Fault => RestoreError::BadFrame,
        kernal_usercopy::Error::PanUnavailable
        | kernal_usercopy::Error::PanStateLeak
        | kernal_usercopy::Error::FaultHandlerUnavailable => RestoreError::Invariant,
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn terminate_bad_sigreturn() -> ! {
    if let Some(serial) = super::step15_svc_serial() {
        serial.write_str("KERNAL/ARM64: Step 30 rt_sigreturn bad frame -> SIGSEGV\n");
    }

    // Linux treats an invalid rt_sigreturn frame as a forced SIGSEGV of the current task. Reuse the
    // existing exact-generation signal-exit owner so the malformed userspace frame cannot fall
    // through to the primary kernel exception handler or return to EL0. Signal 11 has the ordinary
    // core-dumping default action, so the eventual parent wait status remains truthful.
    super::exit::handle_fatal_signal(SIGSEGV, true)
}

/// Restores the exact minimal AArch64 signal frame emitted by `step30_signal_delivery`.
///
/// All usercopy, frame parsing, architectural shape checks and canonical VMA permission checks happen
/// before the sole SignalTable mutation. Malformed userspace state is distinguished from kernel
/// ownership/infrastructure failure: bad frames terminate the exact current Linux generation through
/// the canonical signal lifecycle as SIGSEGV, while true kernel invariants remain `Err(())` for the
/// outer fail-closed handler. After the mask commit, the only remaining operations are the infallible
/// architecture FP/SIMD restore and writes to the already-owned exception frame.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(super) fn restore(frame: &mut ExceptionFrame) -> Result<(), ()> {
    match restore_checked(frame) {
        Ok(()) => Ok(()),
        Err(RestoreError::BadFrame) => terminate_bad_sigreturn(),
        Err(RestoreError::Invariant) => Err(()),
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn restore_checked(frame: &mut ExceptionFrame) -> Result<(), RestoreError> {
    let cpu = super::super::current_cpu_index();
    let scheduler = super::super::CPU_SCHEDULERS
        .get(cpu)
        .ok_or(RestoreError::Invariant)?;
    // SAFETY: rt_sigreturn is a synchronous lower-EL SVC on the exact current owner PE.
    let current = unsafe { scheduler.bootstrap_current_global_thread() }
        .map_err(|_| RestoreError::Invariant)?;
    if usize::from(current.cpu.0) != cpu {
        return Err(RestoreError::Invariant);
    }
    let entry_switch_generation = frame.entry_switch_generation();

    let mut bytes = [0u8; RT_SIGFRAME_BYTES];
    kernal_usercopy_aarch64::copy_from_user(&mut bytes, frame.sp_el0)
        .map_err(classify_usercopy_error)?;
    let minimal =
        MinimalAarch64RtSignalFrame::decode_from(&bytes).map_err(|_| RestoreError::BadFrame)?;
    let prefix = minimal.prefix();
    let stack = prefix.stack();
    // Step-30 has no sigaltstack owner yet. Accept exactly the frame profile emitted by the paired
    // delivery owner rather than treating arbitrary ucontext stack metadata as restored authority.
    if prefix.uc_flags() != 0
        || prefix.uc_link() != 0
        || stack.sp() != 0
        || stack.flags() != SS_DISABLE
        || stack.size() != 0
    {
        return Err(RestoreError::BadFrame);
    }

    let integer = prefix.integer();
    let return_state = El0ReturnState::new(integer.pc(), integer.pstate(), integer.sp())
        .map_err(|_| RestoreError::BadFrame)?;
    let fpsimd = minimal.fpsimd();
    let fpsimd_state = El0FpsimdState::new(*fpsimd.vregs(), fpsimd.fpcr(), fpsimd.fpsr());
    let restored_mask = SignalSet::from_bits(prefix.signal_mask());
    let stack_probe = return_state
        .user_sp()
        .checked_sub(1)
        .ok_or(RestoreError::BadFrame)?;

    // Revalidate the exact Process/AddressSpace generation immediately before the only mutable owner
    // edge. Scalar PC/SP values are observations only and must be covered by the canonical VMA table.
    let committed = super::runtime::with_linux_runtime(|state| {
        state.with_current_signal_delivery(
            current,
            entry_switch_generation,
            |process, address_space, objects, identities, signals| {
                let mut pc_executable = false;
                let mut sp_writable = false;
                for index in 0..super::runtime::STEP15_RUNTIME_VMAS {
                    let Some(vma) = address_space
                        .user_vma_at(process, objects, process.address_space_handle(), index)
                        .map_err(|_| RestoreError::Invariant)?
                    else {
                        break;
                    };
                    let end = vma.end().ok_or(RestoreError::Invariant)?;
                    if vma.start <= return_state.return_pc() && return_state.return_pc() < end {
                        pc_executable = vma.perms.executable();
                    }
                    if vma.start <= stack_probe && stack_probe < end {
                        sp_writable = vma.perms.writable();
                    }
                }
                if !pc_executable || !sp_writable {
                    return Err(RestoreError::BadFrame);
                }
                signals
                    .update_thread_mask(identities, process, current, MaskHow::Set, restored_mask)
                    .map_err(|_| RestoreError::Invariant)?;
                Ok::<(), RestoreError>(())
            },
        )
    })
    .map_err(|_| RestoreError::Invariant)?
    .map_err(|_| RestoreError::Invariant)?;
    committed?;

    // No fallible operation may follow the SignalTable commit. The decoded FP/SIMD image and return
    // state are already fully copied/validated, so committing architecture/frame state is one-way.
    // SAFETY: current exact EL0 generation still owns the live FP/SIMD registers on this PE.
    unsafe { kernal_context_aarch64::restore_current_el0_fpsimd(&fpsimd_state) };
    frame.x = *integer.registers();
    frame.sp_el0 = return_state.user_sp();
    frame.elr_el1 = return_state.return_pc();
    frame.spsr_el1 = return_state.spsr_el1();
    Ok(())
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub(super) fn restore(_frame: &mut ExceptionFrame) -> Result<(), ()> {
    Err(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    const RUNTIME: &str = include_str!("step30_runtime.rs");
    const RESTORE: &str = include_str!("step30_sigreturn.rs");

    #[test]
    fn rt_sigreturn_is_an_explicit_frame_commit() {
        assert!(RUNTIME.contains("Step30RuntimeCall::RtSigreturn"));
        assert!(RUNTIME.contains("sigreturn::restore(frame)?"));
        assert!(RUNTIME.contains("Ok(Outcome::FrameCommitted)"));
    }

    #[test]
    fn restore_is_copy_validate_mask_commit_then_architecture_apply() {
        let copy = RESTORE.find("copy_from_user").unwrap();
        let decode = RESTORE
            .find("MinimalAarch64RtSignalFrame::decode_from")
            .unwrap();
        let state = RESTORE.find("El0ReturnState::new").unwrap();
        let vma = RESTORE.find("user_vma_at").unwrap();
        let mask = RESTORE.find("update_thread_mask").unwrap();
        let fpsimd = RESTORE.find("restore_current_el0_fpsimd").unwrap();
        let frame = RESTORE.find("frame.x = *integer.registers()").unwrap();
        assert!(copy < decode && decode < state && state < vma && vma < mask);
        assert!(mask < fpsimd && fpsimd < frame);
    }

    #[test]
    fn restore_rejects_unowned_mapping_shapes() {
        assert!(RESTORE.contains("vma.perms.executable()"));
        assert!(RESTORE.contains("vma.perms.writable()"));
        assert!(RESTORE.contains("stack.flags() != SS_DISABLE"));
        assert!(RESTORE.contains("entry_switch_generation"));
    }

    #[test]
    fn bad_user_frames_terminate_via_truthful_sigsegv_lifecycle() {
        let classify = RESTORE
            .find("Err(RestoreError::BadFrame) => terminate_bad_sigreturn()")
            .expect("bad frame must not escape as a generic kernel invariant");
        let terminate = RESTORE
            .find("fn terminate_bad_sigreturn() -> !")
            .expect("bad frame needs a non-returning forced-signal path");
        let signal_exit = RESTORE
            .find("handle_fatal_signal(SIGSEGV, true)")
            .expect("bad frame must use the exact signaled exit lifecycle");
        assert!(terminate < signal_exit);
        assert!(classify > signal_exit || classify < terminate);
        assert!(RESTORE.contains("rt_sigreturn bad frame -> SIGSEGV"));
    }

    #[test]
    fn usercopy_faults_are_bad_frames_but_pan_failures_remain_kernel_invariants() {
        for error in [
            kernal_usercopy::Error::NullGuard,
            kernal_usercopy::Error::OutsideUserRange,
            kernal_usercopy::Error::Overflow,
            kernal_usercopy::Error::TooLarge,
            kernal_usercopy::Error::Fault,
        ] {
            assert_eq!(classify_usercopy_error(error), RestoreError::BadFrame);
        }
        for error in [
            kernal_usercopy::Error::PanUnavailable,
            kernal_usercopy::Error::PanStateLeak,
            kernal_usercopy::Error::FaultHandlerUnavailable,
        ] {
            assert_eq!(classify_usercopy_error(error), RestoreError::Invariant);
        }
    }
}
