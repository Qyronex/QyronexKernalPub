// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

mod active_process;
pub use active_process::ActiveProcessHandle;

use kernal_exceptions_aarch64::{ExceptionFrame, LowerElAarch64Synchronous};
use kernal_linux_aarch64_abi::{
    decode_registers as decode_linux_registers, write_result as write_linux_result,
};
use kernal_linux_abi::{SyscallRequest, SyscallReturn};
use kernal_native_abi::{MAX_SYSCALL_ARGS, SyscallFrame};
use kernal_process::Personality;
use kernal_process_aarch64::{ActiveProcess, Error as ActiveProcessError};
use kernal_user_entry_aarch64::{El0ReturnState, ReturnStateError};

/// The initial native AArch64 ABI uses `svc #0`; the syscall number is carried in x8.
pub const NATIVE_SVC_IMMEDIATE: u16 = 0;
/// Linux arm64 also uses `svc #0`; process personality, not the immediate, selects the ABI.
pub const LINUX_SVC_IMMEDIATE: u16 = 0;
pub const SYSCALL_NUMBER_REGISTER: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NotNativeSupervisorCall,
    NotLinuxSupervisorCall,
    SyscallNumberTooLarge,
    InactiveProcess,
    NotCurrentProcess,
    PersonalityMismatch,
    InvalidReturnState(ReturnStateError),
}

/// ABI-decoded request selected exclusively from the process that trapped this exact frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedProcessSyscall {
    Native(SyscallFrame),
    Linux(SyscallRequest),
}

/// Decodes one lower-EL syscall according to the process/address-space pair that trapped this frame.
///
/// Both Native and Linux use `svc #0`; neither the immediate nor x8 may select policy. Callers must
/// supply the opaque [`ActiveProcess`] witness produced by the process/address-space owner. The
/// accepted exception frame also carries the canonical TTBR0 switch generation sampled before any
/// lower-EL Rust handler ran. A process switch after trap entry therefore makes an old frame fail
/// closed even if a new Linux process is current when decode is attempted.
pub fn decode_process_syscall<const CAPS: usize, const VMAS: usize>(
    current: &ActiveProcess<'_, CAPS, VMAS>,
    frame: &ExceptionFrame,
) -> Result<DecodedProcessSyscall, Error> {
    let personality = current_personality(current, frame.entry_switch_generation())?;
    decode_process_syscall_parts(personality, frame.lower_el_aarch64_synchronous(), &frame.x)
}

fn decode_process_syscall_parts(
    personality: Personality,
    synchronous: Option<LowerElAarch64Synchronous>,
    registers: &[u64; 31],
) -> Result<DecodedProcessSyscall, Error> {
    match personality {
        Personality::Native => {
            decode_native_syscall_parts(synchronous, registers).map(DecodedProcessSyscall::Native)
        }
        Personality::Linux => {
            decode_linux_syscall_parts(synchronous, registers).map(DecodedProcessSyscall::Linux)
        }
    }
}

/// Decodes the architecture-neutral native syscall request from an AArch64 lower-EL SVC frame.
///
/// Register convention for the first native AArch64 boundary:
/// - x8: native syscall number;
/// - x0..x5: six register arguments;
/// - `svc #0`: native Kernal entry instruction.
///
/// The saved `ELR_EL1` is already the architectural continuation address after SVC. This adapter
/// therefore never increments it. Return-state policy remains owned by `kernal-user-entry-aarch64`.
pub fn decode_native_syscall(frame: &ExceptionFrame) -> Result<SyscallFrame, Error> {
    decode_native_syscall_parts(frame.lower_el_aarch64_synchronous(), &frame.x)
}

fn decode_native_syscall_parts(
    synchronous: Option<LowerElAarch64Synchronous>,
    registers: &[u64; 31],
) -> Result<SyscallFrame, Error> {
    match synchronous {
        Some(LowerElAarch64Synchronous::SupervisorCall { immediate })
            if immediate == NATIVE_SVC_IMMEDIATE => {}
        _ => return Err(Error::NotNativeSupervisorCall),
    }

    let number = u32::try_from(registers[SYSCALL_NUMBER_REGISTER])
        .map_err(|_| Error::SyscallNumberTooLarge)?;
    let mut args = [0; MAX_SYSCALL_ARGS];
    args.copy_from_slice(&registers[..MAX_SYSCALL_ARGS]);
    Ok(SyscallFrame::new(number, args))
}

fn decode_linux_syscall_parts(
    synchronous: Option<LowerElAarch64Synchronous>,
    registers: &[u64; 31],
) -> Result<SyscallRequest, Error> {
    match synchronous {
        Some(LowerElAarch64Synchronous::SupervisorCall { immediate })
            if immediate == LINUX_SVC_IMMEDIATE => {}
        _ => return Err(Error::NotLinuxSupervisorCall),
    }

    Ok(decode_linux_registers(registers))
}

/// Validates the architectural state that a native syscall handler intends to restore with `eret`.
///
/// The actual policy is centralized in [`El0ReturnState`]. This adapter must not grow a parallel
/// user-range, alignment or SPSR policy.
pub fn validate_native_return(frame: &ExceptionFrame) -> Result<El0ReturnState, Error> {
    validate_return_parts(frame.elr_el1, frame.spsr_el1, frame.sp_el0)
}

/// Validates Linux return state only for the exact live Linux process that trapped this frame.
pub fn validate_linux_return<const CAPS: usize, const VMAS: usize>(
    current: &ActiveProcess<'_, CAPS, VMAS>,
    frame: &ExceptionFrame,
) -> Result<El0ReturnState, Error> {
    let personality = current_personality(current, frame.entry_switch_generation())?;
    validate_linux_return_parts(personality, frame.elr_el1, frame.spsr_el1, frame.sp_el0)
}

fn validate_linux_return_parts(
    personality: Personality,
    return_pc: u64,
    spsr_el1: u64,
    user_sp: u64,
) -> Result<El0ReturnState, Error> {
    ensure_linux_personality(personality)?;
    validate_return_parts(return_pc, spsr_el1, user_sp)
}

fn validate_return_parts(
    return_pc: u64,
    spsr_el1: u64,
    user_sp: u64,
) -> Result<El0ReturnState, Error> {
    El0ReturnState::new(return_pc, spsr_el1, user_sp).map_err(Error::InvalidReturnState)
}

fn current_personality<const CAPS: usize, const VMAS: usize>(
    current: &ActiveProcess<'_, CAPS, VMAS>,
    entry_switch_generation: u64,
) -> Result<Personality, Error> {
    match current.personality_at_switch_generation(entry_switch_generation) {
        Ok(personality) => Ok(personality),
        Err(ActiveProcessError::InactiveProcess) => Err(Error::InactiveProcess),
        Err(_) => Err(Error::NotCurrentProcess),
    }
}

fn ensure_linux_personality(personality: Personality) -> Result<(), Error> {
    match personality {
        Personality::Linux => Ok(()),
        Personality::Native => Err(Error::PersonalityMismatch),
    }
}

/// Rewrites the mutable exception frame from one already-validated return-state object.
///
/// Call this only after the native syscall implementation has finished mutating result registers
/// and any allowed return state. On error the frame is left unchanged.
pub fn apply_native_return(frame: &mut ExceptionFrame) -> Result<(), Error> {
    let state = validate_native_return(frame)?;
    frame.elr_el1 = state.return_pc();
    frame.spsr_el1 = state.spsr_el1();
    frame.sp_el0 = state.user_sp();
    Ok(())
}

/// Writes a common Linux result only for the exact live Linux process that trapped this frame.
///
/// Frame-generation, current-process, personality and return-state validation all happen before x0
/// is changed. A retained frame from an older process generation, stale witness, raw TTBR0 switch,
/// Native personality, inactive process or hostile PC/SP/PSTATE leaves the frame untouched.
pub fn apply_linux_return<const CAPS: usize, const VMAS: usize>(
    current: &ActiveProcess<'_, CAPS, VMAS>,
    frame: &mut ExceptionFrame,
    result: SyscallReturn,
) -> Result<(), Error> {
    let process_validation = current_personality(current, frame.entry_switch_generation());
    let return_pc = frame.elr_el1;
    let spsr_el1 = frame.spsr_el1;
    let user_sp = frame.sp_el0;
    let state = apply_linux_result_after_process_validation(
        process_validation,
        &mut frame.x,
        return_pc,
        spsr_el1,
        user_sp,
        result,
    )?;
    frame.elr_el1 = state.return_pc();
    frame.spsr_el1 = state.spsr_el1();
    frame.sp_el0 = state.user_sp();
    Ok(())
}

fn apply_linux_result_after_process_validation(
    process_validation: Result<Personality, Error>,
    registers: &mut [u64; 31],
    return_pc: u64,
    spsr_el1: u64,
    user_sp: u64,
    result: SyscallReturn,
) -> Result<El0ReturnState, Error> {
    let personality = process_validation?;
    apply_linux_result_parts(personality, registers, return_pc, spsr_el1, user_sp, result)
}

fn apply_linux_result_parts(
    personality: Personality,
    registers: &mut [u64; 31],
    return_pc: u64,
    spsr_el1: u64,
    user_sp: u64,
    result: SyscallReturn,
) -> Result<El0ReturnState, Error> {
    let state = validate_linux_return_parts(personality, return_pc, spsr_el1, user_sp)?;
    write_linux_result(registers, result);
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_linux_aarch64_abi::nr as linux_nr;
    use kernal_linux_abi::Errno;
    use kernal_native_abi::syscall;
    use kernal_user_entry_aarch64::{KERNEL_HALF_MIN, STACK_ALIGNMENT, USER_ENTRY_ALIGNMENT};

    const RETURN_PC: u64 = 0x0000_0000_0004_0000;
    const USER_SP: u64 = 0x0000_0000_0008_0000;

    fn native_registers() -> [u64; 31] {
        let mut registers = [0; 31];
        registers[SYSCALL_NUMBER_REGISTER] = syscall::ABI_QUERY as u64;
        for (index, argument) in registers[..MAX_SYSCALL_ARGS].iter_mut().enumerate() {
            *argument = 0x100 + index as u64;
        }
        registers
    }

    fn linux_registers(number: u64) -> [u64; 31] {
        let mut registers = [0; 31];
        registers[SYSCALL_NUMBER_REGISTER] = number;
        for (index, argument) in registers[..6].iter_mut().enumerate() {
            *argument = 0x200 + index as u64;
        }
        registers[19] = 0x1919;
        registers[20] = 0x2020;
        registers
    }

    fn svc_zero() -> Option<LowerElAarch64Synchronous> {
        Some(LowerElAarch64Synchronous::SupervisorCall { immediate: 0 })
    }

    #[test]
    fn svc_zero_decodes_native_number_and_six_arguments() {
        let registers = native_registers();
        let call = decode_native_syscall_parts(svc_zero(), &registers).unwrap();
        assert_eq!(call.number, syscall::ABI_QUERY);
        assert_eq!(call.args, [0x100, 0x101, 0x102, 0x103, 0x104, 0x105]);
        assert!(call.is_compatible());
    }

    #[test]
    fn linux_personality_selects_linux_request() {
        let registers = linux_registers(linux_nr::WRITE);
        let decoded =
            decode_process_syscall_parts(Personality::Linux, svc_zero(), &registers).unwrap();
        assert_eq!(
            decoded,
            DecodedProcessSyscall::Linux(SyscallRequest::new(
                linux_nr::WRITE,
                [0x200, 0x201, 0x202, 0x203, 0x204, 0x205],
            ))
        );
    }

    #[test]
    fn same_svc_and_x8_follow_personality_not_register_heuristics() {
        let number = u64::from(u32::MAX) + 1;
        let registers = linux_registers(number);

        assert_eq!(
            decode_process_syscall_parts(Personality::Native, svc_zero(), &registers),
            Err(Error::SyscallNumberTooLarge)
        );
        assert_eq!(
            decode_process_syscall_parts(Personality::Linux, svc_zero(), &registers),
            Ok(DecodedProcessSyscall::Linux(SyscallRequest::new(
                number,
                [0x200, 0x201, 0x202, 0x203, 0x204, 0x205],
            )))
        );
    }

    #[test]
    fn linux_decoder_preserves_unknown_full_width_number() {
        let request = decode_linux_syscall_parts(svc_zero(), &linux_registers(u64::MAX)).unwrap();
        assert_eq!(request.number, u64::MAX);
    }

    #[test]
    fn nonzero_svc_immediate_is_not_native_entry() {
        assert_eq!(
            decode_native_syscall_parts(
                Some(LowerElAarch64Synchronous::SupervisorCall { immediate: 7 }),
                &native_registers(),
            ),
            Err(Error::NotNativeSupervisorCall)
        );
    }

    #[test]
    fn nonzero_svc_immediate_is_not_linux_entry() {
        assert_eq!(
            decode_linux_syscall_parts(
                Some(LowerElAarch64Synchronous::SupervisorCall { immediate: 7 }),
                &linux_registers(linux_nr::READ),
            ),
            Err(Error::NotLinuxSupervisorCall)
        );
    }

    #[test]
    fn non_svc_lower_el_exception_is_not_native_entry() {
        assert_eq!(
            decode_native_syscall_parts(
                Some(LowerElAarch64Synchronous::Breakpoint { comment: 0 }),
                &native_registers(),
            ),
            Err(Error::NotNativeSupervisorCall)
        );
    }

    #[test]
    fn non_svc_lower_el_exception_is_not_linux_entry() {
        assert_eq!(
            decode_linux_syscall_parts(
                Some(LowerElAarch64Synchronous::Breakpoint { comment: 0 }),
                &linux_registers(linux_nr::READ),
            ),
            Err(Error::NotLinuxSupervisorCall)
        );
    }

    #[test]
    fn oversized_native_syscall_number_fails_closed() {
        let mut registers = native_registers();
        registers[SYSCALL_NUMBER_REGISTER] = u64::from(u32::MAX) + 1;
        assert_eq!(
            decode_native_syscall_parts(svc_zero(), &registers),
            Err(Error::SyscallNumberTooLarge)
        );
    }

    #[test]
    fn valid_return_keeps_architectural_svc_continuation_unchanged() {
        let state = validate_return_parts(RETURN_PC, 0xa000_0000, USER_SP).unwrap();
        assert_eq!(state.return_pc(), RETURN_PC);
        assert_eq!(state.user_sp(), USER_SP);
        assert_eq!(state.spsr_el1(), 0xa000_0000);
    }

    #[test]
    fn linux_result_writeback_preserves_non_result_registers() {
        let mut registers = linux_registers(linux_nr::WRITE);
        let before = registers;
        let result = SyscallReturn::error(Errno::ENOSYS);
        let state = apply_linux_result_parts(
            Personality::Linux,
            &mut registers,
            RETURN_PC,
            0xa000_0000,
            USER_SP,
            result,
        )
        .unwrap();

        assert_eq!(state.return_pc(), RETURN_PC);
        assert_eq!(registers[0], (-38_i64) as u64);
        assert_eq!(&registers[1..], &before[1..]);
    }

    #[test]
    fn stale_frame_process_validation_cannot_mutate_linux_result() {
        let mut registers = linux_registers(linux_nr::WRITE);
        let before = registers;

        assert_eq!(
            apply_linux_result_after_process_validation(
                Err(Error::NotCurrentProcess),
                &mut registers,
                RETURN_PC,
                0xa000_0000,
                USER_SP,
                SyscallReturn::error(Errno::ENOSYS),
            ),
            Err(Error::NotCurrentProcess)
        );
        assert_eq!(registers, before);
    }

    #[test]
    fn native_personality_cannot_apply_linux_result() {
        let mut registers = linux_registers(linux_nr::WRITE);
        let before = registers;

        assert_eq!(
            apply_linux_result_parts(
                Personality::Native,
                &mut registers,
                RETURN_PC,
                0xa000_0000,
                USER_SP,
                SyscallReturn::error(Errno::ENOSYS),
            ),
            Err(Error::PersonalityMismatch)
        );
        assert_eq!(registers, before);
    }

    #[test]
    fn invalid_linux_return_state_does_not_write_result() {
        let mut registers = linux_registers(linux_nr::WRITE);
        let before = registers;
        let result = SyscallReturn::error(Errno::ENOSYS);

        assert_eq!(
            apply_linux_result_parts(
                Personality::Linux,
                &mut registers,
                KERNEL_HALF_MIN,
                0,
                USER_SP,
                result,
            ),
            Err(Error::InvalidReturnState(
                ReturnStateError::ReturnPcOutsideUserRange
            ))
        );
        assert_eq!(registers, before);
    }

    #[test]
    fn invalid_pc_stack_and_pstate_are_delegated_to_shared_policy() {
        assert_eq!(
            validate_return_parts(KERNEL_HALF_MIN, 0, USER_SP),
            Err(Error::InvalidReturnState(
                ReturnStateError::ReturnPcOutsideUserRange
            ))
        );
        assert_eq!(
            validate_return_parts(RETURN_PC + USER_ENTRY_ALIGNMENT / 2, 0, USER_SP),
            Err(Error::InvalidReturnState(
                ReturnStateError::ReturnPcMisaligned
            ))
        );
        assert_eq!(
            validate_return_parts(RETURN_PC, 0, USER_SP + STACK_ALIGNMENT / 2),
            Err(Error::InvalidReturnState(
                ReturnStateError::UserStackMisaligned
            ))
        );
        assert_eq!(
            validate_return_parts(RETURN_PC, 0x5, USER_SP),
            Err(Error::InvalidReturnState(
                ReturnStateError::UnsupportedSpsrEl1
            ))
        );
    }
}
