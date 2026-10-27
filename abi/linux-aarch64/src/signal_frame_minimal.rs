// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use crate::{
    AARCH64_CONTEXT_TERMINATOR_BYTES, Aarch64FpsimdContext, Aarch64RtSignalFramePrefix,
    FPSIMD_CONTEXT_BYTES, FPSIMD_CONTEXT_OFFSET, MINIMAL_CONTEXT_END,
    MINIMAL_CONTEXT_TERMINATOR_OFFSET, RT_SIGFRAME_BYTES, RT_SIGFRAME_FIXED_PREFIX_BYTES,
    SignalFrameError, encode_context_terminator,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimalSignalFrameError {
    Frame(SignalFrameError),
    InvalidTerminator,
    UnsupportedContextData,
}

impl From<SignalFrameError> for MinimalSignalFrameError {
    fn from(value: SignalFrameError) -> Self {
        Self::Frame(value)
    }
}

/// Complete Linux/AArch64 signal-frame subset currently supported by Kernal.
///
/// The fixed integer/ucontext prefix is followed by exactly one FPSIMD record, one zero context
/// terminator and otherwise-zero reserved bytes. This deliberately excludes SVE/SME/GCS/ZA/ZT and
/// every future `_aarch64_ctx` extension until Kernal owns matching generation state for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimalAarch64RtSignalFrame {
    prefix: Aarch64RtSignalFramePrefix,
    fpsimd: Aarch64FpsimdContext,
}

impl MinimalAarch64RtSignalFrame {
    pub const fn new(prefix: Aarch64RtSignalFramePrefix, fpsimd: Aarch64FpsimdContext) -> Self {
        Self { prefix, fpsimd }
    }

    pub const fn prefix(self) -> Aarch64RtSignalFramePrefix {
        self.prefix
    }

    pub const fn fpsimd(self) -> Aarch64FpsimdContext {
        self.fpsimd
    }

    /// Encodes a complete deterministic 4688-byte minimal frame.
    ///
    /// The full frame is zeroed before encoding. This guarantees that the unused part of Linux'
    /// 4096-byte extension area cannot expose stale kernel/user bytes and makes unsupported extension
    /// state explicit rather than accidentally inheriting memory contents from the signal stack.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), MinimalSignalFrameError> {
        let frame = output
            .get_mut(..RT_SIGFRAME_BYTES)
            .ok_or(SignalFrameError::BufferTooSmall)?;
        frame.fill(0);
        self.prefix
            .encode_into(&mut frame[..RT_SIGFRAME_FIXED_PREFIX_BYTES])?;
        self.fpsimd.encode_into(
            &mut frame[FPSIMD_CONTEXT_OFFSET..FPSIMD_CONTEXT_OFFSET + FPSIMD_CONTEXT_BYTES],
        )?;
        encode_context_terminator(
            &mut frame[MINIMAL_CONTEXT_TERMINATOR_OFFSET
                ..MINIMAL_CONTEXT_TERMINATOR_OFFSET + AARCH64_CONTEXT_TERMINATOR_BYTES],
        )?;
        Ok(())
    }

    /// Parses the exact minimal profile accepted by the current Kernal runtime.
    ///
    /// This function is intentionally stricter than a general Linux extension walker. Any non-zero
    /// bytes after the required FPSIMD terminator indicate an architectural extension that Kernal
    /// does not own yet and therefore fail closed. Callers must still validate PC/SP/PSTATE and
    /// Process mappings through their existing architecture/AddressSpace owners before restoring.
    pub fn decode_from(input: &[u8]) -> Result<Self, MinimalSignalFrameError> {
        let frame = input
            .get(..RT_SIGFRAME_BYTES)
            .ok_or(SignalFrameError::BufferTooSmall)?;
        let prefix =
            Aarch64RtSignalFramePrefix::decode_from(&frame[..RT_SIGFRAME_FIXED_PREFIX_BYTES])?;
        let fpsimd = Aarch64FpsimdContext::decode_from(
            &frame[FPSIMD_CONTEXT_OFFSET..FPSIMD_CONTEXT_OFFSET + FPSIMD_CONTEXT_BYTES],
        )?;

        let terminator = &frame[MINIMAL_CONTEXT_TERMINATOR_OFFSET
            ..MINIMAL_CONTEXT_TERMINATOR_OFFSET + AARCH64_CONTEXT_TERMINATOR_BYTES];
        if terminator.iter().any(|byte| *byte != 0) {
            return Err(MinimalSignalFrameError::InvalidTerminator);
        }
        if frame[MINIMAL_CONTEXT_END..].iter().any(|byte| *byte != 0) {
            return Err(MinimalSignalFrameError::UnsupportedContextData);
        }

        Ok(Self::new(prefix, fpsimd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Aarch64SignalIntegerContext, Aarch64SignalStack, RT_SIGFRAME_SIGINFO_BYTES};

    fn fixture() -> MinimalAarch64RtSignalFrame {
        let registers = core::array::from_fn(|index| 0x1000 + index as u64);
        let prefix = Aarch64RtSignalFramePrefix::new(
            [0x5au8; RT_SIGFRAME_SIGINFO_BYTES],
            0,
            0,
            Aarch64SignalStack::new(0, 2, 0),
            0x1234_5678,
            Aarch64SignalIntegerContext::new(0, registers, 0x7000_0000, 0x4000_1000, 0x9000_0000),
        );
        let vregs = core::array::from_fn(|index| (index as u8).wrapping_mul(7));
        MinimalAarch64RtSignalFrame::new(
            prefix,
            Aarch64FpsimdContext::new(0x1122_3344, 0x5566_7788, vregs),
        )
    }

    #[test]
    fn minimal_full_frame_roundtrips_exact_supported_state() {
        let expected = fixture();
        let mut bytes = [0xa5u8; RT_SIGFRAME_BYTES];
        expected.encode_into(&mut bytes).unwrap();
        assert_eq!(
            MinimalAarch64RtSignalFrame::decode_from(&bytes),
            Ok(expected)
        );
        assert!(bytes[MINIMAL_CONTEXT_END..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn malformed_fpsimd_header_fails_before_restore() {
        let expected = fixture();
        let mut bytes = [0u8; RT_SIGFRAME_BYTES];
        expected.encode_into(&mut bytes).unwrap();
        bytes[FPSIMD_CONTEXT_OFFSET] ^= 1;
        assert_eq!(
            MinimalAarch64RtSignalFrame::decode_from(&bytes),
            Err(MinimalSignalFrameError::Frame(
                SignalFrameError::InvalidFpsimdHeader
            ))
        );
    }

    #[test]
    fn nonzero_terminator_is_rejected() {
        let expected = fixture();
        let mut bytes = [0u8; RT_SIGFRAME_BYTES];
        expected.encode_into(&mut bytes).unwrap();
        bytes[MINIMAL_CONTEXT_TERMINATOR_OFFSET] = 1;
        assert_eq!(
            MinimalAarch64RtSignalFrame::decode_from(&bytes),
            Err(MinimalSignalFrameError::InvalidTerminator)
        );
    }

    #[test]
    fn unsupported_extension_bytes_are_rejected() {
        let expected = fixture();
        let mut bytes = [0u8; RT_SIGFRAME_BYTES];
        expected.encode_into(&mut bytes).unwrap();
        bytes[MINIMAL_CONTEXT_END] = 1;
        assert_eq!(
            MinimalAarch64RtSignalFrame::decode_from(&bytes),
            Err(MinimalSignalFrameError::UnsupportedContextData)
        );
    }

    #[test]
    fn short_frame_is_rejected_without_partial_decode() {
        let bytes = [0u8; RT_SIGFRAME_BYTES - 1];
        assert_eq!(
            MinimalAarch64RtSignalFrame::decode_from(&bytes),
            Err(MinimalSignalFrameError::Frame(
                SignalFrameError::BufferTooSmall
            ))
        );
    }
}
