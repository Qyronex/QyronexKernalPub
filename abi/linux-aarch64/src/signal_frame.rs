// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

/// Linux/AArch64 aligns realtime signal frames and every `_aarch64_ctx` extension record to 16
/// bytes. These constants describe only the fixed UAPI layout; they grant no user-memory or register
/// restore authority.
pub const RT_SIGFRAME_ALIGNMENT: u64 = 16;
pub const RT_SIGFRAME_SIGINFO_OFFSET: usize = 0;
pub const RT_SIGFRAME_SIGINFO_BYTES: usize = 128;
pub const RT_SIGFRAME_UCONTEXT_OFFSET: usize = 128;

pub const UCONTEXT_FLAGS_OFFSET: usize = 0;
pub const UCONTEXT_LINK_OFFSET: usize = 8;
pub const UCONTEXT_STACK_OFFSET: usize = 16;
pub const UCONTEXT_STACK_BYTES: usize = 24;
pub const UCONTEXT_STACK_SP_OFFSET: usize = 16;
pub const UCONTEXT_STACK_FLAGS_OFFSET: usize = 24;
pub const UCONTEXT_STACK_SIZE_OFFSET: usize = 32;
pub const UCONTEXT_SIGMASK_OFFSET: usize = 40;
/// Linux arm64 reserves the glibc-compatible 1024-bit sigset_t footprint even though the kernel
/// signal mask currently occupies only the low 64-bit word.
pub const UCONTEXT_SIGMASK_AREA_BYTES: usize = 128;
pub const UCONTEXT_MCONTEXT_OFFSET: usize = 176;

pub const SIGCONTEXT_FAULT_ADDRESS_OFFSET: usize = 0;
pub const SIGCONTEXT_REGS_OFFSET: usize = 8;
pub const SIGCONTEXT_REG_COUNT: usize = 31;
pub const SIGCONTEXT_SP_OFFSET: usize = 256;
pub const SIGCONTEXT_PC_OFFSET: usize = 264;
pub const SIGCONTEXT_PSTATE_OFFSET: usize = 272;
pub const SIGCONTEXT_RESERVED_OFFSET: usize = 288;
pub const SIGCONTEXT_RESERVED_BYTES: usize = 4096;
pub const SIGCONTEXT_BYTES: usize = SIGCONTEXT_RESERVED_OFFSET + SIGCONTEXT_RESERVED_BYTES;
pub const UCONTEXT_BYTES: usize = UCONTEXT_MCONTEXT_OFFSET + SIGCONTEXT_BYTES;
pub const RT_SIGFRAME_BYTES: usize = RT_SIGFRAME_UCONTEXT_OFFSET + UCONTEXT_BYTES;

/// Absolute frame offset at which Linux arm64 begins the 16-byte-aligned extension-record area.
pub const RT_SIGFRAME_RESERVED_OFFSET: usize =
    RT_SIGFRAME_UCONTEXT_OFFSET + UCONTEXT_MCONTEXT_OFFSET + SIGCONTEXT_RESERVED_OFFSET;
/// Bytes that can be encoded/decoded without making any claim about FP/SIMD or later architectural
/// extension records. The caller must handle the reserved extension area separately.
pub const RT_SIGFRAME_FIXED_PREFIX_BYTES: usize = RT_SIGFRAME_RESERVED_OFFSET;

pub const AARCH64_CONTEXT_HEADER_BYTES: usize = 8;
pub const AARCH64_CONTEXT_TERMINATOR_BYTES: usize = 16;
pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
pub const FPSIMD_CONTEXT_BYTES: usize = 0x210;
pub const FPSIMD_VREG_BYTES: usize = 32 * 16;
pub const FPSIMD_CONTEXT_OFFSET: usize = RT_SIGFRAME_RESERVED_OFFSET;
pub const FPSIMD_CONTEXT_END: usize = FPSIMD_CONTEXT_OFFSET + FPSIMD_CONTEXT_BYTES;
pub const MINIMAL_CONTEXT_TERMINATOR_OFFSET: usize = FPSIMD_CONTEXT_END;
pub const MINIMAL_CONTEXT_END: usize =
    MINIMAL_CONTEXT_TERMINATOR_OFFSET + AARCH64_CONTEXT_TERMINATOR_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalFrameError {
    BufferTooSmall,
    InvalidFpsimdHeader,
}

/// Authority-free copy of the fixed AArch64 integer state carried by Linux `struct sigcontext`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64SignalIntegerContext {
    fault_address: u64,
    registers: [u64; SIGCONTEXT_REG_COUNT],
    sp: u64,
    pc: u64,
    pstate: u64,
}

impl Aarch64SignalIntegerContext {
    pub const fn new(
        fault_address: u64,
        registers: [u64; SIGCONTEXT_REG_COUNT],
        sp: u64,
        pc: u64,
        pstate: u64,
    ) -> Self {
        Self {
            fault_address,
            registers,
            sp,
            pc,
            pstate,
        }
    }

    pub const fn fault_address(self) -> u64 {
        self.fault_address
    }

    pub const fn registers(&self) -> &[u64; SIGCONTEXT_REG_COUNT] {
        &self.registers
    }

    pub const fn sp(self) -> u64 {
        self.sp
    }

    pub const fn pc(self) -> u64 {
        self.pc
    }

    pub const fn pstate(self) -> u64 {
        self.pstate
    }
}

/// Linux `stack_t` observation embedded in `ucontext`. Signal-stack policy remains outside this ABI
/// type; the fields are copied exactly and confer no stack-selection authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64SignalStack {
    sp: u64,
    flags: i32,
    size: u64,
}

impl Aarch64SignalStack {
    pub const fn new(sp: u64, flags: i32, size: u64) -> Self {
        Self { sp, flags, size }
    }

    pub const fn sp(self) -> u64 {
        self.sp
    }

    pub const fn flags(self) -> i32 {
        self.flags
    }

    pub const fn size(self) -> u64 {
        self.size
    }
}

/// Fixed prefix of Linux/AArch64 `struct rt_sigframe` through the integer `sigcontext` fields.
///
/// The 4096-byte `sigcontext.__reserved` extension area is intentionally excluded. A complete signal
/// delivery/return path must separately preserve and validate the generation-owned FP/SIMD image and
/// any enabled architectural extension records before committing userspace frame state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64RtSignalFramePrefix {
    siginfo: [u8; RT_SIGFRAME_SIGINFO_BYTES],
    uc_flags: u64,
    uc_link: u64,
    stack: Aarch64SignalStack,
    signal_mask: u64,
    integer: Aarch64SignalIntegerContext,
}

impl Aarch64RtSignalFramePrefix {
    pub const fn new(
        siginfo: [u8; RT_SIGFRAME_SIGINFO_BYTES],
        uc_flags: u64,
        uc_link: u64,
        stack: Aarch64SignalStack,
        signal_mask: u64,
        integer: Aarch64SignalIntegerContext,
    ) -> Self {
        Self {
            siginfo,
            uc_flags,
            uc_link,
            stack,
            signal_mask,
            integer,
        }
    }

    pub const fn siginfo(&self) -> &[u8; RT_SIGFRAME_SIGINFO_BYTES] {
        &self.siginfo
    }

    pub const fn uc_flags(self) -> u64 {
        self.uc_flags
    }

    pub const fn uc_link(self) -> u64 {
        self.uc_link
    }

    pub const fn stack(self) -> Aarch64SignalStack {
        self.stack
    }

    pub const fn signal_mask(self) -> u64 {
        self.signal_mask
    }

    pub const fn integer(self) -> Aarch64SignalIntegerContext {
        self.integer
    }

    /// Encodes only the fixed prefix and deliberately stops at `sigcontext.__reserved`.
    ///
    /// The encoded prefix is zero-filled first, which deterministically clears C-ABI padding and the
    /// unused upper 960 bits of the 1024-bit userspace sigset_t footprint.
    pub fn encode_into(self, output: &mut [u8]) -> Result<(), SignalFrameError> {
        let prefix = output
            .get_mut(..RT_SIGFRAME_FIXED_PREFIX_BYTES)
            .ok_or(SignalFrameError::BufferTooSmall)?;
        prefix.fill(0);
        prefix[RT_SIGFRAME_SIGINFO_OFFSET..RT_SIGFRAME_UCONTEXT_OFFSET]
            .copy_from_slice(&self.siginfo);

        let uc = RT_SIGFRAME_UCONTEXT_OFFSET;
        write_u64(prefix, uc + UCONTEXT_FLAGS_OFFSET, self.uc_flags);
        write_u64(prefix, uc + UCONTEXT_LINK_OFFSET, self.uc_link);
        write_u64(prefix, uc + UCONTEXT_STACK_SP_OFFSET, self.stack.sp);
        write_i32(prefix, uc + UCONTEXT_STACK_FLAGS_OFFSET, self.stack.flags);
        write_u64(prefix, uc + UCONTEXT_STACK_SIZE_OFFSET, self.stack.size);
        write_u64(prefix, uc + UCONTEXT_SIGMASK_OFFSET, self.signal_mask);

        let sc = uc + UCONTEXT_MCONTEXT_OFFSET;
        write_u64(
            prefix,
            sc + SIGCONTEXT_FAULT_ADDRESS_OFFSET,
            self.integer.fault_address,
        );
        for (index, value) in self.integer.registers.iter().copied().enumerate() {
            write_u64(prefix, sc + SIGCONTEXT_REGS_OFFSET + index * 8, value);
        }
        write_u64(prefix, sc + SIGCONTEXT_SP_OFFSET, self.integer.sp);
        write_u64(prefix, sc + SIGCONTEXT_PC_OFFSET, self.integer.pc);
        write_u64(prefix, sc + SIGCONTEXT_PSTATE_OFFSET, self.integer.pstate);
        Ok(())
    }

    /// Decodes only the fixed integer prefix. The caller must not restore architectural state until
    /// the separate extension-record parser has accepted the reserved area and its mandatory FP/SIMD
    /// record for the active Kernal runtime.
    pub fn decode_from(input: &[u8]) -> Result<Self, SignalFrameError> {
        let prefix = input
            .get(..RT_SIGFRAME_FIXED_PREFIX_BYTES)
            .ok_or(SignalFrameError::BufferTooSmall)?;
        let mut siginfo = [0u8; RT_SIGFRAME_SIGINFO_BYTES];
        siginfo.copy_from_slice(&prefix[RT_SIGFRAME_SIGINFO_OFFSET..RT_SIGFRAME_UCONTEXT_OFFSET]);

        let uc = RT_SIGFRAME_UCONTEXT_OFFSET;
        let mut registers = [0u64; SIGCONTEXT_REG_COUNT];
        let sc = uc + UCONTEXT_MCONTEXT_OFFSET;
        for (index, value) in registers.iter_mut().enumerate() {
            *value = read_u64(prefix, sc + SIGCONTEXT_REGS_OFFSET + index * 8);
        }

        Ok(Self::new(
            siginfo,
            read_u64(prefix, uc + UCONTEXT_FLAGS_OFFSET),
            read_u64(prefix, uc + UCONTEXT_LINK_OFFSET),
            Aarch64SignalStack::new(
                read_u64(prefix, uc + UCONTEXT_STACK_SP_OFFSET),
                read_i32(prefix, uc + UCONTEXT_STACK_FLAGS_OFFSET),
                read_u64(prefix, uc + UCONTEXT_STACK_SIZE_OFFSET),
            ),
            read_u64(prefix, uc + UCONTEXT_SIGMASK_OFFSET),
            Aarch64SignalIntegerContext::new(
                read_u64(prefix, sc + SIGCONTEXT_FAULT_ADDRESS_OFFSET),
                registers,
                read_u64(prefix, sc + SIGCONTEXT_SP_OFFSET),
                read_u64(prefix, sc + SIGCONTEXT_PC_OFFSET),
                read_u64(prefix, sc + SIGCONTEXT_PSTATE_OFFSET),
            ),
        ))
    }
}

/// Linux/AArch64 FPSIMD extension record: `_aarch64_ctx`, FPSR, FPCR and q0..q31.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aarch64FpsimdContext {
    fpsr: u32,
    fpcr: u32,
    vregs: [u8; FPSIMD_VREG_BYTES],
}

impl Aarch64FpsimdContext {
    pub const fn new(fpsr: u32, fpcr: u32, vregs: [u8; FPSIMD_VREG_BYTES]) -> Self {
        Self { fpsr, fpcr, vregs }
    }

    pub const fn fpsr(self) -> u32 {
        self.fpsr
    }

    pub const fn fpcr(self) -> u32 {
        self.fpcr
    }

    pub const fn vregs(&self) -> &[u8; FPSIMD_VREG_BYTES] {
        &self.vregs
    }

    pub fn encode_into(self, output: &mut [u8]) -> Result<(), SignalFrameError> {
        let record = output
            .get_mut(..FPSIMD_CONTEXT_BYTES)
            .ok_or(SignalFrameError::BufferTooSmall)?;
        record.fill(0);
        write_u32(record, 0, FPSIMD_MAGIC);
        write_u32(record, 4, FPSIMD_CONTEXT_BYTES as u32);
        write_u32(record, 8, self.fpsr);
        write_u32(record, 12, self.fpcr);
        record[16..16 + FPSIMD_VREG_BYTES].copy_from_slice(&self.vregs);
        Ok(())
    }

    pub fn decode_from(input: &[u8]) -> Result<Self, SignalFrameError> {
        let record = input
            .get(..FPSIMD_CONTEXT_BYTES)
            .ok_or(SignalFrameError::BufferTooSmall)?;
        if read_u32(record, 0) != FPSIMD_MAGIC || read_u32(record, 4) != FPSIMD_CONTEXT_BYTES as u32
        {
            return Err(SignalFrameError::InvalidFpsimdHeader);
        }
        let mut vregs = [0u8; FPSIMD_VREG_BYTES];
        vregs.copy_from_slice(&record[16..16 + FPSIMD_VREG_BYTES]);
        Ok(Self::new(read_u32(record, 8), read_u32(record, 12), vregs))
    }
}

/// Encodes the padded null `_aarch64_ctx` terminator used after the final extension record.
pub fn encode_context_terminator(output: &mut [u8]) -> Result<(), SignalFrameError> {
    let terminator = output
        .get_mut(..AARCH64_CONTEXT_TERMINATOR_BYTES)
        .ok_or(SignalFrameError::BufferTooSmall)?;
    terminator.fill(0);
    Ok(())
}

/// Computes the Linux arm64 16-byte-aligned frame base from an already selected signal stack pointer.
/// Alternate-stack policy is deliberately outside this pure ABI helper.
pub fn aligned_frame_base(chosen_stack_pointer: u64, frame_bytes: usize) -> Option<u64> {
    let size = u64::try_from(frame_bytes).ok()?;
    let unaligned = chosen_stack_pointer.checked_sub(size)?;
    Some(unaligned & !(RT_SIGFRAME_ALIGNMENT - 1))
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_ne_bytes(word)
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_ne_bytes(word)
}

fn write_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    i32::from_ne_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_layout_matches_linux_aarch64_offsets() {
        assert_eq!(RT_SIGFRAME_UCONTEXT_OFFSET, 128);
        assert_eq!(UCONTEXT_MCONTEXT_OFFSET, 176);
        assert_eq!(SIGCONTEXT_REGS_OFFSET, 8);
        assert_eq!(SIGCONTEXT_SP_OFFSET, 256);
        assert_eq!(SIGCONTEXT_PC_OFFSET, 264);
        assert_eq!(SIGCONTEXT_PSTATE_OFFSET, 272);
        assert_eq!(SIGCONTEXT_RESERVED_OFFSET, 288);
        assert_eq!(SIGCONTEXT_BYTES, 4384);
        assert_eq!(UCONTEXT_BYTES, 4560);
        assert_eq!(RT_SIGFRAME_BYTES, 4688);
        assert_eq!(RT_SIGFRAME_RESERVED_OFFSET, 592);
        assert_eq!(
            RT_SIGFRAME_RESERVED_OFFSET % RT_SIGFRAME_ALIGNMENT as usize,
            0
        );
        const { assert!(MINIMAL_CONTEXT_END <= RT_SIGFRAME_BYTES) };
    }

    #[test]
    fn integer_prefix_roundtrips_and_zeros_padding() {
        let registers = core::array::from_fn(|index| 0x1000 + index as u64);
        let integer = Aarch64SignalIntegerContext::new(
            0xfeed_0000,
            registers,
            0x7000_0000,
            0x4000_1234,
            0x200,
        );
        let stack = Aarch64SignalStack::new(0x6000_0000, 2, 0x20_000);
        let info = core::array::from_fn(|index| index as u8);
        let frame = Aarch64RtSignalFramePrefix::new(
            info,
            0x11,
            0x22,
            stack,
            0x8000_0000_0000_0001,
            integer,
        );
        let mut bytes = [0xa5u8; RT_SIGFRAME_FIXED_PREFIX_BYTES];
        frame.encode_into(&mut bytes).unwrap();

        assert_eq!(
            &bytes[RT_SIGFRAME_UCONTEXT_OFFSET + UCONTEXT_SIGMASK_OFFSET + 8
                ..RT_SIGFRAME_UCONTEXT_OFFSET
                    + UCONTEXT_SIGMASK_OFFSET
                    + UCONTEXT_SIGMASK_AREA_BYTES],
            &[0u8; UCONTEXT_SIGMASK_AREA_BYTES - 8]
        );
        assert_eq!(Aarch64RtSignalFramePrefix::decode_from(&bytes), Ok(frame));
    }

    #[test]
    fn fpsimd_record_roundtrips_linux_header_and_payload_order() {
        let vregs = core::array::from_fn(|index| (index as u8).wrapping_mul(3));
        let context = Aarch64FpsimdContext::new(0x1122_3344, 0x5566_7788, vregs);
        let mut bytes = [0u8; FPSIMD_CONTEXT_BYTES];
        context.encode_into(&mut bytes).unwrap();

        assert_eq!(read_u32(&bytes, 0), FPSIMD_MAGIC);
        assert_eq!(read_u32(&bytes, 4), FPSIMD_CONTEXT_BYTES as u32);
        assert_eq!(read_u32(&bytes, 8), 0x1122_3344);
        assert_eq!(read_u32(&bytes, 12), 0x5566_7788);
        assert_eq!(Aarch64FpsimdContext::decode_from(&bytes), Ok(context));

        bytes[0] ^= 1;
        assert_eq!(
            Aarch64FpsimdContext::decode_from(&bytes),
            Err(SignalFrameError::InvalidFpsimdHeader)
        );
    }

    #[test]
    fn terminator_and_frame_base_are_bounded_and_aligned() {
        let mut terminator = [0xa5u8; AARCH64_CONTEXT_TERMINATOR_BYTES];
        encode_context_terminator(&mut terminator).unwrap();
        assert!(terminator.iter().all(|byte| *byte == 0));

        let base = aligned_frame_base(0x8000_0008, RT_SIGFRAME_BYTES).unwrap();
        assert_eq!(base % RT_SIGFRAME_ALIGNMENT, 0);
        assert!(base < 0x8000_0008);
        assert_eq!(aligned_frame_base(8, RT_SIGFRAME_BYTES), None);
    }
}
