// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const MAX_INTERPRETER_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Machine {
    X86_64,
    Aarch64,
}

impl Machine {
    const fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => EM_X86_64,
            Self::Aarch64 => EM_AARCH64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageType {
    Executable,
    SharedObject,
}

impl ImageType {
    fn parse(value: u16) -> Result<Self, Error> {
        match value {
            ET_EXEC => Ok(Self::Executable),
            ET_DYN => Ok(Self::SharedObject),
            _ => Err(Error::UnsupportedType),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndian,
    UnsupportedVersion,
    UnsupportedType,
    UnsupportedMachine,
    BadHeaderSize,
    BadProgramHeaderSize,
    ProgramTableOverflow,
    ProgramHeaderTableNotMapped,
    MultipleProgramInterpreters,
    ProgramInterpreterAfterLoad,
    EmptyProgramInterpreter,
    ProgramInterpreterTooLong,
    ProgramInterpreterOutOfBounds,
    ProgramInterpreterNotTerminated,
    ProgramInterpreterContainsNul,
    SegmentFileLargerThanMemory,
    SegmentOutOfBounds,
    AddressOverflow,
    NoLoadSegments,
    WritableExecutableSegment,
    OverlappingLoadSegments,
    EntryPointNotExecutable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment {
    pub offset: u64,
    pub virtual_addr: u64,
    pub physical_addr: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
    pub flags: u32,
}

impl Segment {
    pub const fn readable(self) -> bool {
        self.flags & 4 != 0
    }

    pub const fn writable(self) -> bool {
        self.flags & 2 != 0
    }

    pub const fn executable(self) -> bool {
        self.flags & 1 != 0
    }

    pub fn end(self) -> Result<u64, Error> {
        self.virtual_addr
            .checked_add(self.memory_size)
            .ok_or(Error::AddressOverflow)
    }

    pub fn contains_virtual(self, address: u64) -> Result<bool, Error> {
        Ok(address >= self.virtual_addr && address < self.end()?)
    }
}

/// ELF64 program-header table metadata after proving the complete table is present in one PT_LOAD
/// file mapping. `virtual_addr` is the image-relative/link-time virtual address; ET_DYN loaders must
/// apply the same accepted load bias used for the image's load segments before publishing AT_PHDR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramHeaderTable {
    virtual_addr: u64,
    entry_size: usize,
    entry_count: usize,
}

impl ProgramHeaderTable {
    pub const fn virtual_addr(self) -> u64 {
        self.virtual_addr
    }

    pub const fn entry_size(self) -> usize {
        self.entry_size
    }

    pub const fn entry_count(self) -> usize {
        self.entry_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Image<'a> {
    bytes: &'a [u8],
    image_type: ImageType,
    entry: u64,
    phoff: usize,
    phnum: usize,
}

impl<'a> Image<'a> {
    /// Parses the current x86_64 kernel image format. Kept as the compatibility entrypoint for the
    /// existing x86 loader; new architecture loaders should call `parse_for_machine` explicitly.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_for_machine(bytes, Machine::X86_64)
    }

    pub fn parse_for_machine(bytes: &'a [u8], machine: Machine) -> Result<Self, Error> {
        if bytes.len() < ELF64_EHDR_SIZE {
            return Err(Error::Truncated);
        }
        if bytes.get(0..4) != Some(ELF_MAGIC) {
            return Err(Error::BadMagic);
        }
        if bytes[4] != ELFCLASS64 {
            return Err(Error::UnsupportedClass);
        }
        if bytes[5] != ELFDATA2LSB {
            return Err(Error::UnsupportedEndian);
        }
        if bytes[6] != EV_CURRENT {
            return Err(Error::UnsupportedVersion);
        }

        let image_type = ImageType::parse(read_u16(bytes, 16)?)?;
        if read_u16(bytes, 18)? != machine.elf_machine() {
            return Err(Error::UnsupportedMachine);
        }
        if read_u16(bytes, 52)? as usize != ELF64_EHDR_SIZE {
            return Err(Error::BadHeaderSize);
        }
        if read_u16(bytes, 54)? as usize != ELF64_PHDR_SIZE {
            return Err(Error::BadProgramHeaderSize);
        }

        let phoff =
            usize::try_from(read_u64(bytes, 32)?).map_err(|_| Error::ProgramTableOverflow)?;
        let phnum = read_u16(bytes, 56)? as usize;
        let table_len = phnum
            .checked_mul(ELF64_PHDR_SIZE)
            .ok_or(Error::ProgramTableOverflow)?;
        let table_end = phoff
            .checked_add(table_len)
            .ok_or(Error::ProgramTableOverflow)?;
        if table_end > bytes.len() {
            return Err(Error::Truncated);
        }

        let image = Self {
            bytes,
            image_type,
            entry: read_u64(bytes, 24)?,
            phoff,
            phnum,
        };
        image.validate_load_layout()?;
        image.interpreter_path()?;
        Ok(image)
    }

    pub const fn image_type(&self) -> ImageType {
        self.image_type
    }

    pub const fn entry(&self) -> u64 {
        self.entry
    }

    /// Returns the validated PT_INTERP path without its trailing NUL byte.
    ///
    /// This is parser metadata only. Resolving or mapping the interpreter remains owned by the
    /// later runtime/VFS integration path. The parser accepts at most one bounded PT_INTERP record,
    /// requires it to precede every PT_LOAD entry, and fails closed on malformed file ranges,
    /// missing termination or embedded NUL bytes.
    pub fn interpreter_path(&self) -> Result<Option<&'a [u8]>, Error> {
        let mut interpreter = None;
        let mut saw_load = false;
        let mut cursor = self.phoff;

        for _ in 0..self.phnum {
            let kind = read_u32(self.bytes, cursor)?;
            if kind == PT_LOAD {
                saw_load = true;
            }
            if kind == PT_INTERP {
                if saw_load {
                    return Err(Error::ProgramInterpreterAfterLoad);
                }
                if interpreter.is_some() {
                    return Err(Error::MultipleProgramInterpreters);
                }

                let offset = usize::try_from(read_u64(self.bytes, cursor + 8)?)
                    .map_err(|_| Error::ProgramInterpreterOutOfBounds)?;
                let file_size = usize::try_from(read_u64(self.bytes, cursor + 32)?)
                    .map_err(|_| Error::ProgramInterpreterOutOfBounds)?;
                if file_size <= 1 {
                    return Err(Error::EmptyProgramInterpreter);
                }
                if file_size > MAX_INTERPRETER_PATH_BYTES {
                    return Err(Error::ProgramInterpreterTooLong);
                }
                let end = offset
                    .checked_add(file_size)
                    .ok_or(Error::ProgramInterpreterOutOfBounds)?;
                let raw = self
                    .bytes
                    .get(offset..end)
                    .ok_or(Error::ProgramInterpreterOutOfBounds)?;
                if raw.last().copied() != Some(0) {
                    return Err(Error::ProgramInterpreterNotTerminated);
                }
                let path = &raw[..raw.len() - 1];
                if path.is_empty() {
                    return Err(Error::EmptyProgramInterpreter);
                }
                if path.contains(&0) {
                    return Err(Error::ProgramInterpreterContainsNul);
                }
                interpreter = Some(path);
            }
            cursor = cursor
                .checked_add(ELF64_PHDR_SIZE)
                .ok_or(Error::ProgramTableOverflow)?;
        }

        Ok(interpreter)
    }

    /// Resolves the ELF64 program-header table to a virtual address that the existing PT_LOAD-only
    /// runtime will actually map into the user image.
    ///
    /// PT_PHDR, when present, is treated as an authoritative address declaration only if it covers
    /// the complete e_phoff/e_phnum table and agrees exactly with the PT_LOAD file mapping that
    /// contains those same bytes. Without PT_PHDR the address is derived from that PT_LOAD mapping.
    /// Multiple PT_LOAD mappings for the same table bytes must agree on the resulting virtual
    /// address; otherwise the image fails closed rather than publishing an ambiguous AT_PHDR.
    pub fn program_header_table(&self) -> Result<ProgramHeaderTable, Error> {
        let table_len = self
            .phnum
            .checked_mul(ELF64_PHDR_SIZE)
            .ok_or(Error::ProgramTableOverflow)?;
        let table_start = u64::try_from(self.phoff).map_err(|_| Error::ProgramTableOverflow)?;
        let table_len = u64::try_from(table_len).map_err(|_| Error::ProgramTableOverflow)?;
        let table_end = table_start
            .checked_add(table_len)
            .ok_or(Error::ProgramTableOverflow)?;

        let mut declared_phdr_va = None;
        let mut cursor = self.phoff;
        for _ in 0..self.phnum {
            if read_u32(self.bytes, cursor)? == PT_PHDR {
                let phdr = parse_segment(self.bytes, cursor)?;
                if declared_phdr_va.is_some()
                    || !file_range_contains(phdr.offset, phdr.file_size, table_start, table_end)?
                {
                    return Err(Error::ProgramHeaderTableNotMapped);
                }
                declared_phdr_va = Some(virtual_for_file_offset(phdr, table_start)?);
            }
            cursor = cursor
                .checked_add(ELF64_PHDR_SIZE)
                .ok_or(Error::ProgramTableOverflow)?;
        }

        let mut mapped_va = None;
        for segment_result in self.load_segments() {
            let segment = segment_result?;
            if !file_range_contains(segment.offset, segment.file_size, table_start, table_end)? {
                continue;
            }
            let candidate = virtual_for_file_offset(segment, table_start)?;
            match mapped_va {
                None => mapped_va = Some(candidate),
                Some(existing) if existing == candidate => {}
                Some(_) => return Err(Error::ProgramHeaderTableNotMapped),
            }
        }

        let mapped_va = mapped_va.ok_or(Error::ProgramHeaderTableNotMapped)?;
        if let Some(declared) = declared_phdr_va
            && declared != mapped_va
        {
            return Err(Error::ProgramHeaderTableNotMapped);
        }

        Ok(ProgramHeaderTable {
            virtual_addr: declared_phdr_va.unwrap_or(mapped_va),
            entry_size: ELF64_PHDR_SIZE,
            entry_count: self.phnum,
        })
    }

    pub fn load_segments(&self) -> LoadSegments<'a> {
        LoadSegments {
            bytes: self.bytes,
            cursor: self.phoff,
            remaining: self.phnum,
        }
    }

    fn validate_load_layout(&self) -> Result<(), Error> {
        let mut load_count = 0usize;
        let mut entry_is_executable = false;

        for (index, segment_result) in self.load_segments().enumerate() {
            let segment = segment_result?;
            load_count += 1;

            if segment.writable() && segment.executable() {
                return Err(Error::WritableExecutableSegment);
            }
            if segment.executable() && segment.contains_virtual(self.entry)? {
                entry_is_executable = true;
            }

            for other_result in self.load_segments().skip(index + 1) {
                let other = other_result?;
                if ranges_overlap(segment, other)? {
                    return Err(Error::OverlappingLoadSegments);
                }
            }
        }

        if load_count == 0 {
            return Err(Error::NoLoadSegments);
        }
        if !entry_is_executable {
            return Err(Error::EntryPointNotExecutable);
        }
        Ok(())
    }
}

pub struct LoadSegments<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl Iterator for LoadSegments<'_> {
    type Item = Result<Segment, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining > 0 {
            let offset = self.cursor;
            self.cursor += ELF64_PHDR_SIZE;
            self.remaining -= 1;
            let p_type = match read_u32(self.bytes, offset) {
                Ok(value) => value,
                Err(error) => return Some(Err(error)),
            };
            if p_type != PT_LOAD {
                continue;
            }
            return Some(parse_segment(self.bytes, offset));
        }
        None
    }
}

fn ranges_overlap(left: Segment, right: Segment) -> Result<bool, Error> {
    if left.memory_size == 0 || right.memory_size == 0 {
        return Ok(false);
    }
    Ok(left.virtual_addr < right.end()? && right.virtual_addr < left.end()?)
}

fn file_range_contains(
    segment_offset: u64,
    segment_file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<bool, Error> {
    let segment_end = segment_offset
        .checked_add(segment_file_size)
        .ok_or(Error::AddressOverflow)?;
    Ok(range_start >= segment_offset && range_end <= segment_end)
}

fn virtual_for_file_offset(segment: Segment, file_offset: u64) -> Result<u64, Error> {
    let delta = file_offset
        .checked_sub(segment.offset)
        .ok_or(Error::ProgramHeaderTableNotMapped)?;
    segment
        .virtual_addr
        .checked_add(delta)
        .ok_or(Error::AddressOverflow)
}

fn parse_segment(bytes: &[u8], at: usize) -> Result<Segment, Error> {
    let flags = read_u32(bytes, at + 4)?;
    let offset = read_u64(bytes, at + 8)?;
    let virtual_addr = read_u64(bytes, at + 16)?;
    let physical_addr = read_u64(bytes, at + 24)?;
    let file_size = read_u64(bytes, at + 32)?;
    let memory_size = read_u64(bytes, at + 40)?;
    let align = read_u64(bytes, at + 48)?;

    if file_size > memory_size {
        return Err(Error::SegmentFileLargerThanMemory);
    }
    let file_end = offset
        .checked_add(file_size)
        .ok_or(Error::AddressOverflow)?;
    if file_end > bytes.len() as u64 {
        return Err(Error::SegmentOutOfBounds);
    }
    virtual_addr
        .checked_add(memory_size)
        .ok_or(Error::AddressOverflow)?;

    Ok(Segment {
        offset,
        virtual_addr,
        physical_addr,
        file_size,
        memory_size,
        align,
        flags,
    })
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let raw: [u8; 2] = bytes
        .get(at..at + 2)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, Error> {
    let raw: [u8; 8] = bytes
        .get(at..at + 8)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERP_OFFSET: usize = 0x180;
    const AARCH64_INTERP: &[u8] = b"/lib/ld-linux-aarch64.so.1";

    fn minimal_elf() -> [u8; 0x120] {
        let mut bytes = [0u8; 0x120];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0xffff_8000_0010_0000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let p = 64;
        bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&0xffff_8000_0010_0000u64.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0x10_0000u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&0x20u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    fn elf_with_mapped_program_headers() -> [u8; 0x180] {
        let mut bytes = [0u8; 0x180];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        let base = 0xffff_8000_0020_0000u64;
        bytes[24..32].copy_from_slice(&base.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

        let p = 64;
        bytes[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[p + 16..p + 24].copy_from_slice(&base.to_le_bytes());
        bytes[p + 24..p + 32].copy_from_slice(&0x20_0000u64.to_le_bytes());
        bytes[p + 32..p + 40].copy_from_slice(&0x180u64.to_le_bytes());
        bytes[p + 40..p + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    fn elf_with_pt_phdr() -> [u8; 0x180] {
        let mut bytes = [0u8; 0x180];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        let base = 0xffff_8000_0030_0000u64;
        bytes[24..32].copy_from_slice(&base.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

        let phdr = 64;
        bytes[phdr..phdr + 4].copy_from_slice(&PT_PHDR.to_le_bytes());
        bytes[phdr + 4..phdr + 8].copy_from_slice(&4u32.to_le_bytes());
        bytes[phdr + 8..phdr + 16].copy_from_slice(&64u64.to_le_bytes());
        bytes[phdr + 16..phdr + 24].copy_from_slice(&(base + 64).to_le_bytes());
        bytes[phdr + 24..phdr + 32].copy_from_slice(&0u64.to_le_bytes());
        bytes[phdr + 32..phdr + 40].copy_from_slice(&112u64.to_le_bytes());
        bytes[phdr + 40..phdr + 48].copy_from_slice(&112u64.to_le_bytes());
        bytes[phdr + 48..phdr + 56].copy_from_slice(&8u64.to_le_bytes());

        let load = 64 + ELF64_PHDR_SIZE;
        bytes[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[load + 4..load + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[load + 8..load + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[load + 16..load + 24].copy_from_slice(&base.to_le_bytes());
        bytes[load + 24..load + 32].copy_from_slice(&0x30_0000u64.to_le_bytes());
        bytes[load + 32..load + 40].copy_from_slice(&0x180u64.to_le_bytes());
        bytes[load + 40..load + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[load + 48..load + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    fn aarch64_elf_with_interp() -> [u8; 0x200] {
        let mut bytes = [0u8; 0x200];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        let base = 0x40_0000u64;
        bytes[24..32].copy_from_slice(&(base + 0x100).to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_EHDR_SIZE as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PHDR_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

        let interp = 64;
        bytes[interp..interp + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
        bytes[interp + 4..interp + 8].copy_from_slice(&4u32.to_le_bytes());
        bytes[interp + 8..interp + 16].copy_from_slice(&(INTERP_OFFSET as u64).to_le_bytes());
        let interp_size = (AARCH64_INTERP.len() + 1) as u64;
        bytes[interp + 32..interp + 40].copy_from_slice(&interp_size.to_le_bytes());
        bytes[interp + 40..interp + 48].copy_from_slice(&interp_size.to_le_bytes());
        bytes[interp + 48..interp + 56].copy_from_slice(&1u64.to_le_bytes());

        let load = interp + ELF64_PHDR_SIZE;
        bytes[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[load + 4..load + 8].copy_from_slice(&5u32.to_le_bytes());
        bytes[load + 8..load + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[load + 16..load + 24].copy_from_slice(&base.to_le_bytes());
        bytes[load + 24..load + 32].copy_from_slice(&0u64.to_le_bytes());
        bytes[load + 32..load + 40].copy_from_slice(&0x200u64.to_le_bytes());
        bytes[load + 40..load + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[load + 48..load + 56].copy_from_slice(&0x1000u64.to_le_bytes());

        bytes[INTERP_OFFSET..INTERP_OFFSET + AARCH64_INTERP.len()].copy_from_slice(AARCH64_INTERP);
        bytes[INTERP_OFFSET + AARCH64_INTERP.len()] = 0;
        bytes
    }

    #[test]
    fn parses_valid_x86_64_load_segment() {
        let bytes = minimal_elf();
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(image.image_type(), ImageType::Executable);
        assert_eq!(image.entry(), 0xffff_8000_0010_0000);
        let segment = image.load_segments().next().unwrap().unwrap();
        assert!(segment.readable());
        assert!(segment.executable());
        assert!(!segment.writable());
    }

    #[test]
    fn exposes_validated_dynamic_image_type() {
        let mut bytes = minimal_elf();
        bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(image.image_type(), ImageType::SharedObject);
    }

    #[test]
    fn parses_valid_aarch64_load_segment_when_requested() {
        let mut bytes = minimal_elf();
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        assert_eq!(image.image_type(), ImageType::Executable);
        assert_eq!(image.entry(), 0xffff_8000_0010_0000);
        assert_eq!(Image::parse(&bytes), Err(Error::UnsupportedMachine));
    }

    #[test]
    fn machine_selection_rejects_cross_architecture_images() {
        let bytes = minimal_elf();
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(Error::UnsupportedMachine)
        );
    }

    #[test]
    fn static_image_has_no_program_interpreter() {
        let bytes = minimal_elf();
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(image.interpreter_path(), Ok(None));
    }

    #[test]
    fn exposes_bounded_aarch64_program_interpreter() {
        let bytes = aarch64_elf_with_interp();
        let image = Image::parse_for_machine(&bytes, Machine::Aarch64).unwrap();
        assert_eq!(image.image_type(), ImageType::SharedObject);
        assert_eq!(image.interpreter_path(), Ok(Some(AARCH64_INTERP)));
    }

    #[test]
    fn rejects_duplicate_program_interpreters() {
        let mut bytes = aarch64_elf_with_interp();
        bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
        let first = 64;
        let second = first + ELF64_PHDR_SIZE;
        let third = second + ELF64_PHDR_SIZE;
        bytes.copy_within(second..second + ELF64_PHDR_SIZE, third);
        bytes.copy_within(first..first + ELF64_PHDR_SIZE, second);
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(Error::MultipleProgramInterpreters)
        );
    }

    #[test]
    fn rejects_unterminated_program_interpreter() {
        let mut bytes = aarch64_elf_with_interp();
        bytes[INTERP_OFFSET + AARCH64_INTERP.len()] = b'x';
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(Error::ProgramInterpreterNotTerminated)
        );
    }

    #[test]
    fn rejects_embedded_nul_in_program_interpreter() {
        let mut bytes = aarch64_elf_with_interp();
        bytes[INTERP_OFFSET + 4] = 0;
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(Error::ProgramInterpreterContainsNul)
        );
    }

    #[test]
    fn rejects_out_of_bounds_program_interpreter() {
        let mut bytes = aarch64_elf_with_interp();
        let interp = 64;
        bytes[interp + 8..interp + 16].copy_from_slice(&0x1f8u64.to_le_bytes());
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(Error::ProgramInterpreterOutOfBounds)
        );
    }

    #[test]
    fn rejects_oversized_program_interpreter() {
        let mut bytes = aarch64_elf_with_interp();
        let interp = 64;
        bytes[interp + 32..interp + 40]
            .copy_from_slice(&((MAX_INTERPRETER_PATH_BYTES as u64) + 1).to_le_bytes());
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(Error::ProgramInterpreterTooLong)
        );
    }

    #[test]
    fn rejects_empty_program_interpreter() {
        let mut bytes = aarch64_elf_with_interp();
        let interp = 64;
        bytes[interp + 32..interp + 40].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            Image::parse_for_machine(&bytes, Machine::Aarch64),
            Err(Error::EmptyProgramInterpreter)
        );
    }

    #[test]
    fn resolves_program_header_table_through_covering_load_segment() {
        let bytes = elf_with_mapped_program_headers();
        let image = Image::parse(&bytes).unwrap();
        let table = image.program_header_table().unwrap();
        assert_eq!(table.virtual_addr(), 0xffff_8000_0020_0040);
        assert_eq!(table.entry_size(), ELF64_PHDR_SIZE);
        assert_eq!(table.entry_count(), 1);
    }

    #[test]
    fn pt_phdr_must_agree_with_covering_load_mapping() {
        let bytes = elf_with_pt_phdr();
        let image = Image::parse(&bytes).unwrap();
        let table = image.program_header_table().unwrap();
        assert_eq!(table.virtual_addr(), 0xffff_8000_0030_0040);
        assert_eq!(table.entry_count(), 2);

        let mut mismatched = bytes;
        let phdr = 64;
        mismatched[phdr + 16..phdr + 24].copy_from_slice(&0xffff_8000_0030_0080u64.to_le_bytes());
        let image = Image::parse(&mismatched).unwrap();
        assert_eq!(
            image.program_header_table(),
            Err(Error::ProgramHeaderTableNotMapped)
        );
    }

    #[test]
    fn rejects_program_header_table_not_present_in_loaded_file_range() {
        let bytes = minimal_elf();
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(
            image.program_header_table(),
            Err(Error::ProgramHeaderTableNotMapped)
        );
    }

    #[test]
    fn rejects_out_of_bounds_segment() {
        let mut bytes = minimal_elf();
        let p = 64;
        bytes[p + 32..p + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        assert_eq!(Image::parse(&bytes), Err(Error::SegmentOutOfBounds));
    }

    #[test]
    fn rejects_writable_executable_segment() {
        let mut bytes = minimal_elf();
        let p = 64;
        bytes[p + 4..p + 8].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(Image::parse(&bytes), Err(Error::WritableExecutableSegment));
    }

    #[test]
    fn rejects_non_executable_entry_point() {
        let mut bytes = minimal_elf();
        let p = 64;
        bytes[p + 4..p + 8].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(Image::parse(&bytes), Err(Error::EntryPointNotExecutable));
    }
}
