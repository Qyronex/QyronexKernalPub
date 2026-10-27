// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::str;

pub const MAGIC: u32 = 0xd00d_feed;
pub const HEADER_SIZE: usize = 40;
pub const CURRENT_VERSION: u32 = 17;

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadMagic,
    BadTotalSize,
    UnsupportedVersion,
    BadOffset,
    BadStructure,
    BadString,
    UnbalancedNodes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub total_size: usize,
    pub structure_offset: usize,
    pub strings_offset: usize,
    pub reserve_map_offset: usize,
    pub version: u32,
    pub last_compatible_version: u32,
    pub boot_cpu_id: u32,
    pub strings_size: usize,
    pub structure_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryReservation {
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    BeginNode(&'a str),
    EndNode,
    Property { name: &'a str, value: &'a [u8] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blob<'a> {
    bytes: &'a [u8],
    header: Header,
}

impl<'a> Blob<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::Truncated);
        }
        if read_be_u32(bytes, 0)? != MAGIC {
            return Err(Error::BadMagic);
        }

        let total_size = read_be_u32(bytes, 4)? as usize;
        if total_size < HEADER_SIZE || total_size > bytes.len() {
            return Err(Error::BadTotalSize);
        }

        let structure_offset = read_be_u32(bytes, 8)? as usize;
        let strings_offset = read_be_u32(bytes, 12)? as usize;
        let reserve_map_offset = read_be_u32(bytes, 16)? as usize;
        let version = read_be_u32(bytes, 20)?;
        let last_compatible_version = read_be_u32(bytes, 24)?;
        let boot_cpu_id = read_be_u32(bytes, 28)?;
        let strings_size = read_be_u32(bytes, 32)? as usize;
        let structure_size = read_be_u32(bytes, 36)? as usize;

        if version < CURRENT_VERSION || last_compatible_version > CURRENT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        checked_range(structure_offset, structure_size, total_size)?;
        checked_range(strings_offset, strings_size, total_size)?;
        if reserve_map_offset < HEADER_SIZE
            || reserve_map_offset >= total_size
            || reserve_map_offset & 0x7 != 0
        {
            return Err(Error::BadOffset);
        }

        let blob = Self {
            bytes: &bytes[..total_size],
            header: Header {
                total_size,
                structure_offset,
                strings_offset,
                reserve_map_offset,
                version,
                last_compatible_version,
                boot_cpu_id,
                strings_size,
                structure_size,
            },
        };

        // Validate that the reserve map terminates inside the blob and that the structure stream
        // reaches FDT_END with balanced nodes before exposing the object to callers.
        for reservation in blob.memory_reservations() {
            reservation?;
        }
        let mut events = blob.events();
        for event in events.by_ref() {
            event?;
        }
        if !events.saw_end || events.depth != 0 {
            return Err(Error::UnbalancedNodes);
        }
        Ok(blob)
    }

    pub const fn header(&self) -> Header {
        self.header
    }

    pub fn events(&self) -> Events<'a> {
        Events {
            structure: &self.bytes[self.header.structure_offset
                ..self.header.structure_offset + self.header.structure_size],
            strings: &self.bytes
                [self.header.strings_offset..self.header.strings_offset + self.header.strings_size],
            cursor: 0,
            depth: 0,
            saw_end: false,
            failed: false,
        }
    }

    pub fn memory_reservations(&self) -> MemoryReservations<'a> {
        MemoryReservations {
            bytes: self.bytes,
            cursor: self.header.reserve_map_offset,
            done: false,
        }
    }
}

pub struct MemoryReservations<'a> {
    bytes: &'a [u8],
    cursor: usize,
    done: bool,
}

impl Iterator for MemoryReservations<'_> {
    type Item = Result<MemoryReservation, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let address = match read_be_u64(self.bytes, self.cursor) {
            Ok(value) => value,
            Err(error) => {
                self.done = true;
                return Some(Err(error));
            }
        };
        let size = match read_be_u64(self.bytes, self.cursor + 8) {
            Ok(value) => value,
            Err(error) => {
                self.done = true;
                return Some(Err(error));
            }
        };
        self.cursor += 16;
        if address == 0 && size == 0 {
            self.done = true;
            return None;
        }
        Some(Ok(MemoryReservation { address, size }))
    }
}

pub struct Events<'a> {
    structure: &'a [u8],
    strings: &'a [u8],
    cursor: usize,
    depth: usize,
    saw_end: bool,
    failed: bool,
}

impl<'a> Events<'a> {
    fn fail(&mut self, error: Error) -> Option<Result<Event<'a>, Error>> {
        self.failed = true;
        Some(Err(error))
    }

    fn property_name(&self, offset: usize) -> Result<&'a str, Error> {
        if offset >= self.strings.len() {
            return Err(Error::BadString);
        }
        c_string(&self.strings[offset..]).ok_or(Error::BadString)
    }
}

impl<'a> Iterator for Events<'a> {
    type Item = Result<Event<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.saw_end {
            return None;
        }

        loop {
            let token = match read_be_u32(self.structure, self.cursor) {
                Ok(value) => value,
                Err(error) => return self.fail(error),
            };
            self.cursor += 4;

            match token {
                FDT_BEGIN_NODE => {
                    let remaining = match self.structure.get(self.cursor..) {
                        Some(bytes) => bytes,
                        None => return self.fail(Error::Truncated),
                    };
                    let zero = match remaining.iter().position(|byte| *byte == 0) {
                        Some(index) => index,
                        None => return self.fail(Error::BadStructure),
                    };
                    let name_bytes = &remaining[..zero];
                    let name = match str::from_utf8(name_bytes) {
                        Ok(name) => name,
                        Err(_) => return self.fail(Error::BadString),
                    };
                    let consumed = match zero.checked_add(1).and_then(align4) {
                        Some(value) => value,
                        None => return self.fail(Error::BadStructure),
                    };
                    self.cursor = match self.cursor.checked_add(consumed) {
                        Some(value) if value <= self.structure.len() => value,
                        _ => return self.fail(Error::Truncated),
                    };
                    self.depth = match self.depth.checked_add(1) {
                        Some(value) => value,
                        None => return self.fail(Error::BadStructure),
                    };
                    return Some(Ok(Event::BeginNode(name)));
                }
                FDT_END_NODE => {
                    if self.depth == 0 {
                        return self.fail(Error::UnbalancedNodes);
                    }
                    self.depth -= 1;
                    return Some(Ok(Event::EndNode));
                }
                FDT_PROP => {
                    let length = match read_be_u32(self.structure, self.cursor) {
                        Ok(value) => value as usize,
                        Err(error) => return self.fail(error),
                    };
                    let name_offset = match read_be_u32(self.structure, self.cursor + 4) {
                        Ok(value) => value as usize,
                        Err(error) => return self.fail(error),
                    };
                    self.cursor += 8;
                    let end = match self.cursor.checked_add(length) {
                        Some(value) if value <= self.structure.len() => value,
                        _ => return self.fail(Error::Truncated),
                    };
                    let value = &self.structure[self.cursor..end];
                    let padded = match align4(length) {
                        Some(value) => value,
                        None => return self.fail(Error::BadStructure),
                    };
                    self.cursor = match self.cursor.checked_add(padded) {
                        Some(value) if value <= self.structure.len() => value,
                        _ => return self.fail(Error::Truncated),
                    };
                    let name = match self.property_name(name_offset) {
                        Ok(name) => name,
                        Err(error) => return self.fail(error),
                    };
                    return Some(Ok(Event::Property { name, value }));
                }
                FDT_NOP => continue,
                FDT_END => {
                    self.saw_end = true;
                    if self.depth != 0 {
                        return self.fail(Error::UnbalancedNodes);
                    }
                    return None;
                }
                _ => return self.fail(Error::BadStructure),
            }
        }
    }
}

fn checked_range(offset: usize, length: usize, total: usize) -> Result<(), Error> {
    if offset < HEADER_SIZE {
        return Err(Error::BadOffset);
    }
    match offset.checked_add(length) {
        Some(end) if end <= total => Ok(()),
        _ => Err(Error::BadOffset),
    }
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn c_string(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    str::from_utf8(&bytes[..end]).ok()
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.checked_add(4).ok_or(Error::Truncated)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u32::from_be_bytes(raw))
}

fn read_be_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.checked_add(8).ok_or(Error::Truncated)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u64::from_be_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn minimal_blob() -> Vec<u8> {
        let reserve_offset = HEADER_SIZE;
        let structure_offset = reserve_offset + 16;

        let mut structure = Vec::new();
        push_u32(&mut structure, FDT_BEGIN_NODE);
        structure.extend_from_slice(&[0, 0, 0, 0]);
        push_u32(&mut structure, FDT_PROP);
        push_u32(&mut structure, 4);
        push_u32(&mut structure, 0);
        structure.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        push_u32(&mut structure, FDT_END_NODE);
        push_u32(&mut structure, FDT_END);

        let strings = b"test\0";
        let strings_offset = structure_offset + structure.len();
        let total_size = strings_offset + strings.len();

        let mut bytes = vec![0u8; total_size];
        bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        bytes[4..8].copy_from_slice(&(total_size as u32).to_be_bytes());
        bytes[8..12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
        bytes[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        bytes[16..20].copy_from_slice(&(reserve_offset as u32).to_be_bytes());
        bytes[20..24].copy_from_slice(&CURRENT_VERSION.to_be_bytes());
        bytes[24..28].copy_from_slice(&CURRENT_VERSION.to_be_bytes());
        bytes[28..32].copy_from_slice(&0u32.to_be_bytes());
        bytes[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        bytes[36..40].copy_from_slice(&(structure.len() as u32).to_be_bytes());
        bytes[structure_offset..strings_offset].copy_from_slice(&structure);
        bytes[strings_offset..].copy_from_slice(strings);
        bytes
    }

    #[test]
    fn parses_minimal_tree_without_allocation_in_parser() {
        let bytes = minimal_blob();
        let blob = Blob::parse(&bytes).unwrap();
        let events: Vec<_> = blob.events().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], Event::BeginNode(""));
        assert_eq!(
            events[1],
            Event::Property {
                name: "test",
                value: &[0x12, 0x34, 0x56, 0x78]
            }
        );
        assert_eq!(events[2], Event::EndNode);
        assert_eq!(blob.memory_reservations().count(), 0);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bytes = minimal_blob();
        bytes[0] = 0;
        assert_eq!(Blob::parse(&bytes), Err(Error::BadMagic));
    }

    #[test]
    fn rejects_property_name_outside_strings_block() {
        let mut bytes = minimal_blob();
        let property_name_offset = HEADER_SIZE + 16 + 4 + 4 + 4 + 4;
        bytes[property_name_offset..property_name_offset + 4]
            .copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        assert_eq!(Blob::parse(&bytes), Err(Error::BadString));
    }

    #[test]
    fn rejects_unbalanced_structure() {
        let mut bytes = minimal_blob();
        let structure_offset = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let end_node_offset = structure_offset + 24;
        bytes[end_node_offset..end_node_offset + 4].copy_from_slice(&FDT_NOP.to_be_bytes());
        assert_eq!(Blob::parse(&bytes), Err(Error::UnbalancedNodes));
    }
}
