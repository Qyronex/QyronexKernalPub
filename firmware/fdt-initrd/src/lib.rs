// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use kernal_fdt::{Blob, Event};

pub const MAX_NODE_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Fdt(kernal_fdt::Error),
    NodeDepthExceeded,
    MalformedProperty,
    DuplicateProperty,
    IncompleteRange,
}

impl From<kernal_fdt::Error> for Error {
    fn from(value: kernal_fdt::Error) -> Self {
        Self::Fdt(value)
    }
}

/// Physical byte range supplied by firmware/QEMU through `/chosen/linux,initrd-*` or the QEMU
/// bare-metal guest-loader ramdisk module contract.
///
/// `end` is exclusive. This type deliberately describes only transport provenance; it does not
/// parse, trust, map, reserve or execute the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitrdRange {
    start: u64,
    end: u64,
}

impl InitrdRange {
    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn end(self) -> u64 {
        self.end
    }

    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Clone, Copy, Default)]
struct GuestModule {
    compatible_seen: bool,
    reg_seen: bool,
    is_multiboot_module: bool,
    is_ramdisk: bool,
    range: Option<InitrdRange>,
}

/// Discovers an optional initrd range from an already validated FDT blob.
///
/// Preferred Linux firmware transport is the direct `/chosen/linux,initrd-start` +
/// `/chosen/linux,initrd-end` pair. QEMU's ARM `virt` bare-metal ELF boot does not populate those
/// properties for classic `-initrd`; the supported `guest-loader` device instead publishes a direct
/// `/chosen/module@...` node with `multiboot,module` + `multiboot,ramdisk` compatibility and a
/// two-u64 big-endian `reg = <start size>` payload. This parser accepts exactly that bounded alternate
/// transport so the same downstream Core provenance checks remain authoritative.
///
/// A single bound without its peer, duplicate/conflicting transports, malformed widths, duplicate
/// properties, a non-increasing range or multiple ramdisk modules fail closed. Nodes named `chosen`
/// below any path other than the root are ignored.
pub fn parse_initrd(blob: &Blob<'_>) -> Result<Option<InitrdRange>, Error> {
    let mut depth = 0usize;
    let mut chosen_depth = None;
    let mut module_depth = None;
    let mut module = GuestModule::default();
    let mut module_range = None;
    let mut start = None;
    let mut end = None;

    for event in blob.events() {
        match event? {
            Event::BeginNode(name) => {
                if depth == MAX_NODE_DEPTH {
                    return Err(Error::NodeDepthExceeded);
                }
                let direct_root_chosen = depth == 1 && name == "chosen";
                let direct_chosen_module = chosen_depth == Some(depth)
                    && module_depth.is_none()
                    && name.starts_with("module@");
                depth += 1;
                if direct_root_chosen {
                    chosen_depth = Some(depth);
                } else if direct_chosen_module {
                    module_depth = Some(depth);
                    module = GuestModule::default();
                }
            }
            Event::Property { name, value } => {
                if depth == 0 {
                    return Err(Error::MalformedProperty);
                }
                if chosen_depth == Some(depth) {
                    match name {
                        "linux,initrd-start" => set_once(&mut start, decode_address(value)?)?,
                        "linux,initrd-end" => set_once(&mut end, decode_address(value)?)?,
                        _ => {}
                    }
                } else if module_depth == Some(depth) {
                    match name {
                        "compatible" => {
                            if module.compatible_seen {
                                return Err(Error::DuplicateProperty);
                            }
                            module.compatible_seen = true;
                            let (is_module, is_ramdisk) = decode_guest_compatible(value)?;
                            module.is_multiboot_module = is_module;
                            module.is_ramdisk = is_ramdisk;
                        }
                        "reg" => {
                            if module.reg_seen {
                                return Err(Error::DuplicateProperty);
                            }
                            module.reg_seen = true;
                            module.range = Some(decode_guest_reg(value)?);
                        }
                        _ => {}
                    }
                }
            }
            Event::EndNode => {
                if depth == 0 {
                    return Err(Error::MalformedProperty);
                }
                if module_depth == Some(depth) {
                    if module.is_ramdisk && !module.is_multiboot_module {
                        return Err(Error::MalformedProperty);
                    }
                    if module.is_multiboot_module && module.is_ramdisk {
                        let range = module.range.ok_or(Error::MalformedProperty)?;
                        if module_range.replace(range).is_some() {
                            return Err(Error::DuplicateProperty);
                        }
                    }
                    module_depth = None;
                    module = GuestModule::default();
                }
                if chosen_depth == Some(depth) {
                    chosen_depth = None;
                }
                depth -= 1;
            }
        }
    }

    if depth != 0 || module_depth.is_some() {
        return Err(Error::MalformedProperty);
    }

    let linux_range = match (start, end) {
        (None, None) => None,
        (Some(start), Some(end)) if start < end => Some(InitrdRange { start, end }),
        (Some(_), Some(_)) => return Err(Error::MalformedProperty),
        _ => return Err(Error::IncompleteRange),
    };

    match (linux_range, module_range) {
        (Some(_), Some(_)) => Err(Error::DuplicateProperty),
        (Some(range), None) | (None, Some(range)) => Ok(Some(range)),
        (None, None) => Ok(None),
    }
}

fn set_once(slot: &mut Option<u64>, value: u64) -> Result<(), Error> {
    if slot.replace(value).is_some() {
        return Err(Error::DuplicateProperty);
    }
    Ok(())
}

fn decode_address(value: &[u8]) -> Result<u64, Error> {
    match value.len() {
        4 => {
            let raw: [u8; 4] = value.try_into().map_err(|_| Error::MalformedProperty)?;
            Ok(u32::from_be_bytes(raw) as u64)
        }
        8 => {
            let raw: [u8; 8] = value.try_into().map_err(|_| Error::MalformedProperty)?;
            Ok(u64::from_be_bytes(raw))
        }
        _ => Err(Error::MalformedProperty),
    }
}

fn decode_guest_reg(value: &[u8]) -> Result<InitrdRange, Error> {
    if value.len() != 16 {
        return Err(Error::MalformedProperty);
    }
    let start = u64::from_be_bytes(
        value[..8]
            .try_into()
            .map_err(|_| Error::MalformedProperty)?,
    );
    let size = u64::from_be_bytes(
        value[8..]
            .try_into()
            .map_err(|_| Error::MalformedProperty)?,
    );
    if size == 0 {
        return Err(Error::MalformedProperty);
    }
    let end = start.checked_add(size).ok_or(Error::MalformedProperty)?;
    Ok(InitrdRange { start, end })
}

fn decode_guest_compatible(value: &[u8]) -> Result<(bool, bool), Error> {
    if value.is_empty() || *value.last().ok_or(Error::MalformedProperty)? != 0 {
        return Err(Error::MalformedProperty);
    }

    let mut is_module = false;
    let mut is_ramdisk = false;
    let mut cursor = 0usize;
    while cursor < value.len() {
        let tail = &value[cursor..];
        let relative_end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(Error::MalformedProperty)?;
        let item = &tail[..relative_end];
        if item == b"multiboot,module" {
            is_module = true;
        } else if item == b"multiboot,ramdisk" {
            is_ramdisk = true;
        }
        cursor = cursor
            .checked_add(relative_end + 1)
            .ok_or(Error::MalformedProperty)?;
    }
    Ok((is_module, is_ramdisk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_fdt::MAGIC;

    const FDT_BEGIN_NODE: u32 = 1;
    const FDT_END_NODE: u32 = 2;
    const FDT_PROP: u32 = 3;
    const FDT_END: u32 = 9;

    struct Names {
        initrd_start: u32,
        initrd_end: u32,
        compatible: u32,
        reg: u32,
    }

    fn intern(strings: &mut Vec<u8>, name: &str) -> u32 {
        let offset = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        offset
    }

    fn names(strings: &mut Vec<u8>) -> Names {
        Names {
            initrd_start: intern(strings, "linux,initrd-start"),
            initrd_end: intern(strings, "linux,initrd-end"),
            compatible: intern(strings, "compatible"),
            reg: intern(strings, "reg"),
        }
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn align_structure(bytes: &mut Vec<u8>) {
        while bytes.len() & 3 != 0 {
            bytes.push(0);
        }
    }

    fn begin_node(structure: &mut Vec<u8>, name: &str) {
        push_u32(structure, FDT_BEGIN_NODE);
        structure.extend_from_slice(name.as_bytes());
        structure.push(0);
        align_structure(structure);
    }

    fn end_node(structure: &mut Vec<u8>) {
        push_u32(structure, FDT_END_NODE);
    }

    fn property(structure: &mut Vec<u8>, name_offset: u32, value: &[u8]) {
        push_u32(structure, FDT_PROP);
        push_u32(structure, value.len() as u32);
        push_u32(structure, name_offset);
        structure.extend_from_slice(value);
        align_structure(structure);
    }

    fn finish_dtb(mut structure: Vec<u8>, strings: Vec<u8>) -> Vec<u8> {
        push_u32(&mut structure, FDT_END);
        let reserve_offset = 40usize;
        let structure_offset = reserve_offset + 16;
        let strings_offset = structure_offset + structure.len();
        let total_size = strings_offset + strings.len();
        let mut blob = vec![0u8; total_size];
        blob[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        blob[4..8].copy_from_slice(&(total_size as u32).to_be_bytes());
        blob[8..12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
        blob[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        blob[16..20].copy_from_slice(&(reserve_offset as u32).to_be_bytes());
        blob[20..24].copy_from_slice(&17u32.to_be_bytes());
        blob[24..28].copy_from_slice(&16u32.to_be_bytes());
        blob[28..32].copy_from_slice(&0u32.to_be_bytes());
        blob[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        blob[36..40].copy_from_slice(&(structure.len() as u32).to_be_bytes());
        blob[structure_offset..strings_offset].copy_from_slice(&structure);
        blob[strings_offset..].copy_from_slice(&strings);
        blob
    }

    fn chosen_dtb(start: Option<&[u8]>, end: Option<&[u8]>) -> Vec<u8> {
        let mut strings = Vec::new();
        let names = names(&mut strings);
        let mut structure = Vec::new();
        begin_node(&mut structure, "");
        begin_node(&mut structure, "chosen");
        if let Some(value) = start {
            property(&mut structure, names.initrd_start, value);
        }
        if let Some(value) = end {
            property(&mut structure, names.initrd_end, value);
        }
        end_node(&mut structure);
        end_node(&mut structure);
        finish_dtb(structure, strings)
    }

    fn guest_loader_dtb(start: u64, size: u64) -> Vec<u8> {
        let mut strings = Vec::new();
        let names = names(&mut strings);
        let mut structure = Vec::new();
        begin_node(&mut structure, "");
        begin_node(&mut structure, "chosen");
        begin_node(&mut structure, "module@0x48000000");
        property(
            &mut structure,
            names.compatible,
            b"multiboot,module\0multiboot,ramdisk\0",
        );
        let mut reg = [0u8; 16];
        reg[..8].copy_from_slice(&start.to_be_bytes());
        reg[8..].copy_from_slice(&size.to_be_bytes());
        property(&mut structure, names.reg, &reg);
        end_node(&mut structure);
        end_node(&mut structure);
        end_node(&mut structure);
        finish_dtb(structure, strings)
    }

    #[test]
    fn discovers_qemu_style_64_bit_initrd_range() {
        let start = 0x0000_0000_4800_0000u64;
        let end = 0x0000_0000_4801_9000u64;
        let bytes = chosen_dtb(Some(&start.to_be_bytes()), Some(&end.to_be_bytes()));
        let blob = Blob::parse(&bytes).unwrap();
        let range = parse_initrd(&blob).unwrap().unwrap();
        assert_eq!(range.start(), start);
        assert_eq!(range.end(), end);
        assert_eq!(range.len(), end - start);
        assert!(!range.is_empty());
    }

    #[test]
    fn discovers_qemu_guest_loader_ramdisk_module() {
        let start = 0x4800_0000u64;
        let size = 0x19_000u64;
        let bytes = guest_loader_dtb(start, size);
        let range = parse_initrd(&Blob::parse(&bytes).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(range.start(), start);
        assert_eq!(range.end(), start + size);
        assert_eq!(range.len(), size);
    }

    #[test]
    fn accepts_32_bit_bounds_without_native_endian_assumptions() {
        let start = 0x4800_0000u32;
        let end = 0x4800_4000u32;
        let bytes = chosen_dtb(Some(&start.to_be_bytes()), Some(&end.to_be_bytes()));
        let blob = Blob::parse(&bytes).unwrap();
        assert_eq!(
            parse_initrd(&blob).unwrap(),
            Some(InitrdRange {
                start: start as u64,
                end: end as u64,
            })
        );
    }

    #[test]
    fn absent_initrd_is_not_an_error() {
        let mut structure = Vec::new();
        begin_node(&mut structure, "");
        end_node(&mut structure);
        let bytes = finish_dtb(structure, Vec::new());
        let blob = Blob::parse(&bytes).unwrap();
        assert_eq!(parse_initrd(&blob), Ok(None));
    }

    #[test]
    fn incomplete_or_non_increasing_range_fails_closed() {
        let start = 0x4800_0000u64;
        let end = 0x47ff_f000u64;

        let incomplete = chosen_dtb(Some(&start.to_be_bytes()), None);
        assert_eq!(
            parse_initrd(&Blob::parse(&incomplete).unwrap()),
            Err(Error::IncompleteRange)
        );

        let reversed = chosen_dtb(Some(&start.to_be_bytes()), Some(&end.to_be_bytes()));
        assert_eq!(
            parse_initrd(&Blob::parse(&reversed).unwrap()),
            Err(Error::MalformedProperty)
        );
    }

    #[test]
    fn malformed_width_and_duplicate_bound_are_rejected() {
        let malformed = [0u8; 6];
        let end = 0x4800_4000u64;
        let bytes = chosen_dtb(Some(&malformed), Some(&end.to_be_bytes()));
        assert_eq!(
            parse_initrd(&Blob::parse(&bytes).unwrap()),
            Err(Error::MalformedProperty)
        );

        let mut strings = Vec::new();
        let names = names(&mut strings);
        let mut structure = Vec::new();
        begin_node(&mut structure, "");
        begin_node(&mut structure, "chosen");
        property(
            &mut structure,
            names.initrd_start,
            &0x4800_0000u64.to_be_bytes(),
        );
        property(
            &mut structure,
            names.initrd_start,
            &0x4800_1000u64.to_be_bytes(),
        );
        property(
            &mut structure,
            names.initrd_end,
            &0x4800_2000u64.to_be_bytes(),
        );
        end_node(&mut structure);
        end_node(&mut structure);
        let duplicate = finish_dtb(structure, strings);
        assert_eq!(
            parse_initrd(&Blob::parse(&duplicate).unwrap()),
            Err(Error::DuplicateProperty)
        );
    }

    #[test]
    fn malformed_guest_loader_reg_is_rejected() {
        let bytes = guest_loader_dtb(0x4800_0000, 0);
        assert_eq!(
            parse_initrd(&Blob::parse(&bytes).unwrap()),
            Err(Error::MalformedProperty)
        );
    }

    #[test]
    fn nested_chosen_name_is_not_treated_as_root_chosen() {
        let mut strings = Vec::new();
        let names = names(&mut strings);
        let mut structure = Vec::new();
        begin_node(&mut structure, "");
        begin_node(&mut structure, "container");
        begin_node(&mut structure, "chosen");
        property(
            &mut structure,
            names.initrd_start,
            &0x4800_0000u64.to_be_bytes(),
        );
        property(
            &mut structure,
            names.initrd_end,
            &0x4800_1000u64.to_be_bytes(),
        );
        end_node(&mut structure);
        end_node(&mut structure);
        end_node(&mut structure);
        let bytes = finish_dtb(structure, strings);
        assert_eq!(parse_initrd(&Blob::parse(&bytes).unwrap()), Ok(None));
    }
}
