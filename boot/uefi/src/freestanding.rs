// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![no_std]
#![no_main]
#![cfg(target_arch = "x86_64")]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::mem::size_of;
use core::panic::PanicInfo;
use core::ptr::{copy_nonoverlapping, read_volatile, write_bytes, write_volatile};
use core::slice::from_raw_parts_mut;
use kernal_ap_startup_x86_64::{
    BOOTSTRAP_SIZE as AP_BOOTSTRAP_SIZE, LOW_MEMORY_LIMIT as AP_LOW_MEMORY_LIMIT,
    PAGE_SIZE as AP_PAGE_SIZE, trampoline_bytes as ap_trampoline_bytes,
};
use kernal_arch_x86_64::{detect_features, enable_baseline_hardening};
use kernal_bootinfo::{BootInfoV1, MemoryRegionV1, PhysSlice};
use kernal_elf::Image;
use kernal_handoff::{
    DEFAULT_IST_STACK_PAGES, DEFAULT_MEMORY_MAP_PAGES, DEFAULT_STACK_PAGES, HandoffLayout,
    PAGE_SIZE as HANDOFF_PAGE_SIZE, StackLayout,
};
use kernal_kmap_x86_64::{KMAP_SLOTS_PER_CPU, window_base};
use kernal_load_plan::LoadPlan;
use kernal_mapping_plan::{BoundImage, PageAllocator};
use kernal_memory_map::{FirmwareRegion, NormalizedSlice};
use kernal_page_table::{Backend as PageTableBackend, Mapper};
use kernal_paging::MapFlags;
use kernal_recursive_paging_x86_64::RECURSIVE_PML4_SLOT;
use kernal_transition_x86_64::{MAX_IDENTITY_ADDRESS, TransitionArgs, jump, trampoline_bytes};
use uefi::boot::{AllocateType, MemoryType};
use uefi::fs::FileSystem;
use uefi::mem::memory_map::MemoryMap;
use uefi::table::cfg::ConfigTableEntry;
use uefi::{Status, cstr16, entry};

const COM1: u16 = 0x03f8;
const MAX_LOAD_SEGMENTS: usize = 16;
const MAX_AP_CR3_ADDRESS: u64 = u32::MAX as u64;

struct UefiPageAllocator;
impl PageAllocator for UefiPageAllocator {
    fn allocate_pages(&mut self, page_count: usize) -> Option<u64> { allocate_loader_pages(page_count) }
}

struct UefiPageTableBackend;
impl PageTableBackend for UefiPageTableBackend {
    fn allocate_zeroed_table(&mut self) -> Option<u64> {
        allocate_zeroed_loader_pages_below(MAX_AP_CR3_ADDRESS, 1)
    }

    fn read_entry(&self, table_phys: u64, index: usize) -> Option<u64> {
        if index >= 512 || table_phys & (HANDOFF_PAGE_SIZE - 1) != 0 { return None; }
        let address = table_phys.checked_add((index as u64).checked_mul(8)?)?;
        // SAFETY: table pages are loader-owned and identity-addressable before CR3 switch.
        Some(unsafe { read_volatile(address as *const u64) })
    }

    fn write_entry(&mut self, table_phys: u64, index: usize, value: u64) -> bool {
        if index >= 512 || table_phys & (HANDOFF_PAGE_SIZE - 1) != 0 { return false; }
        let Some(offset) = (index as u64).checked_mul(8) else { return false; };
        let Some(address) = table_phys.checked_add(offset) else { return false; };
        // SAFETY: bounds above keep this volatile write inside the loader-owned table page.
        unsafe { write_volatile(address as *mut u64, value) };
        true
    }
}

struct PreparedAddressSpace {
    root_table: u64,
    stack_physical: u64,
    ist_physical: [u64; 3],
    bootinfo_physical: u64,
    memory_map_physical: u64,
    memory_map_capacity: usize,
    trampoline_physical: u64,
    ap_trampoline_physical: u64,
    layout: HandoffLayout,
}

#[entry]
fn main() -> Status {
    serial_init();
    serial_write("KERNAL/BOOT: UEFI loader entered\r\n");

    if uefi::helpers::init().is_err() { return fail("KERNAL/BOOT: uefi helper init failed\r\n"); }
    let cpu_features = detect_features();
    if !cpu_features.nx { return fail("KERNAL/BOOT: CPU lacks required NX support\r\n"); }

    let protocol = match uefi::boot::get_image_file_system(uefi::boot::image_handle()) {
        Ok(protocol) => protocol,
        Err(_) => return fail("KERNAL/BOOT: image filesystem unavailable\r\n"),
    };
    let mut fs = FileSystem::new(protocol);
    let bytes = match fs.read(cstr16!("\\KERNAL\\CORE.ELF")) {
        Ok(bytes) => bytes,
        Err(_) => return fail("KERNAL/BOOT: CORE.ELF read failed\r\n"),
    };

    let image = match Image::parse(&bytes) {
        Ok(image) => image,
        Err(_) => return fail("KERNAL/BOOT: CORE.ELF validation failed\r\n"),
    };
    let plan = match LoadPlan::<MAX_LOAD_SEGMENTS>::from_image(&image) {
        Ok(plan) => plan,
        Err(_) => return fail("KERNAL/BOOT: CORE.ELF load plan rejected\r\n"),
    };
    let mut allocator = UefiPageAllocator;
    let bound = match BoundImage::allocate(&plan, &mut allocator) {
        Ok(bound) => bound,
        Err(_) => return fail("KERNAL/BOOT: physical kernel allocation failed\r\n"),
    };
    if materialize_kernel(&bytes, &bound).is_err() {
        return fail("KERNAL/BOOT: physical kernel materialization failed\r\n");
    }

    let address_space = match build_address_space(&bound) {
        Ok(address_space) => address_space,
        Err(()) => return fail("KERNAL/BOOT: kernel page-table construction failed\r\n"),
    };
    if address_space.layout.validate_kernel_entry(bound.entry()).is_err() {
        return fail("KERNAL/BOOT: kernel entry rejected by handoff layout\r\n");
    }
    if address_space.root_table == 0
        || address_space.root_table >= (1u64 << 32)
        || address_space.stack_physical == 0
        || address_space.ist_physical.iter().any(|value| *value == 0)
        || address_space.bootinfo_physical == 0
        || address_space.memory_map_physical == 0
        || address_space.memory_map_capacity == 0
        || address_space.trampoline_physical == 0
        || address_space.ap_trampoline_physical == 0
    {
        return fail("KERNAL/BOOT: impossible bootstrap allocation\r\n");
    }

    let transition = TransitionArgs {
        root_table: address_space.root_table,
        stack_pointer: address_space.layout.stack.initial_rsp,
        kernel_entry: bound.entry(),
        bootinfo_virtual: address_space.layout.bootinfo.start,
    };
    if transition.validate().is_err() { return fail("KERNAL/BOOT: transition arguments rejected\r\n"); }

    let rsdp_phys = find_rsdp();
    serial_write("KERNAL/BOOT: all pre-exit allocations complete\r\n");

    // `Image` is Copy and has no resources to release. `LoadPlan`, the file bytes and filesystem
    // handle are the actual pre-ExitBootServices values whose lifetimes must end here.
    drop(plan);
    drop(bytes);
    drop(fs);

    serial_write("KERNAL/BOOT: exiting UEFI boot services\r\n");
    // SAFETY: all protocol/pool objects are gone; no boot service is used after this call.
    let final_map = unsafe { uefi::boot::exit_boot_services(None) };

    let memory_region_count = match publish_final_memory_map(&final_map, &address_space) {
        Ok(count) => count,
        Err(()) => post_exit_fail("KERNAL/BOOT: final memory map normalization failed\r\n"),
    };
    if publish_bootinfo(&address_space, memory_region_count, rsdp_phys).is_err() {
        post_exit_fail("KERNAL/BOOT: BootInfo publication failed\r\n");
    }

    // SAFETY: UEFI executes this loader in ring 0. NX was feature-detected, and the new tables
    // were constructed with NX semantics. WP prevents supervisor writes through read-only PTEs.
    if unsafe { enable_baseline_hardening(cpu_features) }.is_err() {
        post_exit_fail("KERNAL/BOOT: baseline CPU hardening failed\r\n");
    }

    serial_write("KERNAL/BOOT: ExitBootServices complete\r\n");
    serial_write("KERNAL/BOOT: normalized BootInfoV1 ready\r\n");
    serial_write("KERNAL/BOOT: guarded exception stacks ready\r\n");
    serial_write("KERNAL/BOOT: recursive paging and BSP kmap path ready\r\n");
    serial_write("KERNAL/BOOT: low-memory AP bootstrap reserved\r\n");
    serial_write("KERNAL/BOOT: switching to kernel CR3\r\n");

    // SAFETY: the transition trampoline is identity-mapped R-X in the new address space.
    unsafe { jump(address_space.trampoline_physical, transition) }
}

fn find_rsdp() -> u64 {
    let mut acpi1 = 0u64;
    let mut acpi2 = 0u64;
    uefi::system::with_config_table(|entries| {
        for entry in entries {
            if entry.guid == ConfigTableEntry::ACPI2_GUID { acpi2 = entry.address as u64; }
            else if entry.guid == ConfigTableEntry::ACPI_GUID { acpi1 = entry.address as u64; }
        }
    });
    if acpi2 != 0 { acpi2 } else { acpi1 }
}

fn publish_final_memory_map(final_map: &impl MemoryMap, address_space: &PreparedAddressSpace) -> Result<usize, ()> {
    // SAFETY: preallocated zeroed storage can hold exactly memory_map_capacity ABI entries.
    let storage = unsafe {
        from_raw_parts_mut(address_space.memory_map_physical as *mut MemoryRegionV1, address_space.memory_map_capacity)
    };
    let mut normalized = NormalizedSlice::new(storage);
    for descriptor in final_map.entries() {
        normalized.push_firmware(FirmwareRegion {
            memory_type: descriptor.ty.0,
            physical_start: descriptor.phys_start,
            page_count: descriptor.page_count,
            attributes: descriptor.att.bits(),
        }).map_err(|_| ())?;
    }
    Ok(normalized.len())
}

fn publish_bootinfo(address_space: &PreparedAddressSpace, memory_region_count: usize, rsdp_phys: u64) -> Result<(), ()> {
    let count = u32::try_from(memory_region_count).map_err(|_| ())?;
    let bytes = memory_region_count.checked_mul(size_of::<MemoryRegionV1>()).ok_or(())?;
    let mut info = BootInfoV1::empty();
    info.memory_map = PhysSlice {
        phys_addr: address_space.memory_map_physical,
        len: u64::try_from(bytes).map_err(|_| ())?,
    };
    info.memory_region_count = count;
    info.rsdp_phys = rsdp_phys;
    info.ap_trampoline = PhysSlice {
        phys_addr: address_space.ap_trampoline_physical,
        len: AP_BOOTSTRAP_SIZE,
    };
    if !info.ap_trampoline_is_valid() { return Err(()); }
    // SAFETY: BootInfo has a dedicated zeroed loader-data page and its size was checked.
    unsafe { write_volatile(address_space.bootinfo_physical as *mut BootInfoV1, info) };
    Ok(())
}

fn allocate_loader_pages(page_count: usize) -> Option<u64> {
    if page_count == 0 { return None; }
    uefi::boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, page_count)
        .ok()
        .map(|base| base.as_ptr() as u64)
}

fn allocate_loader_pages_below(max_address: u64, page_count: usize) -> Option<u64> {
    if page_count == 0 { return None; }
    uefi::boot::allocate_pages(AllocateType::MaxAddress(max_address), MemoryType::LOADER_DATA, page_count)
        .ok()
        .map(|base| base.as_ptr() as u64)
}

fn allocate_transition_page() -> Option<u64> {
    allocate_loader_pages_below(MAX_IDENTITY_ADDRESS, 1)
}

fn allocate_zeroed_loader_pages(page_count: usize) -> Option<u64> {
    let address = allocate_loader_pages(page_count)?;
    zero_pages(address, page_count)?;
    Some(address)
}

fn allocate_zeroed_loader_pages_below(max_address: u64, page_count: usize) -> Option<u64> {
    let address = allocate_loader_pages_below(max_address, page_count)?;
    zero_pages(address, page_count)?;
    Some(address)
}

fn zero_pages(address: u64, page_count: usize) -> Option<()> {
    let len = page_count.checked_mul(HANDOFF_PAGE_SIZE as usize)?;
    // SAFETY: caller just allocated this loader-data range exclusively.
    unsafe { write_bytes(address as *mut u8, 0, len) };
    Some(())
}

fn allocate_ap_bootstrap() -> Option<u64> {
    let page_count = usize::try_from(AP_BOOTSTRAP_SIZE / AP_PAGE_SIZE).ok()?;
    let address = allocate_zeroed_loader_pages_below(AP_LOW_MEMORY_LIMIT - 1, page_count)?;
    let end = address.checked_add(AP_BOOTSTRAP_SIZE)?;
    if address < AP_PAGE_SIZE || end > AP_LOW_MEMORY_LIMIT || address & (AP_PAGE_SIZE - 1) != 0 {
        return None;
    }
    Some(address)
}

fn materialize_kernel<const N: usize>(bytes: &[u8], image: &BoundImage<N>) -> Result<(), ()> {
    for segment in image.segments() {
        let allocation_len = segment.allocation_len().map_err(|_| ())?;
        let file_end = segment.plan.file_end().map_err(|_| ())?;
        let source = bytes.get(segment.plan.file_offset..file_end).ok_or(())?;
        let destination = segment.file_destination().map_err(|_| ())?;
        let allocation_end = segment.physical_end().map_err(|_| ())?;
        let copy_end = destination.checked_add(source.len() as u64).ok_or(())?;
        if copy_end > allocation_end { return Err(()); }
        // SAFETY: BoundImage owns this loader-data allocation exclusively.
        unsafe { write_bytes(segment.physical_start as *mut u8, 0, allocation_len) };
        // SAFETY: source is valid and destination was checked to lie in the allocation.
        unsafe { copy_nonoverlapping(source.as_ptr(), destination as *mut u8, source.len()) };
    }
    Ok(())
}

fn build_address_space<const N: usize>(image: &BoundImage<N>) -> Result<PreparedAddressSpace, ()> {
    let layout = HandoffLayout::default_layout().map_err(|_| ())?;
    let mut backend = UefiPageTableBackend;
    let root_table = backend.allocate_zeroed_table().ok_or(())?;
    if root_table >= (1u64 << 32) { return Err(()); }
    let mut mapper = Mapper::new(&mut backend, root_table).map_err(|_| ())?;

    for page in image.pages() {
        let page = page.map_err(|_| ())?;
        let mut flags = MapFlags::READ.union(MapFlags::GLOBAL);
        if page.perms.writable { flags = flags.union(MapFlags::WRITE); }
        if page.perms.executable { flags = flags.union(MapFlags::EXECUTE); }
        mapper.map_page(page.virtual_address, page.physical_address, flags).map_err(|_| ())?;
    }

    let stack_physical = allocate_and_map_stack(&mut mapper, layout.stack, DEFAULT_STACK_PAGES)?;
    let ist_physical = [
        allocate_and_map_stack(&mut mapper, layout.exception_stacks.double_fault, DEFAULT_IST_STACK_PAGES)?,
        allocate_and_map_stack(&mut mapper, layout.exception_stacks.nmi, DEFAULT_IST_STACK_PAGES)?,
        allocate_and_map_stack(&mut mapper, layout.exception_stacks.machine_check, DEFAULT_IST_STACK_PAGES)?,
    ];

    let bootinfo_physical = allocate_zeroed_loader_pages(1).ok_or(())?;
    mapper.map_page(
        layout.bootinfo.start,
        bootinfo_physical,
        MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::GLOBAL),
    ).map_err(|_| ())?;

    let memory_map_physical = allocate_zeroed_loader_pages(DEFAULT_MEMORY_MAP_PAGES).ok_or(())?;
    map_linear_range(
        &mut mapper,
        layout.memory_map.start,
        memory_map_physical,
        DEFAULT_MEMORY_MAP_PAGES,
        MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::GLOBAL),
    )?;

    // Pre-create CPU0's complete kmap page-table path without installing leaf mappings.
    let bsp_kmap_base = window_base(0).map_err(|_| ())?;
    let bsp_kmap_last = bsp_kmap_base
        .checked_add(((KMAP_SLOTS_PER_CPU - 1) as u64).checked_mul(HANDOFF_PAGE_SIZE).ok_or(())?)
        .ok_or(())?;
    let first_leaf_table = mapper.ensure_leaf_table(bsp_kmap_base, false).map_err(|_| ())?;
    let last_leaf_table = mapper.ensure_leaf_table(bsp_kmap_last, false).map_err(|_| ())?;
    if first_leaf_table != last_leaf_table { return Err(()); }

    // PML4[510] recursively maps the root. It is RW, supervisor-only and NX.
    mapper.install_recursive_slot(RECURSIVE_PML4_SLOT).map_err(|_| ())?;

    let trampoline_physical = allocate_transition_page().ok_or(())?;
    // SAFETY: fresh single-page loader allocation.
    unsafe { write_bytes(trampoline_physical as *mut u8, 0, HANDOFF_PAGE_SIZE as usize) };
    let trampoline = trampoline_bytes().map_err(|_| ())?;
    if trampoline.len() > HANDOFF_PAGE_SIZE as usize { return Err(()); }
    // SAFETY: destination is the fresh transition page.
    unsafe { copy_nonoverlapping(trampoline.as_ptr(), trampoline_physical as *mut u8, trampoline.len()) };
    mapper.map_page(
        trampoline_physical,
        trampoline_physical,
        MapFlags::READ.union(MapFlags::EXECUTE).union(MapFlags::GLOBAL),
    ).map_err(|_| ())?;

    // Reserve two contiguous pages below 1 MiB for SIPI startup. The code page is immutable R-X
    // in the kernel CR3; the second page is a mutable RW-NX mailbox/GDT shared by one AP at a time.
    let ap_trampoline_physical = allocate_ap_bootstrap().ok_or(())?;
    let ap_code = ap_trampoline_bytes().map_err(|_| ())?;
    if ap_code.len() > AP_PAGE_SIZE as usize { return Err(()); }
    // SAFETY: the two-page region is freshly allocated and zeroed; first page owns the code.
    unsafe { copy_nonoverlapping(ap_code.as_ptr(), ap_trampoline_physical as *mut u8, ap_code.len()) };
    mapper.map_page(
        ap_trampoline_physical,
        ap_trampoline_physical,
        MapFlags::READ.union(MapFlags::EXECUTE).union(MapFlags::GLOBAL),
    ).map_err(|_| ())?;
    mapper.map_page(
        ap_trampoline_physical.checked_add(AP_PAGE_SIZE).ok_or(())?,
        ap_trampoline_physical.checked_add(AP_PAGE_SIZE).ok_or(())?,
        MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::GLOBAL),
    ).map_err(|_| ())?;

    let map_bytes = DEFAULT_MEMORY_MAP_PAGES.checked_mul(HANDOFF_PAGE_SIZE as usize).ok_or(())?;
    let memory_map_capacity = map_bytes.checked_div(size_of::<MemoryRegionV1>()).ok_or(())?;
    if memory_map_capacity == 0 || size_of::<BootInfoV1>() > HANDOFF_PAGE_SIZE as usize { return Err(()); }

    Ok(PreparedAddressSpace {
        root_table,
        stack_physical,
        ist_physical,
        bootinfo_physical,
        memory_map_physical,
        memory_map_capacity,
        trampoline_physical,
        ap_trampoline_physical,
        layout,
    })
}

fn allocate_and_map_stack<B: PageTableBackend>(
    mapper: &mut Mapper<'_, B>, layout: StackLayout, pages: usize,
) -> Result<u64, ()> {
    let physical = allocate_zeroed_loader_pages(pages).ok_or(())?;
    map_linear_range(
        mapper,
        layout.mapped.start,
        physical,
        pages,
        MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::GLOBAL),
    )?;
    Ok(physical)
}

fn map_linear_range<B: PageTableBackend>(
    mapper: &mut Mapper<'_, B>,
    virtual_start: u64,
    physical_start: u64,
    pages: usize,
    flags: MapFlags,
) -> Result<(), ()> {
    for index in 0..pages {
        let offset = (index as u64).checked_mul(HANDOFF_PAGE_SIZE).ok_or(())?;
        mapper.map_page(
            virtual_start.checked_add(offset).ok_or(())?,
            physical_start.checked_add(offset).ok_or(())?,
            flags,
        ).map_err(|_| ())?;
    }
    Ok(())
}

fn fail(message: &str) -> Status { serial_write(message); Status::LOAD_ERROR }
fn post_exit_fail(message: &str) -> ! { serial_write(message); loop { halt(); } }

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_write("KERNAL/PANIC: boot loader panic\r\n");
    loop { halt(); }
}

fn serial_init() {
    // SAFETY: COM1 is the conventional x86 legacy serial port used only for early diagnostics.
    unsafe {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1, 0x03);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xc7);
        outb(COM1 + 4, 0x0b);
    }
}

fn serial_write(message: &str) {
    for byte in message.bytes() {
        // SAFETY: COM1 line-status polling is confined to early diagnostics.
        while unsafe { inb(COM1 + 5) } & 0x20 == 0 {}
        // SAFETY: COM1 transmit register accepts one byte when THR-empty is set.
        unsafe { outb(COM1, byte) };
    }
}

fn halt() { unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) }; }

unsafe fn outb(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)) };
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags)); }
    value
}