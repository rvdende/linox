#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::{
    pe::ImageSummary,
    trusted::{
        boot::Handoff,
        control,
        page_table::{invalidate_page, PageTable as TableView},
        root,
    },
    UefiMemoryDescriptor, EFI_RUNTIME_SERVICES_CODE, EFI_RUNTIME_SERVICES_DATA,
};

const ENTRY_COUNT: usize = 512;
const DIRECTORY_COUNT: usize = 4;
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const PAGE_SIZE: usize = 4096;
// Every 2 MiB region in the bounded 4 GiB bootstrap map may require a 4 KiB
// leaf table. This is the architectural maximum for that map, not a workload
// cap; guarded per-CPU stacks must never compete for a fixed subset.
const MAX_FINE_TABLES: usize = DIRECTORY_COUNT * ENTRY_COUNT;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const WRITE_THROUGH: u64 = 1 << 3;
const ACCESSED: u64 = 1 << 5;
const CACHE_DISABLE: u64 = 1 << 4;
const DIRTY: u64 = 1 << 6;
const LARGE_PAGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const ADDRESS_MASK: usize = 0x000f_ffff_ffff_f000;
const CR0_WRITE_PROTECT: u64 = 1 << 16;

pub(crate) const INITIAL_IDENTITY_LIMIT: usize = 1usize << 32;
pub(crate) const DIRECT_MAP_BASE: usize = 0xffff_8000_0000_0000;
const DIRECT_MAP_PML4_INDEX: usize = 256;
const MMIO_PDPT_INDEX: usize = ENTRY_COUNT - 1;
const MMIO_WINDOW_BASE: usize = DIRECT_MAP_BASE + MMIO_PDPT_INDEX * (1 << 30);
const FRAMEBUFFER_PDPT_INDEX: usize = ENTRY_COUNT - 2;
const FRAMEBUFFER_WINDOW_BASE: usize = DIRECT_MAP_BASE + FRAMEBUFFER_PDPT_INDEX * (1 << 30);
const DEVICE_PDPT_INDEX: usize = ENTRY_COUNT - 3;
const DEVICE_WINDOW_BASE: usize = DIRECT_MAP_BASE + DEVICE_PDPT_INDEX * (1 << 30);
/// Kernel virtual space for kernel stacks, mapped a page at a time so that
/// unmapped guard pages can sit between them (see `map_kernel_stack_page`):
/// one page directory per GiB, enough for a stack for each of thousands of
/// processes. It lies below the device window, so the direct map stops
/// below it.
const KERNEL_STACK_DIRECTORY_COUNT: usize = 4;
const KERNEL_STACK_PDPT_INDEX: usize = ENTRY_COUNT - 3 - KERNEL_STACK_DIRECTORY_COUNT;
pub(crate) const KERNEL_STACK_WINDOW_BASE: usize =
    DIRECT_MAP_BASE + KERNEL_STACK_PDPT_INDEX * (1 << 30);
pub(crate) const KERNEL_STACK_WINDOW_SIZE: usize = KERNEL_STACK_DIRECTORY_COUNT << 30;
/// Register ranges the device window maps for drivers beyond the reference
/// devices, such as USB host controllers.
pub(crate) const MAX_DEVICE_REGIONS: usize = 4;
const GIBIBYTE: u64 = 1 << 30;
const CPUID_EXTENDED_FEATURES: u32 = 0x8000_0001;
const CPUID_PAGE_1GB: u32 = 1 << 26;
const USER_REGION_BASE: u64 = 1_u64 << 39;

#[derive(Clone, Copy)]
pub(crate) struct MmioMapping {
    physical_page: u64,
    physical_start: u64,
    virtual_page: usize,
    length: usize,
    mapped_length: usize,
    writable: bool,
}

pub(crate) struct InitialMmioMappings {
    pub(crate) block_transport: MmioMapping,
    pub(crate) block_msix: MmioMapping,
    pub(crate) iommu: MmioMapping,
    pub(crate) network_common: MmioMapping,
    pub(crate) network_device: MmioMapping,
    pub(crate) network_notification: MmioMapping,
    pub(crate) network_msix: MmioMapping,
    /// Write-combining alias of the firmware framebuffer, when one was requested.
    pub(crate) framebuffer: Option<FramebufferWindow>,
    /// Uncached mappings of the requested device register ranges, in order.
    pub(crate) devices: [Option<MmioMapping>; MAX_DEVICE_REGIONS],
}

/// The kernel's write-combining mapping of the firmware framebuffer: the
/// virtual address of its first byte and the bytes mapped from there. Only
/// this module makes one (`trusted::pixels::PixelBuffer::window` relies on
/// it).
#[derive(Clone, Copy)]
pub(crate) struct FramebufferWindow {
    address: usize,
    length: usize,
}

impl FramebufferWindow {
    pub(crate) fn address(self) -> usize {
        self.address
    }

    pub(crate) fn len(self) -> usize {
        self.length
    }
}

impl MmioMapping {
    pub(crate) fn address(self, physical: u64, length: usize) -> Option<usize> {
        if length == 0 || physical < self.physical_start {
            return None;
        }
        let requested_offset = usize::try_from(physical - self.physical_start).ok()?;
        let requested_end = requested_offset.checked_add(length)?;
        let page_offset = usize::try_from(physical - self.physical_page).ok()?;
        (requested_end <= self.length)
            .then(|| self.virtual_page.checked_add(page_offset))
            .flatten()
    }
}

pub(crate) fn user_context_matches_layout(instruction: u64, stack: u64) -> bool {
    let code_end = USER_REGION_BASE + PAGE_SIZE as u64;
    let first_stack_start = USER_REGION_BASE + 2 * PAGE_SIZE as u64;
    let first_stack_end = USER_REGION_BASE + 3 * PAGE_SIZE as u64;
    let second_stack_start = USER_REGION_BASE + 4 * PAGE_SIZE as u64;
    let second_stack_end = USER_REGION_BASE + 5 * PAGE_SIZE as u64;
    (USER_REGION_BASE..code_end).contains(&instruction)
        && ((first_stack_start < stack && stack <= first_stack_end)
            || (second_stack_start < stack && stack <= second_stack_end))
}

pub(crate) fn verify_user_context_layout_invariants() -> bool {
    let page = PAGE_SIZE as u64;
    user_context_matches_layout(USER_REGION_BASE, USER_REGION_BASE + 3 * page)
        && user_context_matches_layout(USER_REGION_BASE + page - 1, USER_REGION_BASE + 2 * page + 1)
        && user_context_matches_layout(USER_REGION_BASE, USER_REGION_BASE + 5 * page)
        && !user_context_matches_layout(USER_REGION_BASE - 1, USER_REGION_BASE + 3 * page)
        && !user_context_matches_layout(USER_REGION_BASE + page, USER_REGION_BASE + 3 * page)
        && !user_context_matches_layout(USER_REGION_BASE, USER_REGION_BASE + 2 * page)
        && !user_context_matches_layout(USER_REGION_BASE, USER_REGION_BASE + 3 * page + 1)
        && !user_context_matches_layout(USER_REGION_BASE, USER_REGION_BASE + 4 * page)
        && !user_context_matches_layout(USER_REGION_BASE, USER_REGION_BASE + 5 * page + 1)
}

pub(crate) struct ValidatedUserRootFrames {
    base: [u64; 15],
    base_count: usize,
    dma: Option<u64>,
    native_executable_pages: [u64; 3],
    native_image_pages: u8,
    native_stack_page: u8,
    native_stack_pages: u8,
    native_table: u64,
}

impl ValidatedUserRootFrames {
    pub(crate) fn base(&self) -> &[u64] {
        &self.base[..self.base_count]
    }

    pub(crate) const fn base_count(&self) -> usize {
        self.base_count
    }

    pub(crate) fn frames_owned_by(&self, owner: crate::memory::FrameOwner) -> bool {
        if self.base_count <= self.base.len() {
            return crate::memory::frame_addresses_owned_by(owner, self.base());
        }
        let Some(table) = TableView::from_physical(self.native_table) else {
            return false;
        };
        let hierarchy = &self.base[..4];
        crate::memory::frame_addresses_owned_by(owner, hierarchy)
            && (0..usize::from(self.native_image_pages)).all(|index| {
                let frame = table.get(index) & ADDRESS_MASK as u64;
                crate::memory::frame_addresses_owned_by(owner, &[frame])
            })
            && (0..usize::from(self.native_stack_pages))
                .map(|offset| usize::from(self.native_stack_page) + offset)
                .chain(core::iter::once(
                    usize::from(self.native_stack_page) + usize::from(self.native_stack_pages) + 1,
                ))
                .all(|index| {
                    let frame = table.get(index) & ADDRESS_MASK as u64;
                    crate::memory::frame_addresses_owned_by(owner, &[frame])
                })
    }

    pub(crate) fn dma(&self) -> Option<u64> {
        self.dma
    }

    pub(crate) fn context_matches(&self, instruction: u64, stack: u64) -> bool {
        if self.base_count == 7 {
            return user_context_matches_layout(instruction, stack);
        }
        let stack_start = USER_REGION_BASE + u64::from(self.native_stack_page) * PAGE_SIZE as u64;
        let stack_end = stack_start + u64::from(self.native_stack_pages) * PAGE_SIZE as u64;
        let executable_page = instruction
            .checked_sub(USER_REGION_BASE)
            .map(|offset| offset / PAGE_SIZE as u64)
            .filter(|page| *page < u64::from(self.native_image_pages))
            .is_some_and(|page| {
                let page = page as usize;
                self.native_executable_pages[page / 64] & (1_u64 << (page % 64)) != 0
            });
        executable_page && stack_start < stack && stack <= stack_end
    }
}

pub(crate) fn validated_user_root_frames(root: u64) -> Option<ValidatedUserRootFrames> {
    if root == 0 || root >= INITIAL_IDENTITY_LIMIT as u64 || !root.is_multiple_of(PAGE_SIZE as u64)
    {
        return None;
    }
    let entries = TableView::from_physical(root)?;
    let kernel = static_table(&PAGING.pml4)?;
    let kernel_entry = kernel.get(0);
    let kernel_direct_entry = kernel.get(DIRECT_MAP_PML4_INDEX);
    let shared = entries.get(0);
    let user = entries.get(1);
    let direct = entries.get(DIRECT_MAP_PML4_INDEX);
    if shared != kernel_entry
        || direct != kernel_direct_entry
        || shared & PRESENT == 0
        || shared & USER != 0
        || direct & PRESENT == 0
        || direct & USER != 0
        || user & (PRESENT | WRITABLE | USER) != (PRESENT | WRITABLE | USER)
        || user & (LARGE_PAGE | NO_EXECUTE) != 0
        || !(2..ENTRY_COUNT).all(|index| index == DIRECT_MAP_PML4_INDEX || entries.get(index) == 0)
    {
        return None;
    }
    let pdpt_address = user & ADDRESS_MASK as u64;
    let pdpt_entry = single_user_table_entry(pdpt_address)?;
    let directory_address = pdpt_entry & ADDRESS_MASK as u64;
    let directory_entry = single_user_table_entry(directory_address)?;
    let table_address = directory_entry & ADDRESS_MASK as u64;
    if table_address == 0 || table_address >= INITIAL_IDENTITY_LIMIT as u64 {
        return None;
    }
    let table = TableView::from_physical(table_address)?;
    let [code, first_guard, first_stack, second_guard, second_stack, device, dma, notification] =
        core::array::from_fn(|index| table.get(index));
    let code_address = code & ADDRESS_MASK as u64;
    let first_stack_address = first_stack & ADDRESS_MASK as u64;
    let second_stack_address = second_stack & ADDRESS_MASK as u64;
    let device_address = device & ADDRESS_MASK as u64;
    let dma_address = dma & ADDRESS_MASK as u64;
    let notification_address = notification & ADDRESS_MASK as u64;
    let device_flags = PRESENT | USER | WRITE_THROUGH | CACHE_DISABLE | NO_EXECUTE;
    let device_valid = device == 0
        || (device_address >= INITIAL_IDENTITY_LIMIT as u64
            && device & device_flags == device_flags
            && device & LARGE_PAGE == 0
            && (device & DIRTY == 0 || device & WRITABLE != 0)
            && device & !(ADDRESS_MASK as u64 | device_flags | WRITABLE | ACCESSED | DIRTY) == 0);
    let dma_flags = PRESENT | WRITABLE | USER | NO_EXECUTE;
    let dma_valid = dma == 0
        || (dma_address != 0
            && dma_address < INITIAL_IDENTITY_LIMIT as u64
            && dma & dma_flags == dma_flags
            && dma & LARGE_PAGE == 0
            && dma & !(ADDRESS_MASK as u64 | dma_flags | ACCESSED | DIRTY) == 0);
    let notification_flags = PRESENT | WRITABLE | USER | WRITE_THROUGH | CACHE_DISABLE | NO_EXECUTE;
    let notification_valid = notification == 0
        || (device != 0
            && notification_address >= INITIAL_IDENTITY_LIMIT as u64
            && notification & notification_flags == notification_flags
            && notification & LARGE_PAGE == 0
            && notification & !(ADDRESS_MASK as u64 | notification_flags | ACCESSED | DIRTY) == 0
            && notification_address != device_address);
    let legacy_frames = [
        root,
        pdpt_address,
        directory_address,
        table_address,
        code_address,
        first_stack_address,
        second_stack_address,
    ];
    let legacy_valid = code & (PRESENT | USER) == (PRESENT | USER)
        && code & (WRITABLE | NO_EXECUTE | LARGE_PAGE) == 0
        && first_guard == 0
        && first_stack & (PRESENT | WRITABLE | USER | NO_EXECUTE)
            == (PRESENT | WRITABLE | USER | NO_EXECUTE)
        && first_stack & LARGE_PAGE == 0
        && second_guard == 0
        && second_stack & (PRESENT | WRITABLE | USER | NO_EXECUTE)
            == (PRESENT | WRITABLE | USER | NO_EXECUTE)
        && second_stack & LARGE_PAGE == 0
        && device_valid
        && dma_valid
        && notification_valid
        && (8..ENTRY_COUNT).all(|index| table.get(index) == 0)
        && legacy_frames
            .iter()
            .all(|frame| *frame != 0 && *frame < INITIAL_IDENTITY_LIMIT as u64)
        && legacy_frames
            .iter()
            .enumerate()
            .all(|(index, frame)| !legacy_frames[index + 1..].contains(frame))
        && (dma == 0 || !legacy_frames.contains(&dma_address));
    if legacy_valid {
        let mut base = [0_u64; 15];
        base[..legacy_frames.len()].copy_from_slice(&legacy_frames);
        return Some(ValidatedUserRootFrames {
            base,
            base_count: legacy_frames.len(),
            dma: (dma != 0).then_some(dma_address),
            native_executable_pages: [0; 3],
            native_image_pages: 0,
            native_stack_page: 0,
            native_stack_pages: 0,
            native_table: 0,
        });
    }

    let native_entry = |index: usize| table.get(index);
    let owned_flags = PRESENT | USER;
    let read_only_nx = owned_flags | NO_EXECUTE;
    let executable = owned_flags;
    let stack_flags = owned_flags | WRITABLE | NO_EXECUTE;
    let mmio_flags = stack_flags | WRITE_THROUGH | CACHE_DISABLE;
    let flags_match = |entry: u64, expected: u64| {
        entry & !(ACCESSED | DIRTY) == expected && (entry & DIRTY == 0 || expected & WRITABLE != 0)
    };
    let network_layout = native_entry(15) & PRESENT != 0;
    let controller_layout = !network_layout && native_entry(7) & PRESENT != 0;
    let image_capacity = if network_layout {
        crate::address_space::NATIVE_NETWORK_IMAGE_PAGES
    } else if controller_layout {
        crate::address_space::NATIVE_CONTROLLER_IMAGE_PAGES
    } else {
        7
    };
    let stack_pages = if network_layout {
        crate::address_space::NATIVE_NETWORK_STACK_PAGES
    } else {
        2
    };
    let stack_page = image_capacity + 1;
    let boot_info_page = stack_page + stack_pages + 1;
    let image_pages = (0..image_capacity)
        .take_while(|index| native_entry(*index) & PRESENT != 0)
        .count();
    let mut native_executable_pages = [0_u64; 3];
    let image_valid = image_pages != 0
        && (image_pages..image_capacity).all(|index| native_entry(index) == 0)
        && (0..image_pages).all(|index| {
            let entry = native_entry(index);
            let address = entry & ADDRESS_MASK as u64;
            let valid = address != 0
                && address < INITIAL_IDENTITY_LIMIT as u64
                && (flags_match(entry, address | executable)
                    || flags_match(entry, address | read_only_nx)
                    || flags_match(entry, address | stack_flags));
            if valid && entry & NO_EXECUTE == 0 {
                native_executable_pages[index / 64] |= 1_u64 << (index % 64);
            }
            valid
        })
        && native_executable_pages != [0; 3];
    let native_dma = if controller_layout {
        0
    } else {
        native_entry(boot_info_page + 1)
    };
    let native_dma_address = native_dma & ADDRESS_MASK as u64;
    let dma_valid = native_dma == 0
        || (flags_match(native_dma, native_dma_address | stack_flags)
            && native_dma_address != 0
            && native_dma_address < INITIAL_IDENTITY_LIMIT as u64);
    let common_page = boot_info_page + 2;
    let notification_page = boot_info_page + 3;
    let mmio_valid = if native_entry(common_page) == 0 && native_entry(notification_page) == 0 {
        true
    } else {
        flags_match(
            native_entry(common_page),
            (native_entry(common_page) & ADDRESS_MASK as u64) | mmio_flags,
        ) && flags_match(
            native_entry(notification_page),
            (native_entry(notification_page) & ADDRESS_MASK as u64) | mmio_flags,
        ) && native_entry(common_page) & ADDRESS_MASK as u64 >= INITIAL_IDENTITY_LIMIT as u64
            && native_entry(notification_page) & ADDRESS_MASK as u64
                >= INITIAL_IDENTITY_LIMIT as u64
            && native_entry(common_page) & ADDRESS_MASK as u64
                != native_entry(notification_page) & ADDRESS_MASK as u64
    };
    let stack_index = 4 + image_pages;
    let native_frame_count = stack_index + stack_pages + 1;
    let native_frame_at = |index: usize| -> u64 {
        match index {
            0 => root,
            1 => pdpt_address,
            2 => directory_address,
            3 => table_address,
            index if index < 4 + image_pages => native_entry(index - 4) & ADDRESS_MASK as u64,
            index if (stack_index..stack_index + stack_pages).contains(&index) => {
                native_entry(stack_page + index - stack_index) & ADDRESS_MASK as u64
            }
            index if index == stack_index + stack_pages => {
                native_entry(boot_info_page) & ADDRESS_MASK as u64
            }
            _ => 0,
        }
    };
    let native_frames_valid = (0..native_frame_count).all(|index| {
        let frame = native_frame_at(index);
        frame != 0
            && frame < INITIAL_IDENTITY_LIMIT as u64
            && (index + 1..native_frame_count).all(|other| native_frame_at(other) != frame)
    });
    (image_valid
        && native_entry(stack_page - 1) == 0
        && (0..stack_pages).all(|offset| {
            flags_match(
                native_entry(stack_page + offset),
                native_frame_at(stack_index + offset) | stack_flags,
            )
        })
        && native_entry(stack_page + stack_pages) == 0
        && flags_match(
            native_entry(boot_info_page),
            native_frame_at(stack_index + stack_pages) | read_only_nx,
        )
        && (!controller_layout
            || (native_entry(common_page) == 0 && native_entry(notification_page) == 0))
        && dma_valid
        && mmio_valid
        && (notification_page + 1..ENTRY_COUNT).all(|index| table.get(index) == 0)
        && native_frames_valid
        && (native_dma == 0
            || !(0..native_frame_count).any(|index| native_frame_at(index) == native_dma_address)))
    .then_some(ValidatedUserRootFrames {
        base: {
            let mut frames = [0; 15];
            for (index, frame) in frames
                .iter_mut()
                .enumerate()
                .take(native_frame_count.min(15))
            {
                *frame = native_frame_at(index);
            }
            frames
        },
        base_count: native_frame_count,
        dma: (native_dma != 0).then_some(native_dma_address),
        native_executable_pages,
        native_image_pages: image_pages as u8,
        native_stack_page: stack_page as u8,
        native_stack_pages: stack_pages as u8,
        native_table: table_address,
    })
}

fn single_user_table_entry(table_address: u64) -> Option<u64> {
    if table_address == 0 || table_address >= INITIAL_IDENTITY_LIMIT as u64 {
        return None;
    }
    let table = TableView::from_physical(table_address)?;
    let entry = table.get(0);
    (entry & (PRESENT | WRITABLE | USER) == (PRESENT | WRITABLE | USER)
        && entry & (LARGE_PAGE | NO_EXECUTE) == 0
        && (1..ENTRY_COUNT).all(|index| table.get(index) == 0))
    .then_some(entry)
}

/// One of the kernel's static page-table pages. Its entries are atomics,
/// which have `u64`'s layout, so the processor walks the page as an ordinary
/// table while the kernel reads and writes entries by index without raw
/// pointers (relaxed loads and stores, which compile to the same plain moves
/// as before). The page lies in the identity-mapped kernel image, so its
/// address is its physical address.
#[repr(C, align(4096))]
struct PageTable([AtomicU64; ENTRY_COUNT]);

impl PageTable {
    const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; ENTRY_COUNT])
    }

    /// Entry `index` (below 512).
    fn get(&self, index: usize) -> u64 {
        self.0[index].load(Ordering::Relaxed)
    }

    fn set(&self, index: usize, value: u64) {
        self.0[index].store(value, Ordering::Relaxed);
    }

    fn zero(&self) {
        self.0
            .iter()
            .for_each(|entry| entry.store(0, Ordering::Relaxed));
    }

    /// The table's address, which is also its physical address.
    fn address(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }
}

/// The address of the first table in `tables`.
fn tables_address(tables: &[PageTable]) -> usize {
    tables.as_ptr() as usize
}

struct PagingOwner {
    pml4: PageTable,
    pdpt: PageTable,
    direct_pdpt: PageTable,
    page_directories: [PageTable; DIRECTORY_COUNT],
    fine_page_tables: [PageTable; MAX_FINE_TABLES],
    mmio_directory: PageTable,
    mmio_table: PageTable,
    framebuffer_directory: PageTable,
    device_directory: PageTable,
    device_table: PageTable,
    /// The kernel stack window's page directory. Unlike the other tables it
    /// stays writable after boot: page tables for stacks are added to it
    /// while the kernel runs.
    kernel_stack_directories: [PageTable; KERNEL_STACK_DIRECTORY_COUNT],
    /// What a Linux process's first PML4 entry starts from: the kernel's
    /// identity entries for only the 2 MiB regions it still reaches by
    /// physical address while a process's tables are loaded (its own
    /// image, which holds the boot inputs, and the firmware's runtime
    /// services), so the rest of the first 4 GiB is the process's to map.
    /// Entries point at the same leaves and fine tables as the kernel's
    /// directories; the tables are sealed read-only with the others, and
    /// a process makes a directory its own only to add user tables beside
    /// these entries (`address_space::ensure_current_linux_leaf`).
    linux_low_pdpt: PageTable,
    linux_low_directories: [PageTable; DIRECTORY_COUNT],
    /// End of the physical range reachable through the direct map once RAM
    /// above the initial identity map joins it; zero until then. (A zero
    /// initializer keeps this owner, and its page tables, out of the image's
    /// initialized data.)
    direct_map_limit: AtomicUsize,
}

static PAGING: PagingOwner = PagingOwner {
    pml4: PageTable::new(),
    pdpt: PageTable::new(),
    direct_pdpt: PageTable::new(),
    page_directories: [const { PageTable::new() }; DIRECTORY_COUNT],
    fine_page_tables: [const { PageTable::new() }; MAX_FINE_TABLES],
    mmio_directory: PageTable::new(),
    mmio_table: PageTable::new(),
    framebuffer_directory: PageTable::new(),
    device_directory: PageTable::new(),
    device_table: PageTable::new(),
    kernel_stack_directories: [const { PageTable::new() }; KERNEL_STACK_DIRECTORY_COUNT],
    linux_low_pdpt: PageTable::new(),
    linux_low_directories: [const { PageTable::new() }; DIRECTORY_COUNT],
    direct_map_limit: AtomicUsize::new(0),
};

/// One of this owner's static tables as a page-table view through the
/// direct map, for code that runs once the direct map exists. The tables
/// lie in the identity-mapped kernel image, so a table's address is its
/// physical address.
fn static_table(table: &PageTable) -> Option<TableView> {
    TableView::from_physical(table.address() as u64)
}

/// Entry `region % 512` of the kernel's identity-map directory for 2-MiB
/// region `region` of the first 4 GiB.
fn identity_directory_entry(region: usize) -> Option<u64> {
    PAGING
        .page_directories
        .get(region / ENTRY_COUNT)
        .and_then(static_table)
        .map(|directory| directory.get(region % ENTRY_COUNT))
}

pub(crate) fn kernel_root_address() -> u64 {
    PAGING.pml4.address() as u64
}

/// The physical address of the directory-pointer table a Linux process's
/// first PML4 entry is copied from (`PagingOwner::linux_low_pdpt`).
pub(crate) fn linux_low_template() -> u64 {
    PAGING.linux_low_pdpt.address() as u64
}

/// The shared template directory for gigabyte `index` of the first 4 GiB,
/// if the kernel keeps any region there.
pub(crate) fn linux_low_template_directory(index: usize) -> Option<u64> {
    if index >= DIRECTORY_COUNT {
        return None;
    }
    // The template is written once during boot, before any Linux process
    // exists, and is read-only afterwards.
    let entry = PAGING.linux_low_pdpt.get(index);
    (entry & PRESENT != 0).then_some(entry & ADDRESS_MASK as u64)
}

/// Returns the end of the physical range the direct map covers.
pub(crate) fn direct_map_limit() -> usize {
    match PAGING.direct_map_limit.load(Ordering::Acquire) {
        0 => INITIAL_IDENTITY_LIMIT,
        limit => limit,
    }
}

/// Returns the end of the highest RAM region in the UEFI memory map.
fn ram_end(boot_info: Handoff) -> u64 {
    const RAM_TYPES: [u32; 6] = [1, 2, 3, 4, 7, 9];
    boot_info
        .memory_descriptors()
        .filter(|descriptor| RAM_TYPES.contains(&descriptor.memory_type))
        .filter_map(|descriptor| {
            descriptor
                .page_count
                .checked_mul(PAGE_SIZE as u64)
                .and_then(|size| descriptor.physical_start.checked_add(size))
        })
        .max()
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum PagingError {
    RequiredAddressOutsideMap,
    TableAddressOutsideMap,
    TableMisaligned,
    GuardMisaligned,
    FineTableCapacity,
    MmioMapInvalid,
    ExecutableMapInvalid,
    ActivationFailed,
    HardeningFailed,
}

/// Installs a transitional 4 GiB identity map backed by 2 MiB pages.
///
/// `device_regions` are further register ranges, at most
/// [`MAX_DEVICE_REGIONS`], mapped uncached in a window of their own; like the
/// reference devices' ranges they lose any identity alias.
///
/// Runs once, at boot, with interrupts disabled, on the firmware's identity
/// map; it builds the kernel's tables in the statics above and loads them.
pub(crate) fn install_initial_identity_map(
    boot_info: Handoff,
    image: &ImageSummary,
    required_addresses: &[usize],
    guard_pages: &[usize],
    mmio_regions: [(u64, usize); 7],
    device_regions: &[(u64, usize)],
    framebuffer: Option<(u64, usize)>,
) -> Result<InitialMmioMappings, PagingError> {
    let [mmio, auxiliary_mmio, platform_mmio, device_mmio, device_config_mmio, device_notification_mmio, device_msix_mmio] =
        mmio_regions;
    let (mmio_physical, mmio_length) = mmio;
    let (auxiliary_mmio_physical, auxiliary_mmio_length) = auxiliary_mmio;
    let (platform_mmio_physical, platform_mmio_length) = platform_mmio;
    let (device_mmio_physical, device_mmio_length) = device_mmio;
    let (device_config_mmio_physical, device_config_mmio_length) = device_config_mmio;
    let (device_notification_mmio_physical, device_notification_mmio_length) =
        device_notification_mmio;
    let (device_msix_mmio_physical, device_msix_mmio_length) = device_msix_mmio;
    if required_addresses
        .iter()
        .any(|address| *address >= INITIAL_IDENTITY_LIMIT)
    {
        return Err(PagingError::RequiredAddressOutsideMap);
    }

    let pml4_address = PAGING.pml4.address();
    let pdpt_address = PAGING.pdpt.address();
    let direct_pdpt_address = PAGING.direct_pdpt.address();
    let directories_address = tables_address(&PAGING.page_directories);
    let fine_tables_address = tables_address(&PAGING.fine_page_tables);
    let mmio_directory_address = PAGING.mmio_directory.address();
    let mmio_table_address = PAGING.mmio_table.address();

    for address in [
        pml4_address,
        pdpt_address,
        direct_pdpt_address,
        directories_address,
        fine_tables_address,
        mmio_directory_address,
        mmio_table_address,
    ] {
        if address >= INITIAL_IDENTITY_LIMIT {
            return Err(PagingError::TableAddressOutsideMap);
        }
        if address & 0xfff != 0 {
            return Err(PagingError::TableMisaligned);
        }
    }

    if guard_pages
        .iter()
        .any(|address| *address >= INITIAL_IDENTITY_LIMIT || *address % PAGE_SIZE != 0)
    {
        return Err(PagingError::GuardMisaligned);
    }

    let pml4 = &PAGING.pml4;
    let pdpt = &PAGING.pdpt;
    let direct_pdpt = &PAGING.direct_pdpt;
    let directories = &PAGING.page_directories;

    pml4.zero();
    pdpt.zero();
    direct_pdpt.zero();

    pml4.set(0, (pdpt_address as u64) | PRESENT | WRITABLE);
    pml4.set(
        DIRECT_MAP_PML4_INDEX,
        (direct_pdpt_address as u64) | PRESENT | WRITABLE,
    );

    for (directory_index, entries) in directories.iter().enumerate() {
        entries.zero();

        pdpt.set(
            directory_index,
            (entries.address() as u64) | PRESENT | WRITABLE,
        );
        direct_pdpt.set(
            directory_index,
            (entries.address() as u64) | PRESENT | WRITABLE,
        );

        for entry_index in 0..ENTRY_COUNT {
            let page_index = directory_index * ENTRY_COUNT + entry_index;
            let physical_address = page_index as u64 * LARGE_PAGE_SIZE;
            entries.set(
                entry_index,
                physical_address | PRESENT | WRITABLE | LARGE_PAGE | NO_EXECUTE,
            );
        }
    }

    // RAM above 4 GiB joins the direct map as 1 GiB pages, below the
    // device, framebuffer and MMIO windows at the top of the slot.
    let gibibytes = (ram_end(boot_info).div_ceil(GIBIBYTE) as usize).min(KERNEL_STACK_PDPT_INDEX);
    if gibibytes > DIRECTORY_COUNT
        && core::arch::x86_64::__cpuid(CPUID_EXTENDED_FEATURES).edx & CPUID_PAGE_1GB != 0
    {
        for index in DIRECTORY_COUNT..gibibytes {
            direct_pdpt.set(
                index,
                (index as u64 * GIBIBYTE) | PRESENT | WRITABLE | LARGE_PAGE | NO_EXECUTE,
            );
        }
        PAGING
            .direct_map_limit
            .store(gibibytes << 30, Ordering::Release);
    }

    let framebuffer = match framebuffer {
        Some((physical, length)) => Some(map_framebuffer_window(physical, length)?),
        None => None,
    };

    let mmio_page = mmio_physical & !(PAGE_SIZE as u64 - 1);
    let mmio_offset =
        usize::try_from(mmio_physical - mmio_page).map_err(|_| PagingError::MmioMapInvalid)?;
    let mmio_span = mmio_offset
        .checked_add(mmio_length)
        .ok_or(PagingError::MmioMapInvalid)?;
    let mmio_pages = mmio_span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(PagingError::MmioMapInvalid)?
        / PAGE_SIZE;
    let mmio_mapped_end = mmio_page.checked_add((mmio_pages * PAGE_SIZE) as u64);
    if mmio_length == 0
        || mmio_page < INITIAL_IDENTITY_LIMIT as u64
        || mmio_pages == 0
        || mmio_pages > ENTRY_COUNT
        || mmio_page & !(ADDRESS_MASK as u64) != 0
        || mmio_mapped_end.is_none_or(|end| end > ADDRESS_MASK as u64 + PAGE_SIZE as u64)
    {
        return Err(PagingError::MmioMapInvalid);
    }
    let auxiliary_mmio_page = auxiliary_mmio_physical & !(PAGE_SIZE as u64 - 1);
    let auxiliary_mmio_offset = usize::try_from(auxiliary_mmio_physical - auxiliary_mmio_page)
        .map_err(|_| PagingError::MmioMapInvalid)?;
    let auxiliary_mmio_span = auxiliary_mmio_offset
        .checked_add(auxiliary_mmio_length)
        .ok_or(PagingError::MmioMapInvalid)?;
    let auxiliary_mmio_pages = auxiliary_mmio_span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(PagingError::MmioMapInvalid)?
        / PAGE_SIZE;
    let auxiliary_mmio_mapped_end =
        auxiliary_mmio_page.checked_add((auxiliary_mmio_pages * PAGE_SIZE) as u64);
    let auxiliary_mmio_index = ENTRY_COUNT
        .checked_sub(auxiliary_mmio_pages)
        .ok_or(PagingError::MmioMapInvalid)?;
    if auxiliary_mmio_length == 0
        || auxiliary_mmio_pages == 0
        || auxiliary_mmio_index < mmio_pages
        || auxiliary_mmio_page & !(ADDRESS_MASK as u64) != 0
        || auxiliary_mmio_mapped_end.is_none_or(|end| end > ADDRESS_MASK as u64 + PAGE_SIZE as u64)
        || ranges_overlap_u64(
            (mmio_page, mmio_mapped_end.unwrap_or(mmio_page)),
            (
                auxiliary_mmio_page,
                auxiliary_mmio_mapped_end.unwrap_or(auxiliary_mmio_page),
            ),
        )
    {
        return Err(PagingError::MmioMapInvalid);
    }
    let platform_mmio_page = platform_mmio_physical & !(PAGE_SIZE as u64 - 1);
    let platform_mmio_offset = usize::try_from(platform_mmio_physical - platform_mmio_page)
        .map_err(|_| PagingError::MmioMapInvalid)?;
    let platform_mmio_span = platform_mmio_offset
        .checked_add(platform_mmio_length)
        .ok_or(PagingError::MmioMapInvalid)?;
    let platform_mmio_pages = platform_mmio_span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(PagingError::MmioMapInvalid)?
        / PAGE_SIZE;
    let platform_mmio_index = mmio_pages;
    let platform_mmio_mapped_end =
        platform_mmio_page.checked_add((platform_mmio_pages * PAGE_SIZE) as u64);
    if platform_mmio_length == 0
        || platform_mmio_pages == 0
        || platform_mmio_index
            .checked_add(platform_mmio_pages)
            .is_none_or(|end| end > auxiliary_mmio_index)
        || platform_mmio_page & !(ADDRESS_MASK as u64) != 0
        || platform_mmio_mapped_end.is_none_or(|end| end > ADDRESS_MASK as u64 + PAGE_SIZE as u64)
        || ranges_overlap_u64(
            (mmio_page, mmio_mapped_end.unwrap_or(mmio_page)),
            (
                platform_mmio_page,
                platform_mmio_mapped_end.unwrap_or(platform_mmio_page),
            ),
        )
        || ranges_overlap_u64(
            (
                auxiliary_mmio_page,
                auxiliary_mmio_mapped_end.unwrap_or(auxiliary_mmio_page),
            ),
            (
                platform_mmio_page,
                platform_mmio_mapped_end.unwrap_or(platform_mmio_page),
            ),
        )
    {
        return Err(PagingError::MmioMapInvalid);
    }
    let device_mmio_page = device_mmio_physical & !(PAGE_SIZE as u64 - 1);
    let device_mmio_offset = usize::try_from(device_mmio_physical - device_mmio_page)
        .map_err(|_| PagingError::MmioMapInvalid)?;
    let device_mmio_span = device_mmio_offset
        .checked_add(device_mmio_length)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_mmio_pages = device_mmio_span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(PagingError::MmioMapInvalid)?
        / PAGE_SIZE;
    let device_mmio_index = platform_mmio_index
        .checked_add(platform_mmio_pages)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_mmio_mapped_end =
        device_mmio_page.checked_add((device_mmio_pages * PAGE_SIZE) as u64);
    if device_mmio_length == 0
        || device_mmio_pages == 0
        || device_mmio_index
            .checked_add(device_mmio_pages)
            .is_none_or(|end| end > auxiliary_mmio_index)
        || device_mmio_page & !(ADDRESS_MASK as u64) != 0
        || device_mmio_mapped_end.is_none_or(|end| end > ADDRESS_MASK as u64 + PAGE_SIZE as u64)
        || ranges_overlap_u64(
            (mmio_page, mmio_mapped_end.unwrap_or(mmio_page)),
            (
                device_mmio_page,
                device_mmio_mapped_end.unwrap_or(device_mmio_page),
            ),
        )
        || ranges_overlap_u64(
            (
                auxiliary_mmio_page,
                auxiliary_mmio_mapped_end.unwrap_or(auxiliary_mmio_page),
            ),
            (
                device_mmio_page,
                device_mmio_mapped_end.unwrap_or(device_mmio_page),
            ),
        )
        || ranges_overlap_u64(
            (
                platform_mmio_page,
                platform_mmio_mapped_end.unwrap_or(platform_mmio_page),
            ),
            (
                device_mmio_page,
                device_mmio_mapped_end.unwrap_or(device_mmio_page),
            ),
        )
    {
        return Err(PagingError::MmioMapInvalid);
    }
    let device_config_mmio_page = device_config_mmio_physical & !(PAGE_SIZE as u64 - 1);
    let device_config_mmio_offset =
        usize::try_from(device_config_mmio_physical - device_config_mmio_page)
            .map_err(|_| PagingError::MmioMapInvalid)?;
    let device_config_mmio_span = device_config_mmio_offset
        .checked_add(device_config_mmio_length)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_config_mmio_pages = device_config_mmio_span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(PagingError::MmioMapInvalid)?
        / PAGE_SIZE;
    let device_config_mmio_index = device_mmio_index
        .checked_add(device_mmio_pages)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_config_mmio_mapped_end =
        device_config_mmio_page.checked_add((device_config_mmio_pages * PAGE_SIZE) as u64);
    let existing_mmio_ranges = [
        (mmio_page, mmio_mapped_end.unwrap_or(mmio_page)),
        (
            auxiliary_mmio_page,
            auxiliary_mmio_mapped_end.unwrap_or(auxiliary_mmio_page),
        ),
        (
            platform_mmio_page,
            platform_mmio_mapped_end.unwrap_or(platform_mmio_page),
        ),
        (
            device_mmio_page,
            device_mmio_mapped_end.unwrap_or(device_mmio_page),
        ),
    ];
    if device_config_mmio_length == 0
        || device_config_mmio_pages == 0
        || device_config_mmio_index
            .checked_add(device_config_mmio_pages)
            .is_none_or(|end| end > auxiliary_mmio_index)
        || device_config_mmio_page & !(ADDRESS_MASK as u64) != 0
        || device_config_mmio_mapped_end
            .is_none_or(|end| end > ADDRESS_MASK as u64 + PAGE_SIZE as u64)
        || existing_mmio_ranges.into_iter().any(|range| {
            ranges_overlap_u64(
                range,
                (
                    device_config_mmio_page,
                    device_config_mmio_mapped_end.unwrap_or(device_config_mmio_page),
                ),
            )
        })
    {
        return Err(PagingError::MmioMapInvalid);
    }
    let device_notification_mmio_page = device_notification_mmio_physical & !(PAGE_SIZE as u64 - 1);
    let device_notification_mmio_offset =
        usize::try_from(device_notification_mmio_physical - device_notification_mmio_page)
            .map_err(|_| PagingError::MmioMapInvalid)?;
    let device_notification_mmio_span = device_notification_mmio_offset
        .checked_add(device_notification_mmio_length)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_notification_mmio_pages = device_notification_mmio_span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(PagingError::MmioMapInvalid)?
        / PAGE_SIZE;
    let device_notification_mmio_index = device_config_mmio_index
        .checked_add(device_config_mmio_pages)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_notification_mmio_mapped_end = device_notification_mmio_page
        .checked_add((device_notification_mmio_pages * PAGE_SIZE) as u64);
    let existing_mmio_ranges = [
        (mmio_page, mmio_mapped_end.unwrap_or(mmio_page)),
        (
            auxiliary_mmio_page,
            auxiliary_mmio_mapped_end.unwrap_or(auxiliary_mmio_page),
        ),
        (
            platform_mmio_page,
            platform_mmio_mapped_end.unwrap_or(platform_mmio_page),
        ),
        (
            device_mmio_page,
            device_mmio_mapped_end.unwrap_or(device_mmio_page),
        ),
        (
            device_config_mmio_page,
            device_config_mmio_mapped_end.unwrap_or(device_config_mmio_page),
        ),
    ];
    if device_notification_mmio_length == 0
        || device_notification_mmio_pages == 0
        || device_notification_mmio_index
            .checked_add(device_notification_mmio_pages)
            .is_none_or(|end| end > auxiliary_mmio_index)
        || device_notification_mmio_page & !(ADDRESS_MASK as u64) != 0
        || device_notification_mmio_mapped_end
            .is_none_or(|end| end > ADDRESS_MASK as u64 + PAGE_SIZE as u64)
        || existing_mmio_ranges.into_iter().any(|range| {
            ranges_overlap_u64(
                range,
                (
                    device_notification_mmio_page,
                    device_notification_mmio_mapped_end.unwrap_or(device_notification_mmio_page),
                ),
            )
        })
    {
        return Err(PagingError::MmioMapInvalid);
    }
    let device_msix_mmio_page = device_msix_mmio_physical & !(PAGE_SIZE as u64 - 1);
    let device_msix_mmio_offset =
        usize::try_from(device_msix_mmio_physical - device_msix_mmio_page)
            .map_err(|_| PagingError::MmioMapInvalid)?;
    let device_msix_mmio_span = device_msix_mmio_offset
        .checked_add(device_msix_mmio_length)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_msix_mmio_pages = device_msix_mmio_span
        .checked_add(PAGE_SIZE - 1)
        .ok_or(PagingError::MmioMapInvalid)?
        / PAGE_SIZE;
    let device_msix_mmio_index = auxiliary_mmio_index
        .checked_sub(device_msix_mmio_pages)
        .ok_or(PagingError::MmioMapInvalid)?;
    let device_msix_mmio_mapped_end =
        device_msix_mmio_page.checked_add((device_msix_mmio_pages * PAGE_SIZE) as u64);
    let existing_mmio_ranges = [
        (mmio_page, mmio_mapped_end.unwrap_or(mmio_page)),
        (
            auxiliary_mmio_page,
            auxiliary_mmio_mapped_end.unwrap_or(auxiliary_mmio_page),
        ),
        (
            platform_mmio_page,
            platform_mmio_mapped_end.unwrap_or(platform_mmio_page),
        ),
        (
            device_mmio_page,
            device_mmio_mapped_end.unwrap_or(device_mmio_page),
        ),
        (
            device_config_mmio_page,
            device_config_mmio_mapped_end.unwrap_or(device_config_mmio_page),
        ),
        (
            device_notification_mmio_page,
            device_notification_mmio_mapped_end.unwrap_or(device_notification_mmio_page),
        ),
    ];
    if device_msix_mmio_length == 0
        || device_msix_mmio_pages == 0
        || device_msix_mmio_index
            < device_notification_mmio_index
                .checked_add(device_notification_mmio_pages)
                .ok_or(PagingError::MmioMapInvalid)?
        || device_msix_mmio_page & !(ADDRESS_MASK as u64) != 0
        || device_msix_mmio_mapped_end
            .is_none_or(|end| end > ADDRESS_MASK as u64 + PAGE_SIZE as u64)
        || existing_mmio_ranges.into_iter().any(|range| {
            ranges_overlap_u64(
                range,
                (
                    device_msix_mmio_page,
                    device_msix_mmio_mapped_end.unwrap_or(device_msix_mmio_page),
                ),
            )
        })
    {
        return Err(PagingError::MmioMapInvalid);
    }
    let mmio_directory = &PAGING.mmio_directory;
    let mmio_table = &PAGING.mmio_table;
    mmio_directory.zero();
    mmio_table.zero();
    for index in 0..mmio_pages {
        mmio_table.set(
            index,
            (mmio_page + (index * PAGE_SIZE) as u64)
                | PRESENT
                | WRITABLE
                | CACHE_DISABLE
                | NO_EXECUTE,
        );
    }
    for index in 0..auxiliary_mmio_pages {
        mmio_table.set(
            auxiliary_mmio_index + index,
            (auxiliary_mmio_page + (index * PAGE_SIZE) as u64)
                | PRESENT
                | WRITABLE
                | CACHE_DISABLE
                | NO_EXECUTE,
        );
    }
    for index in 0..platform_mmio_pages {
        mmio_table.set(
            platform_mmio_index + index,
            (platform_mmio_page + (index * PAGE_SIZE) as u64)
                | PRESENT
                | WRITABLE
                | CACHE_DISABLE
                | NO_EXECUTE,
        );
    }
    for index in 0..device_mmio_pages {
        mmio_table.set(
            device_mmio_index + index,
            (device_mmio_page + (index * PAGE_SIZE) as u64)
                | PRESENT
                | WRITABLE
                | CACHE_DISABLE
                | NO_EXECUTE,
        );
    }
    for index in 0..device_config_mmio_pages {
        mmio_table.set(
            device_config_mmio_index + index,
            (device_config_mmio_page + (index * PAGE_SIZE) as u64)
                | PRESENT
                | CACHE_DISABLE
                | NO_EXECUTE,
        );
    }
    for index in 0..device_notification_mmio_pages {
        mmio_table.set(
            device_notification_mmio_index + index,
            (device_notification_mmio_page + (index * PAGE_SIZE) as u64)
                | PRESENT
                | WRITABLE
                | CACHE_DISABLE
                | NO_EXECUTE,
        );
    }
    for index in 0..device_msix_mmio_pages {
        mmio_table.set(
            device_msix_mmio_index + index,
            (device_msix_mmio_page + (index * PAGE_SIZE) as u64)
                | PRESENT
                | WRITABLE
                | CACHE_DISABLE
                | NO_EXECUTE,
        );
    }
    mmio_directory.set(0, (mmio_table_address as u64) | PRESENT | WRITABLE);
    direct_pdpt.set(
        MMIO_PDPT_INDEX,
        (mmio_directory_address as u64) | PRESENT | WRITABLE,
    );
    let mmio_mapping = MmioMapping {
        physical_page: mmio_page,
        physical_start: mmio_physical,
        virtual_page: MMIO_WINDOW_BASE,
        length: mmio_length,
        mapped_length: mmio_pages * PAGE_SIZE,
        writable: true,
    };
    let auxiliary_mmio_mapping = MmioMapping {
        physical_page: auxiliary_mmio_page,
        physical_start: auxiliary_mmio_physical,
        virtual_page: MMIO_WINDOW_BASE + auxiliary_mmio_index * PAGE_SIZE,
        length: auxiliary_mmio_length,
        mapped_length: auxiliary_mmio_pages * PAGE_SIZE,
        writable: true,
    };
    let platform_mmio_mapping = MmioMapping {
        physical_page: platform_mmio_page,
        physical_start: platform_mmio_physical,
        virtual_page: MMIO_WINDOW_BASE + platform_mmio_index * PAGE_SIZE,
        length: platform_mmio_length,
        mapped_length: platform_mmio_pages * PAGE_SIZE,
        writable: true,
    };
    let device_mmio_mapping = MmioMapping {
        physical_page: device_mmio_page,
        physical_start: device_mmio_physical,
        virtual_page: MMIO_WINDOW_BASE + device_mmio_index * PAGE_SIZE,
        length: device_mmio_length,
        mapped_length: device_mmio_pages * PAGE_SIZE,
        writable: true,
    };
    let device_config_mmio_mapping = MmioMapping {
        physical_page: device_config_mmio_page,
        physical_start: device_config_mmio_physical,
        virtual_page: MMIO_WINDOW_BASE + device_config_mmio_index * PAGE_SIZE,
        length: device_config_mmio_length,
        mapped_length: device_config_mmio_pages * PAGE_SIZE,
        writable: false,
    };
    let device_notification_mmio_mapping = MmioMapping {
        physical_page: device_notification_mmio_page,
        physical_start: device_notification_mmio_physical,
        virtual_page: MMIO_WINDOW_BASE + device_notification_mmio_index * PAGE_SIZE,
        length: device_notification_mmio_length,
        mapped_length: device_notification_mmio_pages * PAGE_SIZE,
        writable: true,
    };
    let device_msix_mmio_mapping = MmioMapping {
        physical_page: device_msix_mmio_page,
        physical_start: device_msix_mmio_physical,
        virtual_page: MMIO_WINDOW_BASE + device_msix_mmio_index * PAGE_SIZE,
        length: device_msix_mmio_length,
        mapped_length: device_msix_mmio_pages * PAGE_SIZE,
        writable: true,
    };
    let reference_mmio = [
        mmio_mapping,
        auxiliary_mmio_mapping,
        platform_mmio_mapping,
        device_mmio_mapping,
        device_config_mmio_mapping,
        device_notification_mmio_mapping,
        device_msix_mmio_mapping,
    ];
    let devices = map_device_window(device_regions, &reference_mmio)?;
    for index in 0..KERNEL_STACK_DIRECTORY_COUNT {
        let stack_directory = &PAGING.kernel_stack_directories[index];
        stack_directory.zero();
        direct_pdpt.set(
            KERNEL_STACK_PDPT_INDEX + index,
            stack_directory.address() as u64 | PRESENT | WRITABLE,
        );
    }

    let fine_tables = &PAGING.fine_page_tables;
    let mut fine_regions = [usize::MAX; MAX_FINE_TABLES];
    let mut fine_count = 0;
    for guard in guard_pages {
        let region = *guard / LARGE_PAGE_SIZE as usize;
        let fine_index = ensure_fine_region(
            region,
            &mut fine_regions,
            &mut fine_count,
            fine_tables,
            directories,
        )?;
        let page = (*guard % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
        let entries = &fine_tables[fine_index];
        entries.set(page, 0);
    }

    for descriptor in boot_info.memory_descriptors() {
        let Some((start, end)) = runtime_code_bounds(descriptor)? else {
            continue;
        };
        let first_region = start / LARGE_PAGE_SIZE as usize;
        let last_region = (end - 1) / LARGE_PAGE_SIZE as usize;
        for region in first_region..=last_region {
            ensure_fine_region(
                region,
                &mut fine_regions,
                &mut fine_count,
                fine_tables,
                directories,
            )?;
        }
    }
    let (image_start, image_end) = image.image_range();
    let first_region = image_start / LARGE_PAGE_SIZE as usize;
    let last_region = (image_end - 1) / LARGE_PAGE_SIZE as usize;
    for region in first_region..=last_region {
        ensure_fine_region(
            region,
            &mut fine_regions,
            &mut fine_count,
            fine_tables,
            directories,
        )?;
    }
    for address in (image_start..image_end).step_by(PAGE_SIZE) {
        let region = address / LARGE_PAGE_SIZE as usize;
        let Some(fine_index) = fine_regions[..fine_count]
            .iter()
            .position(|candidate| *candidate == region)
        else {
            return Err(PagingError::ExecutableMapInvalid);
        };
        let page = (address % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
        let entries = &fine_tables[fine_index];
        let writable = image
            .writable_ranges()
            .iter()
            .any(|(start, end)| address < *end && *start < address + PAGE_SIZE);
        if !writable {
            let value = entries.get(page);
            entries.set(page, value & !WRITABLE);
        }
    }
    for &(start, end) in image.executable_ranges() {
        let first_region = start / LARGE_PAGE_SIZE as usize;
        let last_region = (end - 1) / LARGE_PAGE_SIZE as usize;
        for region in first_region..=last_region {
            ensure_fine_region(
                region,
                &mut fine_regions,
                &mut fine_count,
                fine_tables,
                directories,
            )?;
        }
    }
    let trampoline = super::smp::TRAMPOLINE_PHYSICAL;
    let trampoline_region = trampoline / LARGE_PAGE_SIZE as usize;
    let trampoline_fine_index = ensure_fine_region(
        trampoline_region,
        &mut fine_regions,
        &mut fine_count,
        fine_tables,
        directories,
    )?;
    let trampoline_page = (trampoline % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
    let trampoline_entries = &fine_tables[trampoline_fine_index];
    let trampoline_value = trampoline_entries.get(trampoline_page);
    trampoline_entries.set(trampoline_page, trampoline_value & !(NO_EXECUTE | WRITABLE));

    if auxiliary_mmio_page < INITIAL_IDENTITY_LIMIT as u64 {
        let auxiliary_end = auxiliary_mmio_mapped_end.ok_or(PagingError::MmioMapInvalid)?;
        if auxiliary_end > INITIAL_IDENTITY_LIMIT as u64 {
            return Err(PagingError::MmioMapInvalid);
        }
        for physical in (auxiliary_mmio_page..auxiliary_end).step_by(PAGE_SIZE) {
            let physical = usize::try_from(physical).map_err(|_| PagingError::MmioMapInvalid)?;
            let region = physical / LARGE_PAGE_SIZE as usize;
            let fine_index = ensure_fine_region(
                region,
                &mut fine_regions,
                &mut fine_count,
                fine_tables,
                directories,
            )?;
            let page = (physical % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            let entries = &fine_tables[fine_index];
            entries.set(page, 0);
        }
    }
    if platform_mmio_page < INITIAL_IDENTITY_LIMIT as u64 {
        let platform_end = platform_mmio_mapped_end.ok_or(PagingError::MmioMapInvalid)?;
        if platform_end > INITIAL_IDENTITY_LIMIT as u64 {
            return Err(PagingError::MmioMapInvalid);
        }
        for physical in (platform_mmio_page..platform_end).step_by(PAGE_SIZE) {
            let physical = usize::try_from(physical).map_err(|_| PagingError::MmioMapInvalid)?;
            let region = physical / LARGE_PAGE_SIZE as usize;
            let fine_index = ensure_fine_region(
                region,
                &mut fine_regions,
                &mut fine_count,
                fine_tables,
                directories,
            )?;
            let page = (physical % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            let entries = &fine_tables[fine_index];
            entries.set(page, 0);
        }
    }
    if device_notification_mmio_page < INITIAL_IDENTITY_LIMIT as u64 {
        let notification_end =
            device_notification_mmio_mapped_end.ok_or(PagingError::MmioMapInvalid)?;
        if notification_end > INITIAL_IDENTITY_LIMIT as u64 {
            return Err(PagingError::MmioMapInvalid);
        }
        for physical in (device_notification_mmio_page..notification_end).step_by(PAGE_SIZE) {
            let physical = usize::try_from(physical).map_err(|_| PagingError::MmioMapInvalid)?;
            let region = physical / LARGE_PAGE_SIZE as usize;
            let fine_index = ensure_fine_region(
                region,
                &mut fine_regions,
                &mut fine_count,
                fine_tables,
                directories,
            )?;
            let page = (physical % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            let entries = &fine_tables[fine_index];
            entries.set(page, 0);
        }
    }
    for device in devices.iter().flatten() {
        let device_end = device.physical_page + device.mapped_length as u64;
        if device.physical_page >= INITIAL_IDENTITY_LIMIT as u64 {
            continue;
        }
        if device_end > INITIAL_IDENTITY_LIMIT as u64 {
            return Err(PagingError::MmioMapInvalid);
        }
        for physical in (device.physical_page..device_end).step_by(PAGE_SIZE) {
            let physical = usize::try_from(physical).map_err(|_| PagingError::MmioMapInvalid)?;
            let region = physical / LARGE_PAGE_SIZE as usize;
            let fine_index = ensure_fine_region(
                region,
                &mut fine_regions,
                &mut fine_count,
                fine_tables,
                directories,
            )?;
            let page = (physical % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            let entries = &fine_tables[fine_index];
            entries.set(page, 0);
        }
    }
    if device_msix_mmio_page < INITIAL_IDENTITY_LIMIT as u64 {
        let msix_end = device_msix_mmio_mapped_end.ok_or(PagingError::MmioMapInvalid)?;
        if msix_end > INITIAL_IDENTITY_LIMIT as u64 {
            return Err(PagingError::MmioMapInvalid);
        }
        for physical in (device_msix_mmio_page..msix_end).step_by(PAGE_SIZE) {
            let physical = usize::try_from(physical).map_err(|_| PagingError::MmioMapInvalid)?;
            let region = physical / LARGE_PAGE_SIZE as usize;
            let fine_index = ensure_fine_region(
                region,
                &mut fine_regions,
                &mut fine_count,
                fine_tables,
                directories,
            )?;
            let page = (physical % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            let entries = &fine_tables[fine_index];
            entries.set(page, 0);
        }
    }
    for descriptor in boot_info.memory_descriptors() {
        let Some((start, end)) = runtime_code_bounds(descriptor)? else {
            continue;
        };
        for address in (start..end).step_by(PAGE_SIZE) {
            let region = address / LARGE_PAGE_SIZE as usize;
            let Some(fine_index) = fine_regions[..fine_count]
                .iter()
                .position(|candidate| *candidate == region)
            else {
                return Err(PagingError::ExecutableMapInvalid);
            };
            let page = (address % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            let entries = &fine_tables[fine_index];
            let value = entries.get(page);
            entries.set(page, value & !NO_EXECUTE);
        }
    }
    for &(start, end) in image.executable_ranges() {
        for address in (start..end).step_by(PAGE_SIZE) {
            let region = address / LARGE_PAGE_SIZE as usize;
            let Some(fine_index) = fine_regions[..fine_count]
                .iter()
                .position(|candidate| *candidate == region)
            else {
                return Err(PagingError::ExecutableMapInvalid);
            };
            let page = (address % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            let entries = &fine_tables[fine_index];
            let value = entries.get(page);
            entries.set(page, value & !(NO_EXECUTE | WRITABLE));
        }
    }

    let table_pages = static_table_pages();
    for address in table_pages {
        ensure_fine_region(
            address / LARGE_PAGE_SIZE as usize,
            &mut fine_regions,
            &mut fine_count,
            fine_tables,
            directories,
        )?;
    }
    // The identity directories are final now: sealing the table pages
    // changes only fine tables, which the template shares.
    install_linux_low_template(boot_info, image, required_addresses);
    for address in table_pages {
        let region = address / LARGE_PAGE_SIZE as usize;
        let Some(fine_index) = fine_regions[..fine_count]
            .iter()
            .position(|candidate| *candidate == region)
        else {
            return Err(PagingError::HardeningFailed);
        };
        let page = (address % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
        let entries = &fine_tables[fine_index];
        let value = entries.get(page);
        if value & PRESENT == 0 {
            return Err(PagingError::HardeningFailed);
        }
        entries.set(page, value & !WRITABLE);
    }

    // Loading CR3 serializes the page-table writes and activates the new root.
    root::install_kernel_root();
    let active_root = root::current() as usize;

    if active_root & ADDRESS_MASK != pml4_address {
        return Err(PagingError::ActivationFailed);
    }

    if !control::enable_write_protect() {
        return Err(PagingError::HardeningFailed);
    }

    for (index, region) in fine_regions[..fine_count].iter().enumerate() {
        let entries = &fine_tables[index];
        for guard in guard_pages {
            if *guard / LARGE_PAGE_SIZE as usize == *region {
                let page = (*guard % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
                if entries.get(page) != 0 {
                    return Err(PagingError::HardeningFailed);
                }
            }
        }
    }
    for address in table_pages {
        let region = address / LARGE_PAGE_SIZE as usize;
        let Some(fine_index) = fine_regions[..fine_count]
            .iter()
            .position(|candidate| *candidate == region)
        else {
            return Err(PagingError::HardeningFailed);
        };
        let page = (address % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
        let entries = &fine_tables[fine_index];
        let value = entries.get(page);
        if value & PRESENT == 0 || value & WRITABLE != 0 {
            return Err(PagingError::HardeningFailed);
        }
    }
    if !identity_map_obeys_wx(boot_info, image) {
        return Err(PagingError::HardeningFailed);
    }

    Ok(InitialMmioMappings {
        block_transport: mmio_mapping,
        block_msix: auxiliary_mmio_mapping,
        iommu: platform_mmio_mapping,
        network_common: device_mmio_mapping,
        network_device: device_config_mmio_mapping,
        network_notification: device_notification_mmio_mapping,
        network_msix: device_msix_mmio_mapping,
        framebuffer,
        devices,
    })
}

/// Maps `regions` uncached, one after another, into the direct-map slot
/// reserved for device registers. Each region must stay clear of the others
/// and of the reference devices' ranges in `reference`.
fn map_device_window(
    regions: &[(u64, usize)],
    reference: &[MmioMapping],
) -> Result<[Option<MmioMapping>; MAX_DEVICE_REGIONS], PagingError> {
    let directory = &PAGING.device_directory;
    let table = &PAGING.device_table;
    directory.zero();
    table.zero();
    let mut mappings = [None; MAX_DEVICE_REGIONS];
    if regions.is_empty() {
        return Ok(mappings);
    }
    if regions.len() > MAX_DEVICE_REGIONS {
        return Err(PagingError::MmioMapInvalid);
    }
    let mut next = 0_usize;
    for (slot, &(physical, length)) in regions.iter().enumerate() {
        let page = physical & !(PAGE_SIZE as u64 - 1);
        let pages = usize::try_from(physical - page)
            .ok()
            .and_then(|offset| offset.checked_add(length))
            .and_then(|span| span.checked_add(PAGE_SIZE - 1))
            .map(|span| span / PAGE_SIZE)
            .ok_or(PagingError::MmioMapInvalid)?;
        let end = page
            .checked_add((pages * PAGE_SIZE) as u64)
            .ok_or(PagingError::MmioMapInvalid)?;
        let overlaps = |other: &MmioMapping| {
            ranges_overlap_u64(
                (page, end),
                (
                    other.physical_page,
                    other.physical_page + other.mapped_length as u64,
                ),
            )
        };
        if length == 0
            || next
                .checked_add(pages)
                .is_none_or(|last| last > ENTRY_COUNT)
            || page & !(ADDRESS_MASK as u64) != 0
            || end > ADDRESS_MASK as u64 + PAGE_SIZE as u64
            || reference.iter().any(overlaps)
            || mappings.iter().flatten().any(overlaps)
        {
            return Err(PagingError::MmioMapInvalid);
        }
        for index in 0..pages {
            table.set(
                next + index,
                (page + (index * PAGE_SIZE) as u64)
                    | PRESENT
                    | WRITABLE
                    | CACHE_DISABLE
                    | NO_EXECUTE,
            );
        }
        mappings[slot] = Some(MmioMapping {
            physical_page: page,
            physical_start: physical,
            virtual_page: DEVICE_WINDOW_BASE + next * PAGE_SIZE,
            length,
            mapped_length: pages * PAGE_SIZE,
            writable: true,
        });
        next += pages;
    }
    directory.set(0, table.address() as u64 | PRESENT | WRITABLE);
    PAGING.direct_pdpt.set(
        DEVICE_PDPT_INDEX,
        directory.address() as u64 | PRESENT | WRITABLE,
    );
    Ok(mappings)
}

/// Maps the page at `physical` writable and non-executable at `address` in the
/// kernel stack window. A missing page table for its 2 MiB region is made
/// from `table`, a zeroed frame the caller supplies (and gets back unused
/// when the table exists). Returns false if `address` is outside the window,
/// unaligned, or already mapped.
///
/// The caller serializes calls. A page `unmap_kernel_stack_page` removed
/// is mapped again only once every CPU has dropped its translation of it.
pub(crate) fn map_kernel_stack_page(
    address: usize,
    physical: u64,
    table: &mut Option<u64>,
) -> bool {
    let Some(offset) = address.checked_sub(KERNEL_STACK_WINDOW_BASE) else {
        return false;
    };
    if offset >= KERNEL_STACK_WINDOW_SIZE
        || !offset.is_multiple_of(PAGE_SIZE)
        || !physical.is_multiple_of(PAGE_SIZE as u64)
        || physical & !(ADDRESS_MASK as u64) != 0
    {
        return false;
    }
    // The directory is this owner's, installed in the shared direct PDPT at
    // boot and left writable; the caller serializes writers.
    let Some(directory) = PAGING
        .kernel_stack_directories
        .get(offset >> 30)
        .and_then(static_table)
    else {
        return false;
    };
    let directory_index = (offset % (1 << 30)) / LARGE_PAGE_SIZE as usize;
    let entry = directory.get(directory_index);
    let table_physical = if entry & PRESENT != 0 {
        entry & ADDRESS_MASK as u64
    } else {
        let Some(frame) = table.take() else {
            return false;
        };
        // The frame is zeroed and now belongs to the window.
        directory.set(directory_index, frame | PRESENT | WRITABLE);
        frame
    };
    // The table frame is only written here, under the caller's
    // serialization.
    let Some(entries) = TableView::from_physical(table_physical) else {
        return false;
    };
    let index = (offset % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
    if entries.get(index) & PRESENT != 0 {
        return false;
    }
    entries.set(index, physical | PRESENT | WRITABLE | NO_EXECUTE);
    // This CPU may still hold the page's translation from before an unmap
    // on another CPU.
    invalidate_page(address as u64);
    true
}

/// Unmaps page `address` of the kernel stack window and returns the
/// frame it mapped, dropping this CPU's translation of it. Other CPUs may
/// still hold one until they next load CR3 (the window's translations are
/// not global), so the caller maps nothing at `address` again before every
/// CPU has (`crate::arch::x86_64::smp::flushed_since`). The page table
/// stays.
///
/// The caller serializes calls, as for `map_kernel_stack_page`.
pub(crate) fn unmap_kernel_stack_page(address: usize) -> Option<u64> {
    let offset = address.checked_sub(KERNEL_STACK_WINDOW_BASE)?;
    if offset >= KERNEL_STACK_WINDOW_SIZE || !offset.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    // As in `map_kernel_stack_page`.
    let directory = PAGING
        .kernel_stack_directories
        .get(offset >> 30)
        .and_then(static_table)?;
    let directory_index = (offset % (1 << 30)) / LARGE_PAGE_SIZE as usize;
    let entry = directory.get(directory_index);
    if entry & PRESENT == 0 {
        return None;
    }
    // The table frame is written only under the caller's serialization;
    // invlpg drops only this CPU's translation of the page.
    let entries = TableView::from_physical(entry & ADDRESS_MASK as u64)?;
    let index = (offset % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
    let value = entries.get(index);
    if value & PRESENT == 0 {
        return None;
    }
    entries.set(index, 0);
    invalidate_page(address as u64);
    Some(value & ADDRESS_MASK as u64)
}

/// Programs this CPU's page attribute table, which is per CPU: entry 0 stays
/// write-back, PWT alone selects write-combining (entry 1) and PCD|PWT
/// uncached (entry 3), as Linux sets it up. Device memory mapped into a
/// process (a GPU's host-visible blobs) takes the caching its device asks
/// for through these bits.
pub(crate) fn install_page_attribute_table() {
    crate::trusted::msr::install_write_combining_pat();
}

/// Maps a framebuffer write-combining into the direct-map slot reserved for it
/// and returns the window from `physical`, `length` bytes. The window holds
/// 1 GiB.
fn map_framebuffer_window(physical: u64, length: usize) -> Result<FramebufferWindow, PagingError> {
    let start = physical & !(LARGE_PAGE_SIZE - 1);
    let end = physical
        .checked_add(length as u64)
        .and_then(|end| end.checked_add(LARGE_PAGE_SIZE - 1))
        .ok_or(PagingError::MmioMapInvalid)?
        & !(LARGE_PAGE_SIZE - 1);
    let pages = ((end - start) / LARGE_PAGE_SIZE) as usize;
    if length == 0 || pages > ENTRY_COUNT || end > ADDRESS_MASK as u64 + PAGE_SIZE as u64 {
        return Err(PagingError::MmioMapInvalid);
    }
    install_page_attribute_table();
    let directory = &PAGING.framebuffer_directory;
    directory.zero();
    for index in 0..pages {
        let page = start + index as u64 * LARGE_PAGE_SIZE;
        directory.set(
            index,
            page | PRESENT | WRITABLE | LARGE_PAGE | WRITE_THROUGH | NO_EXECUTE,
        );
    }
    PAGING.direct_pdpt.set(
        FRAMEBUFFER_PDPT_INDEX,
        directory.address() as u64 | PRESENT | WRITABLE,
    );
    Ok(FramebufferWindow {
        address: FRAMEBUFFER_WINDOW_BASE + (physical - start) as usize,
        length,
    })
}

fn ensure_fine_region(
    region: usize,
    fine_regions: &mut [usize; MAX_FINE_TABLES],
    fine_count: &mut usize,
    fine_tables: &[PageTable; MAX_FINE_TABLES],
    directories: &[PageTable; DIRECTORY_COUNT],
) -> Result<usize, PagingError> {
    if let Some(index) = fine_regions[..*fine_count]
        .iter()
        .position(|candidate| *candidate == region)
    {
        return Ok(index);
    }
    if *fine_count == MAX_FINE_TABLES || region >= DIRECTORY_COUNT * ENTRY_COUNT {
        return Err(PagingError::FineTableCapacity);
    }
    let index = *fine_count;
    fine_regions[index] = region;
    *fine_count += 1;
    let table = &fine_tables[index];
    let entries = table;
    entries.zero();
    let region_base = region as u64 * LARGE_PAGE_SIZE;
    for entry in 0..ENTRY_COUNT {
        entries.set(
            entry,
            (region_base + entry as u64 * PAGE_SIZE as u64) | PRESENT | WRITABLE | NO_EXECUTE,
        );
    }
    let directory_entries = &directories[region / ENTRY_COUNT];
    directory_entries.set(
        region % ENTRY_COUNT,
        (table.address() as u64) | PRESENT | WRITABLE,
    );
    Ok(index)
}

pub(crate) fn supervisor_write_protect_enabled() -> bool {
    control::cr0() & CR0_WRITE_PROTECT != 0
}

pub(crate) fn direct_map_range_address(physical: u64, length: usize) -> Option<usize> {
    if length == 0 {
        return None;
    }
    let physical = usize::try_from(physical).ok()?;
    let end = physical.checked_add(length)?;
    if end > direct_map_limit() {
        return None;
    }
    DIRECT_MAP_BASE.checked_add(physical)
}

/// Whether `address` is mapped present by the active page tables, which
/// are read through the direct map. Crash reports check this before
/// reading memory they cannot trust.
pub(crate) fn kernel_address_is_mapped(address: u64) -> bool {
    // Canonical 48-bit addresses only.
    if (address as i64) << 16 >> 16 != address as i64 {
        return false;
    }
    let mut table = crate::trusted::root::current() & ADDRESS_MASK as u64;
    for level in 0..4 {
        let index = ((address >> (39 - 9 * level)) & 0x1ff) as usize;
        let Some(entries) = TableView::from_physical(table) else {
            return false;
        };
        let entry = entries.entry(index).read_volatile();
        if entry & PRESENT == 0 {
            return false;
        }
        if level == 3 || level != 0 && entry & LARGE_PAGE != 0 {
            return true;
        }
        table = entry & ADDRESS_MASK as u64;
    }
    true
}

/// The physical address a direct-map address refers to.
pub(crate) fn direct_map_physical(address: usize) -> Option<u64> {
    let physical = address.checked_sub(DIRECT_MAP_BASE)?;
    (physical < direct_map_limit()).then_some(physical as u64)
}

pub(crate) fn direct_map_translation_is_bounded() -> bool {
    let limit = direct_map_limit();
    (INITIAL_IDENTITY_LIMIT..=DEVICE_PDPT_INDEX << 30).contains(&limit)
        && direct_map_range_address(0, 1) == Some(DIRECT_MAP_BASE)
        && direct_map_range_address((limit - 1) as u64, 1) == Some(DIRECT_MAP_BASE + limit - 1)
        && direct_map_range_address(0, 0).is_none()
        && direct_map_range_address(limit as u64, 1).is_none()
        && direct_map_range_address((limit - 1) as u64, 2).is_none()
        && direct_map_range_address(u64::MAX, 1).is_none()
}

pub(crate) fn direct_map_alias_is_valid() -> bool {
    let Some(pml4) = static_table(&PAGING.pml4) else {
        return false;
    };
    let identity = pml4.get(0);
    let direct = pml4.get(DIRECT_MAP_PML4_INDEX);
    let expected_identity = PAGING.pdpt.address() as u64 | PRESENT | WRITABLE;
    let expected_direct = PAGING.direct_pdpt.address() as u64 | PRESENT | WRITABLE;
    if (identity ^ expected_identity) & !ACCESSED != 0
        || (direct ^ expected_direct) & !ACCESSED != 0
        || direct & PRESENT == 0
        || direct & USER != 0
    {
        return false;
    }
    let (Some(identity_pdpt), Some(direct_pdpt)) = (
        static_table(&PAGING.pdpt),
        static_table(&PAGING.direct_pdpt),
    ) else {
        return false;
    };
    for index in 0..DIRECTORY_COUNT {
        if (identity_pdpt.get(index) ^ direct_pdpt.get(index)) & !ACCESSED != 0 {
            return false;
        }
    }
    // The root's first entry, read through the direct map and through the
    // kernel image's own mapping, must agree.
    pml4.get(0) == PAGING.pml4.get(0)
}

pub(crate) fn mmio_mapping_is_valid(mapping: MmioMapping) -> bool {
    let Some(window_offset) = mapping.virtual_page.checked_sub(MMIO_WINDOW_BASE) else {
        return false;
    };
    let Some(window_end) = window_offset.checked_add(mapping.mapped_length) else {
        return false;
    };
    if mapping.physical_page & (PAGE_SIZE as u64 - 1) != 0
        || mapping.physical_start < mapping.physical_page
        || usize::try_from(mapping.physical_start - mapping.physical_page)
            .ok()
            .and_then(|offset| offset.checked_add(mapping.length))
            .is_none_or(|end| end > mapping.mapped_length)
        || !window_offset.is_multiple_of(PAGE_SIZE)
        || window_end > ENTRY_COUNT * PAGE_SIZE
        || mapping.length == 0
        || mapping.mapped_length == 0
        || !mapping.mapped_length.is_multiple_of(PAGE_SIZE)
        || mapping.mapped_length > ENTRY_COUNT * PAGE_SIZE
    {
        return false;
    }
    let (Some(direct_pdpt), Some(directory), Some(table)) = (
        static_table(&PAGING.direct_pdpt),
        static_table(&PAGING.mmio_directory),
        static_table(&PAGING.mmio_table),
    ) else {
        return false;
    };
    let directory_entry = direct_pdpt.get(MMIO_PDPT_INDEX);
    if directory_entry & (PRESENT | WRITABLE | USER | LARGE_PAGE | NO_EXECUTE) != PRESENT | WRITABLE
        || directory_entry & ADDRESS_MASK as u64 != PAGING.mmio_directory.address() as u64
    {
        return false;
    }
    let table_entry = directory.get(0);
    if table_entry & (PRESENT | WRITABLE | USER | LARGE_PAGE | NO_EXECUTE) != PRESENT | WRITABLE
        || table_entry & ADDRESS_MASK as u64 != PAGING.mmio_table.address() as u64
        || (1..ENTRY_COUNT).any(|index| directory.get(index) != 0)
    {
        return false;
    }
    let page_count = mapping.mapped_length / PAGE_SIZE;
    let first_page = window_offset / PAGE_SIZE;
    let expected_flags =
        PRESENT | CACHE_DISABLE | NO_EXECUTE | if mapping.writable { WRITABLE } else { 0 };
    (0..page_count).all(|index| {
        let entry = table.get(first_page + index);
        entry & (ADDRESS_MASK as u64 | PRESENT | WRITABLE | USER | CACHE_DISABLE | NO_EXECUTE)
            == (mapping.physical_page + (index * PAGE_SIZE) as u64) | expected_flags
            && entry & LARGE_PAGE == 0
    })
}

pub(crate) fn mmio_mappings_are_exact<const N: usize>(mappings: [MmioMapping; N]) -> bool {
    if !mappings.into_iter().all(mmio_mapping_is_valid) {
        return false;
    }
    for left in 0..mappings.len() {
        for right in left + 1..mappings.len() {
            let left_index = (mappings[left].virtual_page - MMIO_WINDOW_BASE) / PAGE_SIZE;
            let right_index = (mappings[right].virtual_page - MMIO_WINDOW_BASE) / PAGE_SIZE;
            let left_pages = mappings[left].mapped_length / PAGE_SIZE;
            let right_pages = mappings[right].mapped_length / PAGE_SIZE;
            if ranges_overlap(
                (left_index, left_index + left_pages),
                (right_index, right_index + right_pages),
            ) || ranges_overlap_u64(
                (
                    mappings[left].physical_page,
                    mappings[left].physical_page + mappings[left].mapped_length as u64,
                ),
                (
                    mappings[right].physical_page,
                    mappings[right].physical_page + mappings[right].mapped_length as u64,
                ),
            ) {
                return false;
            }
        }
    }
    let Some(table) = static_table(&PAGING.mmio_table) else {
        return false;
    };
    (0..ENTRY_COUNT).all(|index| {
        let expected = mappings.into_iter().find_map(|mapping| {
            let first_index = (mapping.virtual_page - MMIO_WINDOW_BASE) / PAGE_SIZE;
            let pages = mapping.mapped_length / PAGE_SIZE;
            (first_index..first_index + pages)
                .contains(&index)
                .then(|| {
                    (mapping.physical_page + ((index - first_index) * PAGE_SIZE) as u64)
                        | PRESENT
                        | CACHE_DISABLE
                        | NO_EXECUTE
                        | if mapping.writable { WRITABLE } else { 0 }
                })
        });
        let Some(expected) = expected else {
            return table.get(index) == 0;
        };
        let entry = table.get(index);
        entry & (ADDRESS_MASK as u64 | PRESENT | WRITABLE | USER | CACHE_DISABLE | NO_EXECUTE)
            == expected
            && entry & LARGE_PAGE == 0
    })
}

pub(crate) fn mmio_identity_alias_is_absent(mapping: MmioMapping) -> bool {
    let Some(end) = mapping
        .physical_page
        .checked_add(mapping.mapped_length as u64)
    else {
        return false;
    };
    if end > INITIAL_IDENTITY_LIMIT as u64 {
        return mapping.physical_page >= INITIAL_IDENTITY_LIMIT as u64;
    }
    (mapping.physical_page..end)
        .step_by(PAGE_SIZE)
        .all(|physical| {
            let physical = physical as usize;
            let region = physical / LARGE_PAGE_SIZE as usize;
            let Some(directory_entry) = identity_directory_entry(region) else {
                return false;
            };
            if directory_entry & (PRESENT | LARGE_PAGE) != PRESENT {
                return false;
            }
            let page = (physical % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
            TableView::from_physical(directory_entry & ADDRESS_MASK as u64)
                .is_some_and(|table| table.get(page) == 0)
        })
}

pub(crate) fn mmio_mapping_is_writable(mapping: MmioMapping) -> bool {
    mmio_mapping_is_valid(mapping) && mapping.writable
}

pub(crate) fn mmio_translation_is_bounded(
    mapping: MmioMapping,
    physical: u64,
    length: usize,
) -> bool {
    let Some(virtual_start) = mapping.address(physical, length) else {
        return false;
    };
    let Some(last_physical) = physical.checked_add(length.saturating_sub(1) as u64) else {
        return false;
    };
    let Some(after) = physical.checked_add(length as u64) else {
        return false;
    };
    mapping.address(physical, 0).is_none()
        && physical
            .checked_sub(1)
            .is_none_or(|before| mapping.address(before, 1).is_none())
        && mapping.address(last_physical, 1) == virtual_start.checked_add(length - 1)
        && mapping.address(after, 1).is_none()
        && mapping.address(u64::MAX, 1).is_none()
}

/// How many pages `static_table_pages` lists.
const STATIC_TABLE_PAGE_COUNT: usize = 9 + 2 * DIRECTORY_COUNT + MAX_FINE_TABLES;

/// The pages of the kernel's static page tables, which are sealed
/// read-only once built. The kernel stack directory is not among them: it
/// gains tables while the kernel runs.
fn static_table_pages() -> [usize; STATIC_TABLE_PAGE_COUNT] {
    let single = [
        PAGING.pml4.address(),
        PAGING.pdpt.address(),
        PAGING.direct_pdpt.address(),
        PAGING.mmio_directory.address(),
        PAGING.mmio_table.address(),
        PAGING.framebuffer_directory.address(),
        PAGING.device_directory.address(),
        PAGING.device_table.address(),
        PAGING.linux_low_pdpt.address(),
    ];
    let arrays = [
        (tables_address(&PAGING.page_directories), DIRECTORY_COUNT),
        (
            tables_address(&PAGING.linux_low_directories),
            DIRECTORY_COUNT,
        ),
        (tables_address(&PAGING.fine_page_tables), MAX_FINE_TABLES),
    ];
    let mut pages = [0; STATIC_TABLE_PAGE_COUNT];
    pages[..single.len()].copy_from_slice(&single);
    let mut next = single.len();
    for (base, count) in arrays {
        for index in 0..count {
            pages[next] = base + index * PAGE_SIZE;
            next += 1;
        }
    }
    pages
}

/// Fills the Linux low template (`PagingOwner::linux_low_pdpt`) from the
/// finished identity directories. It keeps the 2 MiB regions holding the
/// kernel image (which carries the boot inputs, the boot handoff and the
/// kernel's own stacks and tables), the other addresses the handoff names
/// (the ACPI root pointer, the firmware's reset entry) and the firmware's
/// runtime services. The rest of the first 4 GiB is free RAM, which the
/// kernel reaches through the direct map, and device ranges, which it
/// reaches through its windows; it is left to Linux processes.
///
/// Runs once, from `install_initial_identity_map` with interrupts off,
/// after the last change to an identity directory entry.
fn install_linux_low_template(
    boot_info: Handoff,
    image: &ImageSummary,
    required_addresses: &[usize],
) {
    const REGIONS: usize = DIRECTORY_COUNT * ENTRY_COUNT;
    let mut resident = [false; REGIONS];
    let mut keep = |start: usize, end: usize| {
        let first = start / LARGE_PAGE_SIZE as usize;
        let last = end.div_ceil(LARGE_PAGE_SIZE as usize).min(REGIONS);
        for region in resident.iter_mut().take(last).skip(first) {
            *region = true;
        }
    };
    let (image_start, image_end) = image.image_range();
    keep(image_start, image_end);
    for address in required_addresses {
        keep(*address, address.saturating_add(1));
    }
    for descriptor in boot_info.memory_descriptors() {
        if !matches!(
            descriptor.memory_type,
            EFI_RUNTIME_SERVICES_CODE | EFI_RUNTIME_SERVICES_DATA
        ) {
            continue;
        }
        let start = usize::try_from(descriptor.physical_start).unwrap_or(usize::MAX);
        let size = usize::try_from(descriptor.page_count)
            .unwrap_or(usize::MAX)
            .saturating_mul(PAGE_SIZE);
        if start < INITIAL_IDENTITY_LIMIT {
            keep(
                start,
                start.saturating_add(size).min(INITIAL_IDENTITY_LIMIT),
            );
        }
    }
    let directories = &PAGING.page_directories;
    let low_pdpt = &PAGING.linux_low_pdpt;
    let low_directories = &PAGING.linux_low_directories;
    low_pdpt.zero();
    for directory_index in 0..DIRECTORY_COUNT {
        let kernel = &directories[directory_index];
        let low = &low_directories[directory_index];
        let entries = low;
        entries.zero();
        let mut kept = false;
        for entry_index in 0..ENTRY_COUNT {
            if resident[directory_index * ENTRY_COUNT + entry_index] {
                entries.set(entry_index, kernel.get(entry_index));
                kept = true;
            }
        }
        if kept {
            low_pdpt.set(directory_index, (low.address() as u64) | PRESENT | WRITABLE);
        }
    }
}

/// Writes the ranges of the first 4 GiB that Linux processes cannot map,
/// the kernel's own (`install_linux_low_template`), to the kernel log.
pub(crate) fn report_linux_low_template() {
    let directories = &PAGING.linux_low_directories;
    // The template is read-only after boot.
    let kept = |region: usize| {
        region < DIRECTORY_COUNT * ENTRY_COUNT
            && directories
                .get(region / ENTRY_COUNT)
                .and_then(static_table)
                .is_some_and(|directory| directory.get(region % ENTRY_COUNT) & PRESENT != 0)
    };
    crate::serial_write("linox: kernel ranges in Linux address spaces:");
    let mut run_start = None;
    for region in 0..=DIRECTORY_COUNT * ENTRY_COUNT {
        match (kept(region), run_start) {
            (true, None) => run_start = Some(region),
            (false, Some(start)) => {
                crate::serial_write(" ");
                crate::serial_write_u64(start as u64 * LARGE_PAGE_SIZE);
                crate::serial_write("-");
                crate::serial_write_u64(region as u64 * LARGE_PAGE_SIZE);
                run_start = None;
            }
            _ => {}
        }
    }
    crate::serial_write("\r\n");
}

pub(crate) fn static_page_tables_are_read_only() -> bool {
    static_table_pages().into_iter().all(|address| {
        let region = address / LARGE_PAGE_SIZE as usize;
        let Some(directory_entry) = identity_directory_entry(region) else {
            return false;
        };
        if directory_entry & PRESENT == 0 || directory_entry & LARGE_PAGE != 0 {
            return false;
        }
        let page = (address % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
        TableView::from_physical(directory_entry & ADDRESS_MASK as u64).is_some_and(|table| {
            let entry = table.get(page);
            entry & PRESENT != 0 && entry & WRITABLE == 0
        })
    })
}

pub(crate) fn identity_map_obeys_wx(boot_info: Handoff, image: &ImageSummary) -> bool {
    for region in 0..DIRECTORY_COUNT * ENTRY_COUNT {
        let Some(entry) = identity_directory_entry(region) else {
            return false;
        };
        if entry & PRESENT == 0 {
            return false;
        }
        let region_start = region * LARGE_PAGE_SIZE as usize;
        let region_end = region_start + LARGE_PAGE_SIZE as usize;
        if entry & LARGE_PAGE != 0 {
            if entry & NO_EXECUTE == 0
                || range_contains_executable(boot_info, image, region_start, region_end)
                || ranges_overlap(image.image_range(), (region_start, region_end))
            {
                return false;
            }
            continue;
        }
        let Some(table) = TableView::from_physical(entry & ADDRESS_MASK as u64) else {
            return false;
        };
        for page in 0..ENTRY_COUNT {
            let leaf = table.get(page);
            if leaf & PRESENT == 0 {
                continue;
            }
            let address = region_start + page * PAGE_SIZE;
            let image_code = image
                .executable_ranges()
                .iter()
                .any(|(start, end)| address < *end && *start < address + PAGE_SIZE);
            let image_page = ranges_overlap(image.image_range(), (address, address + PAGE_SIZE));
            let image_writable = image
                .writable_ranges()
                .iter()
                .any(|(start, end)| address < *end && *start < address + PAGE_SIZE);
            let expected_writable = image_writable && !is_static_table_page(address);
            let executable = image_code
                || address == super::smp::TRAMPOLINE_PHYSICAL
                || range_contains_runtime_code(boot_info, address, address + PAGE_SIZE);
            if executable == (leaf & NO_EXECUTE != 0)
                || (image_page && expected_writable != (leaf & WRITABLE != 0))
            {
                return false;
            }
        }
    }
    true
}

pub(crate) fn identity_range_is_read_only_data(start: usize, length: usize) -> bool {
    let Some(last) = length
        .checked_sub(1)
        .and_then(|offset| start.checked_add(offset))
    else {
        return false;
    };
    if last >= INITIAL_IDENTITY_LIMIT {
        return false;
    }
    let first_page = start / PAGE_SIZE * PAGE_SIZE;
    let last_page = last / PAGE_SIZE * PAGE_SIZE;
    let mut address = first_page;
    loop {
        let region = address / LARGE_PAGE_SIZE as usize;
        let Some(directory_entry) = identity_directory_entry(region) else {
            return false;
        };
        let permissions_valid = if directory_entry & LARGE_PAGE != 0 {
            directory_entry & PRESENT != 0
                && directory_entry & WRITABLE == 0
                && directory_entry & NO_EXECUTE != 0
        } else {
            let table = directory_entry & ADDRESS_MASK as u64;
            if directory_entry & PRESENT == 0 || table == 0 {
                false
            } else {
                let page = (address % LARGE_PAGE_SIZE as usize) / PAGE_SIZE;
                TableView::from_physical(table).is_some_and(|table| {
                    let leaf = table.get(page);
                    leaf & PRESENT != 0 && leaf & WRITABLE == 0 && leaf & NO_EXECUTE != 0
                })
            }
        };
        if !permissions_valid {
            return false;
        }
        if address == last_page {
            return true;
        }
        let Some(next) = address.checked_add(PAGE_SIZE) else {
            return false;
        };
        address = next;
    }
}

fn runtime_code_bounds(
    descriptor: UefiMemoryDescriptor,
) -> Result<Option<(usize, usize)>, PagingError> {
    if descriptor.memory_type != EFI_RUNTIME_SERVICES_CODE {
        return Ok(None);
    }
    let start = usize::try_from(descriptor.physical_start)
        .map_err(|_| PagingError::ExecutableMapInvalid)?;
    let size = descriptor
        .page_count
        .checked_mul(PAGE_SIZE as u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(PagingError::ExecutableMapInvalid)?;
    let end = start
        .checked_add(size)
        .ok_or(PagingError::ExecutableMapInvalid)?
        .min(INITIAL_IDENTITY_LIMIT);
    if start % PAGE_SIZE != 0 || size == 0 {
        return Err(PagingError::ExecutableMapInvalid);
    }
    Ok((start < end).then_some((start, end)))
}

fn range_contains_runtime_code(boot_info: Handoff, start: usize, end: usize) -> bool {
    for descriptor in boot_info.memory_descriptors() {
        let Ok(Some((code_start, code_end))) = runtime_code_bounds(descriptor) else {
            continue;
        };
        if start < code_end && code_start < end {
            return true;
        }
    }
    false
}

fn range_contains_executable(
    boot_info: Handoff,
    image: &ImageSummary,
    start: usize,
    end: usize,
) -> bool {
    range_contains_runtime_code(boot_info, start, end)
        || image
            .executable_ranges()
            .iter()
            .any(|(code_start, code_end)| start < *code_end && *code_start < end)
}

const fn ranges_overlap(left: (usize, usize), right: (usize, usize)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

const fn ranges_overlap_u64(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn is_static_table_page(address: usize) -> bool {
    if address == PAGING.pml4.address()
        || address == PAGING.pdpt.address()
        || address == PAGING.direct_pdpt.address()
        || address == PAGING.mmio_directory.address()
        || address == PAGING.mmio_table.address()
        || address == PAGING.framebuffer_directory.address()
        || address == PAGING.device_directory.address()
        || address == PAGING.device_table.address()
        || address == PAGING.linux_low_pdpt.address()
    {
        return true;
    }
    let low_directories = tables_address(&PAGING.linux_low_directories);
    if (low_directories..low_directories + DIRECTORY_COUNT * PAGE_SIZE).contains(&address) {
        return true;
    }
    let directories = tables_address(&PAGING.page_directories);
    let directories_end = directories + DIRECTORY_COUNT * PAGE_SIZE;
    let fine_tables = tables_address(&PAGING.fine_page_tables);
    let fine_tables_end = fine_tables + MAX_FINE_TABLES * PAGE_SIZE;
    (directories..directories_end).contains(&address)
        || (fine_tables..fine_tables_end).contains(&address)
}
