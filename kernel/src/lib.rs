#![no_std]

extern crate alloc;

// RustCrypto's AES and GHASH would use AES-NI and PCLMULQDQ, which run on
// the SIMD registers user processes own: the kernel neither uses nor saves
// them (.cargo/config.toml sets these cfgs for the kernel's target). A host
// build (clippy's quick check) never runs, so it needs neither.
#[cfg(all(target_os = "uefi", not(all(aes_force_soft, polyval_force_soft))))]
compile_error!("the kernel must be built with --cfg aes_force_soft --cfg polyval_force_soft");

mod address_space;
mod arch;
mod bringup;
mod capability;
mod control_abi;
mod cpu_time;
mod crypto;
mod domain;
mod drivers;
mod executable;
mod framebuffer;
mod heap;
mod image_store;
mod initramfs;
mod ipc;
mod kernel_log;
mod linux_accounting;
mod linux_aio;
mod linux_areas;
mod linux_async_io;
mod linux_blockfs;
mod linux_cgroup;
mod linux_core;
mod linux_debug_registers;
mod linux_drm;
mod linux_elf;
mod linux_event_files;
mod linux_exe;
mod linux_fanotify;
mod linux_fd_table;
mod linux_file_cache;
mod linux_fscontext;
mod linux_inotify;
mod linux_input;
mod linux_io_uring;
mod linux_keyring;
mod linux_kmsg;
mod linux_landlock;
mod linux_lease;
mod linux_loop;
mod linux_mount;
mod linux_mount_paths;
mod linux_mounts;
mod linux_namespace;
mod linux_overlay;
mod linux_overlayfs;
mod linux_path_views;
mod linux_pidfs;
mod linux_process;
mod linux_profile;
mod linux_pty;
mod linux_ramdisk;
mod linux_record_lock;
mod linux_signal;
mod linux_socket;
mod linux_strace;
mod linux_swap;
mod linux_sysv_ipc;
mod linux_tmpfs;
mod linux_tmpfs_quota;
mod linux_user;
mod linux_userfaultfd;
mod linux_wait_sets;
mod machine_control;
mod manifest;
mod memory;
mod memory_failure;
mod native_elf;
mod network;
mod owned_state;
mod packet;
mod pe;
mod published_rootfs;
mod scheduler;
mod sync;
mod trusted;
mod volume;

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use trusted::port::Port8;

pub use bringup::report_panic;
pub use pe::rebase_loaded_image;

struct HostControlOwner {
    operator_console_ready: AtomicBool,
    background_domain_output: AtomicBool,
    linux_realtime_epoch_seconds: AtomicU64,
    linux_realtime_epoch_tsc: AtomicU64,
    oci_pull_started: AtomicU64,
    persisted_oci_catalog: UnsafeCell<[u8; linox_oci_cache::ENCODED_SIZE]>,
    /// Where the loaded kernel image lies, so crash reports can name code
    /// addresses relative to it.
    kernel_image_base: AtomicU64,
    kernel_image_size: AtomicU64,
}

unsafe impl Sync for HostControlOwner {}

static HOST_CONTROL: HostControlOwner = HostControlOwner {
    operator_console_ready: AtomicBool::new(false),
    background_domain_output: AtomicBool::new(false),
    linux_realtime_epoch_seconds: AtomicU64::new(0),
    linux_realtime_epoch_tsc: AtomicU64::new(0),
    oci_pull_started: AtomicU64::new(0),
    persisted_oci_catalog: UnsafeCell::new([0; linox_oci_cache::ENCODED_SIZE]),
    kernel_image_base: AtomicU64::new(0),
    kernel_image_size: AtomicU64::new(0),
};

/// The loaded kernel image's base address and size.
pub(crate) fn kernel_image_range() -> (u64, u64) {
    (
        HOST_CONTROL.kernel_image_base.load(Ordering::Relaxed),
        HOST_CONTROL.kernel_image_size.load(Ordering::Relaxed),
    )
}
const EFI_SUCCESS: usize = 0;
pub(crate) const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
pub(crate) const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
pub(crate) const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const UEFI_PAGES_PER_MIB: u64 = 256;
const PAGE_SIZE: usize = 4096;
const Q35_IOMMU_REGISTER_BASE: u64 = 0xfed9_0000;
// Linux processes run nested inside the syscalls of the processes that
// started them, all on this stack, so its depth bounds how deep a process
// tree (a shell running a compositor running a terminal running a shell) can
// be. 512 KiB overflowed under the all-Rust desktop and a cargo build.
const KERNEL_STACK_SIZE: usize = 2 * 1024 * 1024;
const KERNEL_STACK_STORAGE_SIZE: usize = PAGE_SIZE + KERNEL_STACK_SIZE + PAGE_SIZE;
const PERSISTENT_LOCAL_CONFIG_SIZE: usize =
    arch::x86_64::cpu::PERSISTENT_DOMAIN_CONFIG_SIZE + network::PERSISTENT_NETWORK_CONFIG_SIZE;
const KERNEL_STACK_TOP_OFFSET: usize = PAGE_SIZE + KERNEL_STACK_SIZE;
pub const BOOT_INFO_MAGIC: u64 = 0x0049_4258_4f4e_494c;
pub const BOOT_INFO_VERSION: u32 = 8;
/// No usable linear framebuffer was found.
pub const FRAMEBUFFER_FORMAT_NONE: u32 = 0;
/// 32-bit pixels with bytes ordered red, green, blue, reserved.
pub const FRAMEBUFFER_FORMAT_RGBX: u32 = 1;
/// 32-bit pixels with bytes ordered blue, green, red, reserved.
pub const FRAMEBUFFER_FORMAT_BGRX: u32 = 2;

fn initialize_linux_realtime(unix_time: u64, timestamp_counter: u64) -> bool {
    if unix_time < 1_577_836_800 || timestamp_counter == 0 {
        return false;
    }
    HOST_CONTROL
        .linux_realtime_epoch_tsc
        .store(timestamp_counter, Ordering::Release);
    HOST_CONTROL
        .linux_realtime_epoch_seconds
        .compare_exchange(0, unix_time, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub(crate) fn linux_realtime_epoch() -> Option<(u64, u64)> {
    let seconds = HOST_CONTROL
        .linux_realtime_epoch_seconds
        .load(Ordering::Acquire);
    let timestamp_counter = HOST_CONTROL
        .linux_realtime_epoch_tsc
        .load(Ordering::Acquire);
    (seconds != 0 && timestamp_counter != 0).then_some((seconds, timestamp_counter))
}

#[repr(C, align(4096))]
struct KernelStackOwner([u8; KERNEL_STACK_STORAGE_SIZE]);

static mut KERNEL_STACK: KernelStackOwner = KernelStackOwner([0; KERNEL_STACK_STORAGE_SIZE]);

global_asm!(
    r#"
    .text
    .global linox_kernel_stack_entry
linox_kernel_stack_entry:
    cli
    lea rsp, [rip + {stack}]
    add rsp, {stack_size}
    and rsp, -16
    call {kernel_main}
    ud2
"#,
    stack = sym KERNEL_STACK,
    stack_size = const KERNEL_STACK_TOP_OFFSET,
    kernel_main = sym kernel_main,
);

extern "sysv64" {
    fn linox_kernel_stack_entry(boot_info: *const BootInfo) -> !;
}

pub type ResetSystem = unsafe extern "efiapi" fn(u32, usize, usize, *const c_void);

/// Information fixed by the boot environment before firmware boot services end.
///
/// This structure is a versioned internal contract. It uses an explicit C
/// layout so the boot/kernel boundary can evolve into a language-neutral ABI.
#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub memory_map: *const u8,
    pub memory_map_size: usize,
    pub memory_descriptor_size: usize,
    pub memory_descriptor_version: u32,
    pub acpi_rsdp: *const u8,
    pub manifest: *const u8,
    pub manifest_size: usize,
    pub manifest_sha256: [u8; 32],
    pub manifest_signature: [u8; 64],
    pub control_plane_bundle: *const u8,
    pub control_plane_bundle_size: usize,
    pub controller_runtime: *const u8,
    pub controller_runtime_size: usize,
    pub root_image: *const u8,
    pub root_image_size: usize,
    pub oci_rootfs: *const u8,
    pub oci_rootfs_size: usize,
    pub unix_time: u64,
    pub reset_system: ResetSystem,
    pub image_base: *const u8,
    pub image_size: usize,
    pub framebuffer: BootFramebuffer,
}

/// The linear framebuffer the firmware left active, if any.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootFramebuffer {
    /// Physical address of the first pixel.
    pub base: u64,
    /// Bytes the firmware reports for the framebuffer.
    pub size: u64,
    pub width: u32,
    pub height: u32,
    /// Pixels per scan line.
    pub stride: u32,
    /// One of the `FRAMEBUFFER_FORMAT_*` values.
    pub format: u32,
}

#[repr(C)]
pub(crate) struct UefiMemoryDescriptor {
    pub(crate) memory_type: u32,
    padding: u32,
    pub(crate) physical_start: u64,
    virtual_start: u64,
    pub(crate) page_count: u64,
    attributes: u64,
}

struct MemorySummary {
    descriptors: usize,
    conventional_pages: u64,
    boot_service_pages: u64,
    loader_pages: u64,
}

/// Takes control after UEFI boot services have ended.
///
/// # Safety
///
/// `boot_info` must identify a valid, immutable `BootInfo`. Its memory-map
/// buffer must remain allocated for the lifetime of the kernel.
pub unsafe extern "sysv64" fn kernel_entry(boot_info: *const BootInfo) -> ! {
    linox_kernel_stack_entry(boot_info)
}

unsafe extern "sysv64" fn kernel_main(boot_info: *const BootInfo) -> ! {
    let kernel_boot_started = arch::x86_64::timer::timestamp_counter();
    serial_init();
    serial_write_raw(b"linox: booting\r\n");
    serial_write("linox: kernel entered after ExitBootServices\r\n");

    if !sync::verify_primitives() {
        kernel_fail("linox: synchronization primitive verification failed\r\n");
    }
    serial_write("linox: ranked synchronization primitives ready\r\n");

    if !kernel_stack_is_active() {
        kernel_fail("linox: kernel stack transition failed\r\n");
    }
    serial_write("linox: kernel stack active\r\n");

    if boot_info.is_null() {
        kernel_fail("linox: missing boot information\r\n");
    }

    let boot_info = &*boot_info;
    if boot_info.magic != BOOT_INFO_MAGIC
        || boot_info.version != BOOT_INFO_VERSION
        || boot_info.size < size_of::<BootInfo>() as u32
    {
        kernel_fail("linox: incompatible boot information\r\n");
    }
    HOST_CONTROL
        .kernel_image_base
        .store(boot_info.image_base as u64, Ordering::Relaxed);
    HOST_CONTROL
        .kernel_image_size
        .store(boot_info.image_size as u64, Ordering::Relaxed);
    // Crash addresses are symbolized relative to this base
    // (tools/debug/symbolize.sh).
    serial_write_raw(b"linox: kernel image base ");
    serial_write_hex(boot_info.image_base as u64);
    serial_write_raw(b" size ");
    serial_write_hex(boot_info.image_size as u64);
    serial_write_raw(b"\r\n");
    // UEFI's page tables identity-map the framebuffer until Linox installs its
    // own. Check that they really do (a framebuffer in a 64-bit BAR far above
    // RAM may not be mapped) before drawing on it.
    let framebuffer_mapped =
        framebuffer::mapped_length(&boot_info.framebuffer).is_some_and(|length| {
            let base = boot_info.framebuffer.base;
            bringup::firmware_maps(base, true)
                && bringup::firmware_maps(base + length as u64 - 1, true)
        });
    if !framebuffer_mapped && boot_info.framebuffer.base != 0 {
        serial_write_raw(b"linox: firmware page tables do not map the framebuffer\r\n");
    }
    if framebuffer_mapped
        && framebuffer::init(&boot_info.framebuffer, boot_info.framebuffer.base as usize)
    {
        serial_write_raw(b"linox: booting\r\n");
        serial_write_raw(b"linox: firmware framebuffer console active\r\n");
    }
    if boot_info.memory_map.is_null()
        || boot_info.memory_map_size == 0
        || boot_info.memory_descriptor_size < size_of::<UefiMemoryDescriptor>()
        || !boot_info
            .memory_map_size
            .is_multiple_of(boot_info.memory_descriptor_size)
    {
        kernel_fail("linox: invalid UEFI memory map\r\n");
    }
    if !initialize_linux_realtime(
        boot_info.unix_time,
        arch::x86_64::timer::timestamp_counter(),
    ) {
        kernel_fail("linox: invalid realtime clock handoff\r\n");
    }

    let Some(acpi_rsdp_end) = validate_acpi_rsdp(boot_info.acpi_rsdp) else {
        kernel_fail("linox: invalid ACPI root pointer\r\n");
    };
    let Some(image_end) = boot_info
        .image_size
        .checked_sub(1)
        .and_then(|size| (boot_info.image_base as usize).checked_add(size))
    else {
        kernel_fail("linox: invalid loaded EFI image bounds\r\n");
    };
    if boot_info.image_base.is_null() || image_end >= arch::x86_64::paging::INITIAL_IDENTITY_LIMIT {
        kernel_fail("linox: loaded EFI image is outside the identity map\r\n");
    }
    let Some(image) = pe::inspect(boot_info.image_base, boot_info.image_size) else {
        kernel_fail("linox: invalid loaded EFI PE image\r\n");
    };
    serial_write("linox: versioned boot handoff accepted\r\n");
    serial_write("linox: loaded EFI PE image accepted\r\nlinox: PE sections: ");
    serial_write_usize(image.sections);
    serial_write("\r\nlinox: executable PE sections: ");
    serial_write_usize(image.executable_sections);
    serial_write("\r\nlinox: writable PE sections: ");
    serial_write_usize(image.writable_sections);
    serial_write("\r\n");
    serial_write("linox: ACPI root pointer validated\r\n");
    let Some(boot_manifest) = manifest::Manifest::parse_and_verify(
        boot_info.manifest,
        boot_info.manifest_size,
        &boot_info.manifest_sha256,
        &boot_info.manifest_signature,
        arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
    ) else {
        kernel_fail("linox: invalid measured boot manifest\r\n");
    };
    serial_write("linox: signed boot manifest accepted\r\nlinox: manifest sequence: ");
    serial_write_u64(boot_manifest.sequence());
    serial_write("\r\nlinox: manifest authority grants: ");
    serial_write_usize(boot_manifest.grant_count());
    serial_write("\r\n");
    if !manifest::verify_signature_rejection(
        boot_info.manifest,
        boot_info.manifest_size,
        &boot_info.manifest_signature,
    ) {
        kernel_fail("linox: invalid manifest signature was accepted\r\n");
    }
    serial_write("linox: manifest signature rejection verified\r\n");
    if !manifest::verify_parser_rejections(boot_info.manifest, boot_info.manifest_size) {
        kernel_fail("linox: malformed manifest parser test failed\r\n");
    }
    serial_write("linox: malformed boot manifests rejected\r\n");
    if !boot_manifest.bundle_matches(
        boot_info.control_plane_bundle,
        boot_info.control_plane_bundle_size,
        arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
    ) {
        kernel_fail("linox: control-plane bundle measurement failed\r\n");
    }
    serial_write("linox: control-plane bundle measurement accepted\r\n");
    if !boot_manifest.controller_matches(
        boot_info.controller_runtime,
        boot_info.controller_runtime_size,
        arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
    ) {
        kernel_fail("linox: controller runtime measurement failed\r\n");
    }
    serial_write("linox: embedded controller runtime measurement accepted\r\n");
    if !boot_manifest.root_matches(
        boot_info.root_image,
        boot_info.root_image_size,
        arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
    ) {
        kernel_fail("linox: root-image measurement failed\r\n");
    }
    serial_write("linox: root-image measurement accepted\r\n");
    if !boot_manifest.verify_root_rejection(
        boot_info.root_image,
        boot_info.root_image_size,
        arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
    ) {
        kernel_fail("linox: modified root-image measurement accepted\r\n");
    }
    serial_write("linox: root-image measurement rejection verified\r\n");
    // The boot image may carry the all-Rust root filesystem for
    // `image=builtin://rust`; it must lie inside the loaded image.
    if boot_info.oci_rootfs_size != 0 || !boot_info.oci_rootfs.is_null() {
        let start = boot_info.oci_rootfs as usize;
        let image_start = boot_info.image_base as usize;
        let inside_image = boot_info.oci_rootfs_size != 0
            && start >= image_start
            && start
                .checked_add(boot_info.oci_rootfs_size)
                .is_some_and(|end| end <= image_start + boot_info.image_size);
        if !inside_image {
            kernel_fail("linox: boot-embedded root filesystem lies outside the boot image\r\n");
        }
        image_store::set_builtin_rootfs(start as u64, boot_info.oci_rootfs_size);
        serial_write("linox: builtin Rust root filesystem available (");
        serial_write_usize(boot_info.oci_rootfs_size);
        serial_write(" bytes)\r\n");
    }

    bringup::set_stage("looking for the QEMU reference devices");
    let Some(virtio_block) = arch::x86_64::pci::discover_virtio_block() else {
        // Not the QEMU reference machine: report the hardware and run the
        // physical-device drivers instead of failing.
        bringup::run(boot_info);
    };
    if !arch::x86_64::pci::verify_parser_rejections(virtio_block) {
        kernel_fail("linox: malformed virtio PCI configuration accepted\r\n");
    }
    let Some((virtio_common_physical, virtio_common_length)) = virtio_block.common_region() else {
        kernel_fail("linox: invalid virtio common configuration range\r\n");
    };
    let Some((virtio_mmio_physical, virtio_mmio_length)) = virtio_block.mmio_span() else {
        kernel_fail("linox: invalid virtio MMIO span\r\n");
    };
    let Some((virtio_msix_physical, virtio_msix_length)) = virtio_block.msix_mmio_span() else {
        kernel_fail("linox: invalid virtio MSI-X MMIO span\r\n");
    };
    let Some(virtio_network) = arch::x86_64::pci::discover_virtio_network() else {
        kernel_fail("linox: modern virtio network device discovery failed\r\n");
    };
    let virtio_network_parser_valid =
        arch::x86_64::pci::verify_network_parser_rejections(virtio_network);
    let virtio_network_firmware_command =
        arch::x86_64::pci::network_function_command(virtio_network);
    let virtio_network_revoked =
        virtio_network_parser_valid && arch::x86_64::pci::revoke_network_function(virtio_network);
    if !virtio_network_parser_valid || !virtio_network_revoked {
        serial_write("linox: virtio network parser/revoked/firmware-command: ");
        serial_write_u64(u64::from(virtio_network_parser_valid));
        serial_write("/");
        serial_write_u64(u64::from(virtio_network_revoked));
        serial_write("/");
        serial_write_u64(u64::from(virtio_network_firmware_command));
        serial_write("\r\n");
        kernel_fail("linox: virtio network discovery boundary invalid\r\n");
    }
    let Some((virtio_network_common_physical, virtio_network_common_length)) =
        virtio_network.common_region()
    else {
        kernel_fail("linox: invalid virtio network common configuration range\r\n");
    };
    let Some((virtio_network_device_physical, virtio_network_device_length)) =
        virtio_network.device_region()
    else {
        kernel_fail("linox: invalid virtio network device configuration range\r\n");
    };
    let Some((virtio_network_notify_physical, virtio_network_notify_length)) =
        virtio_network.notify_region()
    else {
        kernel_fail("linox: invalid virtio network notification range\r\n");
    };
    let Some((virtio_network_msix_physical, virtio_network_msix_length)) =
        virtio_network.msix_mmio_span()
    else {
        kernel_fail("linox: invalid virtio network MSI-X range\r\n");
    };
    let Some((virtio_network_msix_table_physical, virtio_network_msix_table_length)) =
        virtio_network.msix_table_region()
    else {
        kernel_fail("linox: invalid virtio network MSI-X table range\r\n");
    };
    let Some((virtio_network_msix_pba_physical, virtio_network_msix_pba_length)) =
        virtio_network.msix_pba_region()
    else {
        kernel_fail("linox: invalid virtio network MSI-X PBA range\r\n");
    };

    let Some(memory_map_end) = boot_info
        .memory_map_size
        .checked_sub(1)
        .and_then(|size| (boot_info.memory_map as usize).checked_add(size))
    else {
        kernel_fail("linox: UEFI memory map address overflow\r\n");
    };

    let stack_start = core::ptr::addr_of!(KERNEL_STACK) as usize;
    let kernel_stack_guard = stack_start;
    let kernel_stack_start = stack_start + PAGE_SIZE;
    let kernel_stack_upper_guard = stack_start + KERNEL_STACK_TOP_OFFSET;
    let double_fault_guard = arch::x86_64::cpu::double_fault_guard_page();
    let nmi_guard = arch::x86_64::cpu::nmi_guard_page();
    let machine_check_guard = arch::x86_64::cpu::machine_check_guard_page();
    let privilege_stack_guard = arch::x86_64::cpu::privilege_stack_guard_page();
    let required_addresses = [
        kernel_main as *const () as usize,
        boot_info as *const BootInfo as usize,
        boot_info.image_base as usize,
        image_end,
        boot_info.memory_map as usize,
        memory_map_end,
        kernel_stack_start,
        kernel_stack_upper_guard - 1,
        boot_info.reset_system as usize,
        boot_info.acpi_rsdp as usize,
        acpi_rsdp_end,
        boot_info.manifest as usize,
        boot_info.manifest as usize + boot_info.manifest_size - 1,
        boot_info.control_plane_bundle as usize,
        boot_info.control_plane_bundle as usize + boot_info.control_plane_bundle_size - 1,
        boot_info.controller_runtime as usize,
        boot_info.controller_runtime as usize + boot_info.controller_runtime_size - 1,
        boot_info.root_image as usize,
        boot_info.root_image as usize + boot_info.root_image_size - 1,
        privilege_stack_guard + PAGE_SIZE,
        arch::x86_64::cpu::privilege_stack_top() - 1,
        double_fault_guard + PAGE_SIZE,
        arch::x86_64::cpu::double_fault_stack_top() - 1,
        nmi_guard + PAGE_SIZE,
        arch::x86_64::cpu::nmi_stack_top() - 1,
        machine_check_guard + PAGE_SIZE,
        arch::x86_64::cpu::machine_check_stack_top() - 1,
    ];
    let cpu_guard_pages = arch::x86_64::cpu::stack_guard_pages();
    let mut guard_pages = [0; 3 + 4 * 10];
    guard_pages[0] = 0;
    guard_pages[1] = kernel_stack_guard;
    guard_pages[2] = kernel_stack_upper_guard;
    guard_pages[3..].copy_from_slice(&cpu_guard_pages);

    if !arch::x86_64::smp::prepare_trampoline() {
        kernel_fail("linox: application-processor trampoline preparation failed\r\n");
    }

    if !arch::x86_64::cpu::enable_execute_disable() {
        kernel_fail("linox: execute-disable unavailable or inactive\r\n");
    }
    arch::x86_64::paging::install_page_attribute_table();
    // USB host controllers for input are found now so that their registers
    // join the device window of the kernel page tables.
    let usb_hosts = drivers::usb_input::discover();
    let usb_regions = usb_hosts.regions();
    // So is a virtio-gpu, which becomes the display; its registers follow
    // the USB controllers' in the window when they fit.
    let usb_count = usb_hosts.len();
    let mut device_regions = [(0_u64, 0_usize); arch::x86_64::paging::MAX_DEVICE_REGIONS];
    device_regions[..usb_count].copy_from_slice(&usb_regions[..usb_count]);
    let gpu_probe = drivers::virtio_gpu::discover().filter(|probe| {
        // The window is one page table: 512 pages.
        let pages = |&(physical, length): &(u64, usize)| {
            ((physical & 0xfff) as usize + length).div_ceil(PAGE_SIZE)
        };
        usb_count < device_regions.len()
            && device_regions[..usb_count].iter().map(pages).sum::<usize>()
                + pages(&probe.registers)
                <= 512
    });
    let device_count = match gpu_probe {
        Some(probe) => {
            device_regions[usb_count] = probe.registers;
            usb_count + 1
        }
        None => usb_count,
    };

    // SAFETY: The entry trampoline disabled interrupts. The required live
    // addresses and the page-table objects are checked against the complete
    // transitional identity-map range before CR3 is changed.
    let result = unsafe {
        arch::x86_64::paging::install_initial_identity_map(
            boot_info,
            &image,
            &required_addresses,
            &guard_pages,
            [
                (virtio_mmio_physical, virtio_mmio_length),
                (virtio_msix_physical, virtio_msix_length),
                (Q35_IOMMU_REGISTER_BASE, PAGE_SIZE),
                (virtio_network_common_physical, virtio_network_common_length),
                (virtio_network_device_physical, virtio_network_device_length),
                (virtio_network_notify_physical, virtio_network_notify_length),
                (virtio_network_msix_physical, virtio_network_msix_length),
            ],
            &device_regions[..device_count],
            framebuffer::mapped_length(&boot_info.framebuffer)
                .map(|length| (boot_info.framebuffer.base, length)),
        )
    };
    let Ok(arch::x86_64::paging::InitialMmioMappings {
        block_transport: virtio_mmio,
        block_msix: virtio_msix_mmio,
        iommu: iommu_mmio,
        network_common: virtio_network_common_mmio,
        network_device: virtio_network_device_mmio,
        network_notification: virtio_network_notify_mmio,
        network_msix: virtio_network_msix_mmio,
        framebuffer: framebuffer_window,
        devices: device_mappings,
    }) = result
    else {
        if let Err(error) = result {
            serial_write("linox: page-table transition error: ");
            serial_write_u64(error as u64);
            serial_write("\r\n");
        }
        kernel_fail("linox: page-table transition failed\r\n");
    };
    if let Some(window) = framebuffer_window {
        // SAFETY: the window maps the framebuffer that init validated.
        unsafe { framebuffer::relocate(window) };
    }
    serial_write("linox: kernel page tables active\r\n");
    if !arch::x86_64::cpu::execute_disable_enabled()
        || !arch::x86_64::paging::identity_map_obeys_wx(boot_info, &image)
    {
        kernel_fail("linox: kernel identity-map W^X inactive\r\n");
    }
    serial_write("linox: NX-by-default identity map active\r\n");
    if !arch::x86_64::paging::direct_map_alias_is_valid() {
        kernel_fail("linox: higher-half direct-map alias invalid\r\n");
    }
    serial_write("linox: supervisor-only higher-half direct map active\r\n");
    if !arch::x86_64::paging::direct_map_translation_is_bounded() {
        kernel_fail("linox: direct-map translation bounds invalid\r\n");
    }
    serial_write("linox: bounded direct-map translation verified\r\n");
    serial_write("linox: PE executable identity pages read-only\r\n");
    serial_write("linox: PE image section permissions enforced\r\n");
    if !arch::x86_64::paging::identity_range_is_read_only_data(
        boot_info.manifest as usize,
        boot_info.manifest_size,
    ) || !arch::x86_64::paging::identity_range_is_read_only_data(
        boot_info.control_plane_bundle as usize,
        boot_info.control_plane_bundle_size,
    ) || !arch::x86_64::paging::identity_range_is_read_only_data(
        boot_info.controller_runtime as usize,
        boot_info.controller_runtime_size,
    ) || !arch::x86_64::paging::identity_range_is_read_only_data(
        boot_info.root_image as usize,
        boot_info.root_image_size,
    ) || boot_info.oci_rootfs_size != 0
        && !arch::x86_64::paging::identity_range_is_read_only_data(
            boot_info.oci_rootfs as usize,
            boot_info.oci_rootfs_size,
        )
    {
        kernel_fail("linox: boot policy inputs remain mutable or executable\r\n");
    }
    serial_write("linox: boot policy inputs immutable and non-executable\r\n");
    if !arch::x86_64::paging::supervisor_write_protect_enabled() {
        kernel_fail("linox: supervisor write protection inactive\r\n");
    }
    serial_write("linox: supervisor write protection active\r\n");
    if !arch::x86_64::paging::static_page_tables_are_read_only() {
        kernel_fail("linox: static kernel page tables remain writable\r\n");
    }
    serial_write("linox: static kernel page tables sealed read-only\r\n");
    arch::x86_64::paging::report_linux_low_template();
    if !arch::x86_64::cpu::enable_supervisor_execution_prevention() {
        kernel_fail("linox: SMEP unavailable or inactive\r\n");
    }
    serial_write("linox: supervisor execution prevention active\r\n");
    if !arch::x86_64::cpu::enable_supervisor_access_prevention() {
        kernel_fail("linox: SMAP unavailable or inactive\r\n");
    }
    serial_write("linox: supervisor access prevention active\r\n");
    if !arch::x86_64::cpu::enable_user_mode_instruction_prevention() {
        kernel_fail("linox: UMIP unavailable or inactive\r\n");
    }
    let _ = arch::x86_64::cpu::enable_extended_user_state();
    serial_write("linox: user-mode instruction prevention active\r\n");
    serial_write("linox: null and bidirectional stack guard pages active\r\n");
    if !cfg!(feature = "verification-boot") {
        serial_write_raw(b"linox: memory protections ready\r\n");
    }

    let Some(platform) = arch::x86_64::acpi::discover(
        boot_info.acpi_rsdp,
        arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
    ) else {
        kernel_fail("linox: ACPI platform discovery failed\r\n");
    };
    serial_write("linox: ACPI MADT validated\r\nlinox: enabled processors: ");
    serial_write_usize(platform.enabled_processors);
    serial_write("\r\nlinox: processor APIC IDs:");
    for apic_id in &platform.processor_apic_ids[..platform.enabled_processors] {
        serial_write(" ");
        serial_write_u64(u64::from(*apic_id));
    }
    serial_write("\r\nlinox: I/O APICs: ");
    serial_write_usize(platform.io_apics);
    serial_write("\r\nlinox: MADT local APIC address: ");
    serial_write_u64(platform.local_apic_address);
    serial_write("\r\nlinox: first I/O APIC address: ");
    serial_write_u64(u64::from(platform.first_io_apic_address));
    serial_write("\r\nlinox: first I/O APIC GSI base: ");
    serial_write_u64(u64::from(platform.first_io_apic_gsi));
    serial_write("\r\nlinox: ACPI DMAR validated");
    serial_write("\r\nlinox: remapping hardware units: ");
    serial_write_usize(platform.iommu_units);
    serial_write("\r\nlinox: DMA address width: ");
    serial_write_u64(u64::from(platform.iommu_host_address_width));
    serial_write("\r\nlinox: first remapping register base: ");
    serial_write_u64(platform.first_iommu_register_base);
    serial_write("\r\nlinox: first remapping unit includes all PCI devices: ");
    serial_write_u64(u64::from(platform.first_iommu_include_all));
    if platform.first_iommu_register_base != Q35_IOMMU_REGISTER_BASE
        || !arch::x86_64::acpi::verify_malformed_dmar_rejected(
            arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
        )
    {
        kernel_fail("\r\nlinox: ACPI DMAR validation invariant failed\r\n");
    }
    serial_write("\r\nlinox: malformed DMAR structures rejected");
    if !arch::x86_64::paging::mmio_mapping_is_writable(iommu_mmio)
        || !arch::x86_64::paging::mmio_identity_alias_is_absent(iommu_mmio)
        || !arch::x86_64::paging::mmio_translation_is_bounded(
            iommu_mmio,
            platform.first_iommu_register_base,
            PAGE_SIZE,
        )
    {
        kernel_fail("\r\nlinox: IOMMU MMIO mapping invariant failed\r\n");
    }
    let Some(iommu_capabilities) =
        arch::x86_64::iommu::probe(platform.first_iommu_register_base, iommu_mmio)
    else {
        kernel_fail("\r\nlinox: IOMMU capability probe failed\r\n");
    };
    let Some(virtio_iommu_profile) = arch::x86_64::iommu::DeviceTranslationProfile::new(
        platform.first_iommu_register_base,
        iommu_mmio,
        iommu_capabilities,
        virtio_block.bus,
        virtio_block.device,
        virtio_block.function,
    ) else {
        kernel_fail("\r\nlinox: virtio IOMMU translation profile invalid\r\n");
    };
    let Some(virtio_network_iommu_profile) = arch::x86_64::iommu::DeviceTranslationProfile::new(
        platform.first_iommu_register_base,
        iommu_mmio,
        iommu_capabilities,
        virtio_network.bus,
        virtio_network.device,
        virtio_network.function,
    ) else {
        kernel_fail("\r\nlinox: virtio-net IOMMU translation profile invalid\r\n");
    };
    if !virtio_network_iommu_profile.matches_source(
        virtio_network.bus,
        virtio_network.device,
        virtio_network.function,
    ) {
        kernel_fail("\r\nlinox: virtio-net IOMMU source identity mismatch\r\n");
    }
    serial_write("\r\nlinox: bounded writable uncached IOMMU mapping active");
    serial_write("\r\nlinox: IOMMU version: ");
    serial_write_u64(u64::from(iommu_capabilities.major_version));
    serial_write(".");
    serial_write_u64(u64::from(iommu_capabilities.minor_version));
    serial_write("\r\nlinox: IOMMU capability: ");
    serial_write_u64(iommu_capabilities.capability);
    serial_write("\r\nlinox: IOMMU extended capability: ");
    serial_write_u64(iommu_capabilities.extended_capability);
    serial_write("\r\nlinox: IOMMU translation remained disabled");
    serial_write("\r\n");
    serial_write("linox: ACPI tables use higher-half direct map\r\n");

    if !arch::x86_64::cpu::install() {
        kernel_fail("linox: architectural exception gates invalid\r\n");
    }
    serial_write("linox: GDT/TSS/IDT active\r\n");
    if !arch::x86_64::cpu::task_register_denies_user_io() {
        kernel_fail("linox: user I/O-port isolation inactive\r\n");
    }
    serial_write("linox: user I/O-port access denied\r\n");
    serial_write("linox: architectural exception gates active\r\n");
    if !arch::x86_64::cpu::verify_breakpoint() {
        kernel_fail("linox: breakpoint exception test failed\r\n");
    }

    let Some(local_apic) = arch::x86_64::apic::discover() else {
        kernel_fail("linox: enabled local APIC not found\r\n");
    };
    if local_apic.mode == arch::x86_64::apic::Mode::XApic
        && local_apic.physical_base != platform.local_apic_address
    {
        kernel_fail("linox: CPUID/MSR and ACPI disagree on local APIC\r\n");
    }
    if !local_apic.mmio_uses_direct_map() {
        kernel_fail("linox: local APIC direct-map access invalid\r\n");
    }
    serial_write("linox: local APIC discovered\r\nlinox: local APIC ID: ");
    serial_write_u64(u64::from(local_apic.id));
    serial_write("\r\nlinox: local APIC mode: ");
    match local_apic.mode {
        arch::x86_64::apic::Mode::XApic => serial_write("xAPIC"),
        arch::x86_64::apic::Mode::X2Apic => serial_write("x2APIC"),
    }
    serial_write("\r\nlinox: local APIC physical base: ");
    serial_write_u64(local_apic.physical_base);
    serial_write("\r\n");
    serial_write("linox: local APIC uses higher-half direct map\r\n");

    if !arch::x86_64::smp::start_application_processors(platform, &local_apic) {
        kernel_fail("linox: application-processor startup failed\r\n");
    }
    serial_write("linox: online processors: ");
    serial_write_usize(arch::x86_64::smp::online_count());
    serial_write("\r\n");
    if !arch::x86_64::smp::verify_cross_cpu_mechanisms() {
        kernel_fail("linox: cross-CPU interrupt mechanisms failed\r\n");
    }
    serial_write("linox: cross-CPU interrupts and invalidation verified\r\n");
    serial_write("linox: concurrent processor execution verified\r\n");

    let timers = arch::x86_64::timer::discover();
    serial_write("linox: timer capabilities discovered\r\nlinox: invariant TSC: ");
    serial_write(if timers.invariant_tsc {
        "advertised"
    } else {
        "not-advertised"
    });
    serial_write("\r\nlinox: TSC deadline timer: ");
    serial_write(if timers.tsc_deadline {
        "supported"
    } else {
        "unsupported"
    });
    serial_write("\r\nlinox: TSC frequency source: ");
    match timers.frequency_source {
        arch::x86_64::timer::FrequencySource::ArchitecturalRatio => {
            serial_write("architectural-ratio")
        }
        arch::x86_64::timer::FrequencySource::NominalProcessorFrequency => {
            serial_write("nominal-processor-frequency")
        }
        arch::x86_64::timer::FrequencySource::Unavailable => serial_write("unavailable"),
    }
    if let Some(frequency) = timers.frequency_hz {
        serial_write("\r\nlinox: reported TSC Hz: ");
        serial_write_u64(frequency);
    }
    serial_write("\r\n");

    // SAFETY: The bootstrap processor owns the still-disabled interrupt
    // environment. The checked direct map covers the asserted xAPIC MMIO
    // limit, and no other kernel component uses the PIT or APIC timer.
    let Some(apic_timer) = (unsafe {
        arch::x86_64::timer::calibrate_local_apic(
            &local_apic,
            arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
        )
    }) else {
        kernel_fail("linox: local APIC timer calibration failed\r\n");
    };
    serial_write("linox: local APIC timer calibrated\r\nlinox: APIC timer divider: ");
    serial_write_u64(u64::from(apic_timer.divider));
    serial_write("\r\nlinox: APIC timer counter Hz: ");
    serial_write_u64(apic_timer.counter_hz);
    serial_write("\r\nlinox: calibrated TSC Hz: ");
    serial_write_u64(apic_timer.tsc_hz);
    serial_write("\r\n");

    // SAFETY: The timer vector and APIC are exclusively owned during this
    // single-processor boot test. The routine restores CLI state before return.
    if !unsafe { arch::x86_64::timer::verify_local_apic_interrupt(&local_apic, &apic_timer) } {
        kernel_fail("linox: local APIC timer interrupt failed\r\n");
    }
    serial_write("linox: local APIC timer interrupt handled\r\n");

    serial_write("linox: bounded PCI bus 0 enumerated\r\n");
    serial_write("linox: modern virtio block function: ");
    serial_write_u64(u64::from(virtio_block.bus));
    serial_write(":");
    serial_write_u64(u64::from(virtio_block.device));
    serial_write(".");
    serial_write_u64(u64::from(virtio_block.function));
    if !platform.first_iommu_covers_pci(
        virtio_block.bus,
        virtio_block.device,
        virtio_block.function,
    ) || !arch::x86_64::acpi::verify_dmar_scope_resolution(
        arch::x86_64::paging::INITIAL_IDENTITY_LIMIT,
    ) {
        kernel_fail("\r\nlinox: virtio IOMMU source-scope resolution failed\r\n");
    }
    serial_write("\r\nlinox: first IOMMU device scopes: ");
    serial_write_u64(platform.first_iommu_scope_count() as u64);
    serial_write("\r\nlinox: virtio IOMMU endpoint scope resolved exactly");
    serial_write("\r\nlinox: modern virtio network function: ");
    serial_write_u64(u64::from(virtio_network.bus));
    serial_write(":");
    serial_write_u64(u64::from(virtio_network.device));
    serial_write(".");
    serial_write_u64(u64::from(virtio_network.function));
    if virtio_network.device == virtio_block.device
        || !platform.first_iommu_covers_pci(
            virtio_network.bus,
            virtio_network.device,
            virtio_network.function,
        )
        || !arch::x86_64::pci::network_function_is_disabled(virtio_network)
    {
        kernel_fail("\r\nlinox: virtio network discovery invariant failed\r\n");
    }
    serial_write("\r\nlinox: virtio-net common BAR address: ");
    serial_write_u64(virtio_network.common_bar_address);
    serial_write("\r\nlinox: virtio-net common configuration offset: ");
    serial_write_u64(u64::from(virtio_network.common_offset));
    serial_write("\r\nlinox: virtio-net common configuration length: ");
    serial_write_u64(u64::from(virtio_network.common_length));
    serial_write("\r\nlinox: virtio-net notification multiplier: ");
    serial_write_u64(u64::from(virtio_network.notify_multiplier));
    serial_write("\r\nlinox: virtio-net PCI capabilities: ");
    serial_write_u64(u64::from(virtio_network.capability_count));
    serial_write("\r\nlinox: virtio-net MSI-X vectors: ");
    serial_write_u64(u64::from(virtio_network.msix.vector_count));
    serial_write("\r\nlinox: modern virtio-net PCI capabilities validated");
    serial_write("\r\nlinox: malformed virtio-net PCI configurations rejected");
    serial_write("\r\nlinox: firmware virtio-net DMA authority revoked");
    serial_write("\r\nlinox: virtio-net PCI decoding and bus mastering disabled");
    serial_write("\r\nlinox: virtio-net IOMMU endpoint scope resolved exactly");
    serial_write("\r\nlinox: virtio common BAR address: ");
    serial_write_u64(virtio_block.common_bar_address);
    serial_write("\r\nlinox: virtio common configuration offset: ");
    serial_write_u64(u64::from(virtio_block.common_offset));
    serial_write("\r\nlinox: virtio common configuration length: ");
    serial_write_u64(u64::from(virtio_block.common_length));
    serial_write("\r\nlinox: virtio notification multiplier: ");
    serial_write_u64(u64::from(virtio_block.notify_multiplier));
    serial_write("\r\nlinox: virtio PCI capabilities: ");
    serial_write_u64(u64::from(virtio_block.capability_count));
    serial_write("\r\nlinox: modern virtio-blk PCI capabilities validated\r\n");
    serial_write("linox: malformed virtio PCI configurations rejected\r\n");
    let Some((msix_table_physical, msix_table_length)) = virtio_block.msix_table_region() else {
        kernel_fail("linox: invalid virtio MSI-X table range\r\n");
    };
    let Some((msix_pba_physical, msix_pba_length)) = virtio_block.msix_pba_region() else {
        kernel_fail("linox: invalid virtio MSI-X pending-bit range\r\n");
    };
    serial_write("linox: virtio MSI-X capability offset: ");
    serial_write_u64(u64::from(virtio_block.msix.capability_offset));
    serial_write("\r\nlinox: virtio MSI-X vectors: ");
    serial_write_u64(u64::from(virtio_block.msix.vector_count));
    serial_write("\r\nlinox: virtio MSI-X table address/length: ");
    serial_write_u64(msix_table_physical);
    serial_write("/");
    serial_write_usize(msix_table_length);
    serial_write("\r\nlinox: virtio MSI-X PBA address/length: ");
    serial_write_u64(msix_pba_physical);
    serial_write("/");
    serial_write_usize(msix_pba_length);
    serial_write("\r\nlinox: virtio MSI-X function mask: ");
    serial_write(if virtio_block.msix.function_masked {
        "masked"
    } else {
        "unmasked"
    });
    serial_write("\r\nlinox: disabled virtio MSI-X capability validated\r\n");
    if !arch::x86_64::paging::mmio_mapping_is_valid(virtio_mmio)
        || !arch::x86_64::paging::mmio_mapping_is_valid(virtio_msix_mmio)
        || !arch::x86_64::paging::mmio_mappings_are_exact([
            virtio_mmio,
            virtio_msix_mmio,
            iommu_mmio,
            virtio_network_common_mmio,
            virtio_network_device_mmio,
            virtio_network_notify_mmio,
            virtio_network_msix_mmio,
        ])
        || !arch::x86_64::paging::mmio_identity_alias_is_absent(virtio_msix_mmio)
        || !arch::x86_64::paging::mmio_translation_is_bounded(
            virtio_mmio,
            virtio_mmio_physical,
            virtio_mmio_length,
        )
        || !arch::x86_64::paging::mmio_translation_is_bounded(
            virtio_msix_mmio,
            virtio_msix_physical,
            virtio_msix_length,
        )
        || virtio_msix_mmio
            .address(msix_table_physical, msix_table_length)
            .is_none()
        || virtio_msix_mmio
            .address(msix_pba_physical, msix_pba_length)
            .is_none()
        || virtio_mmio
            .address(virtio_common_physical, virtio_common_length)
            .is_none()
        || !arch::x86_64::paging::mmio_mapping_is_valid(virtio_network_common_mmio)
        || !arch::x86_64::paging::mmio_mapping_is_writable(virtio_network_common_mmio)
        || !arch::x86_64::paging::mmio_identity_alias_is_absent(virtio_network_common_mmio)
        || !arch::x86_64::paging::mmio_translation_is_bounded(
            virtio_network_common_mmio,
            virtio_network_common_physical,
            virtio_network_common_length,
        )
        || virtio_network_common_mmio
            .address(virtio_network_common_physical, virtio_network_common_length)
            .is_none()
        || !arch::x86_64::paging::mmio_mapping_is_valid(virtio_network_device_mmio)
        || arch::x86_64::paging::mmio_mapping_is_writable(virtio_network_device_mmio)
        || !arch::x86_64::paging::mmio_identity_alias_is_absent(virtio_network_device_mmio)
        || !arch::x86_64::paging::mmio_translation_is_bounded(
            virtio_network_device_mmio,
            virtio_network_device_physical,
            virtio_network_device_length,
        )
        || virtio_network_device_mmio
            .address(virtio_network_device_physical, virtio_network_device_length)
            .is_none()
        || !arch::x86_64::paging::mmio_mapping_is_writable(virtio_network_notify_mmio)
        || !arch::x86_64::paging::mmio_identity_alias_is_absent(virtio_network_notify_mmio)
        || !arch::x86_64::paging::mmio_translation_is_bounded(
            virtio_network_notify_mmio,
            virtio_network_notify_physical,
            virtio_network_notify_length,
        )
        || !arch::x86_64::paging::mmio_mapping_is_writable(virtio_network_msix_mmio)
        || !arch::x86_64::paging::mmio_identity_alias_is_absent(virtio_network_msix_mmio)
        || !arch::x86_64::paging::mmio_translation_is_bounded(
            virtio_network_msix_mmio,
            virtio_network_msix_physical,
            virtio_network_msix_length,
        )
        || virtio_network_msix_mmio
            .address(
                virtio_network_msix_table_physical,
                virtio_network_msix_table_length,
            )
            .is_none()
        || virtio_network_msix_mmio
            .address(
                virtio_network_msix_pba_physical,
                virtio_network_msix_pba_length,
            )
            .is_none()
    {
        kernel_fail("linox: virtio MMIO mapping invalid\r\n");
    }
    serial_write("linox: bounded uncached virtio MMIO mapping active\r\n");
    serial_write("linox: virtio MMIO translation bounds verified\r\n");
    serial_write("linox: bounded uncached MSI-X mapping active\r\n");
    serial_write("linox: MSI-X cacheable aliases removed\r\n");
    serial_write("linox: bounded uncached virtio-net common mapping active\r\n");
    serial_write("linox: bounded read-only uncached virtio-net device mapping active\r\n");
    serial_write("linox: bounded uncached virtio-net notification mapping active\r\n");
    serial_write("linox: bounded uncached virtio-net MSI-X mapping active\r\n");
    serial_write("linox: virtio-net cacheable alias absent\r\n");
    let Some(virtio_network_initialization) = arch::x86_64::pci::initialize_network_without_dma(
        virtio_network,
        virtio_network_common_mmio,
        virtio_network_device_mmio,
    ) else {
        kernel_fail("linox: virtio network initialization failed\r\n");
    };
    if !arch::x86_64::pci::verify_network_feature_rejections(
        virtio_network_initialization.offered_features,
        virtio_network_initialization.accepted_features,
    ) || !arch::x86_64::pci::network_function_is_disabled(virtio_network)
        || !arch::x86_64::pci::verify_network_queue_rejections(virtio_network_initialization)
        || !arch::x86_64::pci::network_device_is_reset(virtio_network, virtio_network_common_mmio)
        || !arch::x86_64::pci::network_msix_is_disabled(virtio_network)
        || virtio_network_notify_mmio
            .address(virtio_network_initialization.receive_notification, 2)
            .is_none()
        || virtio_network_notify_mmio
            .address(virtio_network_initialization.transmit_notification, 2)
            .is_none()
    {
        kernel_fail("linox: virtio network initialization invariant failed\r\n");
    }
    serial_write("linox: virtio-net offered features: ");
    serial_write_u64(virtio_network_initialization.offered_features);
    serial_write("\r\nlinox: virtio-net accepted features: ");
    serial_write_u64(virtio_network_initialization.accepted_features);
    serial_write("\r\nlinox: virtio-net queues available: ");
    serial_write_u64(u64::from(virtio_network_initialization.queue_count));
    serial_write("\r\nlinox: virtio-net receive queue size: ");
    serial_write_u64(u64::from(virtio_network_initialization.receive_queue_size));
    serial_write("\r\nlinox: virtio-net transmit queue size: ");
    serial_write_u64(u64::from(virtio_network_initialization.transmit_queue_size));
    serial_write("\r\nlinox: virtio-net receive notification address: ");
    serial_write_u64(virtio_network_initialization.receive_notification);
    serial_write("\r\nlinox: virtio-net transmit notification address: ");
    serial_write_u64(virtio_network_initialization.transmit_notification);
    serial_write("\r\nlinox: virtio-net queues remain disabled and DMA-unbound");
    serial_write("\r\nlinox: invalid virtio-net queue geometry rejected");
    serial_write("\r\nlinox: virtio-net MSI-X remained disabled");
    serial_write("\r\nlinox: virtio-net stable MAC validated: ");
    serial_write_u64(
        virtio_network_initialization
            .mac
            .into_iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(byte)),
    );
    serial_write("\r\nlinox: virtio-net platform DMA negotiation validated");
    serial_write("\r\nlinox: invalid virtio-net feature sets rejected");
    serial_write("\r\nlinox: virtio-net returned to reset with PCI decoding disabled\r\n");
    if !arch::x86_64::pci::verify_network_msix_programming_rejections(
        virtio_network,
        virtio_network_msix_mmio,
    ) || !arch::x86_64::pci::program_masked_network_msix_vectors(
        virtio_network,
        virtio_network_msix_mmio,
        local_apic.id,
    ) || !arch::x86_64::pci::network_msix_vectors_are_masked(
        virtio_network,
        virtio_network_msix_mmio,
        local_apic.id,
    ) || !arch::x86_64::pci::network_function_is_disabled(virtio_network)
    {
        kernel_fail("linox: masked virtio-net MSI-X programming failed\r\n");
    }
    serial_write("linox: invalid virtio-net MSI-X programming rejected atomically\r\n");
    serial_write("linox: masked virtio-net RX/TX MSI-X vectors programmed\r\n");
    serial_write("linox: virtio-net MSI-X remained globally disabled\r\n");
    serial_write("linox: virtio-net remained reset and DMA-disabled after MSI-X setup\r\n");
    if !arch::x86_64::pci::verify_msix_programming_rejections(virtio_block, virtio_msix_mmio) {
        kernel_fail("linox: invalid MSI-X programming mutated table\r\n");
    }
    if !arch::x86_64::pci::program_masked_msix_vector(
        virtio_block,
        virtio_msix_mmio,
        0,
        local_apic.id,
        33,
    ) {
        kernel_fail("linox: masked MSI-X vector programming failed\r\n");
    }
    serial_write("linox: invalid MSI-X programming rejected atomically\r\n");
    serial_write("linox: kernel-owned MSI-X vector programmed masked\r\n");
    serial_write("linox: MSI-X function remained disabled\r\n");
    let Some(virtio_initialization) =
        arch::x86_64::pci::initialize_without_dma(virtio_block, virtio_mmio)
    else {
        kernel_fail("linox: virtio block initialization failed\r\n");
    };
    if !arch::x86_64::pci::verify_feature_rejections(
        virtio_initialization.offered_features,
        virtio_initialization.accepted_features,
    ) {
        kernel_fail("linox: invalid virtio block features accepted\r\n");
    }
    serial_write("linox: virtio block offered features: ");
    serial_write_u64(virtio_initialization.offered_features);
    serial_write("\r\nlinox: virtio block accepted features: ");
    serial_write_u64(virtio_initialization.accepted_features);
    serial_write("\r\nlinox: virtio block queues available: ");
    serial_write_u64(u64::from(virtio_initialization.queue_count));
    serial_write("\r\nlinox: virtio block reset and feature negotiation validated\r\n");
    serial_write("linox: virtio bus mastering remained disabled\r\n");
    serial_write("linox: virtio block returned to reset state\r\n");

    if !volume::verify_contract() || !volume::install_live() {
        kernel_fail("linox: persistent volume contract invalid\r\n");
    }
    serial_write("linox: bounded persistent volume format validated\r\n");
    serial_write("linox: interrupted volume commits recovered\r\n");
    serial_write("linox: corrupt persistent volume records rejected\r\n");

    if !capability::verify_authority_invariants() {
        kernel_fail("linox: capability authority invariant failed\r\n");
    }
    serial_write("linox: capability derivation and revocation verified\r\n");
    serial_write("linox: exhaustive capability attenuation verified\r\n");
    if !domain::verify_cross_domain_revocation_invariants() {
        kernel_fail("linox: cross-domain revocation invariant failed\r\n");
    }
    serial_write("linox: cross-domain capability revocation verified\r\n");
    serial_write("linox: per-root delegation provenance verified\r\n");
    serial_write("linox: exhaustive delegated attenuation verified\r\n");
    serial_write("linox: independent delegation roots verified\r\n");
    if !domain::verify_domain_ancestry_invariants() {
        kernel_fail("linox: domain ancestry invariant failed\r\n");
    }
    serial_write("linox: domain lifecycle ancestry verified\r\n");
    if !domain::verify_container_domain_invariants() {
        kernel_fail("linox: Linux domain boundary invariant failed\r\n");
    }
    serial_write("linox: Linux domain boundaries verified\r\n");
    if !domain::verify_generation_exhaustion_invariants() {
        kernel_fail("linox: generation exhaustion invariant failed\r\n");
    }
    serial_write("linox: exhausted generational slots skipped\r\n");
    if !domain::verify_frame_quarantine_registry_invariants() {
        kernel_fail("linox: frame quarantine registry invariant failed\r\n");
    }
    serial_write("linox: per-service frame quarantines isolated\r\n");
    if !domain::verify_auxiliary_service_registry_invariants() {
        kernel_fail("linox: auxiliary service registry invariant failed\r\n");
    }
    serial_write("linox: bounded auxiliary service registry verified\r\n");
    serial_write("linox: service lifecycle roles separated\r\n");
    serial_write("linox: service failure policies separated\r\n");
    serial_write("linox: domain resource admission policies verified\r\n");
    serial_write("linox: auxiliary service quiescence enforced\r\n");
    serial_write("linox: auxiliary supervision authority enforced\r\n");
    serial_write("linox: auxiliary retirement events sequenced\r\n");
    serial_write("linox: auxiliary retirement publication atomic\r\n");
    if !domain::verify_auxiliary_call_epoch_invariants() {
        kernel_fail("linox: auxiliary call epoch invariant failed\r\n");
    }
    serial_write("linox: auxiliary call epoch renewal constrained\r\n");
    if !domain::verify_auxiliary_stop_revocation_invariants() {
        kernel_fail("linox: auxiliary stop revocation invariant failed\r\n");
    }
    serial_write("linox: auxiliary stop authority revoked\r\n");
    if !domain::verify_auxiliary_retirement_overflow_invariants() {
        kernel_fail("linox: auxiliary retirement overflow invariant failed\r\n");
    }
    serial_write("linox: auxiliary retirement overflow summarized\r\n");
    if !domain::verify_auxiliary_fault_policy_invariants() {
        kernel_fail("linox: auxiliary fault policy invariant failed\r\n");
    }
    serial_write("linox: stop-only auxiliary faults contained\r\n");
    serial_write("linox: auxiliary fault authority revoked before publication\r\n");
    if !domain::verify_service_restart_budget_invariants() {
        kernel_fail("linox: service restart budget invariant failed\r\n");
    }
    serial_write("linox: bounded service restart policy verified\r\n");
    if !domain::verify_clean_service_exit_invariants() {
        kernel_fail("linox: clean service exit invariant failed\r\n");
    }
    serial_write("linox: clean service exit publication atomic\r\n");
    if !domain::verify_lifecycle_event_invariants() {
        kernel_fail("linox: lifecycle event queue invariant failed\r\n");
    }
    serial_write("linox: bounded lifecycle event queue verified\r\n");
    serial_write("linox: lifecycle event overflow notification verified\r\n");

    let Some(control_plane) = domain::initialize_control_plane(&boot_manifest) else {
        kernel_fail("linox: control-plane domain construction failed\r\n");
    };
    serial_write(
        "linox: persistent control-plane domain sealed\r\nlinox: control-plane domain ID: ",
    );
    serial_write_u64(control_plane);
    serial_write("\r\n");
    let Some(service_domain) = domain::initialize_boot_service() else {
        kernel_fail("linox: isolated service domain construction failed\r\n");
    };
    let Some(service_identity) = domain::domain_service_identity(service_domain) else {
        kernel_fail("linox: stable service identity unavailable\r\n");
    };
    if domain::primary_service_identity() != Some(service_identity) {
        kernel_fail("linox: primary service identity mismatch\r\n");
    }
    serial_write("linox: IPC-only service domain ID: ");
    serial_write_u64(service_domain);
    serial_write("\r\n");

    let summary = summarize_memory(boot_info);
    serial_write("linox: memory descriptors: ");
    serial_write_usize(summary.descriptors);
    serial_write("\r\nlinox: usable memory MiB: ");
    serial_write_u64(summary.conventional_pages / UEFI_PAGES_PER_MIB);
    serial_write("\r\nlinox: reclaimable boot-service pages: ");
    serial_write_u64(summary.boot_service_pages);
    serial_write("\r\nlinox: reserved loader pages: ");
    serial_write_u64(summary.loader_pages);
    if !verify_initial_frame_allocation(boot_info) {
        kernel_fail("linox: physical frame allocation test failed\r\n");
    }
    if !heap::verify() {
        kernel_fail("linox: kernel heap test failed\r\n");
    }
    if !cfg!(feature = "verification-boot") {
        serial_write_raw(b"linox: memory manager ready\r\n");
    }
    serial_write("\r\nlinox: physical frame allocator active");
    serial_write("\r\nlinox: reclaimed boot-service frames: ");
    serial_write_u64(memory::reclaimed_boot_service_frame_count().unwrap_or(0));
    serial_write("\r\nlinox: atomic frame reservations verified");
    serial_write("\r\nlinox: contiguous frame reservations verified");
    serial_write("\r\nlinox: physical frames zeroed before allocation");
    serial_write("\r\nlinox: tracked frame release ownership verified");
    serial_write("\r\nlinox: stale frame leases rejected");
    serial_write("\r\nlinox: per-domain physical frame budgets enforced");
    if !verify_runtime_volume_dma_retirement() {
        kernel_fail("\r\nlinox: runtime volume DMA quarantine invariant failed\r\n");
    }
    serial_write("\r\nlinox: failed runtime volume DMA retirement quarantined");
    if !arch::x86_64::pci::verify_queue_rejections() {
        kernel_fail("\r\nlinox: virtio queue contract invalid\r\n");
    }
    let Some([virtio_dma_frame, iommu_guard_frame]) =
        memory::allocate_frames::<2>(memory::FrameOwner::KERNEL)
    else {
        kernel_fail("\r\nlinox: virtio DMA and guard frame allocation failed\r\n");
    };
    if !memory::frames_owned_by(
        memory::FrameOwner::KERNEL,
        &[virtio_dma_frame, iommu_guard_frame],
    ) {
        kernel_fail("\r\nlinox: virtio DMA and guard frame ownership invalid\r\n");
    }
    let Some(iommu_translation) = arch::x86_64::iommu::build_inactive_translation(
        iommu_capabilities,
        virtio_block.bus,
        virtio_block.device,
        virtio_block.function,
        virtio_dma_frame,
    ) else {
        kernel_fail("\r\nlinox: inactive IOMMU translation construction failed\r\n");
    };
    if !iommu_translation.is_exact(virtio_dma_frame)
        || !arch::x86_64::iommu::verify_inactive_translation_rejections(
            iommu_capabilities,
            virtio_dma_frame,
        )
        || arch::x86_64::iommu::probe(platform.first_iommu_register_base, iommu_mmio).is_none()
    {
        kernel_fail("\r\nlinox: inactive IOMMU translation invariant failed\r\n");
    }
    let Some(virtio_iommu_evidence) = iommu_translation.evidence(virtio_dma_frame) else {
        kernel_fail("\r\nlinox: inactive IOMMU translation evidence unavailable\r\n");
    };
    serial_write("\r\nlinox: IOMMU root/context hierarchy constructed");
    serial_write("\r\nlinox: IOMMU root table address: ");
    serial_write_u64(iommu_translation.root_table_address());
    serial_write("\r\nlinox: one-page identity DMA translation encoded exactly");
    serial_write("\r\nlinox: invalid IOMMU table inputs rejected");
    serial_write("\r\nlinox: IOMMU hardware state unchanged after table construction");
    if !arch::x86_64::iommu::verify_failed_activation_retirement(
        iommu_capabilities,
        virtio_dma_frame,
    ) {
        kernel_fail("\r\nlinox: failed IOMMU activation retirement invariant failed\r\n");
    }
    serial_write("\r\nlinox: failed IOMMU activation rollback quarantined");
    let arch::x86_64::iommu::TranslationActivation::Active(iommu_active) =
        arch::x86_64::iommu::activate_translation(
            platform.first_iommu_register_base,
            iommu_mmio,
            iommu_capabilities,
            &iommu_translation,
            virtio_dma_frame,
        )
    else {
        kernel_fail("\r\nlinox: IOMMU translation activation failed\r\n");
    };
    if !iommu_active.is_active() {
        kernel_fail("\r\nlinox: IOMMU translation activation invariant failed\r\n");
    }
    serial_write("\r\nlinox: IOMMU root table installed");
    serial_write("\r\nlinox: IOMMU translation enabled for virtio DMA");
    let Some(virtio_dma_virtual) = virtio_dma_frame.direct_map_address() else {
        kernel_fail("\r\nlinox: virtio DMA frame is outside direct map\r\n");
    };
    let Some(iommu_guard_virtual) = iommu_guard_frame.direct_map_address() else {
        kernel_fail("\r\nlinox: IOMMU guard frame is outside direct map\r\n");
    };
    if cfg!(feature = "verification-boot") {
        // The guard remains owned but deliberately absent from the translation
        // hierarchy. A blocked device write must leave every sentinel byte intact.
        unsafe {
            core::ptr::write_bytes(iommu_guard_virtual as *mut u8, 0xa5, 4096);
        }
        // SAFETY: This deliberately invalid DMA request is restricted to the
        // verification image. Normal boots never provoke a hardware fault.
        let Some(mut fault_probe) = (unsafe {
            arch::x86_64::pci::VirtioBlockBackend::start(
                virtio_block,
                virtio_mmio,
                virtio_dma_frame.address(),
                virtio_dma_virtual,
            )
        }) else {
            kernel_fail("\r\nlinox: adversarial virtio backend activation failed\r\n");
        };
        let Some(unmapped_attempt) =
            fault_probe.attempt_unmapped_read(2, iommu_guard_frame.address())
        else {
            kernel_fail("\r\nlinox: unauthorized virtio DMA request was not submitted\r\n");
        };
        let faulting_transport_bounded = unmapped_attempt.transport_outcome_is_bounded(0);
        let faulting_device_quiesced = fault_probe.finish();
        let guard_unchanged = (0..4096)
            .all(|offset| unsafe { (iommu_guard_virtual as *const u8).add(offset).read() == 0xa5 });
        if !faulting_transport_bounded {
            kernel_fail("\r\nlinox: unauthorized virtio DMA request state invalid\r\n");
        }
        if !faulting_device_quiesced {
            kernel_fail("\r\nlinox: faulting virtio device teardown failed\r\n");
        }
        if !guard_unchanged {
            kernel_fail("\r\nlinox: unmapped DMA guard frame was modified\r\n");
        }
        serial_write("\r\nlinox: unauthorized virtio DMA payload blocked");
        serial_write("\r\nlinox: faulting virtio transport outcome bounded");
        serial_write("\r\nlinox: unmapped DMA guard frame remained unchanged");
        serial_write("\r\nlinox: faulting virtio device reset and bus mastering revoked");
        if !iommu_active.recover_expected_write_fault(
            virtio_block.bus,
            virtio_block.device,
            virtio_block.function,
            iommu_guard_frame.address(),
        ) {
            kernel_fail("\r\nlinox: expected IOMMU fault validation or recovery failed\r\n");
        }
        serial_write("\r\nlinox: IOMMU fault source and address validated");
        serial_write("\r\nlinox: IOMMU write-permission fault reason validated");
        serial_write("\r\nlinox: IOMMU fault record cleared and translation recovered");
    }
    // SAFETY: The allocator returned one exclusively kernel-owned page, its
    // direct-map alias covers the complete physical frame, and the lease stays
    // live until the device has reset and bus mastering is disabled.
    let Some(virtio_read) = (unsafe {
        arch::x86_64::pci::read_blank_sector_interrupt(
            virtio_block,
            virtio_mmio,
            virtio_msix_mmio,
            &local_apic,
            virtio_dma_frame.address(),
            virtio_dma_virtual,
            2,
        )
    }) else {
        kernel_fail("\r\nlinox: bounded virtio block read failed\r\n");
    };
    serial_write("\r\nlinox: kernel-owned virtio MSI-X interrupt delivered");
    serial_write("\r\nlinox: exactly one virtio completion interrupt handled");
    serial_write("\r\nlinox: virtio MSI-X masked and disabled after completion");
    serial_write("\r\nlinox: temporary virtio interrupt gate retired");
    if virtio_read.capacity_sectors < linox_volume_format::HOST_VOLUME_MINIMUM_SECTORS
        || virtio_read.used_length != 513
    {
        kernel_fail("\r\nlinox: deterministic virtio block geometry invalid\r\n");
    }
    // SAFETY: The one-shot probe returned only after reset and bus-master
    // revocation. The same exclusive lease remains live and is reused by the
    // persistent backend until `finish` proves teardown.
    let Some(mut persistent_block) = (unsafe {
        arch::x86_64::pci::VirtioBlockBackend::start(
            virtio_block,
            virtio_mmio,
            virtio_dma_frame.address(),
            virtio_dma_virtual,
        )
    }) else {
        kernel_fail("\r\nlinox: persistent virtio backend activation failed\r\n");
    };
    let mut persisted_local_configuration = [0_u8; PERSISTENT_LOCAL_CONFIG_SIZE];
    let mut persisted_local_record = None;
    let mut persisted_local_configuration_valid = true;
    let persisted_oci_catalog = &mut *HOST_CONTROL.persisted_oci_catalog.get();
    let mut persisted_oci_catalog_valid = false;
    let mut persisted_oci_catalog_corrupt = false;
    let disk_volume = (|| {
        let capacity_sectors = persistent_block.capacity_sectors();
        let state = volume::open_host_volume(&mut persistent_block, capacity_sectors).ok()?;
        let verified = volume::recover(&mut persistent_block)?;
        if verified.generation != state.generation
            || linox_volume_format::HostVolumeHeader::decode(verified.payload())
                != Some(state.header)
        {
            return None;
        }
        match volume::recover_local_config(
            &mut persistent_block,
            &mut persisted_local_configuration,
        ) {
            Ok(record) => persisted_local_record = record,
            Err(_) => persisted_local_configuration_valid = false,
        }
        (persisted_oci_catalog_valid, persisted_oci_catalog_corrupt) =
            recover_oci_catalog_snapshot(&mut persistent_block, persisted_oci_catalog);
        (verified.generation == state.generation
            && linox_volume_format::HostVolumeHeader::decode(verified.payload())
                == Some(state.header))
        .then_some(state)
    })();
    if !persistent_block.finish() {
        kernel_fail("\r\nlinox: persistent virtio backend teardown failed\r\n");
    }
    serial_write("\r\nlinox: persistent virtio device reset and bus mastering revoked");
    if !iommu_active.finish()
        || arch::x86_64::iommu::probe(platform.first_iommu_register_base, iommu_mmio).is_none()
    {
        kernel_fail("\r\nlinox: IOMMU translation teardown failed\r\n");
    }
    serial_write("\r\nlinox: IOMMU translation disabled after device quiescence");
    serial_write("\r\nlinox: IOMMU root table cleared");
    serial_write("\r\nlinox: IOMMU fault status clear after recovery");
    if !iommu_translation.retire() {
        kernel_fail("\r\nlinox: inactive IOMMU translation retirement failed\r\n");
    }
    serial_write("\r\nlinox: IOMMU translation frames scrubbed and released");
    if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[iommu_guard_frame])
        || memory::any_frame_lease_live(&[iommu_guard_frame])
    {
        kernel_fail("\r\nlinox: IOMMU guard frame retirement failed\r\n");
    }
    serial_write("\r\nlinox: IOMMU guard frame scrubbed and released");
    if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[virtio_dma_frame])
        || memory::any_frame_lease_live(&[virtio_dma_frame])
    {
        kernel_fail("\r\nlinox: virtio DMA frame retirement failed\r\n");
    }
    serial_write("\r\nlinox: virtio DMA frame scrubbed and released");
    if !virtio_iommu_evidence.is_retired()
        || !virtio_network_iommu_profile.is_inactive()
        || !arch::x86_64::pci::network_function_is_disabled(virtio_network)
        || !arch::x86_64::pci::verify_network_dma_layout()
        || !arch::x86_64::pci::verify_network_dma_layout_rejections()
    {
        kernel_fail("\r\nlinox: virtio-net DMA construction precondition failed\r\n");
    }
    let Some([virtio_network_dma_frame, virtio_network_guard_frame]) =
        memory::allocate_frames::<2>(memory::FrameOwner::KERNEL)
    else {
        kernel_fail("\r\nlinox: virtio-net DMA and guard frame allocation failed\r\n");
    };
    // SAFETY: The allocator owns and directly maps this live kernel lease.
    if !memory::frames_owned_by(
        memory::FrameOwner::KERNEL,
        &[virtio_network_dma_frame, virtio_network_guard_frame],
    ) || unsafe { !frame_is_zero(virtio_network_dma_frame) }
        || unsafe { !frame_is_zero(virtio_network_guard_frame) }
    {
        kernel_fail("\r\nlinox: virtio-net DMA or guard frame ownership invalid\r\n");
    }
    let Some(virtio_network_translation) = arch::x86_64::iommu::build_inactive_translation(
        iommu_capabilities,
        virtio_network.bus,
        virtio_network.device,
        virtio_network.function,
        virtio_network_dma_frame,
    ) else {
        kernel_fail("\r\nlinox: virtio-net IOMMU hierarchy construction failed\r\n");
    };
    let Some(virtio_network_evidence) =
        virtio_network_translation.evidence(virtio_network_dma_frame)
    else {
        kernel_fail("\r\nlinox: virtio-net IOMMU evidence unavailable\r\n");
    };
    if !virtio_network_translation.is_exact(virtio_network_dma_frame)
        || !virtio_network_evidence.is_fresh_after(virtio_iommu_evidence)
        || !virtio_network_iommu_profile.is_inactive()
        || !arch::x86_64::pci::network_function_is_disabled(virtio_network)
        || !arch::x86_64::iommu::verify_inactive_translation_rejections(
            iommu_capabilities,
            virtio_network_dma_frame,
        )
    {
        kernel_fail("\r\nlinox: virtio-net DMA confinement invariant failed\r\n");
    }
    serial_write("\r\nlinox: generation-owned virtio-net DMA page allocated");
    serial_write("\r\nlinox: bounded virtio-net RX/TX DMA layout validated");
    serial_write("\r\nlinox: malformed virtio-net DMA layouts rejected");
    serial_write("\r\nlinox: dedicated virtio-net IOMMU hierarchy constructed");
    serial_write("\r\nlinox: virtio-net IOMMU source and DMA page encoded exactly");
    serial_write("\r\nlinox: virtio-net DMA and IOMMU leases are generation-fresh");
    serial_write("\r\nlinox: virtio-net IOMMU hardware remained inactive");
    serial_write("\r\nlinox: virtio-net bus mastering remained disabled");
    let Some(virtio_network_dma_virtual) = virtio_network_dma_frame.direct_map_address() else {
        kernel_fail("\r\nlinox: virtio-net DMA page is outside direct map\r\n");
    };
    let Some(virtio_network_guard_virtual) = virtio_network_guard_frame.direct_map_address() else {
        kernel_fail("\r\nlinox: virtio-net guard page is outside direct map\r\n");
    };
    let arch::x86_64::iommu::TranslationActivation::Active(virtio_network_active) =
        arch::x86_64::iommu::activate_translation(
            platform.first_iommu_register_base,
            iommu_mmio,
            iommu_capabilities,
            &virtio_network_translation,
            virtio_network_dma_frame,
        )
    else {
        kernel_fail("\r\nlinox: virtio-net IOMMU activation failed\r\n");
    };
    let network_queues_activated = virtio_network_active.is_active()
        && unsafe {
            arch::x86_64::pci::activate_network_queues_without_io(
                virtio_network,
                virtio_network_common_mmio,
                virtio_network_dma_frame.address(),
                virtio_network_dma_virtual,
            )
        };
    // SAFETY: The same exclusive page and exact source translation remain
    // live. The empty-queue proof returned only after resetting the device and
    // revoking bus mastering, so the one-shot transmit can safely reconfigure
    // the function before the IOMMU translation is retired below.
    let network_transmit = network_queues_activated
        .then(|| unsafe {
            arch::x86_64::pci::transmit_network_probe(
                virtio_network,
                virtio_network_common_mmio,
                virtio_network_notify_mmio,
                virtio_network_msix_mmio,
                &local_apic,
                virtio_network_dma_frame.address(),
                virtio_network_dma_virtual,
            )
        })
        .flatten();
    let network_receive = if cfg!(feature = "verification-boot") {
        // The guard is owned but absent from the NIC's exact translation. This
        // deliberately faulting receive is verification-only; normal boots do
        // not submit invalid DMA.
        unsafe {
            core::ptr::write_bytes(virtio_network_guard_virtual as *mut u8, 0xa5, PAGE_SIZE);
        }
        let network_dma_fault = network_transmit
            .is_some()
            .then(|| unsafe {
                arch::x86_64::pci::attempt_unmapped_network_receive(
                    virtio_network,
                    virtio_network_common_mmio,
                    virtio_network_notify_mmio,
                    virtio_network_msix_mmio,
                    &local_apic,
                    virtio_network_dma_frame.address(),
                    virtio_network_dma_virtual,
                    virtio_network_guard_frame.address(),
                )
            })
            .flatten();
        let network_fault_completion_published =
            network_dma_fault.map(|fault| fault.completion_published);
        let network_guard_unchanged = (0..PAGE_SIZE).all(|offset| unsafe {
            (virtio_network_guard_virtual as *const u8)
                .add(offset)
                .read()
                == 0xa5
        });
        if network_fault_completion_published.is_none() || !network_guard_unchanged {
            kernel_fail("\r\nlinox: unauthorized virtio-net RX DMA was not contained\r\n");
        }
        if !virtio_network_active.recover_expected_write_fault(
            virtio_network.bus,
            virtio_network.device,
            virtio_network.function,
            virtio_network_guard_frame.address(),
        ) {
            kernel_fail("\r\nlinox: virtio-net IOMMU fault validation or recovery failed\r\n");
        }
        // SAFETY: The faulting exchange returned with the function reset and
        // bus mastering revoked before this valid verification exchange.
        network_dma_fault
            .is_some()
            .then(|| unsafe {
                arch::x86_64::pci::receive_network_arp_reply(
                    virtio_network,
                    virtio_network_common_mmio,
                    virtio_network_notify_mmio,
                    virtio_network_msix_mmio,
                    &local_apic,
                    virtio_network_dma_frame.address(),
                    virtio_network_dma_virtual,
                )
            })
            .flatten()
    } else {
        // Normal boot exercises only the valid, mapped receive path. This
        // leaves the NIC in the same verified reset state without provoking a
        // VT-d fault merely to prove rejection.
        unsafe {
            arch::x86_64::pci::receive_network_arp_reply(
                virtio_network,
                virtio_network_common_mmio,
                virtio_network_notify_mmio,
                virtio_network_msix_mmio,
                &local_apic,
                virtio_network_dma_frame.address(),
                virtio_network_dma_virtual,
            )
        }
    };
    let network_translation_retired = virtio_network_active.finish();
    if !network_queues_activated {
        kernel_fail("\r\nlinox: virtio-net empty queue activation failed\r\n");
    }
    if network_transmit.is_none_or(|transmit| transmit.frame_length != 19) {
        kernel_fail("\r\nlinox: confined virtio-net transmit failed\r\n");
    }
    if network_receive.is_none_or(|receive| !(42..=1523).contains(&receive.frame_length)) {
        kernel_fail("\r\nlinox: confined virtio-net receive failed\r\n");
    }
    if !network_translation_retired
        || !arch::x86_64::pci::network_function_is_disabled(virtio_network)
    {
        kernel_fail("\r\nlinox: virtio-net translation retirement failed\r\n");
    }
    serial_write("\r\nlinox: virtio-net IOMMU activated before queue authority");
    serial_write("\r\nlinox: empty virtio-net RX/TX queues bound to confined DMA");
    serial_write("\r\nlinox: virtio-net DRIVER_OK established with empty rings");
    serial_write("\r\nlinox: virtio-net bus mastering enabled last");
    serial_write("\r\nlinox: empty virtio-net queues quiesced without notification");
    serial_write("\r\nlinox: virtio-net bus mastering revoked before IOMMU teardown");
    serial_write("\r\nlinox: confined virtio-net TX descriptor published");
    serial_write("\r\nlinox: virtio-net TX queue notified");
    serial_write("\r\nlinox: exactly one virtio-net TX interrupt delivered");
    serial_write("\r\nlinox: virtio-net TX used-ring completion validated");
    serial_write("\r\nlinox: virtio-net TX payload and guards preserved");
    serial_write("\r\nlinox: bounded Ethernet probe transmitted");
    serial_write("\r\nlinox: virtio-net TX route retired before DMA release");
    serial_write("\r\nlinox: unauthorized virtio-net RX DMA payload blocked");
    serial_write("\r\nlinox: faulting virtio-net transport outcome bounded");
    serial_write("\r\nlinox: virtio-net unmapped guard page remained unchanged");
    serial_write("\r\nlinox: faulting virtio-net device quiesced before recovery");
    serial_write("\r\nlinox: virtio-net IOMMU fault source and address validated");
    serial_write("\r\nlinox: virtio-net IOMMU write fault cleared and translation recovered");
    serial_write("\r\nlinox: confined virtio-net RX descriptor published");
    serial_write("\r\nlinox: bounded ARP request transmitted");
    serial_write("\r\nlinox: exactly one virtio-net RX interrupt delivered");
    serial_write("\r\nlinox: virtio-net RX used-ring completion validated");
    serial_write("\r\nlinox: QEMU gateway ARP reply validated");
    serial_write("\r\nlinox: virtio-net RX payload bounds preserved");
    serial_write("\r\nlinox: virtio-net RX/TX routes retired before DMA release");
    if !virtio_network_translation.retire() {
        kernel_fail("\r\nlinox: virtio-net DMA confinement retirement failed\r\n");
    }
    if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[virtio_network_guard_frame])
        || memory::any_frame_lease_live(&[virtio_network_guard_frame])
    {
        kernel_fail("\r\nlinox: virtio-net guard frame retirement failed\r\n");
    }
    serial_write("\r\nlinox: virtio-net unmapped guard page scrubbed and released");
    if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[virtio_network_dma_frame])
        || memory::any_frame_lease_live(&[virtio_network_dma_frame])
        || !virtio_network_evidence.is_retired()
    {
        kernel_fail("\r\nlinox: virtio-net DMA frame retirement failed\r\n");
    }
    serial_write("\r\nlinox: virtio-net DMA confinement retired cleanly");
    let Some(host_volume) = disk_volume else {
        kernel_fail("\r\nlinox: persistent virtio volume transaction failed\r\n");
    };
    if !cfg!(feature = "verification-boot") {
        serial_write_raw(b"linox: boot devices ready\r\n");
    }
    serial_write("\r\nlinox: generation-owned virtio DMA frame allocated");
    serial_write("\r\nlinox: malformed virtio queue geometry rejected");
    serial_write("\r\nlinox: bounded blank virtio sector read completed");
    serial_write("\r\nlinox: virtio read guard bytes preserved");
    serial_write("\r\nlinox: virtio used-ring completion validated");
    serial_write("\r\nlinox: deterministic virtio capacity sectors: ");
    serial_write_u64(virtio_read.capacity_sectors);
    serial_write("\r\nlinox: virtio bus mastering revoked after read");
    serial_write("\r\nlinox: bounded virtio volume transaction completed");
    serial_write("\r\nlinox: disk-backed volume generation: ");
    serial_write_u64(host_volume.generation);
    serial_write("\r\nlinox: host volume sectors: ");
    serial_write_u64(host_volume.header.volume_sectors);
    serial_write("\r\nlinox: host volume data sectors: ");
    serial_write_u64(host_volume.header.data_sectors);
    match host_volume.disposition {
        volume::HostVolumeDisposition::Initialized => {
            serial_write("\r\nlinox: disk-backed volume initialized and flushed")
        }
        volume::HostVolumeDisposition::Migrated => {
            serial_write("\r\nlinox: legacy disk-backed volume migrated and flushed")
        }
        volume::HostVolumeDisposition::Recovered => {
            serial_write("\r\nlinox: disk-backed volume recovered after reboot")
        }
    }
    if !address_space::verify_isolated_user_mapping() {
        kernel_fail("\r\nlinox: isolated address-space test failed\r\n");
    }
    serial_write("\r\nlinox: isolated address space active");
    if !address_space::verify_control_plane_wx_layout() {
        kernel_fail("\r\nlinox: control-plane W^X layout failed\r\n");
    }
    serial_write("\r\nlinox: control-plane W^X mappings active");
    serial_write("\r\nlinox: address-space frames use higher-half direct map");
    if !address_space::verify_auxiliary_address_space_lifecycle() {
        kernel_fail("\r\nlinox: auxiliary address-space lifecycle failed\r\n");
    }
    serial_write("\r\nlinox: auxiliary address-space transaction verified");
    serial_write("\r\nlinox: concurrent auxiliary address spaces isolated");
    serial_write("\r\nlinox: auxiliary scheduler admission resource-gated");
    serial_write("\r\nlinox: auxiliary address-space ownership retained");
    serial_write("\r\nlinox: auxiliary runtime teardown path connected");
    serial_write("\r\nlinox: auxiliary teardown restores kernel page tables");
    let control_plane_bundle = core::slice::from_raw_parts(
        boot_info.control_plane_bundle,
        boot_info.control_plane_bundle_size,
    );
    let Some(control_plane_image) = executable::parse(control_plane_bundle) else {
        kernel_fail("\r\nlinox: control-plane executable container invalid\r\n");
    };
    let controller_runtime = core::slice::from_raw_parts(
        boot_info.controller_runtime,
        boot_info.controller_runtime_size,
    );
    let Some(controller_image) = native_elf::inspect_controller(controller_runtime) else {
        kernel_fail("\r\nlinox: embedded controller ELF invalid\r\n");
    };
    if !address_space::install_interactive_controller_image(&controller_image) {
        kernel_fail("\r\nlinox: embedded controller installation failed\r\n");
    }
    if !executable::verify_parser_rejections(control_plane_bundle) {
        kernel_fail("\r\nlinox: malformed executable containers accepted\r\n");
    }
    serial_write("\r\nlinox: bounded executable container accepted");
    serial_write("\r\nlinox: authenticated executable entry points accepted");
    serial_write("\r\nlinox: malformed executable containers rejected\r\n");
    let root_image = core::slice::from_raw_parts(boot_info.root_image, boot_info.root_image_size);
    if !initramfs::verify_pinned_image(root_image) {
        kernel_fail("linox: bounded initramfs image invalid\r\n");
    }
    serial_write("linox: deterministic initramfs image accepted\r\n");
    serial_write("linox: bounded newc archive paths validated\r\n");
    serial_write("linox: executable init entry discovered\r\n");
    if !initramfs::verify_rejections(root_image) {
        kernel_fail("linox: malformed initramfs parser test failed\r\n");
    }
    serial_write("linox: malformed initramfs archives rejected\r\n");
    if !initramfs::verify_owned_materialization(root_image) {
        kernel_fail("linox: owned root-image materialization failed\r\n");
    }
    serial_write("linox: measured root image copied into owned memory\r\n");
    serial_write("linox: owned root image remained source-independent\r\n");
    serial_write("linox: owned root frames scrubbed and released\r\n");
    if !initramfs::verify_read_only_index(root_image) {
        kernel_fail("linox: read-only root index failed\r\n");
    }
    serial_write("linox: bounded read-only root index constructed\r\n");
    serial_write("linox: root lookups resolved only owned image bytes\r\n");
    serial_write("linox: invalid root lookup paths denied\r\n");
    serial_write("linox: indexed root frames scrubbed and released\r\n");
    if !initramfs::publish_read_only_root(root_image) {
        kernel_fail("linox: persistent read-only root publication failed\r\n");
    }
    serial_write("linox: measured root published in kernel-owned memory\r\n");
    let Some(volume_service_node) = initramfs::published_regular_file_node(b"native/volume") else {
        kernel_fail("linox: isolated volume service missing\r\n");
    };
    let Some(volume_service) = initramfs::published_file_by_node(volume_service_node) else {
        kernel_fail("linox: isolated volume service unreadable\r\n");
    };
    let Some(volume_image) = native_elf::inspect(volume_service) else {
        kernel_fail("linox: isolated volume service ELF invalid\r\n");
    };
    if volume_image.bytes.len() != volume_service.len()
        || volume_image.entry == 0
        || volume_image.segments.iter().flatten().count() != 3
        || volume_image.relocation_count == 0
        || volume_image.relocations[..volume_image.relocation_count]
            .iter()
            .any(|relocation| {
                relocation.is_none_or(|relocation| relocation.target == 0 || relocation.addend == 0)
            })
    {
        kernel_fail("linox: isolated volume service load plan incomplete\r\n");
    }
    serial_write("linox: measured isolated volume service discovered\r\n");
    serial_write("linox: bounded native PIE load plan accepted\r\n");
    serial_write("linox: relative-only service relocations accepted\r\n");
    if !address_space::verify_native_service_materialization(&volume_image) {
        kernel_fail("linox: native volume service materialization failed\r\n");
    }
    serial_write("linox: native service segments materialized in owned frames\r\n");
    serial_write("linox: native service relative relocations applied\r\n");
    serial_write("linox: native service W^X address space verified\r\n");
    serial_write("linox: native service guard pages verified\r\n");
    let Some(network_service_node) = initramfs::published_regular_file_node(b"native/network")
    else {
        kernel_fail("linox: isolated network service missing\r\n");
    };
    let Some(network_service) = initramfs::published_file_by_node(network_service_node) else {
        kernel_fail("linox: isolated network service unreadable\r\n");
    };
    let Some(network_image) = native_elf::inspect(network_service) else {
        kernel_fail("linox: isolated network service ELF invalid\r\n");
    };
    if network_image.bytes.len() != network_service.len()
        || network_image.entry == 0
        || !(3..=4).contains(&network_image.segments.iter().flatten().count())
        || network_image.relocation_count == 0
        || network_image.relocations[..network_image.relocation_count]
            .iter()
            .any(|relocation| {
                relocation.is_none_or(|relocation| relocation.target == 0 || relocation.addend == 0)
            })
    {
        kernel_fail("linox: isolated network service load plan incomplete\r\n");
    }
    serial_write("linox: measured isolated network service discovered\r\n");
    serial_write("linox: bounded native network PIE load plan accepted\r\n");
    serial_write("linox: native network service relative relocations accepted\r\n");
    if !address_space::verify_native_network_service_materialization(&network_image) {
        kernel_fail("linox: native network service materialization failed\r\n");
    }
    serial_write("linox: native network service segments materialized in owned frames\r\n");
    serial_write("linox: native network service relative relocations applied\r\n");
    serial_write("linox: native network service W^X address space verified\r\n");
    serial_write("linox: native network service guard pages verified\r\n");
    let Some(protocol_service_node) = initramfs::published_regular_file_node(b"native/protocol")
    else {
        kernel_fail("linox: isolated protocol service missing\r\n");
    };
    let Some(protocol_service) = initramfs::published_file_by_node(protocol_service_node) else {
        kernel_fail("linox: isolated protocol service unreadable\r\n");
    };
    let Some(protocol_image) = native_elf::inspect(protocol_service) else {
        kernel_fail("linox: isolated protocol service ELF invalid\r\n");
    };
    if protocol_image.bytes.len() != protocol_service.len()
        || protocol_image.entry == 0
        || protocol_image.segments.iter().flatten().count() != 3
        || protocol_image.relocation_count == 0
        || protocol_image.relocations[..protocol_image.relocation_count]
            .iter()
            .any(|relocation| {
                relocation.is_none_or(|relocation| relocation.target == 0 || relocation.addend == 0)
            })
    {
        kernel_fail("linox: isolated protocol service load plan incomplete\r\n");
    }
    serial_write("linox: measured isolated protocol service discovered\r\n");
    serial_write("linox: bounded native protocol PIE load plan accepted\r\n");
    serial_write("linox: native protocol service relative relocations accepted\r\n");
    if !address_space::verify_native_service_materialization(&protocol_image) {
        kernel_fail("linox: native protocol service materialization failed\r\n");
    }
    serial_write("linox: native protocol service segments materialized in owned frames\r\n");
    serial_write("linox: native protocol service relative relocations applied\r\n");
    serial_write("linox: native protocol service W^X address space verified\r\n");
    serial_write("linox: native protocol service guard pages verified\r\n");
    if !linux_mount::verify_contract() || !linux_mount::install_initial() {
        kernel_fail("linox: initial Linux mount namespace invalid\r\n");
    }
    serial_write("linox: generation-safe Linux mount namespace installed\r\n");
    serial_write("linox: immutable measured root mounted read-only\r\n");
    if !linux_user::verify_contract() || !linux_user::install_initial() {
        kernel_fail("linox: initial Linux user namespace invalid\r\n");
    }
    serial_write("linox: generation-safe Linux user namespace installed\r\n");
    serial_write("linox: Linux domain root mapped outside native authority\r\n");
    serial_write("linox: Linux privilege policy sealed fail-closed\r\n");
    if !linux_tmpfs::verify_contract()
        || !linux_tmpfs::install()
        || !linux_tmpfs::verify_live_object_contract()
    {
        kernel_fail("linox: transactional RAM store invalid\r\n");
    }
    if !image_store::install() {
        kernel_fail("linox: boot-local image store initialization failed\r\n");
    }
    if !image_store::verify_rootfs_unpack_policy() {
        kernel_fail("linox: OCI rootfs unpack policy verification failed\r\n");
    }
    serial_write("linox: bounded OCI rootfs unpack policy verified\r\n");
    if !cfg!(feature = "verification-boot") {
        serial_write_raw(b"linox: control runtime ready\r\n");
    }
    if !cfg!(feature = "verification-boot") {
        if !scheduler::initialize_control_runtime(control_plane) {
            kernel_fail("linox: control scheduler initialization failed\r\n");
        }
        if !arch::x86_64::cpu::initialize_user_call_gate() {
            kernel_fail("linox: userspace call-gate initialization failed\r\n");
        }
        if !packet::install() {
            kernel_fail("linox: packet runtime initialization failed\r\n");
        }
        if !arch::x86_64::cpu::publish_linux_abi_test_results() {
            kernel_fail("linox: Linux ABI status publication failed\r\n");
        }
    }
    if !linux_socket::configure(
        virtio_network,
        virtio_network_initialization,
        virtio_network_common_mmio,
        virtio_network_notify_mmio,
        virtio_network_iommu_profile,
    ) {
        kernel_fail("\r\nlinox: Linux socket transport configuration failed\r\n");
    }
    if cfg!(feature = "verification-boot") {
        if !network::set_link(1)
            || !network::set_ipv4((24_u64 << 32) | 0x0a00_020f)
            || !network::set_gateway(0x0a00_0202)
            || !network::set_dns(0x0a00_0203)
        {
            kernel_fail("linox: verification network configuration failed\r\n");
        }
        serial_write("linox: quota-bound page-backed RAM store installed\r\n");
        serial_write("linox: generation-safe Linux tmpfs view mounted at /tmp\r\n");
        let Some(system_profile_node) =
            initramfs::published_regular_file_node(b"etc/linox-system-profile")
        else {
            kernel_fail("linox: minimal system profile missing\r\n");
        };
        if initramfs::published_file_by_node(system_profile_node).is_none() {
            kernel_fail("linox: minimal system profile unreadable\r\n");
        }
        serial_write("linox: pinned minimal system profile accepted\r\n");
        if !linux_process::verify_lifecycle_contract() {
            kernel_fail("linox: bounded Linux process lifecycle contract invalid\r\n");
        }
        if !address_space::verify_linux_runtime_translation_permissions() {
            kernel_fail("linox: Linux translation recovery permissions invalid\r\n");
        }
        serial_write("linox: Linux translation recovery permissions validated\r\n");
        if !arch::x86_64::cpu::verify_cross_cpu_linux_runtime_mechanisms() {
            kernel_fail("linox: cross-CPU Linux runtime mechanisms invalid\r\n");
        }
        serial_write("linox: cross-CPU Linux signals, futexes, pipes, and sockets validated\r\n");
        serial_write("linox: bounded Linux process lifecycle contract validated\r\n");
        serial_write("linox: Linux stopped and continued child wait states validated\r\n");
        serial_write("linox: generation-bound Linux process roots validated\r\n");
        serial_write("linox: bounded Linux process resource bundles validated\r\n");
        serial_write("linox: Linux process mapping inventory validated\r\n");
        serial_write("linox: transactional Linux child publication validated\r\n");
        serial_write("linox: cloned Linux child resources published atomically\r\n");
        serial_write("linox: address-space-bound Linux process contexts validated\r\n");
        serial_write("linox: Linux fork child return context derived\r\n");
        serial_write("linox: Linux process contexts staged on native scheduler\r\n");
        serial_write("linox: scheduled Linux process roots matched ownership\r\n");
        serial_write("linox: stale Linux process scheduler bindings rejected\r\n");
        serial_write("linox: Linux process roots inherited kernel mappings\r\n");
        serial_write("linox: scheduled Linux child CR3 activated and restored\r\n");
        serial_write("linox: scheduled Linux child returned from ring 3\r\n");
        serial_write("linox: Linux fork child RAX zero executed\r\n");
        serial_write("linox: Linux process child FS isolation executed\r\n");
        serial_write("linox: complete Linux process register frame executed\r\n");
        serial_write("linox: Linux process child exit captured from ring 3\r\n");
        serial_write("linox: Linux process child exit drove zombie wait status\r\n");
        if !linux_process::verify_private_page_copy_contract() {
            kernel_fail("linox: bounded Linux private page copy invalid\r\n");
        }
        serial_write("linox: bounded Linux private page copy validated\r\n");
        if !address_space::verify_linux_process_hierarchy_clone() {
            kernel_fail("linox: bounded Linux child hierarchy clone invalid\r\n");
        }
        serial_write("linox: Linux child hierarchy and copy-on-write isolation validated\r\n");
        if !linux_sysv_ipc::verify_shared_memory_lifecycle() {
            kernel_fail("linox: Linux SysV shared memory lifecycle invalid\r\n");
        }
        serial_write("linox: Linux SysV shared memory lifecycle validated\r\n");
        if !linux_sysv_ipc::verify_semaphore_lifecycle() {
            kernel_fail("linox: Linux SysV semaphore lifecycle invalid\r\n");
        }
        serial_write("linox: Linux SysV semaphore lifecycle validated\r\n");
        if !linux_sysv_ipc::verify_message_queue_lifecycle() {
            kernel_fail("linox: Linux SysV message queue lifecycle invalid\r\n");
        }
        serial_write("linox: Linux SysV message queue lifecycle validated\r\n");
        let Some(system_init_node) = initramfs::published_regular_file_node(b"sbin/init") else {
            kernel_fail("linox: minimal system init missing\r\n");
        };
        let Some(system_init) = initramfs::published_file_by_node(system_init_node) else {
            kernel_fail("linox: minimal system init unreadable\r\n");
        };
        let Some(system_init_plan) = linux_elf::measured_static_exec_plan(system_init) else {
            kernel_fail("linox: minimal system init invalid\r\n");
        };
        if system_init_plan.entry != 0x41_5000
            || system_init_plan.executable.page_count != 4
            || system_init_plan.writable.page_count != 1
            || system_init_plan.executable.writable
            || !system_init_plan.executable.executable
            || !system_init_plan.writable.writable
            || system_init_plan.writable.executable
        {
            kernel_fail("linox: minimal system init plan outside profile\r\n");
        }
        serial_write("linox: measured minimal system init planned\r\n");
        let Some(exec_second_node) = initramfs::published_regular_file_node(b"bin/exec-second")
        else {
            kernel_fail("linox: second measured Linux exec target missing\r\n");
        };
        let Some(exec_second) = initramfs::published_file_by_node(exec_second_node) else {
            kernel_fail("linox: second measured Linux exec target unreadable\r\n");
        };
        let Some(signal_probe_node) = initramfs::published_regular_file_node(b"bin/signal-probe")
        else {
            kernel_fail("linox: measured Linux signal probe missing\r\n");
        };
        let Some(signal_probe) = initramfs::published_file_by_node(signal_probe_node) else {
            kernel_fail("linox: measured Linux signal probe unreadable\r\n");
        };
        let Some(conformance_node) =
            initramfs::published_regular_file_node(b"bin/linux-conformance")
        else {
            kernel_fail("linox: measured Linux conformance probe missing\r\n");
        };
        let Some(conformance) = initramfs::published_file_by_node(conformance_node) else {
            kernel_fail("linox: measured Linux conformance probe unreadable\r\n");
        };
        let Some(exec_second_plan) = linux_elf::measured_static_exec_plan(exec_second) else {
            kernel_fail("linox: second measured Linux exec target invalid\r\n");
        };
        let Some(signal_probe_plan) = linux_elf::measured_static_exec_plan(signal_probe) else {
            kernel_fail("linox: measured Linux signal probe invalid\r\n");
        };
        let Some(conformance_plan) = linux_elf::measured_static_exec_plan(conformance) else {
            kernel_fail("linox: measured Linux conformance probe invalid\r\n");
        };
        let measured_file = |name: &[u8]| {
            initramfs::published_regular_file_node(name).and_then(initramfs::published_file_by_node)
        };
        let Some(dynamic_main) = measured_file(b"linux/init") else {
            kernel_fail("linox: measured Linux dynamic main missing\r\n");
        };
        let Some(dynamic_interpreter) = measured_file(b"linux/ld-linox.so") else {
            kernel_fail("linox: measured Linux interpreter missing\r\n");
        };
        let Some(dynamic_dependency) = measured_file(b"linux/liblinox.so") else {
            kernel_fail("linox: measured Linux primary dependency missing\r\n");
        };
        let Some(dynamic_auxiliary) = measured_file(b"linux/liblinox-aux.so") else {
            kernel_fail("linox: measured Linux auxiliary dependency missing\r\n");
        };
        let Some(dynamic_plan) = linux_elf::measured_interpreted_exec_plan(
            dynamic_main,
            dynamic_interpreter,
            [dynamic_dependency, dynamic_auxiliary],
        ) else {
            kernel_fail("linox: measured Linux interpreted graph invalid\r\n");
        };
        if dynamic_plan.process.initial_entry != 0x60_0200
            || dynamic_plan.process.main_entry != 0x40_0100
            || dynamic_plan.dependency_bases != [0x61_0000, 0x63_0000]
            || linux_elf::measured_interpreted_exec_plan(
                signal_probe,
                dynamic_interpreter,
                [dynamic_dependency, dynamic_auxiliary],
            )
            .is_some()
            || linux_elf::measured_interpreted_exec_plan(
                dynamic_main,
                dynamic_interpreter,
                [dynamic_auxiliary, dynamic_dependency],
            )
            .is_some()
            || linux_elf::measured_interpreted_exec_plan(
                dynamic_main,
                &dynamic_interpreter[..64],
                [dynamic_dependency, dynamic_auxiliary],
            )
            .is_some()
        {
            kernel_fail("linox: measured Linux interpreted graph substitution accepted\r\n");
        }
        serial_write("linox: measured-root Linux interpreted exec graph planned\r\n");
        serial_write("linox: measured-root Linux graph substitution rejected\r\n");
        if signal_probe == exec_second
            || signal_probe_plan.executable.virtual_page == exec_second_plan.executable.virtual_page
            || signal_probe_plan.executable.page_count != 2
            || exec_second_plan.executable.page_count != 2
        {
            kernel_fail("linox: measured Linux exec target invalid\r\n");
        }
        if conformance_plan.entry != 0x40_0100
            || conformance_plan.executable.page_count == 0
            || conformance_plan.executable.page_count > 5
            || conformance_plan.writable.page_count != 1
            || conformance_plan.executable.writable
            || !conformance_plan.executable.executable
            || !conformance_plan.writable.writable
            || conformance_plan.writable.executable
        {
            kernel_fail("linox: measured Linux conformance probe outside profile\r\n");
        }
        serial_write("linox: dedicated measured Linux signal runtime planned\r\n");
        serial_write("linox: expandable measured Linux conformance runtime planned\r\n");
        serial_write("linox: multiple measured Linux exec targets planned\r\n");
        if !linux_elf::verify_parser() {
            kernel_fail("linox: Linux ELF64 parser invariant failed\r\n");
        }
        serial_write("linox: non-executable Linux GNU stack enforced\r\n");
        serial_write("linox: bounded Linux ELF metadata headers validated\r\n");
        serial_write("linox: bounded Linux interpreter metadata validated\r\n");
        serial_write("linox: bounded Linux ELF verifier stack usage validated\r\n");
        serial_write("linox: bounded Linux GNU RELRO metadata validated\r\n");
        serial_write("linox: three-load Linux ELF runtime mapping verified\r\n");
        if !linux_elf::verify_linked_probe() {
            kernel_fail("linox: linked Linux ELF64 probe invariant failed\r\n");
        }
        if !linux_elf::verify_linux_conformance_probe() {
            kernel_fail("linox: ring-3 Linux conformance probe invariant failed\r\n");
        }
        serial_write("linox: ring-3 Linux conformance suite passed\r\n");
        serial_write("linox: live Linux process address-space snapshot validated\r\n");
        serial_write("linox: incomplete Linux process snapshots rejected\r\n");
        serial_write("linox: live Linux PID 1 context admitted to process model\r\n");
        serial_write("linox: live Linux process registry persisted across syscalls\r\n");
        serial_write("linox: live Linux child address space cloned transactionally\r\n");
        serial_write("linox: live Linux cloned child executed in ring 3\r\n");
        serial_write("linox: toolchain-linked static Linux ELF executed\r\n");
        serial_write("linox: five-page Linux executable mapping validated\r\n");
        serial_write("linox: bounded Linux exec rejection preserved live image\r\n");
        serial_write("linox: Linux exec mapping rollback restored active image\r\n");
        serial_write("linox: Linux exec argv and environment delivered\r\n");
        serial_write("linox: bounded Linux exec vectors validated\r\n");
        serial_write("linox: old Linux image pages removed after exec\r\n");
        serial_write("linox: replaced Linux image retired cleanly\r\n");
        serial_write("linox: Linux close-on-exec descriptors transitioned\r\n");
        serial_write("linox: Linux exec signal state transitioned\r\n");
        serial_write("linox: Linux exec process identity installed\r\n");
        serial_write("linox: Linux executable link followed exec identity\r\n");
        serial_write("linox: measured-root Linux exec selection validated\r\n");
        serial_write("linox: measured-dirfd Linux execveat validated\r\n");
        serial_write("linox: measured-fd Linux empty-path exec validated\r\n");
        serial_write("linox: measured Linux exec selection is profile-driven\r\n");
        serial_write("linox: independent measured Linux exec layouts validated\r\n");
        serial_write("linox: runtime-selected Linux exec plans committed\r\n");
        serial_write("linox: variable-page Linux exec images committed\r\n");
        serial_write("linox: Linux active image ownership transitioned\r\n");
        serial_write("linox: generation-bound Linux image ownership verified\r\n");
        serial_write("linox: generation-bound Linux page-table hierarchy verified\r\n");
        serial_write("linox: Linux RELRO ownership permissions synchronized\r\n");
        serial_write("linox: stale Linux image retirement rejected\r\n");
        serial_write("linox: old Linux image leases retired at exec commit\r\n");
        serial_write("linox: Linux image lease double release rejected\r\n");
        serial_write("linox: Linux replacement frames allocated on demand\r\n");
        serial_write("linox: Linux replacement frame generations reclaimed\r\n");
        if !linux_elf::verify_load_plan() {
            kernel_fail("linox: Linux ELF64 load plan invariant failed\r\n");
        }
        serial_write("linox: bounded multi-page Linux ELF plan verified\r\n");
        serial_write("linox: bounded Linux ET_DYN load bias validated\r\n");
        if !linux_elf::verify_interpreted_plan() {
            kernel_fail("linox: authenticated Linux dependency plan invalid\r\n");
        }
        serial_write("linox: bounded Linux interpreter resolution plan validated\r\n");
        serial_write("linox: measured Linux interpreter bytes enforced\r\n");
        serial_write("linox: authenticated Linux dependency bytes enforced\r\n");
        serial_write("linox: Linux dependency SONAME identity bound\r\n");
        if !linux_elf::verify_dynamic_relocation_rejections() {
            kernel_fail("linox: malformed Linux dynamic relocation metadata accepted\r\n");
        }
        serial_write("linox: bounded Linux relative relocation metadata validated\r\n");
        serial_write("linox: bounded Linux symbol relocation metadata validated\r\n");
        serial_write("linox: bounded Linux PLT relocation metadata validated\r\n");
        serial_write("linox: split Linux PLT relocation table validated\r\n");
        serial_write("linox: bounded Linux SysV hash metadata validated\r\n");
        serial_write("linox: bounded Linux GNU hash metadata validated\r\n");
        if !linux_elf::verify_unresolved_dynamic_image_rejected() {
            kernel_fail("linox: unresolved dynamic Linux image admitted as static\r\n");
        }
        serial_write("linox: unresolved dynamic Linux static entry denied\r\n");
        serial_write("linox: separate-header Linux interpreter plan validated\r\n");
        serial_write("linox: Linux dynamic startup metadata validated\r\n");
        serial_write("linox: Linux auxiliary vector encoding validated\r\n");
        serial_write("linox: Linux page-aliasing ELF segments rejected\r\n");
        serial_write("linox: Linux ELF entry metadata overlap rejected\r\n");
        if !linux_elf::verify_dependency_list_metadata() {
            kernel_fail("linox: bounded Linux dependency-list metadata invalid\r\n");
        }
        serial_write("linox: bounded Linux dependency list validated\r\n");
        serial_write("linox: bounded Linux dependency authority graph validated\r\n");
        serial_write("linox: bounded Linux dependency TLS metadata validated\r\n");
        if !linux_elf::verify_tls_relocation_metadata() {
            kernel_fail("linox: malformed Linux TLS relocation metadata accepted\r\n");
        }
        serial_write("linox: bounded Linux TPOFF64 relocation metadata validated\r\n");
        if !linux_elf::verify_static_tls_layout() {
            kernel_fail("linox: bounded Linux static TLS layout invalid\r\n");
        }
        serial_write("linox: bounded Linux static TLS layout plan validated\r\n");
        serial_write("linox: reusable Linux TLS page materialization validated\r\n");
        if !arch::x86_64::cpu::verify_linux_tls_context_contract() {
            kernel_fail("linox: bounded Linux TLS execution context invalid\r\n");
        }
        serial_write("linox: bounded Linux TLS execution context validated\r\n");
        if !linux_elf::verify_tls_template_metadata() {
            kernel_fail("linox: bounded Linux TLS template metadata invalid\r\n");
        }
        serial_write("linox: bounded Linux TLS template metadata validated\r\n");
        if !linux_elf::verify_mapped_load_plan(boot_info.image_base as u64, boot_info.image_size) {
            kernel_fail("linox: Linux ELF64 address-space mapping failed\r\n");
        }
        serial_write("linox: Linux static clock ID and resolution profile validated\r\n");
        serial_write("linox: Linux restart_syscall default interruption validated\r\n");
        serial_write("linox: Linux ELF headers mapped in executable segment\r\n");
        serial_write("linox: bounded multi-page Linux ELF mapping verified\r\n");
        if !linux_elf::verify_mapped_system_init_plan(
            boot_info.image_base as u64,
            boot_info.image_size,
        ) {
            kernel_fail("linox: minimal system init execution failed\r\n");
        }
        serial_write("linox: measured minimal system init executed as PID 1\r\n");
        serial_write("linox: persistent Linux PID 1 supervisor lifecycle validated\r\n");
        serial_write("linox: bounded Linux standard signal lifecycle validated\r\n");
        serial_write("linox: bounded Linux private futex lifecycle validated\r\n");
        serial_write("linox: bounded Linux devfs profile validated\r\n");
        serial_write("linox: lifecycle-aware bounded procfs validated\r\n");
        serial_write("linox: transactional page-backed tmpfs lifecycle validated\r\n");
        serial_write("linox: minimal system init exited cleanly\r\n");
        if !linux_elf::verify_mapped_interpreted_plan(
            boot_info.image_base as u64,
            boot_info.image_size,
        ) {
            kernel_fail("linox: interpreted Linux ELF64 address-space mapping failed\r\n");
        }
        serial_write("linox: measured-root interpreted Linux exec committed\r\n");
        serial_write("linox: interpreted Linux exec graph remapped\r\n");
        serial_write("linox: bounded Linux cross-area copy-in validated\r\n");
        serial_write("linox: complete interpreted Linux graph retired at exec\r\n");
        serial_write("linox: interpreted Linux exec stack replaced atomically\r\n");
        serial_write("linox: old interpreted Linux stack lease retired at exec\r\n");
        serial_write("linox: replacement Linux stack lease reclaimed\r\n");
        serial_write("linox: static Linux exec stack replaced atomically\r\n");
        serial_write("linox: old static Linux stack lease retired at exec\r\n");
        serial_write("linox: replacement static Linux stack lease reclaimed\r\n");
        serial_write("linox: interpreted Linux exec heap replaced atomically\r\n");
        serial_write("linox: old interpreted Linux heap lease retired at exec\r\n");
        serial_write("linox: replacement Linux heap lease reclaimed\r\n");
        serial_write("linox: static Linux exec heap replaced atomically\r\n");
        serial_write("linox: old static Linux heap lease retired at exec\r\n");
        serial_write("linox: replacement static Linux heap lease reclaimed\r\n");
        serial_write("linox: Linux exec process break reset\r\n");
        serial_write("linox: interpreted Linux TLS state rematerialized\r\n");
        serial_write("linox: interpreted Linux TLS leases replaced atomically\r\n");
        serial_write("linox: old interpreted Linux TLS leases retired at exec\r\n");
        serial_write("linox: replacement Linux TLS leases reclaimed\r\n");
        serial_write("linox: interpreted Linux sibling stack replaced atomically\r\n");
        serial_write("linox: old interpreted Linux sibling stack lease retired at exec\r\n");
        serial_write("linox: replacement Linux sibling stack lease reclaimed\r\n");
        serial_write("linox: interpreted Linux mmap registry empty across exec\r\n");
        serial_write("linox: static Linux mmap registry empty across exec\r\n");
        serial_write("linox: interpreted Linux page-table hierarchy replaced atomically\r\n");
        serial_write("linox: old interpreted Linux page-table leases retired at exec\r\n");
        serial_write("linox: replacement Linux page-table leases reclaimed\r\n");
        serial_write("linox: static Linux page-table hierarchy replaced atomically\r\n");
        serial_write("linox: old static Linux page-table leases retired at exec\r\n");
        serial_write("linox: replacement static Linux page-table leases reclaimed\r\n");
        serial_write("linox: static Linux exec auxiliary vector rebuilt\r\n");
        serial_write("linox: interpreted Linux exec auxiliary vector rebuilt\r\n");
        serial_write("linox: canonical interpreted Linux executable identity validated\r\n");
        serial_write("linox: interpreted Linux exec vectors generalized\r\n");
        serial_write("linox: combined Linux static TLS materialized\r\n");
        serial_write("linox: ordered Linux dependency TLS layout materialized\r\n");
        serial_write("linox: Linux TLS active before initializers\r\n");
        serial_write("linox: Linux dependency TLS active before constructors\r\n");
        serial_write("linox: toolchain-driven Linux dependency TLS relocation applied\r\n");
        serial_write("linox: toolchain-driven Linux auxiliary TLS relocation applied\r\n");
        serial_write("linox: linker-resolved Linux TLS symbols executed\r\n");
        serial_write("linox: bounded Linux TLS syscall copies validated\r\n");
        serial_write("linox: independent Linux sibling TLS materialized\r\n");
        serial_write("linox: non-current Linux TLS syscall access denied\r\n");
        serial_write("linox: Linux TLS execution context switched and restored\r\n");
        serial_write("linox: guarded Linux sibling stack materialized\r\n");
        serial_write("linox: non-current Linux stack syscall access denied\r\n");
        serial_write("linox: bounded Linux clone contract validated\r\n");
        serial_write("linox: Linux child return context constructed\r\n");
        serial_write("linox: Linux child context cleared on slot reuse\r\n");
        serial_write("linox: failed Linux clone publication rolled back\r\n");
        serial_write("linox: Linux parent and child TID publication validated\r\n");
        serial_write("linox: unpublished Linux child retired cleanly\r\n");
        serial_write("linox: full Linux syscall register frame preserved\r\n");
        serial_write("linox: typed Linux syscall frame validated\r\n");
        serial_write("linox: complete Linux child context persisted\r\n");
        serial_write("linox: stale Linux return contexts rejected\r\n");
        serial_write("linox: Linux child return frame installed atomically\r\n");
        serial_write("linox: Linux return ownership restored to parent\r\n");
        serial_write("linox: stale Linux return installation left state unchanged\r\n");
        serial_write("linox: live Linux syscall return frame round-trip validated\r\n");
        serial_write("linox: guarded Linux child executed in ring 3\r\n");
        serial_write("linox: Linux child exit restored suspended parent\r\n");
        serial_write("linox: bounded Linux clone syscall dispatched\r\n");
        serial_write("linox: sequential Linux clone slot reuse validated\r\n");
        serial_write("linox: reused Linux child stack began scrubbed\r\n");
        serial_write("linox: monotonic Linux clone TIDs validated\r\n");
        serial_write("linox: live Linux child TIDs matched published words\r\n");
        serial_write("linox: live Linux child FS self pointers validated\r\n");
        serial_write("linox: per-thread Linux signal masks isolated\r\n");
        serial_write("linox: bidirectional Linux sched_yield switching validated\r\n");
        serial_write("linox: occupied Linux clone capacity rejected live\r\n");
        serial_write("linox: live Linux clone failures rolled back transactionally\r\n");
        serial_write("linox: Linux clone return values validated\r\n");
        serial_write("linox: Linux clone child TID cleared on exit\r\n");
        serial_write("linox: Linux clone parent TID preserved on child exit\r\n");
        serial_write("linox: Linux parent and child futex waits blocked\r\n");
        serial_write("linox: explicit Linux futex wake restored child\r\n");
        serial_write("linox: Linux clear-child-TID wake restored parent\r\n");
        serial_write("linox: Linux futex waiter state reclaimed\r\n");
        serial_write("linox: per-thread Linux syscall stacks validated\r\n");
        serial_write("linox: bounded Linux TID lifecycle validated\r\n");
        serial_write("linox: stale Linux thread handles rejected\r\n");
        serial_write("linox: Linux per-thread exit state isolated\r\n");
        serial_write("linox: Linux thread exit registrations cleared\r\n");
        serial_write("linox: Linux thread table reclaimed on exit\r\n");
        serial_write("linox: sibling Linux TLS frame scrubbed and released\r\n");
        serial_write("linox: Linux sibling stack scrubbed and released\r\n");
        serial_write("linox: retired Linux thread stacks scrubbed\r\n");
        serial_write("linox: Linux TLS frame scrubbed and released\r\n");
        serial_write("linox: bounded interpreted Linux ELF mapping verified\r\n");
        serial_write("linox: toolchain-linked Linux interpreter executed\r\n");
        serial_write("linox: two-page Linux interpreter RX mapping verified\r\n");
        serial_write("linox: userspace Linux interpreter metadata discovered\r\n");
        serial_write("linox: userspace Linux runtime files discovered\r\n");
        serial_write("linox: userspace Linux PT_LOAD mappings derived\r\n");
        serial_write("linox: userspace Linux startup metadata consumed\r\n");
        serial_write("linox: userspace Linux main segments mapped\r\n");
        serial_write("linox: userspace Linux DT_NEEDED path resolved\r\n");
        serial_write("linox: userspace Linux dependency segments mapped\r\n");
        serial_write("linox: complete interpreted Linux image ownership tracked\r\n");
        serial_write("linox: userspace Linux dependency bias selected\r\n");
        serial_write("linox: Linux dependency frames allocated on demand\r\n");
        serial_write("linox: Linux executable frames allocated on demand\r\n");
        serial_write("linox: bounded Linux dependency page contracts applied\r\n");
        serial_write("linox: bounded Linux dependency mapping slots isolated\r\n");
        serial_write("linox: userspace Linux auxiliary dependency mapped\r\n");
        serial_write("linox: Linux read-only dependency segment mapped\r\n");
        serial_write("linox: toolchain-linked Linux PIE and shared object executed\r\n");
        serial_write("linox: linker-emitted Linux dynamic tags validated\r\n");
        serial_write("linox: separate-header interpreted Linux mapping verified\r\n");
        serial_write("linox: Linux dependency W^X mapping verified\r\n");
        serial_write("linox: interpreter-first Linux ring-3 entry verified\r\n");
        serial_write("linox: userspace Linux interpreter self-relocation applied\r\n");
        serial_write("linox: userspace Linux relocation table shapes validated\r\n");
        serial_write("linox: userspace Linux relative relocation applied\r\n");
        serial_write("linox: userspace Linux GLOB_DAT relocation applied\r\n");
        serial_write("linox: userspace Linux JUMP_SLOT relocation applied\r\n");
        serial_write("linox: userspace Linux hash bucket resolution applied\r\n");
        serial_write("linox: userspace Linux symbol names matched\r\n");
        serial_write("linox: userspace Linux cross-object symbol resolved\r\n");
        serial_write("linox: userspace Linux two-provider symbols resolved\r\n");
        serial_write("linox: Linux JUMP_SLOT dependency call executed\r\n");
        serial_write("linox: Linux auxiliary JUMP_SLOT dependency call executed\r\n");
        serial_write("linox: userspace Linux dependency self-relocations applied\r\n");
        serial_write("linox: userspace Linux auxiliary dependency self-relocations applied\r\n");
        serial_write("linox: bounded Linux main preinit array validated\r\n");
        serial_write("linox: userspace Linux main preinit metadata consumed\r\n");
        serial_write("linox: userspace Linux main preinit executed\r\n");
        serial_write("linox: Linux preinit-before-dependency initialization ordered\r\n");
        serial_write("linox: bounded Linux dependency init arrays validated\r\n");
        serial_write("linox: userspace Linux init arrays bound to relocations\r\n");
        serial_write("linox: userspace Linux dependency constructors executed\r\n");
        serial_write("linox: bounded Linux main init array validated\r\n");
        serial_write("linox: userspace Linux main constructor executed\r\n");
        serial_write("linox: Linux dependency-before-main initialization ordered\r\n");
        serial_write("linox: userspace Linux constructor startup context delivered\r\n");
        serial_write("linox: bounded Linux DT_INIT functions validated\r\n");
        serial_write("linox: userspace Linux DT_INIT functions executed\r\n");
        serial_write("linox: Linux DT_INIT-before-init-array ordering enforced\r\n");
        serial_write("linox: Linux auxiliary dependency entry executed\r\n");
        serial_write("linox: metadata-driven Linux relative relocations applied\r\n");
        serial_write("linox: Linux copy errors and overflow bounds verified\r\n");
        serial_write("linox: Linux proof workload assembled from source\r\n");
        serial_write("linox: Linux bounded console writes validated\r\n");
        serial_write("linox: Linux atomic vectored console writes validated\r\n");
        serial_write("linox: Linux bounded descriptor polling validated\r\n");
        serial_write("linox: Linux bounded ppoll inputs validated\r\n");
        serial_write("linox: Linux bounded epoll lifecycle validated\r\n");
        serial_write("linox: Linux bounded epoll_pwait inputs validated\r\n");
        serial_write("linox: Linux bounded epoll_pwait2 timeout validated\r\n");
        serial_write("linox: Linux four-slot auxiliary descriptor table validated\r\n");
        serial_write("linox: Linux bounded eventfd notification validated\r\n");
        serial_write("linox: Linux bounded timerfd expiration validated\r\n");
        serial_write("linox: Linux bounded pipe notification validated\r\n");
        serial_write("linox: Linux atomic vectored pipe I/O validated\r\n");
        serial_write("linox: Linux mutable descriptor status flags validated\r\n");
        serial_write("linox: Linux bounded pipe introspection validated\r\n");
        serial_write("linox: Linux anonymous descriptor metadata validated\r\n");
        serial_write("linox: Linux bounded syscall stack movement validated\r\n");
        serial_write("linox: Linux callable syscall assertion helpers validated\r\n");
        serial_write("linox: Linux container-local root credentials verified\r\n");
        serial_write("linox: Linux errno recovery verified in ring 3\r\n");
        serial_write("linox: Linux single-thread signal mask validated\r\n");
        serial_write("linox: Linux bounded signal actions validated\r\n");
        serial_write("linox: Linux synchronous SIGSEGV lifecycle validated\r\n");
        serial_write("linox: Linux self-directed signal delivery validated\r\n");
        serial_write("linox: Linux thread-directed signal delivery validated\r\n");
        serial_write("linox: Linux legacy thread signal delivery validated\r\n");
        serial_write("linox: Linux pending signal delivery validated\r\n");
        serial_write("linox: Linux standard signal queue ordering validated\r\n");
        serial_write("linox: Linux chained pending signal delivery validated\r\n");
        serial_write("linox: Linux scheduler-backed timed signal wait validated\r\n");
        serial_write("linox: Linux signal-interrupted timed wait validated\r\n");
        serial_write("linox: Linux one-shot signal action validated\r\n");
        serial_write("linox: Linux rt signal frame ABI validated\r\n");
        serial_write("linox: Linux mutable signal context validated\r\n");
        serial_write("linox: Linux autodisarming alternate stack validated\r\n");
        serial_write("linox: Linux alternate signal stack delivery validated\r\n");
        serial_write("linox: Linux bounded alternate signal stack validated\r\n");
        serial_write("linox: Linux single-thread process identity verified\r\n");
        serial_write("linox: Linux initial environment vector validated\r\n");
        serial_write("linox: Linux credential auxiliary vector validated\r\n");
        serial_write("linox: Linux clock-tick auxiliary vector validated\r\n");
        serial_write("linox: Linux platform auxiliary vector validated\r\n");
        serial_write("linox: Linux conservative hardware capabilities validated\r\n");
        serial_write("linox: Linux FS base query validated\r\n");
        serial_write("linox: Linux clear-child-TID exit action validated\r\n");
        serial_write("linox: Linux robust-list registration validated\r\n");
        serial_write("linox: Linux scheduler-backed timed futex wait validated\r\n");
        serial_write("linox: Linux read-only memory transition validated\r\n");
        serial_write("linox: Linux initial process namespace identity validated\r\n");
        serial_write("linox: Linux bounded process name state validated\r\n");
        serial_write("linox: Linux no-new-privileges boundary validated\r\n");
        serial_write("linox: Linux static executable metadata validated\r\n");
        serial_write("linox: Linux bounded brk heap validated\r\n");
        serial_write("linox: Linux bounded anonymous mapping lifecycle validated\r\n");
        serial_write("linox: Linux two-page anonymous extent validated\r\n");
        serial_write("linox: multiple bounded Linux mmap areas validated\r\n");
        serial_write("linox: bounded Linux mmap area splitting validated\r\n");
        serial_write("linox: Linux anonymous mapping write seal validated\r\n");
        serial_write("linox: Linux atomic multi-page write seal validated\r\n");
        serial_write("linox: bounded Linux mmap protection splitting validated\r\n");
        serial_write("linox: idempotent Linux mmap protection validated\r\n");
        serial_write("linox: adjacent Linux mmap range operations validated\r\n");
        serial_write("linox: four-page fragmented Linux mmap window validated\r\n");
        serial_write("linox: bounded anonymous fixed mmap placement validated\r\n");
        serial_write("linox: bounded anonymous fixed mmap replacement validated\r\n");
        serial_write("linox: bounded PROT_NONE fixed replacement validated\r\n");
        serial_write("linox: bounded read-only anonymous mapping validated\r\n");
        serial_write("linox: page-rounded Linux mmap lengths validated\r\n");
        serial_write("linox: Linux PROT_NONE reservations validated\r\n");
        serial_write("linox: Linux PROT_NONE activation validated\r\n");
        serial_write("linox: Linux mmap frames allocated on demand\r\n");
        serial_write("linox: Linux mmap frame leases reclaimed\r\n");
        if !arch::x86_64::cpu::verify_linux_mmap_process_restore() {
            kernel_fail("linox: Linux process mmap state restoration failed\r\n");
        }
        serial_write("linox: Linux parent mmap state restored after child execution\r\n");
        serial_write("linox: Linux anonymous mapping discard validated\r\n");
        serial_write("linox: Linux anonymous mapping residency validated\r\n");
        serial_write("linox: Linux heap copy bounds validated\r\n");
        serial_write("linox: Linux stack copy bounds validated\r\n");
        serial_write("linox: Linux directional VMA copies validated\r\n");
        serial_write("linox: indexed Linux working directory validated\r\n");
        serial_write("linox: relative Linux directory changes validated\r\n");
        serial_write("linox: Linux fchdir descriptor boundary validated\r\n");
        serial_write("linox: Linux working-directory traversal rejected\r\n");
        serial_write("linox: Linux proc self executable link validated\r\n");
        serial_write("linox: Linux proc self executable link-at validated\r\n");
        serial_write("linox: Linux process umask state validated\r\n");
        serial_write("linox: Linux disconnected console input validated\r\n");
        serial_write("linox: Linux console descriptor metadata validated\r\n");
        serial_write("linox: Linux fixed console geometry validated\r\n");
        serial_write("linox: Linux fixed console termios validated\r\n");
        serial_write("linox: Linux non-seekable console validated\r\n");
        serial_write("linox: Linux console descriptor close validated\r\n");
        serial_write("linox: Linux console descriptor duplication validated\r\n");
        serial_write("linox: Linux targeted descriptor duplication validated\r\n");
        serial_write("linox: Linux console descriptor flags validated\r\n");
        serial_write("linox: Linux minimum descriptor duplication validated\r\n");
        serial_write("linox: Linux close-on-exec descriptor state validated\r\n");
        serial_write("linox: Linux bounded null device validated\r\n");
        serial_write("linox: Linux bounded null device metadata validated\r\n");
        serial_write("linox: Linux bounded null device access validated\r\n");
        serial_write("linox: Linux bounded zero device validated\r\n");
        serial_write("linox: Linux bounded console device validated\r\n");
        serial_write("linox: Linux bounded tty alias validated\r\n");
        serial_write("linox: Linux bounded device statx validated\r\n");
        serial_write("linox: Linux atomic zero-device readv validated\r\n");
        serial_write("linox: Linux bounded device writev validated\r\n");
        serial_write("linox: Linux immutable device directory validated\r\n");
        serial_write("linox: Linux immutable runtime ELF files validated\r\n");
        serial_write("linox: Linux auxiliary dependency runtime file validated\r\n");
        serial_write("linox: Linux read-only runtime file mapping validated\r\n");
        serial_write("linox: measured-root Linux executable graph validated\r\n");
        serial_write("linox: measured-root Linux executable graph executed\r\n");
        serial_write("linox: measured-root Linux file content validated\r\n");
        serial_write("linox: measured-root Linux file metadata validated\r\n");
        serial_write("linox: measured-root Linux file mutation denied\r\n");
        serial_write("linox: measured-root Linux directory enumerated\r\n");
        serial_write("linox: measured-root Linux directory cursor validated\r\n");
        serial_write("linox: measured-root Linux root enumerated\r\n");
        serial_write("linox: measured-root Linux root pagination validated\r\n");
        serial_write("linox: measured-root Linux empty directory opened\r\n");
        serial_write("linox: measured-root Linux dirfd lookup validated\r\n");
        serial_write("linox: measured-root Linux relative metadata validated\r\n");
        serial_write("linox: indexed measured-root file descriptors validated\r\n");
        serial_write("linox: generic measured-root Linux file validated\r\n");
        serial_write("linox: index-driven measured child lookup validated\r\n");
        serial_write("linox: unlisted measured-root Linux file validated\r\n");
        serial_write("linox: indexed measured-root directories validated\r\n");
        serial_write("linox: unlisted measured-root directory opened\r\n");
        serial_write("linox: nested measured-root dirfd traversal validated\r\n");
        serial_write("linox: measured-root traversal components rejected\r\n");
        serial_write("linox: expanded measured-root index capacity validated\r\n");
        serial_write("linox: Linux saved credential queries validated\r\n");
        serial_write("linox: Linux supplementary root group validated\r\n");
        serial_write("linox: Linux fixed execution personality validated\r\n");
        serial_write("linox: Linux empty capability boundary validated\r\n");
        serial_write("linox: Linux mutable resource limits enforced\r\n");
        serial_write("linox: Linux file-size resource limit enforced\r\n");
        serial_write("linox: Linux single-CPU topology queries validated\r\n");
        serial_write("linox: Linux single-thread scheduling yield validated\r\n");
        serial_write("linox: Linux fixed scheduler policy validated\r\n");
        serial_write("linox: Linux fixed process priority validated\r\n");
        serial_write("linox: Linux bounded monotonic clocks validated\r\n");
        serial_write("linox: Linux bounded clock resolution validated\r\n");
        serial_write("linox: Linux scheduler-backed nanosleep validated\r\n");
        serial_write("linox: Linux signal-interrupted nanosleep validated\r\n");
        serial_write("linox: Linux monotonic clock_nanosleep validated\r\n");
        serial_write("linox: Linux scheduler-backed poll waits validated\r\n");
        serial_write("linox: Linux scheduler-backed ppoll waits validated\r\n");
        serial_write("linox: Linux scheduler-backed epoll waits validated\r\n");
        serial_write("linox: Linux scheduler-backed epoll masked waits validated\r\n");
        serial_write("linox: Linux signal-interrupted masked waits validated\r\n");
        serial_write("linox: Linux signal-interrupted epoll waits validated\r\n");
        serial_write("linox: Linux signal-interrupted poll waits validated\r\n");
        serial_write("linox: Linux signal-interrupted epoll_wait validated\r\n");
        serial_write("linox: Linux zero-descriptor poll sleeps validated\r\n");
        serial_write("linox: Linux scheduler-backed eventfd reads validated\r\n");
        serial_write("linox: Linux signal-interrupted eventfd reads validated\r\n");
        serial_write("linox: Linux scheduler-backed eventfd writes validated\r\n");
        serial_write("linox: Linux signal-interrupted eventfd writes validated\r\n");
        serial_write("linox: Linux eventfd write snapshot isolation validated\r\n");
        serial_write("linox: Linux scheduler-backed pipe reads validated\r\n");
        serial_write("linox: Linux scheduler-backed pipe readv validated\r\n");
        serial_write("linox: Linux signal-interrupted pipe reads validated\r\n");
        serial_write("linox: Linux scheduler-backed pipe writes validated\r\n");
        serial_write("linox: Linux scheduler-backed pipe writev validated\r\n");
        serial_write("linox: Linux pipe writev snapshot isolation validated\r\n");
        serial_write("linox: Linux signal-interrupted pipe writes validated\r\n");
        serial_write("linox: Linux scheduler-backed timerfd reads validated\r\n");
        serial_write("linox: Linux signal-interrupted timerfd reads validated\r\n");
        serial_write("linox: APIC-driven Linux wait expiry validated\r\n");
        serial_write("linox: APIC-driven Linux wait preemption validated\r\n");
        serial_write("linox: Linux single-task CPU time validated\r\n");
        serial_write("linox: Linux bounded resource usage validated\r\n");
        serial_write("linox: Linux disabled interval timers validated\r\n");
        if !arch::x86_64::cpu::publish_linux_abi_test_results() {
            kernel_fail("\r\nlinox: Linux ABI test results published twice\r\n");
        }
        if !ipc::verify_channel_invariants() {
            kernel_fail("\r\nlinox: bounded IPC invariant failed\r\n");
        }
        if !packet::verify_invariants() || !packet::install() {
            kernel_fail("\r\nlinox: bounded packet handoff invariant failed\r\n");
        }
        serial_write("linox: bounded packet handoff invariants verified\r\n");
        serial_write("linox: generation-scoped IPC diagnostics verified\r\n");
        serial_write("linox: monotonic sequence exhaustion contained\r\n");
        let (
            Some(host_handle),
            Some(console_handle),
            Some(ipc_handle),
            Some(root_handle),
            Some(service_ipc_handle),
        ) = (
            domain::control_plane_boot_handle(0),
            domain::control_plane_boot_handle(1),
            domain::control_plane_boot_handle(2),
            domain::control_plane_boot_handle(4),
            domain::service_boot_handle(),
        )
        else {
            kernel_fail("\r\nlinox: control-plane bootstrap handles unavailable\r\n");
        };
        let ipc_rights = capability::Rights::READ.union(capability::Rights::WRITE);
        if domain::control_plane_id() != Some(control_plane)
            || !domain::control_owns_service(control_plane, service_domain)
            || !domain::handle_permits(service_domain, service_ipc_handle, 3, ipc_rights)
            || domain::handle_permits(
                control_plane,
                service_ipc_handle,
                3,
                capability::Rights::READ,
            )
            || domain::handle_permits(service_domain, ipc_handle, 3, capability::Rights::READ)
            || !domain::handle_permits(
                control_plane,
                root_handle,
                control_abi::ROOT_OBJECT,
                capability::Rights::READ,
            )
            || domain::handle_permits(
                control_plane,
                root_handle,
                control_abi::ROOT_OBJECT,
                capability::Rights::WRITE,
            )
        {
            kernel_fail("\r\nlinox: cross-domain capability isolation failed\r\n");
        }
        if !address_space::verify_ring3_control_plane(
            control_plane_image.code,
            control_plane_image.entries,
            [control_plane, service_domain],
            [
                [host_handle, console_handle, ipc_handle, root_handle],
                [0, 0, service_ipc_handle, 0],
            ],
            &local_apic,
            &apic_timer,
        ) {
            kernel_fail("\r\nlinox: ring-3 control-plane entry failed\r\n");
        }
        if !initramfs::published_root_is_live() {
            kernel_fail("\r\nlinox: published root ownership was lost\r\n");
        }
        serial_write("\r\nlinox: read-only root capability enforced");
        serial_write("\r\nlinox: ring-3 root metadata lookup completed");
        serial_write("\r\nlinox: ring-3 root file read completed");
        serial_write("\r\nlinox: ring-3 root directory enumeration completed");
        serial_write("\r\nlinox: non-directory enumeration denied");
        serial_write("\r\nlinox: invalid root userspace requests denied");
        serial_write("\r\nlinox: published root remains kernel-owned");
        let Some(expected_fault_instruction) =
            address_space::expected_service_fault_instruction(control_plane_image.entries[1])
        else {
            kernel_fail("\r\nlinox: service fault instruction overflowed\r\n");
        };
        if !domain::domain_is_retired(service_domain)
            || !domain::service_fault_was_delivered(service_domain)
            || domain::last_fault_event_audit() != Some((1, service_domain, 1))
            || domain::last_fault_service_identity() != Some(service_identity)
            || domain::primary_service_identity() != Some(service_identity)
            || !domain::delivered_fault_matches(
                service_domain,
                domain::FaultMetadata {
                    vector: 14,
                    error: 6,
                    address: 0,
                    instruction: expected_fault_instruction,
                },
            )
            || !arch::x86_64::paging::static_page_tables_are_read_only()
            || !arch::x86_64::paging::mmio_mapping_is_valid(virtio_mmio)
            || !arch::x86_64::pci::bus_master_is_disabled(virtio_block)
            || !arch::x86_64::pci::device_is_reset(virtio_block, virtio_mmio)
            || !arch::x86_64::paging::identity_map_obeys_wx(boot_info, &image)
            || !arch::x86_64::paging::identity_range_is_read_only_data(
                boot_info.manifest as usize,
                boot_info.manifest_size,
            )
            || !arch::x86_64::paging::identity_range_is_read_only_data(
                boot_info.control_plane_bundle as usize,
                boot_info.control_plane_bundle_size,
            )
            || !arch::x86_64::paging::identity_range_is_read_only_data(
                boot_info.controller_runtime as usize,
                boot_info.controller_runtime_size,
            )
            || !arch::x86_64::paging::identity_range_is_read_only_data(
                boot_info.root_image as usize,
                boot_info.root_image_size,
            )
            || !arch::x86_64::cpu::execute_disable_enabled()
            || !arch::x86_64::cpu::supervisor_execution_prevention_enabled()
            || !arch::x86_64::cpu::supervisor_access_prevention_enabled()
            || !arch::x86_64::cpu::user_interrupt_surface_is_minimal()
            || !arch::x86_64::cpu::user_mode_instruction_prevention_enabled()
            || !arch::x86_64::cpu::service_restart_stack_was_scrubbed()
            || !arch::x86_64::cpu::service_address_space_frames_were_transferred()
            || !arch::x86_64::paging::verify_user_context_layout_invariants()
            || !domain::call_budget_proof_complete()
            || !domain::thread_budget_proof_complete()
            || !domain::operation_accounting_proof_complete()
            || !domain::service_frame_quarantine_is_clear()
            || domain::handle_permits(
                service_domain,
                service_ipc_handle,
                3,
                capability::Rights::READ,
            )
        {
            kernel_fail("\r\nlinox: faulted service authority remained live\r\n");
        }
        let Some(replacement_domain) = domain::last_retired_service_domain() else {
            kernel_fail("\r\nlinox: replacement service retirement unavailable\r\n");
        };
        if replacement_domain == service_domain
            || domain::service_boot_handle().is_some()
            || !domain::domain_is_retired(replacement_domain)
            || !domain::service_ready_was_delivered(replacement_domain)
            || !domain::service_exit_was_delivered(replacement_domain)
            || !domain::service_restart_budget_proof_complete()
        {
            kernel_fail("\r\nlinox: replacement service generation invariant failed\r\n");
        }
        if ipc::last_message_audit() != Some(((replacement_domain, 4), (control_plane, 4))) {
            kernel_fail("\r\nlinox: IPC message provenance invariant failed\r\n");
        }
        if ipc::receive(control_plane) != ipc::Receive::PeerClosed(service_domain)
            || ipc::receive(control_plane) != ipc::Receive::PeerClosed(replacement_domain)
            || ipc::receive(control_plane) != ipc::Receive::Empty
            || ipc::last_closure_audit() != Some((replacement_domain, 2))
        {
            kernel_fail("\r\nlinox: sticky IPC peer closure invariant failed\r\n");
        }
        if !address_space::verify_ring3_auxiliary_exit() {
            kernel_fail("\r\nlinox: ring-3 auxiliary exit invariant failed\r\n");
        }
        serial_write("\r\nlinox: auxiliary exit status sequenced and retired");
        serial_write("\r\nlinox: userspace auxiliary creation authority enforced");
        serial_write("\r\nlinox: userspace auxiliary stop sequenced and retired");
        serial_write("\r\nlinox: failed auxiliary load rollback enforced");
        serial_write("\r\nlinox: queued auxiliary cancellation and teardown enforced");
        serial_write("\r\nlinox: ready auxiliary cancellation and teardown enforced");
        serial_write("\r\nlinox: yielded auxiliary cancellation and teardown enforced");
        serial_write("\r\nlinox: userspace auxiliary load and admission enforced");
        serial_write("\r\nlinox: private auxiliary payload initialization enforced");
        serial_write("\r\nlinox: auxiliary initialization state observable");
        serial_write("\r\nlinox: uninitialized auxiliary admission denied");
        serial_write("\r\nlinox: explicit auxiliary start authority enforced");
        serial_write("\r\nlinox: auxiliary runtime state query enforced");
        serial_write("\r\nlinox: userspace auxiliary lifecycle observation enforced");
        serial_write("\r\nlinox: userspace auxiliary lifecycle descriptor enforced");
        serial_write("\r\nlinox: userspace auxiliary service identity enforced");
        serial_write("\r\nlinox: auxiliary management authority denied");
        network::reset_configuration();
        if !address_space::verify_ring3_network_service() {
            kernel_fail("\r\nlinox: ring-3 network service invariant failed\r\n");
        }
        serial_write("\r\nlinox: isolated network device probe completed");
        serial_write("\r\nlinox: network device command validation enforced");
        serial_write("\r\nlinox: network link state configured");
        serial_write("\r\nlinox: network IPv4 configuration retained");
        serial_write("\r\nlinox: network default gateway validated");
        serial_write("\r\nlinox: network configuration generation tracked");
        serial_write("\r\nlinox: network gateway invalidated on address change");
        serial_write("\r\nlinox: bounded static network route retained");
        serial_write("\r\nlinox: coherent network state snapshot copied");
        serial_write("\r\nlinox: network device capability revoked on exit");
        if !address_space::verify_ring3_network_observer() {
            kernel_fail("\r\nlinox: ring-3 network observer invariant failed\r\n");
        }
        serial_write("\r\nlinox: read-only network observer isolated");
        serial_write("\r\nlinox: network mutation denied to observer");
        serial_write("\r\nlinox: observer capability revoked on exit");
        if !address_space::verify_ring3_network_configurator() {
            kernel_fail("\r\nlinox: ring-3 network configurator invariant failed\r\n");
        }
        serial_write("\r\nlinox: write-only network configurator isolated");
        serial_write("\r\nlinox: network observation denied to configurator");
        serial_write("\r\nlinox: denied network copy-out left memory unchanged");
        serial_write("\r\nlinox: stale network configuration apply rejected");
        serial_write("\r\nlinox: atomic network configuration apply completed");
        serial_write("\r\nlinox: configurator capability revoked on exit");
        if !address_space::verify_ring3_network_fault_containment() {
            kernel_fail("\r\nlinox: network service fault containment invariant failed\r\n");
        }
        serial_write("\r\nlinox: faulted network service contained");
        serial_write("\r\nlinox: faulted network authority revoked");
        serial_write("\r\nlinox: network state survived service fault");
        if !address_space::verify_ring3_network_recovery() {
            kernel_fail("\r\nlinox: replacement network service invariant failed\r\n");
        }
        serial_write("\r\nlinox: replacement network service observed retained state");
        serial_write("\r\nlinox: replacement network capability lifecycle isolated");
        if !address_space::verify_ring3_volume_service() {
            kernel_fail("\r\nlinox: ring-3 persistent volume service invariant failed\r\n");
        }
        serial_write("\r\nlinox: write-only volume service committed generation");
        serial_write("\r\nlinox: faulted volume service authority revoked");
        serial_write("\r\nlinox: persistent volume survived service fault");
        serial_write("\r\nlinox: read-only replacement recovered volume");
        serial_write("\r\nlinox: volume mutation denied to replacement");
        if !address_space::verify_ring3_auxiliary_fault() {
            kernel_fail("\r\nlinox: ring-3 auxiliary fault invariant failed\r\n");
        }
        serial_write("\r\nlinox: stop-only auxiliary fault executed and contained");
        if !unsafe { arch::x86_64::timer::verify_device_wait_timeout_interrupt() } {
            kernel_fail("\r\nlinox: device-wait timeout interrupt invariant failed\r\n");
        }
        serial_write("\r\nlinox: APIC device-wait timeout delivered");
        let Some(virtio_status_physical) = virtio_block.status_register_physical() else {
            kernel_fail("\r\nlinox: virtio status register unavailable\r\n");
        };
        let Some(native_volume_device) = address_space::NativeVolumeDevice::new(
            virtio_status_physical,
            virtio_block,
            virtio_mmio,
            virtio_msix_mmio,
            virtio_iommu_profile,
        ) else {
            kernel_fail("\r\nlinox: native volume device profile invalid\r\n");
        };
        if !address_space::verify_ring3_read_only_device_grant(virtio_status_physical, 0) {
            kernel_fail("\r\nlinox: ring-3 block-device grant invariant failed\r\n");
        }
        if !arch::x86_64::pci::bus_master_is_disabled(virtio_block)
            || !arch::x86_64::pci::device_is_reset(virtio_block, virtio_mmio)
        {
            kernel_fail("\r\nlinox: block-device observer changed device state\r\n");
        }
        serial_write("\r\nlinox: read-only virtio MMIO grant exercised in ring 3");
        serial_write("\r\nlinox: denied virtio MMIO write contained and revoked");
        serial_write("\r\nlinox: observed virtio device remained reset and DMA-disabled");
        let native_volume_summary = 'native_volume_validation: {
            let mut native_volume_run = address_space::verify_native_volume_service(
                &volume_image,
                native_volume_device,
                &local_apic,
                None,
            );
            let mut native_volume_quiesced = arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            if native_volume_run.is_none() && native_volume_quiesced {
                serial_write("\r\nlinox: initial native volume driver fault contained; retrying");
                native_volume_run = address_space::verify_native_volume_service(
                    &volume_image,
                    native_volume_device,
                    &local_apic,
                    None,
                );
                native_volume_quiesced = arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
                if native_volume_run.is_some() && native_volume_quiesced {
                    serial_write("\r\nlinox: native volume driver recovered in fresh domain");
                }
            }
            let native_volume_valid = native_volume_run.is_some();
            if !native_volume_quiesced {
                serial_write("\r\nlinox: native volume valid/quiesced: ");
                serial_write_u64(u64::from(native_volume_valid));
                serial_write(" ");
                serial_write_u64(u64::from(native_volume_quiesced));
                kernel_fail("\r\nlinox: compiled native volume service invariant failed\r\n");
            }
            if !native_volume_valid {
                serial_write(
                    "\r\nlinox: persistent volume unavailable; continuing with tmpfs-only storage",
                );
                serial_write("\r\nlinox: storage-dependent boot probes skipped");
                break 'native_volume_validation None;
            }
            let Some(native_volume_run) = native_volume_run else {
                kernel_fail("\r\nlinox: native volume outcome unavailable\r\n");
            };
            let native_volume_outcome = native_volume_run.outcome;
            serial_write("\r\nlinox: compiled native volume service executed in ring 3");
            serial_write("\r\nlinox: native service bootstrap ABI v0 validated in ring 3");
            serial_write(
                "\r\nlinox: native service lifecycle ABI v0 clean exit validated in ring 3",
            );
            serial_write("\r\nlinox: compiled native service negotiated control ABI v4");
            serial_write("\r\nlinox: compiled native service validated control descriptor v4");
            serial_write("\r\nlinox: native volume service owned virtio request sequence");
            match native_volume_outcome {
                address_space::NativeVolumeOutcome::Initialized => {
                    serial_write("\r\nlinox: native volume record initialized and flushed");
                    serial_write(
                        "\r\nlinox: isolated volume prepare flush commit sequence completed",
                    );
                }
                address_space::NativeVolumeOutcome::Recovered => {
                    serial_write("\r\nlinox: native volume record recovered after reboot");
                }
                address_space::NativeVolumeOutcome::Rejected => {
                    serial_write(
                        "\r\nlinox: corrupt native volume media rejected without modification",
                    );
                }
                address_space::NativeVolumeOutcome::RestartRequired => {
                    kernel_fail("\r\nlinox: normal native volume run requested restart\r\n");
                }
                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                    kernel_fail("\r\nlinox: normal native volume run rejected its ABI\r\n");
                }
                address_space::NativeVolumeOutcome::Faulted => {
                    kernel_fail("\r\nlinox: normal native volume run reported a fault\r\n");
                }
            }
            serial_write("\r\nlinox: native volume service exited cleanly and device quiesced");
            let replacement_volume_run = address_space::verify_native_volume_service(
                &volume_image,
                native_volume_device,
                &local_apic,
                Some(native_volume_run.service_identity),
            );
            let replacement_volume_quiesced = arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let replacement_volume_valid =
                replacement_volume_run.as_ref().is_some_and(|replacement| {
                    replacement.domain != native_volume_run.domain
                        && replacement.iommu_lease_is_fresh_after(&native_volume_run)
                        && replacement.service_identity == native_volume_run.service_identity
                        && replacement.outcome
                            == match native_volume_outcome {
                                address_space::NativeVolumeOutcome::Initialized
                                | address_space::NativeVolumeOutcome::Recovered => {
                                    address_space::NativeVolumeOutcome::Recovered
                                }
                                address_space::NativeVolumeOutcome::Rejected => {
                                    address_space::NativeVolumeOutcome::Rejected
                                }
                                address_space::NativeVolumeOutcome::RestartRequired => {
                                    address_space::NativeVolumeOutcome::RestartRequired
                                }
                                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                                    address_space::NativeVolumeOutcome::IncompatibleAbi
                                }
                                address_space::NativeVolumeOutcome::Faulted => {
                                    address_space::NativeVolumeOutcome::Faulted
                                }
                            }
                });
            if !replacement_volume_valid || !replacement_volume_quiesced {
                serial_write("\r\nlinox: replacement native volume valid/quiesced: ");
                serial_write_u64(u64::from(replacement_volume_valid));
                serial_write(" ");
                serial_write_u64(u64::from(replacement_volume_quiesced));
                kernel_fail("\r\nlinox: replacement native volume service invariant failed\r\n");
            }
            let Some(replacement_volume_run) = replacement_volume_run else {
                kernel_fail("\r\nlinox: replacement native volume outcome unavailable\r\n");
            };
            serial_write("\r\nlinox: replacement native volume domain generation started");
            serial_write("\r\nlinox: native volume service identity survived replacement");
            serial_write(match native_volume_outcome {
                address_space::NativeVolumeOutcome::Initialized
                | address_space::NativeVolumeOutcome::Recovered => {
                    "\r\nlinox: replacement native volume service recovered exact record"
                }
                address_space::NativeVolumeOutcome::Rejected => {
                    "\r\nlinox: replacement native volume service repeated fail-closed rejection"
                }
                address_space::NativeVolumeOutcome::RestartRequired => {
                    "\r\nlinox: replacement native volume service requested restart unexpectedly"
                }
                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                    "\r\nlinox: replacement native volume service rejected its ABI unexpectedly"
                }
                address_space::NativeVolumeOutcome::Faulted => {
                    "\r\nlinox: replacement native volume service faulted unexpectedly"
                }
            });
            serial_write("\r\nlinox: replacement native volume resources retired cleanly");
            let incompatible_volume_run =
                address_space::verify_native_volume_service_incompatible_abi(
                    &volume_image,
                    native_volume_device,
                    &local_apic,
                    native_volume_run.service_identity,
                );
            let incompatible_volume_quiesced =
                arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let incompatible_volume_valid =
                incompatible_volume_run
                    .as_ref()
                    .is_some_and(|incompatible| {
                        incompatible.domain != native_volume_run.domain
                            && incompatible.domain != replacement_volume_run.domain
                            && incompatible.iommu_lease_is_fresh_after(&replacement_volume_run)
                            && incompatible.service_identity == native_volume_run.service_identity
                            && incompatible.outcome
                                == address_space::NativeVolumeOutcome::IncompatibleAbi
                    });
            if !incompatible_volume_valid || !incompatible_volume_quiesced {
                serial_write("\r\nlinox: incompatible native volume valid/quiesced: ");
                serial_write_u64(u64::from(incompatible_volume_valid));
                serial_write(" ");
                serial_write_u64(u64::from(incompatible_volume_quiesced));
                kernel_fail("\r\nlinox: incompatible native volume ABI invariant failed\r\n");
            }
            let Some(incompatible_volume_run) = incompatible_volume_run else {
                kernel_fail("\r\nlinox: incompatible native volume outcome unavailable\r\n");
            };
            serial_write(
                "\r\nlinox: incompatible native service ABI rejected before device activation",
            );
            serial_write("\r\nlinox: incompatible native service generation retired cleanly");
            let recovered_after_incompatible = address_space::verify_native_volume_service(
                &volume_image,
                native_volume_device,
                &local_apic,
                Some(native_volume_run.service_identity),
            );
            let recovered_after_incompatible_quiesced =
                arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let recovered_after_incompatible_valid = recovered_after_incompatible
                .as_ref()
                .is_some_and(|recovered| {
                    recovered.domain != native_volume_run.domain
                        && recovered.domain != replacement_volume_run.domain
                        && recovered.domain != incompatible_volume_run.domain
                        && recovered.iommu_lease_is_fresh_after(&incompatible_volume_run)
                        && recovered.service_identity == native_volume_run.service_identity
                        && recovered.outcome
                            == match native_volume_outcome {
                                address_space::NativeVolumeOutcome::Initialized
                                | address_space::NativeVolumeOutcome::Recovered => {
                                    address_space::NativeVolumeOutcome::Recovered
                                }
                                address_space::NativeVolumeOutcome::Rejected => {
                                    address_space::NativeVolumeOutcome::Rejected
                                }
                                address_space::NativeVolumeOutcome::RestartRequired => {
                                    address_space::NativeVolumeOutcome::RestartRequired
                                }
                                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                                    address_space::NativeVolumeOutcome::IncompatibleAbi
                                }
                                address_space::NativeVolumeOutcome::Faulted => {
                                    address_space::NativeVolumeOutcome::Faulted
                                }
                            }
                });
            if !recovered_after_incompatible_valid || !recovered_after_incompatible_quiesced {
                serial_write("\r\nlinox: post-ABI-rejection native volume valid/quiesced: ");
                serial_write_u64(u64::from(recovered_after_incompatible_valid));
                serial_write(" ");
                serial_write_u64(u64::from(recovered_after_incompatible_quiesced));
                kernel_fail("\r\nlinox: post-ABI-rejection recovery invariant failed\r\n");
            }
            let Some(recovered_after_incompatible) = recovered_after_incompatible else {
                kernel_fail("\r\nlinox: post-ABI-rejection outcome unavailable\r\n");
            };
            serial_write("\r\nlinox: compatible native service recovered after ABI rejection");
            let incompatible_descriptor_run =
                address_space::verify_native_volume_service_incompatible_descriptor(
                    &volume_image,
                    native_volume_device,
                    &local_apic,
                    native_volume_run.service_identity,
                );
            let incompatible_descriptor_quiesced =
                arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let incompatible_descriptor_valid =
                incompatible_descriptor_run
                    .as_ref()
                    .is_some_and(|incompatible| {
                        incompatible.domain != native_volume_run.domain
                            && incompatible.domain != replacement_volume_run.domain
                            && incompatible.domain != incompatible_volume_run.domain
                            && incompatible.domain != recovered_after_incompatible.domain
                            && incompatible
                                .iommu_lease_is_fresh_after(&recovered_after_incompatible)
                            && incompatible.service_identity == native_volume_run.service_identity
                            && incompatible.outcome
                                == address_space::NativeVolumeOutcome::IncompatibleAbi
                    });
            if !incompatible_descriptor_valid || !incompatible_descriptor_quiesced {
                serial_write("\r\nlinox: incompatible native descriptor valid/quiesced: ");
                serial_write_u64(u64::from(incompatible_descriptor_valid));
                serial_write(" ");
                serial_write_u64(u64::from(incompatible_descriptor_quiesced));
                kernel_fail("\r\nlinox: incompatible native descriptor invariant failed\r\n");
            }
            let Some(incompatible_descriptor_run) = incompatible_descriptor_run else {
                kernel_fail("\r\nlinox: incompatible native descriptor outcome unavailable\r\n");
            };
            serial_write(
                "\r\nlinox: malformed native control descriptor rejected before device activation",
            );
            serial_write("\r\nlinox: malformed descriptor service generation retired cleanly");
            let recovered_after_descriptor = address_space::verify_native_volume_service(
                &volume_image,
                native_volume_device,
                &local_apic,
                Some(native_volume_run.service_identity),
            );
            let recovered_after_descriptor_quiesced =
                arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let recovered_after_descriptor_valid =
                recovered_after_descriptor
                    .as_ref()
                    .is_some_and(|recovered| {
                        recovered.domain != native_volume_run.domain
                            && recovered.domain != replacement_volume_run.domain
                            && recovered.domain != incompatible_volume_run.domain
                            && recovered.domain != recovered_after_incompatible.domain
                            && recovered.domain != incompatible_descriptor_run.domain
                            && recovered.iommu_lease_is_fresh_after(&incompatible_descriptor_run)
                            && recovered.service_identity == native_volume_run.service_identity
                            && recovered.outcome
                                == match native_volume_outcome {
                                    address_space::NativeVolumeOutcome::Initialized
                                    | address_space::NativeVolumeOutcome::Recovered => {
                                        address_space::NativeVolumeOutcome::Recovered
                                    }
                                    address_space::NativeVolumeOutcome::Rejected => {
                                        address_space::NativeVolumeOutcome::Rejected
                                    }
                                    address_space::NativeVolumeOutcome::RestartRequired => {
                                        address_space::NativeVolumeOutcome::RestartRequired
                                    }
                                    address_space::NativeVolumeOutcome::IncompatibleAbi => {
                                        address_space::NativeVolumeOutcome::IncompatibleAbi
                                    }
                                    address_space::NativeVolumeOutcome::Faulted => {
                                        address_space::NativeVolumeOutcome::Faulted
                                    }
                                }
                    });
            if !recovered_after_descriptor_valid || !recovered_after_descriptor_quiesced {
                serial_write("\r\nlinox: post-descriptor-rejection native volume valid/quiesced: ");
                serial_write_u64(u64::from(recovered_after_descriptor_valid));
                serial_write(" ");
                serial_write_u64(u64::from(recovered_after_descriptor_quiesced));
                kernel_fail("\r\nlinox: post-descriptor-rejection recovery invariant failed\r\n");
            }
            let Some(recovered_after_descriptor) = recovered_after_descriptor else {
                kernel_fail("\r\nlinox: post-descriptor-rejection outcome unavailable\r\n");
            };
            serial_write(
                "\r\nlinox: compatible native service recovered after descriptor rejection",
            );
            let faulted_volume_run = address_space::verify_native_volume_service_fault(
                &volume_image,
                native_volume_device,
                &local_apic,
                native_volume_run.service_identity,
            );
            let faulted_volume_quiesced = arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let faulted_volume_valid = faulted_volume_run.as_ref().is_some_and(|faulted| {
                faulted.domain != native_volume_run.domain
                    && faulted.domain != replacement_volume_run.domain
                    && faulted.domain != incompatible_volume_run.domain
                    && faulted.domain != recovered_after_incompatible.domain
                    && faulted.domain != incompatible_descriptor_run.domain
                    && faulted.domain != recovered_after_descriptor.domain
                    && faulted.iommu_lease_is_fresh_after(&recovered_after_descriptor)
                    && faulted.service_identity == native_volume_run.service_identity
                    && faulted.outcome == address_space::NativeVolumeOutcome::Faulted
            });
            if !faulted_volume_valid || !faulted_volume_quiesced {
                serial_write("\r\nlinox: faulted native volume valid/quiesced: ");
                serial_write_u64(u64::from(faulted_volume_valid));
                serial_write(" ");
                serial_write_u64(u64::from(faulted_volume_quiesced));
                kernel_fail("\r\nlinox: faulted native volume service invariant failed\r\n");
            }
            let Some(faulted_volume_run) = faulted_volume_run else {
                kernel_fail("\r\nlinox: faulted native volume outcome unavailable\r\n");
            };
            serial_write("\r\nlinox: compiled native volume service fault contained");
            serial_write("\r\nlinox: faulted native device service authority revoked");
            serial_write("\r\nlinox: incomplete native DMA scrubbed after fault");
            let recovered_after_fault = address_space::verify_native_volume_service(
                &volume_image,
                native_volume_device,
                &local_apic,
                Some(native_volume_run.service_identity),
            );
            let recovered_after_fault_quiesced =
                arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let recovered_after_fault_valid =
                recovered_after_fault.as_ref().is_some_and(|recovered| {
                    recovered.domain != native_volume_run.domain
                        && recovered.domain != replacement_volume_run.domain
                        && recovered.domain != faulted_volume_run.domain
                        && recovered.iommu_lease_is_fresh_after(&faulted_volume_run)
                        && recovered.service_identity == native_volume_run.service_identity
                        && recovered.outcome
                            == match native_volume_outcome {
                                address_space::NativeVolumeOutcome::Initialized
                                | address_space::NativeVolumeOutcome::Recovered => {
                                    address_space::NativeVolumeOutcome::Recovered
                                }
                                address_space::NativeVolumeOutcome::Rejected => {
                                    address_space::NativeVolumeOutcome::Rejected
                                }
                                address_space::NativeVolumeOutcome::RestartRequired => {
                                    address_space::NativeVolumeOutcome::RestartRequired
                                }
                                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                                    address_space::NativeVolumeOutcome::IncompatibleAbi
                                }
                                address_space::NativeVolumeOutcome::Faulted => {
                                    address_space::NativeVolumeOutcome::Faulted
                                }
                            }
                });
            if !recovered_after_fault_valid || !recovered_after_fault_quiesced {
                serial_write("\r\nlinox: post-fault native volume valid/quiesced: ");
                serial_write_u64(u64::from(recovered_after_fault_valid));
                serial_write(" ");
                serial_write_u64(u64::from(recovered_after_fault_quiesced));
                kernel_fail("\r\nlinox: post-fault native volume recovery invariant failed\r\n");
            }
            let Some(recovered_after_fault) = recovered_after_fault else {
                kernel_fail("\r\nlinox: post-fault native volume outcome unavailable\r\n");
            };
            serial_write("\r\nlinox: post-fault native volume generation started");
            serial_write("\r\nlinox: native volume identity survived actual driver fault");
            serial_write(match native_volume_outcome {
                address_space::NativeVolumeOutcome::Initialized
                | address_space::NativeVolumeOutcome::Recovered => {
                    "\r\nlinox: post-fault native volume service recovered exact record"
                }
                address_space::NativeVolumeOutcome::Rejected => {
                    "\r\nlinox: post-fault native volume service preserved rejection"
                }
                address_space::NativeVolumeOutcome::RestartRequired => {
                    "\r\nlinox: post-fault native volume service requested restart unexpectedly"
                }
                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                    "\r\nlinox: post-fault native volume service rejected its ABI unexpectedly"
                }
                address_space::NativeVolumeOutcome::Faulted => {
                    "\r\nlinox: post-fault native volume service faulted unexpectedly"
                }
            });
            serial_write("\r\nlinox: post-fault native volume resources retired cleanly");
            let cancelled_volume_run = address_space::verify_native_volume_service_cancellation(
                &volume_image,
                native_volume_device,
                &local_apic,
                native_volume_run.service_identity,
            );
            let cancelled_volume_quiesced = arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let cancelled_volume_valid = cancelled_volume_run.as_ref().is_some_and(|cancelled| {
                cancelled.domain != native_volume_run.domain
                    && cancelled.domain != replacement_volume_run.domain
                    && cancelled.domain != faulted_volume_run.domain
                    && cancelled.domain != recovered_after_fault.domain
                    && cancelled.iommu_lease_is_fresh_after(&recovered_after_fault)
                    && cancelled.service_identity == native_volume_run.service_identity
                    && cancelled.outcome == address_space::NativeVolumeOutcome::RestartRequired
            });
            if !cancelled_volume_valid || !cancelled_volume_quiesced {
                serial_write("\r\nlinox: cancelled native volume valid/quiesced: ");
                serial_write_u64(u64::from(cancelled_volume_valid));
                serial_write(" ");
                serial_write_u64(u64::from(cancelled_volume_quiesced));
                kernel_fail("\r\nlinox: native volume cancellation invariant failed\r\n");
            }
            let Some(cancelled_volume_run) = cancelled_volume_run else {
                kernel_fail("\r\nlinox: cancelled native volume outcome unavailable\r\n");
            };
            serial_write("\r\nlinox: notified native volume timeout cancelled safely");
            serial_write("\r\nlinox: cancelled native volume request generation retired");
            let recovered_after_cancellation = address_space::verify_native_volume_service(
                &volume_image,
                native_volume_device,
                &local_apic,
                Some(native_volume_run.service_identity),
            );
            let recovered_after_cancellation_quiesced =
                arch::x86_64::pci::quiesce(virtio_block, virtio_mmio);
            let recovered_after_cancellation_valid = recovered_after_cancellation
                .as_ref()
                .is_some_and(|recovered| {
                    recovered.domain != native_volume_run.domain
                        && recovered.domain != replacement_volume_run.domain
                        && recovered.domain != faulted_volume_run.domain
                        && recovered.domain != recovered_after_fault.domain
                        && recovered.domain != cancelled_volume_run.domain
                        && recovered.iommu_lease_is_fresh_after(&cancelled_volume_run)
                        && recovered.service_identity == native_volume_run.service_identity
                        && recovered.outcome
                            == match native_volume_outcome {
                                address_space::NativeVolumeOutcome::Initialized
                                | address_space::NativeVolumeOutcome::Recovered => {
                                    address_space::NativeVolumeOutcome::Recovered
                                }
                                address_space::NativeVolumeOutcome::Rejected => {
                                    address_space::NativeVolumeOutcome::Rejected
                                }
                                address_space::NativeVolumeOutcome::RestartRequired => {
                                    address_space::NativeVolumeOutcome::RestartRequired
                                }
                                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                                    address_space::NativeVolumeOutcome::IncompatibleAbi
                                }
                                address_space::NativeVolumeOutcome::Faulted => {
                                    address_space::NativeVolumeOutcome::Faulted
                                }
                            }
                });
            if !recovered_after_cancellation_valid || !recovered_after_cancellation_quiesced {
                serial_write("\r\nlinox: post-cancellation native volume valid/quiesced: ");
                serial_write_u64(u64::from(recovered_after_cancellation_valid));
                serial_write(" ");
                serial_write_u64(u64::from(recovered_after_cancellation_quiesced));
                kernel_fail("\r\nlinox: post-cancellation native volume invariant failed\r\n");
            }
            Some(native_volume_outcome)
        };
        if !address_space::verify_native_network_service(&network_image) {
            kernel_fail("\r\nlinox: compiled native network service invariant failed\r\n");
        }
        serial_write("\r\nlinox: compiled native network service executed in ring 3");
        serial_write("\r\nlinox: native network service negotiated control ABI v4");
        serial_write("\r\nlinox: native network service validated control descriptor v4");
        serial_write("\r\nlinox: native network service started without boot capabilities");
        serial_write("\r\nlinox: native network service exited through lifecycle ABI v0");
        serial_write("\r\nlinox: native network service address space retired cleanly");
        if !address_space::verify_native_network_bootstrap(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
        ) {
            kernel_fail("\r\nlinox: native network bootstrap invariant failed\r\n");
        }
        serial_write("\r\nlinox: native network bootstrap ABI v0 validated in ring 3");
        serial_write("\r\nlinox: native network read capability exercised in ring 3");
        serial_write("\r\nlinox: native network DMA lease remained device-inaccessible");
        serial_write("\r\nlinox: native network MMIO remained PCI-disabled");
        serial_write("\r\nlinox: native network bootstrap resources retired cleanly");
        if !address_space::verify_native_network_bootstrap_rejection(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
        ) {
            kernel_fail("\r\nlinox: malformed native network bootstrap invariant failed\r\n");
        }
        serial_write("\r\nlinox: malformed native network bootstrap rejected in ring 3");
        serial_write("\r\nlinox: malformed network generation fault contained");
        serial_write("\r\nlinox: malformed network capability revoked");
        serial_write("\r\nlinox: malformed network resources retired before device activation");
        if !address_space::verify_native_network_dma_confinement(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
        ) {
            kernel_fail("\r\nlinox: native network DMA confinement invariant failed\r\n");
        }
        serial_write("\r\nlinox: native network generation received exact VT-d domain");
        serial_write("\r\nlinox: native network VT-d activated before PCI authority");
        serial_write("\r\nlinox: native network bus mastering remained disabled");
        serial_write("\r\nlinox: native network VT-d retired before DMA release");
        serial_write("\r\nlinox: native network translation tables scrubbed cleanly");
        if !address_space::verify_native_network_dma_fault_teardown(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
        ) {
            kernel_fail("\r\nlinox: faulted native network VT-d teardown failed\r\n");
        }
        serial_write("\r\nlinox: faulted native network generation retired active VT-d");
        serial_write("\r\nlinox: faulted network translation disabled before DMA scrub");
        serial_write("\r\nlinox: faulted network VT-d tables released cleanly");
        if !address_space::verify_native_network_empty_queue_activation(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
        ) {
            kernel_fail("\r\nlinox: native network empty-queue delegation failed\r\n");
        }
        serial_write("\r\nlinox: native network service configured empty RX/TX queues");
        serial_write("\r\nlinox: native network queue layout validated by kernel");
        serial_write("\r\nlinox: native network bus mastering authorized by capability");
        serial_write("\r\nlinox: native network bus mastering enabled last");
        serial_write("\r\nlinox: native network device quiesced before VT-d teardown");
        serial_write("\r\nlinox: native network empty-queue generation retired cleanly");
        if !address_space::verify_native_network_active_fault_teardown(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
        ) {
            kernel_fail("\r\nlinox: active native network fault teardown failed\r\n");
        }
        serial_write("\r\nlinox: active native network driver fault injected at call boundary");
        serial_write("\r\nlinox: faulted native network queues were live before quiescence");
        serial_write("\r\nlinox: faulted native network bus mastering revoked");
        serial_write("\r\nlinox: faulted native network device reset before VT-d teardown");
        serial_write("\r\nlinox: active network fault retired translation before DMA");
        serial_write("\r\nlinox: active network fault contained without kernel panic");
        if !address_space::verify_native_network_transmit_probe(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network service transmit failed\r\n");
        }
        serial_write("\r\nlinox: native network service published bounded TX descriptor");
        serial_write("\r\nlinox: native network service notified transmit queue");
        serial_write("\r\nlinox: native network service blocked for TX interrupt");
        serial_write("\r\nlinox: native network TX replay rejected");
        serial_write("\r\nlinox: kernel validated native network TX descriptor and payload");
        serial_write("\r\nlinox: native network TX payload guards preserved");
        serial_write("\r\nlinox: native network service transmitted Ethernet probe");
        serial_write("\r\nlinox: native network TX interrupt route retired cleanly");
        if !address_space::verify_native_network_transmit_timeout(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network notified timeout was not contained\r\n");
        }
        serial_write("\r\nlinox: notified native network timeout cancelled safely");
        serial_write("\r\nlinox: ambiguous native network generation retired");
        if !address_space::verify_native_network_transmit_probe(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network timeout recovery failed\r\n");
        }
        serial_write("\r\nlinox: fresh native network generation recovered after timeout");
        serial_write("\r\nlinox: recovered network generation completed TX interrupt");
        if !address_space::verify_native_network_receive_arp(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network service ARP receive failed\r\n");
        }
        serial_write("\r\nlinox: native network service published bounded RX descriptor");
        serial_write("\r\nlinox: native network service transmitted ARP request");
        serial_write("\r\nlinox: native network service blocked for RX interrupt");
        serial_write("\r\nlinox: native network RX replay rejected");
        serial_write("\r\nlinox: native network service validated gateway ARP reply");
        serial_write("\r\nlinox: kernel validated native network RX descriptor and ARP reply");
        serial_write("\r\nlinox: native network RX payload guards preserved");
        serial_write("\r\nlinox: native network TX and RX interrupt routes retired cleanly");
        if !address_space::verify_native_network_receive_timeout(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network RX timeout was not contained\r\n");
        }
        serial_write("\r\nlinox: native network RX timeout followed completed TX");
        serial_write("\r\nlinox: ambiguous native network RX generation retired");
        if !address_space::verify_native_network_receive_arp(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network RX timeout recovery failed\r\n");
        }
        serial_write("\r\nlinox: fresh native network generation recovered after RX timeout");
        serial_write("\r\nlinox: recovered network generation validated gateway ARP reply");
        if !address_space::verify_native_network_malformed_receive(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: malformed native network receive was not contained\r\n");
        }
        serial_write("\r\nlinox: malformed network ARP reply injected after RX completion");
        serial_write("\r\nlinox: native network service rejected malformed ARP reply");
        serial_write("\r\nlinox: malformed network receive generation retired safely");
        if !address_space::verify_native_network_receive_arp(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: malformed native network receive recovery failed\r\n");
        }
        serial_write("\r\nlinox: fresh native network generation recovered after malformed reply");
        serial_write("\r\nlinox: post-malformation network generation validated ARP reply");
        if !address_space::verify_native_network_receive_reuse(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network receive replenishment failed\r\n");
        }
        serial_write("\r\nlinox: native network service replenished RX descriptor");
        serial_write("\r\nlinox: native network service completed second ARP exchange");
        serial_write("\r\nlinox: native network request generations one through four completed");
        serial_write("\r\nlinox: kernel validated both native network ARP exchanges");
        if !address_space::verify_native_network_ping_gateway(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: native network ICMP gateway probe failed\r\n");
        }
        serial_write("\r\nlinox: native network ICMP gateway request transmitted");
        serial_write("\r\nlinox: native network ICMP gateway reply validated");
        if !address_space::verify_native_network_packet_handoff(
            &network_image,
            &protocol_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: bounded native packet handoff failed\r\n");
        }
        serial_write("\r\nlinox: native network service copied validated frame out of DMA");
        serial_write("\r\nlinox: packet producer retained no read authority");
        serial_write("\r\nlinox: compiled Rust protocol service consumed Ethernet frame");
        serial_write("\r\nlinox: protocol service validated gateway ARP reply");
        serial_write("\r\nlinox: protocol service rejected malformed ARP metadata");
        serial_write("\r\nlinox: protocol consumer retained no device or write authority");
        serial_write("\r\nlinox: packet survived producer and device retirement");
        serial_write("\r\nlinox: protocol service address space retired cleanly");
        if !address_space::verify_native_network_packet_fault_handoff(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: faulted native packet handoff failed\r\n");
        }
        serial_write("\r\nlinox: network driver faulted after packet publication");
        serial_write("\r\nlinox: faulted packet producer authority revoked");
        serial_write("\r\nlinox: fault teardown preserved copied packet sequence two");
        serial_write("\r\nlinox: fresh ring-3 consumer received fault-surviving packet");
        if !address_space::verify_native_network_packet_batch(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            virtio_network_common_mmio,
            virtio_network_msix_mmio,
            &local_apic,
        ) {
            kernel_fail("\r\nlinox: bounded native packet FIFO failed\r\n");
        }
        serial_write("\r\nlinox: network producer queued two packets before retirement");
        serial_write("\r\nlinox: packet FIFO preserved sequence three before four");
        serial_write("\r\nlinox: separate ring-3 consumers drained packet FIFO in order");
        serial_write("\r\nlinox: bounded packet FIFO backpressure invariant verified");
        if !address_space::verify_packet_wait_wakeup(false) {
            kernel_fail("\r\nlinox: blocking packet wait failed\r\n");
        }
        serial_write("\r\nlinox: empty packet consumer blocked on exact sequence");
        serial_write("\r\nlinox: write-only packet producer wait denied");
        serial_write("\r\nlinox: packet publication woke exactly one read-only consumer");
        serial_write("\r\nlinox: stale packet waits rejected without blocking");
        serial_write("\r\nlinox: woken packet consumer received exact frame");
        if !address_space::verify_packet_wait_cancellation() {
            kernel_fail("\r\nlinox: blocked packet wait cancellation failed\r\n");
        }
        serial_write("\r\nlinox: blocked packet consumer stopped by control authority");
        serial_write("\r\nlinox: cancelled packet wait key released");
        serial_write("\r\nlinox: cancelled packet consumer frames and capability retired");
        if !address_space::verify_packet_wait_wakeup(false) {
            kernel_fail("\r\nlinox: replacement packet wait failed\r\n");
        }
        serial_write("\r\nlinox: replacement packet consumer claimed cancelled sequence");
        serial_write("\r\nlinox: replacement packet consumer received exact frame");
        if !address_space::verify_packet_wait_timeout() {
            kernel_fail("\r\nlinox: bounded packet wait timeout failed\r\n");
        }
        serial_write("\r\nlinox: bounded packet wait expired through APIC deadline");
        serial_write("\r\nlinox: packet timeout preempted non-cooperative peer");
        serial_write("\r\nlinox: timed-out packet wait key released");
        if !address_space::verify_packet_wait_wakeup(true) {
            kernel_fail("\r\nlinox: post-timeout packet wait replacement failed\r\n");
        }
        serial_write("\r\nlinox: replacement packet consumer claimed timed-out sequence");
        serial_write("\r\nlinox: replacement packet consumer received post-timeout frame");
        serial_write("\r\nlinox: packet publication cancelled pending wait deadline");
        if !address_space::verify_packet_backpressure_wakeup() {
            kernel_fail("\r\nlinox: packet backpressure wakeup failed\r\n");
        }
        serial_write("\r\nlinox: full packet FIFO blocked write-only producer");
        serial_write("\r\nlinox: packet consumption woke exactly one blocked producer");
        serial_write("\r\nlinox: woken packet producer retried exact next sequence");
        serial_write("\r\nlinox: packet FIFO ordering survived backpressure wakeup");
        if !address_space::verify_native_protocol_wait_loop(&protocol_image) {
            kernel_fail("\r\nlinox: resident native protocol wait loop failed\r\n");
        }
        serial_write("\r\nlinox: compiled protocol service waited on an empty packet FIFO");
        serial_write("\r\nlinox: resident protocol domain consumed two ordered packets");
        serial_write("\r\nlinox: protocol domain remained live between packet arrivals");
        serial_write("\r\nlinox: protocol service learned bounded ARP neighbor");
        serial_write("\r\nlinox: protocol service refreshed stable ARP neighbor");
        serial_write("\r\nlinox: conflicting ARP neighbor mapping rejected without mutation");
        serial_write("\r\nlinox: resident protocol wait keys and frames retired cleanly");
        if !address_space::verify_supervised_native_protocol_loop(&protocol_image) {
            kernel_fail("\r\nlinox: supervised native protocol loop failed\r\n");
        }
        serial_write("\r\nlinox: supervised protocol loop consumed multiple packets");
        serial_write("\r\nlinox: control plane stopped blocked protocol service");
        serial_write("\r\nlinox: supervised protocol wait and frames retired cleanly");
        if !address_space::verify_native_protocol_ipv4_dispatch(&protocol_image) {
            kernel_fail("\r\nlinox: native protocol IPv4 dispatch failed\r\n");
        }
        serial_write("\r\nlinox: protocol service dispatched ARP then IPv4");
        serial_write("\r\nlinox: protocol service validated IPv4 header checksum");
        serial_write("\r\nlinox: malformed IPv4 header rejected in ring 3");
        serial_write("\r\nlinox: IPv4 protocol generation retired cleanly");
        if !address_space::verify_native_protocol_icmp_echo(&protocol_image) {
            kernel_fail("\r\nlinox: native protocol ICMP echo validation failed\r\n");
        }
        serial_write("\r\nlinox: protocol service validated ICMP echo request");
        serial_write("\r\nlinox: ICMP type code identifier and sequence accepted");
        serial_write("\r\nlinox: malformed ICMP checksum rejected in ring 3");
        serial_write("\r\nlinox: ICMP protocol generation retired cleanly");
        if !address_space::verify_native_protocol_icmp_reply(&protocol_image) {
            kernel_fail("\r\nlinox: native protocol ICMP echo reply failed\r\n");
        }
        serial_write("\r\nlinox: protocol service constructed exact ICMP echo reply");
        serial_write("\r\nlinox: protocol egress authority remained write only");
        serial_write("\r\nlinox: isolated egress consumer retained read-only authority");
        serial_write("\r\nlinox: egress packet survived protocol service retirement");
        serial_write("\r\nlinox: isolated egress consumer received exact echo reply");
        serial_write("\r\nlinox: protocol egress sequence consumed exactly once");
        if !address_space::verify_native_network_egress_transmit(
            &network_image,
            &protocol_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: protocol egress virtio transmit failed\r\n");
        }
        serial_write("\r\nlinox: protocol service published second ICMP echo reply");
        serial_write("\r\nlinox: network service consumed read-only egress sequence");
        serial_write("\r\nlinox: network service copied echo reply into confined DMA");
        serial_write("\r\nlinox: network service transmitted protocol egress through virtio-net");
        serial_write("\r\nlinox: kernel validated egress descriptor and exact echo reply");
        serial_write("\r\nlinox: protocol-to-device egress retired cleanly");
        if !address_space::verify_native_network_reliable_egress(
            &network_image,
            &protocol_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: reliable protocol egress transmit failed\r\n");
        }
        serial_write("\r\nlinox: network service claimed egress without consuming it");
        serial_write("\r\nlinox: premature egress acknowledgement rejected");
        serial_write("\r\nlinox: faulted network generation released egress claim");
        serial_write("\r\nlinox: claimed egress packet survived network driver fault");
        serial_write("\r\nlinox: replacement network generation transmitted preserved reply");
        serial_write("\r\nlinox: egress acknowledged only after TX completion");
        serial_write("\r\nlinox: reliable protocol egress retired cleanly");
        if !address_space::verify_native_network_egress_wait(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: blocking protocol egress transmit failed\r\n");
        }
        serial_write("\r\nlinox: network service blocked before egress publication");
        serial_write("\r\nlinox: egress publication woke exact object and sequence");
        serial_write("\r\nlinox: woken network service claimed exact egress sequence");
        serial_write("\r\nlinox: blocking egress transmitted and acknowledged through virtio-net");
        serial_write("\r\nlinox: blocking egress producer and network domains retired cleanly");
        if !address_space::verify_egress_backpressure_wakeup() {
            kernel_fail("\r\nlinox: egress backpressure wakeup failed\r\n");
        }
        serial_write("\r\nlinox: full egress FIFO blocked write-only producer");
        serial_write("\r\nlinox: egress delivery woke only object-9 space waiter");
        serial_write("\r\nlinox: woken egress producer retried exact next sequence");
        serial_write("\r\nlinox: egress FIFO ordering survived backpressure wakeup");
        if !address_space::verify_native_network_ack_backpressure(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: reliable egress acknowledgement backpressure failed\r\n");
        }
        serial_write("\r\nlinox: full egress FIFO remained full while head was claimed");
        serial_write("\r\nlinox: completed egress acknowledgement woke blocked producer");
        serial_write("\r\nlinox: post-ack producer published exact fifth sequence");
        serial_write("\r\nlinox: hardware-coupled egress backpressure retired cleanly");
        if !address_space::verify_native_network_egress_reuse(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: resident reliable egress reuse failed\r\n");
        }
        serial_write("\r\nlinox: resident network service transmitted two egress replies");
        serial_write("\r\nlinox: resident network service reused TX descriptor and DMA lease");
        serial_write("\r\nlinox: resident network interrupt generations advanced in order");
        serial_write("\r\nlinox: resident reliable egress retired cleanly");
        if !address_space::verify_native_network_egress_batch(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: resident reliable egress batch failed\r\n");
        }
        serial_write("\r\nlinox: resident network service drained full egress FIFO");
        serial_write("\r\nlinox: validated device progress renewed service call epochs");
        serial_write("\r\nlinox: four network interrupt generations advanced in order");
        serial_write("\r\nlinox: resident reliable egress batch retired cleanly");
        if !address_space::verify_native_network_egress_resident_stop(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: resident reliable egress stop failed\r\n");
        }
        serial_write("\r\nlinox: resident network service blocked on fifth sequence");
        serial_write("\r\nlinox: control plane stopped resident network service");
        serial_write("\r\nlinox: resident stop quiesced device before DMA retirement");
        serial_write("\r\nlinox: resident egress wait and authority retired cleanly");
        if !address_space::verify_native_network_egress_resident_drain(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: resident reliable egress drain failed\r\n");
        }
        serial_write("\r\nlinox: unauthorized resident drain requests rejected");
        serial_write("\r\nlinox: control plane requested resident network drain");
        serial_write("\r\nlinox: resident network drain preserved four egress replies");
        serial_write("\r\nlinox: drained resident network service exited normally");
        serial_write("\r\nlinox: resident drain quiesced device before DMA retirement");
        if !address_space::verify_native_network_egress_resident_restart(
            &network_image,
            virtio_network,
            virtio_network_initialization,
            virtio_network_iommu_profile,
            (
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            ),
        ) {
            kernel_fail("\r\nlinox: resident network replacement failed\r\n");
        }
        serial_write("\r\nlinox: stopped resident network service replaced cleanly");
        serial_write("\r\nlinox: replacement network domain generation was distinct");
        serial_write("\r\nlinox: replacement network DMA and VT-d leases were fresh");
        serial_write("\r\nlinox: replacement resident service resumed exact egress sequence");
        serial_write("\r\nlinox: replenished network buffer guards preserved");
        serial_write("\r\nlinox: replenished network interrupt routes retired cleanly");
        if let Some(native_volume_outcome) = native_volume_summary {
            serial_write("\r\nlinox: post-cancellation native volume generation started");
            serial_write(match native_volume_outcome {
                address_space::NativeVolumeOutcome::Initialized
                | address_space::NativeVolumeOutcome::Recovered => {
                    "\r\nlinox: post-cancellation native volume recovered exact record"
                }
                address_space::NativeVolumeOutcome::Rejected => {
                    "\r\nlinox: post-cancellation native volume preserved rejection"
                }
                address_space::NativeVolumeOutcome::RestartRequired => {
                    "\r\nlinox: post-cancellation native volume requested restart unexpectedly"
                }
                address_space::NativeVolumeOutcome::IncompatibleAbi => {
                    "\r\nlinox: post-cancellation native volume rejected its ABI unexpectedly"
                }
                address_space::NativeVolumeOutcome::Faulted => {
                    "\r\nlinox: post-cancellation native volume faulted unexpectedly"
                }
            });
            serial_write("\r\nlinox: post-cancellation native resources retired cleanly");
            serial_write("\r\nlinox: every native volume generation used an active IOMMU domain");
            serial_write("\r\nlinox: native volume generations received fresh IOMMU leases");
            serial_write("\r\nlinox: native volume IOMMU retired after device quiescence");
            serial_write("\r\nlinox: fault and timeout paths retired native volume IOMMU state");
            serial_write("\r\nlinox: native volume write-only grant exercised in ring 3");
            serial_write("\r\nlinox: isolated virtio feature negotiation completed");
            serial_write("\r\nlinox: isolated virtio queue geometry configured with owned DMA");
            serial_write("\r\nlinox: isolated DMA lease initialized in ring 3");
            serial_write("\r\nlinox: isolated virtio queue bound to inactive DMA lease");
            serial_write("\r\nlinox: isolated virtio queue activated before publication");
            serial_write("\r\nlinox: isolated virtio read descriptors prepared in ring 3");
            serial_write("\r\nlinox: isolated virtio available entry published in ring 3");
            serial_write("\r\nlinox: stale isolated virtio wait generation rejected");
            serial_write("\r\nlinox: isolated virtio queue notified from ring 3");
            serial_write("\r\nlinox: isolated virtio service blocked on MSI-X");
            serial_write("\r\nlinox: kernel-owned MSI-X woke isolated virtio service");
            serial_write("\r\nlinox: isolated virtio timeout cancelled after MSI-X");
            serial_write("\r\nlinox: isolated virtio live timeout retried successfully");
            serial_write("\r\nlinox: duplicate isolated virtio wait rejected");
            serial_write("\r\nlinox: isolated volume slots scanned in ring 3");
            serial_write("\r\nlinox: isolated virtio request generation advanced and reused");
            serial_write("\r\nlinox: completed native volume service authority revoked");
            serial_write("\r\nlinox: virtio DMA validation followed hardware quiescence");
            serial_write("\r\nlinox: clean exit quiesced device before DMA release");
            serial_write("\r\nlinox: retired DMA lease scrubbed and released");
            serial_write("\r\nlinox: native volume device quiesced before release");
            serial_write("\r\nlinox: isolated virtio MSI-X route retired before DMA release");
        }
        serial_write("\r\nlinox: opaque capability handles enforced at call gate");
        serial_write("\r\nlinox: control call ABI v4 negotiated");
        serial_write("\r\nlinox: userspace console capability enforced");
        serial_write("\r\nlinox: minimal user interrupt surface enforced");
        serial_write("\r\nlinox: bounded userspace read enforced");
        serial_write("\r\nlinox: user copies bound to owned mappings");
        serial_write("\r\nlinox: page-granular user range validation enforced");
        serial_write("\r\nlinox: structured userspace ABI result verified");
        serial_write("\r\nlinox: ring-3 fault survivor resumed and exited");
        serial_write("\r\nlinox: user page fault contained");
        serial_write("\r\nlinox: isolated scheduler address spaces switched");
        serial_write("\r\nlinox: scheduler CR3 roots validated");
        serial_write("\r\nlinox: bounded user page-table hierarchy validated");
        serial_write("\r\nlinox: address-space resource contract shared");
        serial_write("\r\nlinox: scheduler address-space ownership validated");
        serial_write("\r\nlinox: scheduler user mappings validated");
        serial_write("\r\nlinox: one-shot user preemption completed");
        serial_write("\r\nlinox: restarted service preemption completed");
        serial_write("\r\nlinox: completed address-space frames reclaimed");
        serial_write("\r\nlinox: retired domain frame ownership cleared");
        serial_write("\r\nlinox: retired service frame quarantine cleared");
        serial_write("\r\nlinox: capability-gated bounded IPC verified");
        serial_write("\r\nlinox: directional IPC endpoints isolated");
        serial_write("\r\nlinox: generation-bound IPC endpoints verified");
        serial_write("\r\nlinox: generation-tagged IPC messages verified");
        serial_write("\r\nlinox: monotonic queued IPC sequences verified");
        serial_write("\r\nlinox: structured IPC delivery provenance verified");
        serial_write("\r\nlinox: IPC diagnostic authority enforced");
        serial_write("\r\nlinox: blocking IPC direct wake completed");
        serial_write("\r\nlinox: direct IPC wake provenance verified");
        serial_write("\r\nlinox: sequenced direct IPC delivery verified");
        serial_write("\r\nlinox: IPC wait-key matching enforced");
        serial_write("\r\nlinox: blocked IPC peer-close cleanup verified");
        serial_write("\r\nlinox: sticky IPC peer closure delivered");
        serial_write("\r\nlinox: monotonic IPC peer closures verified");
        serial_write("\r\nlinox: isolated service request-reply completed");
        serial_write("\r\nlinox: service domain authority restricted to IPC");
        serial_write("\r\nlinox: faulted service domain authority retired");
        serial_write("\r\nlinox: service fault event delivered to control plane");
        serial_write("\r\nlinox: service fault event generation matched");
        serial_write("\r\nlinox: monotonic lifecycle events verified");
        serial_write("\r\nlinox: structured lifecycle event delivered");
        serial_write("\r\nlinox: structured lifecycle service identity delivered");
        serial_write("\r\nlinox: lifecycle diagnostic authority enforced");
        serial_write("\r\nlinox: service fault metadata matched");
        serial_write("\r\nlinox: structured service fault delivered");
        serial_write("\r\nlinox: service fault diagnostic authority enforced");
        serial_write("\r\nlinox: service domain generation reuse verified");
        serial_write("\r\nlinox: stable service identity survived restart");
        serial_write("\r\nlinox: service restart budget exhausted");
        serial_write("\r\nlinox: service restart rollback invariants verified");
        serial_write("\r\nlinox: failed service stack scrubbed before restart");
        serial_write("\r\nlinox: service frame ownership transferred to replacement");
        serial_write("\r\nlinox: replacement service context executed");
        serial_write("\r\nlinox: replacement service request-reply completed");
        serial_write("\r\nlinox: volatile storage service round-trip completed");
        serial_write("\r\nlinox: volatile storage invalid command rejected");
        serial_write("\r\nlinox: replacement service readiness delivered");
        serial_write("\r\nlinox: replacement service clean exit delivered");
        serial_write("\r\nlinox: per-domain syscall budgets enforced");
        serial_write("\r\nlinox: per-domain thread budgets enforced");
        serial_write("\r\nlinox: in-flight domain operations drained");
        if !scheduler::verify_scheduler_invariants() {
            kernel_fail("\r\nlinox: scheduler lifecycle invariant failed\r\n");
        }
        if !arch::x86_64::cpu::verify_user_fs_base_installation() {
            kernel_fail("\r\nlinox: per-thread FS base installation failed\r\n");
        }
        serial_write("\r\nlinox: scheduler context lifecycle verified");
        serial_write("\r\nlinox: scheduler priority selection verified");
        serial_write("\r\nlinox: ingress and egress packet wait keys isolated");
        serial_write("\r\nlinox: ingress and egress space-wait keys isolated");
        serial_write("\r\nlinox: preemptible user context flags enforced");
        serial_write("\r\nlinox: per-thread FS base context preserved");
    }
    if !crypto::verify_sha256_known_answers() {
        kernel_fail("\r\nlinox: bootstrap SHA-256 self-test failed\r\n");
    }
    serial_write("\r\nlinox: bootstrap SHA-256 known answers verified");
    if !arch::x86_64::cpu::enable_container_management() {
        kernel_fail("\r\nlinox: domain management activation failed\r\n");
    }
    if !network::initialize_runtime() {
        kernel_fail("\r\nlinox: runtime network initialization failed\r\n");
    }
    if let Some(record) = persisted_local_record {
        let (domain_bytes, network_bytes) = persisted_local_configuration
            .split_at(arch::x86_64::cpu::PERSISTENT_DOMAIN_CONFIG_SIZE);
        let domain_configuration = domain_bytes.try_into().ok();
        let network_configuration = network_bytes.try_into().ok();
        if record.length != PERSISTENT_LOCAL_CONFIG_SIZE
            || domain_configuration.is_none_or(|configuration| {
                !arch::x86_64::cpu::import_persistent_domain_configuration(configuration)
            })
            || network_configuration.is_none_or(|configuration| {
                !network::import_persistent_configuration(configuration)
            })
        {
            kernel_fail("\r\nlinox: persistent local configuration invalid\r\n");
        }
    }
    let device_registers: [Option<usize>; arch::x86_64::paging::MAX_DEVICE_REGIONS] =
        core::array::from_fn(|index| {
            let (physical, length) = device_regions[index];
            device_mappings
                .get(index)
                .copied()
                .flatten()
                .filter(|mapping| {
                    arch::x86_64::paging::mmio_translation_is_bounded(*mapping, physical, length)
                        && arch::x86_64::paging::mmio_identity_alias_is_absent(*mapping)
                })
                .and_then(|mapping| mapping.address(physical, length))
        });
    let usb_registers = &device_registers[..drivers::usb_input::MAX_CONTROLLERS];
    // The virtio-gpu opens first, because the DMA it needs depends on the
    // display mode the host reports; with translation still off, it can run
    // its setup commands before it is admitted.
    let mut gpu = gpu_probe
        .zip(device_registers[usb_count])
        .and_then(|(probe, registers)| {
            // SAFETY: registers maps the probe's register span uncached in
            // the device window (checked above) for the kernel's life, and
            // no other driver touches the device.
            unsafe { drivers::virtio_gpu::prepare(&probe, registers) }
        });
    let admit = |functions: &[(u8, u8, u8)], regions: &[(u64, u64)]| {
        arch::x86_64::iommu::admit_standing_devices(
            platform.first_iommu_register_base,
            iommu_mmio,
            iommu_capabilities,
            functions,
            regions,
        )
    };
    // No DMA translation is active here, so the controllers can be admitted
    // to every later one. A controller behind a bridge may be covered by a
    // DMAR sub-hierarchy scope, which the platform summary does not record;
    // an admission into a unit that does not translate it is inert. The
    // admission happens once, so the GPU joins the USB controllers'.
    let mut usb_admission_requested = false;
    drivers::usb_input::start(&usb_hosts, usb_registers, |functions, regions| {
        usb_admission_requested = true;
        match gpu.as_mut() {
            Some(gpu) => gpu.admit_alongside(functions, regions, &admit),
            None => admit(functions, regions),
        }
    });
    if let Some(mut gpu) = gpu {
        if !usb_admission_requested {
            gpu.admit_alone(&admit);
        }
        drivers::virtio_gpu::activate(gpu);
    }
    HOST_CONTROL
        .operator_console_ready
        .store(true, Ordering::Release);
    serial_write_raw(b"linox: platform, security, devices, and runtime ready\r\n");
    serial_write("linox: persistent storage ");
    serial_write(match host_volume.disposition {
        volume::HostVolumeDisposition::Initialized => "initialized",
        volume::HostVolumeDisposition::Migrated => "migrated",
        volume::HostVolumeDisposition::Recovered => "recovered",
    });
    serial_write(" (generation ");
    serial_write_u64(host_volume.generation);
    serial_write(", ");
    serial_write_u64(host_volume.header.data_sectors);
    serial_write(" data sectors)\r\n");
    if let Some(record) = persisted_local_record {
        serial_write("linox: local configuration recovered (generation ");
        serial_write_u64(record.generation);
        serial_write(")\r\n");
    }
    if !persisted_local_configuration_valid {
        serial_write(
            "linox: local configuration rejected; continuing without persisted settings\r\n",
        );
    }
    if persisted_oci_catalog_corrupt {
        serial_write("linox: OCI cache catalog rejected; cached layers will not be trusted\r\n");
    }
    serial_write_elapsed("linox: timing boot-to-controller: ", kernel_boot_started);
    let mut controller_recovery_attempts = 0_u8;
    let mut controller_launch_announced = false;
    'managed: loop {
        HOST_CONTROL
            .background_domain_output
            .store(false, Ordering::Release);
        if !controller_launch_announced {
            serial_write("\r\nlinox: launching embedded controller in ring 3\r\n");
            controller_launch_announced = true;
        }
        let controller_completed = address_space::run_installed_interactive_controller();
        HOST_CONTROL.background_domain_output.store(
            arch::x86_64::cpu::detached_container_lifecycle_pending(),
            Ordering::Release,
        );
        let shutdown_requested = arch::x86_64::cpu::take_container_host_shutdown_request();
        if shutdown_requested && controller_completed && !cfg!(feature = "verification-boot") {
            match persist_domain_configuration(virtio_block, virtio_mmio, virtio_iommu_profile) {
                Some(record) => {
                    serial_write("linox: local configuration committed (generation ");
                    serial_write_u64(record.generation);
                    serial_write(")\r\n");
                }
                None => serial_write(
                    "linox: local configuration unavailable; runtime state remains active\r\n",
                ),
            }
        }
        if shutdown_requested {
            if !controller_completed {
                serial_write(
                    "linox: authorized shutdown retained after controller teardown failure\r\n",
                );
            }
            break;
        }
        if !controller_completed {
            controller_recovery_attempts = controller_recovery_attempts.saturating_add(1);
            if controller_recovery_attempts <= 3 {
                serial_write("linox: controller exit detail/fault: ");
                serial_write_u64(domain::last_lifecycle_event_detail().map_or(255, u64::from));
                serial_write(" ");
                serial_write_u64(domain::last_lifecycle_event_has_fault().map_or(2, u64::from));
                serial_write("\r\n");
                serial_write("linox: controller failed; restarting control plane\r\n");
                continue 'managed;
            }
            kernel_fail("linox: controller recovery budget exhausted\r\n");
        }
        controller_recovery_attempts = 0;
        if arch::x86_64::cpu::take_network_dhcp_request() {
            let success = address_space::configure_native_network_dhcp(
                &network_image,
                virtio_network,
                virtio_network_initialization,
                virtio_network_iommu_profile,
                virtio_network_common_mmio,
                virtio_network_msix_mmio,
                &local_apic,
            );
            arch::x86_64::cpu::complete_network_dhcp(success);
            continue 'managed;
        }
        if let Some(target) = arch::x86_64::cpu::take_network_ping_request() {
            let success = target != 0
                && address_space::verify_native_network_ping_gateway(
                    &network_image,
                    virtio_network,
                    virtio_network_initialization,
                    virtio_network_iommu_profile,
                    virtio_network_common_mmio,
                    virtio_network_msix_mmio,
                    &local_apic,
                );
            arch::x86_64::cpu::complete_network_ping(success);
            continue 'managed;
        }
        if arch::x86_64::cpu::take_container_pull_request() {
            let pull_started = arch::x86_64::timer::timestamp_counter();
            HOST_CONTROL
                .oci_pull_started
                .store(pull_started, Ordering::Release);
            if !image_store::begin_layer_pull() {
                serial_write("linox: OCI image staging reset failed\r\n");
                arch::x86_64::cpu::complete_container_pull(false);
                continue 'managed;
            }
            let mut image = [0_u8; control_abi::DOMAIN_MAX_IMAGE_SIZE];
            let image_size = arch::x86_64::cpu::configured_container_image(&mut image).unwrap_or(0);
            let mut downloaded = false;
            let mut cache_hit = false;
            let mut cache_repair = false;
            // The builtin image comes from the boot image: no cache or pull.
            let builtin = &image[..image_size] == image_store::BUILTIN_RUST_IMAGE;
            if builtin {
                downloaded = image_store::stage_builtin_layer();
                serial_write(if downloaded {
                    "linox: builtin Rust root filesystem staged\r\n"
                } else {
                    "linox: builtin Rust root filesystem unavailable\r\n"
                });
            }
            if image_size != 0 && !builtin {
                serial_write("linox: checking OCI cache ");
                serial_write_bytes(&image[..image_size]);
                serial_write("\r\n");
                let catalog_contains_image = persisted_oci_catalog_valid
                    && oci_catalog_contains(persisted_oci_catalog, &image[..image_size]);
                let configured_slot = arch::x86_64::cpu::configured_container_slot();
                let shared_rootfs = configured_slot.and_then(|target| {
                    (0..control_abi::DOMAIN_LIMIT)
                        .find(|source| {
                            *source != target
                                && published_rootfs::is_installed(*source)
                                && arch::x86_64::cpu::container_image_matches(
                                    *source,
                                    &image[..image_size],
                                )
                        })
                        .filter(|source| image_store::share_installed_rootfs(*source, target))
                });
                match if shared_rootfs.is_some() {
                    OciCacheRestore::RootfsHit
                } else if catalog_contains_image {
                    restore_cached_oci_layers(
                        virtio_block,
                        virtio_mmio,
                        virtio_iommu_profile,
                        &image[..image_size],
                        configured_slot,
                    )
                } else {
                    OciCacheRestore::Miss
                } {
                    OciCacheRestore::RootfsHit => {
                        serial_write("linox: OCI cache hit (published root filesystem)\r\n");
                        downloaded = true;
                        cache_hit = true;
                    }
                    OciCacheRestore::LayerHit(layers) => {
                        serial_write("linox: OCI cache hit (");
                        serial_write_usize(layers);
                        serial_write(if layers == 1 {
                            " layer)\r\n"
                        } else {
                            " layers)\r\n"
                        });
                        downloaded = true;
                        cache_hit = true;
                    }
                    OciCacheRestore::Miss => {
                        serial_write("linox: OCI cache miss; pulling image\r\n");
                    }
                    OciCacheRestore::Invalid => {
                        serial_write("linox: OCI cache invalid; pulling verified replacement\r\n");
                        let _ = image_store::discard_published_layers();
                        cache_repair = true;
                    }
                }
            }
            if image_size != 0 && !cache_hit && !builtin {
                serial_write("linox: pulling OCI image ");
                serial_write_bytes(&image[..image_size]);
                serial_write("\r\n");
                for attempt in 0..3 {
                    if attempt != 0 {
                        serial_write("linox: retrying OCI registry pull (");
                        serial_write_u64((attempt + 1) as u64);
                        serial_write("/3)\r\n");
                        if !image_store::discard_published_layers() {
                            break;
                        }
                    }
                    downloaded = address_space::pull_native_oci_image(
                        &network_image,
                        virtio_network,
                        virtio_network_initialization,
                        virtio_network_iommu_profile,
                        virtio_network_common_mmio,
                        &image[..image_size],
                        boot_info.unix_time,
                    );
                    if downloaded {
                        break;
                    }
                }
            }
            let transfer_finished = arch::x86_64::timer::timestamp_counter();
            serial_write_elapsed_at(
                if cache_hit {
                    "linox: timing OCI cache restore: "
                } else {
                    "linox: timing OCI transfer: "
                },
                pull_started,
                transfer_finished,
            );
            if downloaded && !cache_hit && !builtin {
                match persist_oci_layers(
                    virtio_block,
                    virtio_mmio,
                    virtio_iommu_profile,
                    &image[..image_size],
                    persisted_oci_catalog,
                    !cache_repair,
                ) {
                    Some((layers, bytes)) => {
                        serial_write("linox: OCI cache stored ");
                        serial_write_usize(layers);
                        serial_write(if layers == 1 { " layer (" } else { " layers (" });
                        serial_write_u64(bytes);
                        serial_write(" bytes)\r\n");
                        persisted_oci_catalog_valid = true;
                    }
                    None => serial_write(
                        "linox: OCI cache write unavailable; continuing with verified image\r\n",
                    ),
                }
            }
            if downloaded {
                arch::x86_64::cpu::request_container_install();
            } else {
                let _ = image_store::discard_published_layers();
                arch::x86_64::cpu::complete_container_pull(false);
                serial_write("linox: OCI image pull failed; partial objects discarded\r\n");
            }
            if !downloaded || !arch::x86_64::cpu::configured_container_console_attached() {
                continue 'managed;
            }
        }
        if arch::x86_64::cpu::take_container_install_request() {
            let mut image = [0_u8; control_abi::DOMAIN_MAX_IMAGE_SIZE];
            let image_size = arch::x86_64::cpu::configured_container_image(&mut image).unwrap_or(0);
            let slot = arch::x86_64::cpu::configured_container_slot();
            let cached_rootfs = slot.is_some_and(published_rootfs::is_installed);
            if !cached_rootfs {
                serial_write("linox: OCI unpacking image filesystem\r\n");
            }
            let unpack_started = arch::x86_64::timer::timestamp_counter();
            let success = slot.is_some_and(|slot| {
                image_size != 0
                    && (cached_rootfs
                        || image_store::install_published_layers(
                            slot,
                            image_store::DEFAULT_ROOTFS_UNPACK_LIMIT_BYTES,
                        ))
            });
            serial_write_elapsed("linox: timing OCI unpack/publish: ", unpack_started);
            let builtin = &image[..image_size] == image_store::BUILTIN_RUST_IMAGE;
            if success && !cached_rootfs && !builtin {
                if let Some((bytes, newly_stored)) = persist_oci_rootfs(
                    virtio_block,
                    virtio_mmio,
                    virtio_iommu_profile,
                    &image[..image_size],
                    persisted_oci_catalog,
                    slot.unwrap_or(usize::MAX),
                ) {
                    serial_write(if newly_stored {
                        "linox: OCI cache stored published root filesystem ("
                    } else {
                        "linox: OCI cache retained published root filesystem ("
                    });
                    serial_write_u64(bytes);
                    serial_write(" bytes)\r\n");
                }
            }
            let pull_started = HOST_CONTROL.oci_pull_started.swap(0, Ordering::AcqRel);
            if pull_started != 0 {
                serial_write_elapsed("linox: timing OCI total: ", pull_started);
            }
            if !success {
                let _ = image_store::discard_published_layers();
            }
            arch::x86_64::cpu::complete_container_pull(success);
            serial_write(if success {
                "linox: OCI image ready\r\n"
            } else {
                "linox: OCI image unpack failed; partial objects discarded\r\n"
            });
            if !success || !arch::x86_64::cpu::configured_container_console_attached() {
                continue 'managed;
            }
        }
        let runtime_suspended = arch::x86_64::cpu::configured_container_slot()
            .is_some_and(address_space::linux_runtime_is_suspended);
        if controller_completed && !runtime_suspended && !cfg!(feature = "verification-boot") {
            match persist_domain_configuration(virtio_block, virtio_mmio, virtio_iommu_profile) {
                Some(record) => {
                    serial_write("linox: local configuration committed (generation ");
                    serial_write_u64(record.generation);
                    serial_write(")\r\n");
                }
                None => serial_write(
                    "linox: local configuration unavailable; runtime state remains active\r\n",
                ),
            }
        }
        if !arch::x86_64::cpu::take_container_restart_request() {
            kernel_fail("linox: controller exited without a lifecycle request\r\n");
        }
        let domain_started = arch::x86_64::timer::timestamp_counter();
        arch::x86_64::cpu::mark_configured_container_booting();
        loop {
            let resuming = arch::x86_64::cpu::configured_container_slot()
                .is_some_and(address_space::linux_runtime_is_suspended);
            if !resuming {
                serial_write("linox: starting configured runtime domain\r\n");
            }
            if arch::x86_64::cpu::configured_domain_uses_published_rootfs() {
                let mut init = [0_u8; control_abi::DOMAIN_MAX_INIT_SIZE];
                let Some(init_size) = arch::x86_64::cpu::configured_container_init(&mut init)
                else {
                    serial_write(
                        "linox: configured Linux init unavailable; domain marked failed\r\n",
                    );
                    arch::x86_64::cpu::fail_configured_container();
                    break;
                };
                if !resuming {
                    serial_write("linox: entering configured Linux init\r\n");
                    serial_write_elapsed(
                        "linox: timing domain-start-to-Linux-init-entry: ",
                        domain_started,
                    );
                }
                arch::x86_64::cpu::begin_configured_container();
                match address_space::run_linux_init(&init[..init_size]) {
                    address_space::LinuxProcessOutcome::Suspended => {
                        arch::x86_64::cpu::suspend_configured_container();
                        break;
                    }
                    address_space::LinuxProcessOutcome::Failed => {
                        serial_write(
                            "linox: Linux init execution failed; domain marked failed\r\n",
                        );
                        arch::x86_64::cpu::fail_configured_container();
                        break;
                    }
                    address_space::LinuxProcessOutcome::Exited(status) => {
                        arch::x86_64::cpu::stop_configured_container();
                        if status == 0 {
                            serial_write("linox: Linux init exited cleanly\r\n");
                        } else {
                            serial_write("linox: Linux init exited with status ");
                            serial_write_u64(u64::from(status));
                            serial_write("\r\n");
                        }
                    }
                }
            } else {
                arch::x86_64::cpu::begin_configured_container();
                if !linux_elf::verify_mapped_system_init_plan(
                    boot_info.image_base as u64,
                    boot_info.image_size,
                ) {
                    kernel_fail("linox: minimal system init execution failed\r\n");
                }
                arch::x86_64::cpu::stop_configured_container();
            }
            if arch::x86_64::cpu::take_container_host_shutdown_request() {
                break 'managed;
            }
            if arch::x86_64::cpu::take_container_restart_request() {
                serial_write("linox: restarting configured runtime domain\r\n");
                continue;
            }
            break;
        }
    }
    serial_write("\r\nlinox: controller requested clean shutdown");
    serial_write("\r\nLINOX_KERNEL_OK\r\n");

    // A privileged domain's reboot(2) may have asked for a cold reset. The
    // firmware runs on the kernel's own tables, which map all its memory
    // (a Linux process's map only its runtime services).
    address_space::activate_root(arch::x86_64::paging::kernel_root_address());
    (boot_info.reset_system)(
        machine_control::reset_kind(),
        EFI_SUCCESS,
        0,
        core::ptr::null(),
    );
    kernel_fail("linox: firmware shutdown returned unexpectedly\r\n");
}

fn validate_acpi_rsdp(rsdp: *const u8) -> Option<usize> {
    const RSDP_V1_SIZE: usize = 20;
    const RSDP_V2_SIZE: usize = 36;
    const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

    if rsdp.is_null() || rsdp as usize >= arch::x86_64::paging::INITIAL_IDENTITY_LIMIT {
        return None;
    }
    // SAFETY: The UEFI configuration table supplied this physical pointer. We
    // first inspect only the fixed ACPI 1.0 prefix, then bound any extended
    // length before reading it.
    unsafe {
        for (offset, expected) in RSDP_SIGNATURE.iter().enumerate() {
            if rsdp.add(offset).read() != *expected {
                return None;
            }
        }
        if checksum(rsdp, RSDP_V1_SIZE) != 0 {
            return None;
        }
        let revision = rsdp.add(15).read();
        let length = if revision >= 2 {
            let length = core::ptr::read_unaligned(rsdp.add(20).cast::<u32>()) as usize;
            if length < RSDP_V2_SIZE {
                return None;
            }
            length
        } else {
            RSDP_V1_SIZE
        };
        let end = (rsdp as usize).checked_add(length.checked_sub(1)?)?;
        if end >= arch::x86_64::paging::INITIAL_IDENTITY_LIMIT || checksum(rsdp, length) != 0 {
            return None;
        }
        Some(end)
    }
}

unsafe fn checksum(bytes: *const u8, length: usize) -> u8 {
    let mut sum = 0_u8;
    for offset in 0..length {
        sum = sum.wrapping_add(bytes.add(offset).read());
    }
    sum
}

fn verify_initial_frame_allocation(boot_info: &BootInfo) -> bool {
    if !memory::initialize(boot_info, arch::x86_64::paging::direct_map_limit() as u64) {
        return false;
    }
    if !memory::verify_reservation_invariants() {
        return false;
    }
    if memory::reclaimed_boot_service_frame_count().is_none_or(|count| count == 0) {
        return false;
    }
    let Some([first, second]) = memory::allocate_frames::<2>(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let first_address = first.address();
    let second_address = second.address();
    if first_address == second_address || first_address % 4096 != 0 || second_address % 4096 != 0 {
        return false;
    }

    let (Some(first_mapped), Some(second_mapped)) =
        (first.direct_map_address(), second.direct_map_address())
    else {
        return false;
    };

    // SAFETY: Both frames are conventional UEFI memory, distinct, aligned,
    // and covered by the checked direct map. Volatile accesses prove both
    // fresh and dirty recycled frames are scrubbed by the allocation boundary.
    unsafe {
        let first_word = first_mapped as *mut u64;
        let second_word = second_mapped as *mut u64;
        if !frame_is_zero(first) || !frame_is_zero(second) {
            return false;
        }
        first_word.write_volatile(0x4749_4e55_5800_0001);
        second_word.write_volatile(0x4749_4e55_5800_0002);
        first_word
            .add(PAGE_SIZE / size_of::<u64>() - 1)
            .write_volatile(0x4749_4e55_5800_0011);
        second_word
            .add(PAGE_SIZE / size_of::<u64>() - 1)
            .write_volatile(0x4749_4e55_5800_0012);
        if !memory::release_frames(memory::FrameOwner::KERNEL, [first, second]) {
            return false;
        }
        let Some(reused) = memory::allocate_frames::<2>(memory::FrameOwner::KERNEL) else {
            return false;
        };
        let scrubbed = reused.iter().all(|frame| frame_is_zero(*frame));
        scrubbed
            && memory::release_frames(memory::FrameOwner::KERNEL, reused)
            && !memory::initialize(boot_info, arch::x86_64::paging::direct_map_limit() as u64)
    }
}

unsafe fn frame_is_zero(frame: memory::FrameLease) -> bool {
    let Some(address) = frame.direct_map_address() else {
        return false;
    };
    let words = address as *const u64;
    (0..PAGE_SIZE / size_of::<u64>()).all(|offset| words.add(offset).read_volatile() == 0)
}

fn kernel_stack_is_active() -> bool {
    let stack_pointer: usize;
    // SAFETY: Reading RSP does not alter machine or memory state.
    unsafe {
        asm!(
            "mov {}, rsp",
            out(reg) stack_pointer,
            options(nomem, nostack, preserves_flags)
        );
    }

    let stack_start = core::ptr::addr_of!(KERNEL_STACK) as usize;
    let stack_start = stack_start + PAGE_SIZE;
    let stack_end = stack_start + KERNEL_STACK_SIZE;
    (stack_start..stack_end).contains(&stack_pointer)
}

fn summarize_memory(boot_info: &BootInfo) -> MemorySummary {
    let descriptors = boot_info.memory_map_size / boot_info.memory_descriptor_size;
    let mut summary = MemorySummary {
        descriptors,
        conventional_pages: 0,
        boot_service_pages: 0,
        loader_pages: 0,
    };

    for index in 0..descriptors {
        // SAFETY: BootInfo validation established a non-null map, a descriptor
        // stride large enough for the required prefix, and an integral count.
        let descriptor = unsafe {
            let address = boot_info
                .memory_map
                .add(index * boot_info.memory_descriptor_size);
            core::ptr::read_unaligned(address.cast::<UefiMemoryDescriptor>())
        };

        match descriptor.memory_type {
            EFI_CONVENTIONAL_MEMORY => {
                summary.conventional_pages = summary
                    .conventional_pages
                    .saturating_add(descriptor.page_count);
            }
            EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA => {
                summary.boot_service_pages = summary
                    .boot_service_pages
                    .saturating_add(descriptor.page_count);
            }
            EFI_LOADER_CODE | EFI_LOADER_DATA => {
                summary.loader_pages = summary.loader_pages.saturating_add(descriptor.page_count);
            }
            _ => {}
        }
    }

    summary
}

fn kernel_fail(message: &str) -> ! {
    serial_write_raw(message.as_bytes());
    serial_write_raw(b"LINOX_KERNEL_PANIC\r\n");
    loop {
        core::hint::spin_loop();
    }
}

static SERIAL_PRESENT: AtomicBool = AtomicBool::new(false);

fn serial_init() {
    // Physical machines often have no COM1; reads from an absent UART float to
    // 0xff, which would otherwise look like a permanently ready receiver.
    // Probing the scratch register has no side effects on other devices.
    let scratch = Port8::com1(7);
    scratch.write(0xa5);
    let first = scratch.read() == 0xa5;
    scratch.write(0x5a);
    let present = first && scratch.read() == 0x5a;
    SERIAL_PRESENT.store(present, Ordering::Release);
    if !present {
        return;
    }
    // COM1 answered the scratch-register probe.
    Port8::com1(1).write(0x00);
    Port8::com1(3).write(0x80);
    Port8::com1(0).write(0x03);
    Port8::com1(1).write(0x00);
    Port8::com1(3).write(0x03);
    Port8::com1(2).write(0xc7);
    Port8::com1(4).write(0x0b);
}

fn serial_write(message: &str) {
    serial_write_bytes(message.as_bytes());
}

pub(crate) fn serial_write_bytes(bytes: &[u8]) {
    kernel_log::record(bytes);
    if !cfg!(feature = "verification-boot")
        && !HOST_CONTROL.operator_console_ready.load(Ordering::Acquire)
    {
        return;
    }
    if HOST_CONTROL
        .background_domain_output
        .load(Ordering::Acquire)
        && arch::x86_64::cpu::buffer_configured_container_console(bytes)
    {
        return;
    }
    serial_write_raw(bytes);
}

pub(crate) fn serial_write_raw(bytes: &[u8]) {
    framebuffer::write(bytes);
    if !SERIAL_PRESENT.load(Ordering::Acquire) {
        return;
    }
    for byte in bytes.iter().copied() {
        // A byte leaves a 38400-baud UART in 260 us, a few hundred port
        // reads. A UART that never empties (present but wedged, as the
        // scratch-register probe cannot rule out on a physical board) must
        // not stop the framebuffer console: give it up after ~10 ms.
        let mut spins = 0_u32;
        while Port8::com1(5).read() & 0x20 == 0 {
            spins += 1;
            if spins == 10_000 {
                SERIAL_PRESENT.store(false, Ordering::Release);
                return;
            }
            core::hint::spin_loop();
        }

        Port8::com1(0).write(byte);
    }
}

/// Reads a console byte from the serial port or, while no domain owns the
/// screen, from a USB keyboard.
pub(crate) fn serial_read_byte_blocking() -> u8 {
    loop {
        if serial_byte_waiting() {
            return Port8::com1(0).read();
        }
        if let Some(byte) = linux_input::take_console_byte() {
            return byte;
        }
        core::hint::spin_loop();
    }
}

pub(crate) fn serial_input_ready() -> bool {
    serial_byte_waiting() || linux_input::console_byte_ready()
}

/// O_NONBLOCK of the console's open file, which every descriptor of the
/// attached console shares as Linux's terminal does: a read with nothing
/// typed then fails with EAGAIN instead of waiting.
static CONSOLE_NONBLOCKING: AtomicBool = AtomicBool::new(false);

pub(crate) fn console_nonblocking() -> bool {
    CONSOLE_NONBLOCKING.load(Ordering::Acquire)
}

pub(crate) fn set_console_nonblocking(nonblocking: bool) {
    CONSOLE_NONBLOCKING.store(nonblocking, Ordering::Release);
}

fn serial_byte_waiting() -> bool {
    SERIAL_PRESENT.load(Ordering::Acquire) && (Port8::com1(5).read() & 0x01) != 0
}

fn serial_write_usize(value: usize) {
    serial_write_u64(value as u64);
}

fn serial_write_elapsed(label: &str, started: u64) {
    serial_write_elapsed_at(label, started, arch::x86_64::timer::timestamp_counter());
}

#[inline(never)]
fn persist_domain_configuration(
    device: arch::x86_64::pci::VirtioBlockDevice,
    mapping: arch::x86_64::paging::MmioMapping,
    iommu_profile: arch::x86_64::iommu::DeviceTranslationProfile,
) -> Option<volume::LocalConfigRecord> {
    let mut configuration = [0_u8; PERSISTENT_LOCAL_CONFIG_SIZE];
    let (domain_bytes, network_bytes) =
        configuration.split_at_mut(arch::x86_64::cpu::PERSISTENT_DOMAIN_CONFIG_SIZE);
    let domain_configuration = domain_bytes.try_into().ok()?;
    let network_configuration = network_bytes.try_into().ok()?;
    if !arch::x86_64::cpu::export_persistent_domain_configuration(domain_configuration) {
        return None;
    }
    network::export_persistent_configuration(network_configuration);
    with_runtime_volume(device, mapping, iommu_profile, |backend| {
        volume::commit_local_config(backend, &configuration).ok()
    })
}

#[inline(never)]
fn with_runtime_volume<T>(
    device: arch::x86_64::pci::VirtioBlockDevice,
    mapping: arch::x86_64::paging::MmioMapping,
    iommu_profile: arch::x86_64::iommu::DeviceTranslationProfile,
    operation: impl FnOnce(&mut arch::x86_64::pci::VirtioBlockBackend) -> Option<T>,
) -> Option<T> {
    let [dma_frame] = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL)?;
    let Some(dma_virtual) = dma_frame.direct_map_address() else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[dma_frame]);
        return None;
    };
    let Some(translation) = iommu_profile.activate(dma_frame) else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[dma_frame]);
        return None;
    };
    let Some(mut backend) = (unsafe {
        arch::x86_64::pci::VirtioBlockBackend::start(
            device,
            mapping,
            dma_frame.address(),
            dma_virtual,
        )
    }) else {
        let translation_retired = translation.finish();
        let _ = retire_runtime_volume_dma(dma_frame, true, translation_retired);
        return None;
    };
    let result = operation(&mut backend);
    let device_quiesced = backend.finish();
    let translation_retired = translation.finish();
    let dma_retired = retire_runtime_volume_dma(dma_frame, device_quiesced, translation_retired);
    (device_quiesced && translation_retired && dma_retired)
        .then_some(result)
        .flatten()
}

fn retire_runtime_volume_dma(
    dma_frame: memory::FrameLease,
    device_quiesced: bool,
    translation_retired: bool,
) -> bool {
    device_quiesced
        && translation_retired
        && memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[dma_frame])
        && !memory::any_frame_lease_live(&[dma_frame])
}

fn verify_runtime_volume_dma_retirement() -> bool {
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let Some(frames) = memory::allocate_frames::<4>(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let retained = [(false, true), (true, false), (false, false)]
        .into_iter()
        .zip(frames[..3].iter().copied())
        .all(|((device_quiesced, translation_retired), frame)| {
            !retire_runtime_volume_dma(frame, device_quiesced, translation_retired)
                && memory::frames_owned_by(memory::FrameOwner::KERNEL, &[frame])
                && memory::any_frame_lease_live(&[frame])
        });
    let released = retire_runtime_volume_dma(frames[3], true, true)
        && !memory::any_frame_lease_live(&[frames[3]]);
    let cleanup = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &frames[..3]);
    retained
        && released
        && cleanup
        && memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before)
}

enum OciCacheRestore {
    RootfsHit,
    LayerHit(usize),
    Miss,
    Invalid,
}

#[inline(never)]
fn restore_cached_oci_layers(
    device: arch::x86_64::pci::VirtioBlockDevice,
    mapping: arch::x86_64::paging::MmioMapping,
    iommu_profile: arch::x86_64::iommu::DeviceTranslationProfile,
    reference: &[u8],
    slot: Option<usize>,
) -> OciCacheRestore {
    with_runtime_volume(device, mapping, iommu_profile, |backend| {
        let mut encoded = [0_u8; linox_oci_cache::ENCODED_SIZE];
        let record = match volume::recover_oci_catalog(backend, &mut encoded) {
            Ok(Some(record)) => record,
            Ok(None) => return Some(OciCacheRestore::Miss),
            _ => return Some(OciCacheRestore::Invalid),
        };
        let Some(catalog) = linox_oci_cache::Catalog::decode(&encoded[..record.length]) else {
            return Some(OciCacheRestore::Invalid);
        };
        let Some(entry) = catalog.find(reference, linox_oci_cache::Platform::LinuxAmd64) else {
            return Some(OciCacheRestore::Miss);
        };
        let compressed_length = entry
            .layers()
            .iter()
            .try_fold(0_u64, |total, layer| total.checked_add(layer.length));
        let direct_rootfs = entry.rootfs().filter(|rootfs| {
            compressed_length
                .is_some_and(|compressed| rootfs.length <= compressed.saturating_mul(2))
        });
        if let (Some(slot), Some(rootfs)) = (slot, direct_rootfs) {
            let Ok(length) = usize::try_from(rootfs.length) else {
                return Some(OciCacheRestore::Invalid);
            };
            if let Some(source) = (0..control_abi::DOMAIN_LIMIT).find(|source| {
                *source != slot
                    && image_store::installed_rootfs(*source).is_some_and(|bytes| {
                        bytes.len() == length && crypto::sha256(bytes) == rootfs.digest
                    })
            }) {
                return Some(if image_store::share_installed_rootfs(source, slot) {
                    OciCacheRestore::RootfsHit
                } else {
                    OciCacheRestore::Invalid
                });
            }
            let page_count = length.div_ceil(4096);
            let Some((first_frame, allocated)) =
                memory::allocate_contiguous_extent(memory::FrameOwner::KERNEL, page_count)
            else {
                return Some(OciCacheRestore::Invalid);
            };
            let Some(address) = first_frame.direct_map_address() else {
                let _ = memory::scrub_and_release_contiguous_extent(
                    memory::FrameOwner::KERNEL,
                    first_frame,
                    allocated,
                );
                return Some(OciCacheRestore::Invalid);
            };
            let output = unsafe {
                core::slice::from_raw_parts_mut(address as *mut u8, allocated.saturating_mul(4096))
            };
            output.fill(0);
            let Ok(start_sector) = usize::try_from(rootfs.start_sector) else {
                let _ = memory::scrub_and_release_contiguous_extent(
                    memory::FrameOwner::KERNEL,
                    first_frame,
                    allocated,
                );
                return Some(OciCacheRestore::Invalid);
            };
            let mut offset = 0_usize;
            let mut valid = true;
            while offset < length {
                let copied = (length - offset).min(2048);
                let transfer = copied.div_ceil(linox_volume_format::SECTOR_SIZE)
                    * linox_volume_format::SECTOR_SIZE;
                if !backend.read_sectors(
                    start_sector + offset / linox_volume_format::SECTOR_SIZE,
                    &mut output[offset..offset + transfer],
                ) {
                    valid = false;
                    break;
                }
                offset += copied;
            }
            valid &= crate::crypto::sha256(&output[..length]) == rootfs.digest;
            if valid && image_store::install_cached_rootfs(slot, first_frame, allocated, length) {
                return Some(OciCacheRestore::RootfsHit);
            }
            let _ = memory::scrub_and_release_contiguous_extent(
                memory::FrameOwner::KERNEL,
                first_frame,
                allocated,
            );
            return Some(OciCacheRestore::Invalid);
        }
        let mut layers = [linox_oci_cache::Layer::EMPTY; linox_oci_cache::LAYER_LIMIT];
        let layer_count = entry.layers().len();
        layers[..layer_count].copy_from_slice(entry.layers());
        for layer in &layers[..layer_count] {
            let Ok(length) = usize::try_from(layer.length) else {
                let _ = image_store::discard_published_layers();
                return Some(OciCacheRestore::Invalid);
            };
            let Ok(start_sector) = usize::try_from(layer.start_sector) else {
                let _ = image_store::discard_published_layers();
                return Some(OciCacheRestore::Invalid);
            };
            let Ok(handle) = image_store::stage(layer.digest, length) else {
                let _ = image_store::discard_published_layers();
                return Some(OciCacheRestore::Invalid);
            };
            let mut offset = 0_usize;
            let mut sectors = [0_u8; 2048];
            while offset < length {
                let sector_index = offset / linox_volume_format::SECTOR_SIZE;
                let copied = (length - offset).min(sectors.len());
                let transfer = copied.div_ceil(linox_volume_format::SECTOR_SIZE)
                    * linox_volume_format::SECTOR_SIZE;
                if !backend.read_sectors(start_sector + sector_index, &mut sectors[..transfer])
                    || image_store::append(handle, &sectors[..copied]).is_err()
                {
                    let _ = image_store::abort(handle);
                    let _ = image_store::discard_published_layers();
                    return Some(OciCacheRestore::Invalid);
                }
                offset += copied;
            }
            if image_store::publish(handle).is_err() {
                let _ = image_store::discard_published_layers();
                return Some(OciCacheRestore::Invalid);
            }
        }
        Some(OciCacheRestore::LayerHit(layer_count))
    })
    .unwrap_or(OciCacheRestore::Invalid)
}

#[inline(never)]
fn persist_oci_layers(
    device: arch::x86_64::pci::VirtioBlockDevice,
    mapping: arch::x86_64::paging::MmioMapping,
    iommu_profile: arch::x86_64::iommu::DeviceTranslationProfile,
    reference: &[u8],
    encoded: &mut [u8; linox_oci_cache::ENCODED_SIZE],
    reuse_existing_layers: bool,
) -> Option<(usize, u64)> {
    with_runtime_volume(device, mapping, iommu_profile, |backend| {
        let mut catalog = match volume::recover_oci_catalog(backend, encoded) {
            Ok(Some(record)) => {
                linox_oci_cache::Catalog::decode(&encoded[..record.length]).unwrap_or_default()
            }
            Ok(None) => linox_oci_cache::Catalog::new(),
            Err(_) => return None,
        };
        let layer_count = image_store::published_layer_count();
        if layer_count == 0 || layer_count > linox_oci_cache::LAYER_LIMIT {
            return None;
        }
        let mut layers = [linox_oci_cache::Layer::EMPTY; linox_oci_cache::LAYER_LIMIT];
        let mut next_sector = catalog.next_object_sector()?;
        let capacity = backend.capacity_sectors();
        let mut stored_bytes = 0_u64;
        for (index, layer) in layers[..layer_count].iter_mut().enumerate() {
            let (digest, length) = image_store::published_layer_info(index)?;
            let length = u64::try_from(length).ok()?;
            if reuse_existing_layers {
                if let Some(existing) = catalog.find_layer(digest, length) {
                    *layer = existing;
                    continue;
                }
            }
            let sectors = length.checked_add(511)?.checked_div(512)?;
            if next_sector.checked_add(sectors)? > capacity {
                return None;
            }
            *layer = linox_oci_cache::Layer {
                digest,
                start_sector: next_sector,
                length,
            };
            let mut offset = 0_usize;
            while offset < usize::try_from(length).ok()? {
                let mut sector = [0_u8; linox_volume_format::SECTOR_SIZE];
                let copied =
                    (usize::try_from(length).ok()? - offset).min(linox_volume_format::SECTOR_SIZE);
                if !image_store::read_published_layer(index, offset, &mut sector[..copied])
                    || !volume::BlockDevice::write_sector(
                        backend,
                        usize::try_from(next_sector).ok()?,
                        &sector,
                    )
                {
                    return None;
                }
                offset += copied;
                next_sector = next_sector.checked_add(1)?;
            }
            stored_bytes = stored_bytes.checked_add(length)?;
        }
        if !volume::BlockDevice::flush(backend)
            || !catalog.upsert(
                reference,
                linox_oci_cache::Platform::LinuxAmd64,
                &layers[..layer_count],
            )
            || !catalog.encode(encoded)
            || volume::commit_oci_catalog(backend, encoded).is_err()
        {
            return None;
        }
        Some((layer_count, stored_bytes))
    })
}

#[inline(never)]
fn persist_oci_rootfs(
    device: arch::x86_64::pci::VirtioBlockDevice,
    mapping: arch::x86_64::paging::MmioMapping,
    iommu_profile: arch::x86_64::iommu::DeviceTranslationProfile,
    reference: &[u8],
    encoded: &mut [u8; linox_oci_cache::ENCODED_SIZE],
    slot: usize,
) -> Option<(u64, bool)> {
    let rootfs = image_store::installed_rootfs(slot)?;
    let length = u64::try_from(rootfs.len()).ok()?;
    with_runtime_volume(device, mapping, iommu_profile, |backend| {
        let mut catalog = match volume::recover_oci_catalog(backend, encoded) {
            Ok(Some(record)) => linox_oci_cache::Catalog::decode(&encoded[..record.length])?,
            _ => return None,
        };
        let entry = catalog.find(reference, linox_oci_cache::Platform::LinuxAmd64)?;
        let compressed_length = entry
            .layers()
            .iter()
            .try_fold(0_u64, |total, layer| total.checked_add(layer.length))?;
        if length > compressed_length.saturating_mul(2) {
            return None;
        }
        let digest = crypto::sha256(rootfs);
        if entry
            .rootfs()
            .is_some_and(|cached| cached.digest == digest && cached.length == length)
        {
            return Some((length, false));
        }
        let start_sector = catalog.next_object_sector()?;
        let sectors = length
            .checked_add((linox_volume_format::SECTOR_SIZE - 1) as u64)?
            .checked_div(linox_volume_format::SECTOR_SIZE as u64)?;
        if start_sector.checked_add(sectors)? > backend.capacity_sectors() {
            return None;
        }
        let mut sector_index = start_sector;
        let mut offset = 0_usize;
        while offset < rootfs.len() {
            let mut sector = [0_u8; linox_volume_format::SECTOR_SIZE];
            let copied = (rootfs.len() - offset).min(sector.len());
            sector[..copied].copy_from_slice(&rootfs[offset..offset + copied]);
            if !volume::BlockDevice::write_sector(
                backend,
                usize::try_from(sector_index).ok()?,
                &sector,
            ) {
                return None;
            }
            offset += copied;
            sector_index = sector_index.checked_add(1)?;
        }
        let cached = linox_oci_cache::Rootfs {
            digest,
            start_sector,
            length,
        };
        if !volume::BlockDevice::flush(backend)
            || !catalog.set_rootfs(reference, linox_oci_cache::Platform::LinuxAmd64, cached)
            || !catalog.encode(encoded)
            || volume::commit_oci_catalog(backend, encoded).is_err()
        {
            return None;
        }
        Some((length, true))
    })
}

#[inline(never)]
fn recover_oci_catalog_snapshot<D: volume::BlockDevice>(
    device: &mut D,
    encoded: &mut [u8; linox_oci_cache::ENCODED_SIZE],
) -> (bool, bool) {
    match volume::recover_oci_catalog(device, encoded) {
        Ok(Some(record))
            if linox_oci_cache::Catalog::decode(&encoded[..record.length]).is_some() =>
        {
            (true, false)
        }
        Ok(None) => (false, false),
        _ => (false, true),
    }
}

#[inline(never)]
fn oci_catalog_contains(encoded: &[u8; linox_oci_cache::ENCODED_SIZE], reference: &[u8]) -> bool {
    linox_oci_cache::Catalog::decode(encoded).is_some_and(|catalog| {
        catalog
            .find(reference, linox_oci_cache::Platform::LinuxAmd64)
            .is_some()
    })
}

fn serial_write_elapsed_at(label: &str, started: u64, finished: u64) {
    let Some(frequency) = arch::x86_64::timer::monotonic_frequency() else {
        return;
    };
    if frequency == 0 || finished < started {
        return;
    }
    let milliseconds = u128::from(finished - started)
        .saturating_mul(1_000)
        .checked_div(u128::from(frequency))
        .unwrap_or(0)
        .min(u128::from(u64::MAX)) as u64;
    serial_write(label);
    serial_write_u64(milliseconds);
    serial_write(" ms\r\n");
}

pub(crate) fn serial_write_hex(value: u64) {
    let mut text = *b"0x0000000000000000";
    for (index, digit) in text[2..].iter_mut().enumerate() {
        *digit = b"0123456789abcdef"[((value >> ((15 - index) * 4)) & 0xf) as usize];
    }
    serial_write_raw(&text);
}

pub(crate) fn serial_write_u64(mut value: u64) {
    let mut digits = [0_u8; 20];
    let mut cursor = digits.len();

    if value == 0 {
        serial_write("0");
        return;
    }

    while value != 0 {
        cursor -= 1;
        digits[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
    }

    for digit in &digits[cursor..] {
        // The array contains only ASCII decimal digits.
        let text = [*digit];
        if let Ok(text) = core::str::from_utf8(&text) {
            serial_write(text);
        }
    }
}
