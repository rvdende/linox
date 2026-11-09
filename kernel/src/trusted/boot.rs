//! The kernel's entry from the boot loader, and the boot information it
//! hands over, as a value safe code can use (docs/FRAMEKERNEL.md §4.3 H).
//!
//! [`kernel_entry`] is the one function the loader calls (`boot/efi`), after
//! `ExitBootServices`, with a pointer to its [`BootInfo`]. It switches to the
//! kernel's own boot stack ([`KERNEL_STACK`], with a guard page below and
//! above) and calls `kernel_main` with the boot information as a
//! [`Handoff`], or the reason it is unusable.
//!
//! The audited facts: the loader's contract (the `# Safety` section of
//! `kernel_entry`) that the pointer names a `BootInfo` that stays valid and
//! unchanged for the kernel's lifetime, with a memory map that stays
//! allocated and firmware runtime services at `reset_system`; and the
//! stack switch below. A `Handoff` exists only for a `BootInfo` that passed
//! the loader's contract and the magic/version/size check, so its methods
//! may read the memory map and call the firmware.
//!
//! [`for_each_memory_descriptor`] reads the same memory map for the frame
//! allocator (`memory.rs`), which takes the `BootInfo` by reference; only
//! `memory.rs` may call it (`tools/architecture/check-kernel-unsafe.sh`),
//! after `kernel_main` checked the map's shape (non-null, a whole number of
//! descriptors of at least `UefiMemoryDescriptor`'s size), with the map
//! mapped and unchanged for the boot.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ops::Deref;

use super::image::BootImage;
use crate::{BootInfo, UefiMemoryDescriptor, BOOT_INFO_MAGIC, BOOT_INFO_VERSION};

const PAGE_SIZE: usize = 4096;
/// The boot stack: Linux processes run nested inside the system calls of
/// the processes that started them, all on this stack, so its depth bounds
/// how deep a process tree (a shell running a compositor running a terminal
/// running a shell) can be. 512 KiB overflowed under the all-Rust desktop and
/// a cargo build.
pub(crate) const KERNEL_STACK_SIZE: usize = 2 * 1024 * 1024;
const KERNEL_STACK_STORAGE_SIZE: usize = PAGE_SIZE + KERNEL_STACK_SIZE + PAGE_SIZE;
/// Offset of the stack's top (the start of the upper guard page).
pub(crate) const KERNEL_STACK_TOP_OFFSET: usize = PAGE_SIZE + KERNEL_STACK_SIZE;

/// The boot stack's storage: a guard page, the stack, a guard page. Only
/// the stack switch below uses it, as the processor's stack; Rust code
/// never reads or writes it as data, and only its address is taken.
#[repr(C, align(4096))]
struct KernelStack(UnsafeCell<[u8; KERNEL_STACK_STORAGE_SIZE]>);

// SAFETY: no Rust code reaches the bytes (see above); the stack is the
// bootstrap processor's alone.
unsafe impl Sync for KernelStack {}

static KERNEL_STACK: KernelStack = KernelStack(UnsafeCell::new([0; KERNEL_STACK_STORAGE_SIZE]));

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
    kernel_main = sym enter_kernel_main,
);

extern "sysv64" {
    fn linox_kernel_stack_entry(boot_info: *const BootInfo) -> !;
}

/// Takes control after UEFI boot services have ended.
///
/// # Safety
///
/// `boot_info` must identify a valid, immutable `BootInfo`. Its memory-map
/// buffer must remain allocated for the lifetime of the kernel, and
/// `reset_system` must be the firmware's runtime service.
/// The boot inputs (manifest, bundle, controller runtime, root images,
/// the loaded image) must be images the loader placed in memory the frame
/// allocator never takes and nothing writes for the kernel's lifetime.
pub unsafe extern "sysv64" fn kernel_entry(boot_info: *const BootInfo) -> ! {
    // SAFETY: the stub only switches to the boot stack, which nothing else
    // uses, and passes `boot_info` on unchanged; the caller's contract
    // carries over to `enter_kernel_main`.
    unsafe { linox_kernel_stack_entry(boot_info) }
}

/// The firmware's `ResetSystem` runtime service, as `BootInfo` carries it.
pub type ResetSystem = unsafe extern "efiapi" fn(u32, usize, usize, *const c_void);

/// Why the loader's boot information cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffError {
    Missing,
    Incompatible,
}

extern "sysv64" fn enter_kernel_main(boot_info: *const BootInfo) -> ! {
    // SAFETY: `kernel_entry`'s contract: a non-null pointer names a valid
    // `BootInfo` that lives, unchanged, as long as the kernel.
    let boot_info = unsafe { boot_info.as_ref() };
    let handoff = match boot_info {
        None => Err(HandoffError::Missing),
        Some(boot_info)
            if boot_info.magic != BOOT_INFO_MAGIC
                || boot_info.version != BOOT_INFO_VERSION
                || boot_info.size < size_of::<BootInfo>() as u32 =>
        {
            Err(HandoffError::Incompatible)
        }
        Some(boot_info) => Ok(Handoff(boot_info)),
    };
    crate::kernel_main(handoff)
}

/// Whether `address` lies in the boot stack itself (not its guard pages).
pub(crate) fn kernel_stack_contains(address: usize) -> bool {
    let start = kernel_stack_base() + PAGE_SIZE;
    (start..start + KERNEL_STACK_SIZE).contains(&address)
}

/// The boot stack's storage: its lower guard page's address.
pub(crate) fn kernel_stack_base() -> usize {
    KERNEL_STACK.0.get() as usize
}

/// The loader's boot information, checked and kept for the kernel's
/// lifetime (see the module comment).
#[derive(Clone, Copy)]
pub(crate) struct Handoff(&'static BootInfo);

impl Deref for Handoff {
    type Target = BootInfo;

    fn deref(&self) -> &BootInfo {
        self.0
    }
}

impl Handoff {
    /// The descriptor count of the firmware's memory map, or 0 if the map
    /// is malformed (no address, a stride shorter than a descriptor, a size
    /// that is not a whole number of strides).
    pub(crate) fn memory_descriptor_count(self) -> usize {
        let info = self.0;
        if info.memory_map.is_null()
            || info.memory_descriptor_size < size_of::<UefiMemoryDescriptor>()
            || !info
                .memory_map_size
                .is_multiple_of(info.memory_descriptor_size)
        {
            return 0;
        }
        info.memory_map_size / info.memory_descriptor_size
    }

    /// Descriptor `index` of the firmware's memory map.
    pub(crate) fn memory_descriptor(self, index: usize) -> Option<UefiMemoryDescriptor> {
        if index >= self.memory_descriptor_count() {
            return None;
        }
        let offset = index.checked_mul(self.0.memory_descriptor_size)?;
        // SAFETY: the loader's contract keeps `memory_map_size` bytes at
        // `memory_map` allocated and unchanged; the count check puts a whole
        // descriptor (the stride is at least its size) inside them, and the
        // read copies it out unaligned.
        Some(unsafe {
            self.0
                .memory_map
                .add(offset)
                .cast::<UefiMemoryDescriptor>()
                .read_unaligned()
        })
    }

    /// Every descriptor of the firmware's memory map, in order.
    pub(crate) fn memory_descriptors(self) -> impl Iterator<Item = UefiMemoryDescriptor> {
        (0..self.memory_descriptor_count()).filter_map(move |index| self.memory_descriptor(index))
    }

    /// The image the loader handed over at `start`, `length` bytes long, as
    /// a `trusted::image::BootImage`.
    fn image(start: *const u8, length: usize) -> Option<BootImage> {
        // SAFETY: the loader's contract (`kernel_entry`): a boot input's
        // pointer and size describe an image it loaded into memory the
        // frame allocator never takes and nothing writes for the rest of
        // the kernel's life, which is `BootImage::from_loader`'s contract.
        unsafe { BootImage::from_loader(start, length) }
    }

    /// The loaded kernel image.
    pub(crate) fn loaded_image(self) -> Option<BootImage> {
        Self::image(self.0.image_base, self.0.image_size)
    }

    /// The signed boot manifest.
    pub(crate) fn manifest(self) -> Option<BootImage> {
        Self::image(self.0.manifest, self.0.manifest_size)
    }

    /// The control-plane bundle the manifest names.
    pub(crate) fn control_plane_bundle(self) -> Option<BootImage> {
        Self::image(
            self.0.control_plane_bundle,
            self.0.control_plane_bundle_size,
        )
    }

    /// The controller's runtime image.
    pub(crate) fn controller_runtime(self) -> Option<BootImage> {
        Self::image(self.0.controller_runtime, self.0.controller_runtime_size)
    }

    /// The initial root archive.
    pub(crate) fn root_image(self) -> Option<BootImage> {
        Self::image(self.0.root_image, self.0.root_image_size)
    }

    /// The built-in Rust root filesystem.
    pub(crate) fn oci_rootfs(self) -> Option<BootImage> {
        Self::image(self.0.oci_rootfs, self.0.oci_rootfs_size)
    }

    /// Asks the firmware to reset the machine (`ResetSystem` with `kind`
    /// and `status`); returns only if it does not.
    pub(crate) fn reset_system(self, kind: u32, status: usize) {
        // SAFETY: the loader's contract makes `reset_system` the firmware's
        // runtime service; the caller runs it on page tables that map the
        // firmware's runtime regions (bring-up runs on the firmware's own,
        // and the kernel's map all memory below 4 GiB, where they lie). The
        // null data pointer with size 0 is the call's documented form.
        unsafe { (self.0.reset_system)(kind, status, 0, core::ptr::null::<c_void>()) };
    }
}

/// Calls `visit` with a copy of each descriptor in the memory map of
/// `boot_info`, the loader's handoff.
pub(crate) fn for_each_memory_descriptor(
    boot_info: &BootInfo,
    mut visit: impl FnMut(UefiMemoryDescriptor),
) {
    let stride = boot_info.memory_descriptor_size;
    if boot_info.memory_map.is_null() || stride < size_of::<UefiMemoryDescriptor>() {
        return;
    }
    for index in 0..boot_info.memory_map_size / stride {
        // SAFETY: the module invariant: descriptor `index` lies inside the
        // map kernel_main checked, which stays mapped and unchanged; the
        // read is unaligned because the stride need not be a multiple of
        // the descriptor's alignment.
        visit(unsafe {
            core::ptr::read_unaligned(
                boot_info
                    .memory_map
                    .add(index * stride)
                    .cast::<UefiMemoryDescriptor>(),
            )
        });
    }
}
