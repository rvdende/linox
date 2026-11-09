//! The boot handoff: what the loader passes the kernel in `BootInfo`.
//!
//! [`for_each_memory_descriptor`] reads the firmware's memory map, which
//! the loader copied into memory it keeps for the kernel and describes by
//! a pointer, a byte size and a descriptor stride.
//!
//! Who may call it: the code that builds the kernel's view of memory at
//! boot (`memory.rs`), with the `BootInfo` the loader handed `kernel_main`;
//! `tools/architecture/check-kernel-unsafe.sh` enforces that.
//!
//! The invariant the `unsafe` block relies on: `kernel_main` checked the
//! loader's `BootInfo` (magic, version, size) and its memory map (non-null,
//! a whole number of descriptors of at least `UefiMemoryDescriptor`'s size)
//! before anything calls this, and the loader's map stays mapped and
//! unchanged for the boot.

use crate::{BootInfo, UefiMemoryDescriptor};

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
