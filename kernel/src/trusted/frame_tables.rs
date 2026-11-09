//! The frame allocator's per-frame tables, carved out of RAM at boot.
//!
//! `memory.rs` keeps, for every frame of RAM, an 8-byte metadata word
//! (read without the allocator's lock, so atomic), a bit in a free bitmap
//! and a 2-byte memory cgroup charge. The tables are sized to the installed
//! memory, so they cannot be statics: [`FrameTables::carve`] takes them from
//! the top of the largest usable range of the firmware's memory map, zeroes
//! them, and hands them out as `'static` slices.
//!
//! Who may call `carve`: only the frame allocator (`memory.rs`), once per
//! boot, with a range it then removes from the frames it hands out;
//! `tools/architecture/check-kernel-unsafe.sh` enforces that.
//!
//! The invariant the `unsafe` blocks rely on: the range is usable RAM
//! (conventional or boot-services memory the firmware no longer uses),
//! inside the direct map (checked), that nothing else ever reaches: the
//! allocator never hands its frames out, and the carve happens once
//! (checked), so the slices are the only access for the kernel's life.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::paging;

const PAGE_SIZE: u64 = 4096;

static CARVED: AtomicBool = AtomicBool::new(false);

/// The tables for `frames` frames, from frame 0.
pub(crate) struct FrameTables {
    /// Each frame's metadata word.
    pub(crate) metadata: &'static [AtomicU64],
    /// One bit per frame: set when the frame is free.
    pub(crate) free: &'static mut [u64],
    /// Each frame's memory cgroup charge.
    pub(crate) charges: &'static mut [u16],
}

/// The byte sizes of the three tables for `frames` frames.
const fn sizes(frames: usize) -> (u64, u64, u64) {
    (
        frames as u64 * 8,
        frames.div_ceil(64) as u64 * 8,
        frames as u64 * 2,
    )
}

impl FrameTables {
    /// The bytes the tables for `frames` frames take, in whole pages.
    pub(crate) const fn bytes(frames: usize) -> u64 {
        let (metadata, free, charges) = sizes(frames);
        (metadata + free + charges).div_ceil(PAGE_SIZE) * PAGE_SIZE
    }

    /// Zeroed tables for `frames` frames in the [`bytes`](Self::bytes)
    /// bytes of RAM at `physical`, unless the range is not page-aligned
    /// and inside the direct map, or tables were carved already. Only the
    /// frame allocator calls this (see the module comment).
    pub(crate) fn carve(physical: u64, frames: usize) -> Option<Self> {
        let length = usize::try_from(Self::bytes(frames)).ok()?;
        if !physical.is_multiple_of(PAGE_SIZE) {
            return None;
        }
        let base = paging::direct_map_range_address(physical, length)?;
        if CARVED.swap(true, Ordering::AcqRel) {
            return None;
        }
        let (metadata_bytes, free_bytes, _) = sizes(frames);
        let free_base = base + metadata_bytes as usize;
        let charges_base = free_base + free_bytes as usize;
        // SAFETY: the module invariant: `length` bytes of RAM at `base` that
        // nothing else reaches. Zeroing them makes every element of the
        // three tables below valid (zero is a valid AtomicU64, u64 and u16).
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, length) };
        // SAFETY: the module invariant, for three disjoint ranges inside
        // the zeroed `length` bytes (the sizes add up to at most `length`),
        // each aligned for its element type: `base` is page-aligned and the
        // first two tables are whole 8-byte words. The carve happens once,
        // so these are the only references to the range.
        let tables = unsafe {
            Self {
                metadata: core::slice::from_raw_parts(base as *const AtomicU64, frames),
                free: core::slice::from_raw_parts_mut(free_base as *mut u64, frames.div_ceil(64)),
                charges: core::slice::from_raw_parts_mut(charges_base as *mut u16, frames),
            }
        };
        Some(tables)
    }
}
