#![forbid(unsafe_code)]
//! The kernel heap behind `alloc`: memory for kernel objects whose number or
//! size is only known at run time, such as tasks, kernel stacks and tables
//! that grow.
//!
//! Requests of up to 2016 bytes come from slabs (`linox_slab`): a frame per
//! slab, one size class each, as in Linux's slab allocators. A slab whose
//! objects are all freed goes back to the frame allocator, but for a few
//! kept for the next slab of any class (`linox_slab::SPARE_EMPTY`), so a
//! burst of kernel objects leaves no memory behind once it is over.
//! Larger requests take a run of contiguous frames of their own and return
//! it to the frame allocator when freed. All heap memory is reached through
//! the direct map. The allocator itself is `trusted::heap`; this module
//! keeps what is safe around it.
//!
//! The heap lock ranks just below the frame allocator's, because a refill
//! takes frames while holding it. So the heap must not be used while holding
//! the frame allocator lock or any lock ranked above it.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::memory::{self, FrameOwner};
use crate::trusted::heap::{heap_frames, slab_frames};

const PAGE_SIZE: usize = 4096;

/// The kernel's frames outside the heap. Checks that a lifecycle gives back
/// what it took compare this.
pub(crate) fn kernel_frames_outside_heap() -> Option<usize> {
    memory::owner_live_frame_count(FrameOwner::KERNEL)?.checked_sub(heap_frames())
}

/// The bytes the heap's slabs hold.
pub(crate) fn slab_bytes() -> usize {
    slab_frames() * PAGE_SIZE
}

/// A zeroed page of bytes on the heap, or `None` without memory. It is a
/// frame run of its own, so freeing it scrubs the frame and gives it back.
pub(crate) fn zeroed_page() -> Option<Box<[u8; PAGE_SIZE]>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(PAGE_SIZE).ok()?;
    bytes.resize(PAGE_SIZE, 0);
    bytes.into_boxed_slice().try_into().ok()
}

/// `N` copies of `value` in one heap allocation, built in place (only
/// `value` itself is ever on the stack), or `None` without memory.
pub(crate) fn try_boxed_array<T: Clone, const N: usize>(value: T) -> Option<Box<[T; N]>> {
    let mut values = Vec::new();
    values.try_reserve_exact(N).ok()?;
    values.resize(N, value);
    values.into_boxed_slice().try_into().ok()
}

/// Exercises both allocation paths at boot, so a broken heap fails here
/// rather than in whatever first uses it.
pub(crate) fn verify() -> bool {
    let small: Vec<Box<u64>> = (0..600_u64).map(Box::new).collect();
    let small_intact = small.iter().map(|value| **value).eq(0..600);
    let mut large: Vec<u8> = Vec::with_capacity(3 * PAGE_SIZE + 1);
    large.resize(large.capacity(), 0xa5);
    let large_intact = large.iter().all(|byte| *byte == 0xa5);
    drop(small);
    drop(large);
    let reused: Vec<Box<u64>> = (0..600_u64).map(Box::new).collect();
    small_intact && large_intact && reused.iter().map(|value| **value).eq(0..600)
}
