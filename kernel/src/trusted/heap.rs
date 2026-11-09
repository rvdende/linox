//! The kernel heap's allocator core: the `GlobalAlloc` behind `alloc`, its
//! slabs and the frames they and large allocations take (`crate::heap`
//! describes the design and keeps the safe helpers around it).
//!
//! Requests of up to 2016 bytes come from slabs (`linox_slab`), each a
//! kernel frame reached through the direct map; larger ones take a run of
//! contiguous kernel frames of their own. The invariants the `unsafe` code
//! relies on:
//! - every frame [`KernelFrames`] gives the slabs is a whole kernel frame
//!   from the frame allocator, lent to this heap alone until the slabs give
//!   it back, and reached through the direct map, which maps it writable
//!   and page-aligned;
//! - a frame run for a large allocation is the same, `layout.size()`
//!   rounded up to whole frames, owned by the allocation until it is freed;
//! - `dealloc` gets back only what `alloc` handed out, with the same
//!   layout (`GlobalAlloc`'s contract on its callers), so the size class
//!   or frame count it computes is the one the allocation was made with.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use linox_slab::{Frames, Slabs};

use crate::arch::x86_64::paging;
use crate::memory::{self, FrameOwner};
use crate::sync::{IrqSpinLock, LockRank};

const PAGE_SIZE: usize = 4096;

const _: () = assert!(linox_slab::FRAME_SIZE == PAGE_SIZE);

/// Frames the heap holds: its slabs (kept empty ones included) and the
/// frame runs of live large allocations.
static HEAP_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// Frames the heap's slabs hold (/proc/meminfo's Slab).
static SLAB_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// The frames the heap holds now.
pub(crate) fn heap_frames() -> usize {
    HEAP_FRAMES.load(Ordering::Acquire)
}

/// The frames the heap's slabs hold now.
pub(crate) fn slab_frames() -> usize {
    SLAB_FRAMES.load(Ordering::Acquire)
}

struct KernelHeap {
    slabs: IrqSpinLock<Slabs>,
}

#[global_allocator]
static KERNEL_HEAP: KernelHeap = KernelHeap {
    slabs: IrqSpinLock::new(LockRank::KERNEL_HEAP, Slabs::new()),
};

/// The slab class serving `layout`, or `None` for a frame-run allocation.
fn size_class(layout: Layout) -> Option<usize> {
    linox_slab::class_for(layout.size(), layout.align())
}

/// Slab frames from the frame allocator, through the direct map.
struct KernelFrames;

impl Frames for KernelFrames {
    fn allocate(&mut self) -> Option<usize> {
        let [frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
        let address = frame.direct_map_address()?;
        HEAP_FRAMES.fetch_add(1, Ordering::AcqRel);
        SLAB_FRAMES.fetch_add(1, Ordering::AcqRel);
        Some(address)
    }

    fn release(&mut self, frame: usize) {
        let released = paging::direct_map_physical(frame)
            .and_then(|physical| memory::live_frame_lease(FrameOwner::KERNEL, physical))
            .is_some_and(|lease| memory::scrub_and_release_frames(FrameOwner::KERNEL, &[lease]));
        if !released {
            crate::kernel_fail("linox: kernel heap released a slab it never took\r\n");
        }
        HEAP_FRAMES.fetch_sub(1, Ordering::AcqRel);
        SLAB_FRAMES.fetch_sub(1, Ordering::AcqRel);
    }
}

impl KernelHeap {
    fn allocate_object(&self, class: usize) -> *mut u8 {
        let mut slabs = self.slabs.lock();
        // SAFETY: KernelFrames gives whole kernel frames through the direct
        // map, page aligned, writable and used by nothing else until the
        // slabs release them (the module invariant).
        unsafe { slabs.allocate(class, &mut KernelFrames) }.unwrap_or(ptr::null_mut())
    }

    fn free_object(&self, class: usize, object: *mut u8) {
        if paging::direct_map_physical(object as usize).is_none() {
            crate::kernel_fail("linox: kernel heap free of a pointer it never allocated\r\n");
        }
        let mut slabs = self.slabs.lock();
        // SAFETY: as in allocate_object; `dealloc`'s caller gives back an
        // object of this class (the module invariant) that it no longer
        // uses.
        if unsafe { slabs.free(class, object, &mut KernelFrames) }.is_err() {
            crate::kernel_fail("linox: kernel heap free of a pointer it never allocated\r\n");
        }
    }
}

fn page_count(layout: Layout) -> usize {
    layout.size().div_ceil(PAGE_SIZE)
}

/// Allocates zeroed contiguous frames for a request too large for a slab.
fn allocate_pages(layout: Layout) -> *mut u8 {
    if layout.align() > PAGE_SIZE {
        return ptr::null_mut();
    }
    let count = page_count(layout);
    memory::allocate_contiguous_extent(FrameOwner::KERNEL, count)
        .and_then(|(first, count)| {
            HEAP_FRAMES.fetch_add(count, Ordering::AcqRel);
            paging::direct_map_range_address(first.address(), count * PAGE_SIZE)
        })
        .map_or(ptr::null_mut(), |address| address as *mut u8)
}

fn free_pages(pointer: *mut u8, layout: Layout) {
    let released = paging::direct_map_physical(pointer as usize)
        .and_then(|physical| memory::live_frame_lease(FrameOwner::KERNEL, physical))
        .is_some_and(|first| {
            memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                first,
                page_count(layout),
            )
        });
    if !released {
        crate::kernel_fail("linox: kernel heap free of frames it never allocated\r\n");
    }
    HEAP_FRAMES.fetch_sub(page_count(layout), Ordering::AcqRel);
}

// SAFETY: slab objects are distinct, aligned to their class size (which
// covers the layout's size and alignment) and handed out once until freed;
// frame runs are page aligned and owned by the kernel until freed (the
// module invariant).
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match size_class(layout) {
            Some(class) => self.allocate_object(class),
            None => allocate_pages(layout),
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        match size_class(layout) {
            Some(class) => self.free_object(class, pointer),
            None => free_pages(pointer, layout),
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        match size_class(layout) {
            Some(class) => {
                let object = self.allocate_object(class);
                if !object.is_null() {
                    // SAFETY: the object is at least `layout.size()` bytes,
                    // handed to no one else yet.
                    unsafe { ptr::write_bytes(object, 0, layout.size()) };
                }
                object
            }
            // The frame allocator hands out zeroed frames.
            None => allocate_pages(layout),
        }
    }
}
