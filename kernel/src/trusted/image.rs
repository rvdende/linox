//! Images the kernel reads in place as byte slices that live as long as
//! the kernel uses them: the boot loader's handoff images and the root
//! filesystem images domains are given.
//!
//! [`BootImage`]: an image the boot loader placed in memory and handed
//! over (the signed manifest, the control-plane bundle, the controller
//! runtime, the root archive, the Rust root filesystem, the loaded kernel
//! image). Made once, at kernel entry, from the handoff record
//! ([`BootImage::from_loader`], whose caller vouches for the pointer);
//! after that it is a plain `&'static [u8]`. The memory is the loader's
//! (its data or the loaded image), which the frame allocator never hands
//! out and the kernel never writes: `lib.rs` checks each range is mapped
//! read-only before going on. The loader's pointers are identity-mapped,
//! which only the firmware's and the kernel's own page tables are; a view
//! used later, when a process's page tables may be loaded, goes through
//! the kernel's direct map instead ([`BootImage::direct_mapped`]).
//!
//! [`ImageFrames`]: a private run of kernel frames an image is copied
//! into (the boot archive's published copy), read as one slice.
//!
//! [`PublishedImage`]: a root filesystem image on the kernel heap,
//! published for domains to read in place. Its bytes are handed out as
//! `&'static [u8]` (the published root filesystem's entries borrow them,
//! `published_rootfs`), so it is freed only through
//! [`PublishedImage::retire`], whose caller vouches that no domain that
//! could hold such a borrow still runs.

use alloc::vec::Vec;

use crate::arch::x86_64::paging;
use crate::memory::{self, FrameLease, FrameOwner};
use crate::trusted::frame::FRAME_SIZE;

/// A run of `N` contiguous kernel frames holding an image, owned by this
/// value and read and written as one byte slice through the direct map.
/// The frame allocator hands the run to this value alone (the leases are
/// private and the value is neither `Copy` nor `Clone`), so a borrow of
/// the value is a borrow of the frames.
pub(crate) struct ImageFrames<const N: usize> {
    frames: [FrameLease; N],
    base: usize,
}

impl<const N: usize> ImageFrames<N> {
    /// Zeroed, contiguous, direct-mapped kernel frames, if there are some.
    pub(crate) fn allocate() -> Option<Self> {
        let frames = memory::allocate_contiguous_frames::<N>(FrameOwner::KERNEL)?;
        let contiguous = N != 0
            && frames.iter().enumerate().all(|(index, frame)| {
                frame.address() == frames[0].address() + (index * FRAME_SIZE) as u64
            });
        let base = paging::direct_map_range_address(frames[0].address(), N * FRAME_SIZE)
            .filter(|_| contiguous);
        let Some(base) = base else {
            let _ = memory::release_frames(FrameOwner::KERNEL, frames);
            return None;
        };
        Some(Self { frames, base })
    }

    pub(crate) fn frames(&self) -> &[FrameLease; N] {
        &self.frames
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: the run is `N` contiguous frames inside the direct map
        // (checked by `allocate`), owned by this value alone until
        // `release`, and the shared borrow of `self` excludes writers.
        unsafe { core::slice::from_raw_parts(self.base as *const u8, N * FRAME_SIZE) }
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as for `bytes`; the unique borrow of `self` makes this
        // the only view.
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, N * FRAME_SIZE) }
    }

    /// Clears the frames and gives them back.
    pub(crate) fn release(mut self) -> bool {
        self.bytes_mut().fill(0);
        let scrubbed = self.bytes().iter().all(|byte| *byte == 0);
        scrubbed && memory::release_frames(FrameOwner::KERNEL, self.frames)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BootImage {
    bytes: &'static [u8],
}

impl BootImage {
    /// The `length` bytes at `pointer` that the boot loader handed over,
    /// if the range is non-empty and lies inside the identity map the
    /// firmware and the kernel's page tables share.
    ///
    /// # Safety
    ///
    /// `pointer..pointer + length` must be an image the boot loader
    /// handed over in the boot information: memory the frame allocator
    /// never takes and nothing writes for the rest of the kernel's life.
    pub(crate) unsafe fn from_loader(pointer: *const u8, length: usize) -> Option<Self> {
        let start = pointer as usize;
        let end = start.checked_add(length)?;
        if pointer.is_null() || length == 0 || end > paging::INITIAL_IDENTITY_LIMIT {
            return None;
        }
        // SAFETY: the caller's contract: the range is the loader's
        // immutable, never reallocated image, identity-mapped (checked
        // against the identity map's bounds above).
        Some(Self {
            bytes: unsafe { core::slice::from_raw_parts(pointer, length) },
        })
    }

    pub(crate) fn bytes(self) -> &'static [u8] {
        self.bytes
    }

    /// The same image through the kernel's direct map, which every address
    /// space shares. Only for use once the kernel's page tables (and so
    /// the direct map) are installed; before, the alias is not mapped.
    pub(crate) fn direct_mapped(self) -> Option<Self> {
        let physical = self.bytes.as_ptr() as u64;
        let address = paging::direct_map_range_address(physical, self.bytes.len())?;
        // SAFETY: the direct map maps the same physical bytes (an identity
        // address is its physical address), which the module invariant
        // keeps allocated and unchanged for the kernel's lifetime.
        Some(Self {
            bytes: unsafe { core::slice::from_raw_parts(address as *const u8, self.bytes.len()) },
        })
    }
}

/// A root filesystem image on the kernel heap, read in place by the
/// domains it is installed for. It owns the allocation, which it keeps as
/// a raw pointer (a vector it took apart) so the shared views it hands
/// out never alias a unique reference.
pub(crate) struct PublishedImage {
    pointer: core::ptr::NonNull<u8>,
    length: usize,
    capacity: usize,
}

// SAFETY: a PublishedImage owns its heap allocation like the vector it
// was made from, and only ever reads it through shared views.
unsafe impl Send for PublishedImage {}

impl PublishedImage {
    /// Publishes `image`: its bytes are never written again and stay
    /// allocated until [`retire`](Self::retire).
    pub(crate) fn publish(image: Vec<u8>) -> Self {
        let mut image = core::mem::ManuallyDrop::new(image);
        Self {
            pointer: core::ptr::NonNull::new(image.as_mut_ptr())
                .unwrap_or(core::ptr::NonNull::dangling()),
            length: image.len(),
            capacity: image.capacity(),
        }
    }

    pub(crate) fn bytes(&self) -> &'static [u8] {
        // SAFETY: the allocation holds `length` initialized bytes, nothing
        // writes them after `publish`, and it stays allocated until
        // `retire`, whose caller vouches that no view is still in use.
        unsafe { core::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
    }

    /// Frees the image (the heap scrubs large allocations as it frees
    /// them).
    ///
    /// # Safety
    ///
    /// No view from [`bytes`](Self::bytes) may be in use or used again:
    /// every domain the image was installed for has been torn down (its
    /// processes, which hold the root filesystem's entries, are gone) and
    /// the root filesystem was uninstalled from each.
    pub(crate) unsafe fn retire(self) {
        // SAFETY: `publish` took apart a vector of this pointer, length and
        // capacity, which this value alone owns, and the caller vouches
        // that no view of it remains.
        drop(unsafe { Vec::from_raw_parts(self.pointer.as_ptr(), self.length, self.capacity) });
    }
}
