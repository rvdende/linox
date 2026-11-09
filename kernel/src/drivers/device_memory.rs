//! The unsafe floor under the virtio drivers' DMA memory.
//!
//! [`DmaBuffer`] is physically contiguous kernel frames that a device reads
//! and writes by DMA at their physical addresses (the I/O MMU, when it
//! translates, maps them one to one). The frames come from the frame
//! allocator, owned by the kernel, and are scrubbed and returned when the
//! buffer drops. Device registers are `trusted::mmio::Mmio`.
//!
//! Every access is volatile, since the device changes DMA memory behind
//! the compiler's back, and no Rust reference to it is ever formed: a
//! `&[u8]` over memory that a device writes would be undefined behaviour.
//! An access outside the buffer, or misaligned for its width, reads as all
//! ones and writes nothing, as `Mmio` does. The buffer is not `Sync`: a
//! driver that shares one between contexts has to serialize access itself.

use core::cell::Cell;
use core::marker::PhantomData;

use crate::arch::x86_64::paging;
use crate::memory::{self, FrameLease, FrameOwner};
use crate::trusted::mmio::{span, Word};

const PAGE_SIZE: usize = 4096;

/// Physically contiguous, zeroed kernel memory that a device reaches by
/// DMA.
pub(crate) struct DmaBuffer {
    first: FrameLease,
    pages: usize,
    /// Where the kernel reaches the frames: their direct-map alias.
    base: usize,
    _not_sync: PhantomData<Cell<u8>>,
}

impl DmaBuffer {
    /// Takes `pages` contiguous zeroed frames from the frame allocator.
    pub(crate) fn allocate(pages: usize) -> Option<Self> {
        let (first, pages) = memory::allocate_contiguous_extent(FrameOwner::KERNEL, pages)?;
        // The allocator only hands out frames inside the direct map.
        let Some(base) = paging::direct_map_range_address(first.address(), pages * PAGE_SIZE)
        else {
            let _ = memory::scrub_and_release_contiguous_extent(FrameOwner::KERNEL, first, pages);
            return None;
        };
        Some(Self {
            first,
            pages,
            base,
            _not_sync: PhantomData,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.pages * PAGE_SIZE
    }

    /// The address the device uses for byte `offset` of the buffer.
    pub(crate) fn device_address(&self, offset: usize) -> u64 {
        self.first.address() + offset.min(self.len()) as u64
    }

    /// The buffer's physical range (start, length), for I/O MMU admission.
    pub(crate) fn region(&self) -> (u64, u64) {
        (self.first.address(), self.len() as u64)
    }

    /// The kernel virtual address of the first byte. Writing through it is
    /// the caller's responsibility; the buffer itself stays valid until it
    /// drops.
    pub(crate) fn kernel_address(&self) -> usize {
        self.base
    }

    pub(crate) fn read<T: Word>(&self, offset: usize) -> T {
        let size = core::mem::size_of::<T>();
        match span(self.base, self.len(), offset, size, size) {
            // SAFETY: the direct map covers the whole extent, which this
            // buffer owns until it drops, and span keeps the access inside.
            Some(address) => unsafe { (address as *const T).read_volatile() },
            None => T::ONES,
        }
    }

    pub(crate) fn write<T: Word>(&self, offset: usize, value: T) {
        let size = core::mem::size_of::<T>();
        if let Some(address) = span(self.base, self.len(), offset, size, size) {
            // SAFETY: as for read.
            unsafe { (address as *mut T).write_volatile(value) };
        }
    }

    /// Copies `bytes` to `offset`, or nothing if they do not fit.
    pub(crate) fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        if let Some(address) = span(self.base, self.len(), offset, bytes.len(), 1) {
            for (index, byte) in bytes.iter().enumerate() {
                // SAFETY: as for read; every byte lies inside the span.
                unsafe { (address as *mut u8).add(index).write_volatile(*byte) };
            }
        }
    }

    /// Fills `bytes` from `offset`, with ones if they do not fit.
    pub(crate) fn read_bytes(&self, offset: usize, bytes: &mut [u8]) {
        match span(self.base, self.len(), offset, bytes.len(), 1) {
            Some(address) => {
                for (index, byte) in bytes.iter_mut().enumerate() {
                    // SAFETY: as for read; every byte lies inside the span.
                    *byte = unsafe { (address as *const u8).add(index).read_volatile() };
                }
            }
            None => bytes.fill(u8::MAX),
        }
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // The owner stops the device before its buffers drop, so nothing
        // reaches these frames once they are back in the allocator.
        let _ =
            memory::scrub_and_release_contiguous_extent(FrameOwner::KERNEL, self.first, self.pages);
    }
}
