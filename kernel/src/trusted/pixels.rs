//! A display surface the console and /dev/fb0 draw into.
//!
//! [`PixelBuffer`] is a window of display memory written pixel by pixel
//! (volatile 32-bit stores) and copied in and out by byte ranges, every
//! access checked against the window: one out of range writes nothing and
//! reads nothing. No Rust reference into the surface is ever formed, since
//! the display hardware, a host GPU or a program that mapped /dev/fb0 may
//! read or write it at any time.
//!
//! Who may make one:
//! - the boot path, for the firmware's framebuffer through the firmware's
//!   identity map ([`PixelBuffer::firmware`], checked by walking its page
//!   tables); only `lib.rs` and `bringup/` call it, which
//!   `tools/architecture/check-kernel-unsafe.sh` enforces;
//! - anyone holding the kernel's write-combining window of that
//!   framebuffer ([`PixelBuffer::window`]), which only `paging.rs` makes;
//! - a `trusted::dma::DmaBuffer` given to the display for good (a
//!   virtio-gpu surface), whose frames are then never returned.
//!
//! The invariant the `unsafe` blocks rely on: `base..base + length` is
//! mapped display memory (a framebuffer, or frames kept for the display)
//! for the rest of the kernel's life, reached only by raw-pointer copies
//! and volatile stores. A buffer is `Copy`: copies alias the same surface,
//! which every user of it shares with the hardware anyway.

use crate::arch::x86_64::paging::FramebufferWindow;

/// A window of display memory.
#[derive(Clone, Copy)]
pub(crate) struct PixelBuffer {
    base: usize,
    length: usize,
}

impl PixelBuffer {
    /// A buffer that covers nothing: every access is out of range.
    pub(crate) const EMPTY: Self = Self { base: 0, length: 0 };

    /// The `length` bytes of the firmware's framebuffer at `physical`,
    /// reached through the firmware's identity map, if the firmware maps
    /// them writable. Only the boot path calls this (see the module
    /// comment).
    pub(crate) fn firmware(physical: u64, length: usize) -> Option<Self> {
        let last = physical.checked_add(u64::try_from(length).ok()?.checked_sub(1)?)?;
        let base = usize::try_from(physical).ok().filter(|base| *base != 0)?;
        (crate::bringup::firmware_maps(physical, true) && crate::bringup::firmware_maps(last, true))
            .then_some(Self { base, length })
    }

    /// The framebuffer the kernel's write-combining window maps.
    pub(crate) fn window(window: FramebufferWindow) -> Self {
        Self {
            base: window.address(),
            length: window.len(),
        }
    }

    /// Frames a `DmaBuffer` keeps for the display, at their direct-map
    /// alias `base`.
    pub(super) fn kept_dma(base: usize, length: usize) -> Self {
        Self { base, length }
    }

    pub(crate) fn len(&self) -> usize {
        self.length
    }

    /// The address of `length` bytes at `offset`, if they lie inside the
    /// buffer.
    fn at(&self, offset: usize, length: usize) -> Option<usize> {
        (self.base != 0 && offset.checked_add(length)? <= self.length).then(|| self.base + offset)
    }

    /// Stores pixel `index`: the 32-bit word at byte `index * 4`.
    pub(crate) fn write_pixel(&self, index: usize, value: u32) {
        let Some(address) = index.checked_mul(4).and_then(|offset| self.at(offset, 4)) else {
            return;
        };
        if address.is_multiple_of(4) {
            // SAFETY: the module invariant, for the four aligned bytes `at`
            // checked to lie inside the buffer.
            unsafe { (address as *mut u32).write_volatile(value) };
        }
    }

    /// Copies `bytes` to byte `offset`, or as many as fit, and returns how
    /// many it copied.
    pub(crate) fn copy_from(&self, offset: usize, bytes: &[u8]) -> usize {
        let length = bytes.len().min(self.length.saturating_sub(offset));
        let Some(address) = self.at(offset, length).filter(|_| length != 0) else {
            return 0;
        };
        // SAFETY: the module invariant, for the range `at` checked; `bytes`
        // is the caller's own buffer, which no surface overlaps.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, length) };
        length
    }

    /// Copies from byte `offset` into `bytes`, as many as the buffer holds,
    /// and returns how many it copied.
    pub(crate) fn copy_to(&self, offset: usize, bytes: &mut [u8]) -> usize {
        let length = bytes.len().min(self.length.saturating_sub(offset));
        let Some(address) = self.at(offset, length).filter(|_| length != 0) else {
            return 0;
        };
        // SAFETY: the module invariant, for the range `at` checked; `bytes`
        // is the caller's own exclusive buffer, which no surface overlaps.
        unsafe { core::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), length) };
        length
    }
}
