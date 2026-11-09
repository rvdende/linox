//! Static DMA pages for the hardware drivers, claimed by one driver
//! instance at a time and reached only by copying.
//!
//! The bring-up drivers (and USB input in the main kernel) give their
//! devices pages inside the kernel image, which both the firmware's page
//! tables and the kernel's identity map at their physical address, so a
//! page's address is also what the device uses ([`DmaPages::device_address`]).
//!
//! A [`StaticDma`] is a page-aligned run of such pages in a `static`. A
//! driver takes them with [`StaticDma::claim`] (all of them) or
//! [`StaticDma::claim_page`] (one, for drivers that keep a page per port),
//! which fails while another [`DmaPages`] holds them; dropping the
//! `DmaPages` gives them back. That is what lets a driver's `open` be safe:
//! two instances can no longer share their rings by accident.
//!
//! Every access is volatile and bounds-checked like `trusted::mmio::Mmio`
//! (out of range reads as all ones, writes nothing), and no Rust reference
//! into the pages is formed, since the device writes them behind the
//! compiler's back. `DmaPages` is not `Sync`.
//!
//! What a device may reach is the I/O MMU's policy: [`StaticDma::region`]
//! is what a driver hands it.

use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use super::mmio::{span, Word};

const PAGE_SIZE: usize = 4096;
/// Every claim bit set: the whole run is claimed.
const ALL: u64 = u64::MAX;

#[repr(C, align(4096))]
struct Page(UnsafeCell<[u8; PAGE_SIZE]>);

/// `PAGES` zeroed, contiguous, page-aligned DMA pages in a `static`.
#[repr(C)]
pub(crate) struct StaticDma<const PAGES: usize> {
    pages: [Page; PAGES],
    /// Bit n: page n is claimed (single pages, `PAGES` at most 64); all
    /// bits: the whole run is.
    claims: AtomicU64,
}

// SAFETY: the pages are reached only through a `DmaPages`, which a claim
// makes unique; `claims` is atomic.
unsafe impl<const PAGES: usize> Sync for StaticDma<PAGES> {}

impl<const PAGES: usize> StaticDma<PAGES> {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: Page = Page(UnsafeCell::new([0; PAGE_SIZE]));

    pub(crate) const fn new() -> Self {
        Self {
            pages: [Self::ZERO; PAGES],
            claims: AtomicU64::new(0),
        }
    }

    fn base(&'static self) -> usize {
        self.pages.as_ptr() as usize
    }

    /// The pages' physical range (start, length), for the I/O MMU.
    pub(crate) fn region(&'static self) -> (u64, u64) {
        (self.base() as u64, (PAGES * PAGE_SIZE) as u64)
    }

    /// All the pages, unless any is claimed.
    pub(crate) fn claim(&'static self) -> Option<DmaPages> {
        self.claims
            .compare_exchange(0, ALL, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(DmaPages {
            base: self.base(),
            length: PAGES * PAGE_SIZE,
            claims: &self.claims,
            release: ALL,
            _not_sync: PhantomData,
        })
    }

    /// Page `index` alone, unless it (or the whole run) is claimed.
    pub(crate) fn claim_page(&'static self, index: usize) -> Option<DmaPages> {
        if index >= PAGES || PAGES > 64 {
            return None;
        }
        let bit = 1_u64 << index;
        self.claims
            .try_update(Ordering::Acquire, Ordering::Relaxed, |claims| {
                (claims & bit == 0).then_some(claims | bit)
            })
            .ok()?;
        Some(DmaPages {
            base: self.base() + index * PAGE_SIZE,
            length: PAGE_SIZE,
            claims: &self.claims,
            release: bit,
            _not_sync: PhantomData,
        })
    }
}

/// Claimed static DMA pages.
pub(crate) struct DmaPages {
    base: usize,
    length: usize,
    claims: &'static AtomicU64,
    /// The claim bits this handle gives back.
    release: u64,
    _not_sync: PhantomData<Cell<u8>>,
}

impl DmaPages {
    /// The address the device uses for byte `offset` (the pages are
    /// identity mapped).
    pub(crate) fn device_address(&self, offset: usize) -> u64 {
        (self.base + offset.min(self.length)) as u64
    }

    pub(crate) fn read<T: Word>(&self, offset: usize) -> T {
        let size = size_of::<T>();
        match span(self.base, self.length, offset, size, size) {
            // SAFETY: the claim makes these pages this handle's, span keeps
            // the aligned access inside them, and the static is never
            // reached through a reference.
            Some(address) => unsafe { (address as *const T).read_volatile() },
            None => T::ONES,
        }
    }

    pub(crate) fn write<T: Word>(&self, offset: usize, value: T) {
        let size = size_of::<T>();
        if let Some(address) = span(self.base, self.length, offset, size, size) {
            // SAFETY: as for read.
            unsafe { (address as *mut T).write_volatile(value) };
        }
    }

    /// Copies `bytes` to `offset`, or nothing if they do not fit.
    pub(crate) fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        if span(self.base, self.length, offset, bytes.len(), 1).is_some() {
            for (index, byte) in bytes.iter().enumerate() {
                self.write::<u8>(offset + index, *byte);
            }
        }
    }

    /// Fills `bytes` from `offset`, with ones if they do not fit.
    pub(crate) fn read_bytes(&self, offset: usize, bytes: &mut [u8]) {
        if span(self.base, self.length, offset, bytes.len(), 1).is_some() {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = self.read::<u8>(offset + index);
            }
        } else {
            bytes.fill(u8::MAX);
        }
    }

    /// Sets `length` bytes from `offset` to `value`, or none if they do
    /// not fit.
    pub(crate) fn fill(&self, offset: usize, length: usize, value: u8) {
        if span(self.base, self.length, offset, length, 1).is_some() {
            (offset..offset + length).for_each(|index| self.write::<u8>(index, value));
        }
    }

    /// Writes back and invalidates the cache lines over `length` bytes from
    /// `offset`, for devices that do not snoop the processor caches.
    pub(crate) fn flush_cache(&self, offset: usize, length: usize) {
        if let Some(address) = span(self.base, self.length, offset, length, 1) {
            crate::drivers::flush_cache(address, length);
        }
    }
}

impl Drop for DmaPages {
    fn drop(&mut self) {
        // The driver stops its device before the handle drops.
        self.claims.fetch_and(!self.release, Ordering::Release);
    }
}
