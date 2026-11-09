//! Memory the drivers' devices reach by DMA, which the kernel reaches only
//! by copying.
//!
//! Every kind of DMA memory is used through one view, [`DmaView`]: volatile,
//! bounds-checked accesses by offset like `trusted::mmio::Mmio` (out of
//! range or misaligned reads as all ones and writes nothing), and the
//! address the device uses for each byte. No Rust reference into DMA memory
//! is ever formed, since the device writes it behind the compiler's back,
//! and a view is not `Sync`. Three owners hand views out:
//!
//! - [`StaticDma`]: a page-aligned run of pages in a `static`, inside the
//!   kernel image, which both the firmware's page tables and the kernel's
//!   identity map at their physical address (so a page's address is also
//!   what the device uses). A driver takes them with [`StaticDma::claim`]
//!   (all of them) or [`StaticDma::claim_page`] (one, for drivers that keep
//!   a page per port), which fails while another [`DmaPages`] holds them;
//!   dropping the `DmaPages` gives them back. That is what lets a driver's
//!   `open` be safe: two instances can no longer share their rings by
//!   accident. [`DmaPages::keep`] keeps a claim for good, for tables a
//!   device uses for the rest of the boot (the I/O MMU's).
//! - [`DmaPool`]: such pages sub-allocated by one driver instance at a
//!   time (xHCI, whose controllers each draw rings, contexts and buffers as
//!   they find devices). [`DmaPool::arena`] opens the pool's free tail to
//!   one instance; [`DmaArena::take`] hands out zeroed runs of pages as
//!   [`DmaSpan`]s, [`DmaArena::release_to`] takes back the ones taken after
//!   a mark, and [`DmaArena::keep`] closes the arena with what it took
//!   kept for good, so the next instance starts after it.
//! - [`DmaBuffer`]: physically contiguous frames from the frame allocator
//!   (the virtio drivers), scrubbed and returned when the buffer drops.
//!
//! A view can also be made of one frame-allocator page whose lease its
//! holder keeps and admits to a device itself (the virtio queues in
//! `arch/x86_64/pci.rs` and `linux_socket/virtio_net.rs`, which activate
//! their own I/O MMU translations): [`DmaView::leased`] from the
//! `FrameLease`, by any code, as `trusted::frame::Frame::leased` (and as
//! sound as the lease, that module's known gap), or
//! [`DmaView::from_direct_map`] from the physical address and its
//! direct-map address, only in the `pci.rs` entry points `address_space.rs`
//! calls with the pages it owns (`tools/architecture/check-kernel-unsafe.sh`
//! keeps it there and in the memory layer).
//!
//! A `DmaSpan` does not own its pages: spans may be cloned, and an arena
//! may hand pages it took back out again. Every access is volatile and
//! bounded, so a stale span is a driver logic error (its device and the
//! new owner see the same bytes), never undefined behaviour.
//!
//! What a device may reach is the I/O MMU's policy: [`StaticDma::region`],
//! [`DmaPool::region`] and [`DmaBuffer::region`] are what a driver hands
//! it.

use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomData;
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::mmio::{span, Word};
use super::pixels::PixelBuffer;
use crate::arch::x86_64::paging;
use crate::memory::{self, FrameLease, FrameOwner};

const PAGE_SIZE: usize = 4096;
/// Every claim bit set: the whole run is claimed.
const ALL: u64 = u64::MAX;

#[repr(C, align(4096))]
struct Page(UnsafeCell<[u8; PAGE_SIZE]>);

/// `N` zeroed, contiguous, page-aligned pages in a `static`.
#[repr(C)]
struct Pages<const N: usize>([Page; N]);

// SAFETY: the pages are reached only through a `DmaView`, whose owner (a
// claim or an arena, see the module comment) hands it out, and only by
// volatile raw-pointer accesses, never through a reference.
unsafe impl<const N: usize> Sync for Pages<N> {}

impl<const N: usize> Pages<N> {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: Page = Page(UnsafeCell::new([0; PAGE_SIZE]));

    const fn new() -> Self {
        Self([Self::ZERO; N])
    }

    fn base(&'static self) -> usize {
        self.0.as_ptr() as usize
    }

    /// The pages' physical range (start, length): the kernel image is
    /// identity mapped, so their address is their physical address.
    fn region(&'static self) -> (u64, u64) {
        (self.base() as u64, (N * PAGE_SIZE) as u64)
    }

    /// A view of pages `first..first + count`, which the caller's claim or
    /// arena makes its own.
    fn view(&'static self, first: usize, count: usize) -> DmaView {
        let base = self.base() + first * PAGE_SIZE;
        DmaView::new(base, count * PAGE_SIZE, base as u64)
    }
}

/// A window of DMA memory: `length` bytes the kernel reaches at `base`
/// and the device at `device`.
///
/// The invariant the `unsafe` blocks rely on: `base..base + length` is
/// memory the owner that made the view keeps for the device while the
/// view is used (static pages a claim or arena gave it, frames a
/// `DmaBuffer` holds, or a leased frame whose lease its holder keeps),
/// mapped in the current page tables, and reached only through views,
/// never through a Rust reference.
pub(crate) struct DmaView {
    base: usize,
    length: usize,
    device: u64,
    _not_sync: PhantomData<Cell<u8>>,
}

impl DmaView {
    const fn new(base: usize, length: usize, device: u64) -> Self {
        Self {
            base,
            length,
            device,
            _not_sync: PhantomData,
        }
    }

    /// The frame `lease` names, through the direct map, for its holder (see
    /// the module comment).
    pub(crate) fn leased(lease: FrameLease) -> Option<Self> {
        let physical = lease.address();
        Self::from_direct_map(
            physical,
            paging::direct_map_range_address(physical, PAGE_SIZE)?,
        )
    }

    /// The frame at `physical`, if `address` is its direct-map address.
    /// Only `pci.rs` and the memory layer call this (see the module
    /// comment).
    pub(crate) fn from_direct_map(physical: u64, address: usize) -> Option<Self> {
        (physical.is_multiple_of(PAGE_SIZE as u64)
            && paging::direct_map_range_address(physical, PAGE_SIZE) == Some(address))
        .then(|| Self::new(address, PAGE_SIZE, physical))
    }

    fn duplicate(&self) -> Self {
        Self::new(self.base, self.length, self.device)
    }

    pub(crate) fn len(&self) -> usize {
        self.length
    }

    /// The address the device uses for byte `offset`.
    pub(crate) fn device_address(&self, offset: usize) -> u64 {
        self.device + offset.min(self.length) as u64
    }

    /// The memory's device range (start, length), for I/O MMU admission.
    pub(crate) fn region(&self) -> (u64, u64) {
        (self.device, self.length as u64)
    }

    pub(crate) fn read<T: Word>(&self, offset: usize) -> T {
        let size = size_of::<T>();
        match span(self.base, self.length, offset, size, size) {
            // SAFETY: the type invariant keeps the memory the view's, span
            // keeps the aligned access inside it, and the access is
            // volatile because the device writes it too.
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

    /// Zeroes the whole view, a word at a time.
    pub(crate) fn zero(&self) {
        (0..self.length / 8).for_each(|word| self.write::<u64>(word * 8, 0));
    }

    /// Writes back and invalidates the cache lines over `length` bytes from
    /// `offset`, for devices that read and write memory without snooping
    /// the processor caches: call it after filling a buffer such a device
    /// will read, and before reading what it wrote.
    pub(crate) fn flush_cache(&self, offset: usize, length: usize) {
        if let Some(address) = span(self.base, self.length, offset, length, 1) {
            flush_lines(address, length);
        }
    }
}

/// Writes back and invalidates the cache lines covering `length` bytes at
/// `address`, a range inside one view (checked by its caller).
fn flush_lines(address: usize, length: usize) {
    const LINE: usize = 64;
    let end = address.saturating_add(length);
    let mut line = address & !(LINE - 1);
    while line < end {
        // SAFETY: CLFLUSH only writes back and invalidates the line, which
        // changes no value the program reads; the line holds bytes of the
        // view, which is mapped (a line's first bytes may lie just before
        // it, on the same mapped page).
        unsafe { core::arch::x86_64::_mm_clflush(line as *const u8) };
        line += LINE;
    }
    // A full fence (MFENCE, or a locked instruction where the compiler
    // picks one) orders the flushes before later accesses: CLFLUSH is
    // ordered with both (Intel SDM vol. 2A, CLFLUSH).
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// `PAGES` zeroed, contiguous, page-aligned DMA pages in a `static`,
/// claimed by one driver instance at a time.
#[repr(C)]
pub(crate) struct StaticDma<const PAGES: usize> {
    pages: Pages<PAGES>,
    /// Bit n: page n is claimed (single pages, `PAGES` at most 64); all
    /// bits: the whole run is.
    claims: AtomicU64,
}

impl<const PAGES: usize> StaticDma<PAGES> {
    pub(crate) const fn new() -> Self {
        Self {
            pages: Pages::new(),
            claims: AtomicU64::new(0),
        }
    }

    /// The pages' physical range (start, length), for the I/O MMU.
    pub(crate) fn region(&'static self) -> (u64, u64) {
        self.pages.region()
    }

    /// All the pages, unless any is claimed.
    pub(crate) fn claim(&'static self) -> Option<DmaPages> {
        self.claims
            .compare_exchange(0, ALL, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(DmaPages {
            view: self.pages.view(0, PAGES),
            claims: &self.claims,
            release: ALL,
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
            view: self.pages.view(index, 1),
            claims: &self.claims,
            release: bit,
        })
    }
}

/// Claimed static DMA pages.
pub(crate) struct DmaPages {
    view: DmaView,
    claims: &'static AtomicU64,
    /// The claim bits this handle gives back.
    release: u64,
}

impl DmaPages {
    /// Keeps the claim for good and returns a view that may be shared, for
    /// tables a device keeps using for the rest of the boot.
    pub(crate) fn keep(self) -> DmaSpan {
        let span = DmaSpan {
            view: self.view.duplicate(),
        };
        core::mem::forget(self);
        span
    }
}

impl Deref for DmaPages {
    type Target = DmaView;

    fn deref(&self) -> &DmaView {
        &self.view
    }
}

impl Drop for DmaPages {
    fn drop(&mut self) {
        // The driver stops its device before the handle drops.
        self.claims.fetch_and(!self.release, Ordering::Release);
    }
}

/// `PAGES` zeroed, contiguous, page-aligned DMA pages in a `static`,
/// sub-allocated by one driver instance at a time through a [`DmaArena`].
#[repr(C)]
pub(crate) struct DmaPool<const PAGES: usize> {
    pages: Pages<PAGES>,
    /// The pages before this one are kept by arenas that closed.
    kept: AtomicUsize,
    /// An arena is open.
    open: AtomicBool,
}

impl<const PAGES: usize> DmaPool<PAGES> {
    pub(crate) const fn new() -> Self {
        Self {
            pages: Pages::new(),
            kept: AtomicUsize::new(0),
            open: AtomicBool::new(false),
        }
    }

    /// The whole pool's physical range (start, length), for the I/O MMU.
    pub(crate) fn region(&'static self) -> (u64, u64) {
        self.pages.region()
    }

    /// The pages no closed arena kept, unless another arena is open.
    pub(crate) fn arena(&'static self) -> Option<DmaArena> {
        self.open
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let start = self.kept.load(Ordering::Acquire);
        Some(DmaArena {
            pages: PoolPages {
                base: self.pages.base(),
                count: PAGES,
            },
            start,
            next: start,
            kept: &self.kept,
            open: &self.open,
            _not_sync: PhantomData,
        })
    }
}

/// A pool's pages, for an arena that cannot name the pool's length.
#[derive(Clone, Copy)]
struct PoolPages {
    base: usize,
    count: usize,
}

/// One driver instance's access to a pool's free pages.
pub(crate) struct DmaArena {
    pages: PoolPages,
    /// The first page this arena may hand out.
    start: usize,
    /// The next page it hands out.
    next: usize,
    kept: &'static AtomicUsize,
    open: &'static AtomicBool,
    _not_sync: PhantomData<Cell<u8>>,
}

impl DmaArena {
    /// `count` zeroed, contiguous pages, unless the pool has too few left.
    pub(crate) fn take(&mut self, count: usize) -> Option<DmaSpan> {
        let end = self
            .next
            .checked_add(count)
            .filter(|end| *end <= self.pages.count)?;
        let base = self.pages.base + self.next * PAGE_SIZE;
        let view = DmaView::new(base, count * PAGE_SIZE, base as u64);
        self.next = end;
        view.zero();
        Some(DmaSpan { view })
    }

    /// A mark to [`release_to`](Self::release_to): the pages taken so far.
    pub(crate) fn mark(&self) -> usize {
        self.next
    }

    /// Takes back every page taken after `mark`. The caller no longer uses
    /// them, and its device no longer reaches them.
    pub(crate) fn release_to(&mut self, mark: usize) {
        self.next = mark.clamp(self.start, self.next);
    }

    /// Closes the arena, keeping every page it handed out for good.
    pub(crate) fn keep(self) {
        self.kept.store(self.next, Ordering::Release);
    }
}

impl Drop for DmaArena {
    fn drop(&mut self) {
        // Without `keep`, everything this arena took goes back: its
        // instance stopped its device first.
        self.open.store(false, Ordering::Release);
    }
}

/// Pages an arena handed out, or a kept claim's: a view that may be
/// cloned (see the module comment).
pub(crate) struct DmaSpan {
    view: DmaView,
}

impl Clone for DmaSpan {
    fn clone(&self) -> Self {
        Self {
            view: self.view.duplicate(),
        }
    }
}

impl Deref for DmaSpan {
    type Target = DmaView;

    fn deref(&self) -> &DmaView {
        &self.view
    }
}

/// Physically contiguous, zeroed kernel frames that a device reaches by
/// DMA at their physical addresses (the I/O MMU, when it translates, maps
/// them one to one). The frames come from the frame allocator, owned by
/// the kernel, and are scrubbed and returned when the buffer drops, unless
/// it was given to the display for good ([`DmaBuffer::keep_for_display`]).
pub(crate) struct DmaBuffer {
    /// Reached through the frames' direct-map alias.
    view: DmaView,
    first: FrameLease,
    pages: usize,
    /// Given to the display: never returned.
    kept: bool,
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
            view: DmaView::new(base, pages * PAGE_SIZE, first.address()),
            first,
            pages,
            kept: false,
        })
    }

    /// Keeps the buffer's frames for good (they are never returned, even
    /// when the buffer drops) and returns them as a pixel buffer, for a
    /// display surface the console draws into for the rest of the boot.
    pub(crate) fn keep_for_display(&mut self) -> PixelBuffer {
        self.kept = true;
        PixelBuffer::kept_dma(self.view.base, self.view.length)
    }
}

impl Deref for DmaBuffer {
    type Target = DmaView;

    fn deref(&self) -> &DmaView {
        &self.view
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // The owner stops the device before its buffers drop, so nothing
        // reaches these frames once they are back in the allocator.
        if !self.kept {
            let _ = memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                self.first,
                self.pages,
            );
        }
    }
}
