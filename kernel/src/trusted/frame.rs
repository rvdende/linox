//! A physical frame of RAM, read and written through the kernel's direct
//! map.
//!
//! [`Frame`] names one 4-KiB frame and copies data in and out of it: words,
//! byte ranges, fills, whole-frame copies. It never hands out a Rust
//! reference into the frame, so a frame that user space or a device may
//! write at the same time is still only copied (docs/FRAMEKERNEL.md, R3),
//! and every offset is checked against the frame's bounds (an access out
//! of bounds panics, as slice indexing does).
//!
//! Who may make one:
//! - any kernel code, from a [`FrameLease`] the frame allocator handed out
//!   ([`Frame::leased`]): the lease's holder owns the frame's contents;
//! - only the memory layer (`address_space.rs`, `arch/x86_64/paging.rs`,
//!   `memory.rs` and `trusted/`), from a bare physical address
//!   ([`Frame::from_physical`]): the frame of a page-table entry it walks,
//!   or a frame whose lease it keeps beside the address.
//!   `tools/architecture/check-kernel-unsafe.sh` enforces that list.
//!
//! The invariant the constructors establish and the `unsafe` blocks below
//! rely on: the frame lies wholly inside the direct map (checked), and it
//! is memory the kernel reaches only through raw pointers, never through a
//! live Rust reference: frame-allocator RAM, or one of the kernel's static
//! page tables, which `paging.rs` keeps in `UnsafeCell`s and reads through
//! raw pointers too. A module that views a leased frame as a typed Rust
//! object (`&mut SomePage`, the remaining direct-map views of
//! docs/FRAMEKERNEL.md §5 step 7) must not also reach it through a `Frame`.
//!
//! Known gap: `FrameLease` is `Copy` and `FrameLease::from_parts` builds one
//! for any page-aligned address (docs/FRAMEKERNEL.md §3.5, finding 6), so a
//! `Frame` from a lease is only as sound as the lease. An owning frame
//! handle closes that later; this type is where it will plug in.

use crate::{arch::x86_64::paging, memory::FrameLease};

pub(crate) const FRAME_SIZE: usize = 4096;
/// The 64-bit words in a frame.
pub(crate) const FRAME_WORDS: usize = FRAME_SIZE / size_of::<u64>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Frame {
    physical: u64,
    /// The frame's first byte in the direct map.
    base: usize,
}

impl Frame {
    /// The frame `lease` names, for its holder.
    pub(crate) fn leased(lease: FrameLease) -> Option<Self> {
        Self::from_physical(lease.address())
    }

    /// The frame at `physical`, if it is page-aligned and inside the direct
    /// map. Only the memory layer calls this (see the module comment).
    pub(crate) fn from_physical(physical: u64) -> Option<Self> {
        if !physical.is_multiple_of(FRAME_SIZE as u64) {
            return None;
        }
        let base = paging::direct_map_range_address(physical, FRAME_SIZE)?;
        Some(Self { physical, base })
    }

    /// The direct-map address of byte `offset`, after checking that
    /// `length` bytes from there lie inside the frame.
    fn at(self, offset: usize, length: usize) -> *mut u8 {
        assert!(
            offset <= FRAME_SIZE && length <= FRAME_SIZE - offset,
            "frame access out of bounds"
        );
        (self.base + offset) as *mut u8
    }

    /// The direct-map address of the `T` at byte `offset`, checked to lie
    /// inside the frame and to be aligned for `T`.
    fn at_aligned<T>(self, offset: usize) -> *mut T {
        assert!(
            offset.is_multiple_of(align_of::<T>()),
            "unaligned frame access"
        );
        self.at(offset, size_of::<T>()).cast()
    }

    /// A pointer to word `index`, checked to lie inside the frame, for the
    /// atomic entry updates of `trusted::page_table`.
    pub(super) fn word_pointer(self, index: usize) -> *mut u64 {
        self.at_aligned::<u64>(index.saturating_mul(8))
    }

    /// The 64-bit word at word `index` (below [`FRAME_WORDS`]).
    pub(crate) fn read_u64(self, index: usize) -> u64 {
        let word = self.word_pointer(index);
        // SAFETY: the module invariant (direct-mapped kernel memory no Rust
        // reference covers) and `at_aligned`'s bounds and alignment check.
        unsafe { word.read() }
    }

    pub(crate) fn write_u64(self, index: usize, value: u64) {
        let word = self.word_pointer(index);
        // SAFETY: as for `read_u64`.
        unsafe { word.write(value) }
    }

    pub(crate) fn read_u8(self, offset: usize) -> u8 {
        let byte = self.at(offset, 1);
        // SAFETY: as for `read_u64`.
        unsafe { byte.read() }
    }

    pub(crate) fn write_u8(self, offset: usize, value: u8) {
        let byte = self.at(offset, 1);
        // SAFETY: as for `read_u64`.
        unsafe { byte.write(value) }
    }

    /// Reads the `T` at byte `offset` with a volatile load, for memory a
    /// device writes (a DMA page's ring and status bytes).
    fn read_volatile<T: Copy>(self, offset: usize) -> T {
        let value = self.at_aligned::<T>(offset);
        // SAFETY: as for `read_u64`; `T` is one of the integer types below,
        // valid for every bit pattern.
        unsafe { value.read_volatile() }
    }

    pub(crate) fn read_volatile_u8(self, offset: usize) -> u8 {
        self.read_volatile(offset)
    }

    pub(crate) fn read_volatile_u16(self, offset: usize) -> u16 {
        self.read_volatile(offset)
    }

    pub(crate) fn read_volatile_u32(self, offset: usize) -> u32 {
        self.read_volatile(offset)
    }

    pub(crate) fn read_volatile_u64(self, offset: usize) -> u64 {
        self.read_volatile(offset)
    }

    /// Writes the word at byte `offset` with a volatile store, for a page
    /// user space reads while the kernel updates it (the vvar page).
    pub(crate) fn write_volatile_u64(self, offset: usize, value: u64) {
        let word = self.at_aligned::<u64>(offset);
        // SAFETY: as for `read_u64`.
        unsafe { word.write_volatile(value) }
    }

    /// Copies `output.len()` bytes from byte `offset` into `output`.
    pub(crate) fn read_bytes(self, offset: usize, output: &mut [u8]) {
        let source = self.at(offset, output.len());
        // SAFETY: as for `read_u64`, for the checked range; `output` is a
        // separate buffer the caller owns (a plain copy, not a reference
        // into the frame), and `copy` allows overlap anyway.
        unsafe { core::ptr::copy(source, output.as_mut_ptr(), output.len()) }
    }

    /// Whether the bytes from byte `offset` equal `expected`.
    pub(crate) fn bytes_match(self, offset: usize, expected: &[u8]) -> bool {
        self.at(offset, expected.len());
        expected
            .iter()
            .enumerate()
            .all(|(index, byte)| self.read_u8(offset + index) == *byte)
    }

    /// Copies `input` into the frame at byte `offset`.
    pub(crate) fn write_bytes(self, offset: usize, input: &[u8]) {
        let destination = self.at(offset, input.len());
        // SAFETY: as for `read_bytes`.
        unsafe { core::ptr::copy(input.as_ptr(), destination, input.len()) }
    }

    /// Sets `length` bytes from byte `offset` to `value`.
    pub(crate) fn fill_bytes(self, offset: usize, length: usize, value: u8) {
        let destination = self.at(offset, length);
        // SAFETY: as for `read_u64`, for the checked range.
        unsafe { core::ptr::write_bytes(destination, value, length) }
    }

    /// Sets every byte of the frame to `value`.
    pub(crate) fn fill(self, value: u8) {
        self.fill_bytes(0, FRAME_SIZE, value);
    }

    /// Clears the frame word by word.
    pub(crate) fn zero(self) {
        (0..FRAME_WORDS).for_each(|index| self.write_u64(index, 0));
    }

    pub(crate) fn is_zero(self) -> bool {
        (0..FRAME_WORDS).all(|index| self.read_u64(index) == 0)
    }

    /// Runs `f` on a copy of the frame's bytes and returns its result, for
    /// code that parses a whole page as a slice.
    pub(crate) fn with_bytes<R>(self, f: impl FnOnce(&[u8; FRAME_SIZE]) -> R) -> R {
        let mut bytes = [0; FRAME_SIZE];
        self.read_bytes(0, &mut bytes);
        f(&bytes)
    }

    /// Runs `f` on a copy of the frame's bytes, then copies them back, for
    /// code that builds a whole page (a program image, an initial stack)
    /// as a slice. The frame must be one only its holder writes meanwhile:
    /// a page being prepared, not yet mapped anywhere else.
    pub(crate) fn with_bytes_mut<R>(self, f: impl FnOnce(&mut [u8; FRAME_SIZE]) -> R) -> R {
        let mut bytes = [0; FRAME_SIZE];
        self.read_bytes(0, &mut bytes);
        let result = f(&mut bytes);
        self.write_bytes(0, &bytes);
        result
    }

    /// Copies the whole of `source` into this frame.
    pub(crate) fn copy_from(self, source: Frame) {
        let (from, to) = (source.at(0, FRAME_SIZE), self.at(0, FRAME_SIZE));
        // SAFETY: both frames satisfy the module invariant and are whole
        // frames; `copy` is correct even when they are the same frame.
        unsafe { core::ptr::copy(from, to, FRAME_SIZE) }
    }
}
