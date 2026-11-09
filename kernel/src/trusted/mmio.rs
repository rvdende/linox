//! A window of one device's memory-mapped registers.
//!
//! [`Mmio`] reads and writes registers by offset with volatile accesses of
//! 8 to 64 bits. An access outside the window, or misaligned for its width,
//! reads as all ones and writes nothing, the way an unclaimed bus cycle
//! behaves, instead of reaching memory the window does not cover. No Rust
//! reference to the registers is ever formed, and a window is not `Sync`:
//! a driver that shares one between contexts serializes access itself.
//!
//! Who may make one:
//! - any kernel code, from an [`MmioMapping`] (`Mmio::mapped`): the
//!   uncached mapping `paging.rs` built for a device's register range and
//!   checked against RAM and the kernel's own mappings;
//! - the hardware bring-up drivers, which run on the firmware's page tables
//!   (`Mmio::firmware`): a PCI BAR or an ACPI-described register block at
//!   its physical address, which the firmware's identity map must map
//!   (checked by walking its tables). The firmware assigned those ranges
//!   to the device and keeps RAM out of them. Only `bringup/` and the
//!   drivers it runs call this; `tools/architecture/check-kernel-unsafe.sh`
//!   enforces that list.
//!
//! The invariant every `unsafe` block below relies on: `base..base + length`
//! maps device registers, not RAM, for as long as the window and any
//! [`Mmio::window`] of it are used. A device register access cannot change
//! memory that Rust code reads; what a device does with what it is told
//! (DMA) is the I/O MMU's concern.

use core::cell::Cell;
use core::marker::PhantomData;

use crate::arch::x86_64::paging::MmioMapping;

mod sealed {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
}

/// An integer that devices read and write in one access.
pub(crate) trait Word: sealed::Sealed + Copy {
    /// What a read outside a window returns.
    const ONES: Self;
}

impl Word for u8 {
    const ONES: Self = u8::MAX;
}

impl Word for u16 {
    const ONES: Self = u16::MAX;
}

impl Word for u32 {
    const ONES: Self = u32::MAX;
}

impl Word for u64 {
    const ONES: Self = u64::MAX;
}

/// The address of `size` bytes at `offset` in `base..base + length`, if
/// they lie inside it and the address is a multiple of `align`.
pub(crate) fn span(
    base: usize,
    length: usize,
    offset: usize,
    size: usize,
    align: usize,
) -> Option<usize> {
    let end = offset.checked_add(size)?;
    let address = base.checked_add(offset)?;
    (end <= length && address.is_multiple_of(align)).then_some(address)
}

/// A range of one device's registers, mapped uncached.
pub(crate) struct Mmio {
    base: usize,
    length: usize,
    _not_sync: PhantomData<Cell<u8>>,
}

impl Mmio {
    fn new(base: usize, length: usize) -> Self {
        Self {
            base,
            length,
            _not_sync: PhantomData,
        }
    }

    /// The `length` bytes of registers at `physical` that `mapping` maps.
    pub(crate) fn mapped(mapping: MmioMapping, physical: u64, length: usize) -> Option<Self> {
        mapping
            .address(physical, length)
            .map(|base| Self::new(base, length))
    }

    /// The `length` bytes of registers at `physical`, reached through the
    /// firmware's identity map in hardware bring-up. Only bring-up and its
    /// drivers call this (see the module comment).
    pub(crate) fn firmware(physical: u64, length: usize) -> Option<Self> {
        let last = physical.checked_add(u64::try_from(length).ok()?.checked_sub(1)?)?;
        let base = usize::try_from(physical).ok()?;
        (crate::bringup::firmware_maps(physical, true) && crate::bringup::firmware_maps(last, true))
            .then(|| Self::new(base, length))
    }

    /// The `length` bytes at `offset`, if they lie inside this window.
    pub(crate) fn window(&self, offset: usize, length: usize) -> Option<Self> {
        span(self.base, self.length, offset, length, 1).map(|base| Self::new(base, length))
    }

    pub(crate) fn len(&self) -> usize {
        self.length
    }

    /// Whether the window starts at a multiple of `align` bytes.
    pub(crate) fn is_aligned(&self, align: usize) -> bool {
        self.base.is_multiple_of(align)
    }

    pub(crate) fn read<T: Word>(&self, offset: usize) -> T {
        let size = size_of::<T>();
        match span(self.base, self.length, offset, size, size) {
            // SAFETY: the module invariant maps the whole window to device
            // registers, and span keeps the aligned access inside it.
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
}
