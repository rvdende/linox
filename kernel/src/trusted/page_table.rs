//! A page-table frame viewed as its 512 entries, and single entries the
//! kernel reads and writes in place.
//!
//! [`PageTable`] reads and writes entries by index (an index of 512 or
//! more panics); [`PageEntry`] is one entry kept for a later read or write
//! (a walk's leaf). Both reach the table through the direct map, as a
//! [`Frame`] does, and rely on the same invariant (see `trusted::frame`).
//!
//! Who may make one: only the memory layer (`address_space.rs`,
//! `arch/x86_64/paging.rs`, `memory.rs` and `trusted/`), from the active
//! root, a table frame it leased or keeps in a static, or the address in a
//! present table entry it walked to (`PageTable::from_physical`, confined by
//! `tools/architecture/check-kernel-unsafe.sh`). Page-table frames are
//! freed only when their address space is retired, after the walks over it
//! are done.
//!
//! What this layer guarantees is the memory safety of each access: an
//! aligned 64-bit load or store inside a page-table frame. Which frames a
//! table maps, and with what permissions, is the address-space code's
//! policy, checked by its verification walks; the `Cursor` of
//! docs/FRAMEKERNEL.md §5 step 11 will take that over.

use core::sync::atomic::{AtomicU64, Ordering};

use super::frame::{Frame, FRAME_WORDS};

pub(crate) const ENTRY_COUNT: usize = FRAME_WORDS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageTable(Frame);

impl PageTable {
    /// The table at `physical`, if it is page-aligned and inside the direct
    /// map. Only the memory layer calls this (see the module comment).
    pub(crate) fn from_physical(physical: u64) -> Option<Self> {
        Frame::from_physical(physical).map(Self)
    }

    /// Entry `index`.
    pub(crate) fn get(self, index: usize) -> u64 {
        self.0.read_u64(index)
    }

    pub(crate) fn set(self, index: usize, value: u64) {
        self.0.write_u64(index, value);
    }

    /// Entry `index`, kept to be read or written later.
    pub(crate) fn entry(self, index: usize) -> PageEntry {
        assert!(index < ENTRY_COUNT, "page-table index out of bounds");
        PageEntry {
            table: Some(self.0),
            index,
        }
    }

    /// Copies all 512 entries of `source` into this table.
    pub(crate) fn copy_from(self, source: PageTable) {
        self.0.copy_from(source.0);
    }

    /// Whether every entry is zero.
    pub(crate) fn is_empty(self) -> bool {
        self.0.is_zero()
    }
}

/// One entry of a [`PageTable`], read and written in place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PageEntry {
    /// None for [`PageEntry::UNSET`].
    table: Option<Frame>,
    index: usize,
}

impl PageEntry {
    /// A placeholder for an array slot not yet filled: it reads as 0 and
    /// ignores writes.
    pub(crate) const UNSET: Self = Self {
        table: None,
        index: 0,
    };

    pub(crate) fn read(self) -> u64 {
        self.table.map_or(0, |table| table.read_u64(self.index))
    }

    /// Reads the entry with a volatile load, for a check the compiler must
    /// not fold into an earlier read.
    pub(crate) fn read_volatile(self) -> u64 {
        self.table
            .map_or(0, |table| table.read_volatile_u64(self.index * 8))
    }

    pub(crate) fn write(self, value: u64) {
        if let Some(table) = self.table {
            table.write_u64(self.index, value);
        }
    }

    /// Sets `bits` atomically, so a bit the processor sets meanwhile (the
    /// accessed or dirty bit) is kept.
    pub(crate) fn set_bits(self, bits: u64) {
        if let Some(table) = self.table {
            // SAFETY: the entry is an aligned u64 inside a page-table frame
            // (`entry` checked the index; the frame invariant covers the
            // rest), and the processor updates entries atomically too, so
            // no non-atomic access races with this one but the kernel's own
            // plain accesses, as before this type existed.
            unsafe { AtomicU64::from_ptr(table.word_pointer(self.index)) }
                .fetch_or(bits, Ordering::SeqCst);
        }
    }
}

/// Drops this CPU's cached translation of `address` (invlpg). Always safe:
/// the next access walks the page tables again.
pub(crate) fn invalidate_page(address: u64) {
    // SAFETY: invlpg only discards a TLB entry; it reads and writes no
    // memory the program can observe.
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
    }
}
