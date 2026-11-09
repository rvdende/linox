//! Copies between kernel buffers and the user pages of the address space
//! loaded on this CPU, recovering from page faults.
//!
//! The copy loops are `cpu.rs`'s `linox_raw_copy_from_user` and
//! `linox_raw_copy_to_user`: they lift SMAP for the copy alone, and a page
//! fault inside them (an unmapped or read-only page) returns the count
//! not copied instead of reaching the fault handler. They copy whatever
//! the addresses map, though, and a supervisor page is as reachable to
//! them as a user page: the kernel's identity map shares the lower half
//! with user mappings. So [`copy_from_user`] and [`copy_to_user`] first
//! walk the loaded page tables and copy only the leading run of pages
//! mapped present and user-accessible (and writable, for a copy to user
//! space) at every level: memory user code may read or write itself, which
//! is never a Rust object (docs/FRAMEKERNEL.md, R3). A page that changes
//! after the walk is either unmapped (the copy faults and stops) or mapped
//! again as user memory; the kernel never maps its own memory at a user
//! address in a live address space.
//!
//! What a caller may copy, and from which process, stays its policy (the
//! Linux personality's range checks, `address_space`'s root checks); this
//! module guarantees only that a copy never touches kernel memory beyond
//! the caller's own buffer.

use super::page_table::PageTable;
use super::root;
use crate::arch::x86_64::cpu;

/// The end of the canonical lower half, where user mappings live.
const USER_LIMIT: u64 = 1 << 47;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const LARGE_PAGE: u64 = 1 << 7;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// The bytes of `length` from `address` that lie on a leading run of
/// pages the loaded tables map present and user-accessible (and writable
/// when `write`).
fn user_prefix(address: u64, length: usize, write: bool) -> usize {
    let Some(end) = address.checked_add(length as u64) else {
        return 0;
    };
    let end = end.min(USER_LIMIT);
    let required = PRESENT | USER | if write { WRITABLE } else { 0 };
    let root = root::current() & ADDRESS_MASK;
    let mut cursor = address;
    while cursor < end {
        let Some(mapped_end) = user_mapping_end(root, cursor, required) else {
            break;
        };
        cursor = mapped_end;
    }
    (cursor.min(end).saturating_sub(address)) as usize
}

/// The end of the page (or large page) holding `address`, if every level
/// maps it with the `required` bits.
fn user_mapping_end(root: u64, address: u64, required: u64) -> Option<u64> {
    let mut table = root;
    // Levels from the root: the shift of the address bits each indexes.
    for (level, shift) in [39_u32, 30, 21, 12].into_iter().enumerate() {
        let entry = PageTable::from_physical(table)?.get(((address >> shift) & 0x1ff) as usize);
        if entry & required != required {
            return None;
        }
        // A large page at the 1 GiB or 2 MiB level ends the walk; at the
        // root the bit is reserved.
        if shift == 12 || (level > 0 && entry & LARGE_PAGE != 0) {
            let size = 1_u64 << shift;
            return Some((address & !(size - 1)) + size);
        }
        table = entry & ADDRESS_MASK;
    }
    None
}

/// Copies `output.len()` bytes from user address `address` into `output`,
/// as far as the pages there are user pages and do not fault; returns the
/// number copied (the leading part of `output`).
pub(crate) fn copy_from_user(address: u64, output: &mut [u8]) -> usize {
    let count = user_prefix(address, output.len(), false);
    if count == 0 {
        return 0;
    }
    // SAFETY: the first `count` bytes from `address` lie on user pages
    // (walked above; see the module comment for later changes), which no
    // Rust reference covers, and `output` is a kernel buffer of at least
    // `count` bytes that only this copy writes. The copy recovers from a
    // fault by returning the count it did not copy.
    let missed =
        unsafe { cpu::raw_copy_from_user(output.as_mut_ptr(), address as *const u8, count) };
    count.saturating_sub(missed)
}

/// Copies `input` to user address `address`, as far as the pages there
/// are writable user pages and do not fault; returns the number of bytes
/// copied (the leading part of `input`).
pub(crate) fn copy_to_user(address: u64, input: &[u8]) -> usize {
    let count = user_prefix(address, input.len(), true);
    if count == 0 {
        return 0;
    }
    // SAFETY: as in `copy_from_user`: the first `count` bytes from
    // `address` lie on writable user pages, and `input` is a kernel buffer
    // of at least `count` bytes that the copy only reads.
    let missed = unsafe { cpu::raw_copy_to_user(address as *mut u8, input.as_ptr(), count) };
    count.saturating_sub(missed)
}
