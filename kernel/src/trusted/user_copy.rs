//! Copies between kernel buffers and the user pages of the address space
//! loaded on this CPU, recovering from page faults.
//!
//! The copy loops are [`raw_copy_from_user`] and [`raw_copy_to_user`]
//! (`linox_raw_copy_from_user` and `linox_raw_copy_to_user` below; the
//! page-fault stub in `trusted::entry` knows their fault ranges): they lift SMAP for the copy alone, and a page
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

use core::arch::{asm, global_asm};

use super::page_table::PageTable;
use super::root;

global_asm!(
    r#"
    .text
    .global linox_raw_copy_from_user
    .global linox_copy_from_user_fault_begin
    .global linox_copy_from_user_fault_end
    .global linox_copy_from_user_fixup
linox_raw_copy_from_user:
    mov rax, rdx
    test rax, rax
    jz 2f
    stac
linox_copy_from_user_fault_begin:
1:
    mov cl, byte ptr [rsi]
    mov byte ptr [rdi], cl
    inc rsi
    inc rdi
    dec rax
    jnz 1b
linox_copy_from_user_fault_end:
    clac
2:
    ret
linox_copy_from_user_fixup:
    clac
    ret

    .global linox_raw_copy_to_user
    .global linox_copy_to_user_fault_begin
    .global linox_copy_to_user_fault_end
    .global linox_copy_to_user_fixup
linox_raw_copy_to_user:
    mov rax, rdx
    test rax, rax
    jz 4f
    stac
linox_copy_to_user_fault_begin:
3:
    mov cl, byte ptr [rsi]
    mov byte ptr [rdi], cl
    inc rsi
    inc rdi
    dec rax
    jnz 3b
linox_copy_to_user_fault_end:
    clac
4:
    ret
linox_copy_to_user_fixup:
    clac
    ret
"#
);

extern "sysv64" {
    fn linox_raw_copy_from_user(output: *mut u8, input: *const u8, length: usize) -> usize;
    fn linox_raw_copy_to_user(output: *mut u8, input: *const u8, length: usize) -> usize;
}

/// Copies `length` bytes from `input` to `output` with SMAP lifted,
/// stopping at the first page fault; returns the count not copied.
///
/// # Safety
///
/// `output` is valid for `length` bytes of writes that no live reference
/// covers, and `input` lies on user pages (or faults): this module's
/// checked copies are the callers.
unsafe fn raw_copy_from_user(output: *mut u8, input: *const u8, length: usize) -> usize {
    // SAFETY: the caller's contract; a fault returns the count left.
    unsafe { linox_raw_copy_from_user(output, input, length) }
}

/// Copies `length` bytes from `input` to `output` with SMAP lifted,
/// stopping at the first page fault; returns the count not copied.
///
/// # Safety
///
/// `input` is valid for `length` bytes of reads, and `output` lies on user
/// pages (or faults), which no Rust reference covers.
unsafe fn raw_copy_to_user(output: *mut u8, input: *const u8, length: usize) -> usize {
    // SAFETY: the caller's contract; a fault returns the count left.
    unsafe { linox_raw_copy_to_user(output, input, length) }
}

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
    let missed = unsafe { raw_copy_from_user(output.as_mut_ptr(), address as *const u8, count) };
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
    let missed = unsafe { raw_copy_to_user(address as *mut u8, input.as_ptr(), count) };
    count.saturating_sub(missed)
}

/// Whether the page holding `address` is mapped present at every level of
/// the loaded tables (user or not).
fn present(address: u64) -> bool {
    user_mapping_end(root::current() & ADDRESS_MASK, address, PRESENT).is_some()
}

/// Checks the copies' fault recovery: copies of two bytes that straddle the
/// end of a user mapping (`mapped_end`, with the page below it a writable
/// user page and the page at it unmapped) copy one byte and report one
/// missed, copies from and to `unmapped` (an unmapped page) copy nothing,
/// and SMAP is closed again after each (RFLAGS.AC clear). False without
/// copying if the pages are not as described.
pub(crate) fn verify_fault_fixups(mapped_end: u64, unmapped: u64) -> bool {
    let Some(last) = mapped_end.checked_sub(1) else {
        return false;
    };
    if user_prefix(last, 1, true) != 1 || present(mapped_end) || present(unmapped) {
        return false;
    }
    let mut output = [0_u8; 2];
    let input = [0x5a_u8, 0xa5];
    // SAFETY: `output` and `input` are this function's buffers; the byte
    // below `mapped_end` is a writable user page (checked above) and the
    // pages at `mapped_end` and `unmapped` are not mapped at all, so the
    // copies touch one user byte and fault on the rest, which the fixups
    // turn into a short count.
    let (partial_from, partial_to, rejected_from, rejected_to) = unsafe {
        (
            raw_copy_from_user(output.as_mut_ptr(), last as *const u8, output.len()),
            raw_copy_to_user(last as *mut u8, input.as_ptr(), input.len()),
            raw_copy_from_user(output.as_mut_ptr(), unmapped as *const u8, output.len()),
            raw_copy_to_user(unmapped as *mut u8, input.as_ptr(), input.len()),
        )
    };
    let flags: u64;
    // SAFETY: reading RFLAGS through the stack touches only the two stack
    // slots pushfq/pop use.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem)) };
    partial_from == 1
        && partial_to == 1
        && rejected_from == output.len()
        && rejected_to == input.len()
        && flags & (1 << 18) == 0
}
