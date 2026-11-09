//! Firmware tables (ACPI) viewed in place as byte slices, for parsing at
//! boot (`crates/acpi-tables` does the parsing).
//!
//! A view lasts one call: [`with_direct_mapped`] and [`with_identity_mapped`]
//! hand the closure a `&[u8]` over the table and take it back when the
//! closure returns, so no reference into firmware memory outlives the
//! parse.
//!
//! Who may call them: only the code that reads ACPI tables (the root
//! pointer check in `lib.rs`, `arch/x86_64/acpi.rs` and hardware bring-up),
//! with addresses taken from the root pointer the firmware handed over and
//! the tables it lists; `tools/architecture/check-kernel-unsafe.sh`
//! enforces that list.
//!
//! The invariant the `unsafe` blocks rely on: the range holds ACPI tables,
//! in memory the firmware reserved for them. The kernel never allocates
//! that memory (the frame allocator takes only conventional and
//! boot-services memory) and never writes it, and the views are made at
//! boot or in bring-up, on one CPU, so nothing writes the bytes while a
//! view lives.

use crate::arch::x86_64::paging;

const PAGE_SIZE: u64 = 4096;

/// Runs `f` on the `length` bytes at physical `address`, read through the
/// kernel's direct map, if they lie below `mapped_limit`.
pub(crate) fn with_direct_mapped<R>(
    address: usize,
    length: usize,
    mapped_limit: usize,
    f: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    if !linox_acpi_tables::range_is_mapped(address, length, mapped_limit) {
        return None;
    }
    let base = paging::direct_map_range_address(address as u64, length)?;
    // SAFETY: the direct map covers the range (checked), and the module
    // invariant keeps the bytes unchanged while the view lives.
    Some(f(unsafe {
        core::slice::from_raw_parts(base as *const u8, length)
    }))
}

/// Runs `f` on the `length` bytes at physical `address`, read through the
/// firmware's identity map (before the kernel installs its own page
/// tables, and in hardware bring-up), if the firmware maps every page of
/// them.
pub(crate) fn with_identity_mapped<R>(
    address: u64,
    length: usize,
    f: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    if address == 0 {
        return None;
    }
    let last = address.checked_add(u64::try_from(length).ok()?.checked_sub(1)?)?;
    let mut page = address & !(PAGE_SIZE - 1);
    while page <= last {
        if !crate::bringup::firmware_maps(page, false) {
            return None;
        }
        page = page.checked_add(PAGE_SIZE)?;
    }
    let base = usize::try_from(address).ok()?;
    // SAFETY: the firmware's identity map maps every page of the range
    // (checked), and the module invariant keeps the bytes unchanged while
    // the view lives.
    Some(f(unsafe {
        core::slice::from_raw_parts(base as *const u8, length)
    }))
}
