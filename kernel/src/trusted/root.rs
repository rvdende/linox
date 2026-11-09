//! The page-table root register, CR3, as far as code outside the memory
//! layer may use it: reading which root is loaded, and reloading the same
//! root to drop this CPU's non-global translations.
//!
//! Loading a different root stays with the memory layer, the only code that
//! builds roots and can vouch that a root maps the kernel: a process's root
//! (`address_space.rs`'s `activate`), and the kernel's own, which
//! `paging.rs`'s boot install loads ([`install_kernel_root`]) and the
//! shutdown path loads again before it calls the firmware
//! ([`activate_kernel_root`]); `tools/architecture/check-kernel-unsafe.sh`
//! keeps those two calls in `paging.rs` and `lib.rs`.

use core::arch::asm;

/// CR3 as loaded: the root's physical address and the PCD/PWT bits.
pub(crate) fn current() -> u64 {
    let root: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe {
        asm!("mov {}, cr3", out(reg) root, options(nomem, nostack, preserves_flags));
    }
    root
}

/// Loads the kernel's own root (`paging::kernel_root_address`) into CR3.
/// Only the memory layer calls this, once its boot install has built the
/// kernel's tables (`tools/architecture/check-kernel-unsafe.sh` keeps it
/// there): what those tables map is the memory layer's policy, as for any
/// entry it writes through `trusted::page_table`.
pub(crate) fn install_kernel_root() {
    let root = crate::arch::x86_64::paging::kernel_root_address();
    // SAFETY: the kernel's root maps the kernel image, its stacks and the
    // direct map (`paging::install_initial_identity_map` builds it and
    // checks the result), so the code and data in use stay mapped; loading
    // CR3 also serializes the table writes before it.
    unsafe {
        asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
    }
}

/// Loads the kernel's own root on this CPU as `address_space`'s `activate`
/// loads any root: recorded for TLB shootdowns before the load, and counted
/// after it.
pub(crate) fn activate_kernel_root() {
    use crate::arch::x86_64::{paging, smp};
    smp::note_active_root(paging::kernel_root_address());
    install_kernel_root();
    smp::note_root_loaded();
}

/// Loads CR3 with the value it holds: the mappings stay as they are, and
/// this CPU drops its non-global translations.
pub(crate) fn reload() {
    // SAFETY: loading CR3 with the value it holds changes no mapping; it
    // only drops the non-global translations.
    unsafe {
        asm!(
            "mov {root}, cr3",
            "mov cr3, {root}",
            root = out(reg) _,
            options(nostack, preserves_flags)
        );
    }
}
