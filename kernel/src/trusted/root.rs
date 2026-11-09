//! The page-table root register, CR3, as far as code outside the memory
//! layer may use it: reading which root is loaded, and reloading the same
//! root to drop this CPU's non-global translations.
//!
//! Loading a different root stays with the memory layer
//! (`address_space.rs`'s `activate`, `paging.rs`'s boot install), the only
//! code that builds roots and can vouch that a root maps the kernel.

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
