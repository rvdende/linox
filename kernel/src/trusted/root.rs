//! The page-table root register, CR3: reading which root is loaded,
//! reloading the same root to drop this CPU's non-global translations, and
//! loading another root.
//!
//! A root is loaded only as a [`Root`], which only the memory layer makes
//! (`address_space.rs`, `memory.rs`, `arch/x86_64/paging.rs` and
//! `trusted/`; `tools/architecture/check-kernel-unsafe.sh` keeps
//! [`Root::from_physical`] there, as it keeps `Frame::from_physical`): the
//! code that builds roots and can vouch that a root maps the kernel and
//! stays allocated while it is loaded. [`Root::from_physical`] checks
//! what it can cheaply, every time: the frame is page-aligned and
//! direct-mapped, its direct-map entry (PML4 entry 256) is the kernel
//! root's and supervisor-only, and its first entry (the kernel's low
//! mappings: the identity-mapped image, its stacks) is present; a root
//! that was released is scrubbed to zero and fails. The kernel's own root
//! ([`Root::kernel`]) may be named by anyone. `paging.rs`'s boot install
//! loads it ([`install_kernel_root`]) before the direct map exists, and
//! the shutdown path loads it again before it calls the firmware
//! ([`activate_kernel_root`]). A process root that
//! `paging::validated_user_root_frames` checked (it maps the kernel's
//! shared entries exactly as the kernel's root does) is a `Root` too
//! (`Root::from(&ValidatedUserRootFrames)`), so every load after boot goes
//! through [`activate`].

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

const PRESENT: u64 = 1 << 0;
const USER: u64 = 1 << 2;
const ACCESSED: u64 = 1 << 5;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
/// The PML4 entry of the kernel's direct map.
const DIRECT_MAP_ENTRY: usize = 256;

/// A page-table root that may be loaded into CR3 (see the module comment
/// for who makes one and what is checked).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Root {
    physical: u64,
}

impl Root {
    /// The kernel's own root.
    pub(crate) fn kernel() -> Self {
        Self {
            physical: crate::arch::x86_64::paging::kernel_root_address(),
        }
    }

    /// The root at `physical`, if it passes the checks of the module
    /// comment. Only the memory layer calls this.
    pub(crate) fn from_physical(physical: u64) -> Option<Self> {
        let kernel = Self::kernel();
        if physical == kernel.physical {
            return Some(kernel);
        }
        let table = super::page_table::PageTable::from_physical(physical)?;
        let kernel_table = super::page_table::PageTable::from_physical(kernel.physical)?;
        let direct = kernel_table.get(DIRECT_MAP_ENTRY);
        let candidate = table.get(DIRECT_MAP_ENTRY);
        (direct & PRESENT != 0
            && candidate & !ACCESSED == direct & !ACCESSED
            && candidate & USER == 0
            && table.get(0) & PRESENT != 0)
            .then_some(Self { physical })
    }
}

impl From<&crate::arch::x86_64::paging::ValidatedUserRootFrames> for Root {
    /// A process root the memory layer validated: only that check makes a
    /// `ValidatedUserRootFrames`, which stands for the kernel mappings a
    /// `Root` promises.
    fn from(frames: &crate::arch::x86_64::paging::ValidatedUserRootFrames) -> Self {
        Self {
            physical: frames.root(),
        }
    }
}

/// The physical address of the root loaded on this CPU (CR3 without its
/// PCD/PWT bits).
pub(crate) fn current_address() -> u64 {
    current() & ADDRESS_MASK
}

/// Loads `root` into CR3 on this CPU, recorded for TLB shootdowns before
/// the load and counted after it.
pub(crate) fn activate(root: Root) {
    use crate::arch::x86_64::smp;
    smp::note_active_root(root.physical);
    // SAFETY: a `Root` maps the kernel as the kernel's own root does and
    // stays allocated while it is loaded (its maker's promise, see the
    // module comment, with the checks `from_physical` made), so the code,
    // stacks and data in use stay mapped; loading CR3 also serializes the
    // table writes before it.
    unsafe {
        asm!("mov cr3, {}", in(reg) root.physical, options(nostack, preserves_flags));
    }
    smp::note_root_loaded();
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

/// Loads the kernel's own root on this CPU as [`activate`] loads any root.
pub(crate) fn activate_kernel_root() {
    activate(Root::kernel());
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
