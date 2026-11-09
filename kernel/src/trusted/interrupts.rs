//! This CPU's interrupt flag (RFLAGS.IF), and halting until an interrupt.
//!
//! Each operation is one of the instruction sequences the kernel used inline
//! before this module existed, with the same `asm!` options, so the compiler
//! orders them against the surrounding code exactly as it did then.
//!
//! Why these are safe: `cli`, `sti` and `hlt` touch no memory. What enabling
//! interrupts can do is run an installed interrupt handler on this CPU before
//! the next instruction, and the kernel's handlers are ordinary safe Rust
//! (behind the entry stubs in `trusted::entry` and the CPU core's own) that
//! reach shared state only through atomics, ranked locks and the kernel-entry
//! lock. A handler that wants a lock the interrupted code holds fails the
//! rank check or spins; it never gets a second reference to the data. So the
//! interrupt flag is a scheduling and deadlock-avoidance tool here, never a
//! memory-safety one, and the invariant every `unsafe` block elsewhere must
//! keep is the converse: no unsafe code may rely on interrupts staying off
//! for the soundness of a reference it holds across a call into code that
//! might enable them. (The CPU core's owner cells, `cpu/`, document that
//! they are only reached with the kernel-entry lock held, which handlers
//! take too.)
//!
//! Halting with interrupts off ([`park`]) stops the CPU for good, short of
//! an NMI, SMI or INIT; that is a hang, not a memory-safety matter either.

use core::arch::asm;

const INTERRUPT_FLAG: u64 = 1 << 9;

/// Whether interrupts were enabled before [`save_and_disable`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InterruptState {
    enabled: bool,
}

/// Disables interrupts on this CPU and returns whether they were enabled.
pub(crate) fn save_and_disable() -> InterruptState {
    let flags: u64;
    // SAFETY: reading RFLAGS through the stack and clearing IF touch only
    // this CPU's flags and the two stack slots pushfq/pop use (see the
    // module comment for why clearing IF is safe).
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        asm!("cli", options(nomem, nostack));
    }
    InterruptState {
        enabled: flags & INTERRUPT_FLAG != 0,
    }
}

/// Enables interrupts again if `state` says they were enabled.
pub(crate) fn restore(state: InterruptState) {
    if state.enabled {
        enable();
    }
}

/// Enables interrupts on this CPU (`sti`).
pub(crate) fn enable() {
    // SAFETY: see the module comment.
    unsafe { asm!("sti", options(nomem, nostack)) };
}

/// Disables interrupts on this CPU (`cli`).
pub(crate) fn disable() {
    // SAFETY: see the module comment.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Lets an interrupt pending on this CPU in for one instruction
/// (`sti; nop; cli`: `sti` takes effect after the next instruction).
pub(crate) fn admit_pending() {
    // SAFETY: see the module comment.
    unsafe { asm!("sti", "nop", "cli", options(nomem, nostack)) };
}

/// Enables interrupts, halts until one arrives and has been handled, and
/// disables them again (`sti; hlt; cli`: no interrupt can slip in between
/// `sti` and `hlt`).
pub(crate) fn wait() {
    // SAFETY: see the module comment.
    unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

/// Halts until the next interrupt (`hlt`), leaving the interrupt flag as it
/// is: with interrupts off only an NMI, SMI or INIT ends the halt.
pub(crate) fn halt() {
    // SAFETY: see the module comment.
    unsafe { asm!("hlt", options(nomem, nostack)) };
}

/// Disables interrupts and halts, for good (`cli; hlt` in a loop).
pub(crate) fn park() -> ! {
    loop {
        // SAFETY: see the module comment.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
