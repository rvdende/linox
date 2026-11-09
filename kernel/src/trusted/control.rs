//! Reading the control registers, the stack pointer and the code segment,
//! turning on supervisor write protection, and raising #UD on purpose.
//!
//! Reads have no side effects. Setting CR0.WP only makes the kernel's own
//! writes obey read-only page-table entries, so it can turn a stray write
//! into a page fault but never make one succeed. `ud2` raises an exception
//! the installed handler reports; it is how bring-up's crash test exercises
//! that path.

use core::arch::asm;

const CR0_WRITE_PROTECT: u64 = 1 << 16;

/// CR0, CR2, CR3 and CR4, read in that order.
pub(crate) fn registers() -> [u64; 4] {
    let (cr0, cr2, cr3, cr4): (u64, u64, u64, u64);
    // SAFETY: reading control registers has no side effects.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    [cr0, cr2, cr3, cr4]
}

/// CR0.
pub(crate) fn cr0() -> u64 {
    let cr0: u64;
    // SAFETY: reading CR0 has no side effects.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    }
    cr0
}

/// Sets CR0.WP and reports whether it reads back set.
pub(crate) fn enable_write_protect() -> bool {
    let cr0 = self::cr0() | CR0_WRITE_PROTECT;
    // SAFETY: see the module comment; the other bits are written back as
    // they were read.
    unsafe {
        asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
    }
    self::cr0() & CR0_WRITE_PROTECT != 0
}

/// The stack pointer where this is called.
pub(crate) fn stack_pointer() -> u64 {
    let stack: u64;
    // SAFETY: reading RSP has no side effects.
    unsafe { asm!("mov {}, rsp", out(reg) stack, options(nomem, nostack, preserves_flags)) };
    stack
}

/// The code segment selector loaded now.
pub(crate) fn code_segment() -> u16 {
    let selector: u16;
    // SAFETY: reading CS has no side effects.
    unsafe { asm!("mov {0:x}, cs", out(reg) selector, options(nomem, nostack, preserves_flags)) };
    selector
}

/// Raises an invalid-opcode exception (`ud2`), which the exception handler
/// reports; it does not return.
pub(crate) fn raise_invalid_opcode() -> ! {
    // SAFETY: see the module comment; the handlers installed in bring-up
    // and the kernel report the exception and halt.
    unsafe { asm!("ud2", options(nomem, nostack, noreturn)) }
}
