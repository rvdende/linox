//! Reading the control registers, the stack pointer, the code segment and
//! the task register, turning on supervisor write protection and CR4's
//! protection features, and raising #UD and #BP on purpose.
//!
//! Reads have no side effects. Setting CR0.WP only makes the kernel's own
//! writes obey read-only page-table entries, so it can turn a stray write
//! into a page fault but never make one succeed. Likewise the CR4 features
//! [`enable_cr4_feature`] turns on (SMEP, SMAP, UMIP) only refuse accesses;
//! CR4.TSD ([`set_user_time_stamp_access`]) only decides whether user mode
//! may read the timestamp counter. `ud2` raises an exception the installed
//! handler reports; it is how bring-up's crash test exercises that path,
//! and `int3` ([`raise_breakpoint`]) calls the breakpoint handler, which
//! returns.

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

/// CR2: the linear address of the last page fault.
pub(crate) fn fault_address() -> u64 {
    let cr2: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
    }
    cr2
}

/// The task register's selector (`str`).
pub(crate) fn task_register() -> u16 {
    let selector: u16;
    // SAFETY: reading the task register has no side effects.
    unsafe {
        asm!("str {0:x}", out(reg) selector, options(nomem, nostack, preserves_flags));
    }
    selector
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

/// The CR4 protection features [`enable_cr4_feature`] turns on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Cr4Feature {
    /// Supervisor-mode execution prevention.
    Smep,
    /// Supervisor-mode access prevention.
    Smap,
    /// User-mode instruction prevention.
    Umip,
}

const CR4_TSD: u64 = 1 << 2;

impl Cr4Feature {
    const fn bit(self) -> u64 {
        match self {
            Self::Smep => 1 << 20,
            Self::Smap => 1 << 21,
            Self::Umip => 1 << 11,
        }
    }
}

/// CR4.
pub(crate) fn cr4() -> u64 {
    let cr4: u64;
    // SAFETY: reading CR4 has no side effects.
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr4
}

fn write_cr4(cr4: u64) {
    // SAFETY: callers change only the bits the module comment lists, which
    // restrict what the kernel and user mode may do; `clac` after it keeps
    // AC clear, so turning on SMAP takes effect at once.
    unsafe {
        asm!("mov cr4, {}", "clac", in(reg) cr4, options(nomem, nostack));
    }
}

/// Turns on `feature` (the caller checked CPUID); whether it reads back on.
pub(crate) fn enable_cr4_feature(feature: Cr4Feature) -> bool {
    write_cr4(cr4() | feature.bit());
    cr4_feature_enabled(feature)
}

/// Whether `feature` is on.
pub(crate) fn cr4_feature_enabled(feature: Cr4Feature) -> bool {
    cr4() & feature.bit() != 0
}

/// Lets user mode read the timestamp counter (`allowed`) or makes rdtsc
/// and rdtscp fault there (CR4.TSD); CR4 is written only when it changes.
pub(crate) fn set_user_time_stamp_access(allowed: bool) {
    let cr4 = cr4();
    if (cr4 & CR4_TSD == 0) != allowed {
        // SAFETY: as in `write_cr4`; TSD only governs user-mode rdtsc.
        unsafe {
            asm!("mov cr4, {}", in(reg) cr4 ^ CR4_TSD, options(nomem, nostack, preserves_flags));
        }
    }
}

/// Raises a breakpoint exception (`int3`), whose installed handler
/// (`trusted::entry`'s breakpoint stub) records it and returns.
pub(crate) fn raise_breakpoint() {
    // SAFETY: vector 3's gate names the breakpoint stub, which saves and
    // restores every register around its handler and returns with IRETQ.
    unsafe { asm!("int3", options(nomem, nostack)) };
}
