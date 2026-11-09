//! The model-specific registers the kernel reads and writes outside the CPU
//! core (`arch/x86_64/cpu`, which keeps its own accessors for the system
//! call and segment MSRs).
//!
//! The registers are named, not numbered, because what makes an MSR write
//! dangerous depends on the register: EFER can turn off long mode or NX,
//! the system-call MSRs move the kernel entry point. The ones here:
//!
//! - IA32_APIC_BASE ([`apic_base`]), only read: where the local APIC's
//!   registers are and which mode it runs in;
//! - the local APIC's registers in x2APIC mode ([`read_x2apic`],
//!   [`write_x2apic`]). Like the same registers in xAPIC mode (MMIO), they
//!   reach the interrupt controller and never memory;
//! - the page attribute table, written only with the kernel's one layout
//!   by [`install_write_combining_pat`].
//!
//! Reading an MSR the processor does not implement raises #GP, which the
//! kernel reports as a fatal exception: a crash, not a corruption.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const IA32_APIC_BASE: u32 = 0x1b;
const IA32_PAT: u32 = 0x277;
const X2APIC_FIRST: u32 = 0x800;
// WB, WC, UC-, UC repeated. Entry 1 (PWT only) is write-combining instead of
// the power-on write-through; every other mapping that sets PWT also sets PCD.
const PAT_WITH_WRITE_COMBINING: u64 = 0x0007_0106_0007_0106;
const APIC_BASE_MASK: u64 = 0x000f_ffff_ffff_f000;

/// The local APIC's register base as IA32_APIC_BASE last reported it (0
/// before the first read), for `trusted::mmio::Mmio::local_apic`. Nothing
/// moves the base after boot, so every CPU reports the same one.
static REPORTED_APIC_BASE: AtomicU64 = AtomicU64::new(0);

fn read(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: callers pass one of the registers in the module comment;
    // reading it changes no state.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// IA32_APIC_BASE.
pub(crate) fn apic_base() -> u64 {
    let value = read(IA32_APIC_BASE);
    REPORTED_APIC_BASE.store(value & APIC_BASE_MASK, Ordering::Release);
    value
}

/// The register base IA32_APIC_BASE last reported, if it has been read.
pub(super) fn reported_apic_base() -> Option<u64> {
    match REPORTED_APIC_BASE.load(Ordering::Acquire) {
        0 => None,
        base => Some(base),
    }
}

/// The x2APIC MSR of the local-APIC register at xAPIC offset `register`
/// (a multiple of 16 below 0x400).
fn x2apic_msr(register: u32) -> u32 {
    assert!(
        register < 0x400 && register.is_multiple_of(16),
        "not a local-APIC register"
    );
    X2APIC_FIRST + register / 16
}

pub(crate) fn read_x2apic(register: u32) -> u64 {
    read(x2apic_msr(register))
}

pub(crate) fn write_x2apic(register: u32, value: u64) {
    // SAFETY: an x2APIC register write reaches the interrupt controller,
    // never memory (see the module comment).
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") x2apic_msr(register),
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Programs this CPU's page attribute table: entry 0 stays write-back, PWT
/// alone selects write-combining (entry 1) and PCD|PWT uncached (entry 3),
/// as Linux sets it up.
pub(crate) fn install_write_combining_pat() {
    // SAFETY: IA32_PAT only changes what the PAT, PCD and PWT bits of page
    // table entries mean. Entry 0 (no bits) stays write-back and entries 2
    // and 3 keep their defaults, so existing mappings keep their types;
    // entry 1 (PWT alone) becomes write-combining, which is what the
    // framebuffer window and device pages setting it ask for.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") IA32_PAT,
            in("eax") PAT_WITH_WRITE_COMBINING as u32,
            in("edx") (PAT_WITH_WRITE_COMBINING >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
}
