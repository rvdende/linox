//! The model-specific registers the kernel reads and writes (the CPU
//! tables' GS_BASE, KERNEL_GS_BASE and TSC_AUX are `trusted::cpu_tables`').
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
//!   by [`install_write_combining_pat`];
//! - FS_BASE ([`fs_base`], [`set_fs_base`]): user mode's thread pointer.
//!   The kernel itself never uses FS, so any canonical value is safe for
//!   it;
//! - EFER.NXE ([`enable_execute_disable`]): turned on, never off, so page
//!   table entries' NX bits take effect;
//! - the `syscall` MSRs ([`configure_linux_syscall`]): STAR with the
//!   kernel's and user selectors, LSTAR with `trusted::entry`'s stub only,
//!   the flag mask, and EFER.SCE; and putting back what the CPU held
//!   before ([`restore_linux_syscall`]).
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

const IA32_EFER: u32 = 0xc000_0080;
const IA32_STAR: u32 = 0xc000_0081;
const IA32_LSTAR: u32 = 0xc000_0082;
const IA32_FMASK: u32 = 0xc000_0084;
const IA32_FS_BASE: u32 = 0xc000_0100;
const EFER_SCE: u64 = 1;
const EFER_NXE: u64 = 1 << 11;
/// What `syscall` clears in RFLAGS on entry: IF, DF and AC.
const SYSCALL_FLAG_MASK: u64 = (1 << 9) | (1 << 10) | (1 << 18);

/// Writes one of the registers the module comment lists, with a value it
/// allows (each caller says which).
fn write(msr: u32, value: u64) {
    // SAFETY: the callers write only the registers and values the module
    // comment lists; none of them makes the processor reach memory the
    // kernel does not expect it to.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

/// FS_BASE: user mode's thread pointer as loaded.
pub(crate) fn fs_base() -> u64 {
    read(IA32_FS_BASE)
}

/// Loads `value` into FS_BASE if it is a canonical address; whether it
/// reads back so.
pub(crate) fn set_fs_base(value: u64) -> bool {
    if (1 << 47..0xffff_8000_0000_0000).contains(&value) {
        return false;
    }
    write(IA32_FS_BASE, value);
    fs_base() == value
}

/// Sets EFER.NXE; whether it reads back set. The caller checked CPUID.
pub(crate) fn enable_execute_disable() -> bool {
    write(IA32_EFER, read(IA32_EFER) | EFER_NXE);
    execute_disable_enabled()
}

/// Whether EFER.NXE is set.
pub(crate) fn execute_disable_enabled() -> bool {
    read(IA32_EFER) & EFER_NXE != 0
}

/// The `syscall` MSRs (EFER, STAR, LSTAR, FMASK) and FS_BASE as they were
/// before [`configure_linux_syscall`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SyscallMsrs {
    efer: u64,
    star: u64,
    lstar: u64,
    fmask: u64,
    fs_base: u64,
}

/// Points `syscall` at `trusted::entry`'s Linux system-call stub, with the
/// kernel's selectors and flag mask, and enables it (EFER.SCE). Returns
/// what the registers held before, or None (with them put back) if they
/// do not read back as written.
pub(crate) fn configure_linux_syscall() -> Option<SyscallMsrs> {
    use super::cpu_tables::{KERNEL_CODE_SELECTOR, USER_DATA_SELECTOR};
    // SYSRET loads SS from STAR[63:48] + 8 and CS from STAR[63:48] + 16.
    // Intel forces RPL 3 on both selectors, but AMD copies SS unchanged, so
    // the base must already carry RPL 3 or the next IRET to user mode faults.
    let sysret_base = u64::from(USER_DATA_SELECTOR) - 8;
    let star = (sysret_base << 48) | (u64::from(KERNEL_CODE_SELECTOR) << 32);
    let lstar = super::entry::linux_system_call_entry();
    let saved = SyscallMsrs {
        efer: read(IA32_EFER),
        star: read(IA32_STAR),
        lstar: read(IA32_LSTAR),
        fmask: read(IA32_FMASK),
        fs_base: fs_base(),
    };
    write(IA32_STAR, star);
    write(IA32_LSTAR, lstar);
    write(IA32_FMASK, SYSCALL_FLAG_MASK);
    write(IA32_EFER, read(IA32_EFER) | EFER_SCE);
    let valid = read(IA32_STAR) == star
        && read(IA32_LSTAR) == lstar
        && read(IA32_FMASK) == SYSCALL_FLAG_MASK
        && read(IA32_EFER) & EFER_SCE != 0;
    if valid {
        Some(saved)
    } else {
        let _ = restore_linux_syscall(saved);
        None
    }
}

/// Puts back the registers [`configure_linux_syscall`] found; whether they
/// read back so.
pub(crate) fn restore_linux_syscall(saved: SyscallMsrs) -> bool {
    write(IA32_FS_BASE, saved.fs_base);
    write(IA32_FMASK, saved.fmask);
    write(IA32_LSTAR, saved.lstar);
    write(IA32_STAR, saved.star);
    write(IA32_EFER, saved.efer);
    read(IA32_EFER) == saved.efer
        && read(IA32_STAR) == saved.star
        && read(IA32_LSTAR) == saved.lstar
        && read(IA32_FMASK) == saved.fmask
        && fs_base() == saved.fs_base
}
