//! The processor's extended user state (x87, SSE and AVX): turning on the
//! operating system's support for it, resetting it, and saving it to and
//! restoring it from an [`ExtendedState`] area.
//!
//! [`enable`] sets CR0.MP and CR0.NE, clears CR0.EM (bit 2), sets CR4.OSFXSR,
//! OSXMMEXCPT and OSXSAVE and loads XCR0 with x87|SSE|AVX; those only
//! decide how the FPU and vector units behave and are saved, never what
//! memory the kernel reaches. It then checks that the save area the three
//! components need (CPUID.(EAX=0DH, ECX=0):EBX) fits an [`ExtendedState`],
//! and only after that do [`save`] and [`restore`] run XSAVE and XRSTOR:
//! XSAVE writes at most that many bytes into the 64-byte aligned area it is
//! handed by `&mut`, and XRSTOR only reads it. Restoring an area whose
//! header is malformed (a ptrace-style write of user bytes) raises #GP,
//! which the kernel reports as a crash; it cannot reach memory.

use core::arch::asm;
use core::arch::x86_64::__cpuid_count;
use core::sync::atomic::{AtomicBool, Ordering};

/// Bytes of an extended-state save area.
pub(crate) const EXTENDED_STATE_SIZE: usize = 1024;
const CR0_MP: u64 = 1 << 1;
const CR0_NE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;
const CPUID_EXTENDED_STATE: u32 = 0xd;

/// An XSAVE area for the x87, SSE and AVX components.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub(crate) struct ExtendedState(pub(crate) [u8; EXTENDED_STATE_SIZE]);

impl ExtendedState {
    pub(crate) const ZERO: Self = Self([0; EXTENDED_STATE_SIZE]);
}

/// Set once [`enable`] checked the save area fits an [`ExtendedState`].
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Turns on x87, SSE and AVX state for user mode as the module comment
/// says (the caller checked CPUID for XSAVE and AVX), resets the state,
/// and reports whether saving and restoring it is available.
pub(crate) fn enable() -> bool {
    // SAFETY: see the module comment: these control bits and XCR0 govern
    // the FPU and vector units and what XSAVE saves, not memory access.
    unsafe {
        asm!(
            "mov {cr0}, cr0",
            "or {cr0}, {cr0_set}",
            "btr {cr0}, 2",
            "mov cr0, {cr0}",
            "mov {cr4}, cr4",
            "or {cr4}, {cr4_set}",
            "mov cr4, {cr4}",
            "xor ecx, ecx",
            "mov eax, 7",
            "xor edx, edx",
            "xsetbv",
            cr0 = out(reg) _,
            cr4 = out(reg) _,
            cr0_set = const CR0_MP | CR0_NE,
            cr4_set = const CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE,
            out("ecx") _,
            out("eax") _,
            out("edx") _,
            options(nomem, nostack, preserves_flags)
        );
    }
    let size = __cpuid_count(CPUID_EXTENDED_STATE, 0).ebx as usize;
    let enabled = size <= EXTENDED_STATE_SIZE;
    if enabled {
        reset();
    }
    ENABLED.store(enabled, Ordering::Release);
    enabled
}

/// Puts the x87, SSE and AVX state in its initial condition (FNINIT, the
/// default MXCSR, VZEROALL).
pub(crate) fn reset() {
    let default_mxcsr = 0x1f80_u32;
    // SAFETY: these load only FPU and vector registers; LDMXCSR reads the
    // local `default_mxcsr`.
    unsafe {
        asm!("fninit", options(nostack));
        asm!("ldmxcsr [{}]", in(reg) &default_mxcsr, options(nostack));
        asm!("vzeroall", options(nostack));
    }
}

/// Saves the x87, SSE and AVX state into `area`; false (saving nothing)
/// unless [`enable`] succeeded.
pub(crate) fn save(area: &mut ExtendedState) -> bool {
    if !ENABLED.load(Ordering::Acquire) {
        return false;
    }
    // SAFETY: `area` is a 64-byte aligned, exclusively borrowed area of
    // EXTENDED_STATE_SIZE bytes, at least what the three components take
    // (checked by `enable`).
    unsafe {
        asm!(
            "xsave64 [{}]",
            in(reg) core::ptr::from_mut(area),
            in("eax") 7_u32,
            in("edx") 0_u32,
            options(nostack)
        );
    }
    true
}

/// Loads the x87, SSE and AVX state from `area`; false (loading nothing)
/// unless [`enable`] succeeded.
pub(crate) fn restore(area: &ExtendedState) -> bool {
    if !ENABLED.load(Ordering::Acquire) {
        return false;
    }
    // SAFETY: XRSTOR reads the 64-byte aligned area and loads only FPU and
    // vector registers (a malformed header raises #GP: the module comment).
    unsafe {
        asm!(
            "xrstor64 [{}]",
            in(reg) core::ptr::from_ref(area),
            in("eax") 7_u32,
            in("edx") 0_u32,
            options(nostack, readonly)
        );
    }
    true
}
