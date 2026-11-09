//! The processor's timestamp counter, and the processor id beside it
//! (IA32_TSC_AUX).

use core::arch::asm;

/// Reads the timestamp counter after ordering earlier loads (`lfence;
/// rdtsc`).
pub(crate) fn read() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: LFENCE and RDTSC touch no memory and change no state but the
    // two output registers; LFENCE keeps an earlier load from passing RDTSC.
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// IA32_TSC_AUX, read with RDPID: the processor id the kernel stores there
/// (`trusted::cpu_tables`). A processor without RDPID raises #UD, which
/// the kernel reports as a fatal exception; callers check CPUID first.
pub(crate) fn processor_id() -> u64 {
    let id: u64;
    // SAFETY: RDPID only reads IA32_TSC_AUX into a register.
    unsafe { asm!("rdpid {}", out(reg) id, options(nomem, nostack, preserves_flags)) };
    id
}

/// The timestamp counter and IA32_TSC_AUX, read together with RDTSCP. A
/// processor without RDTSCP raises #UD, as for [`processor_id`].
pub(crate) fn read_with_processor_id() -> (u64, u32) {
    let low: u32;
    let high: u32;
    let id: u32;
    // SAFETY: RDTSCP only reads the timestamp counter and IA32_TSC_AUX into
    // registers.
    unsafe {
        asm!(
            "rdtscp",
            out("eax") low,
            out("edx") high,
            out("ecx") id,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((u64::from(high) << 32) | u64::from(low), id)
}
