//! The processor's timestamp counter.

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
