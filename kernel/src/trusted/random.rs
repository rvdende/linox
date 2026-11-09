//! The processor's random number generator.

use core::arch::asm;

/// The processor's RDRAND instruction, which only [`Rdrand::detect`] hands
/// out, after CPUID says the processor has it (RDRAND on a processor
/// without it raises #UD).
#[derive(Clone, Copy)]
pub(crate) struct Rdrand(());

impl Rdrand {
    /// RDRAND, if the processor has it (CPUID leaf 1, ECX bit 30).
    pub(crate) fn detect() -> Option<Self> {
        (core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0).then_some(Self(()))
    }

    /// A 64-bit value from RDRAND, or `None` when the generator has none
    /// ready.
    pub(crate) fn read(self) -> Option<u64> {
        let value: u64;
        let ready: u8;
        // SAFETY: RDRAND only writes its output register and the flags,
        // which SETC reads; the processor has it (`detect`).
        unsafe {
            asm!(
                "rdrand {value}",
                "setc {ready}",
                value = out(reg) value,
                ready = out(reg_byte) ready,
                options(nomem, nostack)
            );
        }
        (ready != 0).then_some(value)
    }
}
