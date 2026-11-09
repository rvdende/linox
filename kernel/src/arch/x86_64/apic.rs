//! The local APIC: discovery, and its registers (MMIO in xAPIC mode,
//! MSRs in x2APIC mode) behind `trusted::mmio` and `trusted::msr`.

#![forbid(unsafe_code)]

use core::arch::x86_64::__cpuid;

use super::paging;
use crate::trusted::{mmio::Mmio, msr};

const CPUID_FEATURES: u32 = 1;
const CPUID_APIC: u32 = 1 << 9;
const CPUID_X2APIC: u32 = 1 << 21;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
const APIC_X2_MODE: u64 = 1 << 10;
const APIC_BASE_MASK: u64 = 0x000f_ffff_ffff_f000;
const APIC_IN_SERVICE_BASE: u32 = 0x100;
const APIC_TRIGGER_MODE_BASE: u32 = 0x180;
const APIC_INTERRUPT_REQUEST_BASE: u32 = 0x200;
const APIC_INTERRUPT_COMMAND_LOW: u32 = 0x300;
const APIC_INTERRUPT_COMMAND_HIGH: u32 = 0x310;
const APIC_END_OF_INTERRUPT: u32 = 0xb0;
const APIC_SPURIOUS_VECTOR: u32 = 0xf0;
const APIC_SOFTWARE_ENABLE: u32 = 1 << 8;
const APIC_DELIVERY_PENDING: u32 = 1 << 12;
const APIC_LEVEL_ASSERT: u32 = 1 << 14;
const APIC_TRIGGER_LEVEL: u32 = 1 << 15;
const APIC_DELIVERY_INIT: u32 = 5 << 8;
const APIC_DELIVERY_NMI: u32 = 4 << 8;
const APIC_DELIVERY_STARTUP: u32 = 6 << 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    XApic,
    X2Apic,
}

pub(crate) struct LocalApic {
    pub(crate) id: u8,
    pub(crate) mode: Mode,
    pub(crate) physical_base: u64,
    /// The xAPIC registers through the direct map; none in x2APIC mode,
    /// whose registers are MSRs.
    registers: Option<Mmio>,
}

impl LocalApic {
    /// Reads the local-APIC register at xAPIC offset `register` (a multiple
    /// of 16 below 0x400).
    pub(crate) fn read(&self, register: u32) -> u32 {
        debug_assert!(register < 0x400 && register.is_multiple_of(16));
        match &self.registers {
            Some(registers) => registers.read::<u32>(register as usize),
            None => msr::read_x2apic(register) as u32,
        }
    }

    /// Writes a local-APIC register, as `read` reads it.
    pub(crate) fn write(&self, register: u32, value: u32) {
        debug_assert!(register < 0x400 && register.is_multiple_of(16));
        match &self.registers {
            Some(registers) => registers.write::<u32>(register as usize, value),
            None => msr::write_x2apic(register, u64::from(value)),
        }
    }

    /// The local APIC at `physical_base` in `mode`, which must be the base
    /// IA32_APIC_BASE reported at discovery for an xAPIC.
    pub(crate) fn from_saved(id: u8, mode: Mode, physical_base: u64) -> Option<Self> {
        let registers = match mode {
            Mode::XApic => Some(Mmio::local_apic(physical_base, 0x400)?),
            Mode::X2Apic => None,
        };
        Some(Self {
            id,
            mode,
            physical_base,
            registers,
        })
    }

    pub(crate) fn mmio_uses_direct_map(&self) -> bool {
        self.mode == Mode::X2Apic
            || self.registers.is_some()
                && paging::direct_map_range_address(self.physical_base, 0x400).is_some()
    }

    pub(crate) fn vector_is_idle(&self, vector: u8) -> bool {
        let bank = u32::from(vector / 32) * 0x10;
        let bit = 1_u32 << (vector % 32);
        // These three register banks are read-only architectural state.
        self.read(APIC_IN_SERVICE_BASE + bank) & bit == 0
            && self.read(APIC_TRIGGER_MODE_BASE + bank) & bit == 0
            && self.read(APIC_INTERRUPT_REQUEST_BASE + bank) & bit == 0
    }

    pub(crate) fn start_processor(&self, target: u32, vector: u8) -> bool {
        if target == u32::from(self.id) || vector == 0 {
            return false;
        }
        if !self.send_ipi(
            target,
            APIC_DELIVERY_INIT | APIC_LEVEL_ASSERT | APIC_TRIGGER_LEVEL,
        ) {
            return false;
        }
        startup_delay(1_000_000);
        for _ in 0..2 {
            if !self.send_ipi(target, APIC_DELIVERY_STARTUP | u32::from(vector)) {
                return false;
            }
            startup_delay(200_000);
        }
        true
    }

    pub(crate) fn enable_software(&self) {
        let value = self.read(APIC_SPURIOUS_VECTOR);
        self.write(
            APIC_SPURIOUS_VECTOR,
            (value & !0xff) | 0xff | APIC_SOFTWARE_ENABLE,
        );
    }

    pub(crate) fn send_fixed(&self, target: u32, vector: u8) -> bool {
        vector >= 32 && self.send_ipi(target, u32::from(vector))
    }

    pub(crate) fn send_nmi(&self, target: u32) -> bool {
        self.send_ipi(target, APIC_DELIVERY_NMI)
    }

    pub(crate) fn end_of_interrupt(&self) {
        self.write(APIC_END_OF_INTERRUPT, 0);
    }

    fn send_ipi(&self, target: u32, command: u32) -> bool {
        match self.mode {
            Mode::XApic => {
                let Ok(target) = u8::try_from(target) else {
                    return false;
                };
                for _ in 0..1_000_000 {
                    if self.read(APIC_INTERRUPT_COMMAND_LOW) & APIC_DELIVERY_PENDING == 0 {
                        self.write(APIC_INTERRUPT_COMMAND_HIGH, u32::from(target) << 24);
                        self.write(APIC_INTERRUPT_COMMAND_LOW, command);
                        for _ in 0..1_000_000 {
                            if self.read(APIC_INTERRUPT_COMMAND_LOW) & APIC_DELIVERY_PENDING == 0 {
                                return true;
                            }
                            core::hint::spin_loop();
                        }
                        return false;
                    }
                    core::hint::spin_loop();
                }
                false
            }
            Mode::X2Apic => {
                msr::write_x2apic(
                    APIC_INTERRUPT_COMMAND_LOW,
                    (u64::from(target) << 32) | u64::from(command),
                );
                true
            }
        }
    }
}

fn startup_delay(iterations: usize) {
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

/// Discovers the bootstrap processor's already-enabled local APIC.
///
/// This is deliberately read-only. Interrupt delivery, MMIO access, timer
/// configuration, and global interrupt enable remain outside this milestone.
pub(crate) fn discover() -> Option<LocalApic> {
    // CPUID leaf 1 is mandatory on x86-64 and has no side effects.
    let features = __cpuid(CPUID_FEATURES);
    if features.edx & CPUID_APIC == 0 {
        return None;
    }

    // CPUID reports an architectural APIC, for which IA32_APIC_BASE is
    // defined.
    let base_msr = msr::apic_base();
    if base_msr & APIC_GLOBAL_ENABLE == 0 {
        return None;
    }

    let mode = if features.ecx & CPUID_X2APIC != 0 && base_msr & APIC_X2_MODE != 0 {
        Mode::X2Apic
    } else {
        Mode::XApic
    };
    let physical_base = base_msr & APIC_BASE_MASK;
    if physical_base == 0 {
        return None;
    }

    LocalApic::from_saved((features.ebx >> 24) as u8, mode, physical_base)
}
