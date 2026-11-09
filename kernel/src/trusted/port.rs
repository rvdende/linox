//! The I/O ports the kernel uses, each behind a typed handle.
//!
//! An `in` or `out` instruction reaches a device, never memory the program
//! reads, so what makes a port access dangerous is which device it reaches:
//! the PCI configuration ports can move a BAR or turn on bus mastering, the
//! legacy DMA controller can write anywhere in the first 16 MiB, and a few
//! ports reset the machine. This module therefore names the ports the
//! kernel needs instead of taking a port number:
//!
//! - [`Port8::com1`], the eight registers of the first UART (the serial
//!   console);
//! - [`Port8::PIT_CHANNEL_2`], [`Port8::PIT_COMMAND`] and
//!   [`Port8::SPEAKER_CONTROL`], the programmable interval timer's channel 2
//!   and its gate, which calibrate the local APIC timer;
//! - [`PmTimer`], the ACPI power-management timer's counter, only read;
//! - the PCI configuration ports, reached only through
//!   `trusted::pci_config`.
//!
//! None of these devices reads or writes RAM, so every access is safe; a
//! port not listed here needs a new handle and the argument for it.

use core::arch::asm;

const COM1: u16 = 0x3f8;
const COM1_REGISTERS: u16 = 8;

/// An 8-bit port from the list in the module comment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Port8(u16);

impl Port8 {
    pub(crate) const PIT_CHANNEL_2: Self = Self(0x42);
    pub(crate) const PIT_COMMAND: Self = Self(0x43);
    /// The keyboard controller's port B: the PIT channel 2 gate, the
    /// speaker enable and channel 2's output.
    pub(crate) const SPEAKER_CONTROL: Self = Self(0x61);

    /// Register `register` (below 8) of COM1.
    pub(crate) const fn com1(register: u16) -> Self {
        assert!(register < COM1_REGISTERS, "COM1 has eight registers");
        Self(COM1 + register)
    }

    pub(crate) fn read(self) -> u8 {
        let value: u8;
        // SAFETY: the port is one of the devices in the module comment,
        // none of which touches memory.
        unsafe {
            asm!(
                "in al, dx",
                in("dx") self.0,
                out("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }

    pub(crate) fn write(self, value: u8) {
        // SAFETY: writing a register of one of the devices in the module
        // comment changes only that device's state, never memory.
        unsafe {
            asm!(
                "out dx, al",
                in("dx") self.0,
                in("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

/// The ACPI power-management timer's counter port, as the FADT names it.
/// It is only ever read, and reading it has no side effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PmTimer(u16);

impl PmTimer {
    pub(crate) fn new(port: u16) -> Self {
        Self(port)
    }

    pub(crate) fn read(self) -> u32 {
        let value: u32;
        // SAFETY: a 32-bit read of the port the firmware describes as the
        // PM timer. A port read reaches no memory; if the firmware named a
        // wrong port, the worst it does is read some other device's
        // register.
        unsafe {
            asm!(
                "in eax, dx",
                in("dx") self.0,
                out("eax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }
}

/// The PCI configuration mechanism #1 ports, for `trusted::pci_config`.
pub(super) mod pci {
    use core::arch::asm;

    const CONFIG_ADDRESS: u16 = 0xcf8;
    const CONFIG_DATA: u16 = 0xcfc;

    pub(in crate::trusted) fn select(address: u32) {
        // SAFETY: selecting a configuration register touches no memory and
        // changes nothing but which register CONFIG_DATA reaches.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") CONFIG_ADDRESS,
                in("eax") address,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    pub(in crate::trusted) fn read_u32() -> u32 {
        let value: u32;
        // SAFETY: reading CONFIG_DATA returns the selected configuration
        // register and touches no memory; see `pci_config` for why
        // configuration accesses are safe.
        unsafe {
            asm!(
                "in eax, dx",
                in("dx") CONFIG_DATA,
                out("eax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }

    /// Reads the 16 bits at byte `half` (0 or 2) of the selected dword.
    pub(in crate::trusted) fn read_u16(half: u16) -> u16 {
        let value: u16;
        // SAFETY: a 16-bit read of the selected register (CONFIG_DATA plus
        // 0 or 2), touching no memory, as `read_u32`.
        unsafe {
            asm!(
                "in ax, dx",
                in("dx") CONFIG_DATA + half,
                out("ax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }

    pub(in crate::trusted) fn write_u32(value: u32) {
        // SAFETY: writes the selected configuration register, which changes
        // a device's decoding or bus mastering but no memory (`pci_config`
        // says why that is the same power as a device register write).
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") CONFIG_DATA,
                in("eax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    /// Writes the 16 bits at byte `half` (0 or 2) of the selected dword.
    pub(in crate::trusted) fn write_u16(half: u16, value: u16) {
        // SAFETY: as `write_u32`, for the 16 bits at CONFIG_DATA plus 0
        // or 2.
        unsafe {
            asm!(
                "out dx, ax",
                in("dx") CONFIG_DATA + half,
                in("ax") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}
