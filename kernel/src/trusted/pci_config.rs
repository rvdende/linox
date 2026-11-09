//! PCI configuration space through configuration mechanism #1 (the
//! 0xcf8/0xcfc port pair every x86-64 PC chipset has).
//!
//! A function is named by bus, device (below 32) and function (below 8);
//! `offset` is a byte offset into its 256-byte header, rounded down to the
//! dword (or, for the 16-bit accesses, the word inside it) the hardware
//! reaches. A function that does not exist reads as all ones.
//!
//! Why this is safe: configuration accesses reach the PCI host bridge and
//! the function's own registers, never RAM. A write can change what a
//! device decodes or whether it may master the bus, and so what it can
//! reach by DMA; that is the same power a device register write has
//! (`trusted::mmio`), and what DMA may reach is the I/O MMU's policy, not a
//! property of the access. Every write in the kernel is to a function its
//! caller drives.
//!
//! The address and data ports are one shared pair: as before this module
//! existed, callers do not run configuration accesses concurrently (boot,
//! bring-up and device start-up run on one CPU at a time).

use super::port::pci;

const CONFIG_ENABLE: u32 = 1 << 31;

fn select(bus: u8, device: u8, function: u8, offset: u8) {
    pci::select(
        CONFIG_ENABLE
            | u32::from(bus) << 16
            | u32::from(device) << 11
            | u32::from(function) << 8
            | u32::from(offset & 0xfc),
    );
}

pub(crate) fn read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    select(bus, device, function, offset);
    pci::read_u32()
}

pub(crate) fn read_u16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    select(bus, device, function, offset);
    pci::read_u16(u16::from(offset & 2))
}

pub(crate) fn write_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    select(bus, device, function, offset);
    pci::write_u32(value);
}

pub(crate) fn write_u16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    select(bus, device, function, offset);
    pci::write_u16(u16::from(offset & 2), value);
}
