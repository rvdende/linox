//! Realtek RTL8125 and RTL8168-family Ethernet controllers.
//!
//! `probe` only reads registers: the MAC address, the chip identifier, and
//! the PHY link state. `Controller` takes an RTL8125 or RTL8126 from
//! whatever state firmware or the previous OS left it in, resets it, powers
//! its PHY and restarts autonegotiation, and moves frames through polled
//! descriptor rings. Realtek publishes no datasheet for these chips; the
//! register layout and the bring-up steps follow the behaviour of Linux's
//! r8169 driver (read for reference, not copied):
//!
//! 1. Gate the receive path (MISC.RXDV_GATED_EN), ask the MAC to stop
//!    (ChipCmd.StopReq) and wait for its FIFOs to drain: a UEFI network
//!    driver or the previous OS may have left DMA running into memory that
//!    is now ours, and Linux's own shutdown leaves the gate closed.
//! 2. Turn off Tx/Rx, take the MAC from the out-of-band management
//!    controller (clear MCU.NOW_IS_OOB and MAC OCP 0xe8de bit 14) and wait
//!    for the link-list FIFO to report ready.
//! 3. Reset the MAC (ChipCmd.CmdReset), select the classic descriptor format
//!    (MAC OCP 0xeb58 bit 0 clear), program the rings, open the gate, and
//!    enable Tx/Rx.
//! 4. Power up the PHY and restart autonegotiation through the PHY OCP
//!    window (standard MII registers at OCP 0xa400 + 2 * register), then
//!    wait for a link. The PHY firmware patch Linux loads (rtl8125b-2.fw)
//!    fixes errata only; the link comes up without it.
//!
//! The chip-specific tuning r8169 applies (EEE, PCIe PHY tables, power
//! saving) is skipped. It has not run on hardware yet.

use core::ptr::{addr_of, addr_of_mut};

use super::net::{Nic, FRAME_LIMIT};
use super::pci::{Function, Identity};
use super::{wait_until_ms, DmaPage, DmaRegion};

const VENDOR_REALTEK: u16 = 0x10ec;
const MAC_ADDRESS: usize = 0x00;
const MULTICAST_FILTER: usize = 0x08;
const TRANSMIT_RING_LOW: usize = 0x20;
const TRANSMIT_RING_HIGH: usize = 0x24;
const CHIP_COMMAND: usize = 0x37;
const INTERRUPT_MASK_8125: usize = 0x38;
const INTERRUPT_STATUS_8125: usize = 0x3c;
const TRANSMIT_CONFIG: usize = 0x40;
const RECEIVE_CONFIG: usize = 0x44;
const CONFIG_LOCK: usize = 0x50;
const PHY_STATUS: usize = 0x6c;
const TRANSMIT_POLL_8125: usize = 0x90;
const RECEIVE_MAX_SIZE: usize = 0xda;
const RECEIVE_RING_LOW: usize = 0xe4;
const RECEIVE_RING_HIGH: usize = 0xe8;
/// MAC OCP register window: write (reg << 15) | data with bit 31 set, or
/// write reg << 15 and read the data back.
const MAC_OCP: usize = 0xb0;
/// PHY OCP register window: as MAC_OCP, with bit 31 as the busy/ready flag.
const PHY_OCP: usize = 0xb8;
const OCP_FLAG: u32 = 1 << 31;
const MCU: usize = 0xd3;
const MCU_NOW_IS_OOB: u8 = 1 << 7;
const MCU_TRANSMIT_EMPTY: u8 = 1 << 5;
const MCU_RECEIVE_EMPTY: u8 = 1 << 4;
const MCU_LINK_LIST_READY: u8 = 1 << 1;
const INTERRUPT_MITIGATE: usize = 0xe2;
const MISC: usize = 0xf0;
const MISC_RXDV_GATED: u32 = 1 << 19;
const COMMAND_STOP_REQUEST: u8 = 0x80;
/// MAC OCP registers r8169 touches on the RTL8125 family.
const OCP_OOB_CONTROL: u32 = 0xe8de;
const OCP_DESCRIPTOR_FORMAT: u32 = 0xeb58;
/// The PHY's standard MII registers in PHY OCP space.
const OCP_STANDARD_PHY: u32 = 0xa400;
const MII_CONTROL: u32 = 0;
const MII_CONTROL_POWER_DOWN: u16 = 1 << 11;
const MII_CONTROL_AUTONEGOTIATE: u16 = 1 << 12;
const MII_CONTROL_RESTART: u16 = 1 << 9;
/// The receive-config bit r8169 sets from the RTL8125B on.
const RECEIVE_PAUSE_SLOT: u32 = 1 << 11;
/// TxConfig chip identifiers (bits 30:20 masked with 0x7cf) this driver
/// knows: RTL8125A, RTL8125B, and the RTL8126A variants.
const CHIP_8125A: u32 = 0x609;
const CHIP_8125B: u32 = 0x641;
const CHIPS_8126A: [u32; 2] = [0x649, 0x64a];
const COMMAND_RESET: u8 = 0x10;
const COMMAND_RECEIVE: u8 = 0x08;
const COMMAND_TRANSMIT: u8 = 0x04;
const CONFIG_UNLOCKED: u8 = 0xc0;
const CONFIG_LOCKED: u8 = 0x00;
const ACCEPT_BROADCAST: u32 = 0x08;
const ACCEPT_MULTICAST: u32 = 0x04;
const ACCEPT_MY_ADDRESS: u32 = 0x02;
/// RX_FETCH_DFLT_8125 and an unlimited DMA burst, as r8169 sets them.
const RECEIVE_DEFAULTS_8125: u32 = 8 << 27 | 7 << 8;
/// Unlimited DMA burst, the standard inter-frame gap, and automatic FIFO.
const TRANSMIT_DEFAULTS_8125: u32 = 7 << 8 | 3 << 24 | 1 << 7;
const PHY_FULL_DUPLEX: u16 = 0x0001;
const PHY_LINK: u16 = 0x0002;
const PHY_10_MBPS: u16 = 0x0004;
const PHY_100_MBPS: u16 = 0x0008;
const PHY_1000_MBPS: u16 = 0x0010;
const PHY_2500_MBPS: u16 = 0x0400;
/// The RTL8126's 5 Gb/s bit.
const PHY_5000_MBPS: u16 = 0x1000;
const DESCRIPTOR_OWNED: u32 = 1 << 31;
const DESCRIPTOR_RING_END: u32 = 1 << 30;
const DESCRIPTOR_FIRST: u32 = 1 << 29;
const DESCRIPTOR_LAST: u32 = 1 << 28;
const RECEIVE_ERROR: u32 = 1 << 21;
const RECEIVE_DESCRIPTORS: usize = 32;
const TRANSMIT_DESCRIPTORS: usize = 8;
const BUFFER_SIZE: usize = 2048;
const TRANSMIT_TIMEOUT_MS: u64 = 100;
/// 2.5GBASE-T negotiation can take about three seconds.
const LINK_TIMEOUT_MS: u64 = 6000;

static mut RECEIVE_RING: DmaPage = DmaPage::ZERO;
static mut TRANSMIT_RING: DmaPage = DmaPage::ZERO;
static mut RECEIVE_BUFFERS: [DmaPage; RECEIVE_DESCRIPTORS * BUFFER_SIZE / 4096] =
    [DmaPage::ZERO; RECEIVE_DESCRIPTORS * BUFFER_SIZE / 4096];
static mut TRANSMIT_BUFFERS: [DmaPage; TRANSMIT_DESCRIPTORS * BUFFER_SIZE / 4096] =
    [DmaPage::ZERO; TRANSMIT_DESCRIPTORS * BUFFER_SIZE / 4096];

/// What the controller reports about itself and its link.
pub(crate) struct Report {
    pub(crate) mac: [u8; 6],
    /// The chip identifier, bits 30:20 of TxConfig as r8169 masks them.
    pub(crate) chip: u32,
    /// Link speed in Mb/s, or `None` without a link.
    pub(crate) speed: Option<u32>,
    pub(crate) full_duplex: bool,
}

/// Returns whether `device` is an RTL8125 or RTL8168-family controller.
pub(crate) fn is_supported(device: &Identity) -> bool {
    device.vendor == VENDOR_REALTEK && matches!(device.device, 0x8125 | 0x8126 | 0x8161 | 0x8168)
}

/// Returns whether `Controller` can drive `device`: the 2.5 and 5 Gb/s
/// RTL8125 and RTL8126, whose register layout differs from the RTL8168.
pub(crate) fn can_transfer(device: &Identity) -> bool {
    device.vendor == VENDOR_REALTEK && matches!(device.device, 0x8125 | 0x8126)
}

/// The memory Realtek controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 4] {
    [
        DmaRegion::of(addr_of!(RECEIVE_RING)),
        DmaRegion::of(addr_of!(TRANSMIT_RING)),
        DmaRegion::of(addr_of!(RECEIVE_BUFFERS)),
        DmaRegion::of(addr_of!(TRANSMIT_BUFFERS)),
    ]
}

/// Reads the identity and link state of a supported controller.
///
/// # Safety
///
/// `function` must be a supported controller whose memory BAR is identity
/// mapped. Reading these registers has no side effects.
pub(crate) unsafe fn probe(function: Function) -> Option<Report> {
    // BAR 0 is I/O space on these chips; the registers are mirrored in BAR 2.
    let base = function.memory_bar(2)? as usize;
    function.enable_memory();
    let mut mac = [0_u8; 6];
    for (index, value) in mac.iter_mut().enumerate() {
        *value = read8(base, MAC_ADDRESS + index);
    }
    let transmit = read32(base, TRANSMIT_CONFIG);
    let (speed, full_duplex) = link(base);
    Some(Report {
        mac,
        chip: (transmit >> 20) & 0x7cf,
        speed,
        full_duplex,
    })
}

/// The name of a chip identifier this driver knows.
pub(crate) fn chip_name(chip: u32) -> Option<&'static str> {
    match chip {
        CHIP_8125A => Some("RTL8125A"),
        CHIP_8125B => Some("RTL8125B"),
        chip if CHIPS_8126A.contains(&chip) => Some("RTL8126A"),
        _ => None,
    }
}

/// Decodes PHYstatus into a link speed and duplex.
fn link(base: usize) -> (Option<u32>, bool) {
    let phy = read16(base, PHY_STATUS);
    let speed = if phy & PHY_5000_MBPS != 0 {
        5000
    } else if phy & PHY_2500_MBPS != 0 {
        2500
    } else if phy & PHY_1000_MBPS != 0 {
        1000
    } else if phy & PHY_100_MBPS != 0 {
        100
    } else if phy & PHY_10_MBPS != 0 {
        10
    } else {
        0
    };
    (
        (phy & PHY_LINK != 0).then_some(speed),
        phy & PHY_FULL_DUPLEX != 0,
    )
}

/// A running RTL8125 or RTL8126.
pub(crate) struct Controller {
    base: usize,
    mac: [u8; 6],
    next_receive: usize,
    next_transmit: usize,
    /// Set when a transmission timed out: the descriptor ring is out of
    /// step until the controller is opened again.
    broken: bool,
}

/// Why opening a controller failed.
// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    /// The registers read all ones: the function is not decoding.
    NotResponding,
    UnknownChip(u32),
    ResetTimedOut,
}

impl Controller {
    /// Resets the controller, starts its rings, and waits for the link to
    /// come back.
    ///
    /// # Safety
    ///
    /// `function` must satisfy `can_transfer`, nothing else may drive it,
    /// and its registers and this driver's DMA pages must be identity
    /// mapped. Only one controller may be open at a time.
    pub(crate) unsafe fn open(function: Function) -> Result<Self, Error> {
        let base = function.memory_bar(2).ok_or(Error::NoMemoryBar)? as usize;
        // Registers first, bus mastering only once the chip is quiet.
        function.enable_memory();
        let transmit = read32(base, TRANSMIT_CONFIG);
        if transmit == u32::MAX {
            return Err(Error::NotResponding);
        }
        let chip = (transmit >> 20) & 0x7cf;
        if chip_name(chip).is_none() {
            return Err(Error::UnknownChip(chip));
        }
        let mut mac = [0_u8; 6];
        for (index, value) in mac.iter_mut().enumerate() {
            *value = read8(base, MAC_ADDRESS + index);
        }
        write32(base, INTERRUPT_MASK_8125, 0);
        // Step 1: gate receive and drain whatever was running.
        write32(base, MISC, read32(base, MISC) | MISC_RXDV_GATED);
        super::delay_ms(2);
        write8(
            base,
            CHIP_COMMAND,
            read8(base, CHIP_COMMAND) | COMMAND_STOP_REQUEST,
        );
        let empty = MCU_TRANSMIT_EMPTY | MCU_RECEIVE_EMPTY;
        let _ = wait_until_ms(50, || read8(base, MCU) & empty == empty);
        let _ = wait_until_ms(50, || read16(base, INTERRUPT_MITIGATE) & 0x0103 == 0x0103);
        // Step 2: take the MAC from the out-of-band controller.
        write8(
            base,
            CHIP_COMMAND,
            read8(base, CHIP_COMMAND) & !(COMMAND_TRANSMIT | COMMAND_RECEIVE),
        );
        super::delay_ms(1);
        write8(base, MCU, read8(base, MCU) & !MCU_NOW_IS_OOB);
        mac_ocp_modify(base, OCP_OOB_CONTROL, 1 << 14, 0);
        let _ = wait_until_ms(50, || read8(base, MCU) & MCU_LINK_LIST_READY != 0);
        // Step 3: reset, then set up the MAC.
        write8(base, CHIP_COMMAND, COMMAND_RESET);
        if !wait_until_ms(100, || read8(base, CHIP_COMMAND) & COMMAND_RESET == 0) {
            return Err(Error::ResetTimedOut);
        }
        function.enable_memory_and_bus_master();
        write32(base, INTERRUPT_MASK_8125, 0);
        write32(base, INTERRUPT_STATUS_8125, u32::MAX);
        mac_ocp_modify(base, OCP_DESCRIPTOR_FORMAT, 1 << 0, 0);

        let receive_ring = addr_of_mut!(RECEIVE_RING).cast::<u32>();
        for index in 0..RECEIVE_DESCRIPTORS {
            write_descriptor(
                receive_ring,
                index,
                receive_buffer(index),
                receive_ready(index),
            );
        }
        let transmit_ring = addr_of_mut!(TRANSMIT_RING).cast::<u32>();
        for index in 0..TRANSMIT_DESCRIPTORS {
            let end = if index == TRANSMIT_DESCRIPTORS - 1 {
                DESCRIPTOR_RING_END
            } else {
                0
            };
            write_descriptor(transmit_ring, index, transmit_buffer(index), end);
        }

        write8(base, CONFIG_LOCK, CONFIG_UNLOCKED);
        write32(
            base,
            TRANSMIT_RING_HIGH,
            (transmit_ring as u64 >> 32) as u32,
        );
        write32(base, TRANSMIT_RING_LOW, transmit_ring as u32);
        write32(base, RECEIVE_RING_HIGH, (receive_ring as u64 >> 32) as u32);
        write32(base, RECEIVE_RING_LOW, receive_ring as u32);
        write16(base, RECEIVE_MAX_SIZE, BUFFER_SIZE as u16);
        write8(base, CONFIG_LOCK, CONFIG_LOCKED);
        write32(base, MISC, read32(base, MISC) & !MISC_RXDV_GATED);
        write8(base, CHIP_COMMAND, COMMAND_TRANSMIT | COMMAND_RECEIVE);
        let pause = if chip == CHIP_8125A {
            0
        } else {
            RECEIVE_PAUSE_SLOT
        };
        write32(
            base,
            RECEIVE_CONFIG,
            RECEIVE_DEFAULTS_8125 | pause | ACCEPT_BROADCAST | ACCEPT_MULTICAST | ACCEPT_MY_ADDRESS,
        );
        write32(base, MULTICAST_FILTER, u32::MAX);
        write32(base, MULTICAST_FILTER + 4, u32::MAX);
        write32(base, TRANSMIT_CONFIG, TRANSMIT_DEFAULTS_8125);
        // Step 4: the MAC reset leaves the PHY as it was, possibly powered
        // down by the previous driver. Power it up and renegotiate.
        if let Some(control) = phy_read(base, MII_CONTROL) {
            phy_write(
                base,
                MII_CONTROL,
                control & !MII_CONTROL_POWER_DOWN | MII_CONTROL_AUTONEGOTIATE | MII_CONTROL_RESTART,
            );
        }
        // Autonegotiation drops the link first; wait for it to come back.
        super::delay_ms(100);
        let _ = wait_until_ms(LINK_TIMEOUT_MS, || link(base).0.is_some());
        Ok(Self {
            base,
            mac,
            next_receive: 0,
            next_transmit: 0,
            broken: false,
        })
    }

    /// The link speed in Mb/s, or `None` without a link.
    pub(crate) fn link_speed(&self) -> Option<u32> {
        link(self.base).0
    }
}

impl Nic for Controller {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> bool {
        if frame.len() > FRAME_LIMIT || self.broken {
            return false;
        }
        let index = self.next_transmit;
        let ring = addr_of_mut!(TRANSMIT_RING).cast::<u32>();
        // SAFETY: the descriptor and its buffer belong to this driver, and
        // the controller released the descriptor (checked below).
        unsafe {
            if ring.add(index * 4).read_volatile() & DESCRIPTOR_OWNED != 0 {
                return false;
            }
            let buffer = transmit_buffer(index);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer, frame.len());
            // Pad to the 60-byte minimum; the controller appends the FCS.
            let length = frame.len().max(60);
            buffer.add(frame.len()).write_bytes(0, length - frame.len());
            let end = if index == TRANSMIT_DESCRIPTORS - 1 {
                DESCRIPTOR_RING_END
            } else {
                0
            };
            write_descriptor(
                ring,
                index,
                buffer,
                DESCRIPTOR_OWNED | end | DESCRIPTOR_FIRST | DESCRIPTOR_LAST | length as u32,
            );
        }
        self.next_transmit = (index + 1) % TRANSMIT_DESCRIPTORS;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write16(self.base, TRANSMIT_POLL_8125, 1);
        let sent = wait_until_ms(TRANSMIT_TIMEOUT_MS, || {
            // SAFETY: the controller clears the owned bit once it is done.
            unsafe { ring.add(index * 4).read_volatile() & DESCRIPTOR_OWNED == 0 }
        });
        if !sent {
            // The chip still owns the descriptor; later sends would find
            // the ring out of step.
            self.broken = true;
        }
        sent
    }

    fn receive(&mut self, buffer: &mut [u8; FRAME_LIMIT]) -> Option<usize> {
        let index = self.next_receive;
        let ring = addr_of_mut!(RECEIVE_RING).cast::<u32>();
        // SAFETY: the descriptor belongs to this driver; the controller
        // cleared its owned bit after writing the buffer.
        unsafe {
            let status = ring.add(index * 4).read_volatile();
            if status & DESCRIPTOR_OWNED != 0 {
                return None;
            }
            let length = (status & 0x3fff) as usize;
            let complete = status & (DESCRIPTOR_FIRST | DESCRIPTOR_LAST)
                == DESCRIPTOR_FIRST | DESCRIPTOR_LAST
                && status & RECEIVE_ERROR == 0
                && length > 4;
            // The length includes the FCS.
            let copied = if complete {
                let copied = (length - 4).min(FRAME_LIMIT);
                core::ptr::copy_nonoverlapping(receive_buffer(index), buffer.as_mut_ptr(), copied);
                copied
            } else {
                0
            };
            write_descriptor(ring, index, receive_buffer(index), receive_ready(index));
            self.next_receive = (index + 1) % RECEIVE_DESCRIPTORS;
            // An errored frame is dropped; report an empty frame so callers
            // keep polling.
            Some(copied)
        }
    }
}

/// The first word of a receive descriptor handed to the controller.
fn receive_ready(index: usize) -> u32 {
    let end = if index == RECEIVE_DESCRIPTORS - 1 {
        DESCRIPTOR_RING_END
    } else {
        0
    };
    DESCRIPTOR_OWNED | end | BUFFER_SIZE as u32
}

/// Writes descriptor `index`: its buffer address, then its first word, so
/// the controller never sees an owned descriptor without its buffer.
///
/// # Safety
///
/// `ring` must be one of this driver's descriptor rings with room for
/// `index`.
unsafe fn write_descriptor(ring: *mut u32, index: usize, buffer: *mut u8, first: u32) {
    let descriptor = ring.add(index * 4);
    descriptor.add(1).write_volatile(0);
    descriptor.add(2).write_volatile(buffer as u32);
    descriptor
        .add(3)
        .write_volatile((buffer as u64 >> 32) as u32);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    descriptor.write_volatile(first);
}

fn receive_buffer(index: usize) -> *mut u8 {
    // SAFETY: index is below RECEIVE_DESCRIPTORS, so the offset stays in
    // the buffer array.
    unsafe {
        addr_of_mut!(RECEIVE_BUFFERS)
            .cast::<u8>()
            .add(index * BUFFER_SIZE)
    }
}

fn transmit_buffer(index: usize) -> *mut u8 {
    // SAFETY: as for receive_buffer.
    unsafe {
        addr_of_mut!(TRANSMIT_BUFFERS)
            .cast::<u8>()
            .add(index * BUFFER_SIZE)
    }
}

/// Reads MAC OCP register `register` (an even address below 0x10000).
fn mac_ocp_read(base: usize, register: u32) -> u16 {
    write32(base, MAC_OCP, register << 15);
    read32(base, MAC_OCP) as u16
}

fn mac_ocp_modify(base: usize, register: u32, clear: u16, set: u16) {
    let value = mac_ocp_read(base, register) & !clear | set;
    write32(base, MAC_OCP, OCP_FLAG | register << 15 | u32::from(value));
}

/// Reads standard PHY register `register` through the PHY OCP window; the
/// flag rises when the data is valid.
fn phy_read(base: usize, register: u32) -> Option<u16> {
    write32(base, PHY_OCP, (OCP_STANDARD_PHY + register * 2) << 15);
    wait_until_ms(10, || read32(base, PHY_OCP) & OCP_FLAG != 0)
        .then(|| read32(base, PHY_OCP) as u16)
}

/// Writes standard PHY register `register`; the flag falls when done.
fn phy_write(base: usize, register: u32, value: u16) -> bool {
    write32(
        base,
        PHY_OCP,
        OCP_FLAG | (OCP_STANDARD_PHY + register * 2) << 15 | u32::from(value),
    );
    wait_until_ms(10, || read32(base, PHY_OCP) & OCP_FLAG == 0)
}

fn read8(base: usize, offset: usize) -> u8 {
    // SAFETY: callers pass identity-mapped controller registers.
    unsafe { ((base + offset) as *const u8).read_volatile() }
}

fn read16(base: usize, offset: usize) -> u16 {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *const u16).read_volatile() }
}

fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn write8(base: usize, offset: usize, value: u8) {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *mut u8).write_volatile(value) }
}

fn write16(base: usize, offset: usize, value: u16) {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *mut u16).write_volatile(value) }
}

fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *mut u32).write_volatile(value) }
}
