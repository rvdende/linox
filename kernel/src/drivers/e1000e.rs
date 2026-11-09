//! Intel 82574 (e1000e) Ethernet, as QEMU emulates it, with polled transmit
//! and receive through legacy descriptors.
//!
//! The driver exists to test the shared network code in QEMU; the PCs it is
//! aimed at mostly carry Realtek controllers.

#![forbid(unsafe_code)]

use super::net::{Nic, FRAME_LIMIT};
use super::pci::{Function, Identity};
use super::{delay_ms, wait_until_ms, DmaRegion};
use crate::trusted::dma::{DmaPages, StaticDma};
use crate::trusted::mmio::Mmio;

const VENDOR_INTEL: u16 = 0x8086;
const DEVICE_82574: u16 = 0x10d3;
const CONTROL: usize = 0x0000;
const STATUS: usize = 0x0008;
const INTERRUPT_MASK_CLEAR: usize = 0x00d8;
const RECEIVE_CONTROL: usize = 0x0100;
const TRANSMIT_CONTROL: usize = 0x0400;
const MULTICAST_TABLE: usize = 0x5200;
const RECEIVE_ADDRESS_LOW: usize = 0x5400;
const RECEIVE_ADDRESS_HIGH: usize = 0x5404;
const RECEIVE_BASE_LOW: usize = 0x2800;
const RECEIVE_BASE_HIGH: usize = 0x2804;
const RECEIVE_LENGTH: usize = 0x2808;
const RECEIVE_HEAD: usize = 0x2810;
const RECEIVE_TAIL: usize = 0x2818;
const TRANSMIT_BASE_LOW: usize = 0x3800;
const TRANSMIT_BASE_HIGH: usize = 0x3804;
const TRANSMIT_LENGTH: usize = 0x3808;
const TRANSMIT_HEAD: usize = 0x3810;
const TRANSMIT_TAIL: usize = 0x3818;
const CONTROL_SET_LINK_UP: u32 = 1 << 6;
const CONTROL_RESET: u32 = 1 << 26;
const STATUS_LINK_UP: u32 = 1 << 1;
const RECEIVE_ENABLE: u32 = 1 << 1;
const RECEIVE_BROADCAST: u32 = 1 << 15;
const RECEIVE_STRIP_CRC: u32 = 1 << 26;
const TRANSMIT_ENABLE: u32 = 1 << 1;
const TRANSMIT_PAD_SHORT: u32 = 1 << 3;
const TRANSMIT_COLLISION_THRESHOLD: u32 = 0x0f << 4;
const TRANSMIT_COLLISION_DISTANCE: u32 = 0x3f << 12;
const ADDRESS_VALID: u32 = 1 << 31;
const DESCRIPTOR_DONE: u8 = 1 << 0;
const DESCRIPTOR_END_OF_PACKET: u8 = 1 << 0;
const COMMAND_INSERT_FCS: u8 = 1 << 1;
const COMMAND_REPORT_STATUS: u8 = 1 << 3;
const RECEIVE_DESCRIPTORS: usize = 32;
const TRANSMIT_DESCRIPTORS: usize = 8;
const BUFFER_SIZE: usize = 2048;
const TRANSMIT_TIMEOUT_MS: u64 = 100;
/// The 82574's memory BAR (datasheet section 9.3.11): 128 KiB.
const REGISTER_BYTES: usize = 0x2_0000;

static RECEIVE_RING: StaticDma<1> = StaticDma::new();
static TRANSMIT_RING: StaticDma<1> = StaticDma::new();
static RECEIVE_BUFFERS: StaticDma<{ RECEIVE_DESCRIPTORS * BUFFER_SIZE / 4096 }> = StaticDma::new();
static TRANSMIT_BUFFERS: StaticDma<{ TRANSMIT_DESCRIPTORS * BUFFER_SIZE / 4096 }> =
    StaticDma::new();

/// Returns whether `device` is an 82574.
pub(crate) fn is_supported(device: &Identity) -> bool {
    device.vendor == VENDOR_INTEL && device.device == DEVICE_82574
}

/// The memory 82574 controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 4] {
    [
        DmaRegion::from(RECEIVE_RING.region()),
        DmaRegion::from(TRANSMIT_RING.region()),
        DmaRegion::from(RECEIVE_BUFFERS.region()),
        DmaRegion::from(TRANSMIT_BUFFERS.region()),
    ]
}

/// A running controller.
pub(crate) struct Controller {
    registers: Mmio,
    receive_ring: DmaPages,
    transmit_ring: DmaPages,
    receive_buffers: DmaPages,
    transmit_buffers: DmaPages,
    mac: [u8; 6],
    next_receive: usize,
    next_transmit: usize,
}

impl Controller {
    /// Resets the controller and starts its receive and transmit rings.
    /// `function` must be an 82574 that nothing else drives; only one
    /// controller can be open at a time (it holds the driver's DMA pages).
    pub(crate) fn open(function: Function) -> Option<Self> {
        let registers = Mmio::firmware(function.memory_bar(0)?, REGISTER_BYTES)?;
        let receive_ring = RECEIVE_RING.claim()?;
        let transmit_ring = TRANSMIT_RING.claim()?;
        let receive_buffers = RECEIVE_BUFFERS.claim()?;
        let transmit_buffers = TRANSMIT_BUFFERS.claim()?;
        function.enable_memory_and_bus_master();
        registers.write::<u32>(INTERRUPT_MASK_CLEAR, u32::MAX);
        registers.write::<u32>(CONTROL, registers.read::<u32>(CONTROL) | CONTROL_RESET);
        delay_ms(1);
        if !wait_until_ms(100, || registers.read::<u32>(CONTROL) & CONTROL_RESET == 0) {
            return None;
        }
        registers.write::<u32>(INTERRUPT_MASK_CLEAR, u32::MAX);
        registers.write::<u32>(
            CONTROL,
            registers.read::<u32>(CONTROL) | CONTROL_SET_LINK_UP,
        );

        // The controller loads its address from the EEPROM at reset.
        let low = registers.read::<u32>(RECEIVE_ADDRESS_LOW).to_le_bytes();
        let high = registers.read::<u32>(RECEIVE_ADDRESS_HIGH);
        let mac = [
            low[0],
            low[1],
            low[2],
            low[3],
            high as u8,
            (high >> 8) as u8,
        ];
        registers.write::<u32>(RECEIVE_ADDRESS_HIGH, high | ADDRESS_VALID);
        for index in 0..128 {
            registers.write::<u32>(MULTICAST_TABLE + index * 4, 0);
        }

        for index in 0..RECEIVE_DESCRIPTORS {
            receive_ring.write::<u64>(
                index * 16,
                receive_buffers.device_address(index * BUFFER_SIZE),
            );
            receive_ring.write::<u64>(index * 16 + 8, 0);
        }
        for index in 0..TRANSMIT_DESCRIPTORS * 2 {
            transmit_ring.write::<u64>(index * 8, 0);
        }
        write64(
            &registers,
            RECEIVE_BASE_LOW,
            RECEIVE_BASE_HIGH,
            receive_ring.device_address(0),
        );
        registers.write::<u32>(RECEIVE_LENGTH, (RECEIVE_DESCRIPTORS * 16) as u32);
        registers.write::<u32>(RECEIVE_HEAD, 0);
        registers.write::<u32>(RECEIVE_TAIL, (RECEIVE_DESCRIPTORS - 1) as u32);
        write64(
            &registers,
            TRANSMIT_BASE_LOW,
            TRANSMIT_BASE_HIGH,
            transmit_ring.device_address(0),
        );
        registers.write::<u32>(TRANSMIT_LENGTH, (TRANSMIT_DESCRIPTORS * 16) as u32);
        registers.write::<u32>(TRANSMIT_HEAD, 0);
        registers.write::<u32>(TRANSMIT_TAIL, 0);
        // A 2048-byte buffer size is the default encoding (BSIZE 0).
        registers.write::<u32>(
            RECEIVE_CONTROL,
            RECEIVE_ENABLE | RECEIVE_BROADCAST | RECEIVE_STRIP_CRC,
        );
        registers.write::<u32>(
            TRANSMIT_CONTROL,
            TRANSMIT_ENABLE
                | TRANSMIT_PAD_SHORT
                | TRANSMIT_COLLISION_THRESHOLD
                | TRANSMIT_COLLISION_DISTANCE,
        );
        Some(Self {
            registers,
            receive_ring,
            transmit_ring,
            receive_buffers,
            transmit_buffers,
            mac,
            next_receive: 0,
            next_transmit: 0,
        })
    }

    /// Whether the link is up.
    pub(crate) fn link_up(&self) -> bool {
        self.registers.read::<u32>(STATUS) & STATUS_LINK_UP != 0
    }
}

impl Nic for Controller {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> bool {
        if frame.len() > FRAME_LIMIT {
            return false;
        }
        let index = self.next_transmit;
        // The controller is done with the descriptor and its buffer
        // (checked below before reuse).
        let buffer = index * BUFFER_SIZE;
        self.transmit_buffers.write_bytes(buffer, frame);
        let descriptor = index * 16;
        self.transmit_ring
            .write::<u64>(descriptor, self.transmit_buffers.device_address(buffer));
        let command = COMMAND_REPORT_STATUS | COMMAND_INSERT_FCS | DESCRIPTOR_END_OF_PACKET;
        self.transmit_ring.write::<u64>(
            descriptor + 8,
            frame.len() as u64 | u64::from(command) << 24,
        );
        self.next_transmit = (index + 1) % TRANSMIT_DESCRIPTORS;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.registers
            .write::<u32>(TRANSMIT_TAIL, self.next_transmit as u32);
        // The controller writes the status byte back.
        wait_until_ms(TRANSMIT_TIMEOUT_MS, || {
            self.transmit_ring.read::<u8>(index * 16 + 12) & DESCRIPTOR_DONE != 0
        })
    }

    fn receive(&mut self, buffer: &mut [u8; FRAME_LIMIT]) -> Option<usize> {
        let index = self.next_receive;
        // The controller sets the done bit after writing the buffer.
        let descriptor = index * 16;
        let status = self.receive_ring.read::<u8>(descriptor + 12);
        if status & DESCRIPTOR_DONE == 0 {
            return None;
        }
        let length = usize::from(self.receive_ring.read::<u16>(descriptor + 8));
        let copied = length.min(FRAME_LIMIT);
        self.receive_buffers
            .read_bytes(index * BUFFER_SIZE, &mut buffer[..copied]);
        self.receive_ring.write::<u8>(descriptor + 12, 0);
        self.next_receive = (index + 1) % RECEIVE_DESCRIPTORS;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.registers.write::<u32>(RECEIVE_TAIL, index as u32);
        Some(copied)
    }
}

fn write64(registers: &Mmio, low: usize, high: usize, value: u64) {
    registers.write::<u32>(low, value as u32);
    registers.write::<u32>(high, (value >> 32) as u32);
}
