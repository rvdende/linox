//! Read-only polling AHCI (SATA) driver.
//!
//! Like the NVMe driver, this driver only issues IDENTIFY DEVICE and READ DMA
//! EXT, so it never modifies a disk. It drives one command slot per port
//! without interrupts.

#![forbid(unsafe_code)]

use super::pci::Function;
use super::{wait_until_ms, BlockDevice, DmaRegion};
use crate::trusted::dma::{DmaPages, StaticDma};
use crate::trusted::mmio::Mmio;

const HBA_GLOBAL_CONTROL: usize = 0x04;
const HBA_PORTS_IMPLEMENTED: usize = 0x0c;
const HBA_VERSION: usize = 0x10;
const HBA_CAPABILITIES_2: usize = 0x24;
const HBA_HANDOFF: usize = 0x28;
const GLOBAL_AHCI_ENABLE: u32 = 1 << 31;
const HANDOFF_SUPPORTED: u32 = 1 << 0;
const HANDOFF_BIOS_OWNED: u32 = 1 << 0;
const HANDOFF_OS_OWNED: u32 = 1 << 1;
const PORT_BASE: usize = 0x100;
const PORT_STRIDE: usize = 0x80;
const PORT_COMMAND_LIST: usize = 0x00;
const PORT_FIS_BASE: usize = 0x08;
const PORT_INTERRUPT_STATUS: usize = 0x10;
const PORT_INTERRUPT_ENABLE: usize = 0x14;
const PORT_COMMAND: usize = 0x18;
const PORT_TASK_FILE: usize = 0x20;
const PORT_SIGNATURE: usize = 0x24;
const PORT_STATUS: usize = 0x28;
const PORT_ERROR: usize = 0x30;
const PORT_COMMAND_ISSUE: usize = 0x38;
const COMMAND_START: u32 = 1 << 0;
const COMMAND_FIS_RECEIVE: u32 = 1 << 4;
const COMMAND_FIS_RUNNING: u32 = 1 << 14;
const COMMAND_LIST_RUNNING: u32 = 1 << 15;
const TASK_FILE_BUSY: u32 = 1 << 7;
const TASK_FILE_DATA_REQUEST: u32 = 1 << 3;
const TASK_FILE_ERROR: u32 = 1 << 0;
const INTERRUPT_TASK_FILE_ERROR: u32 = 1 << 30;
const STATUS_DEVICE_PRESENT: u32 = 3;
const SIGNATURE_ATA: u32 = 0x0000_0101;
const FIS_HOST_TO_DEVICE: u8 = 0x27;
const ATA_IDENTIFY_DEVICE: u8 = 0xec;
const ATA_READ_DMA_EXT: u8 = 0x25;
const COMMAND_TIMEOUT_MS: u64 = 5000;
/// The HBA's registers: the generic block and 32 ports (AHCI 1.3.1
/// section 3).
const REGISTER_BYTES: usize = PORT_BASE + 32 * PORT_STRIDE;
/// Ports the driver can drive at once; each needs three DMA pages.
pub(crate) const MAX_PORTS: usize = 8;

static COMMAND_LISTS: StaticDma<MAX_PORTS> = StaticDma::new();
static COMMAND_TABLES: StaticDma<MAX_PORTS> = StaticDma::new();
static BUFFERS: StaticDma<MAX_PORTS> = StaticDma::new();

/// The memory AHCI controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 3] {
    [
        DmaRegion::from(COMMAND_LISTS.region()),
        DmaRegion::from(COMMAND_TABLES.region()),
        DmaRegion::from(BUFFERS.region()),
    ]
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    NoDevice,
    NotAta(u32),
    StopTimedOut,
    CommandTimedOut(u8),
    CommandFailed(u8, u32),
}

/// An ATA disk on one AHCI port.
pub(crate) struct Disk {
    port: usize,
    registers: Mmio,
    /// The DMA set the port uses: its command list (and received FISes),
    /// command table and data buffer.
    command_list: DmaPages,
    command_table: DmaPages,
    data: DmaPages,
    /// The last read's data, copied out of `data` for the caller.
    buffer: [u8; 4096],
    pub(crate) sectors: u64,
    pub(crate) sector_size: u32,
    pub(crate) model: [u8; 40],
    pub(crate) serial: [u8; 20],
}

/// Takes the controller from firmware, enables AHCI mode, and returns its
/// registers, the bitmap of implemented ports and its version. `function`
/// must be an AHCI controller that no other code drives.
pub(crate) fn open_controller(function: Function) -> Result<(Mmio, u32, u32), Error> {
    let base = function
        .memory_bar(5)
        .and_then(|bar| Mmio::firmware(bar, REGISTER_BYTES))
        .ok_or(Error::NoMemoryBar)?;
    function.enable_memory_and_bus_master();
    if base.read::<u32>(HBA_CAPABILITIES_2) & HANDOFF_SUPPORTED != 0 {
        base.write::<u32>(
            HBA_HANDOFF,
            base.read::<u32>(HBA_HANDOFF) | HANDOFF_OS_OWNED,
        );
        let _ = wait_until_ms(2000, || {
            base.read::<u32>(HBA_HANDOFF) & HANDOFF_BIOS_OWNED == 0
        });
    }
    base.write::<u32>(
        HBA_GLOBAL_CONTROL,
        base.read::<u32>(HBA_GLOBAL_CONTROL) | GLOBAL_AHCI_ENABLE,
    );
    let ports = base.read::<u32>(HBA_PORTS_IMPLEMENTED);
    let version = base.read::<u32>(HBA_VERSION);
    Ok((base, ports, version))
}

impl Disk {
    /// Brings up `port` of the controller whose registers are `base` and
    /// identifies its disk.
    /// `slot` selects which of the driver's DMA page sets the port uses.
    ///
    /// The controller must have been opened with [`open_controller`], and
    /// no other code may use `port`; a DMA set held by another disk is
    /// refused as [`Error::NoDevice`].
    pub(crate) fn open(base: &Mmio, port: usize, slot: usize) -> Result<Self, Error> {
        let (Some(command_list), Some(command_table), Some(data)) = (
            COMMAND_LISTS.claim_page(slot),
            COMMAND_TABLES.claim_page(slot),
            BUFFERS.claim_page(slot),
        ) else {
            return Err(Error::NoDevice);
        };
        let registers = base
            .window(PORT_BASE + port * PORT_STRIDE, PORT_STRIDE)
            .ok_or(Error::NoDevice)?;
        if registers.read::<u32>(PORT_STATUS) & 0xf != STATUS_DEVICE_PRESENT {
            return Err(Error::NoDevice);
        }
        let signature = registers.read::<u32>(PORT_SIGNATURE);
        if signature != SIGNATURE_ATA {
            return Err(Error::NotAta(signature));
        }
        // Stop the command engine before moving its structures.
        let command = registers.read::<u32>(PORT_COMMAND);
        registers.write::<u32>(
            PORT_COMMAND,
            command & !(COMMAND_START | COMMAND_FIS_RECEIVE),
        );
        if !wait_until_ms(500, || {
            registers.read::<u32>(PORT_COMMAND) & (COMMAND_LIST_RUNNING | COMMAND_FIS_RUNNING) == 0
        }) {
            return Err(Error::StopTimedOut);
        }
        command_list.fill(0, 4096, 0);
        // The command list uses the first 1 KiB; received FISes the next 256 bytes.
        let list = command_list.device_address(0);
        let fis = list + 1024;
        registers.write::<u32>(PORT_COMMAND_LIST, list as u32);
        registers.write::<u32>(PORT_COMMAND_LIST + 4, (list >> 32) as u32);
        registers.write::<u32>(PORT_FIS_BASE, fis as u32);
        registers.write::<u32>(PORT_FIS_BASE + 4, (fis >> 32) as u32);
        registers.write::<u32>(PORT_ERROR, u32::MAX);
        registers.write::<u32>(PORT_INTERRUPT_STATUS, u32::MAX);
        registers.write::<u32>(PORT_INTERRUPT_ENABLE, 0);
        registers.write::<u32>(
            PORT_COMMAND,
            registers.read::<u32>(PORT_COMMAND) | COMMAND_FIS_RECEIVE,
        );
        registers.write::<u32>(
            PORT_COMMAND,
            registers.read::<u32>(PORT_COMMAND) | COMMAND_START,
        );

        let mut disk = Self {
            port,
            registers,
            command_list,
            command_table,
            data,
            buffer: [0; 4096],
            sectors: 0,
            sector_size: 512,
            model: [0; 40],
            serial: [0; 20],
        };
        disk.issue(ATA_IDENTIFY_DEVICE, 0, 0, 512)?;
        disk.data.read_bytes(0, &mut disk.buffer);
        let identify = disk.buffer;
        let word =
            |index: usize| u16::from_le_bytes([identify[index * 2], identify[index * 2 + 1]]);
        // ATA strings store each pair of characters big-endian.
        for (index, pair) in disk.model.chunks_mut(2).enumerate() {
            pair.copy_from_slice(&word(27 + index).to_be_bytes());
        }
        for (index, pair) in disk.serial.chunks_mut(2).enumerate() {
            pair.copy_from_slice(&word(10 + index).to_be_bytes());
        }
        disk.sectors = (0..4).fold(0, |total, index| {
            total | u64::from(word(100 + index)) << (16 * index)
        });
        let sector_info = word(106);
        if sector_info & 0xc000 == 0x4000 && sector_info & (1 << 12) != 0 {
            disk.sector_size = (u32::from(word(117)) | u32::from(word(118)) << 16) * 2;
        }
        Ok(disk)
    }

    pub(crate) fn port(&self) -> usize {
        self.port
    }

    fn issue(&mut self, command: u8, lba: u64, count: u16, bytes: u32) -> Result<(), Error> {
        let header = &self.command_list;
        let table = &self.command_table;
        let table_address = table.device_address(0);
        let buffer = self.data.device_address(0);
        table.fill(0, 4096, 0);
        // Header 0: five-dword FIS, device-to-host (read), one PRD entry.
        header.write::<u32>(0, 5 | 1 << 16);
        header.write::<u32>(4, 0);
        header.write::<u32>(8, table_address as u32);
        header.write::<u32>(12, (table_address >> 32) as u32);
        table.write_bytes(
            0,
            &[
                FIS_HOST_TO_DEVICE,
                0x80,
                command,
                0,
                lba as u8,
                (lba >> 8) as u8,
                (lba >> 16) as u8,
                0x40,
                (lba >> 24) as u8,
                (lba >> 32) as u8,
                (lba >> 40) as u8,
                0,
                count as u8,
                (count >> 8) as u8,
            ],
        );
        table.write::<u32>(0x80, buffer as u32);
        table.write::<u32>(0x84, (buffer >> 32) as u32);
        table.write::<u32>(0x8c, bytes - 1);
        let registers = &self.registers;
        if !wait_until_ms(COMMAND_TIMEOUT_MS, || {
            registers.read::<u32>(PORT_TASK_FILE) & (TASK_FILE_BUSY | TASK_FILE_DATA_REQUEST) == 0
        }) {
            return Err(Error::CommandTimedOut(command));
        }
        registers.write::<u32>(PORT_INTERRUPT_STATUS, u32::MAX);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        registers.write::<u32>(PORT_COMMAND_ISSUE, 1);
        let mut failed = false;
        let finished = wait_until_ms(COMMAND_TIMEOUT_MS, || {
            if registers.read::<u32>(PORT_INTERRUPT_STATUS) & INTERRUPT_TASK_FILE_ERROR != 0 {
                failed = true;
                return true;
            }
            registers.read::<u32>(PORT_COMMAND_ISSUE) & 1 == 0
        });
        if failed || registers.read::<u32>(PORT_TASK_FILE) & TASK_FILE_ERROR != 0 {
            return Err(Error::CommandFailed(
                command,
                registers.read::<u32>(PORT_TASK_FILE),
            ));
        }
        if !finished {
            return Err(Error::CommandTimedOut(command));
        }
        Ok(())
    }
}

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 {
        self.sector_size
    }

    fn read_blocks(&mut self, block: u64, count: u32) -> Option<&[u8]> {
        let bytes = u64::from(count) * u64::from(self.sector_size);
        if count == 0
            || bytes > 4096
            || block
                .checked_add(u64::from(count))
                .is_none_or(|end| end > self.sectors)
        {
            return None;
        }
        self.issue(ATA_READ_DMA_EXT, block, count as u16, bytes as u32)
            .ok()?;
        // The read completed into this disk's buffer page.
        let bytes = bytes as usize;
        self.data.read_bytes(0, &mut self.buffer[..bytes]);
        Some(&self.buffer[..bytes])
    }
}
