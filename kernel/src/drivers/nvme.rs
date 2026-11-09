//! Polling NVMe driver.
//!
//! This driver reads anywhere but writes only inside a Linox volume
//! partition, given as a [`WritableExtent`] for the same disk, so it is safe
//! to run against a disk that holds another operating system. It uses one
//! admin queue pair and one I/O queue pair without interrupts.
//!
//! Section numbers refer to the NVM Express Base Specification 2.0 and the
//! NVM Command Set Specification 1.0.

#![forbid(unsafe_code)]

use super::gpt::{self, WritableExtent};
use super::pci::Function;
use super::{wait_until, BlockDevice, DmaRegion};
use crate::trusted::dma::{DmaPages, StaticDma};
use crate::trusted::mmio::Mmio;

const REGISTER_CAPABILITIES: usize = 0x00;
const REGISTER_VERSION: usize = 0x08;
const REGISTER_CONFIGURATION: usize = 0x14;
const REGISTER_STATUS: usize = 0x1c;
const REGISTER_ADMIN_QUEUE_ATTRIBUTES: usize = 0x24;
const REGISTER_ADMIN_SUBMISSION_QUEUE: usize = 0x28;
const REGISTER_ADMIN_COMPLETION_QUEUE: usize = 0x30;
const DOORBELL_BASE: usize = 0x1000;
const CONFIGURATION_ENABLE: u32 = 1;
// 64-byte submission and 16-byte completion entries, NVM command set, 4 KiB pages.
const CONFIGURATION_QUEUE_ENTRY_SIZES: u32 = (6 << 16) | (4 << 20);
const STATUS_READY: u32 = 1;
const STATUS_FATAL: u32 = 1 << 1;
/// CC.SHN = 01b: normal shutdown (section 3.1.3.5).
const CONFIGURATION_SHUTDOWN_NORMAL: u32 = 1 << 14;
/// CSTS.SHST (section 3.1.3.6): 10b means shutdown processing is complete.
const STATUS_SHUTDOWN_MASK: u32 = 3 << 2;
const STATUS_SHUTDOWN_COMPLETE: u32 = 2 << 2;
/// The longest a shutdown may take when RTD3E does not say: Linux's default.
const SHUTDOWN_TIMEOUT_SECONDS: u64 = 10;
const QUEUE_ENTRIES: u16 = 16;
const OPCODE_CREATE_IO_SUBMISSION_QUEUE: u8 = 0x01;
const OPCODE_CREATE_IO_COMPLETION_QUEUE: u8 = 0x05;
const OPCODE_IDENTIFY: u8 = 0x06;
const OPCODE_READ: u8 = 0x02;
const OPCODE_WRITE: u8 = 0x01;
const OPCODE_FLUSH: u8 = 0x00;
const IDENTIFY_NAMESPACE: u32 = 0x00;
const IDENTIFY_CONTROLLER: u32 = 0x01;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 0x02;
const COMMAND_TIMEOUT_SECONDS: u64 = 5;

static ADMIN_SUBMISSION: StaticDma<1> = StaticDma::new();
static ADMIN_COMPLETION: StaticDma<1> = StaticDma::new();
static IO_SUBMISSION: StaticDma<1> = StaticDma::new();
static IO_COMPLETION: StaticDma<1> = StaticDma::new();
static DATA: StaticDma<1> = StaticDma::new();

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    UnsupportedPageSize,
    DisableTimedOut,
    EnableTimedOut,
    ControllerFatal,
    CommandTimedOut(u8),
    CommandFailed(u8, u16),
    NoNamespace,
    UnsupportedBlockSize(u32),
    /// The namespace's LBA format carries metadata, which this driver does
    /// not provide buffers for.
    UnsupportedMetadata(u16),
    /// The registers read all ones: the function is not decoding.
    NotResponding,
    /// CAP.MQES allows fewer entries than the driver's queues hold.
    QueuesTooSmall(u16),
    /// An earlier command timed out; the queues are out of step until the
    /// controller is opened again.
    Unusable,
    /// A completion carried another command's identifier.
    CompletionMismatch(u16),
    OutOfRange,
    /// The extent belongs to another disk's partition table.
    WrongDisk,
    /// Another controller holds the driver's DMA pages.
    Busy,
}

struct Queue {
    entries: DmaPages,
    completions: DmaPages,
    tail: u16,
    head: u16,
    phase: bool,
    /// The doorbells' offsets in the controller's registers.
    submission_doorbell: usize,
    completion_doorbell: usize,
}

/// An enabled controller with one active namespace.
pub(crate) struct Controller {
    registers: Mmio,
    admin: Queue,
    io: Queue,
    /// The page data transfers go through.
    data: DmaPages,
    /// The last transfer's data, copied out of `data` for the caller.
    buffer: [u8; 4096],
    next_command: u16,
    pub(crate) namespace: u32,
    pub(crate) block_size: u32,
    pub(crate) block_count: u64,
    /// Set when a command timed out (section 4.6: the queues no longer
    /// match what the controller thinks).
    broken: bool,
}

/// What Identify Controller reports.
pub(crate) struct ControllerIdentity {
    pub(crate) serial: [u8; 20],
    pub(crate) model: [u8; 40],
    pub(crate) firmware: [u8; 8],
    pub(crate) version: u32,
}

impl Controller {
    /// Resets and enables the controller, identifies it, and opens the first
    /// active namespace for reading.
    ///
    /// `function` must be an NVMe controller that no other code drives;
    /// only one controller can be open at a time (it holds the driver's DMA
    /// pages).
    pub(crate) fn open(function: Function) -> Result<(Self, ControllerIdentity), Error> {
        let (
            Some(admin_submission),
            Some(admin_completion),
            Some(io_submission),
            Some(io_completion),
            Some(data),
        ) = (
            ADMIN_SUBMISSION.claim(),
            ADMIN_COMPLETION.claim(),
            IO_SUBMISSION.claim(),
            IO_COMPLETION.claim(),
            DATA.claim(),
        )
        else {
            return Err(Error::Busy);
        };
        let bar = function.memory_bar(0).ok_or(Error::NoMemoryBar)?;
        // The controller properties; the doorbells follow once CAP says
        // how far apart they are.
        let properties = Mmio::firmware(bar, DOORBELL_BASE).ok_or(Error::NoMemoryBar)?;
        function.enable_memory_and_bus_master();
        let capabilities = read64(&properties, REGISTER_CAPABILITIES);
        if capabilities == u64::MAX {
            return Err(Error::NotResponding);
        }
        // CAP.MQES is zero-based (section 3.1.3.1).
        let largest_queue = (capabilities & 0xffff) as u16;
        if largest_queue < QUEUE_ENTRIES - 1 {
            return Err(Error::QueuesTooSmall(largest_queue));
        }
        let doorbell_stride = 4_usize << ((capabilities >> 32) & 0xf);
        let minimum_page_shift = 12 + ((capabilities >> 48) & 0xf);
        if minimum_page_shift != 12 {
            return Err(Error::UnsupportedPageSize);
        }
        let ready_timeout = (((capabilities >> 24) & 0xff) / 2).max(1) + 1;
        // The admin and I/O queue pairs' four doorbells.
        let registers =
            Mmio::firmware(bar, DOORBELL_BASE + 4 * doorbell_stride).ok_or(Error::NoMemoryBar)?;

        registers.write::<u32>(REGISTER_CONFIGURATION, 0);
        if !wait_until(ready_timeout, || {
            registers.read::<u32>(REGISTER_STATUS) & STATUS_READY == 0
        }) {
            return Err(Error::DisableTimedOut);
        }

        let admin = Queue::new(
            admin_submission,
            admin_completion,
            DOORBELL_BASE,
            DOORBELL_BASE + doorbell_stride,
        );
        let io = Queue::new(
            io_submission,
            io_completion,
            DOORBELL_BASE + 2 * doorbell_stride,
            DOORBELL_BASE + 3 * doorbell_stride,
        );
        let entries = u32::from(QUEUE_ENTRIES - 1);
        registers.write::<u32>(REGISTER_ADMIN_QUEUE_ATTRIBUTES, (entries << 16) | entries);
        write64(
            &registers,
            REGISTER_ADMIN_SUBMISSION_QUEUE,
            admin.entries.device_address(0),
        );
        write64(
            &registers,
            REGISTER_ADMIN_COMPLETION_QUEUE,
            admin.completions.device_address(0),
        );
        // Section 3.5.1: configure CC, then enable in a second write. CAP
        // may change after the first CC write, so the timeout is read again.
        registers.write::<u32>(REGISTER_CONFIGURATION, CONFIGURATION_QUEUE_ENTRY_SIZES);
        let capabilities = read64(&registers, REGISTER_CAPABILITIES);
        let ready_timeout = (((capabilities >> 24) & 0xff) / 2).max(1) + 1;
        registers.write::<u32>(
            REGISTER_CONFIGURATION,
            CONFIGURATION_QUEUE_ENTRY_SIZES | CONFIGURATION_ENABLE,
        );
        if !wait_until(ready_timeout, || {
            registers.read::<u32>(REGISTER_STATUS) & (STATUS_READY | STATUS_FATAL) != 0
        }) {
            return Err(Error::EnableTimedOut);
        }
        if registers.read::<u32>(REGISTER_STATUS) & STATUS_FATAL != 0 {
            return Err(Error::ControllerFatal);
        }

        let mut controller = Self {
            registers,
            admin,
            io,
            data,
            buffer: [0; 4096],
            next_command: 0,
            namespace: 0,
            block_size: 0,
            block_count: 0,
            broken: false,
        };
        let identity = controller.identify_controller()?;
        controller.open_namespace()?;
        controller.create_io_queues()?;
        Ok((controller, identity))
    }

    /// Reads `count` blocks starting at `block` into the shared data page and
    /// returns it. At most one page is transferred.
    pub(crate) fn read(&mut self, block: u64, count: u32) -> Result<&[u8], Error> {
        let bytes = u64::from(count) * u64::from(self.block_size);
        if count == 0
            || bytes > 4096
            || block
                .checked_add(u64::from(count))
                .is_none_or(|end| end > self.block_count)
        {
            return Err(Error::OutOfRange);
        }
        let mut command = [0_u32; 16];
        command[1] = self.namespace;
        command[6] = self.data_address() as u32;
        command[7] = (self.data_address() >> 32) as u32;
        command[10] = block as u32;
        command[11] = (block >> 32) as u32;
        command[12] = count - 1;
        self.submit(false, OPCODE_READ, command)?;
        // The controller finished writing the page before completing.
        let bytes = bytes as usize;
        self.data.read_bytes(0, &mut self.buffer[..bytes]);
        Ok(&self.buffer[..bytes])
    }

    /// Writes `data`, whole blocks and at most one page, starting at `block`,
    /// then flushes the controller's write cache. Every block must lie inside
    /// `extent`, and the extent must come from this disk's partition table.
    pub(crate) fn write(
        &mut self,
        extent: &WritableExtent,
        block: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        let block_size = self.block_size as usize;
        if data.is_empty() || data.len() > 4096 || !data.len().is_multiple_of(block_size) {
            return Err(Error::OutOfRange);
        }
        let count = (data.len() / block_size) as u32;
        if !extent.contains(block, u64::from(count))
            || block
                .checked_add(u64::from(count))
                .is_none_or(|end| end > self.block_count)
        {
            return Err(Error::OutOfRange);
        }
        let header = self.read(gpt::HEADER_LBA, 1).map(gpt::parse_header)?;
        if header.is_none_or(|header| header.disk != extent.disk()) {
            return Err(Error::WrongDisk);
        }
        // No transfer is using the data page while it is filled.
        self.data.write_bytes(0, data);
        let mut command = [0_u32; 16];
        command[1] = self.namespace;
        command[6] = self.data_address() as u32;
        command[7] = (self.data_address() >> 32) as u32;
        command[10] = block as u32;
        command[11] = (block >> 32) as u32;
        command[12] = count - 1;
        self.submit(false, OPCODE_WRITE, command)?;
        let mut flush = [0_u32; 16];
        flush[1] = self.namespace;
        self.submit(false, OPCODE_FLUSH, flush)
    }

    /// Asks the controller to read `block` into the page at physical
    /// `address`, which this driver does not own. Only the DMA-protection
    /// self-test uses this: with remapping on, the transfer must fail.
    pub(crate) fn read_block_to(&mut self, block: u64, address: u64) -> Result<(), Error> {
        if self.block_size > 4096 || block >= self.block_count {
            return Err(Error::OutOfRange);
        }
        let mut command = [0_u32; 16];
        command[1] = self.namespace;
        command[6] = address as u32;
        command[7] = (address >> 32) as u32;
        command[10] = block as u32;
        command[11] = (block >> 32) as u32;
        self.submit(false, OPCODE_READ, command)
    }

    fn identify_controller(&mut self) -> Result<ControllerIdentity, Error> {
        let mut command = [0_u32; 16];
        command[6] = self.data_address() as u32;
        command[7] = (self.data_address() >> 32) as u32;
        command[10] = IDENTIFY_CONTROLLER;
        self.submit(true, OPCODE_IDENTIFY, command)?;
        let version = self.registers.read::<u32>(REGISTER_VERSION);
        // Identify completed into the data page.
        let data = self.copy_data();
        let mut identity = ControllerIdentity {
            serial: [0; 20],
            model: [0; 40],
            firmware: [0; 8],
            version,
        };
        identity.serial.copy_from_slice(&data[4..24]);
        identity.model.copy_from_slice(&data[24..64]);
        identity.firmware.copy_from_slice(&data[64..72]);
        Ok(identity)
    }

    fn open_namespace(&mut self) -> Result<(), Error> {
        let mut command = [0_u32; 16];
        command[6] = self.data_address() as u32;
        command[7] = (self.data_address() >> 32) as u32;
        command[10] = IDENTIFY_ACTIVE_NAMESPACES;
        self.submit(true, OPCODE_IDENTIFY, command)?;
        // Identify completed into the data page.
        let data = self.copy_data();
        let namespace = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if namespace == 0 {
            return Err(Error::NoNamespace);
        }

        command[1] = namespace;
        command[10] = IDENTIFY_NAMESPACE;
        self.submit(true, OPCODE_IDENTIFY, command)?;
        // Identify completed into the data page.
        let data = self.copy_data();
        let block_count = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
        // FLBAS (NVM Command Set section 4.1.5.1): bits 3:0 and, with more
        // than 16 formats, bits 6:5 above them select the LBA format.
        let flbas = data[26];
        let format = usize::from(flbas & 0x0f | (flbas >> 5 & 3) << 4).min(63);
        let entry = 128 + format * 4;
        let metadata = u16::from_le_bytes([data[entry], data[entry + 1]]);
        if metadata != 0 {
            return Err(Error::UnsupportedMetadata(metadata));
        }
        let block_shift = u32::from(data[entry + 2]);
        let block_size = 1_u32.checked_shl(block_shift).unwrap_or(0);
        if !(512..=4096).contains(&block_size) {
            return Err(Error::UnsupportedBlockSize(block_size));
        }
        self.namespace = namespace;
        self.block_size = block_size;
        self.block_count = block_count;
        Ok(())
    }

    fn data_address(&self) -> u64 {
        self.data.device_address(0)
    }

    /// Copies the data page into `buffer` and returns it.
    fn copy_data(&mut self) -> &[u8; 4096] {
        self.data.read_bytes(0, &mut self.buffer);
        &self.buffer
    }

    fn create_io_queues(&mut self) -> Result<(), Error> {
        let size = u32::from(QUEUE_ENTRIES - 1) << 16;
        let mut command = [0_u32; 16];
        let completions = self.io.completions.device_address(0);
        command[6] = completions as u32;
        command[7] = (completions >> 32) as u32;
        command[10] = size | 1;
        // Physically contiguous, interrupts disabled.
        command[11] = 1;
        self.submit(true, OPCODE_CREATE_IO_COMPLETION_QUEUE, command)?;

        let entries = self.io.entries.device_address(0);
        command[6] = entries as u32;
        command[7] = (entries >> 32) as u32;
        command[10] = size | 1;
        // Completion queue 1, physically contiguous.
        command[11] = (1 << 16) | 1;
        self.submit(true, OPCODE_CREATE_IO_SUBMISSION_QUEUE, command)
    }

    fn submit(&mut self, admin: bool, opcode: u8, mut command: [u32; 16]) -> Result<(), Error> {
        if self.broken {
            return Err(Error::Unusable);
        }
        let identifier = self.next_command;
        self.next_command = self.next_command.wrapping_add(1);
        command[0] = u32::from(opcode) | u32::from(identifier) << 16;
        let queue = if admin { &mut self.admin } else { &mut self.io };
        let slot = usize::from(queue.tail) * 64;
        for (index, word) in command.iter().enumerate() {
            queue.entries.write::<u32>(slot + index * 4, *word);
        }
        queue.tail = (queue.tail + 1) % QUEUE_ENTRIES;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.registers
            .write::<u32>(queue.submission_doorbell, u32::from(queue.tail));

        // Dword 3 of the completion entry at the head.
        let completion = usize::from(queue.head) * 16 + 12;
        let phase = queue.phase;
        let completions = &queue.completions;
        if !wait_until(COMMAND_TIMEOUT_SECONDS, || {
            (completions.read::<u32>(completion) >> 16 & 1 != 0) == phase
        }) {
            self.broken = true;
            return Err(Error::CommandTimedOut(opcode));
        }
        let status = (queue.completions.read::<u32>(completion) >> 17) as u16;
        let completed = queue.completions.read::<u32>(completion) as u16;
        queue.head += 1;
        if queue.head == QUEUE_ENTRIES {
            queue.head = 0;
            queue.phase = !queue.phase;
        }
        self.registers
            .write::<u32>(queue.completion_doorbell, u32::from(queue.head));
        // Completion dword 3 carries the command identifier (section 4.6).
        if completed != identifier {
            self.broken = true;
            return Err(Error::CompletionMismatch(completed));
        }
        if status & 0x7ff != 0 {
            return Err(Error::CommandFailed(opcode, status));
        }
        Ok(())
    }
}

impl Queue {
    fn new(
        entries: DmaPages,
        completions: DmaPages,
        submission_doorbell: usize,
        completion_doorbell: usize,
    ) -> Self {
        entries.fill(0, 4096, 0);
        completions.fill(0, 4096, 0);
        Self {
            entries,
            completions,
            tail: 0,
            head: 0,
            phase: true,
            submission_doorbell,
            completion_doorbell,
        }
    }
}

/// Shuts down the controller at `function` cleanly if it is enabled,
/// whoever enabled it (section 3.6.1), as an operating system must before
/// power goes: the drive then records a safe shutdown and needs no recovery
/// at its next start. The bring-up shell does this before reboot and
/// power-off.
///
/// `function` must be an NVMe controller that no other code drives.
pub(crate) fn shutdown(function: Function) -> bool {
    match function
        .memory_bar(0)
        .and_then(|bar| Mmio::firmware(bar, DOORBELL_BASE))
    {
        Some(registers) => shutdown_registers(&registers),
        None => false,
    }
}

fn shutdown_registers(registers: &Mmio) -> bool {
    let configuration = registers.read::<u32>(REGISTER_CONFIGURATION);
    if configuration == u32::MAX || configuration & CONFIGURATION_ENABLE == 0 {
        return false;
    }
    // RTD3E (Identify Controller) bounds the time; without reading it, use
    // the generous default.
    registers.write::<u32>(
        REGISTER_CONFIGURATION,
        configuration & !(3 << 14) | CONFIGURATION_SHUTDOWN_NORMAL,
    );
    wait_until(SHUTDOWN_TIMEOUT_SECONDS, || {
        registers.read::<u32>(REGISTER_STATUS) & STATUS_SHUTDOWN_MASK == STATUS_SHUTDOWN_COMPLETE
    })
}

/// The memory NVMe controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 5] {
    [
        DmaRegion::from(ADMIN_SUBMISSION.region()),
        DmaRegion::from(ADMIN_COMPLETION.region()),
        DmaRegion::from(IO_SUBMISSION.region()),
        DmaRegion::from(IO_COMPLETION.region()),
        DmaRegion::from(DATA.region()),
    ]
}

/// Reads a 64-bit register as two 32-bit reads, low half first.
fn read64(registers: &Mmio, offset: usize) -> u64 {
    u64::from(registers.read::<u32>(offset)) | u64::from(registers.read::<u32>(offset + 4)) << 32
}

/// Writes a 64-bit register as two 32-bit writes, low half first.
fn write64(registers: &Mmio, offset: usize, value: u64) {
    registers.write::<u32>(offset, value as u32);
    registers.write::<u32>(offset + 4, (value >> 32) as u32);
}

impl BlockDevice for Controller {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn read_blocks(&mut self, block: u64, count: u32) -> Option<&[u8]> {
        self.read(block, count).ok()
    }
}
