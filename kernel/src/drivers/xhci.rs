//! Polling xHCI driver for USB HID input devices and USB audio outputs.
//!
//! The driver takes each controller from firmware, resets it, and brings up
//! the command and event rings without interrupts. It enumerates root ports
//! and the hubs behind them, configures every HID boot keyboard, HID boot
//! mouse and QEMU USB tablet interface, keeping several report transfers
//! queued per interface, and configures the playback outputs of USB Audio
//! Class 1 and 2 devices. Each controller draws its DMA memory from a static
//! pool (`trusted::dma::DmaPool`) while it opens, so several controllers can
//! run at once; a controller without devices returns its pages.

#![forbid(unsafe_code)]

use linox_usb_audio as usb_audio;

use super::pci::Function;
use super::{delay_ms, say, wait_until_ms, DmaRegion};
use crate::trusted::dma::{DmaArena, DmaPool, DmaSpan};
use crate::trusted::mmio::Mmio;

const CAP_LENGTH: usize = 0x00;
const CAP_STRUCTURAL_1: usize = 0x04;
const CAP_STRUCTURAL_2: usize = 0x08;
const CAP_CAPABILITY_1: usize = 0x10;
const CAP_DOORBELL_OFFSET: usize = 0x14;
const CAP_RUNTIME_OFFSET: usize = 0x18;
const OP_COMMAND: usize = 0x00;
const OP_STATUS: usize = 0x04;
const OP_COMMAND_RING: usize = 0x18;
const OP_DEVICE_CONTEXTS: usize = 0x30;
const OP_CONFIGURE: usize = 0x38;
const OP_PORTS: usize = 0x400;
const COMMAND_RUN: u32 = 1 << 0;
const COMMAND_RESET: u32 = 1 << 1;
const STATUS_HALTED: u32 = 1 << 0;
const STATUS_NOT_READY: u32 = 1 << 11;
const PORT_CONNECTED: u32 = 1 << 0;
const PORT_ENABLED: u32 = 1 << 1;
const PORT_RESET: u32 = 1 << 4;
const PORT_POWER: u32 = 1 << 9;
const PORT_RESET_CHANGE: u32 = 1 << 21;
const PORT_WARM_RESET_CHANGE: u32 = 1 << 19;
const PORT_WARM_RESET: u32 = 1 << 31;
/// PORTSC Port Link State (xHCI 1.2 section 5.4.8, table 5-27).
const PORT_LINK_STATE_SHIFT: u32 = 5;
const LINK_INACTIVE: u32 = 6;
const LINK_COMPLIANCE: u32 = 10;
const CRCR_ABORT: u32 = 1 << 2;
const CRCR_RUNNING: u32 = 1 << 3;
// Bits that keep their value when written back; all others are RW1C/RW1S.
const PORT_PRESERVE: u32 = PORT_POWER | (0xf << 5) | (3 << 14) | (7 << 25);
const PORT_CHANGE_BITS: u32 = 0x7f << 17;
const LEGACY_SUPPORT: u32 = 1;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;
const LEGACY_DISABLE_SMI: u32 = (0x7 << 1) | (0xff << 5) | (0x7 << 17);
const LEGACY_SMI_EVENTS: u32 = 0x7 << 29;
/// Extended capability ID of a Supported Protocol capability (section 7.2).
const SUPPORTED_PROTOCOL: u32 = 2;

const TRB_NORMAL: u32 = 1;
const TRB_ISOCH: u32 = 5;
/// Start an isochronous transfer in the next possible frame.
const TRB_START_ISOCH_ASAP: u32 = 1 << 31;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_STOP_ENDPOINT: u32 = 15;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_EVALUATE_CONTEXT: u32 = 13;
const TRB_RESET_ENDPOINT: u32 = 14;
const TRB_SET_TR_DEQUEUE: u32 = 16;
const TRB_TRANSFER_EVENT: u32 = 32;
const TRB_COMMAND_COMPLETION: u32 = 33;
const TRB_CYCLE: u32 = 1 << 0;
const TRB_TOGGLE_CYCLE: u32 = 1 << 1;
/// Interrupt on Short Packet: report a short IN transfer with its residue
/// at the TRB it ended in (section 4.10.1.1).
const TRB_INTERRUPT_ON_SHORT_PACKET: u32 = 1 << 2;
const TRB_INTERRUPT_ON_COMPLETION: u32 = 1 << 5;
const TRB_IMMEDIATE_DATA: u32 = 1 << 6;
const TRB_DIRECTION_IN: u32 = 1 << 16;
const COMPLETION_SUCCESS: u32 = 1;
const COMPLETION_SHORT_PACKET: u32 = 13;
/// A transfer ended by a Stop Endpoint command, not by the device.
const COMPLETION_STOPPED: u32 = 26;
const RING_TRBS: usize = 256;
const MAX_SLOTS: u32 = 32;
const MAX_SCRATCHPADS: usize = 256;
/// HID input interfaces configured on one controller.
pub(crate) const MAX_INPUTS: usize = 4;
/// Report transfers kept queued per input interface.
const REPORT_SLOTS: u64 = 16;
/// The longest report the driver keeps; boot reports and QEMU's tablet
/// reports fit.
pub(crate) const REPORT_BYTES: usize = 8;
/// QEMU's emulated USB keyboard, mouse and tablet share this vendor and
/// product; only the tablet has no boot interface.
const QEMU_HID: (u16, u16) = (0x0627, 0x0001);
const CLASS_HID: u8 = 3;
const HID_SUBCLASS_BOOT: u8 = 1;
const HID_PROTOCOL_KEYBOARD: u8 = 1;
const HID_PROTOCOL_MOUSE: u8 = 2;
/// The SET_PROTOCOL value that selects the boot protocol.
const HID_BOOT_PROTOCOL: u16 = 0;
const ENDPOINT_CONTROL: u32 = 4;
const ENDPOINT_INTERRUPT_IN: u32 = 7;
const ENDPOINT_ISOCH_OUT: u32 = 1;
const REQUEST_SET_INTERFACE: u8 = 0x0b;
/// SET_CUR in USB Audio Class 1, and CUR in either direction in class 2.
const REQUEST_AUDIO_CURRENT: u8 = 0x01;
/// USB Audio Class 1 endpoint control selector for the sampling frequency.
const AUDIO_SAMPLING_FREQUENCY: u16 = 0x0100;
/// USB Audio Class 2 clock source control selector for the sampling frequency.
const AUDIO_2_SAMPLING_FREQUENCY: u16 = 0x0100;
/// USB Audio Class 2 clock selector control selector for its input pin.
const AUDIO_2_CLOCK_SELECTOR: u16 = 0x0100;
const AUDIO_AMPLITUDE: i16 = 6000;
/// Packets per transfer event; two batches are queued while a tone plays.
const AUDIO_BATCH: usize = 100;
/// Audio outputs configured on one controller.
pub(crate) const MAX_SPEAKERS: usize = usb_audio::MAX_OUTPUTS;
const SPEED_FULL: u32 = 1;
const SPEED_LOW: u32 = 2;
const SPEED_HIGH: u32 = 3;
const REQUEST_GET_STATUS: u8 = 0;
const REQUEST_CLEAR_FEATURE: u8 = 1;
const REQUEST_SET_FEATURE: u8 = 3;
const REQUEST_GET_DESCRIPTOR: u8 = 6;
const REQUEST_SET_CONFIGURATION: u8 = 9;
const REQUEST_HID_SET_IDLE: u8 = 0x0a;
const REQUEST_HID_SET_PROTOCOL: u8 = 0x0b;
const DESCRIPTOR_DEVICE: u16 = 1;
const DESCRIPTOR_CONFIGURATION: u16 = 2;
const DESCRIPTOR_HUB: u16 = 0x29;
const DESCRIPTOR_SUPERSPEED_HUB: u16 = 0x2a;
const CLASS_HUB: u8 = 9;
/// Hub class requests address a downstream port as the "other" recipient.
const HUB_PORT_OUT: u8 = 0x23;
const HUB_PORT_IN: u8 = 0xa3;
const HUB_DEVICE_IN: u8 = 0xa0;
const HUB_FEATURE_PORT_RESET: u16 = 4;
const HUB_FEATURE_PORT_POWER: u16 = 8;
const HUB_FEATURE_C_PORT_CONNECTION: u16 = 16;
const HUB_FEATURE_C_PORT_RESET: u16 = 20;
const HUB_PORT_CONNECTION: u32 = 1 << 0;
const HUB_PORT_ENABLE: u32 = 1 << 1;
const HUB_PORT_RESETTING: u32 = 1 << 4;
const HUB_PORT_LOW_SPEED: u32 = 1 << 9;
const HUB_PORT_HIGH_SPEED: u32 = 1 << 10;
const HUB_PORT_RESET_CHANGE: u32 = 1 << 20;
/// The xHCI speed ID of a SuperSpeed device.
const SPEED_SUPER: u32 = 4;
/// USB allows five tiers of hubs below the root hub.
const MAX_HUB_DEPTH: u32 = 5;
const HUB_PORT_LIMIT: u16 = 15;
const COMMAND_TIMEOUT_MS: u64 = 1000;
/// How long a controller may take to finish a reset. Most need milliseconds;
/// some real controllers take seconds, and Linux allows ten.
const RESET_TIMEOUT_MS: u64 = 10_000;
/// How long ports are watched for devices after the controller starts:
/// devices reconnect after the reset, and USB 3 links train on their own.
const PORT_SCAN_MS: u64 = 2000;
/// A connection must be stable this long before the port is reset (USB 2.0
/// section 7.1.7.3, TATTDB).
const DEBOUNCE_MS: u64 = 100;
/// Attempts at addressing a device before its port is given up.
const ATTACH_ATTEMPTS: usize = 3;
/// Corsair keyboards need time between control requests; Linux gives the
/// family USB_QUIRK_DELAY_INIT and USB_QUIRK_DELAY_CTRL_MSG.
const VENDOR_CORSAIR: u16 = 0x1b1c;
const CORSAIR_DELAY_MS: u64 = 200;
const POOL_PAGES: usize = 1536;

/// The DMA memory of every controller: each takes what it needs while it
/// opens and keeps it.
static POOL: DmaPool<POOL_PAGES> = DmaPool::new();

/// The memory xHCI controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 1] {
    [DmaRegion::from(POOL.region())]
}

/// Takes one zeroed page from the controller's DMA pages.
fn pool_page(arena: &mut DmaArena) -> Result<DmaSpan, Error> {
    arena.take(1).ok_or(Error::OutOfDmaMemory)
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    HaltTimedOut,
    ResetTimedOut,
    OutOfDmaMemory,
    TooManyScratchpads(usize),
    CommandTimedOut(u32),
    CommandFailed(u32, u32),
    TransferTimedOut,
    TransferFailed(u32),
    NotConnected,
    PortResetFailed,
    /// A device with neither a supported input interface nor audio
    /// outputs, by vendor and product.
    NotInputDevice(u16, u16),
    NoDevices,
    HubTooDeep,
    /// The device's configuration did not fit what the driver can track.
    NoRoom,
}

/// A transfer or command ring of TRBs (16 bytes each, four dwords) in one
/// DMA page, whose last TRB links back to the first.
struct Ring {
    trbs: DmaSpan,
    index: usize,
    cycle: bool,
}

impl Ring {
    /// Builds a ring in the zeroed page `page`.
    fn new(page: DmaSpan) -> Self {
        // The last TRB links back to the start and toggles the cycle state.
        let link = (RING_TRBS - 1) * 16;
        let base = page.device_address(0);
        page.write::<u32>(link, base as u32);
        page.write::<u32>(link + 4, (base >> 32) as u32);
        Self {
            trbs: page,
            index: 0,
            cycle: true,
        }
    }

    fn address(&self) -> u64 {
        self.trbs.device_address(0)
    }

    /// Where the next TRB goes, with the cycle state in bit 0, as a Set TR
    /// Dequeue Pointer command takes it.
    fn enqueue_pointer(&self) -> u64 {
        (self.address() + (self.index * 16) as u64) | u64::from(self.cycle)
    }

    /// The parameter of the TRB at `address`, if it lies in this ring.
    fn parameter_at(&self, address: u64) -> Option<u64> {
        let offset = address.checked_sub(self.address())?;
        if offset >= (RING_TRBS * 16) as u64 || offset % 16 != 0 {
            return None;
        }
        let trb = offset as usize;
        Some(
            u64::from(self.trbs.read::<u32>(trb)) | u64::from(self.trbs.read::<u32>(trb + 4)) << 32,
        )
    }

    /// Writes one TRB and returns its physical address.
    fn push(&mut self, parameter: u64, status: u32, control: u32) -> u64 {
        let trb = self.index * 16;
        self.trbs.write::<u32>(trb, parameter as u32);
        self.trbs.write::<u32>(trb + 4, (parameter >> 32) as u32);
        self.trbs.write::<u32>(trb + 8, status);
        self.trbs
            .write::<u32>(trb + 12, control | (u32::from(self.cycle) * TRB_CYCLE));
        let address = self.trbs.device_address(trb);
        self.index += 1;
        if self.index == RING_TRBS - 1 {
            let link = self.index * 16;
            self.trbs.write::<u32>(
                link + 12,
                TRB_LINK << 10 | TRB_TOGGLE_CYCLE | (u32::from(self.cycle) * TRB_CYCLE),
            );
            self.index = 0;
            self.cycle = !self.cycle;
        }
        address
    }
}

struct Event {
    parameter: u64,
    status: u32,
    control: u32,
}

impl Event {
    fn kind(&self) -> u32 {
        (self.control >> 10) & 0x3f
    }

    fn completion(&self) -> u32 {
        self.status >> 24
    }

    fn slot(&self) -> u32 {
        self.control >> 24
    }

    /// The endpoint context index of a transfer event.
    fn endpoint(&self) -> u32 {
        (self.control >> 16) & 0x1f
    }

    /// The bytes a transfer event says were not transferred.
    fn residue(&self) -> u32 {
        self.status & 0x00ff_ffff
    }
}

/// Where a device sits: a root port and the hub ports below it.
#[derive(Clone, Copy)]
pub(crate) struct Location {
    root_port: u32,
    /// The xHCI route string: one hub port number per tier, in 4-bit fields.
    route: u32,
    depth: u32,
    /// The slot and port of the high-speed hub whose transaction translator
    /// serves a low- or full-speed device, and whether it has one per port.
    translator: Option<(u32, u32, bool)>,
}

impl Location {
    fn root(port: u32) -> Self {
        Self {
            root_port: port,
            route: 0,
            depth: 0,
            translator: None,
        }
    }
}

impl core::fmt::Display for Location {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(output, "{}", self.root_port)?;
        for tier in 0..self.depth {
            write!(output, ".{}", (self.route >> (4 * tier)) & 0xf)?;
        }
        Ok(())
    }
}

/// What a HID input interface reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputKind {
    /// A keyboard in the boot protocol: modifiers, a reserved byte and six
    /// key usages.
    Keyboard,
    /// A mouse in the boot protocol: buttons, X and Y movement, and on most
    /// mice a wheel byte.
    Mouse,
    /// QEMU's USB tablet in its report protocol: buttons, absolute X and Y,
    /// and a wheel byte.
    Tablet,
}

/// A configured HID input interface with its interrupt-IN endpoint.
pub(crate) struct Input {
    pub(crate) location: Location,
    pub(crate) vendor: u16,
    pub(crate) product: u16,
    pub(crate) kind: InputKind,
    slot: u32,
    endpoint: u32,
    interrupt: Ring,
    /// The page whose slots receive reports, one slot per queued transfer.
    report: DmaSpan,
    /// Bytes each report transfer asks for: the endpoint's packet size.
    report_length: u32,
    /// Times the endpoint halted and was restarted; an input that keeps
    /// failing is dropped.
    recoveries: u8,
}

impl Input {
    /// The bytes between report slots in the report page.
    fn slot_stride(&self) -> u64 {
        u64::from(self.report_length.next_multiple_of(64))
    }

    /// The addresses of the report slots, each the buffer of one queued
    /// transfer.
    fn report_slots(&self) -> impl Iterator<Item = u64> {
        let stride = self.slot_stride();
        let slots = (4096 / stride).clamp(1, REPORT_SLOTS);
        let page = self.report.device_address(0);
        (0..slots).map(move |slot| page + slot * stride)
    }

    /// The report slot of the completed transfer TRB at `trb`, if the TRB
    /// is on this input's ring and points into its report page.
    fn completed_buffer(&self, trb: u64) -> Option<u64> {
        let buffer = self.interrupt.parameter_at(trb)?;
        let page = self.report.device_address(0);
        (buffer >= page && buffer + self.slot_stride() <= page + 4096).then_some(buffer)
    }
}

/// One report from an input interface.
pub(crate) struct Report {
    /// The interface's index among the controller's inputs.
    pub(crate) input: usize,
    pub(crate) kind: InputKind,
    /// The report's first bytes, zero past `length`.
    pub(crate) bytes: [u8; REPORT_BYTES],
    pub(crate) length: usize,
}

impl Report {
    pub(crate) fn data(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// An input interface found in a configuration descriptor, with its
/// interface number and interrupt-IN endpoint.
#[derive(Clone, Copy)]
struct InputInterface {
    kind: InputKind,
    interface: u8,
    endpoint: (u8, u16, u8),
}

/// Per-device DMA pages used while addressing and configuring a device.
struct DevicePages {
    output: DmaSpan,
    input: DmaSpan,
    control: DmaSpan,
    interrupt: DmaSpan,
    buffer: DmaSpan,
}

/// A configured USB audio output: an isochronous OUT endpoint on an audio
/// streaming interface, playing 48 kHz PCM.
pub(crate) struct Speaker {
    pub(crate) location: Location,
    pub(crate) vendor: u16,
    pub(crate) product: u16,
    /// What the output is wired to, such as "headphones".
    pub(crate) name: &'static str,
    pub(crate) channels: u8,
    pub(crate) bits: u8,
    slot: u32,
    endpoint: u32,
    ring: Ring,
    /// Microseconds between packets.
    period_us: u32,
    packet_bytes: usize,
    /// One period of the test tone, which whole packets tile.
    tone: DmaSpan,
    tone_bytes: usize,
}

/// A running controller with at least one configured input or speaker.
pub(crate) struct Controller {
    operational: Mmio,
    runtime: Mmio,
    doorbells: Mmio,
    context_size: usize,
    /// The device context base address array: entry 0 points at the
    /// scratchpad array, entry n at slot n's output device context.
    device_contexts: DmaSpan,
    commands: Ring,
    events: DmaSpan,
    event_index: usize,
    event_cycle: bool,
    inputs: [Option<Input>; MAX_INPUTS],
    speakers: [Option<Speaker>; MAX_SPEAKERS],
    /// Whether enumeration reports every device and hub, not only errors.
    verbose: bool,
    /// Root ports that speak USB 3 (bit n: port n + 1), from the Supported
    /// Protocol capabilities.
    usb3_ports: [u64; 4],
    /// The slot most recently enabled, so a failed attach can disable it.
    last_slot: u32,
}

impl Controller {
    /// Takes over `function`, whose registers (all of BAR 0) are
    /// `registers`, resets it, and configures every input interface and
    /// audio output on its ports, reporting each device when `verbose`. On
    /// failure the controller is halted and its DMA pages are returned to
    /// the pool. The controller's DMA memory is the pool's (which the
    /// kernel image's identity map covers); what else it reaches is the
    /// I/O MMU's policy.
    pub(crate) fn open(function: Function, registers: Mmio, verbose: bool) -> Result<Self, Error> {
        // Controllers open one at a time; another open in progress leaves
        // the pool nothing to give.
        let Some(mut arena) = POOL.arena() else {
            return Err(Error::OutOfDmaMemory);
        };
        let result = Self::open_inner(function, &registers, verbose, &mut arena);
        if result.is_err() {
            // The controller may still point at pool pages (contexts, rings,
            // scratchpads): reset it and cut its bus mastering before the
            // next controller is given them.
            if let Some(operational) = operational_registers(&registers) {
                halt_and_reset(&operational);
            }
            function.disable_bus_master();
            // Dropping the arena returns every page it took.
            drop(arena);
        } else {
            arena.keep();
        }
        result
    }

    fn open_inner(
        function: Function,
        base: &Mmio,
        verbose: bool,
        arena: &mut DmaArena,
    ) -> Result<Self, Error> {
        // Bound the capability walk by the register window, which is BAR
        // 0 as config space sizes it.
        let window = base.len().min(0x10_0000);
        function.enable_memory_and_bus_master();
        if base.read::<u32>(CAP_LENGTH) == u32::MAX {
            // Registers that read all ones: the function is not decoding.
            return Err(Error::NoMemoryBar);
        }
        let handoff = take_from_firmware(base, window);
        if handoff.firmware_kept && verbose {
            say!(
                "linox:   firmware did not release the controller (USB legacy support); took it\n"
            );
        }

        let operational = operational_registers(base).ok_or(Error::NoMemoryBar)?;
        let structural_1 = base.read::<u32>(CAP_STRUCTURAL_1);
        let structural_2 = base.read::<u32>(CAP_STRUCTURAL_2);
        let capability_1 = base.read::<u32>(CAP_CAPABILITY_1);
        let ports = structural_1 >> 24;
        let scratchpads =
            ((((structural_2 >> 21) & 0x1f) << 5) | ((structural_2 >> 27) & 0x1f)) as usize;
        let context_size = if capability_1 & (1 << 2) != 0 { 64 } else { 32 };

        // Section 4.2: wait for Controller Not Ready to clear before
        // touching the operational registers, then halt and reset.
        if !wait_until_ms(RESET_TIMEOUT_MS, || {
            operational.read::<u32>(OP_STATUS) & STATUS_NOT_READY == 0
        }) {
            return Err(Error::ResetTimedOut);
        }
        operational.write::<u32>(
            OP_COMMAND,
            operational.read::<u32>(OP_COMMAND) & !COMMAND_RUN,
        );
        // Section 5.4.2: the controller halts within 16 ms of R/S clearing.
        if !wait_until_ms(100, || {
            operational.read::<u32>(OP_STATUS) & STATUS_HALTED != 0
        }) {
            return Err(Error::HaltTimedOut);
        }
        operational.write::<u32>(OP_COMMAND, COMMAND_RESET);
        if !wait_until_ms(RESET_TIMEOUT_MS, || {
            operational.read::<u32>(OP_COMMAND) & COMMAND_RESET == 0
                && operational.read::<u32>(OP_STATUS) & STATUS_NOT_READY == 0
        }) {
            return Err(Error::ResetTimedOut);
        }

        if scratchpads > MAX_SCRATCHPADS {
            return Err(Error::TooManyScratchpads(scratchpads));
        }
        let device_contexts = pool_page(arena)?;
        if scratchpads != 0 {
            let array = pool_page(arena)?;
            let pages = arena.take(scratchpads).ok_or(Error::OutOfDmaMemory)?;
            for index in 0..scratchpads {
                array.write::<u64>(index * 8, pages.device_address(index * 4096));
            }
            device_contexts.write::<u64>(0, array.device_address(0));
        }
        let slots = (structural_1 & 0xff).min(MAX_SLOTS);
        operational.write::<u32>(OP_CONFIGURE, slots);
        write64(
            &operational,
            OP_DEVICE_CONTEXTS,
            device_contexts.device_address(0),
        );

        let commands = Ring::new(pool_page(arena)?);
        write64(&operational, OP_COMMAND_RING, commands.address() | 1);

        let events = pool_page(arena)?;
        let segments = pool_page(arena)?;
        let events_address = events.device_address(0);
        segments.write::<u32>(0, events_address as u32);
        segments.write::<u32>(4, (events_address >> 32) as u32);
        segments.write::<u32>(8, RING_TRBS as u32);
        let runtime = offset_registers(
            base,
            (base.read::<u32>(CAP_RUNTIME_OFFSET) & !0x1f) as usize,
        )
        .ok_or(Error::NoMemoryBar)?;
        let interrupter = 0x20;
        runtime.write::<u32>(interrupter + 0x08, 1);
        write64(&runtime, interrupter + 0x18, events_address);
        write64(&runtime, interrupter + 0x10, segments.device_address(0));

        operational.write::<u32>(OP_COMMAND, COMMAND_RUN);
        if !wait_until_ms(100, || {
            operational.read::<u32>(OP_STATUS) & STATUS_HALTED == 0
        }) {
            return Err(Error::HaltTimedOut);
        }

        let mut controller = Self {
            operational,
            runtime,
            doorbells: offset_registers(
                base,
                (base.read::<u32>(CAP_DOORBELL_OFFSET) & !0x3) as usize,
            )
            .ok_or(Error::NoMemoryBar)?,
            context_size,
            device_contexts,
            commands,
            events,
            event_index: 0,
            event_cycle: true,
            inputs: [const { None }; MAX_INPUTS],
            speakers: [const { None }; MAX_SPEAKERS],
            verbose,
            usb3_ports: handoff.usb3_ports,
            last_slot: 0,
        };
        if capability_1 & (1 << 3) != 0 {
            for port in 1..=ports {
                let register = controller.port_register(port);
                controller.operational.write::<u32>(
                    register,
                    controller.operational.read::<u32>(register) & PORT_PRESERVE | PORT_POWER,
                );
            }
            // Section 4.19.4: software waits 20 ms after setting Port Power.
            delay_ms(20);
        }
        controller.scan_root_ports(ports, arena);
        if controller.inputs().next().is_none() && controller.speakers().next().is_none() {
            controller.stop();
            return Err(Error::NoDevices);
        }
        // Several transfers stay queued per input, so reports that arrive
        // between polls wait in the event ring instead of being merged by
        // the device. At most MAX_INPUTS * REPORT_SLOTS transfers are
        // outstanding, fewer than the event ring holds.
        for index in 0..MAX_INPUTS {
            let Some(input) = controller.inputs[index].as_ref() else {
                continue;
            };
            for buffer in input.report_slots() {
                controller.queue_report(index, buffer);
            }
        }
        Ok(controller)
    }

    /// Returns the configured speakers.
    pub(crate) fn speakers(&self) -> impl Iterator<Item = &Speaker> {
        self.speakers.iter().flatten()
    }

    /// Plays a 500 Hz square wave for `milliseconds` on speaker `index` of
    /// `speakers`, one packet per service interval, and returns how many
    /// packets the controller sent. A second batch of packets is queued
    /// before waiting for the first, so the stream does not drain between
    /// batches.
    pub(crate) fn play_tone(&mut self, index: usize, milliseconds: usize) -> Option<usize> {
        let speaker = self.speakers.get(index)?.as_ref()?;
        let total = milliseconds * 1000 / speaker.period_us as usize;
        let (slot, endpoint, period_us) = (speaker.slot, speaker.endpoint, speaker.period_us);
        let mut queued = 0;
        let mut sent = 0;
        let mut in_flight: Option<(u64, usize)> = None;
        loop {
            let next = (queued < total).then(|| {
                let speaker = self.speakers[index].as_mut()?;
                let batch = (total - queued).min(AUDIO_BATCH);
                let mut last = 0;
                for packet in queued..queued + batch {
                    let offset = packet * speaker.packet_bytes % speaker.tone_bytes;
                    let interrupt = if packet + 1 == queued + batch {
                        TRB_INTERRUPT_ON_COMPLETION
                    } else {
                        0
                    };
                    last = speaker.ring.push(
                        speaker.tone.device_address(0) + offset as u64,
                        speaker.packet_bytes as u32,
                        TRB_ISOCH << 10 | TRB_START_ISOCH_ASAP | interrupt,
                    );
                }
                queued += batch;
                Some((last, batch))
            });
            let next = match next {
                Some(Some(batch)) => {
                    self.ring(slot, endpoint);
                    Some(batch)
                }
                Some(None) => return None,
                None => None,
            };
            if let Some((last, batch)) = in_flight {
                let batch_ms = (batch as u64 * u64::from(period_us)).div_ceil(1000);
                let finished = wait_until_ms(batch_ms * 2 + 100, || match self.next_event() {
                    Some(event)
                        if event.kind() == TRB_TRANSFER_EVENT && event.parameter == last =>
                    {
                        true
                    }
                    Some(event) => {
                        self.requeue_input(&event);
                        false
                    }
                    None => false,
                });
                if !finished {
                    return Some(sent);
                }
                sent += batch;
            }
            if next.is_none() {
                return Some(sent);
            }
            in_flight = next;
        }
    }

    /// Returns the configured input interfaces, in index order.
    pub(crate) fn inputs(&self) -> impl Iterator<Item = &Input> {
        self.inputs.iter().flatten()
    }

    /// Returns the configured keyboards.
    pub(crate) fn keyboards(&self) -> impl Iterator<Item = &Input> {
        self.inputs()
            .filter(|input| input.kind == InputKind::Keyboard)
    }

    /// Returns the next input report, if one has arrived, and queues its
    /// transfer again. Costs one memory read when no event is waiting.
    pub(crate) fn poll(&mut self) -> Option<Report> {
        // Skip events that carry no report, such as failed transfers.
        for _ in 0..RING_TRBS {
            let event = self.next_event()?;
            if event.kind() != TRB_TRANSFER_EVENT {
                continue;
            }
            let Some(index) = self.inputs.iter().position(|input| {
                input.as_ref().is_some_and(|input| {
                    input.slot == event.slot() && input.endpoint == event.endpoint()
                })
            }) else {
                continue;
            };
            let Some(input) = self.inputs[index].as_ref() else {
                continue;
            };
            // The event names the TRB it completed, which still holds the
            // address of the slot the report went to.
            let Some(buffer) = input.completed_buffer(event.parameter) else {
                continue;
            };
            let completed = matches!(
                event.completion(),
                COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET
            );
            let length =
                (input.report_length.saturating_sub(event.residue()) as usize).min(REPORT_BYTES);
            let mut bytes = [0; REPORT_BYTES];
            if completed {
                // The controller completed the transfer into this slot of
                // the report page, which is queued again only below.
                let slot = (buffer - input.report.device_address(0)) as usize;
                input.report.read_bytes(slot, &mut bytes[..length]);
            }
            let kind = input.kind;
            if !completed && event.completion() != COMPLETION_STOPPED {
                // A transaction error or babble halts the endpoint (section
                // 4.10.2): queued TRBs would never run again.
                self.recover_input(index);
                continue;
            }
            self.queue_report(index, buffer);
            if completed {
                return Some(Report {
                    input: index,
                    kind,
                    bytes,
                    length,
                });
            }
        }
        None
    }

    /// Gives back the report slot of an input transfer event that arrived
    /// while something else was waiting on the event ring (a command, a
    /// control transfer, a test tone). The report is dropped, but its slot
    /// is queued again: otherwise each such event would cost the input one
    /// of its slots for good, and a keyboard typed on during a beep would
    /// eventually go silent.
    fn requeue_input(&mut self, event: &Event) {
        if event.kind() != TRB_TRANSFER_EVENT {
            return;
        }
        let Some(index) = self.inputs.iter().position(|input| {
            input.as_ref().is_some_and(|input| {
                input.slot == event.slot() && input.endpoint == event.endpoint()
            })
        }) else {
            return;
        };
        let buffer = self.inputs[index]
            .as_ref()
            .and_then(|input| input.completed_buffer(event.parameter));
        if let Some(buffer) = buffer {
            self.queue_report(index, buffer);
        }
    }

    /// Restarts input `index` after its endpoint halted: Reset Endpoint, a
    /// clear of the device's halt, moving the dequeue pointer to the ring's
    /// enqueue pointer (dropping what was queued), and requeueing every
    /// report slot.
    fn recover_input(&mut self, index: usize) {
        let Some(input) = self.inputs.get_mut(index).and_then(Option::as_mut) else {
            return;
        };
        input.recoveries = input.recoveries.saturating_add(1);
        if input.recoveries > 8 {
            say!(
                "linox: USB input {:04x}:{:04x} on port {} keeps failing; dropped\n",
                input.vendor,
                input.product,
                input.location
            );
            self.inputs[index] = None;
            return;
        }
        let target = input.endpoint << 16 | input.slot << 24;
        let dequeue = input.interrupt.enqueue_pointer();
        let _ = self.command(0, TRB_RESET_ENDPOINT << 10 | target);
        let _ = self.command(dequeue, TRB_SET_TR_DEQUEUE << 10 | target);
        let Some(input) = self.inputs.get(index).and_then(Option::as_ref) else {
            return;
        };
        let slots: [Option<u64>; REPORT_SLOTS as usize] = {
            let mut slots = [None; REPORT_SLOTS as usize];
            for (slot, buffer) in slots.iter_mut().zip(input.report_slots()) {
                *slot = Some(buffer);
            }
            slots
        };
        for buffer in slots.into_iter().flatten() {
            self.queue_report(index, buffer);
        }
    }

    /// Halts the controller.
    pub(crate) fn stop(&mut self) {
        self.operational.write::<u32>(
            OP_COMMAND,
            self.operational.read::<u32>(OP_COMMAND) & !COMMAND_RUN,
        );
        let _ = wait_until_ms(100, || {
            self.operational.read::<u32>(OP_STATUS) & STATUS_HALTED != 0
        });
    }

    /// The offset of `port`'s status and control register in the
    /// operational registers.
    fn port_register(&self, port: u32) -> usize {
        OP_PORTS + 0x10 * (port as usize - 1)
    }

    fn is_usb3(&self, port: u32) -> bool {
        let bit = port as usize - 1;
        self.usb3_ports
            .get(bit / 64)
            .is_some_and(|word| word & 1 << (bit % 64) != 0)
    }

    /// Watches the root ports for [`PORT_SCAN_MS`] and attaches each device
    /// once its connection has been stable for [`DEBOUNCE_MS`]: devices
    /// reconnect at their own pace after the controller reset, and a slow
    /// one must not be missed because another came up first.
    fn scan_root_ports(&mut self, ports: u32, arena: &mut DmaArena) {
        const UNSEEN: u64 = u64::MAX;
        let ports = ports.min(255);
        let start = crate::arch::x86_64::timer::timestamp_counter();
        let mut seen = [UNSEEN; 255];
        let mut done = [false; 255];
        loop {
            let now = super::clock::elapsed_ms(start);
            let mut pending = false;
            for port in 1..=ports {
                let index = port as usize - 1;
                if done[index] {
                    continue;
                }
                if self.operational.read::<u32>(self.port_register(port)) & PORT_CONNECTED == 0 {
                    seen[index] = UNSEEN;
                    continue;
                }
                pending = true;
                if seen[index] == UNSEEN {
                    seen[index] = now;
                    continue;
                }
                if now - seen[index] < DEBOUNCE_MS {
                    continue;
                }
                done[index] = true;
                // A device that fails after its slot is enabled keeps its
                // pages unless the slot could be disabled again.
                match self.try_root_port(port, arena) {
                    Ok(()) | Err(Error::NotConnected) => {}
                    Err(error) => say!("linox:     port {}: {:?}\n", port, error),
                }
            }
            // Stop once the scan time is up, or earlier once every
            // connected port is handled and the slowest USB 3 link has had
            // time to train.
            if now >= PORT_SCAN_MS || (!pending && now >= PORT_SCAN_MS / 4) {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// Resets the root port (a warm reset for a USB 3 link stuck inactive
    /// or in compliance mode) and attaches its device, retrying a device
    /// that fails to address.
    fn try_root_port(&mut self, port: u32, arena: &mut DmaArena) -> Result<(), Error> {
        let register = self.port_register(port);
        let mut last = Error::NotConnected;
        for attempt in 0..ATTACH_ATTEMPTS {
            let status = self.reset_root_port(port, attempt > 0)?;
            let (inputs, speakers) = (self.inputs().count(), self.speakers().count());
            let mark = arena.mark();
            self.last_slot = 0;
            match self.attach(Location::root(port), (status >> 10) & 0xf, arena) {
                Ok(()) => return Ok(()),
                Err(error @ (Error::NotInputDevice(..) | Error::OutOfDmaMemory)) => {
                    return Err(error)
                }
                Err(error) => last = error,
            }
            // Retry only a device that added nothing the controller keeps.
            if self.inputs().count() != inputs || self.speakers().count() != speakers {
                return Err(last);
            }
            if self.disable_last_slot() {
                arena.release_to(mark);
            } else {
                return Err(last);
            }
            if self.operational.read::<u32>(register) & PORT_CONNECTED == 0 {
                return Err(last);
            }
            if self.verbose {
                say!(
                    "linox:     port {}: {:?}; resetting and trying again\n",
                    port,
                    last
                );
            }
        }
        Err(last)
    }

    /// Brings a connected root port to the Enabled state and returns its
    /// status. USB 2 ports are reset (section 4.3.1); USB 3 ports enable
    /// themselves once the link trains, unless the link is stuck, which
    /// takes a warm reset (section 4.19.5.1). `again` forces a reset.
    fn reset_root_port(&mut self, port: u32, again: bool) -> Result<u32, Error> {
        let register = self.port_register(port);
        let status = self.operational.read::<u32>(register);
        if status & PORT_CONNECTED == 0 {
            return Err(Error::NotConnected);
        }
        let usb3 = self.is_usb3(port);
        let link = (status >> PORT_LINK_STATE_SHIFT) & 0xf;
        if usb3
            && !again
            && status & PORT_ENABLED == 0
            && !matches!(link, LINK_INACTIVE | LINK_COMPLIANCE)
        {
            // Still training: give it time to reach U0.
            let _ = wait_until_ms(500, || {
                self.operational.read::<u32>(register) & PORT_ENABLED != 0
            });
        }
        let status = self.operational.read::<u32>(register);
        if again || status & PORT_ENABLED == 0 {
            let (reset, change) =
                if usb3 && (again || matches!(link, LINK_INACTIVE | LINK_COMPLIANCE)) {
                    (PORT_WARM_RESET, PORT_WARM_RESET_CHANGE | PORT_RESET_CHANGE)
                } else {
                    (PORT_RESET, PORT_RESET_CHANGE)
                };
            self.operational
                .write::<u32>(register, status & PORT_PRESERVE | reset);
            if !wait_until_ms(500, || self.operational.read::<u32>(register) & change != 0) {
                return Err(Error::PortResetFailed);
            }
            // USB 2.0 section 7.1.7.5: 10 ms of reset recovery (TRSTRCY).
            delay_ms(20);
        }
        let status = self.operational.read::<u32>(register);
        self.operational.write::<u32>(
            register,
            status & PORT_PRESERVE | (status & PORT_CHANGE_BITS),
        );
        if status & PORT_ENABLED == 0 {
            return Err(Error::PortResetFailed);
        }
        Ok(status)
    }

    /// Disables the slot the last attach enabled, so the controller stops
    /// using its contexts and the pages can be reused. Whether it did.
    fn disable_last_slot(&mut self) -> bool {
        let slot = core::mem::take(&mut self.last_slot);
        if slot == 0 {
            return true;
        }
        let disabled = self.command(0, TRB_DISABLE_SLOT << 10 | slot << 24).is_ok();
        if disabled {
            // The device-context array holds MAX_SLOTS + 1 entries.
            self.device_contexts.write::<u64>(slot as usize * 8, 0);
        }
        disabled
    }

    /// Addresses the device at `location`, then configures its input
    /// interfaces or audio outputs or, for a hub, enumerates the devices
    /// behind it.
    fn attach(
        &mut self,
        location: Location,
        speed: u32,
        arena: &mut DmaArena,
    ) -> Result<(), Error> {
        let pages = DevicePages {
            output: pool_page(arena)?,
            input: pool_page(arena)?,
            control: pool_page(arena)?,
            interrupt: pool_page(arena)?,
            buffer: pool_page(arena)?,
        };
        let mut device = Device {
            control: Ring::new(pages.control.clone()),
            pages,
            slot: 0,
            location,
            speed,
            request_delay_ms: 0,
        };
        let identity = device.address(self)?;
        if self.verbose {
            say!(
                "linox:     port {}: device {:04x}:{:04x} at speed {}\n",
                location,
                identity.vendor,
                identity.product,
                speed
            );
        }
        if identity.class == CLASS_HUB {
            return self.enumerate_hub(device, identity.protocol, arena);
        }
        if device.configure_inputs(self, &identity, arena)? != 0 {
            return Ok(());
        }
        if self.speakers.iter().any(Option::is_none)
            && device.configure_speakers(self, &identity, arena)? != 0
        {
            return Ok(());
        }
        Err(Error::NotInputDevice(identity.vendor, identity.product))
    }

    /// Configures `hub`, powers and resets each downstream port, and attaches
    /// what is connected there. `protocol` is the hub's device protocol: 1 or
    /// 2 for a high-speed hub with one or per-port transaction translators.
    fn enumerate_hub(
        &mut self,
        mut hub: Device,
        protocol: u8,
        arena: &mut DmaArena,
    ) -> Result<(), Error> {
        if hub.location.depth >= MAX_HUB_DEPTH {
            return Err(Error::HubTooDeep);
        }
        let ports = hub.configure_hub(self, protocol)?;
        if self.verbose {
            say!(
                "linox:     port {}: hub with {} ports\n",
                hub.location,
                ports
            );
        }
        for port in 1..=ports {
            match self.try_hub_port(&mut hub, port, protocol, arena) {
                Ok(()) | Err(Error::NotConnected) => {}
                Err(error) => say!("linox:     port {}.{}: {:?}\n", hub.location, port, error),
            }
        }
        Ok(())
    }

    fn try_hub_port(
        &mut self,
        hub: &mut Device,
        port: u16,
        protocol: u8,
        arena: &mut DmaArena,
    ) -> Result<(), Error> {
        let status = hub.port_status(self, port)?;
        if status & HUB_PORT_CONNECTION == 0 {
            return Err(Error::NotConnected);
        }
        hub.control_out(
            self,
            HUB_PORT_OUT,
            REQUEST_SET_FEATURE,
            HUB_FEATURE_PORT_RESET,
            port,
        )?;
        let mut status = 0;
        let reset = wait_until_ms(500, || {
            status = hub.port_status(self, port).unwrap_or(0);
            status & HUB_PORT_RESET_CHANGE != 0 && status & HUB_PORT_RESETTING == 0
        });
        for feature in [HUB_FEATURE_C_PORT_RESET, HUB_FEATURE_C_PORT_CONNECTION] {
            hub.control_out(self, HUB_PORT_OUT, REQUEST_CLEAR_FEATURE, feature, port)?;
        }
        if !reset || status & HUB_PORT_ENABLE == 0 {
            return Err(Error::PortResetFailed);
        }
        // USB 2.0 section 7.1.7.5: allow 10 ms of reset recovery.
        delay_ms(10);
        let speed = if hub.speed == SPEED_SUPER {
            SPEED_SUPER
        } else if status & HUB_PORT_LOW_SPEED != 0 {
            SPEED_LOW
        } else if status & HUB_PORT_HIGH_SPEED != 0 {
            SPEED_HIGH
        } else {
            SPEED_FULL
        };
        let parent = hub.location;
        // A low- or full-speed device below a high-speed hub talks through
        // that hub's transaction translator; deeper hubs pass it on.
        let translator = if hub.speed == SPEED_HIGH && matches!(speed, SPEED_LOW | SPEED_FULL) {
            Some((hub.slot, u32::from(port), protocol == 2))
        } else {
            parent.translator
        };
        let location = Location {
            root_port: parent.root_port,
            route: parent.route | u32::from(port.min(HUB_PORT_LIMIT)) << (4 * parent.depth),
            depth: parent.depth + 1,
            translator,
        };
        self.attach(location, speed, arena)
    }

    /// Queues a report transfer for input `index` into `buffer`, one of its
    /// report slots.
    fn queue_report(&mut self, index: usize, buffer: u64) {
        let Some(input) = self.inputs.get_mut(index).and_then(Option::as_mut) else {
            return;
        };
        input.interrupt.push(
            buffer,
            input.report_length,
            TRB_NORMAL << 10 | TRB_INTERRUPT_ON_COMPLETION | TRB_INTERRUPT_ON_SHORT_PACKET,
        );
        let (slot, endpoint) = (input.slot, input.endpoint);
        self.ring(slot, endpoint);
    }

    fn command(&mut self, parameter: u64, control: u32) -> Result<Event, Error> {
        let kind = (control >> 10) & 0x3f;
        let address = self.commands.push(parameter, 0, control);
        self.ring(0, 0);
        let mut result = Err(Error::CommandTimedOut(kind));
        wait_until_ms(COMMAND_TIMEOUT_MS, || {
            let Some(event) = self.next_event() else {
                return false;
            };
            if event.kind() != TRB_COMMAND_COMPLETION || event.parameter != address {
                self.requeue_input(&event);
                return false;
            }
            result = if event.completion() == COMPLETION_SUCCESS {
                Ok(event)
            } else {
                Err(Error::CommandFailed(kind, event.completion()))
            };
            true
        });
        if matches!(result, Err(Error::CommandTimedOut(_))) {
            self.abort_command();
        }
        result
    }

    /// Aborts the command the controller is stuck on, so the commands
    /// queued after it can run (section 4.6.1.2): set CRCR.CA, wait for the
    /// ring to stop, and drop the Command Ring Stopped event.
    fn abort_command(&mut self) {
        self.operational.write::<u32>(OP_COMMAND_RING, CRCR_ABORT);
        self.operational.write::<u32>(OP_COMMAND_RING + 4, 0);
        let _ = wait_until_ms(COMMAND_TIMEOUT_MS * 5, || {
            self.operational.read::<u32>(OP_COMMAND_RING) & CRCR_RUNNING == 0
        });
        while let Some(event) = self.next_event() {
            self.requeue_input(&event);
        }
    }

    fn ring(&self, slot: u32, target: u32) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.doorbells.write::<u32>(slot as usize * 4, target);
    }

    fn next_event(&mut self) -> Option<Event> {
        // event_index stays within the event ring page.
        let trb = self.event_index * 16;
        let control = self.events.read::<u32>(trb + 12);
        if (control & TRB_CYCLE != 0) != self.event_cycle {
            return None;
        }
        let parameter = u64::from(self.events.read::<u32>(trb))
            | u64::from(self.events.read::<u32>(trb + 4)) << 32;
        let event = Event {
            parameter,
            status: self.events.read::<u32>(trb + 8),
            control,
        };
        self.event_index += 1;
        if self.event_index == RING_TRBS {
            self.event_index = 0;
            self.event_cycle = !self.event_cycle;
        }
        let dequeue = self.events.device_address(0) + (self.event_index * 16) as u64;
        // Bit 3 (EHB) is write-one-to-clear and acknowledges the event.
        write64(&self.runtime, 0x20 + 0x18, dequeue | 1 << 3);
        Some(event)
    }
}

/// What a device descriptor says about a device.
struct Identity {
    vendor: u16,
    product: u16,
    class: u8,
    protocol: u8,
}

/// One device being addressed and configured, with its default control pipe.
/// A hub keeps this while the devices behind it are enumerated.
struct Device {
    pages: DevicePages,
    control: Ring,
    slot: u32,
    location: Location,
    speed: u32,
    /// A pause after each control request, for devices that need one.
    request_delay_ms: u64,
}

impl Device {
    /// Enables a slot, addresses the device, and reads its device descriptor.
    fn address(&mut self, controller: &mut Controller) -> Result<Identity, Error> {
        let completion = controller.command(0, TRB_ENABLE_SLOT << 10)?;
        self.slot = completion.slot();
        if self.slot == 0 || self.slot > MAX_SLOTS {
            return Err(Error::NoRoom);
        }
        controller.last_slot = self.slot;
        // The device-context array holds MAX_SLOTS + 1 entries.
        controller
            .device_contexts
            .write::<u64>(self.slot as usize * 8, self.pages.output.device_address(0));
        let packet = match self.speed {
            SPEED_LOW => 8,
            SPEED_FULL | SPEED_HIGH => 64,
            _ => 512,
        };
        self.clear_input();
        self.input(controller, 0, 1, 0b11);
        self.slot_context(controller, 1, None);
        self.write_endpoint0(controller, packet);
        controller.command(
            self.pages.input.device_address(0),
            TRB_ADDRESS_DEVICE << 10 | self.slot << 24,
        )?;
        // USB 2.0 section 9.2.6.3: two ms of SET_ADDRESS recovery; Linux
        // allows ten.
        delay_ms(10);

        // Read the first eight bytes to learn the real default-pipe packet size.
        self.control_in(
            controller,
            0x80,
            REQUEST_GET_DESCRIPTOR,
            DESCRIPTOR_DEVICE << 8,
            0,
            8,
        )?;
        let reported = u32::from(self.buffer::<8>()[7]);
        // USB 3 devices report the default-pipe packet size as a power of two.
        let actual = if self.speed > SPEED_HIGH {
            1_u32.checked_shl(reported).unwrap_or(0)
        } else {
            reported
        };
        if actual != packet && actual != 0 {
            self.clear_input();
            self.input(controller, 0, 1, 0b10);
            self.write_endpoint0(controller, actual);
            controller.command(
                self.pages.input.device_address(0),
                TRB_EVALUATE_CONTEXT << 10 | self.slot << 24,
            )?;
        }
        self.control_in(
            controller,
            0x80,
            REQUEST_GET_DESCRIPTOR,
            DESCRIPTOR_DEVICE << 8,
            0,
            18,
        )?;
        let device = self.buffer::<18>();
        let identity = Identity {
            vendor: u16::from_le_bytes([device[8], device[9]]),
            product: u16::from_le_bytes([device[10], device[11]]),
            class: device[4],
            protocol: device[6],
        };
        if identity.vendor == VENDOR_CORSAIR {
            self.request_delay_ms = CORSAIR_DELAY_MS;
            delay_ms(CORSAIR_DELAY_MS);
        }
        Ok(identity)
    }

    /// Reads the configuration descriptors into the buffer and returns their
    /// total length.
    fn read_configuration(&mut self, controller: &mut Controller) -> Result<u16, Error> {
        self.control_in(
            controller,
            0x80,
            REQUEST_GET_DESCRIPTOR,
            DESCRIPTOR_CONFIGURATION << 8,
            0,
            9,
        )?;
        let [_, _, low, high] = self.buffer::<4>();
        let total = u16::from_le_bytes([low, high]).min(4096);
        self.control_in(
            controller,
            0x80,
            REQUEST_GET_DESCRIPTOR,
            DESCRIPTOR_CONFIGURATION << 8,
            0,
            total,
        )?;
        Ok(total)
    }

    /// Configures the device's HID boot keyboard, boot mouse and QEMU tablet
    /// interfaces, as many as the controller has room for, each with its
    /// own interrupt-IN transfer ring and report page. Returns how many were
    /// added; none when the device has no such interface.
    fn configure_inputs(
        &mut self,
        controller: &mut Controller,
        identity: &Identity,
        arena: &mut DmaArena,
    ) -> Result<usize, Error> {
        let free = controller
            .inputs
            .iter()
            .filter(|input| input.is_none())
            .count();
        if free == 0 {
            return Ok(0);
        }
        let total = usize::from(self.read_configuration(controller)?);
        let descriptors = self.buffer::<4096>();
        let configuration = descriptors[5];
        let mut found = [None; MAX_INPUTS];
        let mut count = 0;
        let mut interface = None;
        let mut offset = 0;
        while offset + 2 <= total && count < free {
            let length = usize::from(descriptors[offset]);
            if length < 2 || offset + length > total {
                break;
            }
            let descriptor = &descriptors[offset..offset + length];
            match descriptor {
                // Only the default alternate setting of each interface.
                [_, 4, number, 0, _, class, subclass, protocol, ..] => {
                    interface = input_kind(identity, *class, *subclass, *protocol)
                        .map(|kind| (kind, *number));
                }
                [_, 4, ..] => interface = None,
                [_, 5, ..] => {
                    if let (Some((kind, number)), Some(endpoint)) =
                        (interface, interrupt_in_endpoint(descriptor))
                    {
                        found[count] = Some(InputInterface {
                            kind,
                            interface: number,
                            endpoint,
                        });
                        count += 1;
                        interface = None;
                    }
                }
                _ => {}
            }
            offset += length;
        }
        if count == 0 {
            return Ok(0);
        }

        self.control_out(
            controller,
            0x00,
            REQUEST_SET_CONFIGURATION,
            u16::from(configuration),
            0,
        )?;
        let mut entries = 1;
        let mut added = 0;
        for found in found.iter().flatten() {
            let Some(index) = controller.inputs.iter().position(Option::is_none) else {
                break;
            };
            let interface = u16::from(found.interface);
            if found.kind != InputKind::Tablet {
                if let Err(error) = self.control_out(
                    controller,
                    0x21,
                    REQUEST_HID_SET_PROTOCOL,
                    HID_BOOT_PROTOCOL,
                    interface,
                ) {
                    // Many keyboards send boot-format reports on their boot
                    // interface either way (Linux never asks), so carry on.
                    say!(
                        "linox:     port {}: interface {} refused the boot protocol ({:?}); using it anyway\n",
                        self.location,
                        interface,
                        error
                    );
                }
            }
            // SET_IDLE asks for reports only on change. It is optional; some
            // devices stall it.
            let _ = self.control_out(controller, 0x21, REQUEST_HID_SET_IDLE, 0, interface);
            // The first interface uses the device's own pages; the transfer
            // buffer is free once configuration is done.
            let (ring, report) = if added == 0 {
                (self.pages.interrupt.clone(), self.pages.buffer.clone())
            } else {
                (pool_page(arena)?, pool_page(arena)?)
            };
            let (number, packet, interval) = found.endpoint;
            let endpoint = self.configure_interrupt_in(
                controller,
                (number, packet, interval),
                &ring,
                &mut entries,
                None,
            )?;
            controller.inputs[index] = Some(Input {
                location: self.location,
                vendor: identity.vendor,
                product: identity.product,
                kind: found.kind,
                slot: self.slot,
                endpoint,
                interrupt: Ring::new(ring),
                report,
                report_length: u32::from(packet.max(1)),
                recoveries: 0,
            });
            added += 1;
        }
        Ok(added)
    }

    /// Configures the playback outputs of a USB Audio Class 1 or 2 device:
    /// selects the configuration, then for each output its streaming
    /// setting, its isochronous OUT endpoint and a 48 kHz rate. Returns how
    /// many outputs were added; an output that fails is reported and
    /// skipped.
    fn configure_speakers(
        &mut self,
        controller: &mut Controller,
        identity: &Identity,
        arena: &mut DmaArena,
    ) -> Result<usize, Error> {
        let total = self.read_configuration(controller)?;
        let buffer = self.buffer::<4096>();
        let descriptors = &buffer[..usize::from(total)];
        let configuration = descriptors[5];
        let outputs = usb_audio::outputs(descriptors);
        if outputs.iter().next().is_none() {
            return Ok(0);
        }
        self.control_out(
            controller,
            0x00,
            REQUEST_SET_CONFIGURATION,
            u16::from(configuration),
            0,
        )?;
        let mut added = 0;
        let mut entries = 1;
        for output in outputs.iter() {
            let Some(free) = controller.speakers.iter().position(Option::is_none) else {
                break;
            };
            match self.configure_output(controller, identity, output, &mut entries, arena) {
                Ok(Some(speaker)) => {
                    controller.speakers[free] = Some(speaker);
                    added += 1;
                }
                Ok(None) => say!(
                    "linox:     port {}: cannot play 48 kHz on the {} (interface {})\n",
                    self.location,
                    output.terminal_name(),
                    output.interface
                ),
                Err(error) => say!(
                    "linox:     port {}: {} (interface {}) failed: {:?}\n",
                    self.location,
                    output.terminal_name(),
                    output.interface,
                    error
                ),
            }
        }
        Ok(added)
    }

    /// Selects `output`'s streaming setting, adds its endpoint, and sets it
    /// to 48 kHz. Returns `None` when its packets cannot carry 48 kHz or the
    /// device reports another rate. `entries` is the highest endpoint
    /// context in use, which the slot context must cover.
    fn configure_output(
        &mut self,
        controller: &mut Controller,
        identity: &Identity,
        output: &usb_audio::Output,
        entries: &mut u32,
        arena: &mut DmaArena,
    ) -> Result<Option<Speaker>, Error> {
        let high_speed = self.speed >= SPEED_HIGH;
        let (Some(packet_bytes), Some(exponent)) = (
            output.packet_bytes(high_speed),
            self.speaker_interval(output.interval),
        ) else {
            return Ok(None);
        };
        let tone = pool_page(arena)?;
        let ring_page = pool_page(arena)?;
        // The tone page is a fresh, zeroed pool page that only this output
        // uses, and no transfer reads it yet.
        let mut period = [0; 4096];
        let tone_bytes = usb_audio::square_wave(
            &mut period,
            output.channels,
            output.subslot,
            AUDIO_AMPLITUDE,
        );
        tone.write_bytes(0, &period);
        let Some(tone_bytes) = tone_bytes else {
            return Ok(None);
        };
        self.control_out(
            controller,
            0x01,
            REQUEST_SET_INTERFACE,
            u16::from(output.alternate),
            u16::from(output.interface),
        )?;
        let endpoint = u32::from(output.endpoint) * 2;
        *entries = (*entries).max(endpoint);
        let ring = ring_page.device_address(0) | 1;
        let max_packet = u32::from(output.max_packet & 0x7ff);
        // High-speed endpoints may move up to three packets per microframe.
        let burst = if high_speed {
            u32::from((output.max_packet >> 11) & 3)
        } else {
            0
        };
        self.clear_input();
        self.input(controller, 0, 1, 1 | 1 << endpoint);
        self.slot_context(controller, *entries, None);
        let context = 1 + endpoint as usize;
        self.input(controller, context, 0, exponent << 16);
        self.input(
            controller,
            context,
            1,
            ENDPOINT_ISOCH_OUT << 3 | burst << 8 | max_packet << 16,
        );
        self.input(controller, context, 2, ring as u32);
        self.input(controller, context, 3, (ring >> 32) as u32);
        self.input(
            controller,
            context,
            4,
            packet_bytes as u32 | (max_packet * (burst + 1)) << 16,
        );
        controller.command(
            self.pages.input.device_address(0),
            TRB_CONFIGURE_ENDPOINT << 10 | self.slot << 24,
        )?;
        if !self.set_rate(controller, output) {
            return Ok(None);
        }
        Ok(Some(Speaker {
            location: self.location,
            vendor: identity.vendor,
            product: identity.product,
            name: output.terminal_name(),
            channels: output.channels,
            bits: output.bits,
            slot: self.slot,
            endpoint,
            ring: Ring::new(ring_page),
            period_us: output.period_us(high_speed),
            packet_bytes,
            tone,
            tone_bytes,
        }))
    }

    /// Asks for 48 kHz: from the endpoint in Audio Class 1, and from the
    /// clock source in class 2, whose rate is read back. Returns whether the
    /// device plays at 48 kHz, assuming so when it does not say. Devices may
    /// stall requests they do not implement, such as a fixed-rate clock.
    fn set_rate(&mut self, controller: &mut Controller, output: &usb_audio::Output) -> bool {
        let rate = usb_audio::SAMPLE_RATE.to_le_bytes();
        let Some(clock) = output.clock else {
            if output.version == usb_audio::Version::One {
                let _ = self.control_out_data(
                    controller,
                    0x22,
                    REQUEST_AUDIO_CURRENT,
                    AUDIO_SAMPLING_FREQUENCY,
                    u16::from(output.endpoint),
                    &rate[..3],
                );
            }
            return true;
        };
        // Class 2 requests address an entity of the AudioControl interface.
        let entity = |id: u8| u16::from(id) << 8 | u16::from(output.control_interface);
        if let Some(selector) = clock.selector {
            let _ = self.control_out_data(
                controller,
                0x21,
                REQUEST_AUDIO_CURRENT,
                AUDIO_2_CLOCK_SELECTOR,
                entity(selector),
                &[1],
            );
        }
        if clock.programmable {
            let _ = self.control_out_data(
                controller,
                0x21,
                REQUEST_AUDIO_CURRENT,
                AUDIO_2_SAMPLING_FREQUENCY,
                entity(clock.source),
                &rate,
            );
        }
        match self.control_in(
            controller,
            0xa1,
            REQUEST_AUDIO_CURRENT,
            AUDIO_2_SAMPLING_FREQUENCY,
            entity(clock.source),
            4,
        ) {
            Ok(()) => self.buffer::<4>() == rate,
            Err(_) => true,
        }
    }

    /// Converts an isochronous bInterval into the endpoint context's
    /// exponent of 125 us microframes.
    fn speaker_interval(&self, interval: u8) -> Option<u32> {
        let interval = u32::from(interval.clamp(1, 16)) - 1;
        Some(match self.speed {
            // Full-speed periods count 1 ms frames: eight microframes each.
            SPEED_FULL => interval + 3,
            SPEED_HIGH | SPEED_SUPER => interval,
            _ => return None,
        })
    }

    /// Configures a hub: selects its configuration, reads its hub descriptor,
    /// tells the controller it is a hub, and powers its ports. Returns the
    /// number of downstream ports.
    fn configure_hub(&mut self, controller: &mut Controller, protocol: u8) -> Result<u16, Error> {
        let total = self.read_configuration(controller)?;
        let descriptors = self.buffer::<4096>();
        let configuration = descriptors[5];
        let mut status_endpoint = None;
        let mut offset = 0;
        while offset + 2 <= usize::from(total) {
            let length = usize::from(descriptors[offset]);
            if length < 2 || offset + length > usize::from(total) {
                break;
            }
            if descriptors[offset + 1] == 5 && status_endpoint.is_none() {
                status_endpoint = interrupt_in_endpoint(&descriptors[offset..offset + length]);
            }
            offset += length;
        }
        self.control_out(
            controller,
            0x00,
            REQUEST_SET_CONFIGURATION,
            u16::from(configuration),
            0,
        )?;
        let descriptor = if self.speed == SPEED_SUPER {
            DESCRIPTOR_SUPERSPEED_HUB
        } else {
            DESCRIPTOR_HUB
        };
        self.control_in(
            controller,
            HUB_DEVICE_IN,
            REQUEST_GET_DESCRIPTOR,
            descriptor << 8,
            0,
            9,
        )?;
        let hub = self.buffer::<9>();
        let ports = u16::from(hub[2]).min(HUB_PORT_LIMIT);
        let characteristics = u16::from_le_bytes([hub[3], hub[4]]);
        let power_good_ms = u64::from(hub[5]) * 2;
        // Bits 6:5 of wHubCharacteristics give a high-speed hub's TT think
        // time; other hubs have no transaction translator.
        let think_time = if self.speed == SPEED_HIGH {
            u32::from(characteristics >> 5) & 3
        } else {
            0
        };
        let hub_fields = HubFields {
            ports: u32::from(ports),
            multi_translator: protocol == 2,
            think_time,
        };
        let status_endpoint = status_endpoint.unwrap_or((1, 2, 12));
        let ring = self.pages.interrupt.clone();
        self.configure_interrupt_in(controller, status_endpoint, &ring, &mut 1, Some(hub_fields))?;
        for port in 1..=ports {
            self.control_out(
                controller,
                HUB_PORT_OUT,
                REQUEST_SET_FEATURE,
                HUB_FEATURE_PORT_POWER,
                port,
            )?;
        }
        delay_ms(power_good_ms.max(100));
        Ok(ports)
    }

    /// Returns a hub port's status in the low half and its change bits in
    /// the high half.
    fn port_status(&mut self, controller: &mut Controller, port: u16) -> Result<u32, Error> {
        self.control_in(controller, HUB_PORT_IN, REQUEST_GET_STATUS, 0, port, 4)?;
        Ok(u32::from_le_bytes(self.buffer::<4>()))
    }

    /// Adds the interrupt-IN endpoint `(number, packet, interval)` with its
    /// transfer ring in `ring` and, for a hub, the hub fields of the slot
    /// context. `entries` is the highest endpoint context in use, which the
    /// slot context must cover. Returns the endpoint context index.
    fn configure_interrupt_in(
        &mut self,
        controller: &mut Controller,
        (number, packet, interval): (u8, u16, u8),
        ring: &DmaSpan,
        entries: &mut u32,
        hub: Option<HubFields>,
    ) -> Result<u32, Error> {
        let endpoint = u32::from(number) * 2 + 1;
        *entries = (*entries).max(endpoint);
        let exponent = match self.speed {
            SPEED_LOW | SPEED_FULL => {
                // Frames of 1 ms, expressed as 2^n microframes of 125 us.
                let microframes = u32::from(interval.max(1)) * 8;
                (31 - microframes.leading_zeros()).clamp(3, 10)
            }
            _ => u32::from(interval.clamp(1, 16)) - 1,
        };
        let ring = ring.device_address(0) | 1;
        self.clear_input();
        self.input(controller, 0, 1, 1 | 1 << endpoint);
        self.slot_context(controller, *entries, hub);
        let context = 1 + endpoint as usize;
        self.input(controller, context, 0, exponent << 16);
        self.input(
            controller,
            context,
            1,
            3 << 1 | ENDPOINT_INTERRUPT_IN << 3 | u32::from(packet) << 16,
        );
        self.input(controller, context, 2, ring as u32);
        self.input(controller, context, 3, (ring >> 32) as u32);
        self.input(controller, context, 4, 8 | u32::from(packet) << 16);
        controller.command(
            self.pages.input.device_address(0),
            TRB_CONFIGURE_ENDPOINT << 10 | self.slot << 24,
        )?;
        Ok(endpoint)
    }

    /// Writes the input slot context: route, speed and the last valid
    /// endpoint context, the root port, any transaction translator, and for
    /// a hub its port count and translator settings.
    fn slot_context(&mut self, controller: &Controller, entries: u32, hub: Option<HubFields>) {
        let location = self.location;
        let (translator_slot, translator_port, multi_translator) =
            location.translator.unwrap_or((0, 0, false));
        let hub_flags = hub.map_or(0, |hub| 1 << 26 | u32::from(hub.multi_translator) << 25);
        let multi = u32::from(hub.is_none() && multi_translator) << 25;
        self.input(
            controller,
            1,
            0,
            location.route | self.speed << 20 | multi | hub_flags | entries << 27,
        );
        self.input(
            controller,
            1,
            1,
            location.root_port << 16 | hub.map_or(0, |hub| hub.ports << 24),
        );
        self.input(
            controller,
            1,
            2,
            translator_slot | translator_port << 8 | hub.map_or(0, |hub| hub.think_time << 16),
        );
    }

    fn write_endpoint0(&mut self, controller: &Controller, packet: u32) {
        let ring = self.control.address() | 1;
        self.input(
            controller,
            2,
            1,
            3 << 1 | ENDPOINT_CONTROL << 3 | packet << 16,
        );
        self.input(controller, 2, 2, ring as u32);
        self.input(controller, 2, 3, (ring >> 32) as u32);
        self.input(controller, 2, 4, 8);
    }

    fn clear_input(&mut self) {
        self.pages.input.zero();
    }

    /// Writes dword `word` of input context entry `index` (0 is the input
    /// control context, 1 the slot, 2 endpoint 0, and so on).
    fn input(&mut self, controller: &Controller, index: usize, word: usize, value: u32) {
        // The offset stays within the 4 KiB input context page for the
        // entries this driver writes (at most 32 contexts of 64 bytes).
        let offset = index * controller.context_size + word * 4;
        self.pages.input.write::<u32>(offset, value);
    }

    /// The first `N` bytes of the device's transfer buffer (`N` at most a
    /// page), read after the transfer that filled it completed.
    fn buffer<const N: usize>(&self) -> [u8; N] {
        let mut bytes = [0; N];
        self.pages.buffer.read_bytes(0, &mut bytes);
        bytes
    }

    fn control_in(
        &mut self,
        controller: &mut Controller,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Result<(), Error> {
        let setup = u64::from(request_type)
            | u64::from(request) << 8
            | u64::from(value) << 16
            | u64::from(index) << 32
            | u64::from(length) << 48;
        self.control
            .push(setup, 8, TRB_SETUP << 10 | TRB_IMMEDIATE_DATA | 3 << 16);
        self.control.push(
            self.pages.buffer.device_address(0),
            u32::from(length),
            TRB_DATA << 10 | TRB_DIRECTION_IN | TRB_INTERRUPT_ON_SHORT_PACKET,
        );
        let status = self
            .control
            .push(0, 0, TRB_STATUS << 10 | TRB_INTERRUPT_ON_COMPLETION);
        self.transfer(controller, status)
    }

    fn control_out(
        &mut self,
        controller: &mut Controller,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
    ) -> Result<(), Error> {
        let setup = u64::from(request_type)
            | u64::from(request) << 8
            | u64::from(value) << 16
            | u64::from(index) << 32;
        self.control
            .push(setup, 8, TRB_SETUP << 10 | TRB_IMMEDIATE_DATA);
        let status = self.control.push(
            0,
            0,
            TRB_STATUS << 10 | TRB_INTERRUPT_ON_COMPLETION | TRB_DIRECTION_IN,
        );
        self.transfer(controller, status)
    }

    /// A control transfer with a short OUT data stage, such as a class
    /// request that sets a value.
    fn control_out_data(
        &mut self,
        controller: &mut Controller,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<(), Error> {
        let length = data.len().min(64) as u16;
        // The buffer page belongs to this device and no transfer is using
        // it.
        self.pages
            .buffer
            .write_bytes(0, &data[..usize::from(length)]);
        let setup = u64::from(request_type)
            | u64::from(request) << 8
            | u64::from(value) << 16
            | u64::from(index) << 32
            | u64::from(length) << 48;
        self.control
            .push(setup, 8, TRB_SETUP << 10 | TRB_IMMEDIATE_DATA | 2 << 16);
        self.control.push(
            self.pages.buffer.device_address(0),
            u32::from(length),
            TRB_DATA << 10,
        );
        let status = self.control.push(
            0,
            0,
            TRB_STATUS << 10 | TRB_INTERRUPT_ON_COMPLETION | TRB_DIRECTION_IN,
        );
        self.transfer(controller, status)
    }

    /// Rings endpoint 0 and waits for the transfer event of the TRB at
    /// `last`. An error on any earlier TRB of the transfer ends the wait.
    /// Events of other slots and endpoints are not this transfer's.
    fn transfer(&mut self, controller: &mut Controller, last: u64) -> Result<(), Error> {
        controller.ring(self.slot, 1);
        let mut result = Err(Error::TransferTimedOut);
        let control = &self.control;
        let slot = self.slot;
        wait_until_ms(COMMAND_TIMEOUT_MS, || {
            let Some(event) = controller.next_event() else {
                return false;
            };
            if event.kind() != TRB_TRANSFER_EVENT
                || event.slot() != slot
                || event.endpoint() != 1
                || control.parameter_at(event.parameter).is_none()
            {
                controller.requeue_input(&event);
                return false;
            }
            if !matches!(
                event.completion(),
                COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET
            ) {
                result = Err(Error::TransferFailed(event.completion()));
                return true;
            }
            if event.parameter == last {
                result = Ok(());
                return true;
            }
            false
        });
        let target = 1 << 16 | self.slot << 24;
        match result {
            Ok(()) => {}
            // Any error but a short packet halts the default control pipe
            // (section 4.10.2): reset it and move its dequeue pointer past
            // the failed transfer. The device clears a stall at the next
            // SETUP.
            Err(Error::TransferFailed(_)) => {
                let _ = controller.command(0, TRB_RESET_ENDPOINT << 10 | target);
                let _ = controller.command(
                    self.control.enqueue_pointer(),
                    TRB_SET_TR_DEQUEUE << 10 | target,
                );
            }
            // A device that never answers leaves the transfer on the ring:
            // stop the endpoint (section 4.6.9) and skip past it, or its
            // late completion would be taken for a later transfer's.
            Err(_) => {
                let _ = controller.command(0, TRB_STOP_ENDPOINT << 10 | target);
                let _ = controller.command(
                    self.control.enqueue_pointer(),
                    TRB_SET_TR_DEQUEUE << 10 | target,
                );
            }
        }
        if self.request_delay_ms != 0 {
            delay_ms(self.request_delay_ms);
        }
        result
    }
}

/// The slot-context fields that describe a hub.
#[derive(Clone, Copy)]
struct HubFields {
    ports: u32,
    multi_translator: bool,
    think_time: u32,
}

/// What an interface of the device `identity` with this class, subclass and
/// protocol reports, if the driver handles it.
fn input_kind(identity: &Identity, class: u8, subclass: u8, protocol: u8) -> Option<InputKind> {
    match (class, subclass, protocol) {
        (CLASS_HID, HID_SUBCLASS_BOOT, HID_PROTOCOL_KEYBOARD) => Some(InputKind::Keyboard),
        (CLASS_HID, HID_SUBCLASS_BOOT, HID_PROTOCOL_MOUSE) => Some(InputKind::Mouse),
        (CLASS_HID, 0, _) if (identity.vendor, identity.product) == QEMU_HID => {
            Some(InputKind::Tablet)
        }
        _ => None,
    }
}

/// Parses an endpoint descriptor and returns the number, maximum packet size
/// and interval of an interrupt-IN endpoint.
fn interrupt_in_endpoint(descriptor: &[u8]) -> Option<(u8, u16, u8)> {
    let [_, _, address, attributes, low, high, interval, ..] = *descriptor else {
        return None;
    };
    (address & 0x80 != 0 && attributes & 3 == 3).then(|| {
        (
            address & 0x0f,
            u16::from_le_bytes([low, high]) & 0x7ff,
            interval,
        )
    })
}

/// What the extended capabilities said.
struct Handoff {
    /// Firmware kept BIOS Owned set past the handoff wait.
    firmware_kept: bool,
    usb3_ports: [u64; 4],
}

/// Walks the extended capabilities (section 7) in the `window` bytes of
/// registers: performs the USB legacy-support handoff so firmware stops
/// driving the controller through SMIs (section 4.22.1), and records which
/// root ports speak USB 3 from the Supported Protocol capabilities
/// (section 7.2). A walk that leaves the window, reads all ones (a function
/// not decoding), or runs on too long ends.
fn take_from_firmware(base: &Mmio, window: usize) -> Handoff {
    let mut handoff = Handoff {
        firmware_kept: false,
        usb3_ports: [0; 4],
    };
    let mut offset = ((base.read::<u32>(CAP_CAPABILITY_1) >> 16) as usize) * 4;
    for _ in 0..64 {
        if offset == 0 || offset + 16 > window {
            break;
        }
        let capability = base.read::<u32>(offset);
        if capability == u32::MAX {
            break;
        }
        match capability & 0xff {
            LEGACY_SUPPORT => {
                base.write::<u32>(offset, capability | LEGACY_OS_OWNED);
                if !wait_until_ms(1000, || base.read::<u32>(offset) & LEGACY_BIOS_OWNED == 0) {
                    // Firmware did not let go; take the controller anyway,
                    // as section 4.22.1 permits after a timeout.
                    handoff.firmware_kept = true;
                    base.write::<u32>(offset, base.read::<u32>(offset) & !LEGACY_BIOS_OWNED);
                }
                let control = base.read::<u32>(offset + 4);
                base.write::<u32>(
                    offset + 4,
                    (control & LEGACY_DISABLE_SMI) | LEGACY_SMI_EVENTS,
                );
            }
            SUPPORTED_PROTOCOL if capability >> 24 == 3 => {
                let ports = base.read::<u32>(offset + 8);
                let first = ports & 0xff;
                let count = (ports >> 8) & 0xff;
                for port in first..first.saturating_add(count).min(256) {
                    if port != 0 {
                        let bit = port as usize - 1;
                        handoff.usb3_ports[bit / 64] |= 1 << (bit % 64);
                    }
                }
            }
            _ => {}
        }
        let next = ((capability >> 8) & 0xff) as usize * 4;
        if next == 0 {
            break;
        }
        offset += next;
    }
    handoff
}

/// Halts the controller whose operational registers are `operational`
/// and resets it, so it forgets every pointer into memory.
fn halt_and_reset(operational: &Mmio) {
    operational.write::<u32>(
        OP_COMMAND,
        operational.read::<u32>(OP_COMMAND) & !COMMAND_RUN,
    );
    if wait_until_ms(100, || {
        operational.read::<u32>(OP_STATUS) & STATUS_HALTED != 0
    }) {
        operational.write::<u32>(OP_COMMAND, COMMAND_RESET);
        let _ = wait_until_ms(RESET_TIMEOUT_MS, || {
            operational.read::<u32>(OP_COMMAND) & COMMAND_RESET == 0
        });
    }
}

/// The operational registers, which start CAPLENGTH bytes into BAR 0.
fn operational_registers(base: &Mmio) -> Option<Mmio> {
    offset_registers(base, usize::from(base.read::<u32>(CAP_LENGTH) as u8))
}

/// The registers from `offset` to the end of BAR 0.
fn offset_registers(base: &Mmio, offset: usize) -> Option<Mmio> {
    base.window(offset, base.len().checked_sub(offset)?)
}

/// Writes a 64-bit register as two 32-bit writes, low half first.
fn write64(registers: &Mmio, offset: usize, value: u64) {
    registers.write::<u32>(offset, value as u32);
    registers.write::<u32>(offset + 4, (value >> 32) as u32);
}
