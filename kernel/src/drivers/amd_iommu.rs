//! AMD I/O MMU (AMD-Vi) support: the IVRS table, a report of what firmware
//! set up, and DMA remapping that confines each device Linox drives to its
//! driver's buffers.
//!
//! References are to the AMD I/O Virtualization Technology (IOMMU)
//! Specification, publication 48882, revision 3.10 ("IOMMU spec").
//!
//! Remapping uses one device table for every unit, since a unit only sees
//! the requester IDs behind it. Each device gets one of three policies:
//! blocked (the default, including IDs no PCI function claims), passthrough
//! (display controllers, whose firmware framebuffer may live in system
//! memory), or an I/O page table that identity-maps only the regions its
//! driver owns. Devices of one driver share one domain and page table,
//! since they share the driver's static buffers. The unity ranges the
//! firmware declares in IVMD blocks are mapped for the devices they name,
//! so a blocked device that firmware says needs memory keeps exactly that.
//! Requester-ID aliases from IVHD device entries get their device's policy.
//! Interrupt remapping is left off; bring-up drivers poll.

use core::ptr::{addr_of, addr_of_mut};

use super::{wait_until_ms, DmaPage, DmaRegion};

const DEVICE_TABLE_BASE: usize = 0x00;
const COMMAND_BUFFER_BASE: usize = 0x08;
const EVENT_LOG_BASE: usize = 0x10;
const CONTROL: usize = 0x18;
const EXCLUSION_BASE: usize = 0x20;
const EXTENDED_FEATURES: usize = 0x30;
const COMMAND_HEAD: usize = 0x2000;
const COMMAND_TAIL: usize = 0x2008;
const EVENT_HEAD: usize = 0x2010;
const EVENT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;
// Control register bits (IOMMU spec section 3.4.1, MMIO offset 0018h).
const CONTROL_ENABLE: u64 = 1 << 0;
const CONTROL_HT_TUNNEL: u64 = 1 << 1;
const CONTROL_EVENT_LOG: u64 = 1 << 2;
const CONTROL_EVENT_INTERRUPT: u64 = 1 << 3;
const CONTROL_COMPLETION_INTERRUPT: u64 = 1 << 4;
const CONTROL_INVALIDATION_TIMEOUT: u64 = 7 << 5;
/// InvTimeOut = 100b: one second.
const CONTROL_INVALIDATION_TIMEOUT_1S: u64 = 4 << 5;
const CONTROL_PASS_POSTED_WRITE: u64 = 1 << 8;
const CONTROL_RESPONSE_PASS_POSTED_WRITE: u64 = 1 << 9;
const CONTROL_COHERENT: u64 = 1 << 10;
const CONTROL_ISOCHRONOUS: u64 = 1 << 11;
const CONTROL_COMMAND_BUFFER: u64 = 1 << 12;
const CONTROL_PPR_LOG: u64 = 1 << 13;
const CONTROL_PPR_INTERRUPT: u64 = 1 << 14;
const CONTROL_PPR: u64 = 1 << 15;
const CONTROL_GUEST_TRANSLATION: u64 = 1 << 16;
const CONTROL_GUEST_APIC: u64 = 1 << 17;
const CONTROL_GA_LOG: u64 = 1 << 28;
const CONTROL_GA_INTERRUPT: u64 = 1 << 29;
/// Everything firmware may have turned on that Linox does not configure:
/// the logs and interrupts it would deliver into firmware memory, guest
/// translation and guest interrupts.
const CONTROL_FIRMWARE_FEATURES: u64 = CONTROL_ENABLE
    | CONTROL_EVENT_LOG
    | CONTROL_EVENT_INTERRUPT
    | CONTROL_COMPLETION_INTERRUPT
    | CONTROL_COMMAND_BUFFER
    | CONTROL_PPR_LOG
    | CONTROL_PPR_INTERRUPT
    | CONTROL_PPR
    | CONTROL_GUEST_TRANSLATION
    | CONTROL_GUEST_APIC
    | CONTROL_GA_LOG
    | CONTROL_GA_INTERRUPT;
// Status register bits (section 3.4.10, MMIO offset 2020h).
const STATUS_EVENT_OVERFLOW: u64 = 1 << 0;
const STATUS_EVENT_LOG_RUNNING: u64 = 1 << 3;
const STATUS_COMMAND_BUFFER_RUNNING: u64 = 1 << 4;
const STATUS_PPR_LOG_RUNNING: u64 = 1 << 7;
const STATUS_GA_LOG_RUNNING: u64 = 1 << 8;
/// The write-one-to-clear interrupt and overflow bits.
const STATUS_CLEARABLE: u64 = 0b111 | 0b11 << 5 | 0b11 << 9;
const FEATURE_PREFETCH: u64 = 1 << 0;
const FEATURE_PPR: u64 = 1 << 1;
const FEATURE_X2APIC: u64 = 1 << 2;
const FEATURE_NX: u64 = 1 << 3;
const FEATURE_GUEST_TRANSLATION: u64 = 1 << 4;
const FEATURE_INVALIDATE_ALL: u64 = 1 << 6;
const FEATURE_GUEST_APIC: u64 = 1 << 7;
const FEATURE_PERFORMANCE_COUNTERS: u64 = 1 << 9;
// IVHD flags (section 5.2.2.1, table 89); the control register takes the
// first four from them.
const IVHD_HT_TUNNEL: u8 = 1 << 0;
const IVHD_PASS_POSTED_WRITE: u8 = 1 << 1;
const IVHD_RESPONSE_PASS_POSTED_WRITE: u8 = 1 << 2;
const IVHD_ISOCHRONOUS: u8 = 1 << 3;
// IVMD flags (section 5.2.2.3).
const IVMD_UNITY: u8 = 1 << 0;
const IVMD_READ: u8 = 1 << 1;
const IVMD_WRITE: u8 = 1 << 2;
const IVMD_EXCLUSION: u8 = 1 << 3;
/// Device table entries cover every 16-bit requester ID: 512 pages.
const DEVICE_IDS: usize = 1 << 16;
const DEVICE_TABLE_PAGES: u64 = (DEVICE_IDS * 32 / 4096) as u64;
/// The command buffer and event log each hold 2^8 entries of 16 bytes.
const RING_LENGTH_LOG2: u64 = 8;
const RING_BYTES: usize = 4096;
const ENTRY_VALID: u64 = 1 << 0;
const ENTRY_TRANSLATION_VALID: u64 = 1 << 1;
const ENTRY_MODE_SHIFT: u32 = 9;
const ENTRY_READ: u64 = 1 << 61;
const ENTRY_WRITE: u64 = 1 << 62;
/// Three page-table levels translate a 39-bit address space.
const PAGING_LEVELS: u64 = 3;
const PAGING_LIMIT: u64 = 1 << 39;
const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_NEXT_LEVEL_SHIFT: u32 = 9;
const PAGE_TABLE_POOL_PAGES: usize = 128;
const OPCODE_COMPLETION_WAIT: u32 = 1;
const OPCODE_INVALIDATE_DEVICE_ENTRY: u32 = 2;
const OPCODE_INVALIDATE_PAGES: u32 = 3;
const OPCODE_INVALIDATE_ALL: u32 = 8;
const EVENT_IO_PAGE_FAULT: u32 = 2;
const COMMAND_TIMEOUT_MS: u64 = 100;
/// How long a unit may take to stop its command buffer and logs.
const STOP_TIMEOUT_MS: u64 = 100;
/// The most requester IDs a table assigns explicitly, which are also the
/// entries invalidated one by one when a unit is enabled.
const ASSIGNED_LIMIT: usize = 512;
/// Domains one table can hold: one per driver plus the unity-only ones.
const DOMAIN_LIMIT: usize = 32;
pub(crate) const MAX_UNITS: usize = 8;
const MAX_UNITY_RANGES: usize = 16;
const MAX_ALIASES: usize = 32;

#[repr(C, align(4096))]
struct DeviceTable([[u64; 4]; DEVICE_IDS]);

static mut DEVICE_TABLE: DeviceTable = DeviceTable([[0; 4]; DEVICE_IDS]);
static mut COMMANDS: DmaPage = DmaPage::ZERO;
static mut EVENTS: DmaPage = DmaPage::ZERO;
static mut COMPLETION: DmaPage = DmaPage::ZERO;
static mut PAGE_TABLES: [DmaPage; PAGE_TABLE_POOL_PAGES] = [DmaPage::ZERO; PAGE_TABLE_POOL_PAGES];
static mut PAGE_TABLES_USED: usize = 0;

/// One IOMMU unit an IVHD block describes.
#[derive(Clone, Copy)]
pub(crate) struct Unit {
    pub(crate) base: u64,
    /// The unit's own requester ID (its PCI function).
    pub(crate) device: u16,
    pub(crate) segment: u16,
    /// IVHD flags, which say how to program the control register.
    pub(crate) flags: u8,
}

/// A memory range firmware requires some devices to reach (IVMD).
#[derive(Clone, Copy)]
pub(crate) struct UnityRange {
    pub(crate) first_device: u16,
    pub(crate) last_device: u16,
    pub(crate) start: u64,
    pub(crate) length: u64,
    pub(crate) flags: u8,
}

impl UnityRange {
    pub(crate) fn covers(&self, device: u16) -> bool {
        (self.first_device..=self.last_device).contains(&device)
    }

    pub(crate) fn is_exclusion(&self) -> bool {
        self.flags & IVMD_EXCLUSION != 0
    }
}

/// What the IVRS table says (IOMMU spec section 5.2).
pub(crate) struct Ivrs {
    /// IVinfo: bit 1 says firmware enabled DMA protection before the OS
    /// ("pre-boot DMA protection").
    pub(crate) info: u32,
    pub(crate) units: [Option<Unit>; MAX_UNITS],
    pub(crate) unity: [Option<UnityRange>; MAX_UNITY_RANGES],
    /// (requester ID, the alias its DMA carries).
    pub(crate) aliases: [Option<(u16, u16)>; MAX_ALIASES],
    /// Entries that did not fit in the arrays above.
    pub(crate) dropped: usize,
}

impl Ivrs {
    /// Whether firmware asked for DMA protection to stay on across boot.
    pub(crate) fn preboot_dma_protection(&self) -> bool {
        self.info & 1 << 1 != 0
    }

    /// The alias `device`'s DMA carries, if IVRS gives it one.
    pub(crate) fn alias_of(&self, device: u16) -> Option<u16> {
        self.aliases
            .iter()
            .flatten()
            .find(|(source, _)| *source == device)
            .map(|(_, alias)| *alias)
    }
}

/// Parses an IVRS table. Malformed blocks end the parse; what was read
/// before them is kept.
pub(crate) fn parse_ivrs(table: &[u8]) -> Ivrs {
    let mut ivrs = Ivrs {
        info: read_le(table, 36, 4).unwrap_or(0) as u32,
        units: [None; MAX_UNITS],
        unity: [None; MAX_UNITY_RANGES],
        aliases: [None; MAX_ALIASES],
        dropped: 0,
    };
    let length = (read_le(table, 4, 4).unwrap_or(0) as usize).min(table.len());
    let mut offset = 48;
    while offset + 4 <= length {
        let kind = table[offset];
        let size = read_le(table, offset + 2, 2).unwrap_or(0) as usize;
        if size < 4 || offset + size > length {
            break;
        }
        let block = &table[offset..offset + size];
        match kind {
            // IVHD types 10h, 11h and 40h (section 5.2.2.1).
            0x10 | 0x11 | 0x40 if size >= 24 => {
                let unit = Unit {
                    base: read_le(block, 8, 8).unwrap_or(0),
                    device: read_le(block, 4, 2).unwrap_or(0) as u16,
                    segment: read_le(block, 16, 2).unwrap_or(0) as u16,
                    flags: block[1],
                };
                // Several IVHD blocks of different types describe one unit;
                // firmware lists the oldest type first, so keep its flags.
                if unit.base != 0 && !ivrs.units.iter().flatten().any(|u| u.base == unit.base) {
                    match ivrs.units.iter_mut().find(|slot| slot.is_none()) {
                        Some(slot) => *slot = Some(unit),
                        None => ivrs.dropped += 1,
                    }
                }
                let entries = if kind == 0x10 { 24 } else { 40 };
                parse_device_entries(block.get(entries..).unwrap_or(&[]), &mut ivrs);
            }
            // IVMD types 20h (all devices), 21h (one), 22h (a range).
            0x20..=0x22 if size >= 32 => {
                let device = read_le(block, 4, 2).unwrap_or(0) as u16;
                let (first_device, last_device) = match kind {
                    0x20 => (0, u16::MAX),
                    0x21 => (device, device),
                    _ => (device, read_le(block, 6, 2).unwrap_or(0) as u16),
                };
                let range = UnityRange {
                    first_device,
                    last_device,
                    start: read_le(block, 16, 8).unwrap_or(0),
                    length: read_le(block, 24, 8).unwrap_or(0),
                    flags: block[1],
                };
                match ivrs.unity.iter_mut().find(|slot| slot.is_none()) {
                    Some(slot) => *slot = Some(range),
                    None => ivrs.dropped += 1,
                }
            }
            _ => {}
        }
        offset += size;
    }
    ivrs
}

/// Collects requester-ID aliases from IVHD device entries (section
/// 5.2.2.2): 4-byte entries for types below 40h, 8-byte ones up to 7Fh,
/// and variable-length ACPI HID entries (F0h).
fn parse_device_entries(entries: &[u8], ivrs: &mut Ivrs) {
    let mut offset = 0;
    let mut range_start: Option<(u16, Option<u16>)> = None;
    while offset < entries.len() {
        let kind = entries[offset];
        let size = match kind {
            0x00..=0x3f => 4,
            0x40..=0x7f => 8,
            // ACPI HID device: 22 bytes, then a UID of the length at byte 21.
            0xf0 => 22 + usize::from(*entries.get(offset + 21).unwrap_or(&0)),
            _ => break,
        };
        let Some(entry) = entries.get(offset..offset + size) else {
            break;
        };
        let device = read_le(entry, 1, 2).unwrap_or(0) as u16;
        match kind {
            // Select-range start and extended select-range start.
            0x03 | 0x47 => range_start = Some((device, None)),
            // Alias select: this device's DMA carries the source ID.
            0x42 => {
                let alias = read_le(entry, 5, 2).unwrap_or(0) as u16;
                add_alias(ivrs, device, alias);
            }
            // Alias range start: every device up to the range end aliases.
            0x43 => {
                let alias = read_le(entry, 5, 2).unwrap_or(0) as u16;
                range_start = Some((device, Some(alias)));
            }
            0x04 => {
                if let Some((first, Some(alias))) = range_start.take() {
                    for member in first..=device {
                        add_alias(ivrs, member, alias);
                    }
                }
            }
            _ => {}
        }
        offset += size;
    }
}

fn add_alias(ivrs: &mut Ivrs, device: u16, alias: u16) {
    if device == alias || ivrs.alias_of(device).is_some() {
        return;
    }
    match ivrs.aliases.iter_mut().find(|slot| slot.is_none()) {
        Some(slot) => *slot = Some((device, alias)),
        None => ivrs.dropped += 1,
    }
}

fn read_le(bytes: &[u8], offset: usize, width: usize) -> Option<u64> {
    let field = bytes.get(offset..offset.checked_add(width)?)?;
    Some(
        field
            .iter()
            .rev()
            .fold(0, |value, byte| value << 8 | u64::from(*byte)),
    )
}

/// What one AMD-Vi unit reports.
pub(crate) struct Report {
    pub(crate) control: u64,
    pub(crate) features: u64,
    pub(crate) status: u64,
    pub(crate) exclusion: u64,
}

impl Report {
    pub(crate) fn enabled(&self) -> bool {
        self.control & CONTROL_ENABLE != 0
    }

    /// Writes the names of notable supported features.
    pub(crate) fn write_features(&self, output: &mut impl core::fmt::Write) -> core::fmt::Result {
        const NAMES: [(u64, &str); 8] = [
            (FEATURE_PREFETCH, "prefetch"),
            (FEATURE_PPR, "ppr"),
            (FEATURE_X2APIC, "x2apic"),
            (FEATURE_NX, "nx"),
            (FEATURE_GUEST_TRANSLATION, "guest-translation"),
            (FEATURE_INVALIDATE_ALL, "invalidate-all"),
            (FEATURE_GUEST_APIC, "guest-apic"),
            (FEATURE_PERFORMANCE_COUNTERS, "perf-counters"),
        ];
        let mut first = true;
        for (bit, name) in NAMES {
            if self.features & bit != 0 {
                if !first {
                    output.write_char(' ')?;
                }
                output.write_str(name)?;
                first = false;
            }
        }
        if first {
            output.write_str("none")?;
        }
        Ok(())
    }
}

/// Reads the registers of the unit at physical address `base`.
///
/// # Safety
///
/// `base` must be an AMD-Vi MMIO block from IVRS that is identity mapped.
/// Reading these registers has no side effects.
pub(crate) unsafe fn probe(base: u64) -> Report {
    Report {
        control: read64(base as usize, CONTROL),
        features: read64(base as usize, EXTENDED_FEATURES),
        status: read64(base as usize, STATUS),
        exclusion: read64(base as usize, EXCLUSION_BASE),
    }
}

/// How a device may use DMA once remapping is on.
#[derive(Clone, Copy)]
pub(crate) enum Access<'a> {
    Blocked,
    Passthrough,
    /// Only these regions, identity mapped for reads and writes. Devices
    /// given the same slice share a domain.
    Regions(&'a [DmaRegion]),
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum Error {
    OutOfPageTables,
    TooManyDomains,
    TooManyDevices,
    /// A unity range lies beyond the 39 bits the page tables translate.
    UnityRangeTooHigh(u64),
    CommandTimedOut,
    /// The unit did not stop its command buffer or logs when told to.
    StillRunning(u64),
}

/// A fault the unit logged for a DMA it refused.
pub(crate) struct Fault {
    pub(crate) device: u16,
    pub(crate) address: u64,
    /// The event code; 2 is an I/O page fault.
    pub(crate) code: u32,
}

/// One domain: an I/O page table and the regions it was built for.
#[derive(Clone, Copy)]
struct Domain {
    root: u64,
    /// The driver's region slice it was built from (address, count), or
    /// none for a domain of unity ranges only.
    regions: Option<(usize, usize)>,
    /// Bit i set: unity range i is mapped.
    unity: u32,
}

/// The policies to install. Building a table is separate from enabling it
/// so that every unit shares one device table.
pub(crate) struct DeviceTableBuilder<'a> {
    unity: &'a [Option<UnityRange>],
    domains: [Option<Domain>; DOMAIN_LIMIT],
    assigned: [u16; ASSIGNED_LIMIT],
    assigned_count: usize,
}

impl<'a> DeviceTableBuilder<'a> {
    /// Starts a device table in which every requester ID is blocked. The
    /// unity ranges are mapped for the devices they cover as those devices
    /// are assigned.
    ///
    /// # Safety
    ///
    /// No unit may be using the device table or page-table pool, and only
    /// one builder may exist.
    pub(crate) unsafe fn new(unity: &'a [Option<UnityRange>]) -> Self {
        let table = &mut *addr_of_mut!(DEVICE_TABLE);
        for entry in table.0.iter_mut() {
            *entry = [ENTRY_VALID | ENTRY_TRANSLATION_VALID, 0, 0, 0];
        }
        PAGE_TABLES_USED = 0;
        Self {
            unity,
            domains: [None; DOMAIN_LIMIT],
            assigned: [0; ASSIGNED_LIMIT],
            assigned_count: 0,
        }
    }

    /// Sets the policy of requester ID `device`.
    pub(crate) fn assign(&mut self, device: u16, access: Access<'_>) -> Result<(), Error> {
        if self.assigned_count == ASSIGNED_LIMIT {
            return Err(Error::TooManyDevices);
        }
        // The unity ranges firmware requires for this device (exclusion
        // ranges are handled by the unit's exclusion registers instead).
        let unity = self
            .unity
            .iter()
            .enumerate()
            .filter_map(|(index, range)| Some((index, (*range)?)))
            .filter(|(_, range)| {
                range.covers(device) && range.flags & IVMD_UNITY != 0 && !range.is_exclusion()
            })
            .fold(0_u32, |mask, (index, _)| mask | 1 << index);
        let entry = match access {
            Access::Passthrough => [
                ENTRY_VALID | ENTRY_TRANSLATION_VALID | ENTRY_READ | ENTRY_WRITE,
                0,
                0,
                0,
            ],
            Access::Blocked if unity == 0 => [ENTRY_VALID | ENTRY_TRANSLATION_VALID, 0, 0, 0],
            Access::Blocked => self.translated(None, unity)?,
            Access::Regions(regions) => {
                self.translated(Some((regions.as_ptr() as usize, regions.len())), unity)?
            }
        };
        self.assigned[self.assigned_count] = device;
        self.assigned_count += 1;
        // SAFETY: the builder owns the device table until units use it.
        unsafe { (*addr_of_mut!(DEVICE_TABLE)).0[usize::from(device)] = entry };
        Ok(())
    }

    /// A translated device-table entry for the domain of `regions` plus the
    /// unity ranges in `unity`, building the domain if it is new.
    fn translated(
        &mut self,
        regions: Option<(usize, usize)>,
        unity: u32,
    ) -> Result<[u64; 4], Error> {
        let found = self
            .domains
            .iter()
            .position(|domain| domain.is_some_and(|d| d.regions == regions && d.unity == unity));
        let index = match found {
            Some(index) => index,
            None => {
                let index = self
                    .domains
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::TooManyDomains)?;
                let root = allocate_page_table()?;
                if let Some((address, count)) = regions {
                    // SAFETY: the pair came from a live slice in assign.
                    let regions =
                        unsafe { core::slice::from_raw_parts(address as *const DmaRegion, count) };
                    for region in regions {
                        map_range(root, region.start, region.length)?;
                    }
                }
                for (bit, range) in self.unity.iter().enumerate() {
                    if let Some(range) = range.filter(|_| unity & 1 << bit != 0) {
                        map_range(root, range.start, range.length)?;
                    }
                }
                self.domains[index] = Some(Domain {
                    root,
                    regions,
                    unity,
                });
                index
            }
        };
        let root = self.domains[index].map_or(0, |domain| domain.root);
        // Domain IDs start at 1; 0 is left for blocked and passthrough
        // entries, which have no page table to tag.
        Ok([
            ENTRY_VALID
                | ENTRY_TRANSLATION_VALID
                | PAGING_LEVELS << ENTRY_MODE_SHIFT
                | root
                | ENTRY_READ
                | ENTRY_WRITE,
            index as u64 + 1,
            0,
            0,
        ])
    }

    /// The number of domains with page tables.
    pub(crate) fn domains(&self) -> u16 {
        self.domains.iter().flatten().count() as u16
    }

    /// The requester IDs given an explicit policy.
    pub(crate) fn assigned(&self) -> &[u16] {
        &self.assigned[..self.assigned_count]
    }
}

/// One unit with remapping turned on.
pub(crate) struct Remapping {
    base: usize,
}

impl Remapping {
    /// Takes the unit over from firmware and turns on translation with the
    /// device table built so far:
    ///
    /// 1. Turns off translation, the command buffer, the event, PPR and
    ///    guest-APIC logs, their interrupts, and guest translation, and
    ///    waits until the status register says the buffer and logs have
    ///    stopped (section 3.4.10): firmware may have left any of them
    ///    running into memory that is now the kernel's.
    /// 2. Clears the latched status bits, including an event-log overflow,
    ///    which would otherwise keep the new log from recording.
    /// 3. Programs the device table, command buffer and event log bases
    ///    (allowed only while those are off, section 3.4.1), and the
    ///    control bits IVHD flags dictate, plus coherent table accesses and
    ///    a one-second invalidation timeout.
    /// 4. Enables the command buffer, event log and translation, then
    ///    invalidates every cached device entry and translation.
    ///
    /// # Safety
    ///
    /// `unit.base` must be an identity-mapped AMD-Vi unit from IVRS that
    /// nothing else drives, and the device table must not change while it
    /// is on.
    pub(crate) unsafe fn enable(
        unit: &Unit,
        table: &DeviceTableBuilder<'_>,
    ) -> Result<Self, Error> {
        let base = unit.base as usize;
        let control = read64(base, CONTROL) & !CONTROL_FIRMWARE_FEATURES;
        write64(base, CONTROL, control);
        let running = STATUS_EVENT_LOG_RUNNING
            | STATUS_COMMAND_BUFFER_RUNNING
            | STATUS_PPR_LOG_RUNNING
            | STATUS_GA_LOG_RUNNING;
        if !wait_until_ms(STOP_TIMEOUT_MS, || read64(base, STATUS) & running == 0) {
            return Err(Error::StillRunning(read64(base, STATUS)));
        }
        write64(base, STATUS, STATUS_CLEARABLE);
        (*addr_of_mut!(COMMANDS)).0.fill(0);
        (*addr_of_mut!(EVENTS)).0.fill(0);
        write64(
            base,
            DEVICE_TABLE_BASE,
            addr_of!(DEVICE_TABLE) as u64 | (DEVICE_TABLE_PAGES - 1),
        );
        write64(
            base,
            COMMAND_BUFFER_BASE,
            addr_of!(COMMANDS) as u64 | RING_LENGTH_LOG2 << 56,
        );
        write64(
            base,
            EVENT_LOG_BASE,
            addr_of!(EVENTS) as u64 | RING_LENGTH_LOG2 << 56,
        );
        for register in [COMMAND_HEAD, COMMAND_TAIL, EVENT_HEAD, EVENT_TAIL] {
            write64(base, register, 0);
        }
        let flag = |ivhd: u8, control: u64| if unit.flags & ivhd != 0 { control } else { 0 };
        let control = control
            & !(CONTROL_HT_TUNNEL
                | CONTROL_PASS_POSTED_WRITE
                | CONTROL_RESPONSE_PASS_POSTED_WRITE
                | CONTROL_ISOCHRONOUS
                | CONTROL_INVALIDATION_TIMEOUT)
            | flag(IVHD_HT_TUNNEL, CONTROL_HT_TUNNEL)
            | flag(IVHD_PASS_POSTED_WRITE, CONTROL_PASS_POSTED_WRITE)
            | flag(
                IVHD_RESPONSE_PASS_POSTED_WRITE,
                CONTROL_RESPONSE_PASS_POSTED_WRITE,
            )
            | flag(IVHD_ISOCHRONOUS, CONTROL_ISOCHRONOUS)
            | CONTROL_COHERENT
            | CONTROL_INVALIDATION_TIMEOUT_1S;
        write64(base, CONTROL, control);
        write64(
            base,
            CONTROL,
            control | CONTROL_COMMAND_BUFFER | CONTROL_EVENT_LOG | CONTROL_ENABLE,
        );
        let mut unit = Self { base };
        // Invalidate each assigned entry even when the unit can invalidate
        // everything at once: emulated units such as QEMU's re-read device
        // policies on these.
        if read64(base, EXTENDED_FEATURES) & FEATURE_INVALIDATE_ALL != 0 {
            unit.command([0, OPCODE_INVALIDATE_ALL << 28, 0, 0])?;
        }
        for device in table.assigned() {
            unit.command([
                u32::from(*device),
                OPCODE_INVALIDATE_DEVICE_ENTRY << 28,
                0,
                0,
            ])?;
        }
        for domain in 0..=table.domains() {
            // S=1 with every address bit set invalidates the whole domain.
            unit.command([
                0,
                u32::from(domain) | OPCODE_INVALIDATE_PAGES << 28,
                0xffff_f000 | 0b11,
                0x7fff_ffff,
            ])?;
        }
        unit.wait()?;
        Ok(unit)
    }

    /// The unit's register base.
    pub(crate) fn base(&self) -> u64 {
        self.base as u64
    }

    /// Whether the event log overflowed (and stopped recording).
    pub(crate) fn overflowed(&self) -> bool {
        read64(self.base, STATUS) & STATUS_EVENT_OVERFLOW != 0
    }

    /// Returns the next fault in the event log, if any.
    pub(crate) fn next_fault(&mut self) -> Option<Fault> {
        let head = read64(self.base, EVENT_HEAD) as usize & (RING_BYTES - 1);
        let tail = read64(self.base, EVENT_TAIL) as usize & (RING_BYTES - 1);
        if head == tail {
            return None;
        }
        // SAFETY: the unit finished writing entries before moving the tail.
        let entry = unsafe {
            let events = addr_of!(EVENTS).cast::<u32>().add(head / 4);
            [
                events.read_volatile(),
                events.add(1).read_volatile(),
                events.add(2).read_volatile(),
                events.add(3).read_volatile(),
            ]
        };
        write64(self.base, EVENT_HEAD, ((head + 16) % RING_BYTES) as u64);
        Some(Fault {
            device: entry[0] as u16,
            address: u64::from(entry[2]) | u64::from(entry[3]) << 32,
            code: entry[1] >> 28,
        })
    }

    /// Queues one command, waiting for room in the buffer.
    fn command(&mut self, words: [u32; 4]) -> Result<(), Error> {
        let tail = read64(self.base, COMMAND_TAIL) as usize & (RING_BYTES - 1);
        let next = (tail + 16) % RING_BYTES;
        if !wait_until_ms(COMMAND_TIMEOUT_MS, || {
            read64(self.base, COMMAND_HEAD) as usize & (RING_BYTES - 1) != next
        }) {
            return Err(Error::CommandTimedOut);
        }
        // SAFETY: the slot at the tail is not visible to the unit until the
        // tail moves past it.
        unsafe {
            let slot = addr_of_mut!(COMMANDS).cast::<u32>().add(tail / 4);
            for (index, word) in words.iter().enumerate() {
                slot.add(index).write_volatile(*word);
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write64(self.base, COMMAND_TAIL, next as u64);
        Ok(())
    }

    /// Waits until the unit has finished every queued command.
    fn wait(&mut self) -> Result<(), Error> {
        let store = addr_of_mut!(COMPLETION).cast::<u64>();
        // SAFETY: the completion page is only written here and by the unit.
        unsafe { store.write_volatile(0) };
        let address = store as u64;
        self.command([
            address as u32 | 1,
            (address >> 32) as u32 & 0xf_ffff | OPCODE_COMPLETION_WAIT << 28,
            1,
            0,
        ])?;
        // SAFETY: as above.
        if wait_until_ms(COMMAND_TIMEOUT_MS, || unsafe { store.read_volatile() } == 1) {
            Ok(())
        } else {
            Err(Error::CommandTimedOut)
        }
    }
}

impl Fault {
    /// Whether this is an I/O page fault: a DMA the page tables refused.
    pub(crate) fn is_page_fault(&self) -> bool {
        self.code == EVENT_IO_PAGE_FAULT
    }
}

impl UnityRange {
    /// Whether the device may read and write the range, per the IVMD flags.
    pub(crate) fn access(&self) -> (bool, bool) {
        (self.flags & IVMD_READ != 0, self.flags & IVMD_WRITE != 0)
    }
}

fn allocate_page_table() -> Result<u64, Error> {
    // SAFETY: the builder has exclusive use of the pool.
    unsafe {
        if PAGE_TABLES_USED == PAGE_TABLE_POOL_PAGES {
            return Err(Error::OutOfPageTables);
        }
        let page = addr_of_mut!(PAGE_TABLES[PAGE_TABLES_USED]);
        PAGE_TABLES_USED += 1;
        (*page).0.fill(0);
        Ok(page as u64)
    }
}

/// Identity-maps every page of `start..start + length`.
fn map_range(root: u64, start: u64, length: u64) -> Result<(), Error> {
    let first = start & !0xfff;
    let end = start.saturating_add(length).saturating_add(0xfff) & !0xfff;
    if end > PAGING_LIMIT {
        return Err(Error::UnityRangeTooHigh(start));
    }
    for page in (first..end).step_by(4096) {
        map_identity(root, page)?;
    }
    Ok(())
}

/// Maps `page` to itself, readable and writable, in the three-level table
/// rooted at `root`, adding intermediate tables as needed.
fn map_identity(root: u64, page: u64) -> Result<(), Error> {
    let mut table = root;
    for level in (1..=PAGING_LEVELS).rev() {
        let index = ((page >> (12 + 9 * (level - 1))) & 0x1ff) as usize;
        // SAFETY: every table address came from the page-table pool.
        let entry = unsafe { (table as *mut u64).add(index) };
        if level == 1 {
            // A leaf has next level 0.
            unsafe { entry.write_volatile(page | ENTRY_READ | ENTRY_WRITE | PAGE_PRESENT) };
            return Ok(());
        }
        let current = unsafe { entry.read_volatile() };
        table = if current & PAGE_PRESENT != 0 {
            current & 0x000f_ffff_ffff_f000
        } else {
            let next = allocate_page_table()?;
            unsafe {
                entry.write_volatile(
                    next | (level - 1) << PAGE_NEXT_LEVEL_SHIFT
                        | ENTRY_READ
                        | ENTRY_WRITE
                        | PAGE_PRESENT,
                )
            };
            next
        };
    }
    Ok(())
}

fn read64(base: usize, offset: usize) -> u64 {
    // SAFETY: callers pass identity-mapped unit registers.
    unsafe { ((base + offset) as *const u64).read_volatile() }
}

fn write64(base: usize, offset: usize, value: u64) {
    // SAFETY: as for read64.
    unsafe { ((base + offset) as *mut u64).write_volatile(value) }
}
