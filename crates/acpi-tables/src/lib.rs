#![forbid(unsafe_code)]
//! Parsing of the ACPI tables the kernel reads at boot: the root system
//! description pointer, the root table (RSDT or XSDT), the MADT and the
//! DMAR (ACPI 6.5 chapter 5, Intel VT-d specification chapter 8).
//!
//! Everything here works on byte slices the kernel copied or viewed from
//! firmware memory, with every field read bounds-checked, so the parsers
//! can be tested on the host. Lengths and checksums are validated against
//! each table's header before a table is parsed.

#![no_std]

/// The common header of every system description table.
pub const SDT_HEADER_SIZE: usize = 36;
/// The ACPI 1.0 root pointer; ACPI 2.0 and later extend it.
pub const RSDP_V1_SIZE: usize = 20;
pub const RSDP_V2_SIZE: usize = 36;
/// The longest table the kernel accepts.
pub const MAX_TABLE_SIZE: usize = 1024 * 1024;
/// The processors a MADT may list as enabled or online-capable.
pub const MAX_ENABLED_PROCESSORS: usize = 4;
/// A DMAR hardware unit definition without device scopes.
pub const DMAR_DRHD_SIZE: usize = 16;
pub const DMAR_DEVICE_SCOPE_MIN_SIZE: usize = 8;

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const MADT_FIXED_SIZE: usize = 44;
const MADT_ENABLED: u32 = 1;
const MADT_ONLINE_CAPABLE: u32 = 1 << 1;
const DMAR_FIXED_SIZE: usize = 48;
const DMAR_STRUCTURE_HEADER_SIZE: usize = 4;
const MAX_DMAR_ENDPOINT_SCOPES: usize = 64;
const MAX_ROOT_ENTRIES: usize = 4096;
const PAGE_SIZE: usize = 4096;

fn bytes_at<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

fn u8_at(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes_at(bytes, offset).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes_at(bytes, offset).map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes_at(bytes, offset).map(u64::from_le_bytes)
}

/// The byte sum ACPI checksums make zero.
pub fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |sum, byte| sum.wrapping_add(*byte))
}

/// Checks the ACPI 1.0 part of a root pointer (its first
/// [`RSDP_V1_SIZE`] bytes: signature and checksum) and returns its
/// revision.
pub fn rsdp_revision(prefix: &[u8]) -> Option<u8> {
    let prefix = prefix.get(..RSDP_V1_SIZE)?;
    (prefix.starts_with(RSDP_SIGNATURE) && checksum(prefix) == 0).then_some(prefix[15])
}

/// The length an ACPI 2.0 root pointer records (at byte 20), if it covers
/// at least the 2.0 fields.
pub fn rsdp_extended_length(rsdp: &[u8]) -> Option<usize> {
    let length = u32_at(rsdp, 20)? as usize;
    (length >= RSDP_V2_SIZE).then_some(length)
}

/// The root table a root pointer names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTable {
    pub address: u64,
    /// 8 for the XSDT's 64-bit entries, 4 for the RSDT's.
    pub entry_size: usize,
    pub signature: [u8; 4],
}

/// The XSDT when the root pointer (revision 2 or later, [`RSDP_V2_SIZE`]
/// bytes) names one, else the RSDT.
pub fn root_table(rsdp: &[u8]) -> Option<RootTable> {
    let rsdt = || {
        Some(RootTable {
            address: u64::from(u32_at(rsdp, 16)?),
            entry_size: 4,
            signature: *b"RSDT",
        })
    };
    if u8_at(rsdp, 15)? >= 2 {
        let xsdt = u64_at(rsdp, 24)?;
        if xsdt != 0 {
            return Some(RootTable {
                address: xsdt,
                entry_size: 8,
                signature: *b"XSDT",
            });
        }
    }
    rsdt()
}

/// The length a table's header records, if the header carries `signature`
/// and the length lies between the header's size and [`MAX_TABLE_SIZE`].
pub fn table_length(header: &[u8], signature: &[u8; 4]) -> Option<usize> {
    if !header.starts_with(signature) {
        return None;
    }
    let length = u32_at(header, 4)? as usize;
    (SDT_HEADER_SIZE..=MAX_TABLE_SIZE)
        .contains(&length)
        .then_some(length)
}

/// The table addresses a validated root table lists, if its payload is a
/// whole number of `entry_size` entries and not implausibly many.
pub fn root_entries(root: &[u8], entry_size: usize) -> Option<impl Iterator<Item = u64> + '_> {
    let payload = root.get(SDT_HEADER_SIZE..)?;
    if entry_size == 0
        || !payload.len().is_multiple_of(entry_size)
        || payload.len() / entry_size > MAX_ROOT_ENTRIES
    {
        return None;
    }
    Some(payload.chunks_exact(entry_size).map(move |entry| {
        if entry_size == 8 {
            u64_at(entry, 0).unwrap_or(0)
        } else {
            u64::from(u32_at(entry, 0).unwrap_or(0))
        }
    }))
}

/// What the MADT says about the interrupt controllers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Madt {
    pub enabled_processors: usize,
    pub processor_apic_ids: [u32; MAX_ENABLED_PROCESSORS],
    pub io_apics: usize,
    pub local_apic_address: u64,
    pub first_io_apic_address: u32,
    pub first_io_apic_gsi: u32,
}

impl Madt {
    fn record_processor(&mut self, apic_id: u32) -> Option<()> {
        if self.enabled_processors == MAX_ENABLED_PROCESSORS
            || self.processor_apic_ids[..self.enabled_processors].contains(&apic_id)
        {
            return None;
        }
        self.processor_apic_ids[self.enabled_processors] = apic_id;
        self.enabled_processors += 1;
        Some(())
    }
}

/// Parses a validated MADT (signature "APIC"). Fails on a malformed entry,
/// a duplicate or surplus processor, or a table without a processor, an
/// I/O APIC or a local APIC address.
pub fn parse_madt(table: &[u8]) -> Option<Madt> {
    if table.len() < MADT_FIXED_SIZE {
        return None;
    }
    let mut info = Madt {
        enabled_processors: 0,
        processor_apic_ids: [0; MAX_ENABLED_PROCESSORS],
        io_apics: 0,
        local_apic_address: u64::from(u32_at(table, 36)?),
        first_io_apic_address: 0,
        first_io_apic_gsi: 0,
    };
    let mut offset = MADT_FIXED_SIZE;
    while offset < table.len() {
        if table.len() - offset < 2 {
            return None;
        }
        let entry_type = table[offset];
        let entry_length = usize::from(table[offset + 1]);
        if entry_length < 2 || entry_length > table.len() - offset {
            return None;
        }
        let entry = &table[offset..offset + entry_length];
        match entry_type {
            0 if entry_length >= 8 => {
                let flags = u32_at(entry, 4)?;
                if flags & (MADT_ENABLED | MADT_ONLINE_CAPABLE) != 0 {
                    info.record_processor(u32::from(entry[3]))?;
                }
            }
            1 if entry_length >= 12 => {
                let io_apic_address = u32_at(entry, 4)?;
                let gsi = u32_at(entry, 8)?;
                if info.io_apics == 0 {
                    info.first_io_apic_address = io_apic_address;
                    info.first_io_apic_gsi = gsi;
                }
                info.io_apics = info.io_apics.checked_add(1)?;
            }
            5 if entry_length >= 12 => {
                info.local_apic_address = u64_at(entry, 4)?;
            }
            9 if entry_length >= 16 => {
                let apic_id = u32_at(entry, 4)?;
                let flags = u32_at(entry, 8)?;
                if flags & (MADT_ENABLED | MADT_ONLINE_CAPABLE) != 0 {
                    info.record_processor(apic_id)?;
                }
            }
            _ => {}
        }
        offset += entry_length;
    }
    (info.enabled_processors != 0 && info.io_apics != 0 && info.local_apic_address != 0)
        .then_some(info)
}

/// The PCI endpoints one DMAR hardware unit's device scopes name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceScopes {
    endpoint_source_ids: [u16; MAX_DMAR_ENDPOINT_SCOPES],
    endpoint_count: usize,
    scope_count: usize,
}

impl DeviceScopes {
    pub const EMPTY: Self = Self {
        endpoint_source_ids: [0; MAX_DMAR_ENDPOINT_SCOPES],
        endpoint_count: 0,
        scope_count: 0,
    };

    /// Every device scope of the unit, endpoints or not.
    pub fn scope_count(&self) -> usize {
        self.scope_count
    }

    pub fn contains_endpoint(&self, bus: u8, device: u8, function: u8) -> bool {
        let Some(source_id) = pci_source_id(bus, device, function) else {
            return false;
        };
        self.endpoint_source_ids[..self.endpoint_count].contains(&source_id)
    }
}

/// The 16-bit source ID of a PCI function.
pub fn pci_source_id(bus: u8, device: u8, function: u8) -> Option<u16> {
    (device < 32 && function < 8)
        .then_some((u16::from(bus) << 8) | (u16::from(device) << 3) | u16::from(function))
}

/// What the DMAR says about the I/O MMUs: how many hardware units, and the
/// first one's registers and scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dmar {
    pub units: usize,
    pub host_address_width: u8,
    pub first_register_base: u64,
    pub first_include_all: bool,
    pub first_scopes: DeviceScopes,
}

/// Parses a validated DMAR. Each unit's register page must lie below
/// `mapped_limit`, the physical memory the kernel maps.
pub fn parse_dmar(table: &[u8], mapped_limit: usize) -> Option<Dmar> {
    if table.len() < DMAR_FIXED_SIZE {
        return None;
    }
    let host_address_width = table[36].checked_add(1)?;
    let flags = table[37];
    if !(32..=64).contains(&host_address_width)
        || flags & !0x07 != 0
        || table[38..DMAR_FIXED_SIZE].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    parse_dmar_structures(&table[DMAR_FIXED_SIZE..], host_address_width, mapped_limit)
}

/// Parses the remapping structures after the DMAR's fixed fields; only
/// hardware unit definitions are interpreted, the others are skipped.
pub fn parse_dmar_structures(
    bytes: &[u8],
    host_address_width: u8,
    mapped_limit: usize,
) -> Option<Dmar> {
    let length = bytes.len();
    let mut offset = 0;
    let mut units = 0_usize;
    let mut first_register_base = 0_u64;
    let mut first_include_all = false;
    let mut first_scopes = DeviceScopes::EMPTY;
    while offset < length {
        if length - offset < DMAR_STRUCTURE_HEADER_SIZE {
            return None;
        }
        let kind = u16_at(bytes, offset)?;
        let structure_length = usize::from(u16_at(bytes, offset + 2)?);
        if structure_length < DMAR_STRUCTURE_HEADER_SIZE || structure_length > length - offset {
            return None;
        }
        let structure = &bytes[offset..offset + structure_length];
        if kind == 0 {
            if structure_length < DMAR_DRHD_SIZE {
                return None;
            }
            let flags = structure[4];
            let reserved = structure[5];
            let segment = u16_at(structure, 6)?;
            let register_base = u64_at(structure, 8)?;
            let scopes = parse_device_scopes(&structure[DMAR_DRHD_SIZE..])?;
            if flags & !1 != 0
                || reserved != 0
                || segment != 0
                || register_base == 0
                || !register_base.is_multiple_of(PAGE_SIZE as u64)
                || !range_is_mapped(
                    usize::try_from(register_base).ok()?,
                    PAGE_SIZE,
                    mapped_limit,
                )
            {
                return None;
            }
            units = units.checked_add(1)?;
            if units == 1 {
                first_register_base = register_base;
                first_include_all = flags & 1 != 0;
                first_scopes = scopes;
            }
        }
        offset += structure_length;
    }
    (offset == length && units != 0 && first_register_base != 0).then_some(Dmar {
        units,
        host_address_width,
        first_register_base,
        first_include_all,
        first_scopes,
    })
}

fn parse_device_scopes(bytes: &[u8]) -> Option<DeviceScopes> {
    let length = bytes.len();
    let mut scopes = DeviceScopes::EMPTY;
    let mut offset = 0;
    while offset < length {
        if length - offset < 2 {
            return None;
        }
        let scope_type = bytes[offset];
        let scope_length = usize::from(bytes[offset + 1]);
        if scope_length < DMAR_DEVICE_SCOPE_MIN_SIZE
            || scope_length > length - offset
            || !(scope_length - 6).is_multiple_of(2)
            || !(1..=5).contains(&scope_type)
            || u16_at(bytes, offset + 2)? != 0
        {
            return None;
        }
        let scope = &bytes[offset..offset + scope_length];
        let enumeration_id = scope[4];
        let start_bus = scope[5];
        if matches!(scope_type, 1 | 2) && enumeration_id != 0 {
            return None;
        }
        let path_entries = (scope_length - 6) / 2;
        for path in 0..path_entries {
            let device = scope[6 + path * 2];
            let function = scope[7 + path * 2];
            if device >= 32 || function >= 8 {
                return None;
            }
        }
        scopes.scope_count = scopes.scope_count.checked_add(1)?;
        if scope_type == 1 && path_entries == 1 {
            let source_id = pci_source_id(start_bus, scope[6], scope[7])?;
            if scopes.endpoint_count == MAX_DMAR_ENDPOINT_SCOPES
                || scopes.endpoint_source_ids[..scopes.endpoint_count].contains(&source_id)
            {
                return None;
            }
            scopes.endpoint_source_ids[scopes.endpoint_count] = source_id;
            scopes.endpoint_count += 1;
        }
        offset += scope_length;
    }
    (offset == length).then_some(scopes)
}

/// Whether `length` bytes at `address` lie below `mapped_limit`.
pub fn range_is_mapped(address: usize, length: usize, mapped_limit: usize) -> bool {
    length != 0
        && address < mapped_limit
        && address
            .checked_add(length - 1)
            .is_some_and(|end| end < mapped_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1 << 32;

    fn drhd() -> [u8; DMAR_DRHD_SIZE] {
        let mut valid = [0_u8; DMAR_DRHD_SIZE];
        valid[2..4].copy_from_slice(&(DMAR_DRHD_SIZE as u16).to_le_bytes());
        valid[4] = 1;
        valid[8..16].copy_from_slice(&0xfed9_0000_u64.to_le_bytes());
        valid
    }

    #[test]
    fn malformed_dmar_structures_are_rejected() {
        let valid = drhd();
        assert!(parse_dmar_structures(&valid, 48, LIMIT).is_some());
        let mut zero_length = valid;
        zero_length[2..4].copy_from_slice(&0_u16.to_le_bytes());
        let mut short_drhd = valid;
        short_drhd[2..4].copy_from_slice(&8_u16.to_le_bytes());
        let mut zero_base = valid;
        zero_base[8..16].fill(0);
        let mut unknown_flags = valid;
        unknown_flags[4] = 0x80;
        let mut trailing = [0_u8; DMAR_DRHD_SIZE + 1];
        trailing[..DMAR_DRHD_SIZE].copy_from_slice(&valid);
        let mut bad_scope = [0_u8; DMAR_DRHD_SIZE + DMAR_DEVICE_SCOPE_MIN_SIZE];
        bad_scope[..DMAR_DRHD_SIZE].copy_from_slice(&valid);
        let bad_scope_length = bad_scope.len() as u16;
        bad_scope[2..4].copy_from_slice(&bad_scope_length.to_le_bytes());
        bad_scope[4] = 0;
        bad_scope[DMAR_DRHD_SIZE + 1] = 7;
        for bytes in [
            zero_length.as_slice(),
            short_drhd.as_slice(),
            zero_base.as_slice(),
            unknown_flags.as_slice(),
            trailing.as_slice(),
            bad_scope.as_slice(),
        ] {
            assert!(parse_dmar_structures(bytes, 48, LIMIT).is_none());
        }
        // A unit whose registers lie beyond the mapped limit.
        assert!(parse_dmar_structures(&valid, 48, 0xfed9_0000).is_none());
    }

    #[test]
    fn dmar_endpoint_scopes_resolve() {
        let mut endpoint = [0_u8; DMAR_DRHD_SIZE + DMAR_DEVICE_SCOPE_MIN_SIZE];
        let endpoint_length = endpoint.len() as u16;
        endpoint[2..4].copy_from_slice(&endpoint_length.to_le_bytes());
        endpoint[8..16].copy_from_slice(&0xfed9_0000_u64.to_le_bytes());
        endpoint[DMAR_DRHD_SIZE] = 1;
        endpoint[DMAR_DRHD_SIZE + 1] = DMAR_DEVICE_SCOPE_MIN_SIZE as u8;
        endpoint[DMAR_DRHD_SIZE + 6] = 2;
        let info = parse_dmar_structures(&endpoint, 48, LIMIT).unwrap();
        assert!(!info.first_include_all);
        assert!(info.first_scopes.contains_endpoint(0, 2, 0));
        assert!(!info.first_scopes.contains_endpoint(0, 3, 0));
        assert!(!info.first_scopes.contains_endpoint(0, 2, 1));
        assert_eq!(info.first_scopes.scope_count(), 1);

        let mut duplicate = [0_u8; DMAR_DRHD_SIZE + 2 * DMAR_DEVICE_SCOPE_MIN_SIZE];
        duplicate[..endpoint.len()].copy_from_slice(&endpoint);
        let duplicate_length = duplicate.len() as u16;
        duplicate[2..4].copy_from_slice(&duplicate_length.to_le_bytes());
        duplicate[endpoint.len()..].copy_from_slice(&endpoint[DMAR_DRHD_SIZE..]);
        let mut reserved = endpoint;
        reserved[DMAR_DRHD_SIZE + 2] = 1;
        let mut enumeration = endpoint;
        enumeration[DMAR_DRHD_SIZE + 4] = 1;
        let mut invalid_device = endpoint;
        invalid_device[DMAR_DRHD_SIZE + 6] = 32;
        let mut invalid_function = endpoint;
        invalid_function[DMAR_DRHD_SIZE + 7] = 8;
        let mut unknown_type = endpoint;
        unknown_type[DMAR_DRHD_SIZE] = 6;
        for bytes in [
            duplicate.as_slice(),
            reserved.as_slice(),
            enumeration.as_slice(),
            invalid_device.as_slice(),
            invalid_function.as_slice(),
            unknown_type.as_slice(),
        ] {
            assert!(parse_dmar_structures(bytes, 48, LIMIT).is_none());
        }
    }

    fn with_checksum(mut table: [u8; 64], length: usize) -> [u8; 64] {
        table[9] = 0;
        let sum = checksum(&table[..length]);
        table[9] = sum.wrapping_neg();
        table
    }

    #[test]
    fn dmar_fixed_fields_are_checked() {
        let mut table = [0_u8; 64];
        table[..4].copy_from_slice(b"DMAR");
        table[4..8].copy_from_slice(&64_u32.to_le_bytes());
        table[36] = 47;
        table[48..64].copy_from_slice(&drhd());
        let table = with_checksum(table, 64);
        assert_eq!(table_length(&table, b"DMAR"), Some(64));
        assert_eq!(checksum(&table), 0);
        let info = parse_dmar(&table, LIMIT).unwrap();
        assert_eq!(info.host_address_width, 48);
        assert_eq!(info.units, 1);
        assert_eq!(info.first_register_base, 0xfed9_0000);
        assert!(info.first_include_all);
        let mut narrow = table;
        narrow[36] = 30;
        assert!(parse_dmar(&narrow, LIMIT).is_none());
        let mut flagged = table;
        flagged[37] = 0x08;
        assert!(parse_dmar(&flagged, LIMIT).is_none());
        let mut reserved = table;
        reserved[40] = 1;
        assert!(parse_dmar(&reserved, LIMIT).is_none());
    }

    fn madt(entries: &[&[u8]]) -> ([u8; 128], usize) {
        let mut table = [0_u8; 128];
        table[..4].copy_from_slice(b"APIC");
        table[36..40].copy_from_slice(&0xfee0_0000_u32.to_le_bytes());
        let mut length = MADT_FIXED_SIZE;
        for entry in entries {
            table[length..length + entry.len()].copy_from_slice(entry);
            length += entry.len();
        }
        table[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        (table, length)
    }

    const PROCESSOR_0: [u8; 8] = [0, 8, 0, 0, 1, 0, 0, 0];
    const PROCESSOR_1: [u8; 8] = [0, 8, 1, 1, 1, 0, 0, 0];
    const DISABLED: [u8; 8] = [0, 8, 2, 7, 0, 0, 0, 0];
    const IO_APIC: [u8; 12] = [1, 12, 0, 0, 0x00, 0x00, 0xc0, 0xfe, 0, 0, 0, 0];

    #[test]
    fn madt_lists_processors_and_io_apics() {
        let (table, length) = madt(&[&PROCESSOR_0, &PROCESSOR_1, &DISABLED, &IO_APIC]);
        let info = parse_madt(&table[..length]).unwrap();
        assert_eq!(info.enabled_processors, 2);
        assert_eq!(info.processor_apic_ids[..2], [0, 1]);
        assert_eq!(info.io_apics, 1);
        assert_eq!(info.first_io_apic_address, 0xfec0_0000);
        assert_eq!(info.local_apic_address, 0xfee0_0000);
    }

    #[test]
    fn malformed_madts_are_rejected() {
        let (table, length) = madt(&[&PROCESSOR_0, &PROCESSOR_0, &IO_APIC]);
        assert!(
            parse_madt(&table[..length]).is_none(),
            "duplicate processor"
        );
        let (table, length) = madt(&[&PROCESSOR_0]);
        assert!(parse_madt(&table[..length]).is_none(), "no I/O APIC");
        let (mut table, length) = madt(&[&PROCESSOR_0, &IO_APIC]);
        table[MADT_FIXED_SIZE + 1] = 1;
        assert!(parse_madt(&table[..length]).is_none(), "short entry");
        let (table, length) = madt(&[&PROCESSOR_0, &IO_APIC]);
        assert!(parse_madt(&table[..length - 1]).is_none(), "truncated");
    }

    #[test]
    fn root_pointer_and_root_table() {
        let mut rsdp = [0_u8; RSDP_V2_SIZE];
        rsdp[..8].copy_from_slice(RSDP_SIGNATURE);
        rsdp[15] = 2;
        rsdp[16..20].copy_from_slice(&0x1000_u32.to_le_bytes());
        rsdp[20..24].copy_from_slice(&(RSDP_V2_SIZE as u32).to_le_bytes());
        rsdp[8] = checksum(&rsdp[..RSDP_V1_SIZE]).wrapping_neg();
        assert_eq!(rsdp_revision(&rsdp), Some(2));
        assert_eq!(rsdp_extended_length(&rsdp), Some(RSDP_V2_SIZE));
        assert_eq!(
            root_table(&rsdp),
            Some(RootTable {
                address: 0x1000,
                entry_size: 4,
                signature: *b"RSDT"
            })
        );
        rsdp[24..32].copy_from_slice(&0x2000_u64.to_le_bytes());
        assert_eq!(root_table(&rsdp).map(|root| root.entry_size), Some(8));
        let mut corrupt = rsdp;
        corrupt[0] = b'X';
        assert_eq!(rsdp_revision(&corrupt), None);
        let mut short = rsdp;
        short[20..24].copy_from_slice(&20_u32.to_le_bytes());
        assert_eq!(rsdp_extended_length(&short), None);
    }

    #[test]
    fn root_entries_follow_the_header() {
        let mut root = [0_u8; SDT_HEADER_SIZE + 16];
        root[SDT_HEADER_SIZE..SDT_HEADER_SIZE + 8].copy_from_slice(&0x1234_u64.to_le_bytes());
        root[SDT_HEADER_SIZE + 8..].copy_from_slice(&0x5678_u64.to_le_bytes());
        let mut entries = root_entries(&root, 8).unwrap();
        assert_eq!(entries.next(), Some(0x1234));
        assert_eq!(entries.next(), Some(0x5678));
        assert_eq!(entries.next(), None);
        assert_eq!(root_entries(&root, 4).map(Iterator::count), Some(4));
        assert!(root_entries(&root[..SDT_HEADER_SIZE + 12], 8).is_none());
    }

    #[test]
    fn table_lengths_are_bounded() {
        let mut header = [0_u8; SDT_HEADER_SIZE];
        header[..4].copy_from_slice(b"APIC");
        header[4..8].copy_from_slice(&100_u32.to_le_bytes());
        assert_eq!(table_length(&header, b"APIC"), Some(100));
        assert_eq!(table_length(&header, b"DMAR"), None);
        header[4..8].copy_from_slice(&35_u32.to_le_bytes());
        assert_eq!(table_length(&header, b"APIC"), None);
        header[4..8].copy_from_slice(&(MAX_TABLE_SIZE as u32 + 1).to_le_bytes());
        assert_eq!(table_length(&header, b"APIC"), None);
    }
}
