//! The platform the ACPI tables describe: processors and interrupt
//! controllers (MADT) and the first I/O MMU (DMAR). The tables are read
//! through `trusted::firmware` and parsed by `crates/acpi-tables`.

#![forbid(unsafe_code)]

use linox_acpi_tables::{self as tables, DeviceScopes, RootTable, SDT_HEADER_SIZE};

use crate::trusted::firmware;

pub(crate) const MAX_ENABLED_PROCESSORS: usize = tables::MAX_ENABLED_PROCESSORS;

#[derive(Clone, Copy)]
pub(crate) struct PlatformInfo {
    pub(crate) enabled_processors: usize,
    pub(crate) processor_apic_ids: [u32; MAX_ENABLED_PROCESSORS],
    pub(crate) io_apics: usize,
    pub(crate) local_apic_address: u64,
    pub(crate) first_io_apic_address: u32,
    pub(crate) first_io_apic_gsi: u32,
    pub(crate) iommu_units: usize,
    pub(crate) iommu_host_address_width: u8,
    pub(crate) first_iommu_register_base: u64,
    pub(crate) first_iommu_include_all: bool,
    first_iommu_scopes: DeviceScopes,
}

impl PlatformInfo {
    pub(crate) fn first_iommu_scope_count(self) -> usize {
        self.first_iommu_scopes.scope_count()
    }

    pub(crate) fn first_iommu_covers_pci(self, bus: u8, device: u8, function: u8) -> bool {
        tables::pci_source_id(bus, device, function).is_some()
            && (self.first_iommu_include_all
                || self
                    .first_iommu_scopes
                    .contains_endpoint(bus, device, function))
    }
}

pub(crate) fn discover(rsdp: *const u8, mapped_limit: usize) -> Option<PlatformInfo> {
    let rsdp_physical = rsdp as usize;
    let revision = firmware::with_direct_mapped(rsdp_physical, 20, mapped_limit, |rsdp| rsdp[15])?;
    let rsdp_length = if revision >= 2 { 36 } else { 20 };
    let RootTable {
        address: root_address,
        entry_size,
        signature,
    } = firmware::with_direct_mapped(rsdp_physical, rsdp_length, mapped_limit, tables::root_table)
        .flatten()?;
    let root_address = usize::try_from(root_address).ok()?;

    let (platform, iommu) = with_table(root_address, &signature, mapped_limit, |root| {
        let mut platform = None;
        let mut iommu = None;
        for table_address in tables::root_entries(root, entry_size)? {
            let table_address = usize::try_from(table_address).ok()?;
            if signature_at(table_address, b"APIC", mapped_limit) {
                if platform.is_some() {
                    return None;
                }
                platform =
                    with_table(table_address, b"APIC", mapped_limit, tables::parse_madt).flatten();
            } else if signature_at(table_address, b"DMAR", mapped_limit) {
                if iommu.is_some() {
                    return None;
                }
                iommu = with_table(table_address, b"DMAR", mapped_limit, |table| {
                    tables::parse_dmar(table, mapped_limit)
                })
                .flatten();
            }
        }
        Some((platform?, iommu?))
    })
    .flatten()?;
    Some(PlatformInfo {
        enabled_processors: platform.enabled_processors,
        processor_apic_ids: platform.processor_apic_ids,
        io_apics: platform.io_apics,
        local_apic_address: platform.local_apic_address,
        first_io_apic_address: platform.first_io_apic_address,
        first_io_apic_gsi: platform.first_io_apic_gsi,
        iommu_units: iommu.units,
        iommu_host_address_width: iommu.host_address_width,
        first_iommu_register_base: iommu.first_register_base,
        first_iommu_include_all: iommu.first_include_all,
        first_iommu_scopes: iommu.first_scopes,
    })
}

/// Runs `parse` on the table at `address`, if it carries `signature`, its
/// length is plausible, every byte of it lies below `mapped_limit`, and its
/// checksum is right.
fn with_table<R>(
    address: usize,
    signature: &[u8; 4],
    mapped_limit: usize,
    parse: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    let length = firmware::with_direct_mapped(address, SDT_HEADER_SIZE, mapped_limit, |header| {
        tables::table_length(header, signature)
    })
    .flatten()?;
    firmware::with_direct_mapped(address, length, mapped_limit, |table| {
        (tables::checksum(table) == 0).then(|| parse(table))
    })
    .flatten()
}

fn signature_at(address: usize, signature: &[u8; 4], mapped_limit: usize) -> bool {
    firmware::with_direct_mapped(address, signature.len(), mapped_limit, |bytes| {
        bytes == signature
    })
    .unwrap_or(false)
}

pub(crate) fn verify_malformed_dmar_rejected(mapped_limit: usize) -> bool {
    let mut valid = [0_u8; tables::DMAR_DRHD_SIZE];
    valid[2..4].copy_from_slice(&(tables::DMAR_DRHD_SIZE as u16).to_le_bytes());
    valid[4] = 1;
    valid[8..16].copy_from_slice(&0xfed9_0000_u64.to_le_bytes());
    if tables::parse_dmar_structures(&valid, 48, mapped_limit).is_none() {
        return false;
    }
    let mut zero_length = valid;
    zero_length[2..4].copy_from_slice(&0_u16.to_le_bytes());
    let mut short_drhd = valid;
    short_drhd[2..4].copy_from_slice(&8_u16.to_le_bytes());
    let mut zero_base = valid;
    zero_base[8..16].fill(0);
    let mut unknown_flags = valid;
    unknown_flags[4] = 0x80;
    let mut trailing = [0_u8; tables::DMAR_DRHD_SIZE + 1];
    trailing[..tables::DMAR_DRHD_SIZE].copy_from_slice(&valid);
    let mut bad_scope = [0_u8; tables::DMAR_DRHD_SIZE + tables::DMAR_DEVICE_SCOPE_MIN_SIZE];
    bad_scope[..tables::DMAR_DRHD_SIZE].copy_from_slice(&valid);
    let bad_scope_length = bad_scope.len() as u16;
    bad_scope[2..4].copy_from_slice(&bad_scope_length.to_le_bytes());
    bad_scope[4] = 0;
    bad_scope[tables::DMAR_DRHD_SIZE + 1] = 7;
    let rejected = [
        zero_length.as_slice(),
        short_drhd.as_slice(),
        zero_base.as_slice(),
        unknown_flags.as_slice(),
        trailing.as_slice(),
        bad_scope.as_slice(),
    ]
    .into_iter()
    .all(|bytes| tables::parse_dmar_structures(bytes, 48, mapped_limit).is_none());
    rejected
}

pub(crate) fn verify_dmar_scope_resolution(mapped_limit: usize) -> bool {
    const DRHD: usize = tables::DMAR_DRHD_SIZE;
    const SCOPE: usize = tables::DMAR_DEVICE_SCOPE_MIN_SIZE;
    let mut endpoint = [0_u8; DRHD + SCOPE];
    let endpoint_length = endpoint.len() as u16;
    endpoint[2..4].copy_from_slice(&endpoint_length.to_le_bytes());
    endpoint[8..16].copy_from_slice(&0xfed9_0000_u64.to_le_bytes());
    endpoint[DRHD] = 1;
    endpoint[DRHD + 1] = SCOPE as u8;
    endpoint[DRHD + 5] = 0;
    endpoint[DRHD + 6] = 2;
    endpoint[DRHD + 7] = 0;
    let Some(info) = tables::parse_dmar_structures(&endpoint, 48, mapped_limit) else {
        return false;
    };
    if info.first_include_all
        || !info.first_scopes.contains_endpoint(0, 2, 0)
        || info.first_scopes.contains_endpoint(0, 3, 0)
        || info.first_scopes.contains_endpoint(0, 2, 1)
    {
        return false;
    }

    let mut duplicate = [0_u8; DRHD + 2 * SCOPE];
    duplicate[..endpoint.len()].copy_from_slice(&endpoint);
    let duplicate_length = duplicate.len() as u16;
    duplicate[2..4].copy_from_slice(&duplicate_length.to_le_bytes());
    duplicate[endpoint.len()..].copy_from_slice(&endpoint[DRHD..]);
    let mut reserved = endpoint;
    reserved[DRHD + 2] = 1;
    let mut enumeration = endpoint;
    enumeration[DRHD + 4] = 1;
    let mut invalid_device = endpoint;
    invalid_device[DRHD + 6] = 32;
    let mut invalid_function = endpoint;
    invalid_function[DRHD + 7] = 8;
    let mut unknown_type = endpoint;
    unknown_type[DRHD] = 6;
    let rejected = [
        duplicate.as_slice(),
        reserved.as_slice(),
        enumeration.as_slice(),
        invalid_device.as_slice(),
        invalid_function.as_slice(),
        unknown_type.as_slice(),
    ]
    .into_iter()
    .all(|bytes| tables::parse_dmar_structures(bytes, 48, mapped_limit).is_none());
    rejected
}
