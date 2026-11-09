#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kernel_source="${repo_root}/kernel/src"

unsafe_blocks="$(rg -g '*.rs' -o 'unsafe \{' "$kernel_source" | wc -l | tr -d ' ')"
safety_comments="$(rg -g '*.rs' -o 'SAFETY:' "$kernel_source" | wc -l | tr -d ' ')"
static_mut="$(rg -g '*.rs' '^\s*(pub(\([^)]*\))?\s+)?static mut ' "$kernel_source" | wc -l | tr -d ' ')"

if (( unsafe_blocks > 624 )); then
    echo "kernel unsafe check: unsafe blocks grew from 624 to ${unsafe_blocks}" >&2
    exit 1
fi
# Unsafe blocks without a SAFETY comment may only go down. (This replaced a
# floor on the number of SAFETY comments, which removing a documented
# unsafe block would trip.)
undocumented=$(( unsafe_blocks - safety_comments ))
if (( undocumented > 287 )); then
    echo "kernel unsafe check: unsafe blocks without a SAFETY comment grew from 287 to ${undocumented}" >&2
    exit 1
fi
if (( static_mut > 22 )); then
    echo "kernel unsafe check: top-level static mut declarations grew from 22 to ${static_mut}" >&2
    exit 1
fi

# Per-file ratchet for the memory layer and the modules moved onto its safe
# frame and page-table APIs: unsafe sites (blocks, unsafe fns, impls and
# extern blocks) may only go down. Lower a number when a change removes
# sites; a file may not grow.
per_file_limits=(
    "address_space.rs 80"
    "bringup/mod.rs 8"
    "arch/x86_64/paging.rs 13"
    "arch/x86_64/iommu.rs 2"
    "arch/x86_64/pci.rs 25"
    "arch/x86_64/smp.rs 8"
    "arch/x86_64/timer.rs 8"
    "image_store.rs 16"
    "linux_overlay.rs 20"
    "lib.rs 20"
    "memory.rs 38"
    "drivers/amd_iommu.rs 13"
    "drivers/xhci.rs 19"
    "trusted/dma.rs 3"
    "trusted/firmware.rs 2"
    "trusted/frame.rs 9"
    "trusted/mmio.rs 2"
    "trusted/msr.rs 3"
    "trusted/page_table.rs 2"
    "trusted/root.rs 2"
    "trusted/port.rs 8"
)
for limit in "${per_file_limits[@]}"; do
    file="${limit% *}"
    maximum="${limit#* }"
    sites="$(rg -c 'unsafe \{|unsafe fn|unsafe impl|unsafe extern' "${kernel_source}/${file}" || true)"
    sites="${sites:-0}"
    if (( sites > maximum )); then
        echo "kernel unsafe check: ${file} has ${sites} unsafe sites, more than its limit of ${maximum}" >&2
        exit 1
    fi
done

# Files moved onto the trusted layer's safe APIs that have no unsafe left
# keep `#![forbid(unsafe_code)]`, so none can grow an unsafe block again.
forbidding_files=(
    "arch/x86_64/acpi.rs"
    "arch/x86_64/apic.rs"
    "drivers/ahci.rs"
    "drivers/clock.rs"
    "drivers/e1000e.rs"
    "drivers/hda.rs"
    "drivers/nvme.rs"
    "drivers/pci.rs"
    "drivers/realtek.rs"
    "linux_aio.rs"
    "linux_sysv_ipc.rs"
    "linux_tmpfs.rs"
)
for file in "${forbidding_files[@]}"; do
    if ! rg -q '^#!\[forbid\(unsafe_code\)\]$' "${kernel_source}/${file}"; then
        echo "kernel unsafe check: ${file} must keep #![forbid(unsafe_code)]" >&2
        exit 1
    fi
done

# Only the memory layer makes a Frame or a PageTable from a bare physical
# address (kernel/src/trusted/frame.rs and page_table.rs say why); every
# other module starts from a FrameLease.
constructors="$(rg -g '*.rs' -l '\b(Frame|PageTable)::from_physical\(' "$kernel_source" \
    | sed "s|^${kernel_source}/||" \
    | rg -v '^(address_space\.rs|memory\.rs|arch/x86_64/paging\.rs|trusted/.*)$' || true)"
if [[ -n "$constructors" ]]; then
    echo "kernel unsafe check: Frame/PageTable::from_physical outside the memory layer:" >&2
    echo "$constructors" >&2
    exit 1
fi

# Device registers reached through the firmware's identity map
# (trusted::mmio::Mmio::firmware) are for hardware bring-up and the drivers
# it runs; the main kernel maps registers itself (Mmio::mapped).
firmware_registers="$(rg -g '*.rs' -l 'Mmio::firmware\(' "$kernel_source" \
    | sed "s|^${kernel_source}/||" \
    | rg -v '^(bringup/.*|drivers/(ahci|amd_iommu|clock|e1000e|hda|nvme|realtek)\.rs|trusted/.*)$' || true)"
if [[ -n "$firmware_registers" ]]; then
    echo "kernel unsafe check: Mmio::firmware outside hardware bring-up:" >&2
    echo "$firmware_registers" >&2
    exit 1
fi

# Firmware tables are viewed in place (trusted::firmware) only by the
# code that parses ACPI; any other memory needs a type that copies.
firmware_views="$(rg -g '*.rs' -l 'firmware::with_(direct|identity)_mapped\(' "$kernel_source" \
    | sed "s|^${kernel_source}/||" \
    | rg -v '^(lib\.rs|arch/x86_64/acpi\.rs|bringup/.*|trusted/.*)$' || true)"
if [[ -n "$firmware_views" ]]; then
    echo "kernel unsafe check: firmware table views outside the ACPI parsers:" >&2
    echo "$firmware_views" >&2
    exit 1
fi

echo "Kernel unsafe baseline passed (${unsafe_blocks} blocks, ${safety_comments} SAFETY comments, ${static_mut} static mut)"
