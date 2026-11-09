#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kernel_source="${repo_root}/kernel/src"

# rg exits 1 when nothing matches, which is the goal for each of these.
unsafe_blocks="$({ rg -g '*.rs' -o 'unsafe \{' "$kernel_source" || true; } | wc -l | tr -d ' ')"
safety_comments="$({ rg -g '*.rs' -o 'SAFETY:' "$kernel_source" || true; } | wc -l | tr -d ' ')"
static_mut="$({ rg -g '*.rs' '^\s*(pub(\([^)]*\))?\s+)?static mut ' "$kernel_source" || true; } | wc -l | tr -d ' ')"

if (( unsafe_blocks > 146 )); then
    echo "kernel unsafe check: unsafe blocks grew from 146 to ${unsafe_blocks}" >&2
    exit 1
fi
# Unsafe blocks without a SAFETY comment may only go down. (This replaced a
# floor on the number of SAFETY comments, which removing a documented
# unsafe block would trip.)
undocumented=$(( unsafe_blocks - safety_comments ))
if (( undocumented > -30 )); then
    echo "kernel unsafe check: unsafe blocks without a SAFETY comment grew from -30 to ${undocumented}" >&2
    exit 1
fi
if (( static_mut > 0 )); then
    echo "kernel unsafe check: the kernel has ${static_mut} static mut declarations; it has none" >&2
    exit 1
fi

# Per-file ratchet for the memory layer and the modules moved onto its safe
# frame and page-table APIs: unsafe sites (blocks, unsafe fns, impls and
# extern blocks) may only go down. Lower a number when a change removes
# sites; a file may not grow.
per_file_limits=(
    "arch/x86_64/cpu/linux_user_memory.rs 1"
    "image_store.rs 1"
    "lib.rs 0"
    "trusted/ap_start.rs 1"
    "trusted/boot.rs 9"
    "trusted/claim.rs 3"
    "trusted/control.rs 12"
    "trusted/cpu_tables.rs 16"
    "trusted/crash.rs 5"
    "trusted/dma.rs 4"
    "trusted/entry.rs 4"
    "trusted/firmware.rs 2"
    "trusted/frame.rs 9"
    "trusted/frame_tables.rs 2"
    "trusted/heap.rs 7"
    "trusted/image.rs 9"
    "trusted/interrupts.rs 8"
    "trusted/lock.rs 3"
    "trusted/mmio.rs 2"
    "trusted/msr.rs 4"
    "trusted/owned_state.rs 4"
    "trusted/page_table.rs 2"
    "trusted/pixels.rs 3"
    "trusted/pod.rs 10"
    "trusted/port.rs 8"
    "trusted/programs.rs 1"
    "trusted/random.rs 1"
    "trusted/root.rs 5"
    "trusted/switch.rs 12"
    "trusted/take_once.rs 2"
    "trusted/tsc.rs 3"
    "trusted/user_copy.rs 8"
    "trusted/xstate.rs 4"
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
    "address_space.rs"
    "arch/x86_64/acpi.rs"
    "arch/x86_64/apic.rs"
    "arch/x86_64/cpu/activation.rs"
    "arch/x86_64/cpu/architecture.rs"
    "arch/x86_64/cpu/boot_verify.rs"
    "arch/x86_64/cpu/boot_verify_elf.rs"
    "arch/x86_64/cpu/execution.rs"
    "arch/x86_64/cpu/linux_cgroupfs.rs"
    "arch/x86_64/cpu/linux_domain_runtime.rs"
    "arch/x86_64/cpu/linux_exec.rs"
    "arch/x86_64/cpu/linux_process_lifecycle.rs"
    "arch/x86_64/cpu/linux_process_vm.rs"
    "arch/x86_64/cpu/linux_procfs.rs"
    "arch/x86_64/cpu/linux_runtime_loop.rs"
    "arch/x86_64/cpu/linux_scheduler.rs"
    "arch/x86_64/cpu/linux_signal.rs"
    "arch/x86_64/cpu/linux_syscall.rs"
    "arch/x86_64/cpu/linux_system.rs"
    "arch/x86_64/cpu/linux_thread.rs"
    "arch/x86_64/cpu/native_services.rs"
    "arch/x86_64/iommu.rs"
    "arch/x86_64/paging.rs"
    "arch/x86_64/pci.rs"
    "arch/x86_64/smp.rs"
    "arch/x86_64/timer.rs"
    "bringup/mod.rs"
    "bringup/trap.rs"
    "domain.rs"
    "drivers/ahci.rs"
    "drivers/amd_iommu.rs"
    "drivers/clock.rs"
    "drivers/e1000e.rs"
    "drivers/hda.rs"
    "drivers/mod.rs"
    "drivers/nvme.rs"
    "drivers/pci.rs"
    "drivers/realtek.rs"
    "drivers/usb_input.rs"
    "drivers/virtio_gpu.rs"
    "drivers/xhci.rs"
    "framebuffer.rs"
    "heap.rs"
    "initramfs.rs"
    "ipc.rs"
    "linux_aio.rs"
    "linux_file_cache.rs"
    "linux_input.rs"
    "linux_mount.rs"
    "linux_process.rs"
    "linux_signal.rs"
    "linux_socket/virtio_net.rs"
    "linux_sysv_ipc.rs"
    "linux_tmpfs.rs"
    "linux_user.rs"
    "manifest.rs"
    "memory.rs"
    "owned_state.rs"
    "packet.rs"
    "pe.rs"
    "published_rootfs.rs"
    "sync.rs"
    "volume.rs"
)
for file in "${forbidding_files[@]}"; do
    if ! rg -q '^#!\[forbid\(unsafe_code\)\]$' "${kernel_source}/${file}"; then
        echo "kernel unsafe check: ${file} must keep #![forbid(unsafe_code)]" >&2
        exit 1
    fi
done

# The crate root denies unsafe code; the modules that still hold some are
# allowed it where lib.rs declares them, and that list may only shrink.
if ! rg -q '^#!\[deny\(unsafe_code\)\]$' "${kernel_source}/lib.rs"; then
    echo "kernel unsafe check: lib.rs must keep #![deny(unsafe_code)]" >&2
    exit 1
fi
allowed_modules="$(rg -c -U '#\[allow\(unsafe_code\)\]\n(pub(\([^)]*\))? )?mod ' "${kernel_source}/lib.rs" || true)"
if (( ${allowed_modules:-0} > 4 )); then
    echo "kernel unsafe check: lib.rs allows unsafe code in ${allowed_modules} modules, more than 4" >&2
    exit 1
fi
if (( $(rg -c 'allow\(unsafe_code\)' "${kernel_source}/lib.rs" || echo 0) != ${allowed_modules:-0} )); then
    echo "kernel unsafe check: lib.rs allows unsafe code other than on module declarations" >&2
    exit 1
fi

# Only the memory layer makes a Frame, a PageTable or a loadable Root from
# a bare physical address (kernel/src/trusted/frame.rs, page_table.rs and
# root.rs say why); every other module starts from a FrameLease, and loads
# only the kernel's own root (Root::kernel).
constructors="$(rg -g '*.rs' -l '\b(Frame|PageTable|Root)::from_physical\(' "$kernel_source" \
    | sed "s|^${kernel_source}/||" \
    | rg -v '^(address_space\.rs|memory\.rs|arch/x86_64/paging\.rs|trusted/.*)$' || true)"
if [[ -n "$constructors" ]]; then
    echo "kernel unsafe check: Frame/PageTable/Root::from_physical outside the memory layer:" >&2
    echo "$constructors" >&2
    exit 1
fi

# The frame allocator's tables are carved from RAM (trusted::frame_tables)
# and the loader's memory map is read (trusted::boot) only by the frame
# allocator.
boot_memory="$(rg -g '*.rs' -l 'FrameTables::carve\(|for_each_memory_descriptor\(' "$kernel_source" \
    | sed "s|^${kernel_source}/||" \
    | rg -v '^(memory\.rs|trusted/.*)$' || true)"
if [[ -n "$boot_memory" ]]; then
    echo "kernel unsafe check: frame tables or the boot memory map outside the frame allocator:" >&2
    echo "$boot_memory" >&2
    exit 1
fi

# A virtio DMA page is viewed only from its lease (trusted::dma::
# DmaView::leased); the view from a bare direct-map address is gone and
# must not come back.
if rg -q -g '*.rs' 'DmaView::from_direct_map' "$kernel_source"; then
    echo "kernel unsafe check: DmaView::from_direct_map is gone; views start from a FrameLease" >&2
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

# The firmware's framebuffer through its identity map
# (trusted::pixels::PixelBuffer::firmware) is for the boot path before the
# kernel maps it (lib.rs) and for hardware bring-up.
firmware_pixels="$(rg -g '*.rs' -l 'PixelBuffer::firmware\(' "$kernel_source" \
    | sed "s|^${kernel_source}/||" \
    | rg -v '^(lib\.rs|bringup/.*|trusted/.*)$' || true)"
if [[ -n "$firmware_pixels" ]]; then
    echo "kernel unsafe check: PixelBuffer::firmware outside the boot path:" >&2
    echo "$firmware_pixels" >&2
    exit 1
fi

# The generated /proc files are owned per read
# (cpu/linux_descriptors.rs's RegularFile); the static scratch buffer they
# shared (trusted::scratch) is gone and must not come back.
if [[ -e "${kernel_source}/trusted/scratch.rs" ]] || rg -q -g '*.rs' 'ScratchBuffer' "$kernel_source"; then
    echo "kernel unsafe check: trusted::scratch is gone; generated files own their bytes" >&2
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
