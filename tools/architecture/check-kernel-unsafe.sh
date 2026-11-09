#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kernel_source="${repo_root}/kernel/src"

unsafe_blocks="$(rg -g '*.rs' -o 'unsafe \{' "$kernel_source" | wc -l | tr -d ' ')"
safety_comments="$(rg -g '*.rs' -o 'SAFETY:' "$kernel_source" | wc -l | tr -d ' ')"
static_mut="$(rg -g '*.rs' '^\s*(pub(\([^)]*\))?\s+)?static mut ' "$kernel_source" | wc -l | tr -d ' ')"

if (( unsafe_blocks > 807 )); then
    echo "kernel unsafe check: unsafe blocks grew from 807 to ${unsafe_blocks}" >&2
    exit 1
fi
if (( safety_comments < 390 )); then
    echo "kernel unsafe check: SAFETY comments fell from 390 to ${safety_comments}" >&2
    exit 1
fi
if (( static_mut > 43 )); then
    echo "kernel unsafe check: top-level static mut declarations grew from 43 to ${static_mut}" >&2
    exit 1
fi

# Per-file ratchet for the memory layer and the modules moved onto its safe
# frame and page-table APIs: unsafe sites (blocks, unsafe fns, impls and
# extern blocks) may only go down. Lower a number when a change removes
# sites; a file may not grow.
per_file_limits=(
    "address_space.rs 80"
    "arch/x86_64/paging.rs 15"
    "image_store.rs 16"
    "linux_aio.rs 4"
    "linux_overlay.rs 20"
    "linux_sysv_ipc.rs 12"
    "trusted/frame.rs 9"
    "trusted/page_table.rs 2"
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

echo "Kernel unsafe baseline passed (${unsafe_blocks} blocks, ${safety_comments} SAFETY comments, ${static_mut} static mut)"
