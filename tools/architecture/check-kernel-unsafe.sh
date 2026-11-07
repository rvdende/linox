#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kernel_source="${repo_root}/kernel/src"

unsafe_blocks="$(rg -g '*.rs' -o 'unsafe \{' "$kernel_source" | wc -l | tr -d ' ')"
safety_comments="$(rg -g '*.rs' -o 'SAFETY:' "$kernel_source" | wc -l | tr -d ' ')"
static_mut="$(rg -g '*.rs' '^\s*(pub(\([^)]*\))?\s+)?static mut ' "$kernel_source" | wc -l | tr -d ' ')"

if (( unsafe_blocks > 1054 )); then
    echo "kernel unsafe check: unsafe blocks grew from 1054 to ${unsafe_blocks}" >&2
    exit 1
fi
if (( safety_comments < 370 )); then
    echo "kernel unsafe check: SAFETY comments fell from 370 to ${safety_comments}" >&2
    exit 1
fi
if (( static_mut > 43 )); then
    echo "kernel unsafe check: top-level static mut declarations grew from 43 to ${static_mut}" >&2
    exit 1
fi

echo "Kernel unsafe baseline passed (${unsafe_blocks} blocks, ${safety_comments} SAFETY comments, ${static_mut} static mut)"
