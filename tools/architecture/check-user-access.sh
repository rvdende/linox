#!/usr/bin/env bash

set -euo pipefail

root=$(git rev-parse --show-toplevel)
cpu="$root/kernel/src/arch/x86_64/cpu.rs"
# cpu.rs and its submodules (kernel/src/arch/x86_64/cpu/*.rs, which hold code
# split out of cpu.rs): the SMAP and scalar-pointer rules cover all of them.
cpu_tree=("$cpu" "$root/kernel/src/arch/x86_64/cpu")
user_copy="$root/kernel/src/trusted/user_copy.rs"
address_space="$root/kernel/src/address_space.rs"

fail() {
    printf 'user-access check: %s\n' "$*" >&2
    exit 1
}

for required in \
    'linox_raw_copy_from_user:' \
    'linox_copy_from_user_fault_begin:' \
    'linox_copy_from_user_fault_end:' \
    'linox_raw_copy_to_user:' \
    'linox_copy_to_user_fault_begin:' \
    'linox_copy_to_user_fault_end:' \
    'linox_copy_from_user_fixup:' \
    'linox_copy_to_user_fixup:' \
    'verify_fault_fixups'; do
    rg -Fq "$required" "$user_copy" || fail "missing recoverable user-copy invariant: $required"
done

for required in \
    'copy_from_current_user_partial' \
    'copy_to_current_user_partial'; do
    rg -Fq "$required" "$address_space" || fail "missing audited user-copy API: $required"
done

# SMAP is opened only by the fault-recovering copy loops: the closure that
# opened it for arbitrary code (with_supervisor_user_access) is gone, and
# address-space verification reads user memory through trusted::user_copy.
smap_sites=$({ rg -F 'with_supervisor_user_access' "$root/kernel/src" || true; } | wc -l | tr -d ' ')
[[ "$smap_sites" == 0 ]] || \
    fail "with_supervisor_user_access is gone; found $smap_sites sites"

if rg -Uq '\bas \*(const|mut) u(8|16|32|64)\)[[:space:]]*\.(read|write)(_volatile)?\(' "${cpu_tree[@]}"; then
    fail 'cpu.rs or cpu/ directly dereferences a cast userspace scalar pointer'
fi

printf '%s\n' 'User-access architecture check passed'
