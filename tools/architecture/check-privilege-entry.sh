#!/usr/bin/env bash

set -euo pipefail

root=$(git rev-parse --show-toplevel)
# The entry stubs live in the trusted core (kernel/src/trusted/entry.rs).
entry_stubs="$root/kernel/src/trusted/entry.rs"
architecture="$root/kernel/src/arch/x86_64/cpu/architecture.rs"
cpu_tables="$root/kernel/src/trusted/cpu_tables.rs"
address_space="$root/kernel/src/address_space.rs"

fail() {
    printf 'privilege-entry check: %s\n' "$*" >&2
    exit 1
}

entry=$(rg -n -m1 '^linox_linux_syscall_entry:' "$entry_stubs" | cut -d: -f1)
switch=$(awk -v start="$entry" 'NR > start && /mov rsp, gs:\[\{entry_return_stack\}\]/ { print NR; exit }' "$entry_stubs")
[[ -n "$switch" ]] || fail 'missing GS-based trusted stack switch'

if awk -v start="$entry" -v stop="$switch" \
    'NR > start && NR < stop && /^[[:space:]]*(push|call)[[:space:]]/ { exit 0 } END { exit 1 }' \
    "$entry_stubs"; then
    fail 'SYSCALL entry uses the userspace stack before switching to trusted storage'
fi

# Returns to user mode: non-canonical targets go back to the kernel, the
# flags lose IOPL/VM, every entry into user mode keeps the entry state it
# found and puts it back, and a live system-call frame is cleared on the
# way out.
for required in \
    'linox_nmi_entry:' \
    'lock inc byte ptr [rip + {entry_nmi_probe_hits}]' \
    'jne linox_user_return_kernel' \
    'and r11, {user_flags_kept}' \
    'and rcx, {user_flags_kept}' \
    'push qword ptr gs:[{entry_return_stack}]' \
    'pop qword ptr gs:[{entry_return_stack}]' \
    'mov qword ptr gs:[{entry_kernel_frame}], 0'; do
    rg -Fq "$required" "$entry_stubs" || fail "missing required invariant: $required"
done

# The trusted core installs each CPU's entry state and exception gates.
for required in \
    'write_msr(GS_BASE_MSR, entry_state as u64)' \
    '2 => NMI_IST' \
    '8 => DOUBLE_FAULT_IST' \
    '18 => MACHINE_CHECK_IST'; do
    rg -Fq "$required" "$cpu_tables" || fail "missing required invariant: $required"
done

for required in \
    'cpu_tables::exception_ist(vector)' \
    'nmi_guard_page()' \
    'nmi_upper_guard_page()' \
    'machine_check_guard_page()' \
    'machine_check_upper_guard_page()'; do
    rg -Fq "$required" "$architecture" || fail "missing required invariant: $required"
done

stages=$(rg -F 'lock btr qword ptr [rip + {entry_nmi_probe_mask}]' "$entry_stubs" | wc -l | tr -d ' ')
[[ "$stages" == 6 ]] || fail "expected six syscall transition NMI probes, found $stages"

for required in \
    'current_user_entry_context_is_valid' \
    'hostile_entry_contexts_rejected'; do
    rg -Fq "$required" "$address_space" || fail "missing hostile-entry invariant: $required"
done

printf '%s\n' 'Privilege-entry architecture check passed'
