#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
boot_timeout_seconds="${LINOX_BOOT_TIMEOUT_SECONDS:-180}"
if [[ ! "$boot_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "QEMU smoke test failed: LINOX_BOOT_TIMEOUT_SECONDS must be a positive integer." >&2
    exit 2
fi

output_file="$(mktemp -t linox-smoke.XXXXXX)"
volume_image="$(mktemp -t linox-smoke-volume.XXXXXX)"
qemu_pid_file="$(mktemp -t linox-smoke-pid.XXXXXX)"
qemu_pid=""

stop_qemu() {
    local pid=""
    if [[ -s "$qemu_pid_file" ]]; then
        read -r pid <"$qemu_pid_file" || true
    fi
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_qemu
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -f "$output_file" "$volume_image" "$qemu_pid_file"
}
trap cleanup EXIT

dd if=/dev/zero of="$volume_image" bs=1048576 count=1 2>/dev/null
: >"$qemu_pid_file"

# The producer intentionally watches QEMU's append-only serial log so it can
# send shutdown as soon as the prompt appears.
# shellcheck disable=SC2094
{
    for ((attempt = 0; attempt < boot_timeout_seconds; attempt++)); do
        if grep -aFq 'linox> ' "$output_file"; then
            printf 'shutdown\n'
            exit 0
        fi
        if grep -aEq 'LINOX_(BOOT|KERNEL)_PANIC' "$output_file"; then
            exit 0
        fi
        sleep 1
    done
} | LINOX_CPUS=2 LINOX_VOLUME_IMAGE="$volume_image" \
    LINOX_QEMU_PID_FILE="$qemu_pid_file" \
    "$repo_root/tools/qemu/run.sh" >"$output_file" 2>&1 &
qemu_pid=$!

for ((attempt = 0; attempt < boot_timeout_seconds; attempt++)); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 1
done

if kill -0 "$qemu_pid" 2>/dev/null; then
    stop_qemu
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    cat "$output_file"
    echo "QEMU smoke test failed: boot did not finish within ${boot_timeout_seconds} seconds." >&2
    exit 1
fi

if wait "$qemu_pid"; then
    qemu_status=0
else
    qemu_status=$?
fi
qemu_pid=""

if [[ "$qemu_status" -ne 0 ]]; then
    cat "$output_file"
    echo "QEMU smoke test failed: QEMU exited with $qemu_status; expected 0." >&2
    exit 1
fi

for expected in \
    'LINOX_KERNEL_OK' \
    'linox: launching embedded controller in ring 3' \
    'Linox controller v0 (ring 3)' \
    'linox> ' \
    'linox: controller requested clean shutdown'; do
    if ! grep -aFq -- "$expected" "$output_file"; then
        cat "$output_file"
        echo "QEMU smoke test failed: missing '$expected'." >&2
        exit 1
    fi
done

if grep -aEq 'LINOX_(BOOT|KERNEL)_PANIC' "$output_file"; then
    cat "$output_file"
    echo "QEMU smoke test failed: a boot or kernel panic was emitted." >&2
    exit 1
fi

echo "QEMU smoke test passed: the normal image reached the ring-3 controller with QEMU configured for 2 vCPUs and shut down cleanly."
