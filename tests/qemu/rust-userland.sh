#!/usr/bin/env bash
# Boots Linox and starts a domain on the boot image's all-Rust root
# filesystem (image=builtin://rust): linox-init as process 1, the brush
# shell, uutils coreutils and linox-fetch. No registry pull or Alpine is
# involved. Commands typed on the console must run in that userland, and
# leaving the shell must stop the domain cleanly.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
output_file=$(mktemp "${TMPDIR:-/tmp}/linox-rust-userland.XXXXXX")
volume_image=$(mktemp "${TMPDIR:-/tmp}/linox-rust-userland-volume.XXXXXX")
qemu_pid_file=$(mktemp "${TMPDIR:-/tmp}/linox-rust-userland-pid.XXXXXX")
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
    cp "$output_file" "$repo_root/target/rust-userland-serial.log" 2>/dev/null || true
    rm -f "$output_file" "$volume_image" "$qemu_pid_file"
}
trap cleanup EXIT

wait_for() {
    local marker=$1
    local seconds=${2:-120}
    for _ in $(seq 1 "$seconds"); do
        grep -aEq "$marker" "$output_file" && return 0
        if grep -aEq '^LINOX_(BOOT|KERNEL)_PANIC|domain marked failed' "$output_file"; then
            break
        fi
        sleep 1
    done
    tail -n 60 "$output_file" >&2
    echo "Rust userland test failed while waiting for '$marker'." >&2
    stop_qemu
    return 1
}

dd if=/dev/zero of="$volume_image" bs=1048576 count=1 2>/dev/null
{
    wait_for 'linox> ' 300
    printf '%s\n' \
        'domain new rust' \
        'domain set rust image=builtin://rust init=/sbin/init' \
        'domain start rust --attach'
    wait_for 'all written in Rust' 300
    sleep 3
    # The markers are split so the echoed command lines cannot match.
    printf '%s\n' \
        'cat /etc/os-release' \
        'ls /bin | wc -l' \
        'linox-fetch' \
        'echo RUST_USERLAND"_OK" $(uname -s)'
    wait_for '^RUST_USERLAND_OK' 120
    printf '%s\n' 'exit 0'
    wait_for 'linox: Linux init exited cleanly' 120
    sleep 2
    printf '%s\n' 'shutdown'
} | LINOX_MEMORY=2G LINOX_VOLUME_IMAGE="$volume_image" LINOX_QEMU_PID_FILE="$qemu_pid_file" \
    "$repo_root/tools/qemu/run.sh" >"$output_file" 2>&1 &
qemu_pid=$!

for _ in $(seq 1 900); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 1
done
if kill -0 "$qemu_pid" 2>/dev/null; then
    tail -n 60 "$output_file"
    echo "Rust userland test failed: QEMU did not shut down." >&2
    exit 1
fi
wait "$qemu_pid" || true
qemu_pid=""

for marker in 'linox: builtin Rust root filesystem staged' 'NAME="Linox Rust"' \
    '^RUST_USERLAND_OK' 'Kernel: ' 'linox: Linux init exited cleanly'; do
    if ! grep -aEq "$marker" "$output_file"; then
        tail -n 60 "$output_file"
        echo "Rust userland test failed: missing '$marker'." >&2
        exit 1
    fi
done
if grep -aq 'pulling OCI image' "$output_file"; then
    echo "Rust userland test failed: the domain pulled a registry image." >&2
    exit 1
fi
echo "Rust userland test passed."
