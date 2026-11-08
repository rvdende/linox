#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ -n "${LINOX_QEMU_PID_FILE:-}" ]]; then
    printf '%s\n' "$$" >"$LINOX_QEMU_PID_FILE"
fi

qemu="$(find_qemu)"
ovmf_code="$(find_ovmf_code)"
ovmf_vars_template="$(find_ovmf_vars)"
accelerator="${QEMU_ACCEL:-$(default_accelerator)}"
if [[ "$accelerator" == "tcg" ]]; then
    default_cpu_model="max,+smep,+smap,+umip"
    accelerator_spec="tcg,thread=${QEMU_TCG_THREAD:-multi}"
else
    default_cpu_model="host,+smep,+smap,+umip"
    accelerator_spec="$accelerator"
fi
cpu_model="${QEMU_CPU:-$default_cpu_model}"
esp_dir="${LINOX_ESP_DIR:-$repo_root/build/esp}"
runtime_dir="$repo_root/build/qemu"
ovmf_vars="$runtime_dir/ovmf-vars.fd"
volume_image="${LINOX_VOLUME_IMAGE:-$runtime_dir/volume.raw}"
volume_size="${LINOX_VOLUME_SIZE:-64G}"
default_volume_bytes=68719476736

if [[ ! -f "$esp_dir/EFI/BOOT/BOOTX64.EFI" ]]; then
    echo "Missing $esp_dir/EFI/BOOT/BOOTX64.EFI; run 'make build' first." >&2
    exit 1
fi

mkdir -p "$runtime_dir"
cp "$ovmf_vars_template" "$ovmf_vars"
if [[ ! -f "$volume_image" ]]; then
    truncate -s "$volume_size" "$volume_image"
elif [[ -z "${LINOX_VOLUME_IMAGE:-}" && -z "${LINOX_VOLUME_SIZE:-}" ]]; then
    if current_volume_bytes=$(stat -f '%z' "$volume_image" 2>/dev/null) ||
        current_volume_bytes=$(stat -c '%s' "$volume_image" 2>/dev/null); then
        if [[ "$current_volume_bytes" =~ ^[0-9]+$ ]] &&
            ((current_volume_bytes < default_volume_bytes)); then
            truncate -s "$default_volume_bytes" "$volume_image"
        fi
    fi
fi

echo "Booting x86-64 Linox with QEMU/$accelerator using CPU $cpu_model"

memory="${LINOX_MEMORY:-1G}"
cpus="${LINOX_CPUS:-2}"
case "$cpus" in
    1|2|4) ;;
    *) echo "LINOX_CPUS must be 1, 2, or 4" >&2; exit 2 ;;
esac
network_capture=()
if [[ -n "${LINOX_PCAP:-}" ]]; then
    network_capture=(-object "filter-dump,id=linox-capture,netdev=linox-net,file=$LINOX_PCAP")
fi
# LINOX_QEMU_USB_INPUT=1 adds a USB keyboard and tablet on an xHCI
# controller, which Linox offers to domains as /dev/input/eventN.
usb_input=()
if [[ "${LINOX_QEMU_USB_INPUT:-}" == "1" ]]; then
    usb_input=(
        -device "qemu-xhci,id=xhci"
        -device "usb-kbd,bus=xhci.0"
        -device "usb-tablet,bus=xhci.0"
    )
fi
# LINOX_QEMU_GPU selects the display adapter. Unset or "std" keeps QEMU's
# standard VGA, whose firmware framebuffer is the display. "virtio" replaces
# it with a virtio-gpu (virtio-gpu-pci, no VGA at all), which Linox drives
# as the display; "virtio-vga" is a virtio-gpu that also has a VGA
# framebuffer for the firmware, which Linox leaves for the virtio-gpu.
# "venus" is a virtio-gpu with 3D: Vulkan through Venus runs on the host's
# GPU (virglrenderer), with LINOX_QEMU_HOSTMEM (default 4G) of host memory
# to map blobs into; it needs an EGL display, egl-headless unless
# LINOX_QEMU_DISPLAY asks for a window (gtk, with GL).
# LINOX_QEMU_GPU_SIZE=WIDTHxHEIGHT sets the mode a virtio-gpu reports.
gpu=()
case "${LINOX_QEMU_GPU:-std}" in
    std) ;;
    virtio | virtio-vga | venus)
        gpu_device="virtio-gpu-pci"
        if [[ "$LINOX_QEMU_GPU" == "virtio-vga" ]]; then
            gpu_device="virtio-vga"
        fi
        if [[ "$LINOX_QEMU_GPU" == "venus" ]]; then
            # ioeventfd: a queue notification only signals QEMU's main loop,
            # which runs the commands, instead of stopping the vCPU until
            # QEMU has handed them to the renderer (the default for this
            # device, which made every GPU submission cost ~0.6 ms).
            gpu_device="virtio-gpu-gl-pci,blob=on,venus=on,hostmem=${LINOX_QEMU_HOSTMEM:-4G},ioeventfd=on"
        fi
        gpu_device+=",disable-legacy=on,iommu_platform=on"
        if [[ -n "${LINOX_QEMU_GPU_SIZE:-}" ]]; then
            if [[ ! "$LINOX_QEMU_GPU_SIZE" =~ ^([0-9]+)x([0-9]+)$ ]]; then
                echo "LINOX_QEMU_GPU_SIZE must be WIDTHxHEIGHT" >&2
                exit 2
            fi
            gpu_device+=",xres=${BASH_REMATCH[1]},yres=${BASH_REMATCH[2]}"
        fi
        gpu=(-vga none -device "$gpu_device")
        ;;
    *)
        echo "LINOX_QEMU_GPU must be std, virtio, virtio-vga or venus" >&2
        exit 2
        ;;
esac
# LINOX_QEMU_DEBUG_LOG names a file for QEMU debug output selected by
# LINOX_QEMU_DEBUG_FLAGS (default: int).
qemu_debug=()
if [[ -n "${LINOX_QEMU_DEBUG_LOG:-}" ]]; then
    qemu_debug=(-d "${LINOX_QEMU_DEBUG_FLAGS:-int}" -D "$LINOX_QEMU_DEBUG_LOG")
fi
qemu_netdev="user,id=linox-net,restrict=off"
# LINOX_QEMU_LOG names a file for QEMU's CPU reset and guest error log.
# It also keeps QEMU paused, instead of exiting, when the guest resets or
# triple-faults, so the monitor can still read the CPU state.
qemu_log=()
if [[ -n "${LINOX_QEMU_LOG:-}" ]]; then
    # LINOX_QEMU_LOG_INTERRUPTS=1 also logs every exception and interrupt
    # (QEMU_ACCEL=tcg only), which shows the faults that led to a reset.
    events=cpu_reset,guest_errors
    if [[ "${LINOX_QEMU_LOG_INTERRUPTS:-}" == "1" ]]; then
        events+=",int"
    fi
    qemu_log=(-d "$events" -D "$LINOX_QEMU_LOG" -no-shutdown)
fi
# LINOX_QEMU_DISPLAY selects a QEMU display such as gtk or sdl, to see the
# framebuffer (and a Wayland desktop on /dev/fb0) in a window.
display="${LINOX_QEMU_DISPLAY:-none}"
if [[ "${LINOX_QEMU_GPU:-std}" == "venus" ]]; then
    # virglrenderer renders through EGL on the host's GPU.
    case "$display" in
        none) display="egl-headless" ;;
        gtk | sdl) display+=",gl=on" ;;
    esac
fi
# LINOX_QEMU_MONITOR names a Unix socket for the QEMU monitor, which tests
# use to take screenshots (screendump) and inject input.
monitor="none"
if [[ -n "${LINOX_QEMU_MONITOR:-}" ]]; then
    monitor="unix:${LINOX_QEMU_MONITOR},server=on,wait=off"
fi
if [[ -n "${LINOX_QEMU_DNS:-}" ]]; then
    qemu_netdev+=",dns=${LINOX_QEMU_DNS}"
fi
if [[ -n "${LINOX_QEMU_HOSTFWD:-}" ]]; then
    qemu_netdev+=",hostfwd=${LINOX_QEMU_HOSTFWD}"
fi

exec "$qemu" \
    -machine q35 \
    -accel "$accelerator_spec" \
    -cpu "$cpu_model" \
    -smp "$cpus" \
    -m "$memory" \
    -display "$display" \
    -monitor "$monitor" \
    -serial stdio \
    -no-reboot \
    ${qemu_log[@]+"${qemu_log[@]}"} \
    -net none \
    -device "intel-iommu,intremap=off,aw-bits=48" \
    -device "virtio-blk-pci,drive=linox-volume,disable-legacy=on,iommu_platform=on,serial=linox-volume" \
    -netdev "$qemu_netdev" \
    ${network_capture[@]+"${network_capture[@]}"} \
    ${qemu_debug[@]+"${qemu_debug[@]}"} \
    -device "virtio-net-pci,netdev=linox-net,disable-legacy=on,iommu_platform=on,mac=52:54:00:12:34:56,addr=0x3" \
    ${usb_input[@]+"${usb_input[@]}"} \
    ${gpu[@]+"${gpu[@]}"} \
    -drive "if=none,id=linox-volume,format=raw,file=$volume_image" \
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,file=$ovmf_vars" \
    -drive "if=none,id=linox-esp,format=raw,file=fat:rw:$esp_dir" \
    -device "ide-hd,drive=linox-esp,bootindex=1"
