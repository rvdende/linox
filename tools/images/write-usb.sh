#!/usr/bin/env bash
# Write the Linox USB boot image to a USB stick, refusing anything that does
# not look like one.
#
#   tools/images/write-usb.sh [--dry-run] [--image FILE] /dev/sdX
#
# The device must be a whole disk (not a partition) that:
#   - is attached over USB (lsblk TRAN=usb),
#   - reports itself removable (/sys/block/X/removable = 1); a USB disk that
#     does not (some USB SSD enclosures) is accepted only with
#     LINOX_ALLOW_FIXED_USB=1,
#   - is smaller than 256 GB,
#   - has nothing mounted, no swap in use, and no holders (LVM, RAID, dm),
#   - is not the disk holding /, /boot or /boot/efi.
# It then shows the disk's model, serial, size and partitions and asks you to
# type the device name back before anything is written. The checks run
# without root; only the write itself uses sudo. --dry-run stops after the
# checks.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="$repo_root/build/media/linox-usb.img"
dry_run=0
size_limit=$((256 * 1000 * 1000 * 1000))

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
}

fail() {
    printf 'write-usb: refusing: %s\n' "$*" >&2
    exit 1
}

device=""
while (($#)); do
    case "$1" in
    --dry-run) dry_run=1 ;;
    --image)
        shift
        (($#)) || usage
        image=$1
        ;;
    -h | --help) usage ;;
    -*) usage ;;
    *)
        [[ -z "$device" ]] || usage
        device=$1
        ;;
    esac
    shift
done
[[ -n "$device" ]] || usage

for command in lsblk findmnt readlink sha256sum stat dd; do
    command -v "$command" >/dev/null 2>&1 || fail "missing $command"
done

[[ -s "$image" ]] || fail "$image is missing; run 'make boot-media' first"

# Resolve symlinks such as /dev/disk/by-id/usb-... to the kernel name.
[[ -e "$device" ]] || fail "$device does not exist"
real=$(readlink -f -- "$device")
[[ -b "$real" ]] || fail "$device is not a block device"
name=$(basename -- "$real")
sys="/sys/block/$name"
[[ -d "$sys" ]] || fail "$real is not a whole disk (is it a partition? give the disk, e.g. /dev/sdb)"
[[ "$(lsblk -dno TYPE -- "$real")" == disk ]] || fail "$real is not a disk"

transport=$(lsblk -dno TRAN -- "$real" | tr -d ' ')
[[ "$transport" == usb ]] || fail "$real is attached over '${transport:-unknown}', not USB"

removable=$(cat "$sys/removable" 2>/dev/null || echo 0)
if [[ "$removable" != 1 ]]; then
    if [[ "${LINOX_ALLOW_FIXED_USB:-0}" != 1 ]]; then
        fail "$real does not report itself removable; if it is a USB SSD you mean to erase, set LINOX_ALLOW_FIXED_USB=1"
    fi
    echo "write-usb: warning: $real is a non-removable USB disk (LINOX_ALLOW_FIXED_USB=1)" >&2
fi

bytes=$(($(cat "$sys/size") * 512))
((bytes > 0)) || fail "$real reports no media (is the stick inserted?)"
((bytes < size_limit)) || fail "$real is $((bytes / 1000000000)) GB; sticks of 256 GB and more are refused"
image_bytes=$(stat -c '%s' -- "$image")
((image_bytes <= bytes)) || fail "$image ($image_bytes bytes) does not fit on $real ($bytes bytes)"

# Nothing on the disk may be in use.
mounted=$(lsblk -nro MOUNTPOINTS -- "$real" 2>/dev/null | sed '/^$/d' || true)
[[ -z "$mounted" ]] || fail "$real has mounted filesystems: $(echo "$mounted" | tr '\n' ' ')"
while read -r swap _; do
    [[ "$swap" == /dev/* ]] || continue
    swap_disk=$(lsblk -no PKNAME -- "$swap" 2>/dev/null | head -1)
    [[ "$(basename -- "$(readlink -f -- "$swap")")" != "$name" && "$swap_disk" != "$name" ]] ||
        fail "$real holds active swap $swap"
done </proc/swaps
for holders in "$sys"/holders "$sys"/"$name"*/holders; do
    [[ -d "$holders" ]] || continue
    [[ -z "$(ls -A "$holders")" ]] || fail "$real is in use by $(ls "$holders" | tr '\n' ' ')"
done

# Never the disk the running system lives on.
for mountpoint in / /boot /boot/efi; do
    source=$(findmnt -no SOURCE --target "$mountpoint" 2>/dev/null | head -1 || true)
    [[ "$source" == /dev/* ]] || continue
    source=$(readlink -f -- "$source")
    for disk in $(lsblk -nso NAME,TYPE -- "$source" 2>/dev/null | awk '$2 == "disk" {print $1}'); do
        disk=${disk##*[!a-zA-Z0-9]}
        [[ "$disk" != "$name" ]] || fail "$real holds $mountpoint"
    done
done

model=$(lsblk -dno MODEL -- "$real" | sed 's/ *$//')
vendor=$(lsblk -dno VENDOR -- "$real" | sed 's/ *$//')
serial=$(lsblk -dno SERIAL -- "$real" | sed 's/ *$//')
cat <<EOF
Target: $real ($device)
  vendor/model: ${vendor:-?} ${model:-?}
  serial:       ${serial:-?}
  size:         $((bytes / 1000000)) MB ($bytes bytes), transport $transport, removable $removable
  contents:
EOF
lsblk -no NAME,SIZE,FSTYPE,LABEL,PARTLABEL -- "$real" | sed 's/^/    /'
cat <<EOF
Image:  $image ($((image_bytes / 1048576)) MiB)
        sha256 $(sha256sum -- "$image" | cut -d' ' -f1)

EVERYTHING on $real will be erased.
EOF

if ((dry_run)); then
    echo "write-usb: dry run; nothing written"
    exit 0
fi

read -r -p "Type the device name ($name) to write the image, anything else to stop: " answer
[[ "$answer" == "$name" ]] || {
    echo "write-usb: stopped; nothing written"
    exit 1
}

sudo=()
((EUID == 0)) || sudo=(sudo)
"${sudo[@]}" dd if="$image" of="$real" bs=4M conv=fsync oflag=direct status=progress
sync

# Read back what was written and compare.
written=$("${sudo[@]}" dd if="$real" bs=4M iflag=direct status=none |
    head -c "$image_bytes" | sha256sum | cut -d' ' -f1)
expected=$(sha256sum -- "$image" | cut -d' ' -f1)
if [[ "$written" != "$expected" ]]; then
    echo "write-usb: VERIFY FAILED: the stick reads back $written, the image is $expected" >&2
    exit 1
fi
echo "write-usb: written and verified ($expected)."
echo "Boot the target with Secure Boot off and pick the stick in the firmware's one-time boot menu (docs/HARDWARE-BRINGUP.md)."
