#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
boot_timeout_seconds="${LINOX_BOOT_TIMEOUT_SECONDS:-180}"
if [[ ! "$boot_timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo "Boot test failed: LINOX_BOOT_TIMEOUT_SECONDS must be a positive integer." >&2
    exit 2
fi
if [[ -n "${LINOX_BOOT_ARTIFACT_DIR:-}" ]]; then
    mkdir -p "$LINOX_BOOT_ARTIFACT_DIR"
fi

output_file="$(mktemp -t linox-boot.XXXXXX)"
reboot_output_file="$(mktemp -t linox-reboot.XXXXXX)"
corrupt_output_file="$(mktemp -t linox-corrupt.XXXXXX)"
native_corrupt_output_file="$(mktemp -t linox-native-corrupt.XXXXXX)"
volume_image="$(mktemp -t linox-volume.XXXXXX)"
corrupt_volume_image="$(mktemp -t linox-corrupt-volume.XXXXXX)"
native_corrupt_volume_image="$(mktemp -t linox-native-corrupt-volume.XXXXXX)"
qemu_pid_file="$(mktemp -t linox-boot-pid.XXXXXX)"
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
    if [[ -n "${LINOX_BOOT_ARTIFACT_DIR:-}" ]]; then
        mkdir -p "$LINOX_BOOT_ARTIFACT_DIR"
        cp "$output_file" "$LINOX_BOOT_ARTIFACT_DIR/initial-boot.log"
        cp "$reboot_output_file" "$LINOX_BOOT_ARTIFACT_DIR/reboot.log"
        cp "$corrupt_output_file" "$LINOX_BOOT_ARTIFACT_DIR/corrupt-media.log"
        cp "$native_corrupt_output_file" "$LINOX_BOOT_ARTIFACT_DIR/native-corrupt-media.log"
    fi
    rm -f \
        "$output_file" \
        "$reboot_output_file" \
        "$corrupt_output_file" \
        "$native_corrupt_output_file" \
        "$volume_image" \
        "$corrupt_volume_image" \
        "$native_corrupt_volume_image" \
        "$qemu_pid_file"
}
trap cleanup EXIT

dd if=/dev/zero of="$volume_image" bs=1048576 count=1 2>/dev/null

run_boot() {
    local boot_output="$1"
    local boot_name="$2"
    local boot_volume="${3:-$volume_image}"

    : >"$qemu_pid_file"
    {
        qemu_seen=false
        for ((attempt = 0; attempt < boot_timeout_seconds; attempt++)); do
            if grep -Fq 'linox> ' "$boot_output"; then
                break
            fi
            if grep -Eq 'LINOX_(KERNEL|BOOT)_PANIC' "$boot_output"; then
                stop_qemu
                exit 0
            fi
            if [[ -s "$qemu_pid_file" ]]; then
                qemu_seen=true
                read -r active_qemu_pid <"$qemu_pid_file" || true
                if [[ ! "$active_qemu_pid" =~ ^[0-9]+$ ]] ||
                    ! kill -0 "$active_qemu_pid" 2>/dev/null; then
                    exit 0
                fi
            elif [[ "$qemu_seen" == true ]]; then
                exit 0
            fi
            sleep 1
        done
        printf 'shutdown\n'
    } | LINOX_VOLUME_IMAGE="$boot_volume" LINOX_QEMU_PID_FILE="$qemu_pid_file" \
        "$repo_root/tools/qemu/run.sh" >"$boot_output" 2>&1 &
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
        cat "$boot_output"
        echo "Boot test failed: $boot_name QEMU boot did not finish within ${boot_timeout_seconds} seconds." >&2
        exit 1
    fi

    if wait "$qemu_pid"; then
        qemu_status=0
    else
        qemu_status=$?
    fi
    qemu_pid=""
    : >"$qemu_pid_file"

    if [[ "$qemu_status" -ne 0 ]]; then
        cat "$boot_output"
        echo "Boot test failed: $boot_name QEMU boot exited with $qemu_status; expected 0." >&2
        exit 1
    fi
}

assert_native_volume_iommu() {
    local boot_output="$1"
    local boot_name="$2"

    if ! grep -q '^linox: every native volume generation used an active IOMMU domain' "$boot_output" ||
        ! grep -q '^linox: native volume generations received fresh IOMMU leases' "$boot_output" ||
        ! grep -q '^linox: native volume IOMMU retired after device quiescence' "$boot_output" ||
        ! grep -q '^linox: fault and timeout paths retired native volume IOMMU state' "$boot_output"; then
        cat "$boot_output"
        echo "Boot test failed: $boot_name did not prove native volume IOMMU lifecycle isolation." >&2
        exit 1
    fi
}

assert_cpu_topology() {
    local boot_output="$1"
    local boot_name="$2"
    local expected_cpus="${LINOX_CPUS:-2}"

    if ! grep -q "^linox: enabled processors: $expected_cpus" "$boot_output" ||
        ! grep -q "^linox: online processors: $expected_cpus" "$boot_output"; then
        cat "$boot_output"
        echo "Boot test failed: $boot_name did not bring all $expected_cpus configured CPUs online." >&2
        exit 1
    fi
}

run_boot "$output_file" "initial"
assert_native_volume_iommu "$output_file" "initial boot"
assert_cpu_topology "$output_file" "initial boot"

cat "$output_file"

if ! grep -q '^LINOX_KERNEL_OK' "$output_file"; then
    echo "Boot test failed: the post-firmware kernel marker was not emitted." >&2
    exit 1
fi

if ! grep -q '^linox: bounded OCI rootfs unpack policy verified' "$output_file"; then
    echo "Boot test failed: OCI rootfs expansion was not bounded before allocation." >&2
    exit 1
fi

"$repo_root/tests/qemu/check-linux-runtime.sh" "$output_file"

if ! grep -q '^linox: modern virtio network function: 0:3.0' "$output_file" ||
    ! grep -q '^linox: modern virtio-net PCI capabilities validated' "$output_file" ||
    ! grep -q '^linox: malformed virtio-net PCI configurations rejected' "$output_file" ||
    ! grep -q '^linox: firmware virtio-net DMA authority revoked' "$output_file" ||
    ! grep -q '^linox: virtio-net PCI decoding and bus mastering disabled' "$output_file" ||
    ! grep -q '^linox: virtio-net IOMMU endpoint scope resolved exactly' "$output_file" ||
    ! grep -q '^linox: bounded uncached virtio-net common mapping active' "$output_file" ||
    ! grep -q '^linox: bounded read-only uncached virtio-net device mapping active' "$output_file" ||
    ! grep -q '^linox: bounded uncached virtio-net notification mapping active' "$output_file" ||
    ! grep -q '^linox: bounded uncached virtio-net MSI-X mapping active' "$output_file" ||
    ! grep -q '^linox: virtio-net cacheable alias absent' "$output_file" ||
    ! grep -q '^linox: virtio-net accepted features: 12884934688' "$output_file" ||
    ! grep -q '^linox: virtio-net queues available: 3' "$output_file" ||
    ! grep -Eq '^linox: virtio-net receive queue size: (8|16|32|64|128|256|512|1024|2048|4096|8192|16384|32768)[[:space:]]*$' "$output_file" ||
    ! grep -Eq '^linox: virtio-net transmit queue size: (8|16|32|64|128|256|512|1024|2048|4096|8192|16384|32768)[[:space:]]*$' "$output_file" ||
    ! grep -q '^linox: virtio-net receive notification address: [0-9]' "$output_file" ||
    ! grep -q '^linox: virtio-net transmit notification address: [0-9]' "$output_file" ||
    ! grep -q '^linox: virtio-net queues remain disabled and DMA-unbound' "$output_file" ||
    ! grep -q '^linox: invalid virtio-net queue geometry rejected' "$output_file" ||
    ! grep -q '^linox: virtio-net MSI-X remained disabled' "$output_file" ||
    ! grep -q '^linox: invalid virtio-net MSI-X programming rejected atomically' "$output_file" ||
    ! grep -q '^linox: masked virtio-net RX/TX MSI-X vectors programmed' "$output_file" ||
    ! grep -q '^linox: virtio-net MSI-X remained globally disabled' "$output_file" ||
    ! grep -q '^linox: virtio-net remained reset and DMA-disabled after MSI-X setup' "$output_file" ||
    ! grep -q '^linox: generation-owned virtio-net DMA page allocated' "$output_file" ||
    ! grep -q '^linox: bounded virtio-net RX/TX DMA layout validated' "$output_file" ||
    ! grep -q '^linox: malformed virtio-net DMA layouts rejected' "$output_file" ||
    ! grep -q '^linox: dedicated virtio-net IOMMU hierarchy constructed' "$output_file" ||
    ! grep -q '^linox: virtio-net IOMMU source and DMA page encoded exactly' "$output_file" ||
    ! grep -q '^linox: virtio-net DMA and IOMMU leases are generation-fresh' "$output_file" ||
    ! grep -q '^linox: virtio-net IOMMU hardware remained inactive' "$output_file" ||
    ! grep -q '^linox: virtio-net bus mastering remained disabled' "$output_file" ||
    ! grep -q '^linox: virtio-net IOMMU activated before queue authority' "$output_file" ||
    ! grep -q '^linox: empty virtio-net RX/TX queues bound to confined DMA' "$output_file" ||
    ! grep -q '^linox: virtio-net DRIVER_OK established with empty rings' "$output_file" ||
    ! grep -q '^linox: virtio-net bus mastering enabled last' "$output_file" ||
    ! grep -q '^linox: empty virtio-net queues quiesced without notification' "$output_file" ||
    ! grep -q '^linox: virtio-net bus mastering revoked before IOMMU teardown' "$output_file" ||
    ! grep -q '^linox: confined virtio-net TX descriptor published' "$output_file" ||
    ! grep -q '^linox: virtio-net TX queue notified' "$output_file" ||
    ! grep -q '^linox: exactly one virtio-net TX interrupt delivered' "$output_file" ||
    ! grep -q '^linox: virtio-net TX used-ring completion validated' "$output_file" ||
    ! grep -q '^linox: virtio-net TX payload and guards preserved' "$output_file" ||
    ! grep -q '^linox: bounded Ethernet probe transmitted' "$output_file" ||
    ! grep -q '^linox: virtio-net TX route retired before DMA release' "$output_file" ||
    ! grep -q '^linox: unauthorized virtio-net RX DMA payload blocked' "$output_file" ||
    ! grep -q '^linox: faulting virtio-net transport outcome bounded' "$output_file" ||
    ! grep -q '^linox: virtio-net unmapped guard page remained unchanged' "$output_file" ||
    ! grep -q '^linox: faulting virtio-net device quiesced before recovery' "$output_file" ||
    ! grep -q '^linox: virtio-net IOMMU fault source and address validated' "$output_file" ||
    ! grep -q '^linox: virtio-net IOMMU write fault cleared and translation recovered' "$output_file" ||
    ! grep -q '^linox: confined virtio-net RX descriptor published' "$output_file" ||
    ! grep -q '^linox: bounded ARP request transmitted' "$output_file" ||
    ! grep -q '^linox: exactly one virtio-net RX interrupt delivered' "$output_file" ||
    ! grep -q '^linox: virtio-net RX used-ring completion validated' "$output_file" ||
    ! grep -q '^linox: QEMU gateway ARP reply validated' "$output_file" ||
    ! grep -q '^linox: virtio-net RX payload bounds preserved' "$output_file" ||
    ! grep -q '^linox: virtio-net RX/TX routes retired before DMA release' "$output_file" ||
    ! grep -q '^linox: virtio-net unmapped guard page scrubbed and released' "$output_file" ||
    ! grep -q '^linox: virtio-net DMA confinement retired cleanly' "$output_file" ||
    ! grep -q '^linox: virtio-net stable MAC validated: 90520731923542' "$output_file" ||
    ! grep -q '^linox: virtio-net platform DMA negotiation validated' "$output_file" ||
    ! grep -q '^linox: invalid virtio-net feature sets rejected' "$output_file" ||
    ! grep -q '^linox: virtio-net returned to reset with PCI decoding disabled' "$output_file"; then
    echo "Boot test failed: the bounded virtio-net discovery boundary was not established." >&2
    exit 1
fi

if ! grep -q '^linox: measured isolated network service discovered' "$output_file" ||
    ! grep -q '^linox: bounded native network PIE load plan accepted' "$output_file" ||
    ! grep -q '^linox: native network service relative relocations accepted' "$output_file" ||
    ! grep -q '^linox: native network service segments materialized in owned frames' "$output_file" ||
    ! grep -q '^linox: native network service relative relocations applied' "$output_file" ||
    ! grep -q '^linox: native network service W\^X address space verified' "$output_file" ||
    ! grep -q '^linox: native network service guard pages verified' "$output_file"; then
    echo "Boot test failed: the authenticated native network-service image was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: measured isolated protocol service discovered' "$output_file" ||
    ! grep -q '^linox: bounded native protocol PIE load plan accepted' "$output_file" ||
    ! grep -q '^linox: native protocol service relative relocations accepted' "$output_file" ||
    ! grep -q '^linox: native protocol service segments materialized in owned frames' "$output_file" ||
    ! grep -q '^linox: native protocol service relative relocations applied' "$output_file" ||
    ! grep -q '^linox: native protocol service W\^X address space verified' "$output_file" ||
    ! grep -q '^linox: native protocol service guard pages verified' "$output_file"; then
    echo "Boot test failed: the authenticated native protocol-service image was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: compiled native network service executed in ring 3' "$output_file" ||
    ! grep -q '^linox: native network service negotiated control ABI v4' "$output_file" ||
    ! grep -q '^linox: native network service validated control descriptor v4' "$output_file" ||
    ! grep -q '^linox: native network service started without boot capabilities' "$output_file" ||
    ! grep -q '^linox: native network service exited through lifecycle ABI v0' "$output_file" ||
    ! grep -q '^linox: native network service address space retired cleanly' "$output_file"; then
    echo "Boot test failed: the native network-service lifecycle was not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: native network bootstrap ABI v0 validated in ring 3' "$output_file" ||
    ! grep -q '^linox: native network read capability exercised in ring 3' "$output_file" ||
    ! grep -q '^linox: native network DMA lease remained device-inaccessible' "$output_file" ||
    ! grep -q '^linox: native network MMIO remained PCI-disabled' "$output_file" ||
    ! grep -q '^linox: native network bootstrap resources retired cleanly' "$output_file"; then
    echo "Boot test failed: the native network bootstrap was not safely delegated." >&2
    exit 1
fi

if ! grep -q '^linox: malformed native network bootstrap rejected in ring 3' "$output_file" ||
    ! grep -q '^linox: malformed network generation fault contained' "$output_file" ||
    ! grep -q '^linox: malformed network capability revoked' "$output_file" ||
    ! grep -q '^linox: malformed network resources retired before device activation' "$output_file"; then
    echo "Boot test failed: malformed native network bootstrap was not contained." >&2
    exit 1
fi

if ! grep -q '^linox: native network generation received exact VT-d domain' "$output_file" ||
    ! grep -q '^linox: native network VT-d activated before PCI authority' "$output_file" ||
    ! grep -q '^linox: native network bus mastering remained disabled' "$output_file" ||
    ! grep -q '^linox: native network VT-d retired before DMA release' "$output_file" ||
    ! grep -q '^linox: native network translation tables scrubbed cleanly' "$output_file"; then
    echo "Boot test failed: native network VT-d confinement did not retire safely." >&2
    exit 1
fi

if ! grep -q '^linox: faulted native network generation retired active VT-d' "$output_file" ||
    ! grep -q '^linox: faulted network translation disabled before DMA scrub' "$output_file" ||
    ! grep -q '^linox: faulted network VT-d tables released cleanly' "$output_file"; then
    echo "Boot test failed: faulted native network VT-d teardown was unsafe." >&2
    exit 1
fi

if ! grep -q '^linox: native network service configured empty RX/TX queues' "$output_file" ||
    ! grep -q '^linox: native network queue layout validated by kernel' "$output_file" ||
    ! grep -q '^linox: native network bus mastering authorized by capability' "$output_file" ||
    ! grep -q '^linox: native network bus mastering enabled last' "$output_file" ||
    ! grep -q '^linox: native network device quiesced before VT-d teardown' "$output_file" ||
    ! grep -q '^linox: native network empty-queue generation retired cleanly' "$output_file"; then
    echo "Boot test failed: native network empty queues were not delegated safely." >&2
    exit 1
fi

if ! grep -q '^linox: active native network driver fault injected at call boundary' "$output_file" ||
    ! grep -q '^linox: faulted native network queues were live before quiescence' "$output_file" ||
    ! grep -q '^linox: faulted native network bus mastering revoked' "$output_file" ||
    ! grep -q '^linox: faulted native network device reset before VT-d teardown' "$output_file" ||
    ! grep -q '^linox: active network fault retired translation before DMA' "$output_file" ||
    ! grep -q '^linox: active network fault contained without kernel panic' "$output_file"; then
    echo "Boot test failed: active native network fault teardown was unsafe." >&2
    exit 1
fi

if ! grep -q '^linox: native network service published bounded TX descriptor' "$output_file" ||
    ! grep -q '^linox: native network service notified transmit queue' "$output_file" ||
    ! grep -q '^linox: native network service blocked for TX interrupt' "$output_file" ||
    ! grep -q '^linox: native network TX replay rejected' "$output_file" ||
    ! grep -q '^linox: kernel validated native network TX descriptor and payload' "$output_file" ||
    ! grep -q '^linox: native network TX payload guards preserved' "$output_file" ||
    ! grep -q '^linox: native network service transmitted Ethernet probe' "$output_file" ||
    ! grep -q '^linox: native network TX interrupt route retired cleanly' "$output_file" ||
    ! grep -q '^linox: notified native network timeout cancelled safely' "$output_file" ||
    ! grep -q '^linox: ambiguous native network generation retired' "$output_file" ||
    ! grep -q '^linox: fresh native network generation recovered after timeout' "$output_file" ||
    ! grep -q '^linox: recovered network generation completed TX interrupt' "$output_file"; then
    echo "Boot test failed: native network service transmit was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: native network service published bounded RX descriptor' "$output_file" ||
    ! grep -q '^linox: native network service transmitted ARP request' "$output_file" ||
    ! grep -q '^linox: native network service blocked for RX interrupt' "$output_file" ||
    ! grep -q '^linox: native network RX replay rejected' "$output_file" ||
    ! grep -q '^linox: native network service validated gateway ARP reply' "$output_file" ||
    ! grep -q '^linox: kernel validated native network RX descriptor and ARP reply' "$output_file" ||
    ! grep -q '^linox: native network RX payload guards preserved' "$output_file" ||
    ! grep -q '^linox: native network TX and RX interrupt routes retired cleanly' "$output_file" ||
    ! grep -q '^linox: native network RX timeout followed completed TX' "$output_file" ||
    ! grep -q '^linox: ambiguous native network RX generation retired' "$output_file" ||
    ! grep -q '^linox: fresh native network generation recovered after RX timeout' "$output_file" ||
    ! grep -q '^linox: recovered network generation validated gateway ARP reply' "$output_file" ||
    ! grep -q '^linox: malformed network ARP reply injected after RX completion' "$output_file" ||
    ! grep -q '^linox: native network service rejected malformed ARP reply' "$output_file" ||
    ! grep -q '^linox: malformed network receive generation retired safely' "$output_file" ||
    ! grep -q '^linox: fresh native network generation recovered after malformed reply' "$output_file" ||
    ! grep -q '^linox: post-malformation network generation validated ARP reply' "$output_file" ||
    ! grep -q '^linox: native network service replenished RX descriptor' "$output_file" ||
    ! grep -q '^linox: native network service completed second ARP exchange' "$output_file" ||
    ! grep -q '^linox: native network request generations one through four completed' "$output_file" ||
    ! grep -q '^linox: kernel validated both native network ARP exchanges' "$output_file" ||
    ! grep -q '^linox: native network ICMP gateway request transmitted' "$output_file" ||
    ! grep -q '^linox: native network ICMP gateway reply validated' "$output_file" ||
    ! grep -q '^linox: native network service copied validated frame out of DMA' "$output_file" ||
    ! grep -q '^linox: packet producer retained no read authority' "$output_file" ||
    ! grep -q '^linox: compiled Rust protocol service consumed Ethernet frame' "$output_file" ||
    ! grep -q '^linox: protocol service validated gateway ARP reply' "$output_file" ||
    ! grep -q '^linox: protocol service rejected malformed ARP metadata' "$output_file" ||
    ! grep -q '^linox: protocol consumer retained no device or write authority' "$output_file" ||
    ! grep -q '^linox: packet survived producer and device retirement' "$output_file" ||
    ! grep -q '^linox: protocol service address space retired cleanly' "$output_file" ||
    ! grep -q '^linox: network driver faulted after packet publication' "$output_file" ||
    ! grep -q '^linox: faulted packet producer authority revoked' "$output_file" ||
    ! grep -q '^linox: fault teardown preserved copied packet sequence two' "$output_file" ||
    ! grep -q '^linox: fresh ring-3 consumer received fault-surviving packet' "$output_file" ||
    ! grep -q '^linox: network producer queued two packets before retirement' "$output_file" ||
    ! grep -q '^linox: packet FIFO preserved sequence three before four' "$output_file" ||
    ! grep -q '^linox: separate ring-3 consumers drained packet FIFO in order' "$output_file" ||
    ! grep -q '^linox: bounded packet FIFO backpressure invariant verified' "$output_file" ||
    ! grep -q '^linox: empty packet consumer blocked on exact sequence' "$output_file" ||
    ! grep -q '^linox: write-only packet producer wait denied' "$output_file" ||
    ! grep -q '^linox: packet publication woke exactly one read-only consumer' "$output_file" ||
    ! grep -q '^linox: stale packet waits rejected without blocking' "$output_file" ||
    ! grep -q '^linox: woken packet consumer received exact frame' "$output_file" ||
    ! grep -q '^linox: blocked packet consumer stopped by control authority' "$output_file" ||
    ! grep -q '^linox: cancelled packet wait key released' "$output_file" ||
    ! grep -q '^linox: cancelled packet consumer frames and capability retired' "$output_file" ||
    ! grep -q '^linox: replacement packet consumer claimed cancelled sequence' "$output_file" ||
    ! grep -q '^linox: replacement packet consumer received exact frame' "$output_file" ||
    ! grep -q '^linox: bounded packet wait expired through APIC deadline' "$output_file" ||
    ! grep -q '^linox: packet timeout preempted non-cooperative peer' "$output_file" ||
    ! grep -q '^linox: timed-out packet wait key released' "$output_file" ||
    ! grep -q '^linox: replacement packet consumer claimed timed-out sequence' "$output_file" ||
    ! grep -q '^linox: replacement packet consumer received post-timeout frame' "$output_file" ||
    ! grep -q '^linox: packet publication cancelled pending wait deadline' "$output_file" ||
    ! grep -q '^linox: full packet FIFO blocked write-only producer' "$output_file" ||
    ! grep -q '^linox: packet consumption woke exactly one blocked producer' "$output_file" ||
    ! grep -q '^linox: woken packet producer retried exact next sequence' "$output_file" ||
    ! grep -q '^linox: packet FIFO ordering survived backpressure wakeup' "$output_file" ||
    ! grep -q '^linox: compiled protocol service waited on an empty packet FIFO' "$output_file" ||
    ! grep -q '^linox: resident protocol domain consumed two ordered packets' "$output_file" ||
    ! grep -q '^linox: protocol domain remained live between packet arrivals' "$output_file" ||
    ! grep -q '^linox: protocol service learned bounded ARP neighbor' "$output_file" ||
    ! grep -q '^linox: protocol service refreshed stable ARP neighbor' "$output_file" ||
    ! grep -q '^linox: conflicting ARP neighbor mapping rejected without mutation' "$output_file" ||
    ! grep -q '^linox: resident protocol wait keys and frames retired cleanly' "$output_file" ||
    ! grep -q '^linox: supervised protocol loop consumed multiple packets' "$output_file" ||
    ! grep -q '^linox: control plane stopped blocked protocol service' "$output_file" ||
    ! grep -q '^linox: supervised protocol wait and frames retired cleanly' "$output_file" ||
    ! grep -q '^linox: protocol service dispatched ARP then IPv4' "$output_file" ||
    ! grep -q '^linox: protocol service validated IPv4 header checksum' "$output_file" ||
    ! grep -q '^linox: malformed IPv4 header rejected in ring 3' "$output_file" ||
    ! grep -q '^linox: IPv4 protocol generation retired cleanly' "$output_file" ||
    ! grep -q '^linox: protocol service validated ICMP echo request' "$output_file" ||
    ! grep -q '^linox: ICMP type code identifier and sequence accepted' "$output_file" ||
    ! grep -q '^linox: malformed ICMP checksum rejected in ring 3' "$output_file" ||
    ! grep -q '^linox: ICMP protocol generation retired cleanly' "$output_file" ||
    ! grep -q '^linox: protocol service constructed exact ICMP echo reply' "$output_file" ||
    ! grep -q '^linox: protocol egress authority remained write only' "$output_file" ||
    ! grep -q '^linox: isolated egress consumer retained read-only authority' "$output_file" ||
    ! grep -q '^linox: egress packet survived protocol service retirement' "$output_file" ||
    ! grep -q '^linox: isolated egress consumer received exact echo reply' "$output_file" ||
    ! grep -q '^linox: protocol egress sequence consumed exactly once' "$output_file" ||
    ! grep -q '^linox: protocol service published second ICMP echo reply' "$output_file" ||
    ! grep -q '^linox: network service consumed read-only egress sequence' "$output_file" ||
    ! grep -q '^linox: network service copied echo reply into confined DMA' "$output_file" ||
    ! grep -q '^linox: network service transmitted protocol egress through virtio-net' "$output_file" ||
    ! grep -q '^linox: kernel validated egress descriptor and exact echo reply' "$output_file" ||
    ! grep -q '^linox: protocol-to-device egress retired cleanly' "$output_file" ||
    ! grep -q '^linox: network service claimed egress without consuming it' "$output_file" ||
    ! grep -q '^linox: premature egress acknowledgement rejected' "$output_file" ||
    ! grep -q '^linox: faulted network generation released egress claim' "$output_file" ||
    ! grep -q '^linox: claimed egress packet survived network driver fault' "$output_file" ||
    ! grep -q '^linox: replacement network generation transmitted preserved reply' "$output_file" ||
    ! grep -q '^linox: egress acknowledged only after TX completion' "$output_file" ||
    ! grep -q '^linox: reliable protocol egress retired cleanly' "$output_file" ||
    ! grep -q '^linox: network service blocked before egress publication' "$output_file" ||
    ! grep -q '^linox: egress publication woke exact object and sequence' "$output_file" ||
    ! grep -q '^linox: ingress and egress packet wait keys isolated' "$output_file" ||
    ! grep -q '^linox: woken network service claimed exact egress sequence' "$output_file" ||
    ! grep -q '^linox: blocking egress transmitted and acknowledged through virtio-net' "$output_file" ||
    ! grep -q '^linox: blocking egress producer and network domains retired cleanly' "$output_file" ||
    ! grep -q '^linox: full egress FIFO blocked write-only producer' "$output_file" ||
    ! grep -q '^linox: egress delivery woke only object-9 space waiter' "$output_file" ||
    ! grep -q '^linox: woken egress producer retried exact next sequence' "$output_file" ||
    ! grep -q '^linox: egress FIFO ordering survived backpressure wakeup' "$output_file" ||
    ! grep -q '^linox: full egress FIFO remained full while head was claimed' "$output_file" ||
    ! grep -q '^linox: completed egress acknowledgement woke blocked producer' "$output_file" ||
    ! grep -q '^linox: post-ack producer published exact fifth sequence' "$output_file" ||
    ! grep -q '^linox: hardware-coupled egress backpressure retired cleanly' "$output_file" ||
    ! grep -q '^linox: resident network service transmitted two egress replies' "$output_file" ||
    ! grep -q '^linox: resident network service reused TX descriptor and DMA lease' "$output_file" ||
    ! grep -q '^linox: resident network interrupt generations advanced in order' "$output_file" ||
    ! grep -q '^linox: resident reliable egress retired cleanly' "$output_file" ||
    ! grep -q '^linox: resident network service drained full egress FIFO' "$output_file" ||
    ! grep -q '^linox: validated device progress renewed service call epochs' "$output_file" ||
    ! grep -q '^linox: four network interrupt generations advanced in order' "$output_file" ||
    ! grep -q '^linox: resident reliable egress batch retired cleanly' "$output_file" ||
    ! grep -q '^linox: resident network service blocked on fifth sequence' "$output_file" ||
    ! grep -q '^linox: control plane stopped resident network service' "$output_file" ||
    ! grep -q '^linox: resident stop quiesced device before DMA retirement' "$output_file" ||
    ! grep -q '^linox: resident egress wait and authority retired cleanly' "$output_file" ||
    ! grep -q '^linox: unauthorized resident drain requests rejected' "$output_file" ||
    ! grep -q '^linox: control plane requested resident network drain' "$output_file" ||
    ! grep -q '^linox: resident network drain preserved four egress replies' "$output_file" ||
    ! grep -q '^linox: drained resident network service exited normally' "$output_file" ||
    ! grep -q '^linox: resident drain quiesced device before DMA retirement' "$output_file" ||
    ! grep -q '^linox: stopped resident network service replaced cleanly' "$output_file" ||
    ! grep -q '^linox: replacement network domain generation was distinct' "$output_file" ||
    ! grep -q '^linox: replacement network DMA and VT-d leases were fresh' "$output_file" ||
    ! grep -q '^linox: replacement resident service resumed exact egress sequence' "$output_file" ||
    ! grep -q '^linox: ingress and egress space-wait keys isolated' "$output_file" ||
    ! grep -q '^linox: replenished network buffer guards preserved' "$output_file" ||
    ! grep -q '^linox: replenished network interrupt routes retired cleanly' "$output_file"; then
    echo "Boot test failed: native network service ARP receive was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: disk-backed volume generation: 1' "$output_file" ||
    ! grep -q '^linox: disk-backed volume initialized and flushed' "$output_file" ||
    ! grep -q '^linox: bounded virtio volume transaction completed' "$output_file" ||
    ! grep -q '^linox: persistent virtio device reset and bus mastering revoked' "$output_file"; then
    echo "Boot test failed: the first boot did not durably initialize volume generation one." >&2
    exit 1
fi

if grep -q '^linox: disk-backed volume recovered after reboot' "$output_file"; then
    echo "Boot test failed: a fresh volume was reported as a reboot recovery." >&2
    exit 1
fi

if ! grep -q '^linox: compiled native volume service executed in ring 3' "$output_file" ||
    ! grep -q '^linox: native service bootstrap ABI v0 validated in ring 3' "$output_file" ||
    ! grep -q '^linox: compiled native service validated control descriptor v4' "$output_file" ||
    ! grep -q '^linox: native volume service owned virtio request sequence' "$output_file" ||
    ! grep -q '^linox: native volume record initialized and flushed' "$output_file" ||
    ! grep -q '^linox: replacement native volume domain generation started' "$output_file" ||
    ! grep -q '^linox: native volume service identity survived replacement' "$output_file" ||
    ! grep -q '^linox: replacement native volume service recovered exact record' "$output_file" ||
    ! grep -q '^linox: replacement native volume resources retired cleanly' "$output_file" ||
    ! grep -q '^linox: incompatible native service ABI rejected before device activation' "$output_file" ||
    ! grep -q '^linox: compatible native service recovered after ABI rejection' "$output_file" ||
    ! grep -q '^linox: malformed native control descriptor rejected before device activation' "$output_file" ||
    ! grep -q '^linox: compatible native service recovered after descriptor rejection' "$output_file" ||
    grep -q '^linox: native volume record recovered after reboot' "$output_file"; then
    cat "$output_file"
    echo "Boot test failed: compiled native volume service did not initialize its record." >&2
    exit 1
fi

run_boot "$reboot_output_file" "recovery"
assert_native_volume_iommu "$reboot_output_file" "recovery boot"

if ! grep -q '^LINOX_KERNEL_OK' "$reboot_output_file" ||
    ! grep -q '^linox: disk-backed volume generation: 1' "$reboot_output_file" ||
    ! grep -q '^linox: disk-backed volume recovered after reboot' "$reboot_output_file" ||
    ! grep -q '^linox: persistent virtio device reset and bus mastering revoked' "$reboot_output_file" ||
    ! grep -q '^linox: virtio DMA frame scrubbed and released' "$reboot_output_file"; then
    cat "$reboot_output_file"
    echo "Boot test failed: the second boot did not recover durable volume generation one." >&2
    exit 1
fi

if grep -q '^linox: disk-backed volume initialized and flushed' "$reboot_output_file" ||
    grep -qE '^LINOX_(BOOT|KERNEL)_PANIC' "$reboot_output_file"; then
    cat "$reboot_output_file"
    echo "Boot test failed: the recovery boot rewrote the volume or emitted a panic." >&2
    exit 1
fi

if ! grep -q '^linox: compiled native volume service executed in ring 3' "$reboot_output_file" ||
    ! grep -q '^linox: native service bootstrap ABI v0 validated in ring 3' "$reboot_output_file" ||
    ! grep -q '^linox: native service lifecycle ABI v0 clean exit validated in ring 3' "$reboot_output_file" ||
    ! grep -q '^linox: compiled native service negotiated control ABI v4' "$reboot_output_file" ||
    ! grep -q '^linox: compiled native service validated control descriptor v4' "$reboot_output_file" ||
    ! grep -q '^linox: native volume service exited cleanly and device quiesced' "$reboot_output_file" ||
    ! grep -q '^linox: native volume record recovered after reboot' "$reboot_output_file" ||
    ! grep -q '^linox: replacement native volume domain generation started' "$reboot_output_file" ||
    ! grep -q '^linox: native volume service identity survived replacement' "$reboot_output_file" ||
    ! grep -q '^linox: replacement native volume service recovered exact record' "$reboot_output_file" ||
    ! grep -q '^linox: replacement native volume resources retired cleanly' "$reboot_output_file" ||
    ! grep -q '^linox: incompatible native service ABI rejected before device activation' "$reboot_output_file" ||
    ! grep -q '^linox: compatible native service recovered after ABI rejection' "$reboot_output_file" ||
    ! grep -q '^linox: malformed native control descriptor rejected before device activation' "$reboot_output_file" ||
    ! grep -q '^linox: compatible native service recovered after descriptor rejection' "$reboot_output_file" ||
    ! grep -q '^linox: compiled native volume service fault contained' "$reboot_output_file" ||
    ! grep -q '^linox: post-fault native volume service recovered exact record' "$reboot_output_file" ||
    ! grep -q '^linox: notified native volume timeout cancelled safely' "$reboot_output_file" ||
    ! grep -q '^linox: post-cancellation native volume recovered exact record' "$reboot_output_file" ||
    grep -q '^linox: native volume record initialized and flushed' "$reboot_output_file"; then
    cat "$reboot_output_file"
    echo "Boot test failed: compiled native volume service did not recover its record." >&2
    exit 1
fi

cp "$volume_image" "$native_corrupt_volume_image"
dd if=/dev/zero of="$native_corrupt_volume_image" bs=1 seek=2048 count=1 conv=notrunc 2>/dev/null
native_corrupt_checksum="$(cksum "$native_corrupt_volume_image")"
run_boot "$native_corrupt_output_file" "native-volume corruption" "$native_corrupt_volume_image"
assert_native_volume_iommu "$native_corrupt_output_file" "native-volume corruption boot"

if ! grep -q '^LINOX_KERNEL_OK' "$native_corrupt_output_file" ||
    ! grep -q '^linox: native service bootstrap ABI v0 validated in ring 3' "$native_corrupt_output_file" ||
    ! grep -q '^linox: native service lifecycle ABI v0 clean exit validated in ring 3' "$native_corrupt_output_file" ||
    ! grep -q '^linox: compiled native service negotiated control ABI v4' "$native_corrupt_output_file" ||
    ! grep -q '^linox: compiled native service validated control descriptor v4' "$native_corrupt_output_file" ||
    ! grep -q '^linox: disk-backed volume recovered after reboot' "$native_corrupt_output_file" ||
    ! grep -q '^linox: corrupt native volume media rejected without modification' "$native_corrupt_output_file" ||
    ! grep -q '^linox: replacement native volume domain generation started' "$native_corrupt_output_file" ||
    ! grep -q '^linox: native volume service identity survived replacement' "$native_corrupt_output_file" ||
    ! grep -q '^linox: replacement native volume service repeated fail-closed rejection' "$native_corrupt_output_file" ||
    ! grep -q '^linox: replacement native volume resources retired cleanly' "$native_corrupt_output_file" ||
    ! grep -q '^linox: incompatible native service ABI rejected before device activation' "$native_corrupt_output_file" ||
    ! grep -q '^linox: compatible native service recovered after ABI rejection' "$native_corrupt_output_file" ||
    ! grep -q '^linox: malformed native control descriptor rejected before device activation' "$native_corrupt_output_file" ||
    ! grep -q '^linox: compatible native service recovered after descriptor rejection' "$native_corrupt_output_file" ||
    ! grep -q '^linox: compiled native volume service fault contained' "$native_corrupt_output_file" ||
    ! grep -q '^linox: post-fault native volume service preserved rejection' "$native_corrupt_output_file" ||
    ! grep -q '^linox: notified native volume timeout cancelled safely' "$native_corrupt_output_file" ||
    ! grep -q '^linox: post-cancellation native volume preserved rejection' "$native_corrupt_output_file" ||
    ! grep -q '^linox: native volume service exited cleanly and device quiesced' "$native_corrupt_output_file" ||
    ! grep -q '^linox: retired DMA lease scrubbed and released' "$native_corrupt_output_file"; then
    cat "$native_corrupt_output_file"
    echo "Boot test failed: corrupt native volume media was not rejected and cleaned up safely." >&2
    exit 1
fi

if grep -q '^linox: native volume record initialized and flushed' "$native_corrupt_output_file" ||
    grep -q '^linox: native volume record recovered after reboot' "$native_corrupt_output_file" ||
    grep -qE '^LINOX_(BOOT|KERNEL)_PANIC' "$native_corrupt_output_file" ||
    [[ "$(cksum "$native_corrupt_volume_image")" != "$native_corrupt_checksum" ]]; then
    cat "$native_corrupt_output_file"
    echo "Boot test failed: corrupt native volume media was accepted, modified, or fatal." >&2
    exit 1
fi

cp "$volume_image" "$corrupt_volume_image"
dd if=/dev/zero of="$corrupt_volume_image" bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
corrupt_checksum="$(cksum "$corrupt_volume_image")"

: >"$qemu_pid_file"
LINOX_VOLUME_IMAGE="$corrupt_volume_image" LINOX_QEMU_PID_FILE="$qemu_pid_file" \
    "$repo_root/tools/qemu/run.sh" >"$corrupt_output_file" 2>&1 &
qemu_pid=$!
for _ in {1..30}; do
    if grep -q '^LINOX_KERNEL_PANIC' "$corrupt_output_file" ||
        ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 1
done
if kill -0 "$qemu_pid" 2>/dev/null; then
    stop_qemu
    kill "$qemu_pid" 2>/dev/null || true
fi
wait "$qemu_pid" 2>/dev/null || true
qemu_pid=""
: >"$qemu_pid_file"

if ! grep -q '^linox: persistent virtio device reset and bus mastering revoked' "$corrupt_output_file" ||
    ! grep -q '^linox: virtio DMA frame scrubbed and released' "$corrupt_output_file" ||
    ! grep -q '^linox: persistent virtio volume transaction failed' "$corrupt_output_file" ||
    ! grep -q '^LINOX_KERNEL_PANIC' "$corrupt_output_file"; then
    cat "$corrupt_output_file"
    echo "Boot test failed: corrupt nonempty volume media was not rejected safely." >&2
    exit 1
fi

if grep -q '^linox: disk-backed volume initialized and flushed' "$corrupt_output_file" ||
    grep -q '^LINOX_KERNEL_OK' "$corrupt_output_file" ||
    [[ "$(cksum "$corrupt_volume_image")" != "$corrupt_checksum" ]]; then
    cat "$corrupt_output_file"
    echo "Boot test failed: corrupt volume media was accepted or modified." >&2
    exit 1
fi

if ! grep -Eq '^linox: memory descriptors: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the kernel did not receive a valid UEFI memory map." >&2
    exit 1
fi

if ! grep -q '^linox: kernel stack active' "$output_file"; then
    echo "Boot test failed: the kernel did not switch to its owned stack." >&2
    exit 1
fi

if ! grep -q '^linox: versioned boot handoff accepted' "$output_file"; then
    echo "Boot test failed: the versioned boot handoff was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: loaded EFI PE image accepted' "$output_file"; then
    echo "Boot test failed: the loaded EFI image metadata was rejected." >&2
    exit 1
fi

if ! grep -Eq '^linox: PE sections: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the loaded EFI image has no validated PE sections." >&2
    exit 1
fi

if ! grep -Eq '^linox: executable PE sections: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the loaded EFI image has no executable PE section." >&2
    exit 1
fi

if ! grep -q '^linox: ACPI root pointer validated' "$output_file"; then
    echo "Boot test failed: the ACPI root pointer was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: signed boot manifest accepted' "$output_file"; then
    echo "Boot test failed: the signed boot manifest was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: manifest signature rejection verified' "$output_file"; then
    echo "Boot test failed: an invalid manifest signature was not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: malformed boot manifests rejected' "$output_file"; then
    echo "Boot test failed: malformed canonical manifests were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: manifest authority grants: 10' "$output_file"; then
    echo "Boot test failed: a signed directional packet authority grant is missing." >&2
    exit 1
fi

if ! grep -q '^linox: control-plane bundle measurement accepted' "$output_file"; then
    echo "Boot test failed: the measured control-plane bundle was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: root-image measurement accepted' "$output_file"; then
    echo "Boot test failed: the measured root image was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: root-image measurement rejection verified' "$output_file"; then
    echo "Boot test failed: a modified root image was not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: kernel page tables active' "$output_file"; then
    echo "Boot test failed: the kernel did not activate its own page tables." >&2
    exit 1
fi

if ! grep -q '^linox: NX-by-default identity map active' "$output_file"; then
    echo "Boot test failed: non-code identity mappings remain executable." >&2
    exit 1
fi

if ! grep -q '^linox: supervisor-only higher-half direct map active' "$output_file"; then
    echo "Boot test failed: higher-half direct-map alias was not active." >&2
    exit 1
fi

if ! grep -q '^linox: bounded direct-map translation verified' "$output_file"; then
    echo "Boot test failed: direct-map translation bounds were not verified." >&2
    exit 1
fi

if ! grep -q '^linox: PE executable identity pages read-only' "$output_file"; then
    echo "Boot test failed: executable PE pages remain writable." >&2
    exit 1
fi

if ! grep -q '^linox: PE image section permissions enforced' "$output_file"; then
    echo "Boot test failed: PE image section permissions were not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: boot policy inputs immutable and non-executable' "$output_file"; then
    echo "Boot test failed: boot policy inputs remain mutable or executable." >&2
    exit 1
fi

if ! grep -q '^linox: supervisor write protection active' "$output_file"; then
    echo "Boot test failed: supervisor write protection is inactive." >&2
    exit 1
fi

if ! grep -q '^linox: static kernel page tables sealed read-only' "$output_file"; then
    echo "Boot test failed: static kernel page tables remain writable." >&2
    exit 1
fi

if ! grep -q '^linox: supervisor execution prevention active' "$output_file"; then
    echo "Boot test failed: supervisor execution prevention is inactive." >&2
    exit 1
fi

if ! grep -q '^linox: supervisor access prevention active' "$output_file"; then
    echo "Boot test failed: supervisor access prevention is inactive." >&2
    exit 1
fi

if ! grep -q '^linox: user-mode instruction prevention active' "$output_file"; then
    echo "Boot test failed: user-mode instruction prevention is inactive." >&2
    exit 1
fi

if ! grep -q '^linox: null and bidirectional stack guard pages active' "$output_file"; then
    echo "Boot test failed: hardened null/bidirectional stack mappings are not active." >&2
    exit 1
fi

if ! grep -q '^linox: ACPI MADT validated' "$output_file"; then
    echo "Boot test failed: ACPI MADT discovery did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: ACPI DMAR validated' "$output_file" ||
    ! grep -q '^linox: remapping hardware units: 1' "$output_file" ||
    ! grep -q '^linox: DMA address width: 48' "$output_file" ||
    ! grep -q '^linox: first remapping register base: 4275634176' "$output_file" ||
    ! grep -q '^linox: malformed DMAR structures rejected' "$output_file"; then
    echo "Boot test failed: bounded ACPI DMAR discovery did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: bounded writable uncached IOMMU mapping active' "$output_file" ||
    ! grep -q '^linox: IOMMU version: 1\.0' "$output_file" ||
    ! grep -q '^linox: IOMMU translation remained disabled' "$output_file"; then
    echo "Boot test failed: bounded read-only IOMMU capability probe did not complete." >&2
    exit 1
fi

if ! grep -Eq '^linox: first IOMMU device scopes: [1-9][0-9]*' "$output_file" ||
    ! grep -q '^linox: virtio IOMMU endpoint scope resolved exactly' "$output_file"; then
    echo "Boot test failed: virtio PCI source ID is not covered by the DMAR unit." >&2
    exit 1
fi

if ! grep -q '^linox: IOMMU root/context hierarchy constructed' "$output_file" ||
    ! grep -Eq '^linox: IOMMU root table address: [1-9][0-9]*' "$output_file" ||
    ! grep -q '^linox: one-page identity DMA translation encoded exactly' "$output_file" ||
    ! grep -q '^linox: invalid IOMMU table inputs rejected' "$output_file" ||
    ! grep -q '^linox: IOMMU hardware state unchanged after table construction' "$output_file" ||
    ! grep -q '^linox: failed IOMMU activation rollback quarantined' "$output_file" ||
    ! grep -q '^linox: IOMMU translation frames scrubbed and released' "$output_file"; then
    echo "Boot test failed: IOMMU translation hierarchy lifecycle did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: IOMMU root table installed' "$output_file" ||
    ! grep -q '^linox: IOMMU translation enabled for virtio DMA' "$output_file" ||
    ! grep -q '^linox: unauthorized virtio DMA payload blocked' "$output_file" ||
    ! grep -q '^linox: unmapped DMA guard frame remained unchanged' "$output_file" ||
    ! grep -q '^linox: faulting virtio device reset and bus mastering revoked' "$output_file" ||
    ! grep -q '^linox: IOMMU fault source and address validated' "$output_file" ||
    ! grep -q '^linox: IOMMU write-permission fault reason validated' "$output_file" ||
    ! grep -q '^linox: IOMMU fault record cleared and translation recovered' "$output_file" ||
    ! grep -q '^linox: IOMMU translation disabled after device quiescence' "$output_file" ||
    ! grep -q '^linox: IOMMU root table cleared' "$output_file" ||
    ! grep -q '^linox: IOMMU fault status clear after recovery' "$output_file" ||
    ! grep -q '^linox: IOMMU guard frame scrubbed and released' "$output_file"; then
    echo "Boot test failed: active IOMMU confinement and recovery did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: ACPI tables use higher-half direct map' "$output_file"; then
    echo "Boot test failed: ACPI table access did not use the direct map." >&2
    exit 1
fi

if ! grep -Eq '^linox: enabled processors: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: ACPI reported no enabled processors." >&2
    exit 1
fi

if ! grep -Eq '^linox: I/O APICs: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: ACPI reported no I/O APICs." >&2
    exit 1
fi

if ! grep -q '^linox: GDT/TSS/IDT active' "$output_file"; then
    echo "Boot test failed: kernel CPU protection tables are not active." >&2
    exit 1
fi

if ! grep -q '^linox: user I/O-port access denied' "$output_file"; then
    echo "Boot test failed: ring-3 I/O-port access is not denied." >&2
    exit 1
fi

if ! grep -q '^linox: architectural exception gates active' "$output_file"; then
    echo "Boot test failed: architectural exceptions are not fully covered." >&2
    exit 1
fi

if ! grep -q '^linox: breakpoint exception handled' "$output_file"; then
    echo "Boot test failed: the recoverable exception test did not return." >&2
    exit 1
fi

if ! grep -q '^linox: local APIC discovered' "$output_file"; then
    echo "Boot test failed: the local APIC was not discovered." >&2
    exit 1
fi

if ! grep -q '^linox: local APIC uses higher-half direct map' "$output_file"; then
    echo "Boot test failed: local-APIC MMIO did not use the direct map." >&2
    exit 1
fi

if ! grep -Eq '^linox: local APIC mode: x2?APIC' "$output_file"; then
    echo "Boot test failed: the local APIC mode is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: local APIC physical base: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the local APIC base was not reported." >&2
    exit 1
fi

if ! grep -q '^linox: timer capabilities discovered' "$output_file"; then
    echo "Boot test failed: timer capabilities were not discovered." >&2
    exit 1
fi

if ! grep -Eq '^linox: invariant TSC: (advertised|not-advertised)' "$output_file"; then
    echo "Boot test failed: invariant-TSC capability is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: TSC deadline timer: (supported|unsupported)' "$output_file"; then
    echo "Boot test failed: TSC-deadline capability is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: TSC frequency source: (architectural-ratio|nominal-processor-frequency|unavailable)' "$output_file"; then
    echo "Boot test failed: TSC frequency source is invalid." >&2
    exit 1
fi

if ! grep -q '^linox: local APIC timer calibrated' "$output_file"; then
    echo "Boot test failed: the local APIC timer was not calibrated." >&2
    exit 1
fi

if ! grep -Eq '^linox: APIC timer counter Hz: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the local APIC timer frequency is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: calibrated TSC Hz: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the calibrated TSC frequency is invalid." >&2
    exit 1
fi

if ! grep -q '^linox: local APIC timer interrupt handled' "$output_file"; then
    echo "Boot test failed: the local APIC timer interrupt was not handled." >&2
    exit 1
fi

if ! grep -q '^linox: bounded PCI bus 0 enumerated' "$output_file"; then
    echo "Boot test failed: bounded PCI enumeration did not complete." >&2
    exit 1
fi

if ! grep -Eq '^linox: modern virtio block function: 0:[0-9]+\.0' "$output_file"; then
    echo "Boot test failed: the modern virtio block function was not discovered." >&2
    exit 1
fi

if ! grep -Eq '^linox: virtio common BAR address: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the virtio common BAR address is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: virtio common configuration length: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the virtio common configuration region is empty." >&2
    exit 1
fi

if ! grep -Eq '^linox: virtio notification multiplier: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the virtio notification multiplier is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: virtio PCI capabilities: [4-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the required virtio PCI capabilities were not present." >&2
    exit 1
fi

if ! grep -q '^linox: modern virtio-blk PCI capabilities validated' "$output_file"; then
    echo "Boot test failed: virtio-blk PCI capabilities were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: malformed virtio PCI configurations rejected' "$output_file"; then
    echo "Boot test failed: malformed virtio PCI configurations were not rejected." >&2
    exit 1
fi

if ! grep -Eq '^linox: virtio MSI-X capability offset: [1-9][0-9]*' "$output_file" ||
    ! grep -Eq '^linox: virtio MSI-X vectors: [1-9][0-9]*' "$output_file" ||
    ! grep -Eq '^linox: virtio MSI-X table address/length: [1-9][0-9]*/[1-9][0-9]*' "$output_file" ||
    ! grep -Eq '^linox: virtio MSI-X PBA address/length: [1-9][0-9]*/[1-9][0-9]*' "$output_file" ||
    ! grep -Eq '^linox: virtio MSI-X function mask: (masked|unmasked)' "$output_file" ||
    ! grep -q '^linox: disabled virtio MSI-X capability validated' "$output_file"; then
    echo "Boot test failed: the disabled virtio MSI-X capability was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded uncached virtio MMIO mapping active' "$output_file"; then
    echo "Boot test failed: the bounded virtio MMIO mapping is inactive." >&2
    exit 1
fi

if ! grep -q '^linox: bounded uncached MSI-X mapping active' "$output_file" ||
    ! grep -q '^linox: MSI-X cacheable aliases removed' "$output_file"; then
    echo "Boot test failed: the bounded MSI-X mapping retained an unsafe alias." >&2
    exit 1
fi

if ! grep -q '^linox: invalid MSI-X programming rejected atomically' "$output_file" ||
    ! grep -q '^linox: kernel-owned MSI-X vector programmed masked' "$output_file" ||
    ! grep -q '^linox: MSI-X function remained disabled' "$output_file"; then
    echo "Boot test failed: masked MSI-X programming was not contained." >&2
    exit 1
fi

if ! grep -q '^linox: kernel-owned virtio MSI-X interrupt delivered' "$output_file" ||
    ! grep -q '^linox: exactly one virtio completion interrupt handled' "$output_file" ||
    ! grep -q '^linox: virtio MSI-X masked and disabled after completion' "$output_file" ||
    ! grep -q '^linox: temporary virtio interrupt gate retired' "$output_file"; then
    echo "Boot test failed: kernel-owned virtio MSI-X delivery was incomplete." >&2
    exit 1
fi

if ! grep -q '^linox: virtio MMIO translation bounds verified' "$output_file"; then
    echo "Boot test failed: virtio MMIO translation was not bounded." >&2
    exit 1
fi

if ! grep -Eq '^linox: virtio block offered features: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: virtio-blk offered no usable features." >&2
    exit 1
fi

if ! grep -q '^linox: virtio block accepted features: 12884902400' "$output_file"; then
    echo "Boot test failed: virtio-blk accepted the wrong feature set." >&2
    exit 1
fi

if ! grep -Eq '^linox: virtio block queues available: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: virtio-blk exposed no queues." >&2
    exit 1
fi

if ! grep -q '^linox: virtio block reset and feature negotiation validated' "$output_file"; then
    echo "Boot test failed: virtio-blk initialization did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: virtio bus mastering remained disabled' "$output_file"; then
    echo "Boot test failed: virtio-blk gained premature DMA authority." >&2
    exit 1
fi

if ! grep -q '^linox: virtio block returned to reset state' "$output_file"; then
    echo "Boot test failed: virtio-blk was not returned to reset state." >&2
    exit 1
fi

if ! grep -q '^linox: bounded persistent volume format validated' "$output_file"; then
    echo "Boot test failed: the persistent volume format was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: interrupted volume commits recovered' "$output_file"; then
    echo "Boot test failed: interrupted volume commits were not recovered." >&2
    exit 1
fi

if ! grep -q '^linox: corrupt persistent volume records rejected' "$output_file"; then
    echo "Boot test failed: corrupt persistent volume records were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: capability derivation and revocation verified' "$output_file"; then
    echo "Boot test failed: capability authority invariants failed." >&2
    exit 1
fi

if ! grep -q '^linox: exhaustive capability attenuation verified' "$output_file"; then
    echo "Boot test failed: exhaustive capability attenuation failed." >&2
    exit 1
fi

if ! grep -q '^linox: cross-domain capability revocation verified' "$output_file"; then
    echo "Boot test failed: cross-domain capability revocation failed." >&2
    exit 1
fi

if ! grep -q '^linox: per-root delegation provenance verified' "$output_file"; then
    echo "Boot test failed: per-root delegation provenance failed." >&2
    exit 1
fi

if ! grep -q '^linox: exhaustive delegated attenuation verified' "$output_file"; then
    echo "Boot test failed: delegated capability attenuation failed." >&2
    exit 1
fi

if ! grep -q '^linox: independent delegation roots verified' "$output_file"; then
    echo "Boot test failed: independent delegation roots were not preserved." >&2
    exit 1
fi

if ! grep -q '^linox: domain lifecycle ancestry verified' "$output_file"; then
    echo "Boot test failed: domain lifecycle ancestry failed." >&2
    exit 1
fi

if ! grep -q '^linox: exhausted generational slots skipped' "$output_file"; then
    echo "Boot test failed: exhausted generational slots were not skipped." >&2
    exit 1
fi

if ! grep -q '^linox: per-service frame quarantines isolated' "$output_file"; then
    echo "Boot test failed: per-service frame quarantines were not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded auxiliary service registry verified' "$output_file"; then
    echo "Boot test failed: auxiliary service registry invariant failed." >&2
    exit 1
fi

if ! grep -q '^linox: service lifecycle roles separated' "$output_file"; then
    echo "Boot test failed: service lifecycle roles were not separated." >&2
    exit 1
fi

if ! grep -q '^linox: service failure policies separated' "$output_file"; then
    echo "Boot test failed: service failure policies were not separated." >&2
    exit 1
fi

if ! grep -q '^linox: domain resource admission policies verified' "$output_file"; then
    echo "Boot test failed: domain resource admission policies were not verified." >&2
    exit 1
fi
if ! grep -q '^linox: auxiliary call epoch renewal constrained' "$output_file"; then
    echo "Boot test failed: auxiliary call epoch renewal was not constrained." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary service quiescence enforced' "$output_file"; then
    echo "Boot test failed: auxiliary service quiescence was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary supervision authority enforced' "$output_file"; then
    echo "Boot test failed: auxiliary supervision authority was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary retirement events sequenced' "$output_file"; then
    echo "Boot test failed: auxiliary retirement events were not sequenced." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary retirement publication atomic' "$output_file"; then
    echo "Boot test failed: auxiliary retirement publication was not atomic." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary stop authority revoked' "$output_file"; then
    echo "Boot test failed: auxiliary stop authority was not revoked." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary retirement overflow summarized' "$output_file"; then
    echo "Boot test failed: auxiliary retirement overflow was not summarized." >&2
    exit 1
fi

if ! grep -q '^linox: stop-only auxiliary faults contained' "$output_file"; then
    echo "Boot test failed: stop-only auxiliary faults were not contained." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary fault authority revoked before publication' "$output_file"; then
    echo "Boot test failed: auxiliary fault authority was not revoked first." >&2
    exit 1
fi

if ! grep -q '^linox: bounded service restart policy verified' "$output_file"; then
    echo "Boot test failed: service restart policy validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: clean service exit publication atomic' "$output_file"; then
    echo "Boot test failed: clean service exit publication was not atomic." >&2
    exit 1
fi

if ! grep -q '^linox: bounded lifecycle event queue verified' "$output_file"; then
    echo "Boot test failed: lifecycle event queue invariants failed." >&2
    exit 1
fi

if ! grep -q '^linox: lifecycle event overflow notification verified' "$output_file"; then
    echo "Boot test failed: lifecycle event overflow notification failed." >&2
    exit 1
fi

if ! grep -q '^linox: persistent control-plane domain sealed' "$output_file"; then
    echo "Boot test failed: persistent control-plane domain state was not sealed." >&2
    exit 1
fi

if ! grep -Eq '^linox: control-plane domain ID: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: control-plane domain identity is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: IPC-only service domain ID: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: isolated service domain identity is invalid." >&2
    exit 1
fi

if ! grep -Eq '^linox: usable memory MiB: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: the kernel did not inventory usable physical memory." >&2
    exit 1
fi

if ! grep -q '^linox: physical frame allocator active' "$output_file"; then
    echo "Boot test failed: physical frame allocation was not verified." >&2
    exit 1
fi

if ! grep -Eq '^linox: reclaimed boot-service frames: [1-9][0-9]*' "$output_file"; then
    echo "Boot test failed: boot-service memory was not reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: atomic frame reservations verified' "$output_file"; then
    echo "Boot test failed: atomic physical-frame reservations failed." >&2
    exit 1
fi

if ! grep -q '^linox: contiguous frame reservations verified' "$output_file"; then
    echo "Boot test failed: contiguous physical-frame reservations failed." >&2
    exit 1
fi

if ! grep -q '^linox: physical frames zeroed before allocation' "$output_file"; then
    echo "Boot test failed: physical-frame zero-on-allocation failed." >&2
    exit 1
fi

if ! grep -q '^linox: tracked frame release ownership verified' "$output_file"; then
    echo "Boot test failed: physical-frame release ownership failed." >&2
    exit 1
fi

if ! grep -q '^linox: stale frame leases rejected' "$output_file"; then
    echo "Boot test failed: stale physical-frame leases were accepted." >&2
    exit 1
fi

if ! grep -q '^linox: per-domain physical frame budgets enforced' "$output_file"; then
    echo "Boot test failed: per-domain physical-frame budgets were not enforced." >&2
    exit 1
fi
if ! grep -q '^linox: failed runtime volume DMA retirement quarantined' "$output_file"; then
    echo "Boot test failed: failed runtime volume DMA retirement was not quarantined." >&2
    exit 1
fi

if ! grep -q '^linox: generation-owned virtio DMA frame allocated' "$output_file"; then
    echo "Boot test failed: virtio DMA memory was not generation-owned." >&2
    exit 1
fi

if ! grep -q '^linox: malformed virtio queue geometry rejected' "$output_file"; then
    echo "Boot test failed: malformed virtio queue geometry was not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: bounded blank virtio sector read completed' "$output_file"; then
    echo "Boot test failed: the bounded virtio sector read did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: virtio read guard bytes preserved' "$output_file"; then
    echo "Boot test failed: the virtio read crossed its data bounds." >&2
    exit 1
fi

if ! grep -q '^linox: virtio used-ring completion validated' "$output_file"; then
    echo "Boot test failed: the virtio used-ring completion was invalid." >&2
    exit 1
fi

if ! grep -q '^linox: deterministic virtio capacity sectors: 2048' "$output_file"; then
    echo "Boot test failed: the deterministic virtio disk geometry changed." >&2
    exit 1
fi

if ! grep -q '^linox: virtio bus mastering revoked after read' "$output_file"; then
    echo "Boot test failed: virtio bus mastering remained enabled after the read." >&2
    exit 1
fi

if ! grep -q '^linox: virtio DMA frame scrubbed and released' "$output_file"; then
    echo "Boot test failed: the virtio DMA lease was not retired." >&2
    exit 1
fi

if ! grep -q '^linox: read-only virtio MMIO grant exercised in ring 3' "$output_file"; then
    echo "Boot test failed: the isolated service did not exercise its virtio MMIO grant." >&2
    exit 1
fi

if ! grep -q '^linox: denied virtio MMIO write contained and revoked' "$output_file"; then
    echo "Boot test failed: a read-only virtio MMIO grant permitted mutation." >&2
    exit 1
fi

if ! grep -q '^linox: observed virtio device remained reset and DMA-disabled' "$output_file"; then
    echo "Boot test failed: the virtio observer changed device or DMA state." >&2
    exit 1
fi

if ! grep -q '^linox: APIC device-wait timeout delivered' "$output_file"; then
    echo "Boot test failed: the device-wait timeout interrupt did not fire." >&2
    exit 1
fi

if ! grep -q '^linox: native volume write-only grant exercised in ring 3' "$output_file"; then
    echo "Boot test failed: the native volume service did not exercise its write-only grant." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio feature negotiation completed' "$output_file"; then
    echo "Boot test failed: the isolated control service did not negotiate virtio features." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio queue geometry configured with owned DMA' "$output_file"; then
    echo "Boot test failed: isolated queue geometry was not configured safely." >&2
    exit 1
fi

if ! grep -q '^linox: isolated DMA lease initialized in ring 3' "$output_file" ||
    ! grep -q '^linox: retired DMA lease scrubbed and released' "$output_file"; then
    echo "Boot test failed: the isolated DMA lease lifecycle was not completed safely." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio queue bound to inactive DMA lease' "$output_file"; then
    echo "Boot test failed: the inert virtio queue was not bound to its exact DMA lease." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio queue activated before publication' "$output_file"; then
    echo "Boot test failed: the isolated queue was not activated before publication." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio read descriptors prepared in ring 3' "$output_file"; then
    echo "Boot test failed: ring 3 did not prepare the bounded virtio read descriptors." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio available entry published in ring 3' "$output_file"; then
    echo "Boot test failed: ring 3 did not publish the available entry." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio queue notified from ring 3' "$output_file"; then
    echo "Boot test failed: ring 3 did not notify the bounded virtio queue." >&2
    exit 1
fi

if ! grep -q '^linox: stale isolated virtio wait generation rejected' "$output_file"; then
    echo "Boot test failed: a stale isolated virtio wait was accepted." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio service blocked on MSI-X' "$output_file" ||
    ! grep -q '^linox: kernel-owned MSI-X woke isolated virtio service' "$output_file"; then
    echo "Boot test failed: MSI-X did not block and wake the isolated virtio service." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio timeout cancelled after MSI-X' "$output_file"; then
    echo "Boot test failed: successful MSI-X did not cancel its device timeout." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio live timeout retried successfully' "$output_file"; then
    echo "Boot test failed: a timed-out isolated virtio request was not retried safely." >&2
    exit 1
fi

if ! grep -q '^linox: duplicate isolated virtio wait rejected' "$output_file"; then
    echo "Boot test failed: a duplicate isolated virtio wait was accepted." >&2
    exit 1
fi

if ! grep -q '^linox: isolated volume slots scanned in ring 3' "$output_file"; then
    echo "Boot test failed: ring 3 did not scan the persistent volume slots." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio request generation advanced and reused' "$output_file"; then
    echo "Boot test failed: the isolated virtio request generation was not reused." >&2
    exit 1
fi

if ! grep -q '^linox: isolated volume prepare flush commit sequence completed' "$output_file"; then
    echo "Boot test failed: the isolated persistent-volume transaction did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: virtio DMA validation followed hardware quiescence' "$output_file"; then
    echo "Boot test failed: virtio DMA state was not validated after hardware quiescence." >&2
    exit 1
fi

if ! grep -q '^linox: clean exit quiesced device before DMA release' "$output_file"; then
    echo "Boot test failed: device teardown did not precede DMA lease release." >&2
    exit 1
fi

if ! grep -q '^linox: completed native volume service authority revoked' "$output_file"; then
    echo "Boot test failed: the completed native volume service retained authority." >&2
    exit 1
fi

if ! grep -q '^linox: native volume device quiesced before release' "$output_file"; then
    echo "Boot test failed: the completed native volume service left its device active." >&2
    exit 1
fi

if ! grep -q '^linox: isolated virtio MSI-X route retired before DMA release' "$output_file"; then
    echo "Boot test failed: the isolated MSI-X route survived DMA release." >&2
    exit 1
fi

if ! grep -q '^linox: isolated address space active' "$output_file"; then
    echo "Boot test failed: isolated address-space activation failed." >&2
    exit 1
fi

if ! grep -q '^linox: control-plane W\^X mappings active' "$output_file"; then
    echo "Boot test failed: control-plane W^X mappings are not active." >&2
    exit 1
fi

if ! grep -q '^linox: address-space frames use higher-half direct map' "$output_file"; then
    echo "Boot test failed: address-space frame access did not use the direct map." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary address-space transaction verified' "$output_file"; then
    echo "Boot test failed: auxiliary address-space transaction failed." >&2
    exit 1
fi

if ! grep -q '^linox: concurrent auxiliary address spaces isolated' "$output_file"; then
    echo "Boot test failed: concurrent auxiliary address spaces were not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary scheduler admission resource-gated' "$output_file"; then
    echo "Boot test failed: auxiliary scheduler admission was not resource-gated." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary address-space ownership retained' "$output_file"; then
    echo "Boot test failed: auxiliary address-space ownership was not retained." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary runtime teardown path connected' "$output_file"; then
    echo "Boot test failed: auxiliary runtime teardown was not connected." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary teardown restores kernel page tables' "$output_file"; then
    echo "Boot test failed: auxiliary teardown did not restore kernel page tables." >&2
    exit 1
fi

if ! grep -q '^linox: bounded executable container accepted' "$output_file"; then
    echo "Boot test failed: the executable container was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: authenticated executable entry points accepted' "$output_file"; then
    echo "Boot test failed: authenticated executable entry points were not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: malformed executable containers rejected' "$output_file"; then
    echo "Boot test failed: malformed executable containers were accepted." >&2
    exit 1
fi

if ! grep -q '^linox: deterministic initramfs image accepted' "$output_file"; then
    echo "Boot test failed: the deterministic initramfs image was not accepted." >&2
    exit 1
fi
if ! grep -q '^linox: measured isolated volume service discovered' "$output_file"; then
    echo "Boot test failed: the measured isolated volume service was not discovered." >&2
    exit 1
fi
if ! grep -q '^linox: bounded native PIE load plan accepted' "$output_file"; then
    echo "Boot test failed: the bounded native PIE load plan was not accepted." >&2
    exit 1
fi
if ! grep -q '^linox: relative-only service relocations accepted' "$output_file"; then
    echo "Boot test failed: the native service relocation contract was not accepted." >&2
    exit 1
fi
if ! grep -q '^linox: native service segments materialized in owned frames' "$output_file"; then
    echo "Boot test failed: native service segments were not materialized." >&2
    exit 1
fi
if ! grep -q '^linox: native service relative relocations applied' "$output_file"; then
    echo "Boot test failed: native service relocations were not applied." >&2
    exit 1
fi
if ! grep -q '^linox: native service W\^X address space verified' "$output_file"; then
    echo "Boot test failed: native service W^X mappings were not verified." >&2
    exit 1
fi
if ! grep -q '^linox: native service guard pages verified' "$output_file"; then
    echo "Boot test failed: native service guard pages were not verified." >&2
    exit 1
fi

if ! grep -q '^linox: bounded newc archive paths validated' "$output_file"; then
    echo "Boot test failed: bounded initramfs paths were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: executable init entry discovered' "$output_file"; then
    echo "Boot test failed: the initramfs executable init entry was not found." >&2
    exit 1
fi

if ! grep -q '^linox: malformed initramfs archives rejected' "$output_file"; then
    echo "Boot test failed: malformed initramfs archives were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: measured root image copied into owned memory' "$output_file"; then
    echo "Boot test failed: the measured root image was not materialized." >&2
    exit 1
fi

if ! grep -q '^linox: owned root image remained source-independent' "$output_file"; then
    echo "Boot test failed: the owned root image alias contract failed." >&2
    exit 1
fi

if ! grep -q '^linox: owned root frames scrubbed and released' "$output_file"; then
    echo "Boot test failed: the owned root frames were not reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: bounded read-only root index constructed' "$output_file"; then
    echo "Boot test failed: the read-only root index was not constructed." >&2
    exit 1
fi

if ! grep -q '^linox: root lookups resolved only owned image bytes' "$output_file"; then
    echo "Boot test failed: root lookups escaped owned image bytes." >&2
    exit 1
fi

if ! grep -q '^linox: invalid root lookup paths denied' "$output_file"; then
    echo "Boot test failed: invalid root lookup paths were accepted." >&2
    exit 1
fi

if ! grep -q '^linox: indexed root frames scrubbed and released' "$output_file"; then
    echo "Boot test failed: the indexed root frames were not reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: measured root published in kernel-owned memory' "$output_file"; then
    echo "Boot test failed: the measured root was not published." >&2
    exit 1
fi

if ! grep -q '^linox: pinned minimal system profile accepted' "$output_file"; then
    echo "Boot test failed: the minimal system profile was not accepted." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux process lifecycle contract validated' "$output_file"; then
    echo "Boot test failed: the bounded Linux process lifecycle contract was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux stopped and continued child wait states validated' "$output_file"; then
    echo "Boot test failed: stopped/continued child wait reporting was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: generation-bound Linux process roots validated' "$output_file"; then
    echo "Boot test failed: generation-bound Linux process roots were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux process resource bundles validated' "$output_file"; then
    echo "Boot test failed: bounded Linux process resource bundles were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process mapping inventory validated' "$output_file"; then
    echo "Boot test failed: Linux process mappings were not matched to their hierarchy." >&2
    exit 1
fi

if ! grep -q '^linox: transactional Linux child publication validated' "$output_file"; then
    echo "Boot test failed: transactional Linux child publication was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: cloned Linux child resources published atomically' "$output_file"; then
    echo "Boot test failed: cloned Linux child resources were not published atomically." >&2
    exit 1
fi

if ! grep -q '^linox: address-space-bound Linux process contexts validated' "$output_file"; then
    echo "Boot test failed: Linux process contexts were not bound to their mappings." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fork child return context derived' "$output_file"; then
    echo "Boot test failed: the Linux fork child return context was not derived." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process contexts staged on native scheduler' "$output_file"; then
    echo "Boot test failed: Linux process contexts were not staged on the native scheduler." >&2
    exit 1
fi

if ! grep -q '^linox: scheduled Linux process roots matched ownership' "$output_file"; then
    echo "Boot test failed: scheduled Linux roots did not match process ownership." >&2
    exit 1
fi

if ! grep -q '^linox: stale Linux process scheduler bindings rejected' "$output_file"; then
    echo "Boot test failed: stale Linux scheduler bindings were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process roots inherited kernel mappings' "$output_file"; then
    echo "Boot test failed: Linux process roots did not inherit kernel mappings." >&2
    exit 1
fi

if ! grep -q '^linox: scheduled Linux child CR3 activated and restored' "$output_file"; then
    echo "Boot test failed: the scheduled Linux child CR3 was not activated and restored." >&2
    exit 1
fi

if ! grep -q '^linox: scheduled Linux child returned from ring 3' "$output_file"; then
    echo "Boot test failed: the scheduled Linux child did not return from ring 3." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fork child RAX zero executed' "$output_file"; then
    echo "Boot test failed: the Linux fork child did not execute with RAX zero." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process child FS isolation executed' "$output_file"; then
    echo "Boot test failed: the Linux process child's FS isolation was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: complete Linux process register frame executed' "$output_file"; then
    echo "Boot test failed: the complete Linux process register frame was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process child exit captured from ring 3' "$output_file"; then
    echo "Boot test failed: the Linux process child exit was not captured from ring 3." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process child exit drove zombie wait status' "$output_file"; then
    echo "Boot test failed: the ring-3 child exit did not drive zombie wait status." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux private page copy validated' "$output_file"; then
    echo "Boot test failed: bounded Linux private page copying was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux child hierarchy and copy-on-write isolation validated' "$output_file"; then
    echo "Boot test failed: Linux fork copy-on-write isolation was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux process address-space snapshot validated' "$output_file"; then
    echo "Boot test failed: the live Linux process address space was not snapshotted." >&2
    exit 1
fi

if ! grep -q '^linox: incomplete Linux process snapshots rejected' "$output_file"; then
    echo "Boot test failed: incomplete Linux process snapshots were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux PID 1 context admitted to process model' "$output_file"; then
    echo "Boot test failed: live Linux PID 1 was not admitted to the process model." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux process registry persisted across syscalls' "$output_file"; then
    echo "Boot test failed: the live Linux process registry did not persist across syscalls." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux child address space cloned transactionally' "$output_file"; then
    echo "Boot test failed: the live Linux child address space was not cloned transactionally." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux cloned child executed in ring 3' "$output_file"; then
    echo "Boot test failed: the live Linux cloned child did not execute in ring 3." >&2
    exit 1
fi

if ! grep -q '^linox: measured minimal system init planned' "$output_file"; then
    echo "Boot test failed: the minimal system init was not planned." >&2
    exit 1
fi

if [[ "$(grep -c '^LINOX_SYSTEM_INIT_V0' "$output_file")" -ne 1 ]] ||
    [[ "$(grep -c '^SUPERVISOR_SHUTDOWN' "$output_file")" -ne 1 ]] ||
    ! grep -q '^linox: Linux PID 1 fork and wait4 lifecycle completed' "$output_file" ||
    ! grep -q '^linox: measured minimal system init executed as PID 1' "$output_file" ||
    ! grep -q '^linox: persistent Linux PID 1 supervisor lifecycle validated' "$output_file" ||
    ! grep -q '^linox: minimal system init exited cleanly' "$output_file"; then
    echo "Boot test failed: the measured minimal system init was not supervised through shutdown." >&2
    exit 1
fi

if [[ "$(grep -c '^SIGNAL_READY' "$output_file")" -ne 1 ]] ||
    ! grep -q '^linox: bounded Linux standard signal lifecycle validated' "$output_file"; then
    echo "Boot test failed: the bounded Linux standard signal lifecycle was not validated." >&2
    exit 1
fi

if [[ "$(grep -c '^FUTEX_READY' "$output_file")" -ne 1 ]] ||
    ! grep -q '^linox: bounded Linux private futex lifecycle validated' "$output_file" ||
    ! grep -q '^linox: Linux clear-child-TID exit action validated' "$output_file" ||
    ! grep -q '^linox: Linux scheduler-backed timed futex wait validated' "$output_file"; then
    echo "Boot test failed: the bounded Linux private futex lifecycle was not validated." >&2
    exit 1
fi

if ! grep -q $'^Name:\tinit$' "$output_file" ||
    ! grep -q $'^State:\tR (running)$' "$output_file" ||
    ! grep -q $'^Pid:\t1$' "$output_file" ||
    ! grep -q $'^PPid:\t0$' "$output_file" ||
    ! grep -q '^linox: lifecycle-aware bounded procfs validated' "$output_file" ||
    ! grep -q '^PROCFS_READY$' "$output_file"; then
    echo "Boot test failed: the lifecycle-aware bounded procfs view was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: generation-safe Linux mount namespace installed' "$output_file" ||
    ! grep -q '^linox: immutable measured root mounted read-only' "$output_file" ||
    ! grep -q '^1 0 0:1 / / ro,nosuid,nodev - linox-root rootfs ro$' "$output_file"; then
    echo "Boot test failed: the bounded Linux root mount namespace was not observed." >&2
    exit 1
fi

if ! grep -q '^linox: generation-safe Linux user namespace installed' "$output_file" ||
    ! grep -q '^linox: Linux domain root mapped outside native authority' "$output_file" ||
    ! grep -q '^linox: Linux fork inherited user namespace' "$output_file" ||
    ! grep -q '^USERNS_READY$' "$output_file"; then
    echo "Boot test failed: the bounded Linux user namespace was not observed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux privilege policy sealed fail-closed' "$output_file" ||
    ! grep -q '^PRIVILEGE_BOUNDARY_READY$' "$output_file"; then
    echo "Boot test failed: Linux root crossed or bypassed the bounded privilege policy." >&2
    exit 1
fi

if [[ "$(grep -c '^DEVFS_READY' "$output_file")" -ne 1 ]] ||
    ! grep -q '^linox: bounded Linux devfs profile validated' "$output_file"; then
    echo "Boot test failed: the bounded Linux device namespace was not validated." >&2
    exit 1
fi

if [[ "$(grep -c '^TMPFS_READY' "$output_file")" -ne 1 ]] ||
    ! grep -q '^linox: quota-bound page-backed RAM store installed' "$output_file" ||
    ! grep -q '^linox: generation-safe Linux tmpfs view mounted at /tmp' "$output_file" ||
    ! grep -q '^linox: transactional page-backed tmpfs lifecycle validated' "$output_file"; then
    echo "Boot test failed: the transactional page-backed tmpfs lifecycle was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux interpreted exec graph planned' "$output_file" ||
    ! grep -q '^linox: measured-root Linux graph substitution rejected' "$output_file"; then
    echo "Boot test failed: the measured-root interpreted graph was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: multiple measured Linux exec targets planned' "$output_file"; then
    echo "Boot test failed: the measured Linux exec targets were not planned." >&2
    exit 1
fi

if ! grep -q '^linox: read-only root capability enforced' "$output_file"; then
    echo "Boot test failed: the root capability boundary was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: ring-3 root metadata lookup completed' "$output_file"; then
    echo "Boot test failed: ring-3 root lookup did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: ring-3 root file read completed' "$output_file"; then
    echo "Boot test failed: ring-3 root read did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: ring-3 root directory enumeration completed' "$output_file"; then
    echo "Boot test failed: ring-3 root enumeration did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: non-directory enumeration denied' "$output_file"; then
    echo "Boot test failed: a regular file was enumerated as a directory." >&2
    exit 1
fi

if ! grep -q '^linox: invalid root userspace requests denied' "$output_file"; then
    echo "Boot test failed: invalid root requests were accepted." >&2
    exit 1
fi

if ! grep -q '^linox: published root remains kernel-owned' "$output_file"; then
    echo "Boot test failed: published root ownership was lost." >&2
    exit 1
fi

if ! grep -q '^linox: non-executable Linux GNU stack enforced' "$output_file"; then
    echo "Boot test failed: Linux GNU stack policy was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux ELF metadata headers validated' "$output_file"; then
    echo "Boot test failed: bounded Linux ELF metadata headers were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux interpreter metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux interpreter metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux ELF verifier stack usage validated' "$output_file"; then
    echo "Boot test failed: bounded Linux ELF verifier stack usage was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux GNU RELRO metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux GNU RELRO metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: three-load Linux ELF runtime mapping verified' "$output_file"; then
    echo "Boot test failed: three-load Linux ELF runtime mapping was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: toolchain-linked static Linux ELF executed' "$output_file"; then
    echo "Boot test failed: toolchain-linked static Linux ELF was not executed." >&2
    exit 1
fi

if [[ "$(grep -c '^linox: measured Linux exec image replaced atomically' "$output_file")" -ne 5 ]]; then
    echo "Boot test failed: measured Linux exec replacement did not complete five times." >&2
    exit 1
fi

if [[ "$(grep -c '^SIGNAL!' "$output_file")" -ne 1 ]] ||
    [[ "$(grep -c '^SECOND!' "$output_file")" -ne 1 ]] ||
    [[ "$(grep -c '^DYNEXEC' "$output_file")" -ne 1 ]] ||
    [[ "$(grep -c '^ABI_OK!' "$output_file")" -ne 1 ]]; then
    echo "Boot test failed: all measured replacement Linux images did not execute." >&2
    exit 1
fi

for marker in \
    'measured-root interpreted Linux exec admitted' \
    'interpreted Linux exec image committed' \
    'measured-root interpreted Linux exec committed' \
    'interpreted Linux exec graph remapped' \
    'bounded Linux cross-area copy-in validated' \
    'complete interpreted Linux graph retired at exec' \
    'interpreted Linux exec stack replaced atomically' \
    'old interpreted Linux stack lease retired at exec' \
    'replacement Linux stack lease reclaimed' \
    'static Linux exec stack replaced atomically' \
    'old static Linux stack lease retired at exec' \
    'replacement static Linux stack lease reclaimed' \
    'interpreted Linux exec heap replaced atomically' \
    'old interpreted Linux heap lease retired at exec' \
    'replacement Linux heap lease reclaimed' \
    'static Linux exec heap replaced atomically' \
    'old static Linux heap lease retired at exec' \
    'replacement static Linux heap lease reclaimed' \
    'Linux exec process break reset' \
    'interpreted Linux TLS state rematerialized' \
    'interpreted Linux TLS leases replaced atomically' \
    'old interpreted Linux TLS leases retired at exec' \
    'replacement Linux TLS leases reclaimed' \
    'interpreted Linux sibling stack replaced atomically' \
    'old interpreted Linux sibling stack lease retired at exec' \
    'replacement Linux sibling stack lease reclaimed' \
    'interpreted Linux mmap registry empty across exec' \
    'static Linux mmap registry empty across exec' \
    'interpreted Linux page-table hierarchy replaced atomically' \
    'old interpreted Linux page-table leases retired at exec' \
    'replacement Linux page-table leases reclaimed' \
    'static Linux page-table hierarchy replaced atomically' \
    'old static Linux page-table leases retired at exec' \
    'replacement static Linux page-table leases reclaimed' \
    'static Linux exec auxiliary vector rebuilt' \
    'interpreted Linux exec auxiliary vector rebuilt' \
    'canonical interpreted Linux executable identity validated' \
    'interpreted Linux exec vectors generalized'; do
    if ! grep -q "^linox: ${marker}" "$output_file"; then
        echo "Boot test failed: ${marker}." >&2
        exit 1
    fi
done

for marker in \
    'bounded Linux exec rejection preserved live image' \
    'Linux exec mapping rollback restored active image' \
    'Linux exec argv and environment delivered' \
    'bounded Linux exec vectors validated' \
    'old Linux image pages removed after exec' \
    'replaced Linux image retired cleanly' \
    'Linux close-on-exec descriptors transitioned' \
    'Linux exec signal state transitioned' \
    'Linux exec process identity installed' \
    'Linux executable link followed exec identity' \
    'measured-root Linux exec selection validated' \
    'measured-dirfd Linux execveat validated' \
    'measured-fd Linux empty-path exec validated' \
    'measured Linux exec selection is profile-driven' \
    'independent measured Linux exec layouts validated' \
    'runtime-selected Linux exec plans committed' \
    'variable-page Linux exec images committed' \
    'Linux active image ownership transitioned' \
    'generation-bound Linux image ownership verified' \
    'generation-bound Linux page-table hierarchy verified' \
    'Linux RELRO ownership permissions synchronized' \
    'stale Linux image retirement rejected' \
    'old Linux image leases retired at exec commit' \
    'Linux image lease double release rejected' \
    'Linux replacement frames allocated on demand' \
    'Linux replacement frame generations reclaimed'; do
    if ! grep -q "^linox: $marker" "$output_file"; then
        echo "Boot test failed: missing exec proof: $marker." >&2
        exit 1
    fi
done

if ! grep -q '^linox: bounded Linux ET_DYN load bias validated' "$output_file"; then
    echo "Boot test failed: bounded Linux ET_DYN load bias was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux interpreter resolution plan validated' "$output_file"; then
    echo "Boot test failed: bounded Linux interpreter resolution planning was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: separate-header Linux interpreter plan validated' "$output_file"; then
    echo "Boot test failed: separate-header Linux interpreter planning was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux dynamic startup metadata validated' "$output_file"; then
    echo "Boot test failed: Linux dynamic startup metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux auxiliary vector encoding validated' "$output_file"; then
    echo "Boot test failed: Linux auxiliary vector encoding was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux page-aliasing ELF segments rejected' "$output_file"; then
    echo "Boot test failed: page-aliasing Linux ELF segments were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: Linux ELF entry metadata overlap rejected' "$output_file"; then
    echo "Boot test failed: Linux ELF entry overlap with metadata was not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux dependency list validated' "$output_file"; then
    echo "Boot test failed: bounded Linux dependency-list metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux dependency authority graph validated' "$output_file"; then
    echo "Boot test failed: bounded Linux dependency authority graph was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux dependency TLS metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux dependency TLS metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux TPOFF64 relocation metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux TPOFF64 relocation metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux static TLS layout plan validated' "$output_file"; then
    echo "Boot test failed: bounded Linux static TLS layout planning was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: reusable Linux TLS page materialization validated' "$output_file"; then
    echo "Boot test failed: reusable Linux TLS page materialization was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux TLS execution context validated' "$output_file"; then
    echo "Boot test failed: bounded Linux TLS execution context was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux TLS template metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux TLS template metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: combined Linux static TLS materialized' "$output_file"; then
    echo "Boot test failed: combined Linux static TLS was not materialized." >&2
    exit 1
fi

if ! grep -q '^linox: ordered Linux dependency TLS layout materialized' "$output_file"; then
    echo "Boot test failed: ordered Linux dependency TLS was not materialized." >&2
    exit 1
fi

if ! grep -q '^linox: Linux TLS active before initializers' "$output_file"; then
    echo "Boot test failed: Linux TLS was not active before initializers." >&2
    exit 1
fi

if ! grep -q '^linox: Linux dependency TLS active before constructors' "$output_file"; then
    echo "Boot test failed: Linux dependency TLS was not active before constructors." >&2
    exit 1
fi

if ! grep -q '^linox: toolchain-driven Linux dependency TLS relocation applied' "$output_file"; then
    echo "Boot test failed: the toolchain-driven Linux dependency TLS relocation was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: toolchain-driven Linux auxiliary TLS relocation applied' "$output_file"; then
    echo "Boot test failed: the toolchain-driven Linux auxiliary TLS relocation was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: linker-resolved Linux TLS symbols executed' "$output_file"; then
    echo "Boot test failed: linker-resolved Linux TLS symbols were not executed." >&2
    exit 1
fi

if ! grep -q '^linox: interpreted Linux TLS state rematerialized' "$output_file"; then
    echo "Boot test failed: interpreted exec did not rematerialize Linux TLS state." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux TLS syscall copies validated' "$output_file"; then
    echo "Boot test failed: bounded Linux TLS syscall copies were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: independent Linux sibling TLS materialized' "$output_file"; then
    echo "Boot test failed: an independent sibling Linux TLS instance was not materialized." >&2
    exit 1
fi

if ! grep -q '^linox: non-current Linux TLS syscall access denied' "$output_file"; then
    echo "Boot test failed: non-current Linux TLS was admitted to syscall copies." >&2
    exit 1
fi

if ! grep -q '^linox: Linux TLS execution context switched and restored' "$output_file"; then
    echo "Boot test failed: Linux TLS execution context was not switched and restored." >&2
    exit 1
fi

if ! grep -q '^linox: guarded Linux sibling stack materialized' "$output_file"; then
    echo "Boot test failed: a guarded sibling Linux stack was not materialized." >&2
    exit 1
fi

if ! grep -q '^linox: non-current Linux stack syscall access denied' "$output_file"; then
    echo "Boot test failed: the sibling Linux stack was admitted to current-thread syscall copies." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux clone contract validated' "$output_file"; then
    echo "Boot test failed: the bounded Linux clone contract was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux child return context constructed' "$output_file"; then
    echo "Boot test failed: the Linux child return context was not constructed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux child context cleared on slot reuse' "$output_file"; then
    echo "Boot test failed: the Linux child context survived slot reuse." >&2
    exit 1
fi

if ! grep -q '^linox: failed Linux clone publication rolled back' "$output_file"; then
    echo "Boot test failed: failed Linux clone publication did not roll back." >&2
    exit 1
fi

if ! grep -q '^linox: Linux parent and child TID publication validated' "$output_file"; then
    echo "Boot test failed: Linux parent and child TID publication was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: unpublished Linux child retired cleanly' "$output_file"; then
    echo "Boot test failed: the unpublished Linux child did not retire cleanly." >&2
    exit 1
fi

if ! grep -q '^linox: full Linux syscall register frame preserved' "$output_file"; then
    echo "Boot test failed: the full Linux syscall register frame was not preserved." >&2
    exit 1
fi

if ! grep -q '^linox: typed Linux syscall frame validated' "$output_file"; then
    echo "Boot test failed: the typed Linux syscall frame was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: complete Linux child context persisted' "$output_file"; then
    echo "Boot test failed: the complete Linux child context was not persisted." >&2
    exit 1
fi

if ! grep -q '^linox: stale Linux return contexts rejected' "$output_file"; then
    echo "Boot test failed: a stale or empty Linux return context was accepted." >&2
    exit 1
fi

if ! grep -q '^linox: Linux child return frame installed atomically' "$output_file"; then
    echo "Boot test failed: the Linux child return frame was not installed atomically." >&2
    exit 1
fi

if ! grep -q '^linox: Linux return ownership restored to parent' "$output_file"; then
    echo "Boot test failed: Linux return ownership was not restored to the parent." >&2
    exit 1
fi

if ! grep -q '^linox: stale Linux return installation left state unchanged' "$output_file"; then
    echo "Boot test failed: stale Linux return installation changed state." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux syscall return frame round-trip validated' "$output_file"; then
    echo "Boot test failed: the live Linux syscall return frame did not round-trip." >&2
    exit 1
fi

if ! grep -q '^linox: guarded Linux child executed in ring 3' "$output_file"; then
    echo "Boot test failed: the guarded Linux child did not execute in ring 3." >&2
    exit 1
fi

if ! grep -q '^linox: Linux child exit restored suspended parent' "$output_file"; then
    echo "Boot test failed: Linux child exit did not restore the suspended parent." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux clone syscall dispatched' "$output_file"; then
    echo "Boot test failed: the bounded Linux clone syscall was not dispatched." >&2
    exit 1
fi

if ! grep -q '^linox: sequential Linux clone slot reuse validated' "$output_file"; then
    echo "Boot test failed: sequential Linux clone slot reuse was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: reused Linux child stack began scrubbed' "$output_file"; then
    echo "Boot test failed: a reused Linux child stack was not scrubbed." >&2
    exit 1
fi

if ! grep -q '^linox: monotonic Linux clone TIDs validated' "$output_file"; then
    echo "Boot test failed: sequential Linux clone TIDs were not monotonic." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux child TIDs matched published words' "$output_file"; then
    echo "Boot test failed: live Linux child TIDs did not match their published words." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux child FS self pointers validated' "$output_file"; then
    echo "Boot test failed: live Linux children did not observe their own FS self pointers." >&2
    exit 1
fi

if ! grep -q '^linox: bidirectional Linux sched_yield switching validated' "$output_file"; then
    echo "Boot test failed: Linux sched_yield did not switch in both directions." >&2
    exit 1
fi

if ! grep -q '^linox: occupied Linux clone capacity rejected live' "$output_file"; then
    echo "Boot test failed: occupied Linux clone capacity was not rejected live." >&2
    exit 1
fi

if ! grep -q '^linox: live Linux clone failures rolled back transactionally' "$output_file"; then
    echo "Boot test failed: live Linux clone failures did not roll back transactionally." >&2
    exit 1
fi

if ! grep -q '^linox: Linux clone return values validated' "$output_file"; then
    echo "Boot test failed: Linux clone return values were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux clone child TID cleared on exit' "$output_file"; then
    echo "Boot test failed: the Linux clone child TID was not cleared on exit." >&2
    exit 1
fi

if ! grep -q '^linox: Linux clone parent TID preserved on child exit' "$output_file"; then
    echo "Boot test failed: the Linux clone parent TID changed on child exit." >&2
    exit 1
fi

if ! grep -q '^linox: Linux parent and child futex waits blocked' "$output_file"; then
    echo "Boot test failed: Linux parent and child futex waits did not block." >&2
    exit 1
fi

if ! grep -q '^linox: explicit Linux futex wake restored child' "$output_file"; then
    echo "Boot test failed: explicit Linux futex wake did not restore the child." >&2
    exit 1
fi

if ! grep -q '^linox: Linux clear-child-TID wake restored parent' "$output_file"; then
    echo "Boot test failed: Linux clear-child-TID did not wake and restore the parent." >&2
    exit 1
fi

if ! grep -q '^linox: Linux futex waiter state reclaimed' "$output_file"; then
    echo "Boot test failed: Linux futex waiter state was not reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: per-thread Linux syscall stacks validated' "$output_file"; then
    echo "Boot test failed: per-thread Linux syscall stacks were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux TID lifecycle validated' "$output_file"; then
    echo "Boot test failed: bounded Linux TID lifecycle was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: stale Linux thread handles rejected' "$output_file"; then
    echo "Boot test failed: stale Linux thread handles were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: Linux per-thread exit state isolated' "$output_file"; then
    echo "Boot test failed: Linux per-thread exit state was not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux thread exit registrations cleared' "$output_file"; then
    echo "Boot test failed: Linux thread exit registrations were not cleared." >&2
    exit 1
fi

if ! grep -q '^linox: Linux thread table reclaimed on exit' "$output_file"; then
    echo "Boot test failed: Linux thread table was not reclaimed on exit." >&2
    exit 1
fi

if ! grep -q '^linox: sibling Linux TLS frame scrubbed and released' "$output_file"; then
    echo "Boot test failed: the sibling Linux TLS frame was not scrubbed and released." >&2
    exit 1
fi

if ! grep -q '^linox: Linux sibling stack scrubbed and released' "$output_file"; then
    echo "Boot test failed: the sibling Linux stack was not scrubbed and released." >&2
    exit 1
fi

if ! grep -q '^linox: retired Linux thread stacks scrubbed' "$output_file"; then
    echo "Boot test failed: retired Linux thread stacks were not scrubbed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux TLS frame scrubbed and released' "$output_file"; then
    echo "Boot test failed: the Linux TLS frame was not scrubbed and released." >&2
    exit 1
fi

if ! grep -q '^linox: five-page Linux executable mapping validated' "$output_file"; then
    echo "Boot test failed: five-page Linux executable mapping was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded multi-page Linux ELF plan verified' "$output_file"; then
    echo "Boot test failed: bounded multi-page Linux ELF planning was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: measured Linux interpreter bytes enforced' "$output_file"; then
    echo "Boot test failed: measured Linux interpreter bytes were not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: authenticated Linux dependency bytes enforced' "$output_file"; then
    echo "Boot test failed: authenticated Linux dependency bytes were not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: Linux dependency SONAME identity bound' "$output_file"; then
    echo "Boot test failed: Linux dependency SONAME identity was not bound." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux relative relocation metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux relative relocation metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux symbol relocation metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux symbol relocation metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux PLT relocation metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux PLT relocation metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: split Linux PLT relocation table validated' "$output_file"; then
    echo "Boot test failed: the split Linux PLT relocation table was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux SysV hash metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux SysV hash metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux GNU hash metadata validated' "$output_file"; then
    echo "Boot test failed: bounded Linux GNU hash metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: unresolved dynamic Linux static entry denied' "$output_file"; then
    echo "Boot test failed: unresolved dynamic Linux static entry was not denied." >&2
    exit 1
fi

if ! grep -q '^linox: Linux ELF headers mapped in executable segment' "$output_file"; then
    echo "Boot test failed: Linux ELF headers were not mapped." >&2
    exit 1
fi

if ! grep -q '^linox: bounded multi-page Linux ELF mapping verified' "$output_file"; then
    echo "Boot test failed: bounded multi-page Linux ELF mapping was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: bounded interpreted Linux ELF mapping verified' "$output_file"; then
    echo "Boot test failed: bounded interpreted Linux ELF mapping was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: toolchain-linked Linux interpreter executed' "$output_file"; then
    echo "Boot test failed: the toolchain-linked Linux interpreter was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: two-page Linux interpreter RX mapping verified' "$output_file"; then
    echo "Boot test failed: the two-page Linux interpreter RX mapping was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux interpreter metadata discovered' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not discover its metadata." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux runtime files discovered' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not discover runtime files." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux PT_LOAD mappings derived' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not derive PT_LOAD mappings." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux startup metadata consumed' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not consume startup metadata." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux main segments mapped' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not map main segments." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux DT_NEEDED path resolved' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not resolve DT_NEEDED." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux dependency segments mapped' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not map dependency segments." >&2
    exit 1
fi

if ! grep -q '^linox: complete interpreted Linux image ownership tracked' "$output_file"; then
    echo "Boot test failed: interpreted image mapping ownership was incomplete." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux dependency bias selected' "$output_file"; then
    echo "Boot test failed: the userspace Linux interpreter did not select the dependency bias." >&2
    exit 1
fi

if ! grep -q '^linox: Linux dependency frames allocated on demand' "$output_file"; then
    echo "Boot test failed: dependency mapping frames were not demand-allocated and reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux executable frames allocated on demand' "$output_file"; then
    echo "Boot test failed: executable mapping frames were not demand-allocated and reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux dependency page contracts applied' "$output_file"; then
    echo "Boot test failed: the bounded dependency page-contract table was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux dependency mapping slots isolated' "$output_file"; then
    echo "Boot test failed: bounded Linux dependency mapping slots were not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux auxiliary dependency mapped' "$output_file"; then
    echo "Boot test failed: the auxiliary Linux dependency was not mapped by userspace." >&2
    exit 1
fi

if ! grep -q '^linox: Linux read-only dependency segment mapped' "$output_file"; then
    echo "Boot test failed: the read-only dependency segment was not mapped." >&2
    exit 1
fi

if ! grep -q '^linox: toolchain-linked Linux PIE and shared object executed' "$output_file"; then
    echo "Boot test failed: the toolchain-linked Linux PIE/shared-object pair was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: linker-emitted Linux dynamic tags validated' "$output_file"; then
    echo "Boot test failed: linker-emitted Linux dynamic tags were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: separate-header interpreted Linux mapping verified' "$output_file"; then
    echo "Boot test failed: separate-header interpreted Linux mapping was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: Linux dependency W^X mapping verified' "$output_file"; then
    echo "Boot test failed: Linux dependency W^X mapping was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: interpreter-first Linux ring-3 entry verified' "$output_file"; then
    echo "Boot test failed: interpreter-first Linux ring-3 entry was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux interpreter self-relocation applied' "$output_file"; then
    echo "Boot test failed: userspace Linux interpreter self-relocation was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux relocation table shapes validated' "$output_file"; then
    echo "Boot test failed: userspace Linux relocation table shapes were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux relative relocation applied' "$output_file"; then
    echo "Boot test failed: userspace Linux relative relocation was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux GLOB_DAT relocation applied' "$output_file"; then
    echo "Boot test failed: userspace Linux GLOB_DAT relocation was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux JUMP_SLOT relocation applied' "$output_file"; then
    echo "Boot test failed: userspace Linux JUMP_SLOT relocation was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux hash bucket resolution applied' "$output_file"; then
    echo "Boot test failed: userspace Linux hash bucket resolution was not applied." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux symbol names matched' "$output_file"; then
    echo "Boot test failed: userspace Linux symbol names were not matched." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux cross-object symbol resolved' "$output_file"; then
    echo "Boot test failed: userspace Linux cross-object resolution was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux two-provider symbols resolved' "$output_file"; then
    echo "Boot test failed: two-provider Linux symbol resolution was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: Linux JUMP_SLOT dependency call executed' "$output_file"; then
    echo "Boot test failed: the resolved Linux dependency call was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux auxiliary JUMP_SLOT dependency call executed' "$output_file"; then
    echo "Boot test failed: the resolved auxiliary Linux dependency call was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux dependency self-relocations applied' "$output_file"; then
    echo "Boot test failed: Linux dependency self-relocations were not applied." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux auxiliary dependency self-relocations applied' "$output_file"; then
    echo "Boot test failed: auxiliary Linux dependency self-relocations were not applied." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux main preinit array validated' "$output_file"; then
    echo "Boot test failed: the bounded Linux main preinit array was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux main preinit metadata consumed' "$output_file"; then
    echo "Boot test failed: userspace did not consume the Linux main preinit metadata." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux main preinit executed' "$output_file"; then
    echo "Boot test failed: the userspace Linux main preinitializer was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux preinit-before-dependency initialization ordered' "$output_file"; then
    echo "Boot test failed: Linux preinit-before-dependency ordering was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux dependency init arrays validated' "$output_file"; then
    echo "Boot test failed: bounded Linux dependency init arrays were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux init arrays bound to relocations' "$output_file"; then
    echo "Boot test failed: userspace Linux init arrays were not bound to their relocations." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux dependency constructors executed' "$output_file"; then
    echo "Boot test failed: userspace Linux dependency constructors were not executed." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux main init array validated' "$output_file"; then
    echo "Boot test failed: the bounded Linux main init array was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux main constructor executed' "$output_file"; then
    echo "Boot test failed: the userspace Linux main constructor was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux dependency-before-main initialization ordered' "$output_file"; then
    echo "Boot test failed: Linux dependency-before-main initialization was not ordered." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux constructor startup context delivered' "$output_file"; then
    echo "Boot test failed: Linux constructor startup context was not delivered." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux DT_INIT functions validated' "$output_file"; then
    echo "Boot test failed: bounded Linux DT_INIT functions were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: userspace Linux DT_INIT functions executed' "$output_file"; then
    echo "Boot test failed: userspace Linux DT_INIT functions were not executed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux DT_INIT-before-init-array ordering enforced' "$output_file"; then
    echo "Boot test failed: Linux DT_INIT-before-init-array ordering was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: Linux auxiliary dependency entry executed' "$output_file"; then
    echo "Boot test failed: the auxiliary Linux dependency entry was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: metadata-driven Linux relative relocations applied' "$output_file"; then
    echo "Boot test failed: metadata-driven Linux relative relocations were not applied." >&2
    exit 1
fi

if ! grep -q '^linox: Linux copy errors and overflow bounds verified' "$output_file"; then
    echo "Boot test failed: Linux copy errors or overflow bounds were not verified." >&2
    exit 1
fi

if ! grep -q '^linox: Linux proof workload assembled from source' "$output_file"; then
    echo "Boot test failed: assembled Linux proof workload did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded console writes validated' "$output_file"; then
    echo "Boot test failed: Linux bounded console writes were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux atomic vectored console writes validated' "$output_file"; then
    echo "Boot test failed: Linux atomic vectored console writes were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded descriptor polling validated' "$output_file"; then
    echo "Boot test failed: Linux descriptor polling was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded ppoll inputs validated' "$output_file"; then
    echo "Boot test failed: Linux ppoll inputs were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded epoll lifecycle validated' "$output_file"; then
    echo "Boot test failed: Linux bounded epoll lifecycle was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded epoll_pwait inputs validated' "$output_file"; then
    echo "Boot test failed: Linux bounded epoll_pwait inputs were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded epoll_pwait2 timeout validated' "$output_file"; then
    echo "Boot test failed: Linux bounded epoll_pwait2 timeout was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux four-slot auxiliary descriptor table validated' "$output_file"; then
    echo "Boot test failed: Linux four-slot auxiliary descriptor table was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded eventfd notification validated' "$output_file"; then
    echo "Boot test failed: Linux bounded eventfd notification was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded timerfd expiration validated' "$output_file"; then
    echo "Boot test failed: Linux bounded timerfd expiration was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded pipe notification validated' "$output_file"; then
    echo "Boot test failed: Linux bounded pipe notification was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux atomic vectored pipe I/O validated' "$output_file"; then
    echo "Boot test failed: Linux atomic vectored pipe I/O was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux mutable descriptor status flags validated' "$output_file"; then
    echo "Boot test failed: Linux mutable descriptor status flags were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded pipe introspection validated' "$output_file"; then
    echo "Boot test failed: Linux bounded pipe introspection was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux anonymous descriptor metadata validated' "$output_file"; then
    echo "Boot test failed: Linux anonymous descriptor metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded syscall stack movement validated' "$output_file"; then
    echo "Boot test failed: Linux bounded syscall stack movement was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux callable syscall assertion helpers validated' "$output_file"; then
    echo "Boot test failed: Linux callable syscall assertion helpers were not validated." >&2
    exit 1
fi

if [[ "$(grep -c '^PROBE!!$' "$output_file")" -ne 40 ]]; then
    echo "Boot test failed: Linux console output record count is invalid." >&2
    exit 1
fi

if ! grep -q '^linox: Linux restart_syscall default interruption validated' "$output_file"; then
    echo "Boot test failed: Linux restart_syscall behavior was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux static clock ID and resolution profile validated' "$output_file"; then
    echo "Boot test failed: Linux static clock IDs and resolutions were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux live sysinfo accounting validated' "$output_file"; then
    echo "Boot test failed: Linux live sysinfo accounting was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux getrandom contract validated' "$output_file"; then
    echo "Boot test failed: Linux getrandom behavior was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux resource-limit queries validated' "$output_file"; then
    echo "Boot test failed: Linux resource-limit queries were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process identity validated' "$output_file"; then
    echo "Boot test failed: controller Linux identity syscalls were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux timekeeping validated' "$output_file"; then
    echo "Boot test failed: controller Linux timekeeping syscalls were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux runtime pipe accounting validated' "$output_file"; then
    echo "Boot test failed: runtime pipe accounting and poll readiness were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux container-local root credentials verified' "$output_file"; then
    echo "Boot test failed: Linux container-local root credentials were not verified." >&2
    exit 1
fi

if ! grep -q '^linox: Linux errno recovery verified in ring 3' "$output_file"; then
    echo "Boot test failed: Linux ring-3 errno recovery was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: Linux single-thread signal mask validated' "$output_file"; then
    echo "Boot test failed: Linux single-thread signal mask was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: per-thread Linux signal masks isolated' "$output_file"; then
    echo "Boot test failed: Linux per-thread signal masks were not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded signal actions validated' "$output_file"; then
    echo "Boot test failed: Linux bounded signal actions were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux synchronous SIGSEGV lifecycle validated' "$output_file"; then
    echo "Boot test failed: Linux synchronous SIGSEGV lifecycle was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux self-directed signal delivery validated' "$output_file"; then
    echo "Boot test failed: Linux self-directed signal delivery was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux thread-directed signal delivery validated' "$output_file"; then
    echo "Boot test failed: Linux thread-directed signal delivery was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux legacy thread signal delivery validated' "$output_file"; then
    echo "Boot test failed: Linux legacy thread signal delivery was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux pending signal delivery validated' "$output_file"; then
    echo "Boot test failed: Linux pending signal delivery was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux standard signal queue ordering validated' "$output_file"; then
    echo "Boot test failed: Linux standard signal queue ordering was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux chained pending signal delivery validated' "$output_file"; then
    echo "Boot test failed: Linux chained pending signal delivery was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux scheduler-backed timed signal wait validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed timed signal wait was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted timed wait validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted timed wait was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux one-shot signal action validated' "$output_file"; then
    echo "Boot test failed: Linux one-shot signal action was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux rt signal frame ABI validated' "$output_file"; then
    echo "Boot test failed: Linux rt signal frame ABI was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux mutable signal context validated' "$output_file"; then
    echo "Boot test failed: Linux mutable signal context was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux autodisarming alternate stack validated' "$output_file"; then
    echo "Boot test failed: Linux autodisarming alternate stack was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux alternate signal stack delivery validated' "$output_file"; then
    echo "Boot test failed: Linux alternate signal stack delivery was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded alternate signal stack validated' "$output_file"; then
    echo "Boot test failed: Linux bounded alternate signal stack was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux single-thread process identity verified' "$output_file"; then
    echo "Boot test failed: Linux single-thread process identity was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: Linux initial environment vector validated' "$output_file"; then
    echo "Boot test failed: Linux initial environment vector was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux credential auxiliary vector validated' "$output_file"; then
    echo "Boot test failed: Linux credential auxiliary vector was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux clock-tick auxiliary vector validated' "$output_file"; then
    echo "Boot test failed: Linux clock-tick auxiliary vector was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux platform auxiliary vector validated' "$output_file"; then
    echo "Boot test failed: Linux platform auxiliary vector was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux conservative hardware capabilities validated' "$output_file"; then
    echo "Boot test failed: Linux hardware capability vectors were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux FS base query validated' "$output_file"; then
    echo "Boot test failed: Linux FS base query was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux clear-child-TID exit action validated' "$output_file"; then
    echo "Boot test failed: Linux clear-child-TID exit action was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux robust-list registration validated' "$output_file"; then
    echo "Boot test failed: Linux robust-list registration was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux scheduler-backed timed futex wait validated' "$output_file"; then
    echo "Boot test failed: the scheduler-backed timed Linux futex wait was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux read-only memory transition validated' "$output_file"; then
    echo "Boot test failed: Linux read-only memory transition was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux initial process namespace identity validated' "$output_file"; then
    echo "Boot test failed: Linux initial process namespace identity was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded process name state validated' "$output_file"; then
    echo "Boot test failed: Linux bounded process name state was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux no-new-privileges boundary validated' "$output_file"; then
    echo "Boot test failed: Linux no-new-privileges boundary was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux static executable metadata validated' "$output_file"; then
    echo "Boot test failed: Linux static executable metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded brk heap validated' "$output_file"; then
    echo "Boot test failed: Linux bounded brk heap was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded anonymous mapping lifecycle validated' "$output_file"; then
    echo "Boot test failed: Linux anonymous mapping lifecycle was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux two-page anonymous extent validated' "$output_file"; then
    echo "Boot test failed: Linux two-page anonymous extent was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: multiple bounded Linux mmap areas validated' "$output_file"; then
    echo "Boot test failed: multiple bounded Linux mmap areas were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux mmap area splitting validated' "$output_file"; then
    echo "Boot test failed: bounded Linux mmap area splitting was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux anonymous mapping write seal validated' "$output_file"; then
    echo "Boot test failed: Linux anonymous mapping write seal was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux atomic multi-page write seal validated' "$output_file"; then
    echo "Boot test failed: Linux multi-page write seal was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded Linux mmap protection splitting validated' "$output_file"; then
    echo "Boot test failed: Linux mmap protection splitting was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: idempotent Linux mmap protection validated' "$output_file"; then
    echo "Boot test failed: idempotent Linux mmap protection was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: adjacent Linux mmap range operations validated' "$output_file"; then
    echo "Boot test failed: adjacent Linux mmap range operations were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: four-page fragmented Linux mmap window validated' "$output_file"; then
    echo "Boot test failed: four-page fragmented Linux mmap window was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded anonymous fixed mmap placement validated' "$output_file"; then
    echo "Boot test failed: bounded anonymous fixed mmap placement was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded anonymous fixed mmap replacement validated' "$output_file"; then
    echo "Boot test failed: bounded anonymous fixed mmap replacement was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded PROT_NONE fixed replacement validated' "$output_file"; then
    echo "Boot test failed: bounded PROT_NONE fixed replacement was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: bounded read-only anonymous mapping validated' "$output_file"; then
    echo "Boot test failed: bounded read-only anonymous mapping was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: page-rounded Linux mmap lengths validated' "$output_file"; then
    echo "Boot test failed: page-rounded Linux mmap lengths were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux PROT_NONE reservations validated' "$output_file"; then
    echo "Boot test failed: Linux PROT_NONE reservations were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux PROT_NONE activation validated' "$output_file"; then
    echo "Boot test failed: Linux PROT_NONE activation was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux mmap frames allocated on demand' "$output_file"; then
    echo "Boot test failed: Linux mmap frames were not allocated on demand." >&2
    exit 1
fi

if ! grep -q '^linox: Linux mmap frame leases reclaimed' "$output_file"; then
    echo "Boot test failed: Linux mmap frame leases were not reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: Linux anonymous mapping discard validated' "$output_file"; then
    echo "Boot test failed: Linux anonymous mapping discard was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux anonymous mapping residency validated' "$output_file"; then
    echo "Boot test failed: Linux anonymous mapping residency was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux heap copy bounds validated' "$output_file"; then
    echo "Boot test failed: Linux heap copy bounds were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux stack copy bounds validated' "$output_file"; then
    echo "Boot test failed: Linux stack copy bounds were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux directional VMA copies validated' "$output_file"; then
    echo "Boot test failed: Linux directional VMA copies were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: indexed Linux working directory validated' "$output_file"; then
    echo "Boot test failed: indexed Linux working directory was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: relative Linux directory changes validated' "$output_file"; then
    echo "Boot test failed: relative Linux directory changes were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fchdir descriptor boundary validated' "$output_file"; then
    echo "Boot test failed: Linux fchdir descriptor boundary was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux working-directory traversal rejected' "$output_file"; then
    echo "Boot test failed: Linux working-directory traversal was not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: Linux proc self executable link validated' "$output_file"; then
    echo "Boot test failed: Linux proc self executable link was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux proc self executable link-at validated' "$output_file"; then
    echo "Boot test failed: Linux proc self executable link-at was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux process umask state validated' "$output_file"; then
    echo "Boot test failed: Linux process umask state was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux disconnected console input validated' "$output_file"; then
    echo "Boot test failed: Linux disconnected console input was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux console descriptor metadata validated' "$output_file"; then
    echo "Boot test failed: Linux console descriptor metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fixed console geometry validated' "$output_file"; then
    echo "Boot test failed: Linux fixed console geometry was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fixed console termios validated' "$output_file"; then
    echo "Boot test failed: Linux fixed console termios was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux non-seekable console validated' "$output_file"; then
    echo "Boot test failed: Linux non-seekable console behavior was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux console descriptor close validated' "$output_file"; then
    echo "Boot test failed: Linux console descriptor close was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux console descriptor duplication validated' "$output_file"; then
    echo "Boot test failed: Linux console descriptor duplication was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux targeted descriptor duplication validated' "$output_file"; then
    echo "Boot test failed: Linux targeted descriptor duplication was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux console descriptor flags validated' "$output_file"; then
    echo "Boot test failed: Linux console descriptor flags were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux minimum descriptor duplication validated' "$output_file"; then
    echo "Boot test failed: Linux minimum descriptor duplication was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux close-on-exec descriptor state validated' "$output_file"; then
    echo "Boot test failed: Linux close-on-exec descriptor state was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded null device validated' "$output_file"; then
    echo "Boot test failed: Linux bounded null device was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded null device metadata validated' "$output_file"; then
    echo "Boot test failed: Linux bounded null device metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded null device access validated' "$output_file"; then
    echo "Boot test failed: Linux bounded null device access was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded zero device validated' "$output_file"; then
    echo "Boot test failed: Linux bounded zero device was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded console device validated' "$output_file"; then
    echo "Boot test failed: Linux bounded console device was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded tty alias validated' "$output_file"; then
    echo "Boot test failed: Linux bounded tty alias was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded device statx validated' "$output_file"; then
    echo "Boot test failed: Linux bounded device statx was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux atomic zero-device readv validated' "$output_file"; then
    echo "Boot test failed: Linux zero-device readv was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded device writev validated' "$output_file"; then
    echo "Boot test failed: Linux device writev was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux immutable device directory validated' "$output_file"; then
    echo "Boot test failed: Linux immutable device directory was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux immutable runtime ELF files validated' "$output_file"; then
    echo "Boot test failed: Linux immutable runtime ELF files were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux auxiliary dependency runtime file validated' "$output_file"; then
    echo "Boot test failed: Linux auxiliary dependency runtime file was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux read-only runtime file mapping validated' "$output_file"; then
    echo "Boot test failed: Linux read-only runtime file mapping was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux executable graph validated' "$output_file"; then
    echo "Boot test failed: measured-root Linux executable graph was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux executable graph executed' "$output_file"; then
    echo "Boot test failed: measured-root Linux executable graph was not executed." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux file content validated' "$output_file"; then
    echo "Boot test failed: measured-root Linux file content was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux file metadata validated' "$output_file"; then
    echo "Boot test failed: measured-root Linux file metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux file mutation denied' "$output_file"; then
    echo "Boot test failed: measured-root Linux file mutation was not denied." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux directory enumerated' "$output_file"; then
    echo "Boot test failed: measured-root Linux directory was not enumerated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux directory cursor validated' "$output_file"; then
    echo "Boot test failed: measured-root Linux directory cursor was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux root enumerated' "$output_file"; then
    echo "Boot test failed: measured-root Linux root was not enumerated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux root pagination validated' "$output_file"; then
    echo "Boot test failed: measured-root Linux root pagination was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux empty directory opened' "$output_file"; then
    echo "Boot test failed: measured-root Linux empty directory was not opened." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux dirfd lookup validated' "$output_file"; then
    echo "Boot test failed: measured-root Linux dirfd lookup was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root Linux relative metadata validated' "$output_file"; then
    echo "Boot test failed: measured-root Linux relative metadata was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: indexed measured-root file descriptors validated' "$output_file"; then
    echo "Boot test failed: indexed measured-root file descriptors were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: generic measured-root Linux file validated' "$output_file"; then
    echo "Boot test failed: the generic measured-root Linux file was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: index-driven measured child lookup validated' "$output_file"; then
    echo "Boot test failed: index-driven measured child lookup was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: unlisted measured-root Linux file validated' "$output_file"; then
    echo "Boot test failed: an unlisted measured-root Linux file was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: indexed measured-root directories validated' "$output_file"; then
    echo "Boot test failed: indexed measured-root directories were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: unlisted measured-root directory opened' "$output_file"; then
    echo "Boot test failed: an unlisted measured-root directory was not opened." >&2
    exit 1
fi

if ! grep -q '^linox: nested measured-root dirfd traversal validated' "$output_file"; then
    echo "Boot test failed: nested measured-root dirfd traversal was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: measured-root traversal components rejected' "$output_file"; then
    echo "Boot test failed: measured-root traversal components were not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: expanded measured-root index capacity validated' "$output_file"; then
    echo "Boot test failed: expanded measured-root index capacity was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux saved credential queries validated' "$output_file"; then
    echo "Boot test failed: Linux saved credential queries were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux supplementary root group validated' "$output_file"; then
    echo "Boot test failed: Linux supplementary root group was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fixed execution personality validated' "$output_file"; then
    echo "Boot test failed: Linux fixed execution personality was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux empty capability boundary validated' "$output_file"; then
    echo "Boot test failed: Linux empty capability boundary was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux mutable resource limits enforced' "$output_file"; then
    echo "Boot test failed: Linux mutable resource limits were not enforced." >&2
    exit 1
fi
if ! grep -q '^linox: Linux file-size resource limit enforced' "$output_file"; then
    echo "Boot test failed: Linux file-size resource limits were not enforced." >&2
    exit 1
fi
if ! grep -q '^linox: Linux POSIX message queue resource limit enforced' "$output_file"; then
    echo "Boot test failed: Linux POSIX message queue resource limits were not enforced." >&2
    exit 1
fi
if ! grep -q '^linox: Linux cross-process resource limits validated' "$output_file"; then
    echo "Boot test failed: Linux cross-process resource limits were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux nonblocking pidfd wait validated' "$output_file"; then
    echo "Boot test failed: Linux nonblocking pidfd wait was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux process-group wait selectors validated' "$output_file"; then
    echo "Boot test failed: Linux process-group wait selectors were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux cross-process memory transfer validated' "$output_file"; then
    echo "Boot test failed: Linux cross-process memory transfer was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux cross-process resource comparison validated' "$output_file"; then
    echo "Boot test failed: Linux cross-process resource comparison was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux shared open-file position validated' "$output_file"; then
    echo "Boot test failed: Linux shared open-file position was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux cross-process pidfd descriptor duplication validated' "$output_file"; then
    echo "Boot test failed: Linux cross-process pidfd descriptor duplication was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux generation-bound pidfds validated' "$output_file"; then
    echo "Boot test failed: Linux generation-bound pidfd lifecycle was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux UNIX in-flight descriptor limit enforced' "$output_file"; then
    echo "Boot test failed: Linux UNIX in-flight descriptor limits were not enforced." >&2
    exit 1
fi
if ! grep -q '^linox: Linux address-space resource limit enforced' "$output_file"; then
    echo "Boot test failed: Linux address-space resource limits were not enforced." >&2
    exit 1
fi
if ! grep -q '^linox: Linux memfd sealing enforced across descriptors' "$output_file"; then
    echo "Boot test failed: Linux memfd sealing was not enforced across descriptors." >&2
    exit 1
fi

if ! grep -q '^linox: Linux single-CPU topology queries validated' "$output_file"; then
    echo "Boot test failed: Linux single-CPU topology queries were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux single-thread scheduling yield validated' "$output_file"; then
    echo "Boot test failed: Linux single-thread scheduling yield was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fixed scheduler policy validated' "$output_file"; then
    echo "Boot test failed: Linux fixed scheduler policy was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux fixed process priority validated' "$output_file"; then
    echo "Boot test failed: Linux fixed process priority was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded monotonic clocks validated' "$output_file"; then
    echo "Boot test failed: Linux monotonic clocks were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded clock resolution validated' "$output_file"; then
    echo "Boot test failed: Linux clock resolution was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux scheduler-backed nanosleep validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed nanosleep was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux scheduler-backed poll waits validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed poll waits were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux signal-interrupted nanosleep validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted nanosleep was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux monotonic clock_nanosleep validated' "$output_file"; then
    echo "Boot test failed: Linux monotonic clock_nanosleep was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux scheduler-backed ppoll waits validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed ppoll waits were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux scheduler-backed epoll waits validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed epoll waits were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux scheduler-backed epoll masked waits validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed epoll masked waits were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux signal-interrupted masked waits validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted masked waits were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted epoll waits validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted epoll waits were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted poll waits validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted poll waits were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted epoll_wait validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted epoll_wait was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux zero-descriptor poll sleeps validated' "$output_file"; then
    echo "Boot test failed: Linux zero-descriptor poll sleeps were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux scheduler-backed eventfd reads validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed eventfd reads were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted eventfd reads validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted eventfd reads were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux scheduler-backed eventfd writes validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed eventfd writes were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted eventfd writes validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted eventfd writes were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux eventfd write snapshot isolation validated' "$output_file"; then
    echo "Boot test failed: Linux eventfd write snapshot isolation was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux scheduler-backed pipe reads validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed pipe reads were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux scheduler-backed pipe readv validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed pipe readv was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted pipe reads validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted pipe reads were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux scheduler-backed pipe writes validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed pipe writes were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux scheduler-backed pipe writev validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed pipe writev was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux pipe writev snapshot isolation validated' "$output_file"; then
    echo "Boot test failed: Linux pipe writev snapshot isolation was not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted pipe writes validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted pipe writes were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux scheduler-backed timerfd reads validated' "$output_file"; then
    echo "Boot test failed: Linux scheduler-backed timerfd reads were not validated." >&2
    exit 1
fi
if ! grep -q '^linox: Linux signal-interrupted timerfd reads validated' "$output_file"; then
    echo "Boot test failed: Linux signal-interrupted timerfd reads were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: APIC-driven Linux wait expiry validated' "$output_file"; then
    echo "Boot test failed: APIC-driven Linux wait expiry was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: APIC-driven Linux wait preemption validated' "$output_file"; then
    echo "Boot test failed: APIC-driven Linux wait preemption was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux single-task CPU time validated' "$output_file"; then
    echo "Boot test failed: Linux single-task CPU time was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux bounded resource usage validated' "$output_file"; then
    echo "Boot test failed: Linux resource usage was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: Linux disabled interval timers validated' "$output_file"; then
    echo "Boot test failed: Linux disabled interval timers were not validated." >&2
    exit 1
fi

if ! grep -q '^linox: monotonic sequence exhaustion contained' "$output_file"; then
    echo "Boot test failed: monotonic sequence exhaustion was not contained." >&2
    exit 1
fi

if ! grep -q '^linox: generation-scoped IPC diagnostics verified' "$output_file"; then
    echo "Boot test failed: IPC diagnostics crossed a service generation." >&2
    exit 1
fi

if [[ "$(grep -c '^USER_OK' "$output_file")" -ne 1 ]]; then
    echo "Boot test failed: the control-plane console record count is invalid." >&2
    exit 1
fi

if ! grep -q '^linox: opaque capability handles enforced at call gate' "$output_file"; then
    echo "Boot test failed: opaque capability-handle enforcement failed." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary exit status sequenced and retired' "$output_file"; then
    echo "Boot test failed: auxiliary exit status was not sequenced and retired." >&2
    exit 1
fi

if ! grep -q '^linox: userspace auxiliary creation authority enforced' "$output_file"; then
    echo "Boot test failed: userspace auxiliary creation authority was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: userspace auxiliary stop sequenced and retired' "$output_file"; then
    echo "Boot test failed: userspace auxiliary stop was not sequenced and retired." >&2
    exit 1
fi

if ! grep -q '^linox: userspace auxiliary load and admission enforced' "$output_file"; then
    echo "Boot test failed: userspace auxiliary load and admission were not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: private auxiliary payload initialization enforced' "$output_file"; then
    echo "Boot test failed: private auxiliary payload initialization was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary initialization state observable' "$output_file"; then
    echo "Boot test failed: auxiliary initialization state was not observable." >&2
    exit 1
fi

if ! grep -q '^linox: uninitialized auxiliary admission denied' "$output_file"; then
    echo "Boot test failed: uninitialized auxiliary admission was not denied." >&2
    exit 1
fi

if ! grep -q '^linox: explicit auxiliary start authority enforced' "$output_file"; then
    echo "Boot test failed: explicit auxiliary start authority was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary runtime state query enforced' "$output_file"; then
    echo "Boot test failed: auxiliary runtime state queries were not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: userspace auxiliary lifecycle observation enforced' "$output_file"; then
    echo "Boot test failed: userspace auxiliary lifecycle observation was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: userspace auxiliary lifecycle descriptor enforced' "$output_file"; then
    echo "Boot test failed: userspace auxiliary lifecycle descriptor validation was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: userspace auxiliary service identity enforced' "$output_file"; then
    echo "Boot test failed: userspace auxiliary service identity validation was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: auxiliary management authority denied' "$output_file"; then
    echo "Boot test failed: auxiliary management authority was not denied." >&2
    exit 1
fi

if ! grep -q '^linox: isolated network device probe completed' "$output_file"; then
    echo "Boot test failed: isolated network device probe did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: network device command validation enforced' "$output_file"; then
    echo "Boot test failed: network device command validation was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: network link state configured' "$output_file"; then
    echo "Boot test failed: network link state was not configured and observed." >&2
    exit 1
fi

if ! grep -q '^linox: network IPv4 configuration retained' "$output_file"; then
    echo "Boot test failed: network IPv4 configuration was not retained." >&2
    exit 1
fi

if ! grep -q '^linox: network default gateway validated' "$output_file"; then
    echo "Boot test failed: network default gateway validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: network configuration generation tracked' "$output_file"; then
    echo "Boot test failed: network configuration generation was not tracked." >&2
    exit 1
fi

if ! grep -q '^linox: network gateway invalidated on address change' "$output_file"; then
    echo "Boot test failed: stale network gateway survived an address change." >&2
    exit 1
fi

if ! grep -q '^linox: bounded static network route retained' "$output_file"; then
    echo "Boot test failed: bounded static network route was not retained." >&2
    exit 1
fi

if ! grep -q '^linox: coherent network state snapshot copied' "$output_file"; then
    echo "Boot test failed: coherent network state snapshot was not copied." >&2
    exit 1
fi

if ! grep -q '^linox: network device capability revoked on exit' "$output_file"; then
    echo "Boot test failed: network device authority survived service exit." >&2
    exit 1
fi

if ! grep -q '^linox: read-only network observer isolated' "$output_file"; then
    echo "Boot test failed: read-only network observer was not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: network mutation denied to observer' "$output_file"; then
    echo "Boot test failed: network observer mutation was not denied." >&2
    exit 1
fi

if ! grep -q '^linox: observer capability revoked on exit' "$output_file"; then
    echo "Boot test failed: observer network capability survived exit." >&2
    exit 1
fi

if ! grep -q '^linox: write-only network configurator isolated' "$output_file"; then
    echo "Boot test failed: write-only network configurator was not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: network observation denied to configurator' "$output_file"; then
    echo "Boot test failed: network configurator observation was not denied." >&2
    exit 1
fi

if ! grep -q '^linox: denied network copy-out left memory unchanged' "$output_file"; then
    echo "Boot test failed: denied network copy-out changed userspace memory." >&2
    exit 1
fi

if ! grep -q '^linox: stale network configuration apply rejected' "$output_file"; then
    echo "Boot test failed: stale network configuration apply was not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: atomic network configuration apply completed' "$output_file"; then
    echo "Boot test failed: atomic network configuration apply did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: configurator capability revoked on exit' "$output_file"; then
    echo "Boot test failed: configurator network capability survived exit." >&2
    exit 1
fi

if ! grep -q '^linox: faulted network service contained' "$output_file"; then
    echo "Boot test failed: faulted network service was not contained." >&2
    exit 1
fi

if ! grep -q '^linox: faulted network authority revoked' "$output_file"; then
    echo "Boot test failed: faulted network service retained authority." >&2
    exit 1
fi

if ! grep -q '^linox: network state survived service fault' "$output_file"; then
    echo "Boot test failed: network state did not survive a service fault." >&2
    exit 1
fi

if ! grep -q '^linox: replacement network service observed retained state' "$output_file"; then
    echo "Boot test failed: replacement network service did not recover retained state." >&2
    exit 1
fi

if ! grep -q '^linox: replacement network capability lifecycle isolated' "$output_file"; then
    echo "Boot test failed: replacement network capability lifecycle was not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: write-only volume service committed generation' "$output_file"; then
    echo "Boot test failed: the write-only volume service did not commit." >&2
    exit 1
fi

if ! grep -q '^linox: faulted volume service authority revoked' "$output_file"; then
    echo "Boot test failed: faulted volume-service authority was not revoked." >&2
    exit 1
fi

if ! grep -q '^linox: persistent volume survived service fault' "$output_file"; then
    echo "Boot test failed: the volume did not survive its writer fault." >&2
    exit 1
fi

if ! grep -q '^linox: read-only replacement recovered volume' "$output_file"; then
    echo "Boot test failed: the read-only replacement did not recover the volume." >&2
    exit 1
fi

if ! grep -q '^linox: volume mutation denied to replacement' "$output_file"; then
    echo "Boot test failed: the read-only replacement mutated the volume." >&2
    exit 1
fi

if ! grep -q '^linox: failed auxiliary load rollback enforced' "$output_file"; then
    echo "Boot test failed: failed auxiliary load rollback was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: queued auxiliary cancellation and teardown enforced' "$output_file"; then
    echo "Boot test failed: queued auxiliary cancellation was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: ready auxiliary cancellation and teardown enforced' "$output_file"; then
    echo "Boot test failed: ready auxiliary cancellation was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: yielded auxiliary cancellation and teardown enforced' "$output_file"; then
    echo "Boot test failed: yielded auxiliary cancellation was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: stop-only auxiliary fault executed and contained' "$output_file"; then
    echo "Boot test failed: stop-only auxiliary fault was not contained." >&2
    exit 1
fi

if ! grep -q '^linox: native volume service exited cleanly and device quiesced' "$output_file" ||
    ! grep -q '^linox: native service lifecycle ABI v0 clean exit validated in ring 3' "$output_file" ||
    ! grep -q '^linox: compiled native service negotiated control ABI v4' "$output_file" ||
    ! grep -q '^linox: compiled native service validated control descriptor v4' "$output_file" ||
    ! grep -q '^linox: clean exit quiesced device before DMA release' "$output_file" ||
    grep -q '^linox: native volume service fault contained and device quiesced' "$output_file"; then
    echo "Boot test failed: native service completion was not distinct from a fault." >&2
    exit 1
fi

if ! grep -q '^linox: compiled native volume service fault contained' "$output_file" ||
    ! grep -q '^linox: faulted native device service authority revoked' "$output_file" ||
    ! grep -q '^linox: incomplete native DMA scrubbed after fault' "$output_file" ||
    ! grep -q '^linox: post-fault native volume generation started' "$output_file" ||
    ! grep -q '^linox: native volume identity survived actual driver fault' "$output_file" ||
    ! grep -q '^linox: post-fault native volume service recovered exact record' "$output_file" ||
    ! grep -q '^linox: post-fault native volume resources retired cleanly' "$output_file"; then
    echo "Boot test failed: an incomplete native device-service request was not contained." >&2
    exit 1
fi

if ! grep -q '^linox: incompatible native service ABI rejected before device activation' "$output_file" ||
    ! grep -q '^linox: incompatible native service generation retired cleanly' "$output_file" ||
    ! grep -q '^linox: compatible native service recovered after ABI rejection' "$output_file"; then
    echo "Boot test failed: incompatible native control ABI did not fail closed and recover." >&2
    exit 1
fi

if ! grep -q '^linox: malformed native control descriptor rejected before device activation' "$output_file" ||
    ! grep -q '^linox: malformed descriptor service generation retired cleanly' "$output_file" ||
    ! grep -q '^linox: compatible native service recovered after descriptor rejection' "$output_file"; then
    echo "Boot test failed: malformed native control descriptor did not fail closed and recover." >&2
    exit 1
fi

if ! grep -q '^linox: notified native volume timeout cancelled safely' "$output_file" ||
    ! grep -q '^linox: cancelled native volume request generation retired' "$output_file" ||
    ! grep -q '^linox: post-cancellation native volume generation started' "$output_file" ||
    ! grep -q '^linox: post-cancellation native volume recovered exact record' "$output_file" ||
    ! grep -q '^linox: post-cancellation native resources retired cleanly' "$output_file"; then
    echo "Boot test failed: notified request cancellation did not recover in a fresh generation." >&2
    exit 1
fi

if ! grep -q '^linox: control call ABI v4 negotiated' "$output_file"; then
    echo "Boot test failed: control call ABI negotiation failed." >&2
    exit 1
fi

if ! grep -q '^linox: userspace console capability enforced' "$output_file"; then
    echo "Boot test failed: userspace console authority failed." >&2
    exit 1
fi

if ! grep -q '^linox: minimal user interrupt surface enforced' "$output_file"; then
    echo "Boot test failed: unexpected interrupt gates are callable from userspace." >&2
    exit 1
fi

if ! grep -q '^linox: bounded userspace read enforced' "$output_file"; then
    echo "Boot test failed: bounded userspace copying failed." >&2
    exit 1
fi

if ! grep -q '^linox: user copies bound to owned mappings' "$output_file"; then
    echo "Boot test failed: user copies were not bound to owned mappings." >&2
    exit 1
fi

if ! grep -q '^linox: page-granular user range validation enforced' "$output_file"; then
    echo "Boot test failed: page-granular user range validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: structured userspace ABI result verified' "$output_file"; then
    echo "Boot test failed: bounded userspace result copying failed." >&2
    exit 1
fi

if ! grep -q '^linox: ring-3 fault survivor resumed and exited' "$output_file"; then
    echo "Boot test failed: the surviving ring-3 context did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: user page fault contained' "$output_file"; then
    echo "Boot test failed: a ring-3 fault was not contained." >&2
    exit 1
fi

if ! grep -q '^linox: isolated scheduler address spaces switched' "$output_file"; then
    echo "Boot test failed: scheduler address-space switching failed." >&2
    exit 1
fi

if ! grep -q '^linox: scheduler CR3 roots validated' "$output_file"; then
    echo "Boot test failed: scheduler CR3 validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: bounded user page-table hierarchy validated' "$output_file"; then
    echo "Boot test failed: user page-table hierarchy validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: address-space resource contract shared' "$output_file"; then
    echo "Boot test failed: address-space resource contract was not shared." >&2
    exit 1
fi

if ! grep -q '^linox: scheduler address-space ownership validated' "$output_file"; then
    echo "Boot test failed: scheduler address-space ownership validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: scheduler user mappings validated' "$output_file"; then
    echo "Boot test failed: scheduler user mapping validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: one-shot user preemption completed' "$output_file"; then
    echo "Boot test failed: the one-shot user preemption did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: restarted service preemption completed' "$output_file"; then
    echo "Boot test failed: the restarted service was not reached by preemption." >&2
    exit 1
fi

if ! grep -q '^linox: completed address-space frames reclaimed' "$output_file"; then
    echo "Boot test failed: completed address-space frames were not reclaimed." >&2
    exit 1
fi

if ! grep -q '^linox: retired domain frame ownership cleared' "$output_file"; then
    echo "Boot test failed: retired domains retained physical-frame ownership." >&2
    exit 1
fi

if ! grep -q '^linox: retired service frame quarantine cleared' "$output_file"; then
    echo "Boot test failed: retired service frame quarantine remained live." >&2
    exit 1
fi

if ! grep -q '^linox: capability-gated bounded IPC verified' "$output_file"; then
    echo "Boot test failed: bounded IPC authority or FIFO behavior failed." >&2
    exit 1
fi

if ! grep -q '^linox: directional IPC endpoints isolated' "$output_file"; then
    echo "Boot test failed: directional IPC endpoint isolation failed." >&2
    exit 1
fi

if ! grep -q '^linox: generation-bound IPC endpoints verified' "$output_file"; then
    echo "Boot test failed: IPC endpoint generations were not isolated." >&2
    exit 1
fi

if ! grep -q '^linox: generation-tagged IPC messages verified' "$output_file"; then
    echo "Boot test failed: IPC message generations were not retained." >&2
    exit 1
fi

if ! grep -q '^linox: monotonic queued IPC sequences verified' "$output_file"; then
    echo "Boot test failed: queued IPC sequence validation failed." >&2
    exit 1
fi

if ! grep -q '^linox: structured IPC delivery provenance verified' "$output_file"; then
    echo "Boot test failed: structured IPC provenance was not verified." >&2
    exit 1
fi

if ! grep -q '^linox: IPC diagnostic authority enforced' "$output_file"; then
    echo "Boot test failed: IPC diagnostic authority was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: blocking IPC direct wake completed' "$output_file"; then
    echo "Boot test failed: blocking IPC did not wake the waiting service." >&2
    exit 1
fi

if ! grep -q '^linox: direct IPC wake provenance verified' "$output_file"; then
    echo "Boot test failed: direct IPC wake provenance was not retained." >&2
    exit 1
fi

if ! grep -q '^linox: sequenced direct IPC delivery verified' "$output_file"; then
    echo "Boot test failed: direct IPC delivery was not sequenced." >&2
    exit 1
fi

if ! grep -q '^linox: IPC wait-key matching enforced' "$output_file"; then
    echo "Boot test failed: IPC wait-key matching was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: blocked IPC peer-close cleanup verified' "$output_file"; then
    echo "Boot test failed: blocked IPC peer-close cleanup failed." >&2
    exit 1
fi

if ! grep -q '^linox: sticky IPC peer closure delivered' "$output_file"; then
    echo "Boot test failed: a late IPC receiver did not observe peer closure." >&2
    exit 1
fi

if ! grep -q '^linox: monotonic IPC peer closures verified' "$output_file"; then
    echo "Boot test failed: IPC peer closures were not sequenced." >&2
    exit 1
fi

if ! grep -q '^linox: isolated service request-reply completed' "$output_file"; then
    echo "Boot test failed: isolated service request/reply did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: service domain authority restricted to IPC' "$output_file"; then
    echo "Boot test failed: service-domain least authority was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: faulted service domain authority retired' "$output_file"; then
    echo "Boot test failed: faulted service-domain authority remained live." >&2
    exit 1
fi

if ! grep -q '^linox: service fault event delivered to control plane' "$output_file"; then
    echo "Boot test failed: the service fault event did not reach the control plane." >&2
    exit 1
fi

if ! grep -q '^linox: service fault event generation matched' "$output_file"; then
    echo "Boot test failed: service fault event generation did not match." >&2
    exit 1
fi

if ! grep -q '^linox: monotonic lifecycle events verified' "$output_file"; then
    echo "Boot test failed: lifecycle events were not sequenced." >&2
    exit 1
fi

if ! grep -q '^linox: structured lifecycle event delivered' "$output_file"; then
    echo "Boot test failed: structured lifecycle event was not delivered." >&2
    exit 1
fi

if ! grep -q '^linox: structured lifecycle service identity delivered' "$output_file"; then
    echo "Boot test failed: lifecycle service identity was not delivered." >&2
    exit 1
fi

if ! grep -q '^linox: lifecycle diagnostic authority enforced' "$output_file"; then
    echo "Boot test failed: lifecycle diagnostic authority was not enforced." >&2
    exit 1
fi

if ! grep -q '^linox: service fault metadata matched' "$output_file"; then
    echo "Boot test failed: service fault metadata did not match." >&2
    exit 1
fi

if ! grep -q '^linox: structured service fault delivered' "$output_file"; then
    echo "Boot test failed: structured service fault delivery failed." >&2
    exit 1
fi

if ! grep -q '^linox: service fault diagnostic authority enforced' "$output_file"; then
    echo "Boot test failed: service fault diagnostic authority failed." >&2
    exit 1
fi

if ! grep -q '^linox: service domain generation reuse verified' "$output_file"; then
    echo "Boot test failed: service-domain slot reuse accepted stale identity." >&2
    exit 1
fi

if ! grep -q '^linox: stable service identity survived restart' "$output_file"; then
    echo "Boot test failed: stable service identity did not survive restart." >&2
    exit 1
fi

if ! grep -q '^linox: service restart budget exhausted' "$output_file"; then
    echo "Boot test failed: service restart budget was not exhausted." >&2
    exit 1
fi

if ! grep -q '^linox: service restart rollback invariants verified' "$output_file"; then
    echo "Boot test failed: service restart rollback invariants failed." >&2
    exit 1
fi

if ! grep -q '^linox: failed service stack scrubbed before restart' "$output_file"; then
    echo "Boot test failed: failed service stack was not scrubbed." >&2
    exit 1
fi

if ! grep -q '^linox: service frame ownership transferred to replacement' "$output_file"; then
    echo "Boot test failed: service frame ownership was not transferred." >&2
    exit 1
fi

if ! grep -q '^linox: replacement service context executed' "$output_file"; then
    echo "Boot test failed: replacement service context did not execute." >&2
    exit 1
fi

if ! grep -q '^linox: replacement service request-reply completed' "$output_file"; then
    echo "Boot test failed: replacement service request-reply did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: volatile storage service round-trip completed' "$output_file"; then
    echo "Boot test failed: volatile storage service round-trip did not complete." >&2
    exit 1
fi

if ! grep -q '^linox: volatile storage invalid command rejected' "$output_file"; then
    echo "Boot test failed: volatile storage invalid command was not rejected." >&2
    exit 1
fi

if ! grep -q '^linox: replacement service readiness delivered' "$output_file"; then
    echo "Boot test failed: replacement service readiness was not delivered." >&2
    exit 1
fi

if ! grep -q '^linox: replacement service clean exit delivered' "$output_file"; then
    echo "Boot test failed: replacement service clean exit was not delivered." >&2
    exit 1
fi

if ! grep -q '^linox: per-domain syscall budgets enforced' "$output_file"; then
    echo "Boot test failed: per-domain syscall accounting failed." >&2
    exit 1
fi

if ! grep -q '^linox: per-domain thread budgets enforced' "$output_file"; then
    echo "Boot test failed: per-domain thread accounting failed." >&2
    exit 1
fi

if ! grep -q '^linox: in-flight domain operations drained' "$output_file"; then
    echo "Boot test failed: in-flight domain operation accounting failed." >&2
    exit 1
fi

if ! grep -q '^linox: scheduler context lifecycle verified' "$output_file"; then
    echo "Boot test failed: scheduler context lifecycle invariants failed." >&2
    exit 1
fi
if ! grep -q '^linox: scheduler priority selection verified' "$output_file"; then
    echo "Boot test failed: scheduler priority selection was not validated." >&2
    exit 1
fi

if ! grep -q '^linox: preemptible user context flags enforced' "$output_file"; then
    echo "Boot test failed: scheduler accepted a non-preemptible user context." >&2
    exit 1
fi

if ! grep -q '^linox: per-thread FS base context preserved' "$output_file"; then
    echo "Boot test failed: scheduler did not preserve per-thread FS base state." >&2
    exit 1
fi

if ! grep -q '^linox: bootstrap SHA-256 known answers verified' "$output_file"; then
    echo "Boot test failed: bootstrap SHA-256 known-answer tests failed." >&2
    exit 1
fi

if grep -qE '^LINOX_(BOOT|KERNEL)_PANIC' "$output_file"; then
    echo "Boot test failed: a panic marker was emitted." >&2
    exit 1
fi

if [[ "$qemu_status" -ne 0 ]]; then
    echo "Boot test failed: QEMU exited with $qemu_status; expected 0." >&2
    exit 1
fi

echo "Boot test passed."
