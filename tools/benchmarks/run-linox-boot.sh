#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=tools/benchmarks/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mkdir -p "$benchmark_dir"
volume="$benchmark_asset_dir/linox-volume.raw"
summary="$benchmark_dir/linox-boot-summary.tsv"
accelerator=$(benchmark_accelerator)
cpu_model=$(benchmark_cpu "$accelerator")

run_boot() {
    local label=$1
    local require_cache=$2
    local log="$benchmark_dir/linox-boot-$label.log"
    local metrics="$benchmark_dir/linox-boot-$label.metrics"

    rm -f "$metrics"
    LINOX_ROCKY_LOG="$log" \
    LINOX_ROCKY_METRICS_FILE="$metrics" \
    LINOX_VOLUME_IMAGE="$volume" \
    LINOX_MEMORY="$BENCHMARK_MEMORY" \
    LINOX_CPUS="$BENCHMARK_VCPUS" \
    LINOX_ROCKY_IMAGE="$ROCKY_LINOX_IMAGE" \
    LINOX_REQUIRE_OCI_CACHE_HIT="$require_cache" \
    LINOX_ROCKY_RUNTIME_TIMEOUT=600 \
    "$benchmark_root/tests/qemu/rocky-systemd.sh"

    [[ -s "$metrics" ]] || {
        echo "benchmark: Linox run $label did not write boot metrics" >&2
        exit 1
    }
}

# Populate and verify the persistent OCI cache outside the measured runs.
run_boot warmup 0

printf 'run\tqemu_start_to_multi_user_ms\taccelerator\tcpu\tvcpus\tthreads\tmemory\n' >"$summary"
for ((run = 1; run <= BENCHMARK_BOOT_RUNS; run++)); do
    run_boot "$run" 1
    value=$(awk -F '\t' '$1 == "qemu_start_to_multi_user_ms" { print $2 }' \
        "$benchmark_dir/linox-boot-$run.metrics")
    [[ "$value" =~ ^[0-9]+$ ]] || {
        echo "benchmark: invalid Linox boot metric for run $run" >&2
        exit 1
    }
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$run" "$value" "$accelerator" "$cpu_model" \
        "$BENCHMARK_VCPUS" "$BENCHMARK_THREADS" "$BENCHMARK_MEMORY" >>"$summary"
done

echo "Linox boot benchmark completed: $summary"
