#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=tools/benchmarks/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mkdir -p "$benchmark_dir"
volume="$benchmark_asset_dir/linox-volume.raw"
rootfs="$benchmark_asset_dir/sysbench-minimal-rootfs.tar"

[[ -s "$rootfs" ]] || {
    echo "benchmark: missing $rootfs; prepare the local sysbench image first" >&2
    exit 1
}
sysbench_hash=$(tar -xOf "$rootfs" usr/bin/sysbench | {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
} | awk '{print $1}')
if [[ "${LINOX_BENCHMARK_BATCHED:-0}" == 1 ]]; then
    for ((boot_run = 1; boot_run <= BENCHMARK_BOOT_RUNS; boot_run++)); do
        log="$benchmark_dir/linox-sysbench-batch-$boot_run.log"
        LINOX_ROCKY_LOG="$log" \
        LINOX_VOLUME_IMAGE="$volume" \
        LINOX_MEMORY="$BENCHMARK_MEMORY" \
        LINOX_CPUS="$BENCHMARK_VCPUS" \
        LINOX_ROCKY_IMAGE="$LINOX_SYSBENCH_IMAGE" \
        LINOX_ROCKY_INIT=/bin/sh \
        LINOX_REQUIRE_OCI_CACHE_HIT=1 \
        LINOX_BENCHMARK_SYSBENCH=1 \
        LINOX_BENCHMARK_REUSE_DOMAIN=1 \
        LINOX_BENCHMARK_WORKLOAD="${LINOX_BENCHMARK_WORKLOADS:-cpu memory threads mutex}" \
        LINOX_BENCHMARK_THREADS="$BENCHMARK_THREADS" \
        LINOX_BENCHMARK_SYSBENCH_SHA256="$sysbench_hash" \
        LINOX_BENCHMARK_WORKLOAD_RUNS="$BENCHMARK_WORKLOAD_RUNS" \
        LINOX_BENCHMARK_WORKLOAD_SECONDS="$BENCHMARK_WORKLOAD_SECONDS" \
        LINOX_ROCKY_RUNTIME_TIMEOUT=1800 \
        "$benchmark_root/tests/qemu/rocky-systemd.sh"
    done
    echo "Linox batched benchmark completed: $benchmark_dir/linox-sysbench-batch-*.log"
    exit 0
fi

sample_runs=$((BENCHMARK_BOOT_RUNS * BENCHMARK_WORKLOAD_RUNS))

for workload in ${LINOX_BENCHMARK_WORKLOADS:-cpu memory threads mutex}; do
    for ((run = 1; run <= sample_runs; run++)); do
        log="$benchmark_dir/linox-sysbench-${workload}-${run}.log"
        if [[ "${LINOX_BENCHMARK_FORCE:-0}" != 1 ]] \
            && grep -Fq "LINOX_BENCH_WORKLOAD_END_${workload}_1=0" "$log" 2>/dev/null \
            && grep -Fq "LINOX_BENCH_SYSBENCH_SHA256 $sysbench_hash" "$log"; then
            continue
        fi
        LINOX_ROCKY_LOG="$log" \
        LINOX_VOLUME_IMAGE="$volume" \
        LINOX_MEMORY="$BENCHMARK_MEMORY" \
        LINOX_CPUS="$BENCHMARK_VCPUS" \
        LINOX_ROCKY_IMAGE="$LINOX_SYSBENCH_IMAGE" \
        LINOX_ROCKY_INIT=/bin/sh \
        LINOX_REQUIRE_OCI_CACHE_HIT="${LINOX_REQUIRE_OCI_CACHE_HIT:-0}" \
        LINOX_BENCHMARK_SYSBENCH=1 \
        LINOX_BENCHMARK_SINGLE_RUN=1 \
        LINOX_BENCHMARK_WORKLOAD="$workload" \
        LINOX_BENCHMARK_THREADS="${LINOX_BENCHMARK_THREADS:-$BENCHMARK_THREADS}" \
        LINOX_BENCHMARK_SYSBENCH_SHA256="$sysbench_hash" \
        LINOX_BENCHMARK_WORKLOAD_RUNS=1 \
        LINOX_BENCHMARK_WORKLOAD_SECONDS="$BENCHMARK_WORKLOAD_SECONDS" \
        LINOX_ROCKY_RUNTIME_TIMEOUT=900 \
        "$benchmark_root/tests/qemu/rocky-systemd.sh"
    done
done

echo "Linox benchmark completed: $benchmark_dir/linox-sysbench-*.log"
