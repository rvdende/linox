#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
result_root=${LINOX_SMP_CONTEXT_TEST_DIR:-$repo_root/build/benchmark/rocky-smp-thread-context/regression}
asset_dir=${LINOX_BENCHMARK_ASSET_DIR:-$repo_root/build/benchmark/rocky10-single-vcpu}
boot_runs=${LINOX_SMP_CONTEXT_BOOT_RUNS:-3}
workload_runs=${LINOX_SMP_CONTEXT_WORKLOAD_RUNS:-3}

for cpus in ${LINOX_SMP_CONTEXT_CPUS:-2 4}; do
    result_dir=$result_root/${cpus}cpu
    mkdir -p "$result_dir"

    LINOX_BENCHMARK_DIR="$result_dir" \
    LINOX_BENCHMARK_ASSET_DIR="$asset_dir" \
    BENCHMARK_VCPUS="$cpus" \
    BENCHMARK_THREADS="$cpus" \
    BENCHMARK_BOOT_RUNS="$boot_runs" \
    BENCHMARK_WORKLOAD_RUNS="$workload_runs" \
    BENCHMARK_WORKLOAD_SECONDS=3 \
    LINOX_BENCHMARK_BATCHED=1 \
    LINOX_BENCHMARK_WORKLOADS=threads \
        "$repo_root/tools/benchmarks/run-linox.sh"

    for ((boot_run = 1; boot_run <= boot_runs; boot_run++)); do
        log=$result_dir/linox-sysbench-batch-${boot_run}.log
        for ((workload_run = 1; workload_run <= workload_runs; workload_run++)); do
            grep -Fq "LINOX_BENCH_WORKLOAD_END_threads_${workload_run}=0" "$log"
        done
        if grep -Eq 'Linux user fault|LINOX_(BOOT|KERNEL)_PANIC|register mismatch|stale generation' "$log"; then
            echo "rocky-smp-thread-context: ${cpus}-vCPU fault, panic, or context mismatch" >&2
            exit 1
        fi
    done
done

if command -v lsof >/dev/null 2>&1 \
    && lsof "$asset_dir/linox-volume.raw" >"$result_root/open-volume-check.log" 2>&1; then
    cat "$result_root/open-volume-check.log" >&2
    echo 'rocky-smp-thread-context: benchmark volume remains open' >&2
    exit 1
fi

echo 'Rocky 2/4-vCPU Linux thread-context regression passed.'
