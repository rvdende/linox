#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
result_dir=${LINOX_FUTEX_TEST_DIR:-$repo_root/build/benchmark/rocky-smp-futex}
asset_dir=${LINOX_BENCHMARK_ASSET_DIR:-$repo_root/build/benchmark/rocky10-single-vcpu}
log=$result_dir/linox-sysbench-batch-1.log

mkdir -p "$result_dir"

LINOX_BENCHMARK_DIR="$result_dir" \
LINOX_BENCHMARK_ASSET_DIR="$asset_dir" \
BENCHMARK_VCPUS=4 \
BENCHMARK_THREADS=4 \
BENCHMARK_BOOT_RUNS=1 \
BENCHMARK_WORKLOAD_RUNS=1 \
BENCHMARK_WORKLOAD_SECONDS=1 \
LINOX_BENCHMARK_BATCHED=1 \
LINOX_BENCHMARK_WORKLOADS=memory \
    "$repo_root/tools/benchmarks/run-linox.sh"

grep -Fq 'LINOX_BENCH_WORKLOAD_END_memory_1=0' "$log"
if grep -Eq 'first unsupported syscall number/arguments: 202|first-unsupported-syscall=202|Linux user fault' "$log"; then
    echo 'rocky-smp-futex: unexpected futex failure or Linux user fault' >&2
    exit 1
fi

echo 'Rocky four-CPU bitset-futex compatibility regression passed.'
