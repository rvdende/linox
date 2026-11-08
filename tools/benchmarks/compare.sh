#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=tools/benchmarks/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

linux_log="$benchmark_dir/rocky-linux-run-1-results.log"
linox_log=$(find "$benchmark_dir" -maxdepth 1 -type f \
    \( -name 'linox-sysbench-batch-*.log' -o -name 'linox-sysbench-cpu-*.log' \) \
    -print | LC_ALL=C sort | sed -n '1p')

[[ -s "$linux_log" ]] || {
    echo "benchmark: missing Linux results; run 'make benchmark-linux-comparison'" >&2
    exit 1
}
[[ -n "$linox_log" && -s "$linox_log" ]] || {
    echo "benchmark: missing Linox results; run 'make benchmark-linox-sysbench'" >&2
    exit 1
}

linux_hash=$(sed -n 's/^LINOX_BENCH_SYSBENCH_SHA256 //p' "$linux_log" | tail -n 1 | tr -d '\r' || true)
linox_hash=$(sed -n 's/^LINOX_BENCH_SYSBENCH_SHA256 //p' "$linox_log" | tail -n 1 | tr -d '\r' || true)

[[ "$linux_hash" =~ ^[[:xdigit:]]{64}$ ]] || {
    echo "benchmark: Linux sysbench hash was not recorded" >&2
    exit 1
}
[[ "$linox_hash" =~ ^[[:xdigit:]]{64}$ ]] || {
    echo "benchmark: Linox sysbench hash was not recorded" >&2
    exit 1
}
[[ "$linux_hash" == "$linox_hash" ]] || {
    echo "benchmark: sysbench binaries differ" >&2
    echo "  Linux: $linux_hash" >&2
    echo "  Linox: $linox_hash" >&2
    exit 1
}

python3 "$benchmark_root/tools/benchmarks/summarize-sysbench.py" "$benchmark_dir"

cat <<EOF
Benchmark inputs match:
  platform: linux/amd64
  machine:  $BENCHMARK_MACHINE
  vCPUs:    $BENCHMARK_VCPUS
  threads:  $BENCHMARK_THREADS
  memory:   $BENCHMARK_MEMORY
  sysbench: $linux_hash

Raw results:
  $benchmark_dir/rocky-linux-summary.tsv
  $benchmark_dir/rocky-linux-run-*-results.log
  $benchmark_dir/linox-sysbench-*.log
  $benchmark_dir/sysbench-comparison.tsv
EOF
