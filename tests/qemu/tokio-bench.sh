#!/usr/bin/env bash
# Compile-time benchmark: builds tests/bench/tokio (tokio with every
# feature, lockfile pinned) inside Linox in a rust:alpine domain with 4 CPUs,
# timing each build on the host clock from markers on the serial console.
# Crates are fetched before timing; each build starts from `cargo clean`.
# Results go to target/tokio-bench.txt (one "SYSTEM RUN SECONDS" line each).
#
#   tests/qemu/tokio-bench.sh [--runs "debug-j4 release-j4 debug-j1"] [--host]
#
# A run is PROFILE-jN: debug or release, N jobs. --host also builds the same
# project on the host: in the same rust:alpine image under Docker limited to
# 4 CPUs (the like-for-like comparison) and with the host's own toolchain.
# BENCH_PROFILE=1 writes the sysrq CPU accounting (`u`) to the serial log
# before and after the builds and samples a profile (`l`) 15 seconds into
# the first one (target/tokio-bench-serial.log).
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
project=$repo/tests/bench/tokio
runs="debug-j4 release-j4 debug-j1"
host=0
while (( $# )); do
    case $1 in
        --runs) runs=$2; shift 2 ;;
        --host) host=1; shift ;;
        *) echo "usage: $0 [--runs LIST] [--host]" >&2; exit 2 ;;
    esac
done

export TMPDIR=${TMPDIR:-$repo/target/tmp}
export OVMF_CODE=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
export OVMF_VARS=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
mkdir -p "$TMPDIR"
out=$repo/target/tokio-bench-serial.log
results=$repo/target/tokio-bench.txt
pidfile=$(mktemp "$TMPDIR/tokio-bench-pid.XXXXXX")
volume=$(mktemp "$TMPDIR/tokio-bench-volume.XXXXXX")
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
container=""
: >"$out"
: >"$results"

python3 -I -m http.server "$port" --bind 127.0.0.1 --directory "$project" >/dev/null 2>&1 &
http=$!
cleanup() {
    if [[ -s $pidfile ]]; then
        kill "$(cat "$pidfile")" 2>/dev/null || true
    fi
    kill "$http" 2>/dev/null || true
    if [[ -n $container ]]; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    rm -f "$volume" "$pidfile"
}
trap cleanup EXIT

wait_for() {
    local marker=$1 seconds=${2:-600}
    for _ in $(seq 1 "$seconds"); do
        grep -qE "^[0-9.]+ ${marker}" "$out" && return 0
        grep -Eq 'LINOX_(BOOT|KERNEL)_PANIC|domain marked failed' "$out" && break
        sleep 1
    done
    tail -n 40 "$out" >&2
    echo "tokio-bench: gave up waiting for $marker" >&2
    return 1
}

build_args() {
    local profile=${1%-j*} jobs=${1##*-j}
    if [[ $profile = release ]]; then echo "--release -j$jobs"; else echo "-j$jobs"; fi
}

now() { date +%s.%N; }
elapsed() { python3 -c "print(f'{$2 - $1:.1f}')"; }

toolchain=/usr/local/rustup/toolchains/1.99.1-x86_64-unknown-linux-musl/bin
fetch="wget -q http://10.0.2.2:${port}"
dd if=/dev/zero of="$volume" bs=1048576 count=1 2>/dev/null
{
    wait_for 'linox> ' 300 || exit 1
    printf '%s\n' \
        'domain new rust' \
        'domain set rust image=rust:alpine init=/bin/sh memory-mib=12288 cpu=4 privileged=true' \
        'domain start rust --attach'
    wait_for 'linox: OCI image ready' 1200 || exit 1
    sleep 5
    printf '%s\n' \
        "export PATH=$toolchain:\$PATH CARGO_HOME=/tmp/cargo; mkdir -p /tmp/tk/src && cd /tmp/tk" \
        "$fetch/Cargo.toml -O Cargo.toml && $fetch/Cargo.lock -O Cargo.lock && $fetch/src/main.rs -O src/main.rs; cargo fetch --locked 2>&1 | tail -1; echo FETCH\"_DONE\""
    wait_for 'FETCH_DONE' 900 || exit 1
    if [[ ${BENCH_PROFILE:-0} = 1 ]]; then
        printf '%s\n' "echo u > /proc/sysrq-trigger; echo SYSRQ\"_BEFORE\""
        wait_for SYSRQ_BEFORE 30 || exit 1
    fi
    sample=""
    if [[ ${BENCH_PROFILE:-0} = 1 ]]; then
        sample="(sleep 15; echo l > /proc/sysrq-trigger) & "
    fi
    for run in $runs; do
        args=$(build_args "$run")
        printf '%s\n' "cargo clean -q; sync; ${sample}echo START\"_$run\"; cargo build --locked --offline $args 2>&1 | grep -E 'Finished|error'; echo END\"_$run\""
        sample=""
        wait_for "START_$run" 120 || exit 1
        wait_for "END_$run" 3600 || exit 1
    done
    if [[ ${BENCH_PROFILE:-0} = 1 ]]; then
        printf '%s\n' "echo u > /proc/sysrq-trigger; echo SYSRQ\"_AFTER\""
        wait_for SYSRQ_AFTER 30 || exit 1
    fi
    printf '%s\n' "./target/*/tk; echo RAN\"_OK\""
    wait_for 'RAN_OK' 60 || exit 1
    printf '%s\n' 'exit 0'
    wait_for 'linox: Linux init exited cleanly' 120 || true
    sleep 2
    printf '%s\n' 'shutdown'
} | LINOX_CPUS=4 LINOX_MEMORY=16G LINOX_VOLUME_IMAGE="$volume" LINOX_QEMU_PID_FILE="$pidfile" \
    "$repo/tools/qemu/run.sh" 2>&1 | python3 -u -c '
import os, sys, time
start = True
while True:
    data = os.read(0, 4096)
    if not data:
        break
    parts = []
    for piece in data.decode("utf-8", "replace").replace("\r", "").splitlines(keepends=True):
        if start:
            parts.append("%.3f " % time.time())
        parts.append(piece)
        start = piece.endswith("\n")
    sys.stdout.write("".join(parts))
    sys.stdout.flush()
' >"$out"

python3 - "$out" <<'TIMES' | tee -a "$results"
import re, sys
times = {}
for line in open(sys.argv[1]):
    m = re.match(r"(\d+\.\d+) (START|END)_(\S+)$", line.strip())
    if m:
        times.setdefault(m.group(3), {})[m.group(2)] = float(m.group(1))
for run, t in times.items():
    if "START" in t and "END" in t:
        print(f"linox {run} {t['END'] - t['START']:.1f}")
TIMES
if ! grep -q 'tokio ok 7' "$out"; then
    echo "tokio-bench: the built program did not run in Linox" >&2
    exit 1
fi
(( host )) || exit 0

container=linox-tokio-bench-$$
docker run -d --rm --name "$container" --cpus=4 --memory=12g \
    -v "$project:/src:ro" rust:alpine sleep infinity >/dev/null
docker exec "$container" sh -c 'cp -r /src /tmp/tk && cd /tmp/tk && cargo fetch --locked -q'
for run in $runs; do
    args=$(build_args "$run")
    docker exec "$container" sh -c 'cd /tmp/tk && cargo clean -q && sync'
    start=$(now)
    docker exec "$container" sh -c "cd /tmp/tk && cargo build --locked --offline -q $args"
    end=$(now)
    echo "docker $run $(elapsed "$start" "$end")" | tee -a "$results"
done

work=$(mktemp -d "$TMPDIR/tokio-native.XXXXXX")
cp -r "$project/." "$work/"
(
    cd "$work"
    cargo fetch --locked -q
    for run in $runs; do
        args=$(build_args "$run")
        cargo clean -q && sync
        start=$(now)
        cargo build --locked --offline -q $args
        end=$(now)
        echo "native $run $(elapsed "$start" "$end")" | tee -a "$results"
    done
)
rm -rf "$work"
