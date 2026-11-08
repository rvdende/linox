#!/usr/bin/env python3

import re
import statistics
import sys
from pathlib import Path


def value(workload: str, text: str) -> float:
    if workload == "cpu":
        match = re.search(r"events per second:\s*([0-9.]+)", text)
    elif workload == "memory":
        match = re.search(r"\(([0-9.]+) MiB/sec\)", text)
    elif workload == "threads":
        events = re.search(r"total number of events:\s*([0-9.]+)", text)
        elapsed = re.search(r"total time:\s*([0-9.]+)s", text)
        if not events or not elapsed:
            raise ValueError("missing threads result")
        return float(events.group(1)) / float(elapsed.group(1))
    else:
        match = re.search(r"total time:\s*([0-9.]+)s", text)
    if not match:
        raise ValueError(f"missing {workload} result")
    return float(match.group(1))


def linux_samples(directory: Path, workload: str) -> list[float]:
    samples = []
    pattern = re.compile(
        rf"LINOX_BENCH_WORKLOAD_BEGIN {workload} \d+(.*?)"
        rf"LINOX_BENCH_WORKLOAD_END {workload} \d+ 0",
        re.DOTALL,
    )
    for path in sorted(directory.glob("rocky-linux-run-*-results.log")):
        samples.extend(value(workload, block) for block in pattern.findall(path.read_text(errors="replace")))
    return samples


def linox_samples(directory: Path, workload: str) -> list[float]:
    samples = []
    paths = sorted(directory.glob("linox-sysbench-batch-*.log"))
    if not paths:
        paths = sorted(directory.glob(f"linox-sysbench-{workload}-*.log"))
    pattern = re.compile(
        rf"LINOX_BENCH_WORKLOAD_BEGIN_{workload}_[0-9]+(.*?)"
        rf"LINOX_BENCH_WORKLOAD_END_{workload}_[0-9]+=0",
        re.DOTALL,
    )
    for path in paths:
        text = path.read_text(errors="replace")
        samples.extend(value(workload, block) for block in pattern.findall(text))
    return samples


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize-sysbench.py BENCHMARK-DIRECTORY", file=sys.stderr)
        return 2
    directory = Path(sys.argv[1])
    labels = {
        "cpu": ("CPU", "events/s", True),
        "memory": ("Memory", "MiB/s", True),
        "threads": ("Threads", "events/s", True),
        "mutex": ("Mutex", "s/event", False),
    }
    output = directory / "sysbench-comparison.tsv"
    rows = ["workload\tmetric\tlinux_n\tlinux_median\tlinox_n\tlinox_median\tlinox_result"]
    for workload, (label, metric, higher_is_better) in labels.items():
        linux = linux_samples(directory, workload)
        linox = linox_samples(directory, workload)
        if not linux or not linox:
            raise ValueError(f"missing matched samples for {workload}")
        linux_median = statistics.median(linux)
        linox_median = statistics.median(linox)
        ratio = linox_median / linux_median if higher_is_better else linux_median / linox_median
        result = f"{ratio:.3f}x faster" if ratio >= 1 else f"{1 / ratio:.3f}x slower"
        rows.append(
            f"{label}\t{metric}\t{len(linux)}\t{linux_median:.3f}\t"
            f"{len(linox)}\t{linox_median:.3f}\t{result}"
        )
    output.write_text("\n".join(rows) + "\n")
    print(output.read_text(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
