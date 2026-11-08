#!/usr/bin/env python3

import csv
import os
import re
import sys
from pathlib import Path


WORKLOADS = {
    "CPU": ("events/s", True),
    "Memory": ("MiB/s", True),
    "Threads": ("events/s", True),
    "Mutex": ("s/event", False),
}


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def result_path(root: Path, mode: str, cpus: int, threads: int) -> Path:
    if mode == "scaled" and cpus == 1:
        mode = "fixed"
    return root / f"{mode}-{cpus}cpu-{threads}thread"


def hashes(directory: Path) -> tuple[str, str]:
    linux_logs = sorted(directory.glob("rocky-linux-run-*-results.log"))
    linox_logs = sorted(directory.glob("linox-sysbench-*.log"))
    if not linux_logs or not linox_logs:
        raise ValueError(f"missing raw logs in {directory}")
    pattern = re.compile(r"^LINOX_BENCH_SYSBENCH_SHA256 ([0-9a-f]{64})$", re.MULTILINE)
    linux = pattern.findall(linux_logs[0].read_text(errors="replace"))
    linox = pattern.findall(linox_logs[0].read_text(errors="replace"))
    if not linux or not linox:
        raise ValueError(f"missing sysbench digest in {directory}")
    return linux[-1], linox[-1]


def write_rows(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    root = Path(os.environ.get(
        "LINOX_BENCHMARK_MATRIX_DIR", "build/benchmark/rocky10-topology-matrix"
    ))
    configurations = [
        ("fixed", 1, 1),
        ("fixed", 2, 1),
        ("fixed", 4, 1),
        ("scaled", 1, 1),
        ("scaled", 2, 2),
        ("scaled", 4, 4),
    ]
    comparison: list[dict[str, object]] = []
    digests = set()

    for mode, cpus, threads in configurations:
        directory = result_path(root, mode, cpus, threads)
        rows = read_tsv(directory / "sysbench-comparison.tsv")
        linux_hash, linox_hash = hashes(directory)
        if linux_hash != linox_hash:
            raise ValueError(f"sysbench binaries differ in {directory}")
        digests.add(linux_hash)
        for row in rows:
            if int(row["linux_n"]) != 9 or int(row["linox_n"]) != 9:
                raise ValueError(f"expected nine samples in {directory}: {row}")
            linux = float(row["linux_median"])
            linox = float(row["linox_median"])
            _, higher = WORKLOADS[row["workload"]]
            ratio = linox / linux if higher else linux / linox
            comparison.append({
                "mode": mode,
                "vcpus": cpus,
                "threads": threads,
                "workload": row["workload"],
                "metric": row["metric"],
                "linux_n": row["linux_n"],
                "linux_median": f"{linux:.3f}",
                "linox_n": row["linox_n"],
                "linox_median": f"{linox:.3f}",
                "linox_over_linux": f"{ratio:.3f}x",
            })
    if len(digests) != 1:
        raise ValueError(f"matrix used multiple sysbench binaries: {sorted(digests)}")

    fields = [
        "mode", "vcpus", "threads", "workload", "metric", "linux_n",
        "linux_median", "linox_n", "linox_median", "linox_over_linux",
    ]
    write_rows(root / "topology-comparison.tsv", fields, comparison)

    scaling: list[dict[str, object]] = []
    for mode in ("fixed", "scaled"):
        for system, median_field in (("Linux", "linux_median"), ("Linox", "linox_median")):
            for workload, (_, higher) in WORKLOADS.items():
                selected = [
                    row for row in comparison
                    if row["mode"] == mode and row["workload"] == workload
                ]
                baseline = float(selected[0][median_field])
                for row in selected:
                    current = float(row[median_field])
                    ratio = current / baseline if higher else baseline / current
                    scaling.append({
                        "system": system,
                        "mode": mode,
                        "vcpus": row["vcpus"],
                        "threads": row["threads"],
                        "workload": workload,
                        "metric": row["metric"],
                        "median": f"{current:.3f}",
                        "relative_to_1cpu": f"{ratio:.3f}x",
                    })
    write_rows(
        root / "topology-scaling.tsv",
        ["system", "mode", "vcpus", "threads", "workload", "metric", "median", "relative_to_1cpu"],
        scaling,
    )

    boot_rows: list[dict[str, object]] = []
    for cpus in (1, 2, 4):
        directory = result_path(root, "fixed", cpus, 1)
        rows = read_tsv(directory / "boot-comparison.tsv")
        for row in rows:
            if int(row["runs"]) != 3:
                raise ValueError(f"expected three boot samples in {directory}: {row}")
            boot_rows.append({"vcpus": cpus, **row})
    write_rows(
        root / "boot-topology-comparison.tsv",
        ["vcpus", "system", "runs", "median_ms", "min_ms", "max_ms", "mean_ms"],
        boot_rows,
    )

    (root / "environment.tsv").write_text(
        "field\tvalue\n"
        f"sysbench_sha256\t{next(iter(digests))}\n"
        "machine\tq35\n"
        "memory\t2G\n"
        "sysbench_samples_per_cell\t9\n"
        "boot_samples_per_cell\t3\n"
    )
    print((root / "topology-comparison.tsv").read_text(), end="")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"benchmark: {error}", file=sys.stderr)
        raise SystemExit(1)
