#!/usr/bin/env python3
# parse_frost_bench.py
#
# Parse secp256k1/libsecp256k1-style benchmark output and produce:
#
#   - bench_results_long.csv
#   - bench_results_summary.csv
#   - bench_results_table.csv
#   - optional bar/box plots
#
# Current supported output:
#
#   Benchmark                     ,    Min(us)    ,    Avg(us)    ,    Max(us)
#
#   frost_sign                    ,    80.2       ,    80.6       ,    82.0
#   frost_aggregate (2/3)         ,   226.0       ,   233.0       ,   251.0
#   frost_verify                  ,    55.9       ,    56.5       ,    56.9
#
# The boxplot shows process-level variability across repeated executions of
# the benchmark binary. Each point is the Avg(us) reported by one benchmark
# execution for a given operation/configuration. It is not a per-operation
# latency distribution, because the raw benchmark output does not expose
# every individual timed operation.
#
# Suggested campaign:
#
#   REPS=10 ITERS_LIST="1000" ./scripts/run_frost_bench_campaign.sh
#
# or, for more stable averages:
#
#   REPS=10 ITERS_LIST="5000" ./scripts/run_frost_bench_campaign.sh

import argparse
import csv
import re
import statistics
from pathlib import Path

CONFIG_RE = re.compile(r"\((?P<t>[0-9]+)\s*/\s*(?P<n>[0-9]+)\)")

CSV_TABLE_RE = re.compile(
    r"^\s*(?P<name>frost[A-Za-z0-9_ ./+-]*(?:\s*\([0-9]+/[0-9]+\))?)\s*,\s*"
    r"(?P<min>[0-9]+(?:\.[0-9]+)?)\s*,\s*"
    r"(?P<avg>[0-9]+(?:\.[0-9]+)?)\s*,\s*"
    r"(?P<max>[0-9]+(?:\.[0-9]+)?)\s*$",
    re.IGNORECASE,
)

VERBOSE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_ ./+-]+(?:\s*\([0-9]+/[0-9]+\))?)"
    r"\s*:\s*.*?"
    r"(?:min|minimum)\s*(?P<min>[0-9]+(?:\.[0-9]+)?)\s*(?P<min_unit>ns|us|µs|ms|s)?.*?"
    r"(?:avg|average|mean)\s*(?P<avg>[0-9]+(?:\.[0-9]+)?)\s*(?P<avg_unit>ns|us|µs|ms|s)?.*?"
    r"(?:max|maximum)\s*(?P<max>[0-9]+(?:\.[0-9]+)?)\s*(?P<max_unit>ns|us|µs|ms|s)?",
    re.IGNORECASE,
)

OPERATION_ORDER = ["nonce_create", "sign_share", "aggregate", "verify", "dealer_keygen"]

def unit_to_us(value, unit):
    if unit is None:
        return value
    unit = unit.replace("µ", "u").lower()
    if unit == "ns":
        return value / 1000.0
    if unit == "us":
        return value
    if unit == "ms":
        return value * 1000.0
    if unit == "s":
        return value * 1000000.0
    return value

def parse_filename(path):
    iters = None
    rep = None
    m = re.search(r"iters([0-9]+)", path.name)
    if m:
        iters = int(m.group(1))
    m = re.search(r"rep([0-9]+)", path.name)
    if m:
        rep = int(m.group(1))
    return iters, rep

def parse_config(name):
    m = CONFIG_RE.search(name)
    if not m:
        # Current fixed bench_impl.h uses 2-of-3 but labels only aggregate as (2/3).
        return 2, 3, "2/3"
    t = int(m.group("t"))
    n = int(m.group("n"))
    return t, n, f"{t}/{n}"

def normalize_operation(name):
    base = CONFIG_RE.sub("", name).strip()
    base = re.sub(r"\s+", " ", base)
    return {
        "frost_sign": "sign_share",
        "frost_sign_share": "sign_share",
        "frost_aggregate": "aggregate",
        "frost_verify": "verify",
        "frost_nonce_create": "nonce_create",
        "frost_dealer_keygen": "dealer_keygen",
    }.get(base, base)

def parse_log(path):
    rows = []
    iters, rep = parse_filename(path)
    for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if "frost" not in line.lower():
            continue

        m = CSV_TABLE_RE.search(line)
        if m:
            name = m.group("name").strip()
            min_us = float(m.group("min"))
            avg_us = float(m.group("avg"))
            max_us = float(m.group("max"))
        else:
            m = VERBOSE_RE.search(line)
            if not m:
                continue
            name = m.group("name").strip()
            min_us = unit_to_us(float(m.group("min")), m.groupdict().get("min_unit"))
            avg_us = unit_to_us(float(m.group("avg")), m.groupdict().get("avg_unit"))
            max_us = unit_to_us(float(m.group("max")), m.groupdict().get("max_unit"))

        threshold, participants, configuration = parse_config(name)
        rows.append({
            "source_file": str(path),
            "line_no": line_no,
            "iters": iters,
            "rep": rep,
            "benchmark": name,
            "operation": normalize_operation(name),
            "threshold": threshold,
            "participants": participants,
            "configuration": configuration,
            "min_us": min_us,
            "avg_us": avg_us,
            "max_us": max_us,
            "raw_line": line.strip(),
        })
    return rows

def stdev(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0

def pctl(values, p):
    values = sorted(values)
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    k = (len(values) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(values) - 1)
    if f == c:
        return values[f]
    return values[f] * (c - k) + values[c] * (k - f)

def summarize(rows):
    groups = {}
    for r in rows:
        key = (r["iters"], r["operation"], r["threshold"], r["participants"], r["configuration"])
        groups.setdefault(key, []).append(r)

    out = []
    for key, group in sorted(groups.items(), key=lambda kv: str(kv[0])):
        iters, operation, threshold, participants, configuration = key
        avgs = [float(r["avg_us"]) for r in group]
        mins = [float(r["min_us"]) for r in group]
        maxs = [float(r["max_us"]) for r in group]
        out.append({
            "iters": iters,
            "operation": operation,
            "threshold": threshold,
            "participants": participants,
            "configuration": configuration,
            "process_reps": len(group),
            "avg_us_median": statistics.median(avgs),
            "avg_us_mean": statistics.mean(avgs),
            "avg_us_stdev": stdev(avgs),
            "avg_us_p05": pctl(avgs, 5),
            "avg_us_p25": pctl(avgs, 25),
            "avg_us_p75": pctl(avgs, 75),
            "avg_us_p95": pctl(avgs, 95),
            "min_us_min": min(mins),
            "max_us_max": max(maxs),
        })
    return out

def write_csv(path, rows):
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

def config_sort_key(config):
    try:
        t, n = str(config).split("/")
        return int(t), int(n)
    except Exception:
        return 999, 999

def operation_sort_key(op):
    try:
        return OPERATION_ORDER.index(op)
    except ValueError:
        return len(OPERATION_ORDER), op

def write_paper_table(path, summary_rows):
    valid_iters = sorted({r["iters"] for r in summary_rows if r["iters"] is not None})
    chosen_iters = valid_iters[-1] if valid_iters else None
    rows = [r for r in summary_rows if r["iters"] == chosen_iters]
    configs = sorted({str(r["configuration"]) for r in rows}, key=config_sort_key)
    table = []
    for config in configs:
        row = {"configuration": config}
        for op in OPERATION_ORDER:
            matches = [r for r in rows if str(r["configuration"]) == config and r["operation"] == op]
            row[f"{op}_median_us"] = f"{matches[0]['avg_us_median']:.3f}" if matches else ""
            row[f"{op}_iqr_us"] = (
                f"{matches[0]['avg_us_p25']:.3f}--{matches[0]['avg_us_p75']:.3f}" if matches else ""
            )
        table.append(row)
    write_csv(path, table)

def selected_rows_for_plot(summary_or_long_rows, chosen_iters):
    return [r for r in summary_or_long_rows if r["iters"] == chosen_iters]

def plot_bar_summary(outdir, summary_rows, chosen_iters):
    import matplotlib.pyplot as plt

    rows = selected_rows_for_plot(summary_rows, chosen_iters)
    if not rows:
        return

    configs = sorted({str(r["configuration"]) for r in rows}, key=config_sort_key)
    ops = sorted({str(r["operation"]) for r in rows}, key=operation_sort_key)

    labels = []
    values = []
    err_low = []
    err_high = []

    for config in configs:
        for op in ops:
            matches = [r for r in rows if str(r["configuration"]) == config and str(r["operation"]) == op]
            if not matches:
                continue
            r = matches[0]
            median = float(r["avg_us_median"])
            p25 = float(r["avg_us_p25"])
            p75 = float(r["avg_us_p75"])
            labels.append(f"{op}\n{config}")
            values.append(median)
            err_low.append(max(0.0, median - p25))
            err_high.append(max(0.0, p75 - median))

    if not labels:
        return

    fig = plt.figure(figsize=(max(8, len(labels) * 0.8), 4.8))
    ax = fig.add_subplot(111)
    ax.bar(range(len(labels)), values, yerr=[err_low, err_high], capsize=3)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_ylabel("Time (µs)")
    ax.set_title("secp256k1-frost benchmark summary")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(outdir / "bench_summary_bar_iqr.pdf")
    fig.savefig(outdir / "bench_summary_bar_iqr.png", dpi=200)
    plt.close(fig)

def plot_boxplot(outdir, long_rows, chosen_iters):
    import matplotlib.pyplot as plt

    rows = selected_rows_for_plot(long_rows, chosen_iters)
    if not rows:
        return

    configs = sorted({str(r["configuration"]) for r in rows}, key=config_sort_key)
    ops = sorted({str(r["operation"]) for r in rows}, key=operation_sort_key)

    labels = []
    samples = []

    for config in configs:
        for op in ops:
            vals = [
                float(r["avg_us"])
                for r in rows
                if str(r["configuration"]) == config and str(r["operation"]) == op
            ]
            if vals:
                labels.append(f"{op}\n{config}")
                samples.append(vals)

    if not samples:
        return

    fig = plt.figure(figsize=(max(8, len(labels) * 0.85), 4.8))
    ax = fig.add_subplot(111)
    ax.boxplot(samples, labels=labels, showmeans=True)
    ax.set_ylabel("Average time per benchmark run (µs)")
    ax.set_title("secp256k1-frost benchmark variability")
    ax.grid(axis="y", alpha=0.3)
    for tick in ax.get_xticklabels():
        tick.set_rotation(45)
        tick.set_ha("right")
    fig.tight_layout()
    fig.savefig(outdir / "bench_boxplot.pdf")
    fig.savefig(outdir / "bench_boxplot.png", dpi=200)
    plt.close(fig)

def plot_scaling(outdir, summary_rows, chosen_iters):
    import matplotlib.pyplot as plt

    rows = selected_rows_for_plot(summary_rows, chosen_iters)
    for op in ["sign_share", "aggregate", "verify"]:
        op_rows = [r for r in rows if r["operation"] == op and r["threshold"] not in (None, "")]
        if len(op_rows) < 2:
            continue
        op_rows = sorted(op_rows, key=lambda r: int(r["threshold"]))
        fig = plt.figure(figsize=(6.2, 4.2))
        ax = fig.add_subplot(111)
        ax.plot(
            [int(r["threshold"]) for r in op_rows],
            [float(r["avg_us_median"]) for r in op_rows],
            marker="o",
        )
        ax.set_xlabel("Threshold / signing set size")
        ax.set_ylabel("Median average time (µs)")
        ax.set_title(f"FROST {op} scaling")
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(outdir / f"bench_scaling_{op}.pdf")
        fig.savefig(outdir / f"bench_scaling_{op}.png", dpi=200)
        plt.close(fig)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("raw_dir", type=Path)
    p.add_argument("--outdir", type=Path, default=None)
    p.add_argument("--plot", action="store_true", help="Generate bar and scaling plots")
    p.add_argument("--boxplot", action="store_true", help="Generate a boxplot of process-level repetitions")
    args = p.parse_args()

    outdir = args.outdir or args.raw_dir.parent
    outdir.mkdir(parents=True, exist_ok=True)

    logs = sorted(args.raw_dir.glob("*.txt"))
    if not logs:
        raise SystemExit(f"No .txt logs found in {args.raw_dir}")

    rows = []
    for path in logs:
        rows.extend(parse_log(path))

    if not rows:
        raise SystemExit("No benchmark rows parsed. Inspect raw logs and adjust the parser.")

    summary = summarize(rows)
    write_csv(outdir / "bench_results_long.csv", rows)
    write_csv(outdir / "bench_results_summary.csv", summary)
    write_paper_table(outdir / "bench_results_table.csv", summary)

    valid_iters = sorted({r["iters"] for r in summary if r["iters"] is not None})
    chosen_iters = valid_iters[-1] if valid_iters else None

    if args.plot:
        plot_bar_summary(outdir, summary, chosen_iters)
        plot_scaling(outdir, summary, chosen_iters)

    if args.boxplot:
        plot_boxplot(outdir, rows, chosen_iters)

    print(f"Parsed {len(rows)} benchmark rows from {len(logs)} logs.")
    print(f"Wrote {outdir / 'bench_results_long.csv'}")
    print(f"Wrote {outdir / 'bench_results_summary.csv'}")
    print(f"Wrote {outdir / 'bench_results_table.csv'}")
    if args.plot:
        print(f"Wrote bar/scaling plots to {outdir}")
    if args.boxplot:
        print(f"Wrote boxplot to {outdir}")

if __name__ == "__main__":
    main()
