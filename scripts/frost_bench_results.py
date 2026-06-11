#!/usr/bin/env python3
# frost_bench_results.py
#
# Single post-processing script for the secp256k1-frost benchmark campaign.
#
# It parses raw benchmark logs and generates:
#
#   - bench_results_long.csv
#   - bench_results_summary.csv
#   - bench_results_table.csv
#   - frost_bench_table.tex
#   - frost_bench_table_with_iqr.tex
#   - optional clean paper plots:
#       * frost_bench_scaling.pdf
#       * frost_bench_scaling_aggregate.pdf
#       * frost_bench_scaling_online.pdf
#       * frost_bench_boxplot.pdf
#
# It intentionally does NOT generate the older grouped bar plot
# bench_summary_bar_iqr.pdf.
#
# Usage:
#
#   python3 scripts/frost_bench_results.py results/x/raw --outdir results/x --plots --boxplot
#
# Typical workflow:
#
#   REPS=10 ITERS_LIST="1000" ./scripts/run_frost_bench_campaign.sh
#   python3 scripts/frost_bench_results.py results/x/raw --outdir results/x --plots --boxplot
#
# Current supported raw output:
#
#   Benchmark                     ,    Min(us)    ,    Avg(us)    ,    Max(us)
#
#   frost_sign (2/3)              ,    80.2       ,    80.6       ,    82.0
#   frost_aggregate (2/3)         ,   226.0       ,   233.0       ,   251.0
#   frost_verify (2/3)            ,    55.9       ,    56.5       ,    56.9

import argparse
import csv
import re
import statistics
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

OPERATION_LABELS = {
    "nonce_create": "Nonce creation",
    "sign_share": "Sign share",
    "aggregate": "Aggregate",
    "verify": "Verify",
    "dealer_keygen": "Dealer keygen",
}

DEFAULT_PAPER_OPERATIONS = ["sign_share", "aggregate", "verify"]
OPTIONAL_PAPER_OPERATIONS = ["nonce_create", "dealer_keygen"]


def unit_to_us(value: float, unit: Optional[str]) -> float:
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


def parse_filename(path: Path) -> Tuple[Optional[int], Optional[int]]:
    iters = None
    rep = None

    m = re.search(r"iters([0-9]+)", path.name)
    if m:
        iters = int(m.group(1))

    m = re.search(r"rep([0-9]+)", path.name)
    if m:
        rep = int(m.group(1))

    return iters, rep


def parse_config(name: str) -> Tuple[Optional[int], Optional[int], str]:
    m = CONFIG_RE.search(name)
    if not m:
        # Backward-compatible fallback for old fixed 2-of-3 labels such as
        # frost_sign and frost_verify.
        return 2, 3, "2/3"

    t = int(m.group("t"))
    n = int(m.group("n"))
    return t, n, f"{t}/{n}"


def normalize_operation(name: str) -> str:
    base = CONFIG_RE.sub("", name).strip()
    base = re.sub(r"\s+", " ", base)

    aliases = {
        "frost_sign": "sign_share",
        "frost_sign_share": "sign_share",
        "frost_aggregate": "aggregate",
        "frost_verify": "verify",
        "frost_nonce_create": "nonce_create",
        "frost_dealer_keygen": "dealer_keygen",
    }

    return aliases.get(base, base)


def parse_log(path: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
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


def percentile(values: List[float], p: float) -> float:
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


def stdev(values: List[float]) -> float:
    return statistics.stdev(values) if len(values) > 1 else 0.0


def summarize(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    groups: Dict[Tuple[object, object, object, object, object], List[Dict[str, object]]] = {}

    for row in rows:
        key = (
            row["iters"],
            row["operation"],
            row["threshold"],
            row["participants"],
            row["configuration"],
        )
        groups.setdefault(key, []).append(row)

    out: List[Dict[str, object]] = []

    for key, group in sorted(groups.items(), key=lambda kv: str(kv[0])):
        iters, operation, threshold, participants, configuration = key
        avg_values = [float(r["avg_us"]) for r in group]
        min_values = [float(r["min_us"]) for r in group]
        max_values = [float(r["max_us"]) for r in group]

        out.append({
            "iters": iters,
            "operation": operation,
            "threshold": threshold,
            "participants": participants,
            "configuration": configuration,
            "process_reps": len(group),
            "avg_us_median": statistics.median(avg_values),
            "avg_us_mean": statistics.mean(avg_values),
            "avg_us_stdev": stdev(avg_values),
            "avg_us_p05": percentile(avg_values, 5),
            "avg_us_p25": percentile(avg_values, 25),
            "avg_us_p75": percentile(avg_values, 75),
            "avg_us_p95": percentile(avg_values, 95),
            "min_us_min": min(min_values),
            "max_us_max": max(max_values),
        })

    return out


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        path.write_text("")
        return

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def config_sort_key(config: str) -> Tuple[int, int]:
    try:
        t, n = str(config).split("/")
        return int(t), int(n)
    except Exception:
        return 999, 999


def operation_sort_key(op: str):
    try:
        return OPERATION_ORDER.index(op)
    except ValueError:
        return len(OPERATION_ORDER), op


def choose_iters(summary_rows: List[Dict[str, object]], requested: Optional[int]) -> int:
    iters = sorted({int(r["iters"]) for r in summary_rows if r.get("iters") not in (None, "")})

    if not iters:
        raise SystemExit("No iteration count found in parsed benchmark results.")

    if requested is not None:
        if requested not in iters:
            raise SystemExit(f"Requested --iters {requested}, but available values are: {iters}")
        return requested

    return iters[-1]


def index_summary_rows(
    summary_rows: List[Dict[str, object]],
    chosen_iters: int,
) -> Dict[Tuple[str, str], Dict[str, object]]:
    idx: Dict[Tuple[str, str], Dict[str, object]] = {}

    for row in summary_rows:
        if int(row["iters"]) != chosen_iters:
            continue
        idx[(str(row["configuration"]), str(row["operation"]))] = row

    return idx


def available_configs(summary_rows: List[Dict[str, object]], chosen_iters: int) -> List[str]:
    return sorted(
        {str(r["configuration"]) for r in summary_rows if int(r["iters"]) == chosen_iters},
        key=config_sort_key,
    )


def paper_operations(
    idx: Dict[Tuple[str, str], Dict[str, object]],
    configs: List[str],
    include_optional: bool,
) -> List[str]:
    ops = list(DEFAULT_PAPER_OPERATIONS)

    if include_optional:
        if any((c, "nonce_create") in idx for c in configs):
            ops.insert(0, "nonce_create")
        if any((c, "dealer_keygen") in idx for c in configs):
            ops.append("dealer_keygen")

    return ops


def fmt_num(x: object) -> str:
    if x is None or x == "":
        return "--"

    try:
        v = float(x)
    except Exception:
        return "--"

    if v >= 100:
        return f"{v:.1f}"
    if v >= 10:
        return f"{v:.2f}"
    return f"{v:.3f}"


def fmt_iqr(row: Optional[Dict[str, object]]) -> str:
    if row is None:
        return "--"
    try:
        p25 = float(row["avg_us_p25"])
        p75 = float(row["avg_us_p75"])
    except Exception:
        return "--"
    return f"{fmt_num(p25)}--{fmt_num(p75)}"


def write_paper_table_csv(
    path: Path,
    idx: Dict[Tuple[str, str], Dict[str, object]],
    configs: List[str],
) -> None:
    ops = ["nonce_create", "sign_share", "aggregate", "verify", "dealer_keygen"]
    table: List[Dict[str, object]] = []

    for config in configs:
        row: Dict[str, object] = {"configuration": config}
        for op in ops:
            match = idx.get((config, op))
            row[f"{op}_median_us"] = (
                f"{float(match['avg_us_median']):.3f}" if match is not None else ""
            )
            row[f"{op}_iqr_us"] = fmt_iqr(match) if match is not None else ""
        table.append(row)

    write_csv(path, table)


def latex_simple_table(
    idx: Dict[Tuple[str, str], Dict[str, object]],
    configs: List[str],
    ops: List[str],
) -> str:
    colspec = "l" + "r" * len(ops)
    header_ops = " & ".join(OPERATION_LABELS.get(op, op) for op in ops)

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Microbenchmark results for the main FROST online operations. Times are reported in microseconds.}",
        r"\label{tab:frost-benchmarks}",
        rf"\begin{{tabular}}{{{colspec}}}",
        r"\toprule",
        rf"Configuration & {header_ops} \\",
        r"\midrule",
    ]

    for config in configs:
        vals = []
        for op in ops:
            row = idx.get((config, op))
            vals.append(fmt_num(row["avg_us_median"]) if row is not None else "--")
        lines.append(rf"{config} & " + " & ".join(vals) + r" \\")

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
        "",
    ])

    return "\n".join(lines)


def latex_iqr_table(
    idx: Dict[Tuple[str, str], Dict[str, object]],
    configs: List[str],
    ops: List[str],
) -> str:
    colspec = "l" + "r" * len(ops)
    header_ops = " & ".join(OPERATION_LABELS.get(op, op) for op in ops)

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        r"\caption{Microbenchmark results for the main FROST online operations. Times are reported in microseconds as median [IQR] across repeated executions.}",
        r"\label{tab:frost-benchmarks-iqr}",
        rf"\begin{{tabular}}{{{colspec}}}",
        r"\toprule",
        rf"Configuration & {header_ops} \\",
        r"\midrule",
    ]

    for config in configs:
        vals = []
        for op in ops:
            row = idx.get((config, op))
            if row is None:
                vals.append("--")
            else:
                vals.append(rf"{fmt_num(row['avg_us_median'])} [{fmt_iqr(row)}]")
        lines.append(rf"{config} & " + " & ".join(vals) + r" \\")

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\vspace{0.3em}",
        r"\begin{flushleft}",
        r"\footnotesize Values report the median of the benchmark averages across repeated executions; brackets show the interquartile range.",
        r"\end{flushleft}",
        r"\end{table}",
        "",
    ])

    return "\n".join(lines)


def write_latex_tables(
    outdir: Path,
    idx: Dict[Tuple[str, str], Dict[str, object]],
    configs: List[str],
    ops: List[str],
) -> None:
    (outdir / "frost_bench_table.tex").write_text(
        latex_simple_table(idx, configs, ops)
    )
    (outdir / "frost_bench_table_with_iqr.tex").write_text(
        latex_iqr_table(idx, configs, ops)
    )


def plot_clean_scaling(
    outdir: Path,
    idx: Dict[Tuple[str, str], Dict[str, object]],
    configs: List[str],
) -> None:
    import matplotlib.pyplot as plt

    xs = list(range(len(configs)))

    def configs_for(op: str) -> List[str]:
        return [c for c in configs if (c, op) in idx]

    # Main scaling plot: one line per operation.
    fig = plt.figure(figsize=(6.6, 4.2))
    ax = fig.add_subplot(111)

    for op in DEFAULT_PAPER_OPERATIONS:
        cs = configs_for(op)
        if not cs:
            continue
        ax.plot(
            [configs.index(c) for c in cs],
            [float(idx[(c, op)]["avg_us_median"]) for c in cs],
            marker="o",
            label=OPERATION_LABELS[op],
        )

    ax.set_xticks(xs)
    ax.set_xticklabels(configs)
    ax.set_xlabel("Threshold configuration")
    ax.set_ylabel("Median time (µs)")
    # ax.set_title("FROST online-operation scaling")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(outdir / "frost_bench_scaling.pdf")
    plt.close(fig)


def plot_boxplot(
    outdir: Path,
    long_rows: List[Dict[str, object]],
    chosen_iters: int,
) -> None:
    import matplotlib.pyplot as plt

    rows = [r for r in long_rows if r["iters"] == chosen_iters]
    configs = sorted({str(r["configuration"]) for r in rows}, key=config_sort_key)

    labels: List[str] = []
    samples: List[List[float]] = []

    for config in configs:
        for op in DEFAULT_PAPER_OPERATIONS:
            vals = [
                float(r["avg_us"])
                for r in rows
                if str(r["configuration"]) == config and str(r["operation"]) == op
            ]
            if vals:
                labels.append(f"{OPERATION_LABELS[op]}\n{config}")
                samples.append(vals)

    if not samples:
        return

    fig = plt.figure(figsize=(max(8, len(labels) * 0.85), 4.8))
    ax = fig.add_subplot(111)
    ax.boxplot(samples, labels=labels, showmeans=True)
    ax.set_ylabel("Average time per benchmark execution (µs)")
    ax.set_title("FROST benchmark variability")
    ax.grid(axis="y", alpha=0.3)

    for tick in ax.get_xticklabels():
        tick.set_rotation(45)
        tick.set_ha("right")

    fig.tight_layout()
    fig.savefig(outdir / "frost_bench_boxplot.pdf")
    plt.close(fig)


def cleanup_old_plots(outdir: Path) -> None:
    for name in [
        "bench_summary_bar_iqr.pdf",
        "bench_summary.pdf",
    ]:
        path = outdir / name
        if path.exists():
            path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_dir", type=Path, help="Directory containing raw benchmark logs")
    parser.add_argument("--outdir", type=Path, default=None, help="Output directory")
    parser.add_argument("--iters", type=int, default=None, help="Iteration count to use if several are present")
    parser.add_argument("--include-optional", action="store_true", help="Include nonce_create/dealer_keygen in LaTeX tables if available")
    parser.add_argument("--plots", action="store_true", help="Generate clean paper plots")
    parser.add_argument("--boxplot", action="store_true", help="Generate process-level boxplot")
    parser.add_argument("--keep-old-plots", action="store_true", help="Do not delete old grouped bar plots if present")
    args = parser.parse_args()

    outdir = args.outdir or args.raw_dir.parent
    outdir.mkdir(parents=True, exist_ok=True)

    if not args.keep_old_plots:
        cleanup_old_plots(outdir)

    logs = sorted(args.raw_dir.glob("*.txt"))
    if not logs:
        raise SystemExit(f"No .txt logs found in {args.raw_dir}")

    long_rows: List[Dict[str, object]] = []
    for path in logs:
        long_rows.extend(parse_log(path))

    if not long_rows:
        raise SystemExit("No benchmark rows parsed. Inspect raw logs and adjust the parser.")

    summary_rows = summarize(long_rows)
    chosen_iters = choose_iters(summary_rows, args.iters)

    idx = index_summary_rows(summary_rows, chosen_iters)
    configs = available_configs(summary_rows, chosen_iters)
    ops = paper_operations(idx, configs, args.include_optional)

    write_csv(outdir / "bench_results_long.csv", long_rows)
    write_csv(outdir / "bench_results_summary.csv", summary_rows)
    write_paper_table_csv(outdir / "bench_results_table.csv", idx, configs)
    write_latex_tables(outdir, idx, configs, ops)

    if args.plots:
        plot_clean_scaling(outdir, idx, configs)

    if args.boxplot:
        plot_boxplot(outdir, long_rows, chosen_iters)

    print(f"Parsed {len(long_rows)} benchmark rows from {len(logs)} logs.")
    print(f"Using iters={chosen_iters}")
    print(f"Wrote {outdir / 'bench_results_long.csv'}")
    print(f"Wrote {outdir / 'bench_results_summary.csv'}")
    print(f"Wrote {outdir / 'bench_results_table.csv'}")
    print(f"Wrote {outdir / 'frost_bench_table.tex'}")
    print(f"Wrote {outdir / 'frost_bench_table_with_iqr.tex'}")
    if args.plots:
        print(f"Wrote clean scaling plots to {outdir}")
    if args.boxplot:
        print(f"Wrote boxplot to {outdir}")


if __name__ == "__main__":
    main()
