#!/usr/bin/env python3
"""
results/plot_cpu_util.py
Plots per-second CPU utilization for conditions B (EEVDF + cpu.max) and
D (scx_lavd + cpu.max) against the cpu.max quota limit.

Reads:  results/B/cpu_util.csv
        results/D/cpu_util.csv
Writes: results/cpu_util_comparison.svg
        results/cpu_util_comparison.png
"""

import csv
import sys
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    sys.exit(
        "matplotlib not found.\n"
        "  Arch/CachyOS: sudo pacman -S python-matplotlib\n"
        "  Ubuntu:       sudo apt install python3-matplotlib\n"
        "  pip:          pip install matplotlib"
    )

RESULTS_DIR = Path(__file__).parent

SERIES = {
    "B": {"label": "EEVDF (cpu.max on)",    "color": "#e15759"},
    "D": {"label": "scx_lavd (cpu.max on)", "color": "#4e79a7"},
}


def read_csv(path: Path):
    """Return (times, utils, limit_pct), skipping comment lines."""
    times, utils, limit = [], [], None
    with path.open() as f:
        reader = csv.DictReader(row for row in f if not row.startswith("#"))
        for row in reader:
            times.append(float(row["time_s"]))
            utils.append(float(row["util_pct"]))
            if limit is None:
                limit = float(row["limit_pct"])
    return times, utils, limit


fig, ax = plt.subplots(figsize=(12, 5))

limit_drawn = False
found_any = False

for cond, style in SERIES.items():
    csv_path = RESULTS_DIR / cond / "cpu_util.csv"
    if not csv_path.exists():
        print(f"Warning: {csv_path} not found, skipping condition {cond}", file=sys.stderr)
        continue
    times, utils, limit = read_csv(csv_path)
    ax.plot(times, utils, color=style["color"], label=style["label"],
            linewidth=1.2, alpha=0.9)
    if limit is not None and not limit_drawn:
        ax.axhline(limit, color="black", linestyle="--", linewidth=1.0,
                   label=f"cpu.max limit ({limit:.0f}%)")
        limit_drawn = True
    found_any = True

if not found_any:
    sys.exit("No cpu_util.csv files found in results/B/ or results/D/.")

ax.set_xlabel("Time (s)")
ax.set_ylabel("CPU Utilization (% of all CPUs)")
ax.set_title("cpu.max Enforcement: EEVDF vs scx_lavd — per-second CPU utilization")
ax.yaxis.set_major_formatter(ticker.FormatStrFormatter("%.0f%%"))
ax.set_ylim(bottom=0)
ax.legend()
ax.grid(True, alpha=0.3)
plt.tight_layout()

for suffix, fmt, kwargs in [
    ("svg", "svg", {}),
    ("png", "png", {"dpi": 150}),
]:
    out = RESULTS_DIR / f"cpu_util_comparison.{suffix}"
    plt.savefig(out, format=fmt, **kwargs)
    print(f"Saved: {out}")
