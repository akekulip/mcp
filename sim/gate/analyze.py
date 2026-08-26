#!/usr/bin/env python3
"""Time-to-localize (TTL, in epochs) per seed from sim/gate/results/<trace>/<policy>/seed<N>.csv,
median/IQR per policy, and the PREREG §10 abort/tighten verdict."""
import csv
import statistics
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"


def ttl(path):
    """First epoch whose verdict is correct; (ttl, censored, horizon)."""
    horizon = 0
    with open(path) as f:
        for row in csv.DictReader(f):
            horizon = int(row["epoch"])
            if row["correct"] == "1":
                return int(row["epoch"]), False, horizon
    return horizon, True, horizon


def iqr(xs):
    q = statistics.quantiles(xs, n=4) if len(xs) >= 2 else [xs[0]] * 3
    return q[0], q[2]


def main():
    rows = []
    for trace_dir in sorted(RESULTS.iterdir()) if RESULTS.is_dir() else []:
        for pol_dir in sorted(trace_dir.iterdir()):
            per_seed = []
            for f in sorted(pol_dir.glob("seed*.csv")):
                t, cens, hor = ttl(f)
                per_seed.append((f.stem, t, cens, hor))
                print(f"{trace_dir.name},{pol_dir.name},{f.stem},ttl_epochs={t},censored={int(cens)},horizon={hor}")
            if per_seed:
                ts = [t for _, t, _, _ in per_seed]
                lo, hi = iqr(ts)
                rows.append((trace_dir.name, pol_dir.name, len(ts), statistics.median(ts), lo, hi,
                             sum(c for _, _, c, _ in per_seed) / len(ts)))
    print("\n| trace | policy | n | median TTL (epochs) | IQR | censored |")
    print("|---|---|---|---|---|---|")
    for tr, po, n, med, lo, hi, cf in rows:
        print(f"| {tr} | {po} | {n} | {med:g} | [{lo:g}, {hi:g}] | {cf:.0%} |")
    # PREREG §10 rule (TTL values for censored seeds are the horizon, so they are lower bounds)
    for tr, po, n, med, lo, hi, cf in rows:
        if po != "uniform":
            continue
        if med <= 2:
            v = "TOO EASY (uniform median TTL <= 2 epochs): tighten budget/loss and re-run"
        elif cf > 0.5:
            v = "TOO HARD (uniform censored in > 50% of seeds): loosen the operating point one step"
        elif med >= 5:
            v = "OK (uniform median TTL >= 5 epochs)"
        else:
            v = "TIGHTEN (uniform median TTL between 2 and 5 epochs)"
        print(f"PREREG verdict [{tr}]: {v}")
    return 0 if rows else 1


if __name__ == "__main__":
    sys.exit(main())
