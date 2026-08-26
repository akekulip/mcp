#!/usr/bin/env python3
"""PREREG §10 gate outputs from results_real/<trace>/<policy>/seed<N>.{csv,onset,finish,time}.

Per seed: TTL = first epoch with a correct verdict, counted from the onset epoch (epochs before
onset cannot localize a fault that has not started). Right-censored at the last epoch of the run.
Per policy: n, censor fraction, median/IQR TTL (KM-free median of uncensored+censored-at-horizon,
as analyze.py), Kaplan–Meier survival table, CV of log-TTL (uncensored seeds), and Pearson rho
between uniform and random log-TTL on seeds uncensored in both. Ends with the §10 abort/tighten
verdict. Usage: analyze_real.py [results_real_dir] [--epoch-us 100000] [--km]
"""
import argparse
import csv
import math
import statistics
import sys
from pathlib import Path


def read_run(csv_path: Path, onset_us: float, epoch_us: float):
    onset_epoch = int(onset_us // epoch_us)
    horizon = 0
    ttl = None
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            e = int(row["epoch"])
            horizon = e
            if ttl is None and e >= onset_epoch and row["correct"] == "1":
                ttl = e - onset_epoch
    if ttl is None:
        return max(horizon - onset_epoch, 0), True, horizon, onset_epoch
    return ttl, False, horizon, onset_epoch


def km_table(times, censored):
    """Kaplan–Meier S(t) at each distinct event time."""
    pts = sorted(set(t for t, c in zip(times, censored) if not c))
    n_at_risk = len(times)
    s = 1.0
    out = []
    items = sorted(zip(times, censored))
    idx = 0
    for t in pts:
        # remove those with time < t (events or censorings) from the risk set
        while idx < len(items) and items[idx][0] < t:
            n_at_risk -= 1
            idx += 1
        d = sum(1 for tt, c in items if tt == t and not c)
        if n_at_risk > 0:
            s *= 1 - d / n_at_risk
        out.append((t, n_at_risk, d, s))
    return out


def iqr(xs):
    if len(xs) < 2:
        return xs[0], xs[0]
    q = statistics.quantiles(xs, n=4)
    return q[0], q[2]


def pearson(xs, ys):
    if len(xs) < 3:
        return float("nan")
    mx, my = statistics.mean(xs), statistics.mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return float("nan")
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / math.sqrt(sxx * syy)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="?", default=str(Path(__file__).resolve().parent / "results_real"))
    ap.add_argument("--epoch-us", type=float, default=100000.0)
    ap.add_argument("--km", action="store_true", help="print Kaplan–Meier tables")
    a = ap.parse_args()
    root = Path(a.results)
    if not root.is_dir():
        sys.exit(f"no results dir {root}")

    per = {}  # (trace, policy) -> {seed: (ttl, censored)}
    for trace_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for pol_dir in sorted(p for p in trace_dir.iterdir() if p.is_dir()):
            for f in sorted(pol_dir.glob("seed*.csv")):
                onset_file = f.with_suffix(".onset")
                onset_us = float(onset_file.read_text().strip()) * 1000.0 if onset_file.exists() else 0.0
                ttl, cens, hor, oe = read_run(f, onset_us, a.epoch_us)
                fin = f.with_suffix(".finish")
                fin_s = fin.read_text().strip().split("(")[-1].rstrip(")") if fin.exists() else "?"
                tim = f.with_suffix(".time")
                wall = tim.read_text().strip() if tim.exists() else ""
                per.setdefault((trace_dir.name, pol_dir.name), {})[f.stem] = (ttl, cens)
                print(f"{trace_dir.name},{pol_dir.name},{f.stem},onset_epoch={oe},ttl_epochs={ttl},"
                      f"censored={int(cens)},horizon={hor},finish={fin_s},{wall}")

    print("\n| trace | policy | n | median TTL (epochs) | IQR | censored | CV(log TTL, uncens.) |")
    print("|---|---|---|---|---|---|---|")
    rows = {}
    for (trace, pol), d in sorted(per.items()):
        ts = [t for t, _ in d.values()]
        cs = [c for _, c in d.values()]
        unc = [t for t, c in d.values() if not c and t > 0]
        cv = (statistics.stdev([math.log(t) for t in unc]) / abs(statistics.mean([math.log(t) for t in unc]))
              if len(unc) >= 2 and statistics.mean([math.log(t) for t in unc]) != 0 else float("nan"))
        lo, hi = iqr(ts)
        cens_frac = sum(cs) / len(cs)
        rows[(trace, pol)] = (statistics.median(ts), cens_frac)
        print(f"| {trace} | {pol} | {len(ts)} | {statistics.median(ts):.0f} | [{lo:.0f}, {hi:.0f}] | "
              f"{cens_frac:.0%} | {cv:.2f} |")
        if a.km:
            print(f"  KM {trace}/{pol}: " + ", ".join(f"t={t}:S={s:.2f}(n={n},d={dd})" for t, n, dd, s in km_table(ts, cs)))

    # rho between uniform (B3) and random (B9) log-TTL on seeds uncensored in both
    for trace in sorted({t for t, _ in per}):
        u, r = per.get((trace, "uniform"), {}), per.get((trace, "random"), {})
        common = [s for s in u if s in r and not u[s][1] and not r[s][1] and u[s][0] > 0 and r[s][0] > 0]
        rho = pearson([math.log(u[s][0]) for s in common], [math.log(r[s][0]) for s in common])
        print(f"rho(uniform,random) log-TTL [{trace}]: {rho:.3f} on n={len(common)} seeds uncensored in both")

    for trace in sorted({t for t, _ in per}):
        med, cens = rows.get((trace, "uniform"), (None, None))
        if med is None:
            continue
        if cens > 0.5:
            v = "TOO HARD (uniform censored in > 50% of seeds): loosen the operating point one step"
        elif med <= 2:
            v = "TOO EASY (uniform median TTL <= 2 epochs): reduce budget to 0.5% and/or loss to 1e-5"
        elif med >= 5:
            v = "OK (uniform median TTL >= 5 epochs)"
        else:
            v = "BORDERLINE (uniform median TTL in (2,5) epochs): tighten one step"
        print(f"PREREG verdict [{trace}]: {v}")


if __name__ == "__main__":
    main()
