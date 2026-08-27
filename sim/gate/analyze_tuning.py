#!/usr/bin/env python3
"""PREREG §3.2: select each arm's configuration on the tuning split and freeze it.

Reads sim/gate/results_tuning/<arm>/b<budget>/cfg<i>/{args, seed<s>.csv}, computes TTL from onset
per run (censored at the horizon), ranks configurations by (median TTL, censor fraction, mean TTL)
per arm and budget, prints the table, and writes conf/tuned/<arm>.yaml with the selected args per
budget plus the tuning statistics (so the selection is auditable).
"""
import csv
import glob
import os
import statistics
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_tuning")
CONF = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "conf", "tuned")
ONSET_EPOCH = 5   # 500 ms onset / 100 ms epochs


def ttl(path):
    rows = list(csv.DictReader(open(path)))
    hor = int(rows[-1]["epoch"])
    for r in rows:
        if int(r["epoch"]) >= ONSET_EPOCH and r["correct"] == "1":
            return int(r["epoch"]) - ONSET_EPOCH, False
    return hor - ONSET_EPOCH, True


def main():
    os.makedirs(CONF, exist_ok=True)
    for arm in sorted(os.listdir(ROOT)):
        out_lines = [f"# selected on the tuning split (seeds 6-10, LULESH-128) by analyze_tuning.py\narm: {arm}\n"]
        for bdir in sorted(os.listdir(os.path.join(ROOT, arm))):
            table = []
            for cdir in sorted(glob.glob(os.path.join(ROOT, arm, bdir, "cfg*"))):
                files = [f for f in glob.glob(os.path.join(cdir, "seed*.csv")) if not f.endswith(".bridge.csv")]
                if not files:
                    continue
                ts = [ttl(f) for f in files]
                vals = [t for t, _ in ts]
                cens = sum(1 for _, c in ts if c) / len(ts)
                args = open(os.path.join(cdir, "args")).read().strip() if os.path.exists(os.path.join(cdir, "args")) else ""
                table.append((statistics.median(vals), cens, statistics.mean(vals), len(vals), os.path.basename(cdir), args))
            if not table:
                continue
            table.sort()
            print(f"\n== {arm} {bdir}: {len(table)} configs (median TTL, censored, mean, n) ==")
            for row in table[:5]:
                print(f"  {row[4]:6s} median={row[0]:.1f} cens={row[1]:.2f} mean={row[2]:.1f} n={row[3]}  {row[5]}")
            best = table[0]
            out_lines.append(f"{bdir}:\n  cfg: {best[4]}\n  args: \"{best[5]}\"\n  median_ttl: {best[0]}\n  censored: {best[1]:.2f}\n  mean_ttl: {best[2]:.2f}\n  n_seeds: {best[3]}\n  n_configs: {len(table)}\n")
        with open(os.path.join(CONF, f"{arm}.yaml"), "w") as f:
            f.write("".join(out_lines))
        print(f"wrote {CONF}/{arm}.yaml")


if __name__ == "__main__":
    if not os.path.isdir(ROOT):
        sys.exit("no results_tuning")
    main()
