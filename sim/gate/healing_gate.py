#!/usr/bin/env python3
"""healing_gate.py -- run the 30-seed result-gate pilot and print the decisive tables.

Answers the plan's Section 11 stop condition with numbers:

  Does the evidence-lease / audit / probation lifecycle Pareto-beat matched-cost baselines
  (fixed-timer, round-robin, capacity-weighted) at equal audit budget, with bounded unsafe
  restorations -- OR does a trivial baseline tie it under honest parameters?

For every (concurrency K, audit budget B) cell it runs 30 seeds and reports, per arm and
TOGETHER (cross-check discipline): median unsafe restorations, act-rate (fraction of links
ever restored), median stranded-capacity, and median certified-restore delay.

Honest-cost mapping (from docs/review/GATE2-AUDIT-BUDGET.md): one full certification audit is
~45 MB (clean 1e-4 ceiling) to ~209 MB (at the 1e-4 background F0 runs). A shared upstream port
carries, per 100 ms epoch:
    25 G:  312 MB/epoch -> ~7 clean or ~1.5 background audits/epoch
    100 G: 1.25 GB/epoch -> ~28 clean or ~6 background audits/epoch
    400 G: 5 GB/epoch    -> ~111 clean or ~24 background audits/epoch
These give the honest budgets annotated in the table.
"""
import argparse
import statistics
from typing import Dict, List

from sim.gate.healing import make_scenario, make_policy, run_policy, RunMetrics

EPOCH_MS = 100.0


def run_cell(n_links, budget, mean_recovery_epochs, frac_permanent, horizon, seeds,
             cap_choices, fire_epoch) -> Dict[str, List[RunMetrics]]:
    arms = ("oracle", "continuous_probe", "earliest_deadline", "round_robin",
            "capacity_weighted", "fixed_timer", "permanent_quarantine")
    out: Dict[str, List[RunMetrics]] = {a: [] for a in arms}
    for seed in range(seeds):
        sc = make_scenario(seed=seed, n_links=n_links, horizon_epochs=horizon,
                           audit_budget=budget, mean_recovery_epochs=mean_recovery_epochs,
                           frac_permanent=frac_permanent, capacity_choices=cap_choices)
        for a in arms:
            out[a].append(run_policy(sc, make_policy(a, sc, seed=seed, fire_epoch=fire_epoch)))
    return out


def med(xs):
    return statistics.median(xs) if xs else float("nan")


def print_cell(title, cell, n_links, budget, seeds, note=""):
    print(f"\n### {title}  (K={n_links} concurrent links, budget B={budget} audits/epoch, "
          f"{seeds} seeds){note}")
    print("| arm | med unsafe | act-rate | med stranded (Gbps*epoch) | med restore delay (epoch) |")
    print("|---|---|---|---|---|")
    for a, runs in cell.items():
        unsafe = med([r.unsafe_restores for r in runs])
        act = statistics.mean([r.act_rate for r in runs])
        strand = med([r.stranded_capacity_gbps_epochs for r in runs])
        delay = med([r.median_restore_delay for r in runs
                     if r.median_restore_delay == r.median_restore_delay])
        delay_s = f"{delay:.1f}" if delay == delay else "n/a"
        print(f"| {a} | {unsafe:.1f} | {act:.2f} | {strand:.0f} | {delay_s} |")


def pareto_verdict(cell):
    """Does earliest_deadline STRICTLY Pareto-beat round_robin (better on >=1 axis, worse on
    none), across the 30 seeds by median?  Same for capacity_weighted vs round_robin."""
    def summ(a):
        runs = cell[a]
        return (med([r.unsafe_restores for r in runs]),
                statistics.mean([r.act_rate for r in runs]),
                med([r.stranded_capacity_gbps_epochs for r in runs]))
    rr = summ("round_robin")
    ed = summ("earliest_deadline")
    cw = summ("capacity_weighted")
    lines = []
    # lifecycle vs round-robin: unsafe lower-is-better, act higher-is-better, stranded lower-is-better
    def cmp(name, x):
        better = (x[0] < rr[0]) or (x[1] > rr[1]) or (x[2] < rr[2])
        worse = (x[0] > rr[0]) or (x[1] < rr[1]) or (x[2] > rr[2])
        if better and not worse:
            return f"{name}: PARETO-BEATS round_robin"
        if x == rr:
            return f"{name}: TIES round_robin exactly"
        return f"{name}: does NOT Pareto-beat round_robin (better={better}, worse={worse})"
    lines.append(cmp("earliest_deadline (LIFECYCLE)", ed))
    lines.append(cmp("capacity_weighted", cw))
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--mean-recovery", type=float, default=20.0,
                    help="mean recovery epochs (100ms each); 20 = 2 s, deliberately short to "
                         "give the budget its best chance to bind")
    ap.add_argument("--frac-permanent", type=float, default=0.15)
    ap.add_argument("--horizon", type=int, default=200)
    a = ap.parse_args()

    print("# Healing result-gate pilot -- Section 11 stop condition")
    print(f"# {a.seeds} seeds, mean recovery {a.mean_recovery:.0f} epochs "
          f"({a.mean_recovery*EPOCH_MS/1000:.1f} s), frac_permanent={a.frac_permanent}, "
          f"horizon {a.horizon} epochs")
    print("# fixed_timer fires at 1.5x mean recovery; capacities heterogeneous {50,100,200} Gbps")

    fire = int(1.5 * a.mean_recovery)
    caps = (50.0, 100.0, 200.0)

    # Sweep concurrency K and audit budget B. The 'honest budget' annotations mark the B a shared
    # upstream port can actually sustain for full certification audits.
    matrix = [
        # (K, [budgets], note)
        (8,  [1, 2, 4, 8],        "  (single upstream port; honest B: 25G~1.5, 100G~6, 400G~24)"),
        (32, [1, 4, 8, 24, 32],   "  (2% of a ~1600-link fabric; honest B up to ~24 at 400G)"),
        (128,[4, 24, 64, 128],    "  (8% concurrent; even here 400G sustains ~24-111 audits/epoch)"),
    ]
    for K, budgets, note in matrix:
        print(f"\n\n## Concurrency K = {K}{note}")
        for B in budgets:
            cell = run_cell(n_links=K, budget=B, mean_recovery_epochs=a.mean_recovery,
                            frac_permanent=a.frac_permanent, horizon=a.horizon,
                            seeds=a.seeds, cap_choices=caps, fire_epoch=fire)
            print_cell(f"K={K}, B={B}", cell, K, B, a.seeds)
            for line in pareto_verdict(cell):
                print(f"    -> {line}")


if __name__ == "__main__":
    main()
