"""Localization-accuracy head-to-head sweep: MCP vs faithful SprayCheck-Z and
FlowPulse-theta localizers, on identical sprayed traffic (see
`localization.py` for the fairness argument, the primary-source localization
rules, and the topology). Parallels `run_comparison_sweep.py` (detection), but
scores WHICH directed link each arm names, not just whether it detects.

Run from the repo root: `python3 -m sim.baselines.run_localization_sweep`
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from sim.baselines.comparison import SprayCheckDetectorCalibration, wilson_ci
from sim.baselines.localization import (
    ArmLocalization, CounterPairLocalizer, FlowPulseLocalizer, Link, MCPLocalizer,
    SprayCheckLocalizer, mcp_link_counters, score_localization, simulate_epoch,
)

OUTPUT_PATH = "docs/review/artifacts/LOCALIZATION-COMPARISON-SWEEP-2026-09-03.json"
ARMS = ("mcp", "spraycheck", "flowpulse")
# CounterPair-0B read skew (fraction of the epoch): idealized 0 and the
# best case measured on the Tofino (2.6 ms pairwise read vs a 100 ms epoch,
# READ-LOOP-BENCH-2026-09-03.md).
COUNTERPAIR_SKEWS = (0.0, 2.6e-2)


@dataclass
class TrialResult:
    mcp: ArmLocalization
    spraycheck: ArmLocalization
    flowpulse: ArmLocalization
    counterpair: Dict[float, ArmLocalization] = None  # skew -> outcome


def _faulty_link(family: str) -> Link:
    if family == "down":
        return ("down", 0, 0)
    if family == "up":
        return ("up", 1, 0)
    raise ValueError(f"unknown family {family!r}")


def run_one_trial(family: str, faulty_rate: float, healthy_rate: float,
                  n_leaves: int, k: int, packets_per_pair: int,
                  bootstrap_epochs: int, max_post_onset_epochs: int, seed: int,
                  spraycheck_s: float) -> TrialResult:
    import numpy as np
    rng = np.random.default_rng(seed)
    faulty = _faulty_link(family)

    mcp = MCPLocalizer()
    cps = {sk: CounterPairLocalizer(sk, seed) for sk in COUNTERPAIR_SKEWS}
    senders = [a for a in range(n_leaves) if a != 0]
    fp = FlowPulseLocalizer(spine=0, dst=0, senders=senders)
    sc = SprayCheckLocalizer(n_leaves, k, spraycheck_s)

    # Bootstrap: fully healthy traffic. MCP builds its floor; FlowPulse learns
    # its per-port and per-sender baselines; SprayCheck needs no bootstrap.
    epoch = 0
    for _ in range(bootstrap_epochs):
        draw = simulate_epoch(n_leaves, k, None, faulty_rate, healthy_rate,
                              packets_per_pair, rng)
        counters = mcp_link_counters(draw, n_leaves, k)
        mcp.tick(epoch, counters)
        for cp in cps.values():
            cp.tick(epoch, counters)
        fp.observe(draw)
        epoch += 1

    mcp_res: Optional[ArmLocalization] = None
    sc_res: Optional[ArmLocalization] = None
    fp_res: Optional[ArmLocalization] = None
    cp_res: Dict[float, Optional[ArmLocalization]] = {sk: None for sk in COUNTERPAIR_SKEWS}

    for _ in range(max_post_onset_epochs):
        draw = simulate_epoch(n_leaves, k, faulty, faulty_rate, healthy_rate,
                              packets_per_pair, rng)

        counters = mcp_link_counters(draw, n_leaves, k)
        rejected = mcp.tick(epoch, counters)
        if mcp_res is None and rejected:
            mcp_res = score_localization(rejected, faulty, True)
        for sk, cp in cps.items():
            cp_rej = cp.tick(epoch, counters)
            if cp_res[sk] is None and cp_rej:
                cp_res[sk] = score_localization(cp_rej, faulty, True)

        detected, localized = sc.observe_and_localize(draw)
        if sc_res is None and detected:
            sc_res = score_localization(localized, faulty, True)

        if fp_res is None:
            detected, localized = fp.localize(draw)
            if detected:
                fp_res = score_localization(localized, faulty, True)

        epoch += 1
        if (mcp_res is not None and sc_res is not None and fp_res is not None
                and all(v is not None for v in cp_res.values())):
            break

    miss = ArmLocalization(detected=False, exact=False, wrong=False, cardinality=None)
    return TrialResult(mcp=mcp_res or miss, spraycheck=sc_res or miss,
                       flowpulse=fp_res or miss,
                       counterpair={sk: (cp_res[sk] or miss) for sk in COUNTERPAIR_SKEWS})


def sweep(families, loss_rates, n_leaves: int = 4, k: int = 8,
          healthy_rate: float = 1e-5, packets_per_pair: int = 2_000_000,
          bootstrap_epochs: int = 10, max_post_onset_epochs: int = 60,
          trials: int = 50, spraycheck_calibration_lam: float = 2_500_000
          ) -> Dict[Tuple[str, float], List[TrialResult]]:
    s = SprayCheckDetectorCalibration.get(spraycheck_calibration_lam)
    results: Dict[Tuple[str, float], List[TrialResult]] = {}
    for family in families:
        for p in loss_rates:
            results[(family, p)] = [
                run_one_trial(family, p, healthy_rate, n_leaves, k,
                              packets_per_pair, bootstrap_epochs,
                              max_post_onset_epochs, seed, s)
                for seed in range(trials)
            ]
    return results


# ---------------------------------------------------------------------------
# Aggregation + paired statistics (all arms share each seed's stream).
# ---------------------------------------------------------------------------

def _outcome(t: TrialResult, arm: str) -> ArmLocalization:
    if arm.startswith("counterpair@"):
        return t.counterpair[float(arm.split("@", 1)[1])]
    return getattr(t, arm)


def summarize_arm(trials: List[TrialResult], arm: str) -> dict:
    outcomes = [_outcome(t, arm) for t in trials]
    n = len(outcomes)
    n_exact = sum(1 for o in outcomes if o.exact)
    n_wrong = sum(1 for o in outcomes if o.wrong)
    n_detected = sum(1 for o in outcomes if o.detected)
    n_miss = n - n_detected
    cards = [o.cardinality for o in outcomes if o.cardinality is not None]
    mean_card = sum(cards) / len(cards) if cards else None
    return {
        "n": n,
        "exact_rate": n_exact / n,
        "exact_ci95": wilson_ci(n_exact, n),
        "wrong_rate": n_wrong / n,
        "wrong_ci95": wilson_ci(n_wrong, n),
        "miss_rate": n_miss / n,
        "miss_ci95": wilson_ci(n_miss, n),
        "mean_cardinality": mean_card,
        "cardinality_ci95": bootstrap_mean_ci(cards) if cards else None,
        "n_detected": n_detected,
    }


def bootstrap_mean_ci(values: List[float], iters: int = 10000, seed: int = 0,
                      alpha: float = 0.05) -> Tuple[float, float]:
    """Percentile bootstrap CI for a mean -- the cardinalities are small
    integers with a skewed, bounded distribution, so a normal-approx CI would
    misstate the tails; the bootstrap makes no shape assumption."""
    import numpy as np
    if not values:
        return (float("nan"), float("nan"))
    if len(set(values)) == 1:
        return (float(values[0]), float(values[0]))
    rng = np.random.default_rng(seed)
    arr = np.asarray(values, dtype=float)
    means = arr[rng.integers(0, len(arr), size=(iters, len(arr)))].mean(axis=1)
    lo = float(np.quantile(means, alpha / 2))
    hi = float(np.quantile(means, 1 - alpha / 2))
    return (lo, hi)


def mcnemar_exact(trials: List[TrialResult], arm_a: str, arm_b: str) -> dict:
    """Paired McNemar test on the binary 'exact localization' outcome, arm_a
    vs arm_b on the SAME per-seed stream. Reports the discordant counts, an
    exact binomial two-sided p-value (correct at the small discordant counts
    this sweep produces, where the chi-square approximation is unreliable), and
    the paired difference in exact-rate with its sign."""
    b = c = 0  # b: a exact & b not; c: b exact & a not
    for t in trials:
        ea = _outcome(t, arm_a).exact
        eb = _outcome(t, arm_b).exact
        if ea and not eb:
            b += 1
        elif eb and not ea:
            c += 1
    nd = b + c
    if nd == 0:
        p = 1.0
    else:
        # exact two-sided binomial test against Binom(nd, 0.5)
        tail = sum(math.comb(nd, i) for i in range(0, min(b, c) + 1)) * (0.5 ** nd)
        p = min(1.0, 2.0 * tail)
    n = len(trials)
    return {"b_%s_only" % arm_a: b, "c_%s_only" % arm_b: c,
            "discordant": nd, "p_value": p,
            "exact_rate_diff": (sum(_outcome(t, arm_a).exact for t in trials)
                                - sum(_outcome(t, arm_b).exact for t in trials)) / n}


def main() -> None:
    families = ("down", "up")
    loss_rates = [0.015, 0.01, 0.005, 1e-3, 1e-4]
    results = sweep(families, loss_rates, trials=50)

    report: Dict[str, dict] = {}
    for (family, p), trials in results.items():
        key = f"{family}@{p}"
        cp_arms = tuple(f"counterpair@{sk}" for sk in COUNTERPAIR_SKEWS)
        report[key] = {arm: summarize_arm(trials, arm) for arm in ARMS + cp_arms}
        report[key]["paired_mcp_vs_spraycheck"] = mcnemar_exact(trials, "mcp", "spraycheck")
        report[key]["paired_mcp_vs_flowpulse"] = mcnemar_exact(trials, "mcp", "flowpulse")
        for a in cp_arms:
            report[key][f"paired_mcp_vs_{a}"] = mcnemar_exact(trials, "mcp", a)
        print(f"[{key}]", flush=True)
        for arm in ARMS + cp_arms:
            r = report[key][arm]
            print(f"  {arm}: exact={r['exact_rate']:.2f}{tuple(round(x,2) for x in r['exact_ci95'])} "
                  f"wrong={r['wrong_rate']:.2f} miss={r['miss_rate']:.2f} "
                  f"meancard={r['mean_cardinality']}", flush=True)

    with open(OUTPUT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"done -> {OUTPUT_PATH}", flush=True)


if __name__ == "__main__":
    main()
