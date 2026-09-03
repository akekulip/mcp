"""Correlated / multi-link fault stress sweep (attack A4). Extends the
single-independent-fault head-to-head to the three correlated regimes defined in
`correlated.py` (R1 multi-independent, R2 common-mode shock, R3 shock+culprit),
with the same shared-stream fairness discipline and this repo's cross-checks:
an injected-quantity-in-the-DATA sanity (#2), a do-nothing/oracle sense-check
(#1), and false-positive reported next to the action/recall number (#4).

Both a UNION-over-window score (did the arm EVER name this link in the 40 epochs
after onset -- the safety-relevant "ever took this action") and a FINAL-epoch
score (steady state) are reported, so a transient false-positive burst is
distinguished from a persistent latch.

Run from repo root: python3 -m sim.baselines.run_correlated_stress
"""
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

from sim.baselines.comparison import SprayCheckDetectorCalibration, wilson_ci
from sim.baselines.correlated import (
    FleetFlowPulseLocalizer, MultiScore, score_multi, simulate_epoch_correlated,
)
from sim.baselines.localization import (
    Link, MCPLocalizer, SprayCheckLocalizer, mcp_link_counters,
)

OUTPUT_PATH = "docs/review/artifacts/CORRELATED-FAULT-STRESS-SWEEP-2026-09-03.json"

N_LEAVES = 4
K = 8
HEALTHY_RATE = 1e-5
PACKETS_PER_PAIR = 2_000_000
BOOTSTRAP_EPOCHS = 10
POST_ONSET_EPOCHS = 40
TRIALS = 50
SPRAYCHECK_LAM = 2_500_000

ARMS = ("mcp", "spraycheck", "flowpulse")


@dataclass
class Regime:
    name: str
    faulty_links: FrozenSet[Link]
    faulty_rate: float
    base_rate: float
    note: str


def regimes() -> List[Regime]:
    d00 = ("down", 0, 0)
    u13 = ("up", 1, 3)
    d52 = ("down", 5, 2)
    out: List[Regime] = []
    # R1 multi-independent (healthy background, M genuine faults)
    for rate in (0.005, 1e-3):
        out.append(Regime(f"R1_multi2@{rate:g}", frozenset({d00, u13}), rate,
                          HEALTHY_RATE, "two independent directed-link faults"))
        out.append(Regime(f"R1_multi3@{rate:g}", frozenset({d00, u13, d52}), rate,
                          HEALTHY_RATE, "three independent directed-link faults"))
    # R2 common-mode shock (all links elevated, NO single culprit)
    for shock in (0.005, 1e-3):
        out.append(Regime(f"R2_shock@{shock:g}", frozenset(), 0.0, shock,
                          "fleet-wide shock, no localizable single-link fault"))
    # R3 shock + one culprit above the shifted background
    out.append(Regime("R3_shock1e-3_culprit1e-2", frozenset({d00}), 1e-2, 1e-3,
                      "culprit 1% over a 0.1% common-mode shock"))
    out.append(Regime("R3_shock5e-3_culprit5e-2", frozenset({d00}), 5e-2, 5e-3,
                      "culprit 5% over a 0.5% common-mode shock"))
    return out


@dataclass
class ArmTrace:
    union: FrozenSet[Link]
    final: FrozenSet[Link]
    first_true_detect_epoch: Optional[int]
    max_false_simultaneous: int  # peak wrong links named in any single epoch


@dataclass
class TrialResult:
    arms: Dict[str, ArmTrace]
    realized_faulty_loss: float
    realized_background_loss: float


def run_one_trial(reg: Regime, seed: int, spraycheck_s: float) -> TrialResult:
    import numpy as np
    rng = np.random.default_rng(seed)

    mcp = MCPLocalizer()
    sc = SprayCheckLocalizer(N_LEAVES, K, spraycheck_s)
    fp = FleetFlowPulseLocalizer(N_LEAVES, K)

    # Bootstrap: fully healthy fabric (base = healthy floor, no faults), so MCP's
    # floor and FlowPulse's per-port baselines learn the healthy regime before
    # any shock/fault -- the shared-cause onset then hits a warmed detector.
    epoch = 0
    for _ in range(BOOTSTRAP_EPOCHS):
        draw = simulate_epoch_correlated(N_LEAVES, K, frozenset(), 0.0,
                                         HEALTHY_RATE, PACKETS_PER_PAIR, rng)
        mcp.tick(epoch, mcp_link_counters(draw, N_LEAVES, K))
        fp.observe(draw)
        epoch += 1

    traces = {a: {"union": set(), "final": frozenset(),
                  "first": None, "maxfalse": 0} for a in ARMS}
    f_tx = f_lost = b_tx = b_lost = 0
    true = reg.faulty_links

    for _ in range(POST_ONSET_EPOCHS):
        draw = simulate_epoch_correlated(N_LEAVES, K, reg.faulty_links,
                                         reg.faulty_rate, reg.base_rate,
                                         PACKETS_PER_PAIR, rng)
        counters = mcp_link_counters(draw, N_LEAVES, K)
        for link, (tx, rx) in counters.items():
            if link in true:
                f_tx += tx; f_lost += tx - rx
            else:
                b_tx += tx; b_lost += tx - rx

        per_arm_now: Dict[str, FrozenSet[Link]] = {}
        per_arm_now["mcp"] = mcp.tick(epoch, counters)
        _, per_arm_now["spraycheck"] = sc.observe_and_localize(draw)
        _, per_arm_now["flowpulse"] = fp.localize(draw)

        for a in ARMS:
            named = per_arm_now[a]
            t = traces[a]
            t["union"] |= set(named)
            t["final"] = named
            t["maxfalse"] = max(t["maxfalse"], len(set(named) - true))
            if t["first"] is None and (set(named) & true):
                t["first"] = epoch - BOOTSTRAP_EPOCHS  # epochs since onset
        epoch += 1

    arms = {a: ArmTrace(frozenset(traces[a]["union"]), traces[a]["final"],
                        traces[a]["first"], traces[a]["maxfalse"]) for a in ARMS}
    return TrialResult(
        arms=arms,
        realized_faulty_loss=(f_lost / f_tx) if f_tx else float("nan"),
        realized_background_loss=(b_lost / b_tx) if b_tx else float("nan"),
    )


def _summ_scores(scores: List[MultiScore], firsts: List[Optional[int]],
                 maxfalse: List[int], n: int) -> dict:
    has_true = scores[0].n_true > 0
    detect = sum(1 for s in scores if s.detected)
    any_false = sum(1 for s in scores if s.any_false)
    mean_false = statistics.mean(s.n_false for s in scores)
    mean_localn = statistics.mean(s.localized_n for s in scores)
    out = {
        "n": n,
        "detect_rate": detect / n,
        "detect_ci95": wilson_ci(detect, n),
        "fp_rate": any_false / n,
        "fp_ci95": wilson_ci(any_false, n),
        "mean_false_links": mean_false,
        "mean_localized_size": mean_localn,
        "max_false_simultaneous_over_seeds": max(maxfalse) if maxfalse else 0,
    }
    if has_true:
        out["recall_mean"] = statistics.mean(s.recall for s in scores)
        exact = sum(1 for s in scores if s.exact_all)
        out["exact_all_rate"] = exact / n
        out["exact_all_ci95"] = wilson_ci(exact, n)
        det_firsts = [f for f in firsts if f is not None]
        out["median_first_detect_epoch"] = (statistics.median(det_firsts)
                                            if det_firsts else None)
        out["n_true"] = scores[0].n_true
    return out


def summarize(trials: List[TrialResult], reg: Regime) -> dict:
    n = len(trials)
    block: dict = {
        "note": reg.note,
        "faulty_links": sorted(str(l) for l in reg.faulty_links),
        "faulty_rate": reg.faulty_rate,
        "base_rate": reg.base_rate,
        "realized_faulty_loss_mean": (
            statistics.mean(t.realized_faulty_loss for t in trials)
            if reg.faulty_links else None),
        "realized_background_loss_mean":
            statistics.mean(t.realized_background_loss for t in trials),
    }
    for a in ARMS:
        union_scores = [score_multi(t.arms[a].union, reg.faulty_links) for t in trials]
        final_scores = [score_multi(t.arms[a].final, reg.faulty_links) for t in trials]
        firsts = [t.arms[a].first_true_detect_epoch for t in trials]
        maxfalse = [t.arms[a].max_false_simultaneous for t in trials]
        block[a] = {
            "union_over_window": _summ_scores(union_scores, firsts, maxfalse, n),
            "final_epoch": _summ_scores(final_scores, firsts, maxfalse, n),
        }
    # cross-check #4 anchors: do-nothing (never acts) and oracle (perfect).
    block["_anchors"] = {
        "do_nothing": {"fp_rate": 0.0, "recall": 0.0 if reg.faulty_links else None},
        "oracle": {"fp_rate": 0.0,
                   "recall": 1.0 if reg.faulty_links else None,
                   "note": "returns exactly the injected set; recall<1 here "
                           "would mean the injector is broken (cross-check #1)"},
    }
    return block


def main() -> None:
    s = SprayCheckDetectorCalibration.get(SPRAYCHECK_LAM)
    print(f"calibrated s = {s:.4f}", flush=True)
    report: Dict[str, dict] = {"_config": {
        "n_leaves": N_LEAVES, "k": K, "healthy_rate": HEALTHY_RATE,
        "packets_per_pair": PACKETS_PER_PAIR, "bootstrap_epochs": BOOTSTRAP_EPOCHS,
        "post_onset_epochs": POST_ONSET_EPOCHS, "trials": TRIALS,
        "spraycheck_s": s}}
    for reg in regimes():
        trials = [run_one_trial(reg, seed, s) for seed in range(TRIALS)]
        block = summarize(trials, reg)
        report[reg.name] = block
        fl = block["realized_faulty_loss_mean"]
        bl = block["realized_background_loss_mean"]
        print(f"\n[{reg.name}] {reg.note}", flush=True)
        print(f"  realized loss: faulty={fl if fl is None else round(fl,5)} "
              f"background={round(bl,6)}", flush=True)
        for a in ARMS:
            u = block[a]["union_over_window"]
            extra = ""
            if "recall_mean" in u:
                extra = (f" recall={u['recall_mean']:.2f} "
                         f"exact_all={u['exact_all_rate']:.2f} "
                         f"first_detect_ep={u['median_first_detect_epoch']}")
            print(f"  {a:11s} UNION detect={u['detect_rate']:.2f} "
                  f"fp={u['fp_rate']:.2f} mean_false={u['mean_false_links']:.2f} "
                  f"maxfalse_simul={u['max_false_simultaneous_over_seeds']}{extra}",
                  flush=True)
            fin = block[a]["final_epoch"]
            print(f"  {' ':11s} FINAL fp={fin['fp_rate']:.2f} "
                  f"mean_false={fin['mean_false_links']:.2f}", flush=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\ndone -> {OUTPUT_PATH}", flush=True)


if __name__ == "__main__":
    main()
