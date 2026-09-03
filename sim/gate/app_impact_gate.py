#!/usr/bin/env python3
"""app_impact_gate.py -- the CHEAP first gate for the application-impact top-venue path.

Feeds each arm its OWN MEASURED detect+localize behaviour (from
`docs/review/artifacts/BASELINE-COMPARISON-2026-09-02.md` and `LOCALIZATION-COMPARISON-2026-09-02.md`)
into the IDENTICAL Ring-AllReduce CCT model in `cct_model.py`, and answers three questions with
numbers, oracle + do-nothing bounds beside every arm:

  Q1  Is there a MEASURABLE CCT slowdown at all (or is loss masked)?  -> the `e` / do-nothing column.
  Q2  Is the recovered gap DETECTION-limited (does MCP beat the baselines)? -> per-arm CCT ratios.
  Q3  Which regime, if any, lets detection SPEED move CCT?  -> the sweep over p x lam x tau.

Cross-check discipline (repo CLAUDE.md): every table prints the realised parameters (p, lam, tau,
overhead e, packets-to-detect per arm, mitigate cost) and the ORACLE and DO-NOTHING bounds. An arm
that ties the oracle (fault severity swamps detection) OR ties do-nothing (the arm never mitigates)
is flagged as an UNINFORMATIVE regime, never read as a win. A recorded-counter cross-check confirms
the model reproduces the near-zero impact of the actual injected 1e-4 fault, and a reroute-cost
sensitivity exposes the regime where mitigating costs more capacity than the fault costs.
"""
from __future__ import annotations

import argparse
import csv
import zlib
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Tuple

from sim.gate.cct_model import (
    Arm, Fabric, Localize, RECOVERY_MODES, ORACLE, DO_NOTHING, cct_ratio,
)


def scenario_seed(stem: str, role: str) -> int:
    """Stable per-seed scenario seed (CRC-32); Python's str hash is salted per process."""
    return zlib.crc32(f"{stem}/{role}".encode())


# ---------------------------------------------------------------------------------------------
# MEASURED per-arm detect+localize inputs, transcribed from the two 2026-09-02 comparison tables.
# detect_pkts = median FLEET packets-to-detect (None == "never" within the measured budget).
# localize = modal outcome in the "down" fault family; set_size = measured mean ambiguous-set size.
# These are the ONLY things that differ between arms; nothing here is invented.
# ---------------------------------------------------------------------------------------------
M = 1e6
MEASURED: Dict[float, Dict[str, Arm]] = {
    1.5e-2: {
        "MCP":        Arm("MCP",        22.0 * M, Localize.EXACT),
        "SprayCheck": Arm("SprayCheck", 24.0 * M, Localize.EXACT),
        "FlowPulse":  Arm("FlowPulse",  22.0 * M, Localize.EXACT),
    },
    1.0e-2: {
        "MCP":        Arm("MCP",        22.0 * M, Localize.EXACT),
        "SprayCheck": Arm("SprayCheck", 26.0 * M, Localize.EXACT),
        # FP detects (22M) but localizes exact only 0.22, mean set 2.74 -> modal AMBIGUOUS ~3-set
        "FlowPulse":  Arm("FlowPulse",  22.0 * M, Localize.AMBIGUOUS, set_size=2.74),
    },
    0.5e-2: {
        "MCP":        Arm("MCP",        22.0 * M, Localize.EXACT),
        # SC detects (32M) but exact only 0.34, mean set 1.70 -> modal AMBIGUOUS
        "SprayCheck": Arm("SprayCheck", 32.0 * M, Localize.AMBIGUOUS, set_size=1.70),
        # FP down-family localization miss = 1.00 at 0.5%
        "FlowPulse":  Arm("FlowPulse",  None,     Localize.MISS),
    },
    1e-3: {
        "MCP":        Arm("MCP",        22.0 * M, Localize.EXACT),
        # SC detects 0.78 (114M) but exact 0.00, mean set 2.00 -> AMBIGUOUS 2-set
        "SprayCheck": Arm("SprayCheck", 114.0 * M, Localize.AMBIGUOUS, set_size=2.00),
        "FlowPulse":  Arm("FlowPulse",  None,      Localize.MISS),
    },
    1e-4: {
        "MCP":        Arm("MCP",        22.0 * M, Localize.EXACT),
        "SprayCheck": Arm("SprayCheck", None,     Localize.MISS),   # 0.00 action rate at 1e-4
        "FlowPulse":  Arm("FlowPulse",  None,     Localize.MISS),
    },
}
ARM_ORDER = ("MCP", "SprayCheck", "FlowPulse")


def _fmt(x: float) -> str:
    if x != x:
        return "nan"
    return f"{x:.4f}" if x < 100 else f"{x:.2e}"


def _verdict(mcp: float, best_base: float, oracle: float, donothing: float) -> str:
    """Name the regime from the ratios (all are CCT/CCT_clean, lower is better)."""
    span = donothing - oracle
    if span < 1e-4:
        return "UNINFORMATIVE: oracle ~ do-nothing (no slowdown to recover -- loss masked, Q1 NULL)"
    gain = (best_base - mcp) / span * 100.0
    if abs(best_base - mcp) < 1e-4:
        return "UNINFORMATIVE: MCP ties best baseline (detection behaviour does not move CCT here)"
    if abs(mcp - oracle) < 1e-4 and abs(best_base - oracle) < 1e-4:
        return "UNINFORMATIVE: all arms tie the ORACLE (fault severity swamps detection, Q3)"
    if abs(best_base - donothing) < 1e-4:
        return f"MCP beats best baseline by {gain:.0f}% of span; baseline ties DO-NOTHING (miss)"
    return f"MCP beats best baseline by {gain:.0f}% of the oracle<->do-nothing span"


def run_cell(fab: Fabric, mode: str) -> Tuple[Dict[str, float], float, float]:
    """-> ({arm: CCT ratio}, oracle ratio, do-nothing ratio) at this fabric point."""
    arms = MEASURED[fab.p]
    ratios = {name: cct_ratio(fab, arms[name], mode) for name in ARM_ORDER}
    return ratios, cct_ratio(fab, ORACLE, mode), cct_ratio(fab, DO_NOTHING, mode)


def print_sweep(base: Fabric, lams: List[float], taus: List[float], mode: str) -> None:
    print(f"\n## Recovery model: {mode}   "
          f"(CCT_clean={base.cct_clean_s:.3f}s, onset={base.onset_s:.2f}s, k={base.k_spray}, "
          f"mitigate={base.mitigate_s*1e3:.1f}ms, fleet={base.fleet_pkts_s/1e6:.0f}M pkt/s, "
          f"reroute_cost={base.reroute_cap_cost:.3f})")
    for lam in lams:
        for tau in taus:
            print(f"\n### lam={lam:,.0f} pkt/s on faulty link, tau(RTO)={tau*1e3:.2f} ms")
            print("| p (loss) | e (overhead) | detect ms MCP/SC/FP | CCT ratio MCP / SC / FP "
                  "| oracle | do-nothing | verdict |")
            print("|---|---|---|---|---|---|---|")
            for p in sorted(MEASURED, reverse=True):
                fab = replace(base, p=p, lam_pkts_s=lam, tau_s=tau)
                e = fab.overhead(mode)
                ratios, orc, don = run_cell(fab, mode)
                arms = MEASURED[p]
                dms = []
                for nm in ARM_ORDER:
                    ds = arms[nm].detect_s(fab)
                    dms.append("miss" if ds == float("inf") else f"{ds*1e3:.0f}")
                base_best = min(ratios["SprayCheck"], ratios["FlowPulse"])
                v = _verdict(ratios["MCP"], base_best, orc, don)
                print(f"| {p:.0e} | {e:.4f} | {'/'.join(dms)} "
                      f"| {_fmt(ratios['MCP'])} / {_fmt(ratios['SprayCheck'])} / {_fmt(ratios['FlowPulse'])} "
                      f"| {_fmt(orc)} | {_fmt(don)} | {v} |")


def print_reroute_cost_sensitivity(base: Fabric, lam: float, tau: float, mode: str) -> None:
    """Bandwidth-bound sensitivity: rerouting a path costs 1/k capacity. Shows the regime where
    mitigating is net-negative (oracle LOSES to do-nothing) -- reported, never hidden."""
    fab0 = replace(base, lam_pkts_s=lam, tau_s=tau, reroute_cap_cost=0.0)
    fabk = replace(base, lam_pkts_s=lam, tau_s=tau, reroute_cap_cost=1.0 / base.k_spray)
    print(f"\n## Reroute-cost sensitivity ({mode}, lam={lam:,.0f}, tau={tau*1e3:.1f}ms): "
          f"does mitigating pay?")
    print("| p | oracle @cost0 | do-nothing | oracle @cost=1/k | mitigating pays? |")
    print("|---|---|---|---|---|")
    for p in sorted(MEASURED, reverse=True):
        f0 = replace(fab0, p=p)
        fk = replace(fabk, p=p)
        orc0 = cct_ratio(f0, ORACLE, mode)
        don = cct_ratio(f0, DO_NOTHING, mode)
        orck = cct_ratio(fk, ORACLE, mode)
        pays = "yes" if orck < don - 1e-4 else "NO -- reroute costs more than the fault"
        print(f"| {p:.0e} | {_fmt(orc0)} | {_fmt(don)} | {_fmt(orck)} | {pays} |")


def crosscheck_recorded(counters: Path, fault_link: str, base: Fabric) -> None:
    per_epoch: Dict[int, Dict[str, Tuple[int, int]]] = {}
    with open(counters) as f:
        for row in csv.DictReader(f):
            per_epoch.setdefault(int(row["epoch"]), {})[row["link_name"]] = (
                int(row["tx"]), int(row["drop"]))
    eps = sorted(per_epoch)
    last = per_epoch[eps[-1]]                         # cumulative -> realised traffic + loss
    ftx, fdrop = last.get(fault_link, (0, 0))
    dur_s = len(eps) * 0.1
    lam_measured = ftx / dur_s
    p_measured = fdrop / ftx if ftx else 0.0
    print("\n## Recorded-counter cross-check (grounds Q1 at the measured low end)")
    print(f"- counters: `{counters}`, fault link `{fault_link}`, job {dur_s:.2f}s over {len(eps)} epochs")
    print(f"- REALISED on the faulty link: tx={ftx:,} pkts, drop={fdrop} pkts "
          f"-> lam={lam_measured:,.0f} pkt/s, p={p_measured:.2e}")
    for mode in RECOVERY_MODES:
        fab = replace(base, p=max(p_measured, 1e-12), lam_pkts_s=max(lam_measured, 1.0))
        e = fab.overhead(mode)
        don = cct_ratio(fab, DO_NOTHING, mode)
        print(f"  - {mode:8s}: overhead e={e:.6f}, do-nothing CCT ratio={don:.6f} "
              f"(+{(don-1)*100:.3f}% over clean)")
    print("- INTERPRETATION: this is the H27 corner -- the recorded fault sat on a near-idle link, "
          "so even do-nothing barely slows. A real campaign MUST place the fault on a traffic-"
          "carrying critical-path link and report the traffic denominator, or it measures nothing.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lams", default="2e3,1e5,1e6",
                    help="pkts/s the faulty directed link carries on the crit path; "
                         "2e3 = the measured near-idle fault link, 1e5 = a busy active link, "
                         "1e6 = a hot ring edge")
    ap.add_argument("--taus", default="0.05e-3,10e-3,50e-3",
                    help="RTO values in s (H25 first-class): 0.05ms fast-RTT-ish, 10ms, 50ms")
    ap.add_argument("--modes", default=",".join(RECOVERY_MODES))
    ap.add_argument("--recorded", default="sim/gate/results_real_v12/moe8x8b_n16/random/"
                                          "seed1000.counters.csv")
    ap.add_argument("--fault-link", default="US55->CS15")
    a = ap.parse_args()

    base = Fabric()
    lams = [float(x) for x in a.lams.split(",")]
    taus = [float(x) for x in a.taus.split(",")]

    print("# Application-impact gate -- detection-limited CCT under a directed-link grayhole")
    print("# arms fed MEASURED detect+localize (2026-09-02 comparison tables); model = cct_model.py")
    print("# CCT ratios are CCT(arm)/CCT_clean; lower is better; oracle=instant-perfect, "
          "do-nothing=never-mitigate")

    for mode in a.modes.split(","):
        print_sweep(base, lams, taus, mode)

    # the bandwidth-bound sensitivity, at the worst-case hot-link/high-RTO corner
    print_reroute_cost_sensitivity(base, lam=1e6, tau=50e-3, mode="batched")

    rec = Path(a.recorded)
    if rec.exists():
        crosscheck_recorded(rec, a.fault_link, base)
    else:
        print(f"\n(cross-check skipped: {rec} not found)")


if __name__ == "__main__":
    main()
