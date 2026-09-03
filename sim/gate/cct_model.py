#!/usr/bin/env python3
"""cct_model.py -- lightweight Ring-AllReduce collective-completion-time model for the
APPLICATION-IMPACT gate.

This settles the first, cheap question the CAMPAIGN-PLAN application-impact path rests on,
BEFORE the 62-min / 21.5 GB htsim block is run:

    Does a directed-link grayhole at the loss regimes we measured (1.5% down to 1e-4)
    produce a MEASURABLE collective-completion-time (CCT) slowdown at all, and if so is that
    slowdown DETECTION-limited -- i.e. does MCP's measured detect+localize advantage yield a
    smaller CCT slowdown than SprayCheck-Z / FlowPulse-theta, against an ORACLE (instant
    perfect mitigation) upper bound and a DO-NOTHING lower bound?

It is analytical, closed-form, and every load-bearing quantity is a printed parameter, in the
same spirit as `sim/gate/healing.py`: the arms differ in EXACTLY ONE thing -- their measured
detect-latency and localization outcome -- feeding an IDENTICAL mitigation and an IDENTICAL CCT
model. The oracle and do-nothing bounds are reported next to every arm, so a row that ties the
oracle (fault severity swamps detection) or ties do-nothing (the arm never mitigates) is visible
as an uninformative regime rather than mistaken for a win.

MODEL, in one paragraph
-----------------------
A collective is `W_total` units of work done at a clean rate `1` unit/s, so `CCT_clean` seconds of
work. At `onset` a grayhole appears on ONE directed link that carries `lam` packets/s of the
collective's critical-path traffic, dropping each at rate `p`. A barrier-synchronised ring makes
loss recovery, not bandwidth, the cost: while the fault is active, wall time per unit of work is
inflated by a recovery-overhead fraction `e`, so work proceeds at rate `1/(1+e)`. An arm detects at
`onset + detect_s` (its MEASURED packets-to-detect converted to wall time) and, if it localizes the
faulty directed link, reroutes it off the spray set at `onset + detect_s + mitigate_s`; after that
the fault is gone and work runs at `1 - cap_penalty`. An arm that MISSES (or acts on the wrong hop
of an ambiguous set) never fixes the fault, so the degraded rate holds to the end.

`cap_penalty = n_rerouted * reroute_cap_cost`. `reroute_cap_cost` defaults to **0**: the measured
moe8x8b_n16 runs use each 200 Gbps link at well under 1% (median active-link rate ~95 kpkt/s vs a
~16.7 Mpkt/s line rate), so dropping one of `k` sprayed paths removes capacity the collective was
not using. Setting `reroute_cap_cost = 1/k` turns on the bandwidth-bound sensitivity, which exposes
a distinct regime: when the loss overhead is smaller than the capacity a reroute costs, mitigating
is net-negative and even the oracle loses to do-nothing. That regime is reported explicitly, not
hidden inside the bounds.

The recovery overhead `e` is reported under THREE models so the answer is a band, not a point
estimate dressed as a measurement (`x = lam*p` is the loss rate in pkts/s):
  * ``batched`` (central):  e = 1 - exp(-x*tau)  -- one RTO added per recovery-quantum (length tau)
                            that contains >=1 loss; losses within a quantum recover together.
                            Bounded in [0,1], so a fully loss-stalled path is at most 2x slower.
  * ``serial`` (upper):     e = x*tau            -- every loss adds a full RTO, serialised on the
                            critical path with no batching (a deliberately loose pessimistic bound).
  * ``fast_rtt`` (lower):   e = x*rtt            -- loss recovered in one base RTT, no timeout.

`tau` (the RTO) and `rtt` (base RTT) are first-class parameters, per H25 ("CCT under loss is
dominated by the RTO, not by us -- report the RTO config as a first-class parameter").
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Localize(Enum):
    """Localization outcome an arm feeds the identical mitigation."""
    EXACT = "exact"          # named the faulty directed link and only it -> reroute 1 link, fixed
    AMBIGUOUS = "ambiguous"  # returned an m-link set containing the fault -> reroute m links, fixed
    WRONG_HOP = "wrong_hop"  # acted on the wrong link of an ambiguous set -> NOT fixed (pessimistic)
    MISS = "miss"            # never localized -> never mitigates (== do-nothing)


RECOVERY_MODES = ("batched", "serial", "fast_rtt")


@dataclass(frozen=True)
class Fabric:
    """Everything about the fabric + collective that is IDENTICAL across arms."""
    cct_clean_s: float = 3.586          # measured htsim moe8x8b_n16 CCT (results_real_v12/.finish)
    onset_s: float = 0.38               # measured .onset (~0.38 s) -- fault appears early in the job
    lam_pkts_s: float = 1.0e5           # pkts/s the faulty directed link carries on the crit path
    p: float = 1e-3                     # per-packet loss rate on the faulty directed link
    tau_s: float = 10e-3                # RTO (first-class parameter, H25)
    rtt_s: float = 15e-6                # base RTT anchor (link_latency 1us x diameter 6 + serial)
    k_spray: int = 8                    # spray width; rerouting 1 path costs 1/k of a leaf pair
    mitigate_s: float = 5e-3            # detect->reroute actuation cost, IDENTICAL across arms
                                        # (HW measured event-to-first-rerouted median 4.998 ms)
    fleet_pkts_s: float = 160e6         # baseline harness fleet rate: 2e6 pkt/spine/epoch x 8 / 0.1s
    reroute_cap_cost: float = 0.0       # capacity lost per rerouted path; 0 (fabric under-utilised)
                                        # or 1/k (bandwidth-bound sensitivity)

    def overhead(self, mode: str) -> float:
        """Recovery-overhead fraction e: wall time per unit work is (1+e) while the fault is live."""
        x = self.lam_pkts_s * self.p
        if mode == "batched":
            return 1.0 - math.exp(-x * self.tau_s)
        if mode == "serial":
            return x * self.tau_s
        if mode == "fast_rtt":
            return x * self.rtt_s
        raise ValueError(f"unknown recovery mode {mode!r}")


@dataclass(frozen=True)
class Arm:
    """An arm is fully described by MEASURED detection + localization, nothing else."""
    name: str
    detect_pkts: Optional[float]        # MEASURED fleet packets-to-detect; None == never detects
    localize: Localize
    set_size: float = 2.0               # links rerouted when AMBIGUOUS (MEASURED mean set size)

    def detect_s(self, fab: Fabric) -> float:
        if self.detect_pkts is None:
            return math.inf
        return self.detect_pkts / fab.fleet_pkts_s

    def n_rerouted(self) -> float:
        if self.localize == Localize.EXACT:
            return 1.0
        if self.localize == Localize.AMBIGUOUS:
            return self.set_size
        return 0.0                       # MISS / WRONG_HOP reroute nothing that fixes the fault

    def fixes_fault(self) -> bool:
        return self.localize in (Localize.EXACT, Localize.AMBIGUOUS)


def cct_seconds(fab: Fabric, arm: Arm, mode: str = "batched") -> float:
    """Wall-clock CCT for one collective under one arm, integrating piecewise work rates.

    Rates (work/s, clean == 1):
      [0, onset)              : 1
      [onset, t_mit)          : 1/(1+e)                        (fault active, degraded)
      [t_mit, end)            : 1 - cap_penalty                (fault fixed, capacity cost)
    `t_mit` is a fixed wall-clock instant (detection is a fabric-rate process), so a faster arm
    spends fewer wall seconds in the degraded phase.
    """
    W = fab.cct_clean_s                          # total work == clean CCT (clean rate 1)
    e = fab.overhead(mode)
    r_deg = 1.0 / (1.0 + e)

    cap = min(arm.n_rerouted() * fab.reroute_cap_cost, 0.99) if arm.fixes_fault() else 0.0
    r_fix = max(1.0 - cap, 1e-9)

    onset = min(fab.onset_s, W)
    t_mit = onset + arm.detect_s(fab) + fab.mitigate_s if arm.fixes_fault() else math.inf

    # phase 1: clean up to onset
    work = onset
    if work >= W:
        return W                                  # fault after the collective finished (H27 corner)

    # phase 2: degraded from onset to t_mit
    need = W - work
    deg_dur = t_mit - onset
    deg_work = r_deg * deg_dur if math.isfinite(deg_dur) else math.inf
    if deg_work >= need:
        return onset + need / r_deg               # finished before mitigation took effect
    # consumed the whole degraded window
    need -= deg_work
    # phase 3: fixed, reduced-capacity rate to completion
    return t_mit + need / r_fix


def cct_ratio(fab: Fabric, arm: Arm, mode: str = "batched") -> float:
    """CCT as a multiple of the same fabric's clean CCT (the paper's paired metric)."""
    return cct_seconds(fab, arm, mode) / fab.cct_clean_s


# --- the two reference bounds, defined once so every table carries them -----------------------
ORACLE = Arm("oracle", detect_pkts=0.0, localize=Localize.EXACT)         # instant perfect mitigation
DO_NOTHING = Arm("do_nothing", detect_pkts=None, localize=Localize.MISS)  # never mitigates


def bound_band(fab: Fabric, arm: Arm) -> dict:
    """CCT ratio for an arm under all three recovery models -> the honest band."""
    return {m: cct_ratio(fab, arm, m) for m in RECOVERY_MODES}
