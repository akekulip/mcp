#!/usr/bin/env python3
"""ramp.py — certify a suspect link with PRODUCTION traffic, metered by spray weight.

THE IDEA. Every audit design so far tries to manufacture traffic that resembles production, and
`GATE2-REPLAY-RESULT.md` showed a competent synthetic prober matches live cloning on every
marginal dimension, so manufacturing is a solved and unexciting problem. The interesting move is
the opposite one: do not remove the traffic in the first place.

A sprayed fabric already has a per-link admission knob -- the spray weight in `tbl_vlink` /
`tbl_spray_*`. Setting a suspect link's weight to w admits a w-fraction of production onto it. The
W4 witness then observes those packets at line rate, per directed link, with no scheduling and no
sampling. So:

  * COVERAGE is exact by construction: the evidence *is* production traffic, with production's
    joint distribution over size, class, entropy, timing and load. Nothing to enumerate, nothing
    to randomise, no correlation structure to guess.
  * EXPOSURE is bounded and tunable: at weight w and loss rate p, expected damaged packets per
    second is w x (link's share of offered load) x p, and w is a table write.
  * The certificate is scoped to what actually traversed, which is what a coverage-scoped
    certificate is supposed to mean.

The design question becomes a control problem: choose w(t) to certify fastest at the least
exposure. That is engineering, and it is what this file measures against the incumbents.

Arms:
  full_restore   CorrOpt-style: w = 1 immediately, watch passively (the incumbent)
  probe_then_full  w = 0, synthetic train until certified, then w = 1
  ramp_fixed     w steps 0.01 -> 0.1 -> 1 on a fixed schedule
  ramp_adaptive  w doubles while the witness sees no excess loss, halves on any gap
"""
import argparse
import math
import os
import random
import sys
from typing import Callable, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from controller import infer                     # the ONE frozen inference layer (PREREG 3.3)

EPOCH_PKTS = 20_000          # production packets offered to this link's group per epoch
HORIZON = 400                # epochs
# Packets needed to certify p <= 1e-4 at alpha = 0.05, from the exact binomial design in
# docs/AUDIT-FEASIBILITY.md 3. It DEPENDS ON THE BACKGROUND: at b=0 a single loss refutes, at
# b=1e-4 the test must separate 13.9 expected losses from 27.9. Using the b=0 figure while
# running at b=1e-4 makes every arm certify before it can possibly discriminate -- which is
# exactly what it did on the first run (82% of genuinely faulty links certified HEALTHY).
CERT_BY_BG = {0.0: 29_956, 1e-5: 43_125, 1e-4: 139_392}


def run(fault_p: float, strategy: str, rng: random.Random,
        detect_thresh: int = 3, bg: float = 0.0) -> Tuple[int, int, float, str]:
    """-> (exposed lost production packets, epochs to verdict, stranded capacity-epochs, verdict).

    `stranded` integrates (1 - w) over the epochs until the link is certified: capacity the fabric
    could have used and did not.
    """
    w = {"full_restore": 1.0, "probe_then_full": 0.0, "ramp_fixed": 0.01,
         "ramp_adaptive": 0.01, "witness_stop": 1.0, "ramp_witness": 0.02}[strategy]
    seen = lost = exposed = ctrl_lost = 0
    cert_pkts = CERT_BY_BG.get(bg, 139_392)
    stranded = 0.0
    probe_seen = 0
    for t in range(HORIZON):
        stranded += (1.0 - w)
        if strategy == "probe_then_full" and w == 0.0:
            # synthetic train on the idle link: costs no production exposure, but its packets are
            # NOT production -- modelled here as fully representative, i.e. the BEST case for it
            probe_seen += EPOCH_PKTS
            if probe_seen >= cert_pkts:
                hits = sum(1 for _ in range(probe_seen) if rng.random() < fault_p)
                if hits >= detect_thresh:
                    return exposed, t + 1, stranded, "FAULTY"
                return exposed, t + 1, stranded, "HEALTHY"
            continue
        if strategy in ("witness_stop", "ramp_witness"):
            # W4's property that counter polling cannot have: the gap is raised BY THE PACKET, at
            # line rate, so admission can be cut the instant the evidence crosses -- not at the
            # next epoch boundary. Every other arm must commit a whole epoch of production before
            # it can react, and that quantisation is most of their exposure.
            n = int(EPOCH_PKTS * w)
            p_eff = 1.0 - (1.0 - bg) * (1.0 - fault_p)
            for _ in range(n):
                seen += 1
                if rng.random() < p_eff:
                    lost += 1; exposed += 1
                if rng.random() < bg:
                    ctrl_lost += 1
                p0 = max(ctrl_lost / seen, infer.P_FLOOR)
                p0 = min(p0, 1.0 - 2.0 * infer.DELTA_LOSS)
                p1 = p0 + infer.DELTA_LOSS
                if lost and (lost * math.log(p1 / p0)
                             + (seen - lost) * math.log((1.0 - p1) / (1.0 - p0))) > infer.H_DEFAULT:
                    return exposed, t + 1, stranded, "FAULTY"
                if seen >= cert_pkts:
                    return exposed, t + 1, stranded, "HEALTHY"
            if strategy == "ramp_witness":
                # nothing seen this epoch -> widen admission. Bounded exposure while the evidence
                # is thin, full rate once it is thick, and a per-packet stop throughout.
                w = min(1.0, w * 2.0)
            continue
        n = int(EPOCH_PKTS * w)
        # the suspect link: background loss PLUS the fault, composed as independent Bernoulli
        p_eff = 1.0 - (1.0 - bg) * (1.0 - fault_p)
        drops = sum(1 for _ in range(n) if rng.random() < p_eff)
        # THE CONTROL IS FREE. Other links in the same spray group carry production right now, and
        # W4 witnesses them too, so the background rate is measured concurrently at no extra cost
        # -- no cloning, no probe, no assumption that b is known. The decision is on EXCESS loss.
        ctrl = sum(1 for _ in range(n) if rng.random() < bg)
        seen += n; lost += drops; ctrl_lost += ctrl; exposed += max(drops - ctrl, 0)
        excess = lost - ctrl_lost
        # SEQUENTIAL TEST, not a fixed excess threshold. A hand-rolled `excess >= 2` is a random
        # walk on a noisy control: it gave 84% detection at p=1e-4 but certified a HEALTHY link
        # correctly only 56% of the time. The frozen localizer's upper-sided binomial LLR is the
        # right instrument and is already the one every other arm in this project uses -- the
        # control supplies p0, so the background rate never has to be assumed.
        p0 = max(ctrl_lost / seen, infer.P_FLOOR) if seen else infer.P_FLOOR
        p0 = min(p0, 1.0 - 2.0 * infer.DELTA_LOSS)
        p1 = p0 + infer.DELTA_LOSS
        llr = (lost * math.log(p1 / p0) + (seen - lost) * math.log((1.0 - p1) / (1.0 - p0)))
        cusum = max(0.0, llr)
        if cusum > infer.H_DEFAULT:
            return exposed, t + 1, stranded, "FAULTY"
        if seen >= cert_pkts:
            return exposed, t + 1, stranded, "HEALTHY"
        if strategy == "ramp_fixed":
            w = min(1.0, w * 1.35)
        elif strategy == "ramp_adaptive":
            # widen while the excess stays at zero, pull back the moment it moves
            w = min(1.0, w * 1.8) if cusum <= 0.0 else max(0.01, w * 0.5)
    return exposed, HORIZON, stranded, "INCONCLUSIVE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--bg", type=float, default=0.0, help="background loss on every link")
    a = ap.parse_args()
    arms = ["full_restore", "probe_then_full", "ramp_fixed", "ramp_adaptive", "witness_stop",
            "ramp_witness"]
    print(f"# {a.trials} trials, background loss b={a.bg:.0e}. A link is either healthy or faulty at p; the mechanism must")
    print("# decide. EXPOSED = production packets actually lost to the fault while deciding.")
    print("# STRANDED = capacity-epochs the link sat unused. Lower is better for both.\n")
    for p, label in ((0.0, "healthy link"), (1e-4, "faulty p=1e-4"), (1e-3, "faulty p=1e-3")):
        print(f"## {label}")
        print("| arm | exposed pkts (mean) | epochs to verdict | stranded cap-epochs | verdict |")
        print("|---|---|---|---|---|")
        for arm in arms:
            e = ep = st = 0.0
            verdicts = {}
            for i in range(a.trials):
                rng = random.Random(0x2A ^ (i << 7) ^ hash(arm) % 7919)
                ex, tt, sr, v = run(p, arm, rng, bg=a.bg)
                e += ex; ep += tt; st += sr
                verdicts[v] = verdicts.get(v, 0) + 1
            top = max(verdicts, key=verdicts.get)
            print(f"| {arm:16s} | {e/a.trials:19.1f} | {ep/a.trials:17.1f} | {st/a.trials:19.1f} | "
                  f"{top} {100*verdicts[top]//a.trials}% |")
        print()


if __name__ == "__main__":
    main()
