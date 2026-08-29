#!/usr/bin/env python3
"""P3 sensitivity to non-instantaneous behavioral-sublink feedback.

Every capacity number so far (docs/review/CAPSULE-RESULT.md, HEALTH-GATE-RESULT.md) assumed the
decision lands the moment the evidence exists. It does not. The downstream witness raises the gap,
but the spray choice is made UPSTREAM, so something has to carry the event back, and production
keeps flowing onto the faulty sublink until it arrives.

The repository has measured controller-path references, but it has NOT measured the end-to-end
path required here (downstream C-W4 event -> event transport -> upstream health-table update):

* 106.6 ms: median of the existing full-sweep Python loop;
* 2.20 ms: a minimal one-slot register read+write path.

Neither is the actual downstream-C-W4-event -> P2-table-update path. In particular, the 97.4 us F6
number used by an older version is a same-switch congestion-attention reaction and cannot be used
as C-W4 loss feedback. ``--candidate-fast-us`` adds an explicitly unmeasured design target.

Detection time remains a sequential-test approximation. Flapping and stale-event rates are not
modelled here; they require replay through the implemented epoch state machine and event transport.
"""
import argparse
import math
from dataclasses import dataclass

TAU_SWEEP_S = 0.1066
TAU_MIN_SLOT_S = 0.00220
LINK_BPS = 25e9
MTU = 1500
PKT_RATE = LINK_BPS / (MTU * 8)      # ~2.08 M packets/s on a 25 G link


@dataclass
class Outcome:
    unsafe: float          # production packets lost to the fault before mitigation landed
    detect_s: float        # time from fault onset to the witness having enough evidence
    feedback_s: float      # time from evidence to the gate entry being installed


def detect_time(p: float, h_nats: float = 6.5, share: float = 1.0) -> float:
    """Seconds of production before the witness has h nats of evidence at loss rate p.

    A gap is worth about ln(1/p) nats, so the number of LOST packets needed is ~h/ln(1/p) and the
    number of SENT packets is that over p. This is the same sequential test the rest of the project
    uses, expressed in time rather than epochs.
    """
    per_gap = math.log(1.0 / p)
    gaps_needed = max(1.0, h_nats / per_gap)
    return gaps_needed / (p * PKT_RATE * share)


def simulate(p: float, feedback_s: float, share: float, horizon_s: float = 2.0) -> Outcome:
    d = detect_time(p, share=share)
    # production keeps flowing at the fault rate for detection + feedback
    exposed_s = min(d + feedback_s, horizon_s)
    unsafe = exposed_s * PKT_RATE * share * p

    return Outcome(unsafe, d, feedback_s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--share", type=float, default=0.25,
                    help="fraction of the link's packets belonging to the affected context")
    ap.add_argument("--candidate-fast-us", type=float,
                    help="optional UNMEASURED end-to-end C-W4 feedback candidate")
    a = ap.parse_args()

    paths = [("instantaneous (lower bound)", 0.0),
             ("minimal controller reference", TAU_MIN_SLOT_S),
             ("full-sweep controller reference", TAU_SWEEP_S)]
    if a.candidate_fast_us is not None:
        paths.append(("UNMEASURED candidate fast path", a.candidate_fast_us / 1e6))
    print(f"# 25 G link, {MTU} B packets = {PKT_RATE/1e6:.2f} M pkt/s; affected context carries "
          f"{100*a.share:.0f}% of them")
    print("# no end-to-end C-W4 feedback latency has been measured; nonzero defaults are "
          "controller-path references, not P3 results\n")
    print("| fault rate | detection time | feedback | unsafe packets | feedback share of exposure |")
    print("|---|---|---|---|---|")
    rows = {}
    for p in (1e-2, 1e-3, 1e-4, 1e-5):
        for name, fb in paths:
            o = simulate(p, fb, a.share)
            rows[(p, name)] = o
            frac = fb / (o.detect_s + fb) if (o.detect_s + fb) else 0.0
            print(f"| {p:.0e} | {o.detect_s*1e3:8.2f} ms | {name:32s} | {o.unsafe:10.1f} | "
                  f"{100*frac:5.1f} % |")
        sweep = rows[(p, "full-sweep controller reference")].unsafe
        minimal = rows[(p, "minimal controller reference")].unsafe
        gain = (sweep - minimal) / sweep * 100 if sweep else 0.0
        print(f"|  | | **scope sensitivity** | **{sweep-minimal:.1f} packets** | **{gain:.1f}% comes "
              f"from choosing a full sweep rather than an attributed update** |")


if __name__ == "__main__":
    main()
