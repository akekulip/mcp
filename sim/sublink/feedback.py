#!/usr/bin/env python3
"""feedback.py — P3: what conditional mitigation costs once feedback is not instantaneous.

Every capacity number so far (docs/review/CAPSULE-RESULT.md, HEALTH-GATE-RESULT.md) assumed the
decision lands the moment the evidence exists. It does not. The downstream witness raises the gap,
but the spray choice is made UPSTREAM, so something has to carry the event back, and production
keeps flowing onto the faulty sublink until it arrives.

Both latencies here are OUR OWN SILICON MEASUREMENTS, not estimates:

  * controller path  tau_slow = 96.2-116.6 ms   (p4/reports/slow-loop-silicon.md: bfrt register
                                                 read 48.5 ms + counter sync 29.8 ms + write 9.6 ms)
  * data-plane path  tau_fast = 97.4 us         (docs/DESIGN-ALTERNATIVES.md, H7 on silicon)

The plan allows a data-plane fast path "only if it materially improves unsafe exposure", so this
file exists to answer that with a number rather than a preference. The answer is not uniform, which
is the point: feedback latency only matters when it is comparable to DETECTION time, and detection
time depends on the fault rate.

Also modelled, because the plan requires them: event coalescing, epoch/reset, stale feedback, and
flapping.
"""
import argparse
import math
import random
from dataclasses import dataclass
from typing import List, Tuple

TAU_SLOW_S = 0.1066          # measured median of the 96.2-116.6 ms controller path
TAU_FAST_S = 0.0000974       # measured fast-loop reaction on silicon
LINK_BPS = 25e9
MTU = 1500
PKT_RATE = LINK_BPS / (MTU * 8)      # ~2.08 M packets/s on a 25 G link


@dataclass
class Outcome:
    unsafe: float          # production packets lost to the fault before mitigation landed
    detect_s: float        # time from fault onset to the witness having enough evidence
    feedback_s: float      # time from evidence to the gate entry being installed
    installs: int          # control-plane writes (coalescing works if this stays near 1)
    false_quarantine: int  # healthy contexts quarantined by stale or flapping feedback


def detect_time(p: float, h_nats: float = 6.5, share: float = 1.0) -> float:
    """Seconds of production before the witness has h nats of evidence at loss rate p.

    A gap is worth about ln(1/p) nats, so the number of LOST packets needed is ~h/ln(1/p) and the
    number of SENT packets is that over p. This is the same sequential test the rest of the project
    uses, expressed in time rather than epochs.
    """
    per_gap = math.log(1.0 / p)
    gaps_needed = max(1.0, h_nats / per_gap)
    return gaps_needed / (p * PKT_RATE * share)


def simulate(p: float, feedback_s: float, share: float, flap_period_s: float,
             stale_window_s: float, rng: random.Random, horizon_s: float = 2.0) -> Outcome:
    d = detect_time(p, share=share)
    # production keeps flowing at the fault rate for detection + feedback
    exposed_s = min(d + feedback_s, horizon_s)
    unsafe = exposed_s * PKT_RATE * share * p

    # COALESCING: the witness raises a gap per discontinuity, but the controller installs once per
    # (sublink, epoch). Without coalescing every gap in the feedback window would be its own write.
    gaps_in_window = max(1.0, feedback_s * PKT_RATE * share * p)
    installs = 1

    # STALE FEEDBACK: an event that was generated before the last epoch/reset must be discarded.
    # If the feedback path is slower than the flap period, events routinely describe a world that
    # no longer exists, and acting on them quarantines a context that is currently healthy.
    false_q = 0
    if flap_period_s > 0:
        t = 0.0
        while t < horizon_s:
            healthy_now = (int(t / flap_period_s) % 2) == 1
            arrives_at = t + d + feedback_s
            still_healthy = (int(arrives_at / flap_period_s) % 2) == 1
            if healthy_now != still_healthy and feedback_s > stale_window_s:
                false_q += 1          # the event describes a state that has since flipped
            t += flap_period_s
    return Outcome(unsafe, d, feedback_s, installs, false_q)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--share", type=float, default=0.25,
                    help="fraction of the link's packets belonging to the affected context")
    ap.add_argument("--stale-window", type=float, default=0.05)
    a = ap.parse_args()

    paths = (("instantaneous (what we assumed)", 0.0),
             ("controller, measured tau_slow", TAU_SLOW_S),
             ("data plane, measured tau_fast", TAU_FAST_S))
    print(f"# 25 G link, {MTU} B packets = {PKT_RATE/1e6:.2f} M pkt/s; affected context carries "
          f"{100*a.share:.0f}% of them")
    print(f"# tau_slow = {TAU_SLOW_S*1e3:.1f} ms and tau_fast = {TAU_FAST_S*1e6:.1f} us are silicon "
          f"measurements from this project, not estimates\n")
    print("| fault rate | detection time | feedback | unsafe packets | feedback share of exposure |")
    print("|---|---|---|---|---|")
    rows = {}
    for p in (1e-2, 1e-3, 1e-4, 1e-5):
        for name, fb in paths:
            o = simulate(p, fb, a.share, 0.0, a.stale_window, random.Random(1))
            rows[(p, name)] = o
            frac = fb / (o.detect_s + fb) if (o.detect_s + fb) else 0.0
            print(f"| {p:.0e} | {o.detect_s*1e3:8.2f} ms | {name:32s} | {o.unsafe:10.1f} | "
                  f"{100*frac:5.1f} % |")
        base = rows[(p, "controller, measured tau_slow")].unsafe
        fast = rows[(p, "data plane, measured tau_fast")].unsafe
        gain = (base - fast) / base * 100 if base else 0.0
        print(f"|  | | **fast path removes** | **{base-fast:.1f} packets** | **{gain:.1f}% of the "
              f"controller arm's exposure** |")
    print()
    print("## Flapping and stale feedback")
    print("| flap period | controller false quarantines | data plane false quarantines |")
    print("|---|---|---|")
    for flap in (0.02, 0.05, 0.2, 1.0):
        c = simulate(1e-3, TAU_SLOW_S, a.share, flap, a.stale_window, random.Random(2)).false_quarantine
        f = simulate(1e-3, TAU_FAST_S, a.share, flap, a.stale_window, random.Random(2)).false_quarantine
        print(f"| {flap*1e3:6.0f} ms | {c} | {f} |")


if __name__ == "__main__":
    main()
