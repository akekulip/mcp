#!/usr/bin/env python3
"""replay_audit.py — does a production-conditioned audit beat a synthetic train, at equal bytes?

GATE 1 of the ShadowTwin design (docs/review/GATE2-VERDICT.md, second pass). The first-pass
verdict argued from cost: certifying a link takes ~30k packets, which is microseconds of link
time, so the audit budget cannot bind. That is true and beside the point. An audit measures

    L_audit      = E_{x ~ Q} [ loss(x) ]        Q = the audit's own packet distribution
    L_production = E_{x ~ P} [ loss(x) ]        P = what production will actually send

and if Q does not cover P then no number of cheap probes certifies anything. Aegis (NSDI'25)
reports exactly this in production: 64-byte Pingmesh probes missed a fault that only dropped
packets larger than 1 KB.

So the question this file settles is NOT "how many packets" but "which packets", measured as the
false-restoration rate at EQUAL MEASUREMENT BYTES. The pre-registered expectation:

  * on IID loss the two strategies must TIE — a fault that ignores packet features cannot reward
    conditioning on them, and if the conditioned arm wins here the model is rigged;
  * on feature-conditioned faults (size, class, load, burst) the synthetic train must fail in a
    way extra bytes cannot fix.

No htsim: loss is a function of packet features, so this is an event model and runs in seconds.
"""
import argparse
import math
import random
from dataclasses import dataclass
from typing import Callable, List, Tuple

# --------------------------------------------------------------------------------------------
# The production distribution P. An AI training fabric is bimodal: small control/ack traffic and
# large collective payloads. A synthetic train that samples neither is the failure mode of record.
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Packet:
    size: int          # bytes on the wire
    tc: int            # traffic class: 0 = control/ack, 1 = bulk collective
    load: float        # instantaneous offered load on the link, 0..1, when the packet was sent
    entropy: int = 0   # 5-tuple/UDP-source entropy bucket, 0..ENTROPY_SPACE-1

ENTROPY_SPACE = 4096   # the header-entropy space a prober would have to enumerate


def production_packet(rng: random.Random, load: float) -> Packet:
    """Bimodal size, class correlated with size — the shape AI collectives actually produce."""
    e = rng.randrange(ENTROPY_SPACE)          # production spans the entropy space naturally
    if rng.random() < 0.35:
        return Packet(size=rng.choice([64, 128, 256]), tc=0, load=load, entropy=e)
    return Packet(size=rng.choice([1500, 4096, 4096, 9000]), tc=1, load=load, entropy=e)


def load_series(rng: random.Random, n: int) -> List[float]:
    """Collective phases: bursts of high load separated by near-idle gaps (H27's physics)."""
    out, t = [], 0.0
    while len(out) < n:
        busy = rng.random() < 0.45
        span = rng.randint(200, 1200)
        lvl = rng.uniform(0.55, 0.95) if busy else rng.uniform(0.0, 0.08)
        out.extend([lvl] * span)
    return out[:n]


# --------------------------------------------------------------------------------------------
# Fault models: loss(x) as a function of the packet, not just of the link.
# --------------------------------------------------------------------------------------------
def f_iid(p: float) -> Callable[[Packet, random.Random], bool]:
    return lambda x, rng: rng.random() < p


def f_size_selective(p: float, over: int = 1024) -> Callable[[Packet, random.Random], bool]:
    """The Aegis fault, verbatim: only packets larger than 1 KB are dropped."""
    return lambda x, rng: x.size > over and rng.random() < p


def f_class_selective(p: float, tc: int = 1) -> Callable[[Packet, random.Random], bool]:
    return lambda x, rng: x.tc == tc and rng.random() < p


def f_load_triggered(p: float, over: float = 0.5) -> Callable[[Packet, random.Random], bool]:
    """Marginal SerDes/queue faults that only appear when the link is actually driven."""
    return lambda x, rng: x.load > over and rng.random() < p


def f_entropy_selective(p: float, n_bad: int = 64, seed: int = 0xE) -> Callable[[Packet, random.Random], bool]:
    """The fault a synthetic prober cannot ENUMERATE its way out of.

    Loss only for packets whose header entropy falls in a small unknown subset — a broken hash
    bucket, one bad lane of a striped SerDes, one ECMP member of a LAG, a corrupted TCAM entry.
    The space is 4096 wide and the bad set is 64 of it. A prober that fixes its 5-tuple samples one
    point; enumerating the space costs 4096x. Production traffic covers it in proportion for free,
    which is the one conditioning dimension cloning gets that synthesis does not.
    """
    bad = set(random.Random(seed).sample(range(ENTROPY_SPACE), n_bad))
    return lambda x, rng: x.entropy in bad and rng.random() < p


class GilbertElliott:
    """Bursty loss: harmless in GOOD, lossy in BAD. Sampling sparsely can miss BAD entirely."""
    def __init__(self, p_gb=2e-4, p_bg=0.05, loss_bad=0.30):
        self.p_gb, self.p_bg, self.loss_bad, self.bad = p_gb, p_bg, loss_bad, False

    def __call__(self, x: Packet, rng: random.Random) -> bool:
        if self.bad:
            if rng.random() < self.p_bg:      # recover
                self.bad = False
        elif rng.random() < self.p_gb:        # break
            self.bad = True
        return self.bad and rng.random() < self.loss_bad


def healthy(x: Packet, rng: random.Random) -> bool:
    return False


# --------------------------------------------------------------------------------------------
# Audit strategies. Each yields (packet, is_treatment) pairs until its byte budget is spent.
# --------------------------------------------------------------------------------------------
def synthetic_train(budget_bytes: int, size: int, tc: int, rng: random.Random,
                    loads: List[float], self_load: float = 0.0, n_entropy: int = 8) -> List[Packet]:
    """A fixed-size synthetic train. `self_load` models a prober that blasts at line rate to
    induce load itself — the fair counter to 'synthetic probes miss load-triggered faults'."""
    n = budget_bytes // size
    ents = [rng.randrange(ENTROPY_SPACE) for _ in range(n_entropy)]   # a prober fixes a few tuples
    return [Packet(size=size, tc=tc, load=self_load, entropy=ents[i % n_entropy])
            for i in range(n)]


def production_twins(budget_bytes: int, rng: random.Random, loads: List[float],
                     clone_ratio: float = 0.02) -> List[Packet]:
    """Twins of live production packets, on a link that production no longer uses.

    THE CORRECTION THAT MATTERS. An earlier version of this model gave each twin the load of the
    production link it was cloned from. That is wrong and it flattered this arm: the dark link
    carries no production, so the only load on it is the load the twins themselves induce. A twin
    therefore inherits production's SIZE and CLASS but NOT its queue occupancy, which is exactly
    the objection that the certificate's `load_envelope` field is the one the mechanism least
    supports. Induced load is the clone ratio times the load on the source link — so covering the
    high-load stratum costs a proportionally huge clone ratio, and that is the design's real
    tension rather than a detail.
    """
    out, spent, i = [], 0, 0
    while spent < budget_bytes and i < len(loads):
        induced = min(1.0, clone_ratio * loads[i])   # cloning a fraction r induces r x the load
        pk = production_packet(rng, loads[i])
        # carry the ENTROPY through: a twin is a copy of a production packet, and the entropy it
        # inherits is the whole point -- rebuilding the Packet without it silently defaulted every
        # twin to bucket 0 and made this arm fail the one fault it should win
        out.append(Packet(size=pk.size, tc=pk.tc, load=induced, entropy=pk.entropy))
        spent += pk.size; i += 1
    return out


# --------------------------------------------------------------------------------------------
# The decision. Paired: treatment on the suspect link, control on a healthy sibling, so the
# verdict is an EXCESS loss over the control rather than an absolute rate.
# --------------------------------------------------------------------------------------------
def audit(link_fault, control_fault, packets: List[Packet], rng: random.Random,
          paired: bool) -> Tuple[int, int, int]:
    """-> (treatment losses, control losses, packets sent on each arm)."""
    t_loss = sum(1 for x in packets if link_fault(x, rng))
    c_loss = sum(1 for x in packets if control_fault(x, rng)) if paired else 0
    return t_loss, c_loss, len(packets)


def verdict(t_loss: int, c_loss: int, n: int, paired: bool, alpha: float = 0.05) -> str:
    """HEALTHY only if the excess loss is bounded; never 'healthy by absence of evidence'."""
    if n == 0:
        return "INCONCLUSIVE"
    excess = t_loss - c_loss if paired else t_loss
    if excess <= 0:
        # certified only if enough packets were seen to exclude the ceiling at risk alpha
        need = math.log(alpha) / math.log1p(-1e-4)
        return "HEALTHY" if n >= need else "INCONCLUSIVE"
    return "FAULTY"


# --------------------------------------------------------------------------------------------
# The experiment
# --------------------------------------------------------------------------------------------
FAULTS = {
    "iid 1e-4":            lambda: f_iid(1e-4),
    "size>1KB (Aegis)":    lambda: f_size_selective(2e-3, 1024),
    "class=bulk":          lambda: f_class_selective(1e-3, 1),
    "load>0.5":            lambda: f_load_triggered(2e-3, 0.5),
    "bursty (G-E)":        lambda: GilbertElliott(),
    "entropy 64/4096":     lambda: f_entropy_selective(0.05, 64),
}

STRATEGIES = {
    "synth 64B idle":    lambda b, rng, loads: synthetic_train(b, 64, 0, rng, loads),
    "synth 1500B idle":  lambda b, rng, loads: synthetic_train(b, 1500, 1, rng, loads),
    "synth 1500B @line": lambda b, rng, loads: synthetic_train(b, 1500, 1, rng, loads, 0.9),
    "synth mixed @line": lambda b, rng, loads: _mixed_train(b, rng, 0.9),
    "synth mixed rand-e": lambda b, rng, loads: _mixed_train(b, rng, 0.9, n_entropy=ENTROPY_SPACE),
    "twins r=0.02":      lambda b, rng, loads: production_twins(b, rng, loads, 0.02),
    "twins r=0.2 (ramp)": lambda b, rng, loads: production_twins(b, rng, loads, 0.2),
    "twins r=1 (full)":  lambda b, rng, loads: production_twins(b, rng, loads, 1.0),
}


def _mixed_train(budget_bytes: int, rng: random.Random, self_load: float,
                 n_entropy: int = 8) -> List[Packet]:
    """The strongest synthetic prober: it copies production's SIZE MIX and drives the link hard.
    What it still cannot copy is production's timing -- the load it induces is its own, not the
    collective's, so a fault that only appears in a particular phase is still invisible to it."""
    # n_entropy = ENTROPY_SPACE models the strongest possible synthetic prober: one that
    # RANDOMISES its 5-tuple across the whole entropy space. If this arm also catches the
    # entropy-selective fault, then entropy is enumerable too and live cloning buys nothing.
    out, spent = [], 0
    ents = [rng.randrange(ENTROPY_SPACE) for _ in range(min(n_entropy, 4096))]
    while spent < budget_bytes:
        pk = production_packet(rng, self_load)
        out.append(Packet(size=pk.size, tc=pk.tc, load=self_load,
                          entropy=ents[len(out) % len(ents)]))
        spent += pk.size
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget-bytes", type=int, default=200_000_000)
    ap.add_argument("--trials", type=int, default=80)
    ap.add_argument("--paired", action="store_true")
    a = ap.parse_args()

    print(f"# equal budget {a.budget_bytes/1e6:.0f} MB per audit, {a.trials} trials")
    print("# TWO numbers per cell, and BOTH matter:")
    print("#   FR = P(certify HEALTHY | the link is really faulty)  -- unsafe restoration, lower better")
    print("#   OK = P(certify HEALTHY | the link is really healthy)  -- usefulness, higher better")
    print("# An arm that never certifies scores FR=0 by construction and is worthless; reporting")
    print("# FR alone hid exactly that, which is why OK is here.")
    print()
    hdr = f"| {'fault the link really has':22s} |" + "".join(f" {s:17s} |" for s in STRATEGIES)
    print(hdr); print("|" + "---|" * (len(STRATEGIES) + 1))
    for fname, fmake in FAULTS.items():
        row = f"| {fname:22s} |"
        for sname, smake in STRATEGIES.items():
            fr = ok = 0
            for t in range(a.trials):
                rng = random.Random(0xA0D1 ^ (t << 8) ^ (abs(hash(sname)) % 9973))
                loads = load_series(rng, 400_000)
                pk = smake(a.budget_bytes, rng, loads)
                tl, cl, n = audit(fmake(), healthy, pk, rng, a.paired)
                if verdict(tl, cl, n, a.paired) == "HEALTHY":
                    fr += 1
                tl2, cl2, n2 = audit(healthy, healthy, pk, rng, a.paired)
                if verdict(tl2, cl2, n2, a.paired) == "HEALTHY":
                    ok += 1
            row += f" FR{100.0*fr/a.trials:5.1f} OK{100.0*ok/a.trials:5.1f} |"
        print(row)


if __name__ == "__main__":
    main()
