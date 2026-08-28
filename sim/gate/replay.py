#!/usr/bin/env python3
"""replay.py — exact offline replay of read schedules over recorded per-link counters (M1).

Why this is exact, not an approximation: the per-link counter logs written by htsim
(`sim/htsim/htsim/sim/mcp.cpp:120-125`, every link every epoch) are **byte-identical across all
five measured arms for all 30 seeds** (120/120 pairs, verified 2026-08-27, PREREG v1.5 §4). The
measurement policy does not perturb the simulated fabric, so replaying a different schedule over
the recorded counters reproduces exactly what that schedule would have observed.

Each epoch a schedule picks `budget` links to read; reading a link yields the (tx, drop) delta
since that link was last read by this schedule. Those deltas feed the FROZEN localizer
(`controller/infer.py`, PREREG §3.3) and TTL is the first epoch at or after onset whose anomaly
bit is set with the faulty link ranked first — the same rule as `analyze_real.py --detector
localizer`.

Usage:
  ./replay.py --results results_real_v12/moe8x8b_n16/uniform --budgets 10,20,41,82,200 \
              --schedules uniform,random,load_gated,threshold_gated,greedy,oracle
  ./replay.py --results ... --faults 2            # semi-synthetic multi-fault
  ./replay.py --results ... --move-fault-epoch 20 # moving fault
"""
import argparse
import csv
import math
import os
import random
import re
import statistics
import sys
import zlib
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from controller import infer                     # noqa: E402
from controller.types import Sample              # noqa: E402

EPOCH_US = 100000.0
LINK_RE = re.compile(r"US(\d+)->CS(\d+)")


def candidate_order(names) -> List[str]:
    """The simulator's own candidate order: agg-major, core-minor (main_uec.cpp:816-819),
    NOT lexicographic — replaying with a sorted list visits different links per epoch."""
    def key(n):
        m = LINK_RE.match(n)
        return (int(m.group(1)), int(m.group(2))) if m else (1 << 30, n)
    return sorted(names, key=key)


def load_counters(path: Path) -> Tuple[List[str], Dict[int, Dict[str, Tuple[int, int]]]]:
    """-> (uplink names in simulator order, {epoch: {link: (tx, drop)}}) with CUMULATIVE values."""
    per_epoch: Dict[int, Dict[str, Tuple[int, int]]] = {}
    names = set()
    with open(path) as f:
        for row in csv.DictReader(f):
            n = row["link_name"]
            if not n.startswith("US"):          # uplinks are the candidate set
                continue
            names.add(n)
            per_epoch.setdefault(int(row["epoch"]), {})[n] = (int(row["tx"]), int(row["drop"]))
    return candidate_order(names), per_epoch


class Schedule:
    """Every schedule sees only what it has read: (dtx, ddrop) deltas and its own history."""

    def __init__(self, names: List[str], budget: int, seed: int, faulty: List[str]):
        self.names, self.budget, self.rng = names, min(budget, len(names)), random.Random(seed)
        self.faulty = faulty
        self.cursor = 0
        self.last_seen: Dict[str, Tuple[int, int]] = {}   # link -> (tx, drop) at last read
        self.last_epoch: Dict[str, int] = {n: -1 for n in names}

    def _rr(self, k: int, exclude=()) -> List[str]:
        out = []
        while len(out) < k:
            n = self.names[self.cursor]
            self.cursor = (self.cursor + 1) % len(self.names)
            if n not in exclude and n not in out:
                out.append(n)
        return out

    def pick(self, epoch: int, cum: Dict[str, Tuple[int, int]], state) -> List[str]:
        raise NotImplementedError


class Uniform(Schedule):
    name = "uniform"
    def pick(self, epoch, cum, state): return self._rr(self.budget)


class Random_(Schedule):
    name = "random"
    def pick(self, epoch, cum, state): return self.rng.sample(self.names, self.budget)


class LoadGated(Schedule):
    """Round-robin, but skip links with no traffic since this schedule last read them."""
    name = "load_gated"
    def pick(self, epoch, cum, state):
        out, tried = [], 0
        while len(out) < self.budget and tried < 4 * len(self.names):
            n = self.names[self.cursor]; self.cursor = (self.cursor + 1) % len(self.names); tried += 1
            tx0 = self.last_seen.get(n, (0, 0))[0]
            if cum.get(n, (0, 0))[0] - tx0 > 0 and n not in out:
                out.append(n)
        return out or self._rr(self.budget)


class ThresholdGated(LoadGated):
    """Only read a link once it has carried enough packets for the detector to be able to fire."""
    name = "threshold_gated"
    MIN_PKTS = 20000           # ~2 drops at delta_loss = 1e-4
    def pick(self, epoch, cum, state):
        out, tried = [], 0
        while len(out) < self.budget and tried < 4 * len(self.names):
            n = self.names[self.cursor]; self.cursor = (self.cursor + 1) % len(self.names); tried += 1
            tx0 = self.last_seen.get(n, (0, 0))[0]
            if cum.get(n, (0, 0))[0] - tx0 >= self.MIN_PKTS and n not in out:
                out.append(n)
        return out or LoadGated.pick(self, epoch, cum, state)


class Greedy(Schedule):
    """Greedy information: read the links with the most unobserved traffic."""
    name = "greedy"
    def pick(self, epoch, cum, state):
        gain = {n: cum.get(n, (0, 0))[0] - self.last_seen.get(n, (0, 0))[0] for n in self.names}
        return sorted(self.names, key=lambda n: (-gain[n], self.last_epoch[n], n))[: self.budget]


class InBand(Schedule):
    """The link-local in-band invariant (PREREG v1.5 **H8**), replayed.

    A per-link sequence gap checked at the next hop (or an RFC 9341 alternate-marking counter
    diff) makes every drop a *localized event at the moment it happens*: no element has to be
    chosen, because the evidence is carried by the data plane itself. In replay that is exactly
    "read every link's (tx, drop) delta every epoch", which the recorded counters support.

    It spends **zero probe bytes**; its cost is per-packet header state (2 B of sequence, or one
    marking bit) plus a counter pair per link, which is priced separately in the paper's cost
    table -- it is NOT free, it is charged in different units (PREREG §2.3).
    """
    name = "inband"

    def pick(self, epoch, cum, state):
        return list(self.names)        # every link, every epoch: no schedule at all


class InBandSync(Schedule):
    """The same invariant, but the controller only *collects* the per-link verdicts every
    `SYNC` epochs -- the realistic version where the data plane detects continuously and the
    collection is periodic. Detection latency is then bounded by the sync period, not by
    coverage."""
    name = "inband_sync"
    SYNC = 4

    def pick(self, epoch, cum, state):
        return list(self.names) if epoch % self.SYNC == 0 else []


class Oracle(Schedule):
    """Upper bound: always read the faulty link(s), fill with round-robin."""
    name = "oracle"
    def pick(self, epoch, cum, state):
        out = [n for n in self.faulty if n in self.names][: self.budget]
        return out + self._rr(self.budget - len(out), exclude=out)


SCHEDULES = {c.name: c for c in (Uniform, Random_, LoadGated, ThresholdGated, Greedy, Oracle,
                                 InBand, InBandSync)}


def scenario_seed(stem: str, role: str) -> int:
    """Stable per-seed scenario seed.  Python's ``hash`` of a str is salted per process
    (PYTHONHASHSEED), so the semi-synthetic fault identities used to differ between runs of the
    same command; CRC-32 of the stem is stable across processes, machines and versions."""
    return zlib.crc32(f"{stem}/{role}".encode())


def first_drop_epoch_of(counters: Path, link: str):
    """First epoch whose cumulative drop count on the faulty link is > 0 — the first moment any
    detector could possibly fire (the fault's own evidence rate, PREREG v1.5 H8)."""
    with open(counters) as f:
        for row in csv.DictReader(f):
            if row["link_name"] == link and int(row["drop"]) > 0:
                return int(row["epoch"])
    return None


def _poisson(lam: float, rng: random.Random) -> int:
    """Knuth sampler; lam is small here (dtx*p ~ 5), so this is a few multiplications."""
    if lam <= 0:
        return 0
    if lam > 30:                                     # normal approximation, clipped at 0
        return max(0, int(rng.gauss(lam, math.sqrt(lam)) + 0.5))
    l, k, pp = math.exp(-lam), 0, 1.0
    while True:
        k += 1
        pp *= rng.random()
        if pp <= l:
            return k - 1


def replay_seed(counters: Path, faulty: List[str], onset_ms: float, sched_name: str, budget: int,
                seed: int, h: float, extra_faults: Dict[str, float], move_epoch: int,
                move_to: str, objective: str = "any") -> Tuple[int, bool, "int | None", int]:
    """Replay one seed; returns (TTL from onset, censored, detection epoch, false-alarm epochs).

    ``objective`` names the multi-fault success semantics explicitly (PREREG v1.6 §14), because
    'localized' is ambiguous once distractor faults exist:

    * ``any``      -- the top-ranked element is ANY injected fault (the reported default);
    * ``all``      -- every injected fault has been top-ranked at some epoch (hardest);
    * ``original`` -- the top-ranked element is the RECORDED fault, distractors are noise.

    A false-alarm epoch is one whose anomaly bit is set while the top-ranked element is NOT an
    injected fault — the wrong-link alarms this detector would have raised on the way.
    """
    names, per_epoch = load_counters(counters)
    # the oracle is handed EVERY injected fault, semi-synthetic ones included -- otherwise it is
    # not an upper bound under the "all" objective (it would read one link and miss the others)
    sch = SCHEDULES[sched_name](names, budget, seed,
                                list(faulty) + [f for f in extra_faults if f not in faulty])
    state = infer.InferState()
    onset_epoch = int(onset_ms * 1000 // EPOCH_US)
    rng = random.Random(seed ^ 0xA11)
    horizon = max(per_epoch)
    injected = list(faulty) + [f for f in extra_faults if f not in faulty]
    # "any"/"all" count every INJECTED fault as a success; "original" keeps the recorded fault as
    # the only success and treats the semi-synthetic ones as distractors.
    want = {"vlink:" + f for f in (injected if objective != "original" else faulty[:1])}
    all_injected = {"vlink:" + f for f in injected}
    identified: set = set()
    false_alarms = 0
    for epoch in sorted(per_epoch):
        cum = per_epoch[epoch]
        if move_epoch and epoch == move_epoch and move_to:
            sch.faulty = [move_to]
            want = {"vlink:" + move_to}          # the fault is now THERE; the old link is healthy
            all_injected = (all_injected - {"vlink:" + faulty[0]}) | {"vlink:" + move_to}
            identified = set()
        chosen = sch.pick(epoch, cum, state)
        samples = []
        # the in-band arms are not budgeted: their evidence is carried by the packets themselves
        for n in chosen:
            tx, drop = cum.get(n, (0, 0))
            tx0, drop0 = sch.last_seen.get(n, (0, 0))
            dtx, ddrop = tx - tx0, drop - drop0
            # semi-synthetic extra faults: thin the observed traffic of that link
            p = extra_faults.get(n, 0.0)
            if p > 0 and dtx > 0 and epoch >= onset_epoch:
                ddrop += _poisson(dtx * p, rng)      # Binomial(dtx, p) ~ Poisson for small p
            sch.last_seen[n] = (tx, drop)
            sch.last_epoch[n] = epoch
            if dtx > 0:
                samples.append(Sample(element=f"vlink:{n}", delivered=max(dtx - ddrop, 0),
                                      lost=ddrop, latency_us=(), t_us=int(epoch * EPOCH_US)))
        state = infer.update(state, samples, {}, baseline_mode="pooled")
        loc = infer.localize(state, k=1, h=h)
        if epoch >= onset_epoch and loc.anomaly and loc.ranked:
            top = loc.ranked[0][0]
            if top in want:
                identified.add(top)
                if objective != "all" or identified >= want:
                    return epoch - onset_epoch, False, epoch, false_alarms
            elif top not in all_injected:
                false_alarms += 1
    return max(horizon - onset_epoch, 0), True, None, false_alarms


def km_median(times, censored):
    pts = sorted(set(t for t, c in zip(times, censored) if not c))
    items = sorted(zip(times, censored)); n_at_risk = len(times); s = 1.0; idx = 0
    for t in pts:
        while idx < len(items) and items[idx][0] < t:
            n_at_risk -= 1; idx += 1
        d = sum(1 for tt, c in items if tt == t and not c)
        if n_at_risk > 0:
            s *= 1 - d / n_at_risk
        if s <= 0.5:
            return float(t)
    return float("nan")


def sign_test(base: Dict[str, int], arm: Dict[str, int]) -> Tuple[int, int, float]:
    """-> (arm faster than base, arm slower, two-sided sign-test p)."""
    common = [s for s in base if s in arm]
    d = [base[s] - arm[s] for s in common]          # positive => arm took fewer epochs => faster
    w = sum(1 for x in d if x > 0); l = sum(1 for x in d if x < 0); n = w + l
    p = min(1.0, sum(math.comb(n, k) for k in range(0, min(w, l) + 1)) / 2 ** n * 2) if n else float("nan")
    return w, l, p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, help="a directory of seed*.counters.csv + .fault + .onset")
    ap.add_argument("--budgets", default="41")
    ap.add_argument("--schedules", default=",".join(SCHEDULES))
    ap.add_argument("--h", type=float, default=infer.H_DEFAULT)
    ap.add_argument("--faults", type=int, default=1, help="1 = the recorded fault; >1 adds semi-synthetic ones")
    ap.add_argument("--extra-p", type=float, default=1e-4)
    ap.add_argument("--move-fault-epoch", type=int, default=0)
    ap.add_argument("--seeds", default="")
    ap.add_argument("--objective", default="any", choices=["any", "all", "original"],
                    help="multi-fault success semantics (PREREG v1.6 §14)")
    a = ap.parse_args()
    root = Path(a.results)
    runs = sorted(root.glob("seed*.counters.csv"))
    if a.seeds:
        keep = set(a.seeds.split(","))
        runs = [r for r in runs if r.name.split(".")[0].replace("seed", "") in keep]
    budgets = [int(x) for x in a.budgets.split(",")]
    scheds = a.schedules.split(",")
    print(f"# replay: {len(runs)} seeds x {len(scheds)} schedules x {len(budgets)} budgets, "
          f"h={a.h}, faults={a.faults}, move_epoch={a.move_fault_epoch or '-'}")
    print(f"# objective={a.objective} (multi-fault success semantics), detector = frozen "
          f"controller/infer.py {infer.module_hash()[:8]}")
    print("\n| budget | schedule | n | KM median TTL | raw median | censored | wrong-link alarm epochs (seeds with >=1) | vs uniform (faster/slower, p) |")
    print("|---|---|---|---|---|---|---|---|")
    obs: Dict[str, List[int]] = {}
    ev: Dict[str, List[int]] = {}
    fa: Dict[str, List[int]] = {}
    for b in budgets:
        per_sched = {}
        for sname in scheds:
            res = {}
            for c in runs:
                stem = c.name.split(".")[0]
                fault = (root / f"{stem}.fault").read_text().strip()
                onset = float((root / f"{stem}.onset").read_text().strip())
                names, _ = load_counters(c)
                extra = {}
                if a.faults > 1:
                    rng = random.Random(scenario_seed(stem, "extra"))
                    for n in rng.sample([n for n in names if n != fault], a.faults - 1):
                        extra[n] = a.extra_p
                move_to = ""
                if a.move_fault_epoch:
                    rng2 = random.Random(scenario_seed(stem, "move"))
                    move_to = rng2.choice([n for n in names if n != fault])
                r = replay_seed(c, [fault], onset, sname, b, int(stem.replace("seed", "")),
                                a.h, extra, a.move_fault_epoch, move_to, a.objective)
                res[stem] = (r[0], r[1])
                fa.setdefault(sname, []).append(r[3])
                # C1 decomposition: coverage time = localization epoch - first OBSERVABLE drop epoch
                fd = first_drop_epoch_of(c, fault)
                if r[2] is not None and fd is not None:
                    obs.setdefault(sname, []).append(max(r[2] - fd, 0))
                    ev.setdefault(sname, []).append(max(fd - int(onset * 1000 // EPOCH_US), 0))
            per_sched[sname] = res
            ts = [t for t, _ in res.values()]; cs = [c for _, c in res.values()]
            cmp_ = ""
            if sname != "uniform" and "uniform" in per_sched:
                w, l, p = sign_test({k: v[0] for k, v in per_sched["uniform"].items()},
                                    {k: v[0] for k, v in res.items()})
                cmp_ = f"{w} faster / {l} slower, p={p:.3f}"
            kmm = km_median(ts, cs)
            kms = f"{kmm:.1f}" if kmm == kmm else f">{max(ts)} (>50% censored)"
            f = fa.get(sname, [0])
            print(f"| {b} | {sname} | {len(ts)} | {kms} | {statistics.median(ts):.1f} | "
                  f"{sum(cs)}/{len(cs)} | {sum(f)} ({sum(1 for x in f if x)}/{len(f)}) | {cmp_} |")
        if obs:
            print("\n  C1 decomposition (uncensored runs): evidence time = first observable drop - onset;")
            print("  coverage time = localization - first observable drop")
            for sname in per_sched:
                if sname in obs and obs[sname]:
                    print(f"    {sname:16s} evidence {statistics.median(ev[sname]):.1f} + coverage "
                          f"{statistics.median(obs[sname]):.1f} epochs (n={len(obs[sname])})")
            obs.clear(); ev.clear()
        if "oracle" in per_sched and "uniform" in per_sched and \
                km_median([t for t, _ in per_sched["uniform"].values()],
                          [c for _, c in per_sched["uniform"].values()]) == \
                km_median([t for t, _ in per_sched["uniform"].values()],
                          [c for _, c in per_sched["uniform"].values()]):
            o = km_median([t for t, _ in per_sched["oracle"].values()], [c for _, c in per_sched["oracle"].values()])
            u = km_median([t for t, _ in per_sched["uniform"].values()], [c for _, c in per_sched["uniform"].values()])
            gap = (u - o) or float("nan")
            counter = [k for k in per_sched if k not in ("oracle", "inband", "inband_sync")]
            if counter:
                best = min((km_median([t for t, _ in per_sched[k].values()],
                                      [c for _, c in per_sched[k].values()]), k) for k in counter)
                closed = 100 * (u - best[0]) / gap
                _, _, pg = sign_test({k: v[0] for k, v in per_sched["uniform"].items()},
                                     {k: v[0] for k, v in per_sched[best[1]].items()})
                verdict = ("TRIPPED — the allocation thesis is revived and H1 reopens"
                           if closed >= 30 and pg < 0.05 else "not tripped")
                print(f"\n  oracle {o:.1f}, uniform {u:.1f}; best COUNTER-COMPUTABLE schedule "
                      f"{best[1]} {best[0]:.1f} -> closes {closed:.0f}% of the oracle gap, "
                      f"paired p={pg:.3f} vs uniform. H9 gate (>=30% AND p<0.05): {verdict}")
            for k in ("inband", "inband_sync"):     # a different observability class, not a schedule
                if k in per_sched:
                    v = km_median([t for t, _ in per_sched[k].values()],
                                  [c for _, c in per_sched[k].values()])
                    print(f"  {k:12s} (in-band evidence, H8 -- NOT a counter-computable schedule) "
                          f"{v:.1f} -> closes {100*(u-v)/gap:.0f}% of the oracle gap")
            print()


if __name__ == "__main__":
    main()
