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
        # ONE full pass. The old cap of 4*len(names) advanced the cursor 4096 times = 0 mod
        # 1024, so on an epoch with fewer than `budget` eligible links the cursor came back to
        # exactly where it started and the schedule made no round-robin progress at all (H29).
        while len(out) < self.budget and tried < len(self.names):
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
        # ONE full pass. The old cap of 4*len(names) advanced the cursor 4096 times = 0 mod
        # 1024, so on an epoch with fewer than `budget` eligible links the cursor came back to
        # exactly where it started and the schedule made no round-robin progress at all (H29).
        while len(out) < self.budget and tried < len(self.names):
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


class Confirm(Schedule):
    """Round-robin until the localizer suspects something, then PIN the suspects and fill.

    The member of the counter-computable class that would beat round-robin if localization ever
    needed more than one read of the faulty link: it turns a first read into continuous
    observation. A negative result about the class is only worth stating with this arm in it.
    """
    name = "confirm"

    def pick(self, epoch, cum, state):
        known = set(self.names)
        pin = [e[len("vlink:"):] for e, st in
               sorted(state.elements.items(), key=lambda kv: -kv[1].cusum) if st.cusum > 0.0]
        pin = [n for n in pin if n in known][: self.budget]
        return pin + self._rr(self.budget - len(pin), exclude=pin)


class Thompson(Schedule):
    """Thompson sampling over the per-link Beta posteriors the frozen localizer already keeps."""
    name = "thompson"

    def pick(self, epoch, cum, state):
        scored = []
        for n in self.names:
            st = state.elements.get("vlink:" + n)
            a, b = (st.loss_alpha, st.loss_beta) if st is not None else (1.0, 1.0)
            scored.append((self.rng.betavariate(max(a, 1e-6), max(b, 1e-6)), n))
        scored.sort(key=lambda t: -t[0])
        return [n for _, n in scored[: self.budget]]


class Oracle(Schedule):
    """Upper bound: always read the faulty link(s), fill with round-robin."""
    name = "oracle"
    def pick(self, epoch, cum, state):
        out = [n for n in self.faulty if n in self.names][: self.budget]
        return out + self._rr(self.budget - len(out), exclude=out)


SCHEDULES = {c.name: c for c in (Uniform, Random_, LoadGated, ThresholdGated, Greedy, Confirm,
                                 Thompson, Oracle, InBand, InBandSync)}
# the in-band arms are NOT schedules -- they are a different observation, reported separately
COUNTER_COMPUTABLE = ("uniform", "random", "load_gated", "threshold_gated", "greedy", "confirm",
                      "thompson")


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


def apply_scenario(names, per_epoch, stem, fault, onset_epoch, extra_faults, move_epoch, move_to,
                   move_p):
    """Materialise the scenario ONCE per seed, before any schedule runs.

    Semi-synthetic faults and fault movement must not be drawn inside a schedule's read loop. If
    they are, every arm faces a different realisation of the fabric, which destroys the exactness
    the recorded fault has (byte-identical counter logs across arms) and makes the paired tests
    compare different worlds. And a "moving" fault implemented by relabelling the success criterion
    does not move anything at all: the original link keeps dropping, so its CORRECT detections get
    counted as false alarms and the moved-to link never produces evidence (H29).

    Here the effective cumulative (tx, drop) series is rewritten once per seed: extra faults ADD
    drops; a move SUBTRACTS the original link's drops from ``move_epoch`` on and starts dropping on
    the new link instead. Every arm then replays the same series, exactly as for the recorded fault.
    """
    eps = sorted(per_epoch)
    add: Dict[str, Dict[int, int]] = {}
    inject = dict(extra_faults)
    if move_epoch and move_to:
        inject[move_to] = move_p
    for n, p in inject.items():
        rng = random.Random(scenario_seed(stem, "drops/" + n))
        start = move_epoch if (move_epoch and n == move_to) else onset_epoch
        run, prev_tx, series = 0, 0, {}
        for t in eps:
            tx = per_epoch[t].get(n, (0, 0))[0]
            dtx = max(tx - prev_tx, 0)
            prev_tx = tx
            if t >= start and dtx > 0:
                run += _poisson(dtx * p, rng)
            series[t] = run
        add[n] = series
    sub: Dict[str, Dict[int, int]] = {}
    if move_epoch and move_to:              # the vacated link stops dropping at move_epoch
        at_move, series = None, {}
        for t in eps:
            d = per_epoch[t].get(fault, (0, 0))[1]
            if t >= move_epoch and at_move is None:
                at_move = d
            series[t] = max(d - at_move, 0) if at_move is not None else 0
        sub[fault] = series
    eff = {t: {n: (tx, drop - sub.get(n, {}).get(t, 0) + add.get(n, {}).get(t, 0))
               for n, (tx, drop) in per_epoch[t].items()} for t in eps}
    return eff


def first_drop_epoch(per_epoch, link: str, after: int):
    """First epoch at or after ``after`` at which ``link``'s cumulative drop count rises.

    GROUND TRUTH, not an arm-computable quantity: it reads the injected fault's identity out of
    the log. It feeds the evidence/coverage diagnostic only -- never TTL, never a headline number.
    """
    prev = None
    for t in sorted(per_epoch):
        d = per_epoch[t].get(link, (0, 0))[1]
        if prev is not None and t >= after and d > prev:
            return t
        prev = d
    return None


def replay_seed(names, per_epoch, faulty, onset_epoch, horizon, sched_name, budget, seed, h,
                objective, move_epoch, move_to):
    """Replay one seed over an ALREADY-MATERIALISED counter series.

    Returns (TTL from onset, censored, detection epoch, wrong-link alarm epochs, epochs run,
    total link-reads).

    ``objective`` names the multi-fault success semantics explicitly (PREREG v1.6 §14):
    ``any`` -- the top-ranked element is any injected fault; ``all`` -- every injected fault has
    been top-ranked; ``original`` -- the recorded fault only, the synthetic ones are distractors.

    A wrong-link alarm epoch is one whose anomaly bit is set while the top-ranked element is no
    injected fault. It is counted over the WHOLE run, pre-onset included, and returned with the
    number of epochs the arm actually ran so it can be reported as a rate rather than a count
    (arms that detect early are exposed for fewer epochs).
    """
    sch = SCHEDULES[sched_name](names, budget, seed, list(faulty))
    state = infer.InferState()
    want = {"vlink:" + f for f in (faulty if objective != "original" else faulty[:1])}
    all_injected = {"vlink:" + f for f in faulty}
    identified: set = set()
    alarms, epochs_run, reads = 0, 0, 0
    for epoch in sorted(per_epoch):
        cum = per_epoch[epoch]
        epochs_run += 1
        if move_epoch and epoch == move_epoch and move_to:
            sch.faulty = [move_to]
            want = {"vlink:" + move_to}
            all_injected = {"vlink:" + move_to}
            identified = set()
        chosen = sch.pick(epoch, cum, state)
        reads += len(chosen)
        samples = []
        for n in chosen:
            tx, drop = cum.get(n, (0, 0))
            tx0, drop0 = sch.last_seen.get(n, (0, 0))
            dtx, ddrop = tx - tx0, max(drop - drop0, 0)
            sch.last_seen[n] = (tx, drop)
            sch.last_epoch[n] = epoch
            if dtx > 0:
                samples.append(Sample(element=f"vlink:{n}", delivered=max(dtx - ddrop, 0),
                                      lost=ddrop, latency_us=(), t_us=int(epoch * EPOCH_US)))
        state = infer.update(state, samples, {}, baseline_mode="pooled")
        loc = infer.localize(state, k=max(1, len(want)), h=h)
        if loc.anomaly and loc.ranked:
            top = loc.ranked[0][0]
            if top not in all_injected:
                alarms += 1
            elif epoch >= onset_epoch and top in want:
                # "all" is suspect-set CONTAINMENT, not a sequence of top-1 hits: CUSUMs are
                # monotone for read elements, so demanding that fault B overtake fault A's
                # statistic measures the ranking's inertia, not localization (H29).
                if objective != "all":
                    return epoch - onset_epoch, False, epoch, alarms, epochs_run, reads
                identified = want & set(loc.suspects)
                if identified >= want:
                    return epoch - onset_epoch, False, epoch, alarms, epochs_run, reads
    return max(horizon - onset_epoch, 0), True, None, alarms, epochs_run, reads


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
    ap.add_argument("--extra-p", type=float, default=1e-4,
                    help="loss rate of a semi-synthetic or moved fault (= the recorded F1 rate)")
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
    print(f"# objective={a.objective}; detector = frozen controller/infer.py {infer.module_hash()[:8]}")
    print("\n| budget | schedule | n | KM median TTL | raw median | censored | reads/epoch | "
          "wrong-link alarms (per 100 epochs) | vs uniform (faster/slower, p, n) |")
    print("|---|---|---|---|---|---|---|---|---|")
    for b in budgets:
        per_sched: Dict[str, Dict[str, Tuple[int, bool]]] = {s: {} for s in scheds}
        cov: Dict[str, List[Tuple[int, bool]]] = {s: [] for s in scheds}
        ev: Dict[str, List[int]] = {s: [] for s in scheds}
        alarm: Dict[str, List[Tuple[int, int]]] = {s: [] for s in scheds}
        load: Dict[str, List[float]] = {s: [] for s in scheds}
        for c in runs:
            stem = c.name.split(".")[0]
            fault = (root / f"{stem}.fault").read_text().strip()
            onset = float((root / f"{stem}.onset").read_text().strip())
            onset_epoch = int(onset * 1000 // EPOCH_US)
            names, raw = load_counters(c)
            extra: Dict[str, float] = {}
            if a.faults > 1:
                rng = random.Random(scenario_seed(stem, "extra"))
                for n in rng.sample([n for n in names if n != fault], a.faults - 1):
                    extra[n] = a.extra_p
            move_to = ""
            if a.move_fault_epoch:
                move_to = random.Random(scenario_seed(stem, "move")).choice(
                    [n for n in names if n != fault and n not in extra])
            eff = apply_scenario(names, raw, stem, fault, onset_epoch, extra,
                                 a.move_fault_epoch, move_to, a.extra_p)
            horizon = max(eff)
            gt = move_to if a.move_fault_epoch else fault
            fd = first_drop_epoch(eff, gt, max(onset_epoch, a.move_fault_epoch))
            injected = [fault] + [n for n in extra if n != fault]
            for sname in scheds:
                r = replay_seed(names, eff, injected, onset_epoch, horizon, sname, b,
                                int(stem.replace("seed", "")), a.h, a.objective,
                                a.move_fault_epoch, move_to)
                per_sched[sname][stem] = (r[0], r[1])
                alarm[sname].append((r[3], r[4]))
                load[sname].append(r[5] / max(r[4], 1))
                if fd is not None:
                    if r[2] is not None:
                        cov[sname].append((max(r[2] - fd, 0), False))
                        ev[sname].append(max(fd - onset_epoch, 0))
                    else:
                        cov[sname].append((max(horizon - fd, 0), True))
        for sname in scheds:
            res = per_sched[sname]
            ts = [t for t, _ in res.values()]; cs = [c for _, c in res.values()]
            cmp_ = ""
            if sname != "uniform" and "uniform" in per_sched:
                w, l, pv = sign_test({k: v[0] for k, v in per_sched["uniform"].items()},
                                     {k: v[0] for k, v in res.items()})
                cmp_ = f"{w} faster / {l} slower, p={pv:.3f}, n={w + l}"
            kmm = km_median(ts, cs)
            kms = f"{kmm:.1f}" if kmm == kmm else f">{max(ts)} (>50% censored)"
            al = sum(x for x, _ in alarm[sname]); ep = sum(e for _, e in alarm[sname])
            print(f"| {b} | {sname} | {len(ts)} | {kms} | {statistics.median(ts):.1f} | "
                  f"{sum(cs)}/{len(cs)} | {statistics.mean(load[sname]):.1f} | "
                  f"{al} ({100.0 * al / max(ep, 1):.2f}) | {cmp_} |")
        bound = (len(names) - b) / (2.0 * b)
        print(f"\n  coverage time (localization - first observable drop), KM median WITH censored "
              f"runs; classical search bound (n-B)/2B = {bound:.1f} epochs at n={len(names)}, B={b}:")
        allev = [x for s_ in scheds for x in ev[s_]]
        if allev:
            # evidence time is a property of the fault and the traffic phase: it is computed from
            # the log and the injected fault's identity, so it is IDENTICAL for every arm by
            # construction. Reporting it per arm would dress a definition up as a measurement.
            print(f"    evidence time (all arms, by construction): {statistics.median(allev):.1f} epochs")
        for sname in scheds:
            if cov[sname]:
                k = km_median([t for t, _ in cov[sname]], [c for _, c in cov[sname]])
                ks = f"{k:.1f}" if k == k else ">50% censored"
                print(f"    {sname:16s} coverage {ks} "
                      f"({sum(1 for _, c in cov[sname] if c)}/{len(cov[sname])} censored)")
        u = km_median([t for t, _ in per_sched["uniform"].values()],
                      [c for _, c in per_sched["uniform"].values()]) if "uniform" in per_sched else float("nan")
        o = km_median([t for t, _ in per_sched["oracle"].values()],
                      [c for _, c in per_sched["oracle"].values()]) if "oracle" in per_sched else float("nan")
        counter = [k for k in scheds if k in COUNTER_COMPUTABLE and k != "uniform"]
        if not (math.isnan(u) or math.isnan(o)):
            gap = (u - o) or float("nan")
            cands = [(km_median([t for t, _ in per_sched[k].values()],
                                [c for _, c in per_sched[k].values()]), k) for k in counter]
            cands = [(v, k) for v, k in cands if not math.isnan(v)]
            if not cands:
                print(f"\n  oracle {o:.1f}, uniform {u:.1f}; H9 gate UNDEFINED at this budget: every "
                      f"other counter-computable arm is >50% censored, so its KM median does not exist\n")
            else:
                best = min(cands + [(u, "uniform")])
                closed = 100 * (u - best[0]) / gap
                _, _, pg = sign_test({k: v[0] for k, v in per_sched["uniform"].items()},
                                     {k: v[0] for k, v in per_sched[best[1]].items()})
                verdict = ("TRIPPED -- the allocation thesis is revived and H1 reopens"
                           if closed >= 30 and pg < 0.05 else "not tripped")
                print(f"\n  oracle {o:.1f}, uniform {u:.1f}; best COUNTER-COMPUTABLE schedule "
                      f"{best[1]} {best[0]:.1f} -> closes {closed:.0f}% of the oracle gap, "
                      f"paired p={pg:.3f}. H9 gate (>=30% AND p<0.05): {verdict}")
        else:
            print(f"\n  H9 gate UNDEFINED at budget {b} (uniform or oracle >50% censored)")
        for k in ("inband", "inband_sync"):
            if k in per_sched:
                v = km_median([t for t, _ in per_sched[k].values()],
                              [c for _, c in per_sched[k].values()])
                vs = f"{v:.1f}" if v == v else ">50% censored"
                print(f"  {k:12s} (in-band evidence = UNBUDGETED, B=n; not a schedule) {vs}")
        print()


if __name__ == "__main__":
    main()
