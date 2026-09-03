"""Localization head-to-head: MCP's per-directed-link ledger against faithful
SprayCheck-Z (arXiv:2605.03702, §3.6) and FlowPulse-theta (HotNets'25, §5.3)
localization, on IDENTICAL sprayed traffic.

Detection (`comparison.py`) answers "is something wrong?"; this module answers
"which exact DIRECTED link?" -- the question a repair action actually needs.
The two competitor papers are explicit that a single RX-only vantage cannot
answer it, and this module reproduces exactly why, then measures the gap.

WHY RX-ONLY ARRIVAL COUNTS CANNOT NAME A DIRECTED LINK (both papers' own words)
------------------------------------------------------------------------------
A packet from source leaf L_a to destination leaf L_b via spine S_i traverses
TWO directed links: the uplink u=(L_a->S_i) and the downlink d=(S_i->L_b). Any
arrival deficit at L_b is the PRODUCT of the two hops' survival -- an RX-only
counter aliases them.

- SprayCheck (arXiv:2605.03702 v1, §3.6, verified this session): "When the
  central monitor receives a failure report, it flags the entire path between
  the source and destination switch as potentially failed. This path consists
  of two links: the uplink from the source leaf to the spine (link 1), and the
  downlink from the spine to the destination leaf (link 2)." It reaches a
  single directed link only by cross-leaf INTERSECTION: "a link is considered
  failed when it is in the intersection of multiple failure reports that
  include a different leaf switch."
- FlowPulse (HotNets'25, §5.3, verbatim, verified this session): "Reduced
  traffic at a given ingress port can indicate either a fault on the local link
  ... or a fault on a remote link ... To distinguish these cases, FlowPulse
  compares the traffic volumes received from different senders over the given
  port. If traffic from all senders is equally affected, the local link is
  marked as failed. However, if only one sender is affected, the link between
  the spine switch and the leaf switch of the sender is marked as failed." It
  needs >=2 senders on the port (one as a clean control).

MCP's receiver ledger carries a per-hop witness stamp, so it observes each
directed link's OWN (tx, rx). It factors the product from a single vantage,
with no cross-referencing.

FAIRNESS -- the entire point, stated explicitly
------------------------------------------------------------------------------
ONE shared per-(source, dest, spine) spray/survival draw (`simulate_epoch`,
the same i.i.d.-uniform-spray + independent-per-hop-survival model as
`comparison.py`, extended to a 2-hop fabric) feeds all three arms every epoch.
Each arm is given its FULL, paper-faithful localizer and ONLY what its own
switch would see:
- MCP: per-directed-link (tx, rx) from its ledger (`make_mcp_loop`, unchanged).
- SprayCheck-Z: per-flow per-spine RX arrival counts, accumulated across epochs
  exactly as the detection harness accumulates them (RX-only cumulative N), plus
  its own §3.6 cross-leaf intersection over a completed round-robin cycle of
  measured flows. Never TX.
- FlowPulse-theta: per-(sender, spine-port) RX volumes + its own §5.3 per-sender
  rule, predicted from a bootstrapped `LearnedLoadModel`. Never TX.
The baselines are given their STRONGEST honest localizer (full cross-reference,
per-sender visibility their own papers assume) -- not a weakened one. Where they
still degrade, spraying is the cause, not a handicap.

TOPOLOGY
------------------------------------------------------------------------------
Full mesh: `n_leaves` leaves (each a source and a destination), `k` spines.
Exactly one directed link is degraded to `faulty_rate`; every other link is at
`healthy_rate`. Two fault families, run separately (they are the two cases the
papers' own localization rules distinguish):
- Family "down": faulty=('down', 0, 0) = S_0->L_0. Every source to L_0 via S_0
  is equally affected. SprayCheck resolves it by intersecting >=2 sources;
  FlowPulse by "all senders affected -> local".
- Family "up": faulty=('up', 1, 0) = L_1->S_0. Only source L_1's traffic via
  S_0 is affected, to every destination. SprayCheck resolves it by intersecting
  >=2 destinations; FlowPulse by "one sender affected -> that uplink".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

from controller.decision_loop import FleetDecisionLoop
from sim.baselines.comparison import make_mcp_loop
from sim.baselines.flowpulse_theta import FlowPulseDetector, LearnedLoadModel
from sim.baselines.spraycheck_z import SprayCheckConfig, SprayCheckDetector

# A directed link is a canonical tuple: ('up', src_leaf, spine) or
# ('down', spine, dst_leaf). The whole module speaks in these ids.
Link = Tuple[str, int, int]


@dataclass
class EpochDraw:
    """One epoch's shared ground truth on the 2-hop fabric.

    Arrays are indexed [src_leaf, dst_leaf, spine]. `tx` is packets a source
    sprayed to a spine for a given destination; `su` is what survived the
    uplink hop; `arr` is what finally arrived at the destination (survived both
    hops). Every arm derives its own view from these three arrays -- there is
    no separate per-arm ground truth."""
    tx: "object"   # numpy int array [n_leaves, n_leaves, k]
    su: "object"
    arr: "object"


def simulate_epoch(n_leaves: int, k: int, faulty_link: Optional[Link],
                   faulty_rate: float, healthy_rate: float,
                   packets_per_pair: int, rng) -> EpochDraw:
    """Shared 2-hop draw. Each ordered pair (a!=b) sprays `packets_per_pair`
    packets i.i.d.-uniform over k spines; each hop drops independently at its
    link's true rate. `faulty_link=None` is a fully healthy epoch (bootstrap).
    """
    import numpy as np
    tx = np.zeros((n_leaves, n_leaves, k), dtype=np.int64)
    su = np.zeros_like(tx)
    arr = np.zeros_like(tx)

    def up_rate(a: int, i: int) -> float:
        return faulty_rate if faulty_link == ('up', a, i) else healthy_rate

    def down_rate(i: int, b: int) -> float:
        return faulty_rate if faulty_link == ('down', i, b) else healthy_rate

    for a in range(n_leaves):
        for b in range(n_leaves):
            if a == b:
                continue
            sent = rng.multinomial(packets_per_pair, [1.0 / k] * k)
            for i in range(k):
                s = int(sent[i])
                tx[a, b, i] = s
                after_up = s - rng.binomial(s, up_rate(a, i)) if s > 0 else 0
                su[a, b, i] = after_up
                after_down = (after_up - rng.binomial(after_up, down_rate(i, b))
                              if after_up > 0 else 0)
                arr[a, b, i] = after_down
    return EpochDraw(tx=tx, su=su, arr=arr)


# ---------------------------------------------------------------------------
# MCP view: per-directed-link (tx, rx) from the receiver ledger.
# ---------------------------------------------------------------------------

def mcp_link_counters(draw: EpochDraw, n_leaves: int, k: int) -> Dict[Link, Tuple[int, int]]:
    """The exact per-directed-link (tx, rx) pair MCP's witness ledger produces:
    an uplink's tx/rx sum over destinations; a downlink's over sources."""
    counters: Dict[Link, Tuple[int, int]] = {}
    for a in range(n_leaves):
        for i in range(k):
            tx = int(draw.tx[a, :, i].sum())
            rx = int(draw.su[a, :, i].sum())
            if tx > 0:
                counters[('up', a, i)] = (tx, rx)
    for i in range(k):
        for b in range(n_leaves):
            tx = int(draw.su[:, b, i].sum())
            rx = int(draw.arr[:, b, i].sum())
            if tx > 0:
                counters[('down', i, b)] = (tx, rx)
    return counters


class MCPLocalizer:
    """Runs MCP's own frozen decision loop over EVERY directed link, exactly as
    the detection harness runs it over every spine. Localizes to the set of
    links the fleet e-BH controller rejects."""

    def __init__(self):
        self.loop: FleetDecisionLoop = make_mcp_loop()
        self._ids: Dict[Link, int] = {}

    def _id(self, link: Link) -> int:
        if link not in self._ids:
            self._ids[link] = len(self._ids)
        return self._ids[link]

    def tick(self, epoch: int, counters: Dict[Link, Tuple[int, int]]) -> FrozenSet[Link]:
        id_to_link = {}
        snapshot = {}
        for link, (tx, rx) in counters.items():
            lid = self._id(link)
            id_to_link[lid] = link
            snapshot[lid] = (tx, rx)
        decisions = self.loop.tick(epoch, snapshot)
        return frozenset(id_to_link[lid] for lid, d in decisions.items()
                         if d.fleet_rejected)


class CounterPairLocalizer:
    """CounterPair-0B: the same per-directed-link (tx, rx) information as the
    ledger, but with the transmit register on the SENDING switch and the
    receive register on the RECEIVING switch, read at two instants. The tx
    observation is perturbed by the read-skew model of
    `comparison.counterpair_tx` (skew as a fraction of the epoch; 0 is the
    idealized bound with identical information to the ledger). Same frozen
    decision rule."""

    def __init__(self, skew_frac: float, seed: int):
        import numpy as np
        from sim.baselines.comparison import counterpair_tx
        self._cp_tx = counterpair_tx
        self.skew = skew_frac
        self.loop: FleetDecisionLoop = make_mcp_loop()
        self._ids: Dict[Link, int] = {}
        self._prev: Dict[Link, float] = {}
        self._rng = np.random.default_rng(seed + 2_000_003)

    def _id(self, link: Link) -> int:
        if link not in self._ids:
            self._ids[link] = len(self._ids)
        return self._ids[link]

    def tick(self, epoch: int, counters: Dict[Link, Tuple[int, int]]) -> FrozenSet[Link]:
        id_to_link = {}
        snapshot = {}
        for link, (tx, rx) in counters.items():
            tx_obs, off = self._cp_tx(tx, rx, float(tx), self.skew,
                                      self._prev.get(link, 0.0), self._rng)
            self._prev[link] = off
            lid = self._id(link)
            id_to_link[lid] = link
            snapshot[lid] = (tx_obs, rx)
        decisions = self.loop.tick(epoch, snapshot)
        return frozenset(id_to_link[lid] for lid, d in decisions.items()
                         if d.fleet_rejected)


# ---------------------------------------------------------------------------
# SprayCheck-Z view: per-flow per-spine RX + §3.6 cross-leaf intersection.
# ---------------------------------------------------------------------------

def spraycheck_localize(cum_arr, n_leaves: int, k: int, s: float
                        ) -> Tuple[bool, FrozenSet[Link], List[Tuple[int, int, int]]]:
    """A completed round-robin cycle over the CUMULATIVE per-flow arrivals so
    far. SprayCheck measures one flow at a time (§3.4); a full cycle is its best
    case. `cum_arr[a, b, i]` is the cumulative RX arrival count for flow
    (L_a -> L_b) via spine i. Each flow is Z-tested at its own observed size
    N = sum_i cum_arr[a, b, :] (lambda = N/k) -- exactly the RX-only cumulative-N
    rule the detection harness (`comparison.py`) uses -- then §3.6 intersection.

    Returns (detected, localized_set, flagged_paths). `detected` is True iff any
    measured flow flags a spine (something is localizable at all). A flagged
    path (a, i, b) implicates the two directed links ('up',a,i) and ('down',i,b).
    A directed link is CONFIRMED (§3.6) when it lies in the intersection of
    reports from a DIFFERENT leaf: a downlink if >=2 sources flag it, an uplink
    if >=2 destinations flag it. If nothing is confirmed but paths were flagged,
    the returned set is the UNION of every flagged path's two links -- the
    genuine ambiguity SprayCheck is left with when it cannot corroborate."""
    flagged_paths: List[Tuple[int, int, int]] = []
    for a in range(n_leaves):
        for b in range(n_leaves):
            if a == b:
                continue
            arrivals = {i: int(cum_arr[a, b, i]) for i in range(k)}
            n_flow = sum(arrivals.values())
            if n_flow <= 0:
                continue
            cfg = SprayCheckConfig(k=k, flow_packets=n_flow, s=s)
            for i in SprayCheckDetector(cfg).detect_flow(arrivals):
                flagged_paths.append((a, i, b))

    detected = len(flagged_paths) > 0
    # §3.6 intersection over reports that include a different leaf.
    down_sources: Dict[Tuple[int, int], set] = {}   # (i,b) -> {sources}
    up_dests: Dict[Tuple[int, int], set] = {}        # (a,i) -> {dests}
    for (a, i, b) in flagged_paths:
        down_sources.setdefault((i, b), set()).add(a)
        up_dests.setdefault((a, i), set()).add(b)

    confirmed: set = set()
    for (i, b), srcs in down_sources.items():
        if len(srcs) >= 2:
            confirmed.add(('down', i, b))
    for (a, i), dsts in up_dests.items():
        if len(dsts) >= 2:
            confirmed.add(('up', a, i))

    if confirmed:
        return detected, frozenset(confirmed), flagged_paths
    ambiguous: set = set()
    for (a, i, b) in flagged_paths:
        ambiguous.add(('up', a, i))
        ambiguous.add(('down', i, b))
    return detected, frozenset(ambiguous), flagged_paths


class SprayCheckLocalizer:
    """Stateful wrapper: accumulates each onset epoch's per-flow arrivals (so a
    flow's tested size N grows with time, matching the detection harness's
    cumulative RX-only N), then re-runs the full-cycle intersection each epoch."""

    def __init__(self, n_leaves: int, k: int, s: float):
        import numpy as np
        self.n_leaves = n_leaves
        self.k = k
        self.s = s
        self._cum = np.zeros((n_leaves, n_leaves, k), dtype=np.int64)

    def observe_and_localize(self, draw: EpochDraw
                             ) -> Tuple[bool, FrozenSet[Link]]:
        self._cum += draw.arr
        detected, localized, _ = spraycheck_localize(
            self._cum, self.n_leaves, self.k, self.s)
        return detected, localized


# ---------------------------------------------------------------------------
# FlowPulse-theta view: per-(sender, port) RX + §5.3 per-sender rule.
# ---------------------------------------------------------------------------

class FlowPulseLocalizer:
    """Learns a per-(port) and per-(port, sender) baseline over healthy
    bootstrap epochs, then at a chosen victim port applies §5.3: detect on the
    aggregate port deviation, localize by comparing per-sender deviations."""

    def __init__(self, spine: int, dst: int, senders: List[int],
                 bootstrap_iters: int = 5, threshold: float = 0.01):
        self.spine = spine
        self.dst = dst
        self.senders = senders
        self.detector = FlowPulseDetector(threshold=threshold)
        self.threshold = threshold
        self.port_model = LearnedLoadModel(bootstrap_iters=bootstrap_iters)
        self.sender_models = {a: LearnedLoadModel(bootstrap_iters=bootstrap_iters)
                              for a in senders}

    def _port_key(self) -> str:
        return f"{self.spine}:{self.dst}"

    def observe(self, draw: EpochDraw) -> None:
        agg = 0.0
        for a in self.senders:
            v = float(draw.arr[a, self.dst, self.spine])
            self.sender_models[a].observe(str(a), v)
            agg += v
        self.port_model.observe(self._port_key(), agg)

    def localize(self, draw: EpochDraw) -> Tuple[bool, FrozenSet[Link]]:
        """Returns (detected, localized_set). Detection is the aggregate-port
        1% test (§5.3 "Detection"). Localization (§5.3 "Localization"): all
        senders affected -> local downlink; exactly one -> that sender's uplink;
        anything else is outside the two cases the paper's rule covers, so the
        honest output is the whole port's candidate set (the local downlink plus
        every sender's uplink into this spine)."""
        predicted_port = self.port_model.predicted_port_load(self._port_key())
        observed_port = float(sum(draw.arr[a, self.dst, self.spine] for a in self.senders))
        if predicted_port is None or predicted_port <= 0:
            return False, frozenset()
        if not self.detector.flag(observed_port, predicted_port):
            # still-clean observation: keep learning (do not poison baseline)
            self.observe(draw)
            return False, frozenset()

        affected: List[int] = []
        for a in self.senders:
            pred = self.sender_models[a].predicted_port_load(str(a))
            obs = float(draw.arr[a, self.dst, self.spine])
            if pred is None or pred <= 0:
                continue
            if self.detector.deviation(obs, pred) > self.threshold:
                affected.append(a)

        if len(affected) == len(self.senders) and self.senders:
            return True, frozenset({('down', self.spine, self.dst)})
        if len(affected) == 1:
            return True, frozenset({('up', affected[0], self.spine)})
        # ambiguous: the paper's rule covers only "all" and "exactly one".
        port_set = {('down', self.spine, self.dst)}
        for a in self.senders:
            port_set.add(('up', a, self.spine))
        return True, frozenset(port_set)


# ---------------------------------------------------------------------------
# Scoring: turn a localized set + ground-truth link into the three metrics.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArmLocalization:
    """One arm's localization outcome on one trial.

    `detected` -- the arm produced a non-empty localization at all.
    `exact`    -- it named the true faulty directed link and ONLY it.
    `wrong`    -- among detections, its set contains at least one non-faulty
                  link (false localization); not mutually exclusive with a set
                  that also happens to contain the true link.
    `cardinality` -- size of the returned set (None when not detected); this is
                  the "ambiguous-set cardinality" -- 1 is an exact directed-link
                  call, >1 is an ambiguous set the arm could not narrow."""
    detected: bool
    exact: bool
    wrong: bool
    cardinality: Optional[int]


def score_localization(localized_set: FrozenSet[Link], faulty_link: Link,
                       detected: bool) -> ArmLocalization:
    if not detected or not localized_set:
        return ArmLocalization(detected=False, exact=False, wrong=False,
                               cardinality=None)
    exact = (localized_set == frozenset({faulty_link}))
    wrong = any(link != faulty_link for link in localized_set)
    return ArmLocalization(detected=True, exact=exact, wrong=wrong,
                           cardinality=len(localized_set))
