"""Correlated / multi-link fault stress harness (attack A4).

Every committed head-to-head result (`comparison.py`, `localization.py`) injects
exactly ONE independent single directed-link fault, matching PREREG v1.9. This
module extends the SAME shared-stream, each-arm-sees-only-its-own-switch fairness
discipline to the CORRELATED regime the venue ceiling depends on:

  R1  multi_independent -- M in {2, 3} distinct directed links degraded at once
      (a genuinely multi-fault fabric); ground truth = that set of links.
  R2  common_mode       -- a shared-cause shock raises loss on EVERY directed
      link at once (a fabric-wide congestion/thermal event); NO single link is
      individually worse, so the correct behaviour is to NOT localize any link.
      Ground truth = the empty set; any link named is a false localization.
  R3  shock_plus_culprit -- the common-mode shock PLUS one link additionally
      worse than the shifted background; ground truth = that one culprit link.
      Tests whether a real fault is still found against a correlated background.

All three are one generator (`simulate_epoch_correlated`): a directed link's
loss rate is `faulty_rate` if it is in the faulty set, else `base_rate`
(`base_rate` = the healthy floor in R1, the shock level in R2/R3).

Arms, each given ONLY its own switch's view, fabric-wide (see `localization.py`
for the per-arm information argument, reused verbatim here):
  - MCP: per-directed-link (tx, rx) -> its frozen decision loop over every link.
  - SprayCheck-Z: RX-only per-flow arrivals + its full §3.6 cross-leaf
    intersection (`SprayCheckLocalizer`, fabric-wide already).
  - FlowPulse-theta: per-(sender, ingress port) RX vs a learned baseline, applied
    at EVERY (spine, dst) ingress port (`FleetFlowPulseLocalizer`), not one port.
Two reference anchors are reported next to them, per this repo's cross-check #4
(a safety number is meaningless without the action number beside it):
  - do_nothing: never localizes (false-positive 0, recall 0 -- the "perfectly
    safe, perfectly useless" floor).
  - oracle: returns exactly the true set (a sanity upper bound; if it ever fails
    to "detect" an injected fault the harness, not the method, is broken).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Tuple

from sim.baselines.localization import (
    EpochDraw, FlowPulseLocalizer as _FPL, Link,
)


def simulate_epoch_correlated(n_leaves: int, k: int,
                              faulty_links: FrozenSet[Link], faulty_rate: float,
                              base_rate: float, packets_per_pair: int,
                              rng, elevated_links: FrozenSet[Link] = frozenset(),
                              elevated_rate: float = 0.0) -> EpochDraw:
    """Shared 2-hop draw with a SET of faulty directed links over a `base_rate`
    background. Each ordered pair (a!=b) sprays `packets_per_pair` i.i.d.-uniform
    over k spines; each hop drops independently at its link's true rate
    (`faulty_rate` if that directed link is in `faulty_links`, else `base_rate`).
    `faulty_links=frozenset()` with `base_rate=shock` is the pure common-mode
    shock; with `base_rate=healthy` and a non-empty set it is multi-independent.

    R4 (partial correlation, e.g. incast at a collective's reduction point):
    `elevated_links` carry `elevated_rate` -- persistent congestion loss on a
    SUBSET of links that is NOT a fault and must not be named -- while the
    rest of the fabric sits at `base_rate`. A link in `faulty_links` is always
    a fault, whether or not it is also in the elevated subset.
    """
    import numpy as np
    tx = np.zeros((n_leaves, n_leaves, k), dtype=np.int64)
    su = np.zeros_like(tx)
    arr = np.zeros_like(tx)

    def rate_of(link: Link) -> float:
        if link in faulty_links:
            return faulty_rate
        if link in elevated_links:
            return elevated_rate
        return base_rate

    def up_rate(a: int, i: int) -> float:
        return rate_of(('up', a, i))

    def down_rate(i: int, b: int) -> float:
        return rate_of(('down', i, b))

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


class FleetFlowPulseLocalizer:
    """FlowPulse-theta applied at EVERY (spine, dst) ingress port, unioning the
    per-port §5.3 localizations -- the faithful "every leaf switch counts every
    ingress port" reading (§5.3), not the single-victim-port view. Detection =
    any port fires; localized set = union of every port's named link."""

    def __init__(self, n_leaves: int, k: int, bootstrap_iters: int = 5,
                 threshold: float = 0.01):
        self.n_leaves = n_leaves
        self.k = k
        self.ports: Dict[Tuple[int, int], _FPL] = {}
        for i in range(k):
            for b in range(n_leaves):
                senders = [a for a in range(n_leaves) if a != b]
                self.ports[(i, b)] = _FPL(spine=i, dst=b, senders=senders,
                                          bootstrap_iters=bootstrap_iters,
                                          threshold=threshold)

    def observe(self, draw: EpochDraw) -> None:
        for port in self.ports.values():
            port.observe(draw)

    def localize(self, draw: EpochDraw) -> Tuple[bool, FrozenSet[Link]]:
        union: set = set()
        detected = False
        for port in self.ports.values():
            det, links = port.localize(draw)
            if det:
                detected = True
                union |= set(links)
        return detected, frozenset(union)


# ---------------------------------------------------------------------------
# Multi-fault scoring.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MultiScore:
    """One arm's outcome against a (possibly multi-link or empty) true set.

    detected      -- named at least one link.
    n_true        -- size of the ground-truth fault set (0 for common-mode).
    n_true_hit    -- true links the arm named (|localized & true|).
    n_false       -- non-faulty links the arm named (|localized \\ true|) --
                     the false-localization count; each is a wrong repair target.
    recall        -- n_true_hit / n_true (None when n_true == 0).
    exact_all     -- localized == true and n_true > 0 (named all faults, nothing
                     else). Meaningless for common-mode (n_true == 0).
    any_false     -- n_false > 0 (took at least one wrong action).
    localized_n   -- size of the returned set.
    """
    detected: bool
    n_true: int
    n_true_hit: int
    n_false: int
    recall: Optional[float]
    exact_all: bool
    any_false: bool
    localized_n: int


def score_multi(localized_set: FrozenSet[Link], true_links: FrozenSet[Link]
                ) -> MultiScore:
    hits = localized_set & true_links
    false = localized_set - true_links
    n_true = len(true_links)
    recall = (len(hits) / n_true) if n_true > 0 else None
    return MultiScore(
        detected=len(localized_set) > 0,
        n_true=n_true,
        n_true_hit=len(hits),
        n_false=len(false),
        recall=recall,
        exact_all=(n_true > 0 and localized_set == true_links),
        any_false=len(false) > 0,
        localized_n=len(localized_set),
    )
