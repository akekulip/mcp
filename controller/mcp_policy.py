"""mcp_policy.py — the slow-loop learner of MCP (PREREG §0, §8.1, ablations §4.1 A1–A4).

A constrained contextual bandit over measurable ELEMENTS (links in the sim, paths on hardware):

* context ``x_e`` per element, built only from the frozen localizer's state (§3.3) and the
  policy's own bookkeeping — posterior-mean loss, posterior std, CUSUM evidence, recency,
  load, flagged-before;
* reward ``r_e`` per chosen element = that element's §7.2 terms, uncertainty reduction
  ``log s2(t-1) - log s2(t)`` plus ``beta * min(1, C_e/kappa)``; unchosen elements get 0.
  Observation-only by construction (it reads InferState, never ground truth);
* learner: LinUCB with a shared theta in the three §8.1 variants — stationary, discounted
  (gamma) and sliding-window (W) — score ``u_e = theta.x + alpha*sqrt(x A^-1 x)``;
* allocation: greedy knapsack on ``u_e - sum_r lambda_r c_{e,r}`` under per-resource caps
  ``B_r``; shadow prices re-priced each epoch by dual ascent ``lambda_r += eta*(usage_r - B_r)``.
  NOTE: in the htsim gate there is ONE resource with unit cost per probe and a hard per-epoch
  cap, so the prices are inert there (ablation A1 == full MCP in that setting); they bind on
  hardware, where attention levels cost mirror bytes and collector bandwidth (§2.3).

Ablations (§4.1): A1 ``no_prices`` (lambda fixed at initial, hard clipping only);
A2 ``no_context`` (x = [1]); A3 ``alpha = 0``; A4 ``reset_each_epoch``.
Pure Python (d <= 8), no numpy, so it runs on the switch's python3.8.
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from controller import infer

D = 7  # context dimension


@dataclass
class McpConfig:
    learner: str = "linucb"        # linucb | dlinucb | swlinucb
    alpha: float = 1.0             # exploration coefficient (A3: 0)
    gamma: float = 0.99            # dlinucb discount
    window: int = 100              # swlinucb window (epochs)
    ridge: float = 1.0
    eta: float = 0.05              # dual-ascent step for shadow prices
    beta: float = 1.0              # §7.2 evidence weight
    kappa: float = 4.0             # §7.2 evidence scale (= localizer h)
    no_prices: bool = False        # A1
    no_context: bool = False       # A2
    reset_each_epoch: bool = False # A4
    caps: Dict[str, float] = field(default_factory=lambda: {"probes": 4.0})
    prices0: Dict[str, float] = field(default_factory=lambda: {"probes": 0.0})


def _solve(a: List[List[float]], b: List[float]) -> List[float]:
    """Gaussian elimination with partial pivoting (d is tiny)."""
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(m[r][c]))
        m[c], m[p] = m[p], m[c]
        piv = m[c][c] or 1e-12
        for r in range(n):
            if r != c:
                f = m[r][c] / piv
                if f:
                    for k in range(c, n + 1):
                        m[r][k] -= f * m[c][k]
    return [m[i][n] / (m[i][i] or 1e-12) for i in range(n)]


class LinUCB:
    """Shared-theta LinUCB; stationary / discounted / sliding-window (§8.1)."""

    def __init__(self, d: int, cfg: McpConfig):
        self.d, self.cfg = d, cfg
        self.hist: Deque[Tuple[List[float], float]] = deque()
        self.reset()

    def reset(self) -> None:
        self.A = [[self.cfg.ridge if i == j else 0.0 for j in range(self.d)] for i in range(self.d)]
        self.b = [0.0] * self.d
        self.hist.clear()

    def update(self, x: List[float], r: float) -> None:
        c = self.cfg
        if c.learner == "swlinucb":
            self.hist.append((x, r))
            while len(self.hist) > c.window:
                self.hist.popleft()
            self.A = [[c.ridge if i == j else 0.0 for j in range(self.d)] for i in range(self.d)]
            self.b = [0.0] * self.d
            for xx, rr in self.hist:
                self._rank1(xx, rr)
            return
        if c.learner == "dlinucb":
            g = c.gamma
            for i in range(self.d):
                for j in range(self.d):
                    self.A[i][j] = g * self.A[i][j] + (0.0 if i != j else (1 - g) * c.ridge)
                self.b[i] *= g
        self._rank1(x, r)

    def _rank1(self, x: List[float], r: float) -> None:
        for i in range(self.d):
            self.b[i] += r * x[i]
            for j in range(self.d):
                self.A[i][j] += x[i] * x[j]

    def scores(self, xs: List[List[float]]) -> List[float]:
        theta = _solve(self.A, self.b)
        out = []
        for x in xs:
            ainv_x = _solve(self.A, x)
            var = max(sum(x[i] * ainv_x[i] for i in range(self.d)), 0.0)
            out.append(sum(theta[i] * x[i] for i in range(self.d)) + self.cfg.alpha * math.sqrt(var))
        return out


class McpPolicy:
    """One instance per arm; call ``choose`` then, after the epoch's samples are absorbed by
    the localizer, ``observe``."""

    def __init__(self, elements: Sequence[str], costs: Dict[str, Dict[str, float]], cfg: McpConfig):
        self.elements = list(elements)
        self.costs = costs                      # element -> {resource: cost}
        self.cfg = cfg
        self.prices = dict(cfg.prices0)
        self.learner = LinUCB(1 if cfg.no_context else D, cfg)
        self.last_probe: Dict[str, int] = {e: -1 for e in self.elements}
        self.last_load: Dict[str, float] = {e: 0.0 for e in self.elements}
        self.flagged: Dict[str, int] = {e: 0 for e in self.elements}
        self.prev_var: Dict[str, float] = {}
        self.epoch = 0
        self.last_chosen: List[str] = []
        self.last_x: Dict[str, List[float]] = {}

    # ---- context -----------------------------------------------------------
    def context(self, e: str, state: infer.InferState, ranked: Dict[str, float]) -> List[float]:
        if self.cfg.no_context:
            return [1.0]
        st = state.elements.get(e) if hasattr(state, "elements") else None
        mean = float(getattr(st, "loss_mean", 0.0)) if st is not None else 0.0
        var = infer.loss_posterior_var(state, e) if st is not None else 0.25
        cus = min(ranked.get(e, 0.0) / self.cfg.kappa, 1.0)
        rec = 1.0 if self.last_probe[e] < 0 else min((self.epoch - self.last_probe[e]) / 32.0, 1.0)
        maxload = max(self.last_load.values()) or 1.0
        return [1.0, min(mean * 1e3, 1.0), min(math.sqrt(max(var, 0.0)) * 1e3, 1.0),
                cus, rec, self.last_load[e] / maxload, float(self.flagged[e] > 0)]

    # ---- allocation --------------------------------------------------------
    def choose(self, state: infer.InferState, loc: Optional[infer.Localization]) -> List[str]:
        self.epoch += 1
        ranked = dict(loc.ranked) if loc else {}
        xs = [self.context(e, state, ranked) for e in self.elements]
        u = self.learner.scores(xs)
        net = []
        for e, x, ue in zip(self.elements, xs, u):
            penalty = 0.0 if self.cfg.no_prices else sum(
                self.prices.get(r, 0.0) * c for r, c in self.costs.get(e, {}).items())
            net.append((ue - penalty, e, x))
        net.sort(key=lambda t: -t[0])
        usage = {r: 0.0 for r in self.cfg.caps}
        chosen: List[str] = []
        for score, e, x in net:
            c = self.costs.get(e, {})
            if all(usage.get(r, 0.0) + c.get(r, 0.0) <= cap for r, cap in self.cfg.caps.items()):
                chosen.append(e)
                for r, v in c.items():
                    usage[r] = usage.get(r, 0.0) + v
                self.last_x[e] = x
        # dual ascent on the prices (re-pricing, §0)
        if not self.cfg.no_prices:
            for r, cap in self.cfg.caps.items():
                self.prices[r] = max(0.0, self.prices.get(r, 0.0) + self.cfg.eta * (usage.get(r, 0.0) - cap))
        self.last_chosen = chosen
        for e in chosen:
            self.last_probe[e] = self.epoch
        return chosen

    # ---- learning ----------------------------------------------------------
    def observe(self, state: infer.InferState, loc: Optional[infer.Localization],
                loads: Dict[str, float]) -> float:
        """Per-element §7.2 reward for the elements just probed; returns the epoch sum."""
        ranked = dict(loc.ranked) if loc else {}
        total = 0.0
        if self.cfg.reset_each_epoch:
            self.learner.reset()
        for e, ld in loads.items():
            self.last_load[e] = ld
        for e in self.last_chosen:
            var_now = max(infer.loss_posterior_var(state, e), 1e-12)
            var_prev = self.prev_var.get(e, var_now)
            r = math.log(var_prev) - math.log(var_now) + self.cfg.beta * min(1.0, ranked.get(e, 0.0) / self.cfg.kappa)
            self.prev_var[e] = var_now
            if ranked.get(e, 0.0) >= self.cfg.kappa:
                self.flagged[e] += 1
            self.learner.update(self.last_x[e], r)
            total += r
        for e in self.elements:
            if e not in self.last_chosen and e in self.prev_var:
                self.prev_var[e] = max(infer.loss_posterior_var(state, e), 1e-12)
        return total
