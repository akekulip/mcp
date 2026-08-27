#!/usr/bin/env python3
"""policies.py — measurement policies over the 256 `reg_attn` path slots.

Mirrors sim/htsim/htsim/sim/mcp.{h,cpp} MeasurementScheduler: each epoch a policy picks
`budget` of `n` elements to put at high attention (`-mcp_budget` in the sim = number of
elements at high attention per epoch); everything else sits at low attention.

    uniform   round-robin cursor over the slots               (sim UniformScheduler, B10)
    random    seeded partial Fisher-Yates without replacement (sim RandomScheduler,  B9)
    oracle    faulty paths from a manifest first, then round-robin fill
              (sim OracleScheduler, B12) — GROUND TRUTH, flagged in the log
    mcp_stub  keeps attention as the data plane left it: choose() returns None and the
              loop writes nothing (fast loop alone = ablation A6)
    mcp       the learned slow loop (controller/mcp_policy.py): elements = path slots,
              cost = mirror bytes at high attention; chosen paths -> a_hi, others -> a_lo.
              Needs the localizer state each epoch: call set_state(state, loc) before choose().

`choose()` returns the full attention vector to write (attn per slot, 16-bit) or None.
"""
import json
import logging
import random
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)

N_SLOTS = 256
N_LEAF = 4
N_SPINE = 2
A_HI_DEFAULT = 65535       # measure every packet on the chosen paths
A_LO_DEFAULT = 256         # p_a_min in setup_attention.py: the data plane's floor


class Policy:
    name = "base"

    def __init__(self, budget: int, n: int = N_SLOTS,
                 a_hi: int = A_HI_DEFAULT, a_lo: int = A_LO_DEFAULT) -> None:
        self.n = n
        self.budget = min(budget, n)
        self.a_hi = a_hi
        self.a_lo = a_lo
        self.last_chosen: List[int] = []

    def select(self, epoch: int) -> List[int]:
        raise NotImplementedError

    def choose(self, epoch: int, current: Optional[Sequence[int]] = None) -> Optional[List[int]]:
        """Attention vector for this epoch.  `current` is the data plane's snapshot
        (pipe 0), unused by the budgeted policies."""
        self.last_chosen = self.select(epoch)
        vec = [self.a_lo] * self.n
        for i in self.last_chosen:
            vec[i] = self.a_hi
        return vec


class UniformPolicy(Policy):
    name = "uniform"

    def __init__(self, budget: int, n: int = N_SLOTS, **kw: int) -> None:
        super().__init__(budget, n, **kw)
        self._cursor = 0

    def select(self, epoch: int) -> List[int]:
        out: List[int] = []
        for _ in range(self.budget):
            out.append(self._cursor)
            self._cursor = (self._cursor + 1) % self.n
        return out


class RandomPolicy(Policy):
    name = "random"

    def __init__(self, budget: int, n: int = N_SLOTS, seed: int = 1, **kw: int) -> None:
        super().__init__(budget, n, **kw)
        self._rng = random.Random(seed)

    def select(self, epoch: int) -> List[int]:
        idx = list(range(self.n))
        for i in range(self.budget):                 # partial Fisher-Yates, as the sim
            j = self._rng.randint(i, self.n - 1)
            idx[i], idx[j] = idx[j], idx[i]
        return idx[:self.budget]


class OraclePolicy(Policy):
    """B12 only.  Takes the injected fault from a manifest — GROUND TRUTH."""
    name = "oracle(GROUND-TRUTH)"

    def __init__(self, budget: int, faulty: Sequence[int], n: int = N_SLOTS, **kw: int) -> None:
        super().__init__(budget, n, **kw)
        self.faulty = [p for p in faulty if 0 <= p < n]
        self._cursor = 0
        logger.warning("oracle policy: using ground-truth faulty paths %s (B12 arm only)",
                       self.faulty)

    def select(self, epoch: int) -> List[int]:
        out = list(self.faulty)
        while len(out) < self.budget:
            if self._cursor not in out:
                out.append(self._cursor)
            self._cursor = (self._cursor + 1) % self.n
        return out[:self.budget]


class McpLearnedPolicy(Policy):
    """Full MCP slow loop on hardware.  The loop must call ``set_state(state, loc)`` after
    ``infer.update``/``infer.localize`` and ``observe(loads)`` after the epoch's samples."""
    name = "mcp"

    def __init__(self, budget: int, n: int = N_SLOTS, seed: int = 1, cfg=None, **kw: int) -> None:
        super().__init__(budget, n, **kw)
        from controller.mcp_policy import McpConfig, McpPolicy
        els = ["path:%d" % i for i in range(n)]
        cfg = cfg or McpConfig()
        # one resource: mirror bytes at high attention, unit cost per path; cap = budget paths
        cfg.caps = {"mirror": float(self.budget)}
        self.pol = McpPolicy(els, {e: {"mirror": 1.0} for e in els}, cfg)
        self._state = None
        self._loc = None

    def set_state(self, state, loc) -> None:
        self._state, self._loc = state, loc

    def observe(self, loads) -> float:
        if self._state is None:
            return 0.0
        return self.pol.observe(self._state, self._loc, loads)

    def select(self, epoch: int) -> List[int]:
        from controller import infer
        st = self._state if self._state is not None else infer.InferState()
        chosen = self.pol.choose(st, self._loc)
        return sorted(int(e.split(":")[1]) for e in chosen)[: self.budget]


class McpStubPolicy(Policy):
    """Placeholder for the learned slow loop: never overrides the data plane."""
    name = "mcp_stub"

    def __init__(self, budget: int = 0, n: int = N_SLOTS, **kw: int) -> None:
        super().__init__(budget, n, **kw)

    def select(self, epoch: int) -> List[int]:
        return []

    def choose(self, epoch: int, current: Optional[Sequence[int]] = None) -> Optional[List[int]]:
        self.last_chosen = []
        return None


def vlinks_to_paths(vlinks: Sequence[int]) -> List[int]:
    """Faulty vlink ids -> path ids that cross them (uplink l*2+s: every path with spray
    s, since the source leaf is not in the path id; downlink 8+s*4+l: path l*2+s)."""
    out = set()
    for v in vlinks:
        if v < 8:
            s = v % N_SPINE
            out.update(d * N_SPINE + s for d in range(N_LEAF))
        else:
            s, l = divmod(v - 8, N_LEAF)
            out.add(l * N_SPINE + s)
    return sorted(out)


def load_manifest_faults(path: str) -> List[int]:
    """Manifest JSON: {"faulty_paths": [...]} and/or {"faulty_vlinks": [...]}."""
    with open(path) as f:
        m = json.load(f)
    paths = set(int(p) for p in m.get("faulty_paths", []))
    paths.update(vlinks_to_paths([int(v) for v in m.get("faulty_vlinks", [])]))
    return sorted(paths)


def make_policy(name: str, budget: int, seed: int = 1, manifest: Optional[str] = None,
                a_hi: int = A_HI_DEFAULT, a_lo: int = A_LO_DEFAULT, n: int = N_SLOTS) -> Policy:
    kw = {"a_hi": a_hi, "a_lo": a_lo}
    if name == "uniform":
        return UniformPolicy(budget, n, **kw)
    if name == "random":
        return RandomPolicy(budget, n, seed=seed, **kw)
    if name == "oracle":
        if not manifest:
            raise ValueError("oracle policy needs --manifest with the injected fault")
        return OraclePolicy(budget, load_manifest_faults(manifest), n, **kw)
    if name == "mcp_stub":
        return McpStubPolicy(budget, n, **kw)
    if name == "mcp":
        return McpLearnedPolicy(budget, n, seed=seed, **kw)
    raise ValueError("unknown policy %r" % name)
