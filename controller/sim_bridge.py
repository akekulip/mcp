#!/usr/bin/env python3
"""sim_bridge.py — Python side of the htsim co-simulation (sim/htsim mcp hook, `-mcp_policy
extern:<obs_fifo>:<act_fifo>`).  Every arm feeds the ONE frozen inference layer (PREREG §3.3);
this bridge turns the sim's per-epoch probe observations into `Sample` records, runs
`infer.update` / `infer.localize`, and answers with the next epoch's probe set.

Protocol (line-oriented; the sim opens obs for writing first, then act for reading):
    sim -> py   H <n> <budget> <name0> <name1> ...
    py  -> sim  <i1>,<i2>,...            action for epoch 1 (sent BEFORE any observation)
    sim -> py   O <epoch> <idx>:<dtx>:<ddrop> ...
    py  -> sim  <i1>,<i2>,...            action for epoch+1
    ...until the sim closes obs.

Policies over candidate LINK indices (the sim's action space):
    uniform  round-robin cursor (bit-identical to the C++ UniformScheduler)
    random   partial Fisher–Yates with the same seed as the C++ RandomScheduler is NOT
             reproducible across languages; use the C++ one for parity runs
    oracle   faulty indices first (needs --faulty), then round-robin fill
    cusum    MCP v0: the top-ranked suspects of the common localizer fill
             (1-explore)*budget slots, a round-robin cursor fills the rest
Usage:
    python3 controller/sim_bridge.py --obs /tmp/o.fifo --act /tmp/a.fifo --policy cusum \
        [--explore 0.5] [--epoch-us 100000] [--h 4.0] [--log bridge.csv] [--faulty 0]
Create the FIFOs first (mkfifo); start this before htsim.
"""
import argparse
import logging
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from controller import infer  # noqa: E402
from controller.mcp_policy import McpConfig, McpPolicy  # noqa: E402
from controller.types import Sample  # noqa: E402

log = logging.getLogger("controller.sim_bridge")


class LinkPolicy:
    def __init__(self, n: int, budget: int):
        self.n, self.budget = n, min(budget, n)
        self.cursor = 0

    def _rr(self, count: int, exclude: List[int]) -> List[int]:
        out: List[int] = []
        while len(out) < count:
            if self.cursor not in exclude and self.cursor not in out:
                out.append(self.cursor)
            self.cursor = (self.cursor + 1) % self.n
        return out

    def choose(self, epoch: int, loc: Optional[infer.Localization], names: List[str]) -> List[int]:
        raise NotImplementedError


class Uniform(LinkPolicy):
    def choose(self, epoch, loc, names):
        out = []
        for _ in range(self.budget):          # exactly the C++ UniformScheduler
            out.append(self.cursor)
            self.cursor = (self.cursor + 1) % self.n
        return out


class Oracle(LinkPolicy):
    def __init__(self, n, budget, faulty: List[int]):
        super().__init__(n, budget)
        self.faulty = faulty

    def choose(self, epoch, loc, names):
        out = list(self.faulty)[: self.budget]
        return out + self._rr(self.budget - len(out), out)


class Cusum(LinkPolicy):
    """MCP v0 (exploit + explore). Suspects come from the frozen localizer's ranking."""

    def __init__(self, n, budget, explore: float):
        super().__init__(n, budget)
        self.explore = explore

    def choose(self, epoch, loc, names):
        n_exploit = int(round(self.budget * (1.0 - self.explore)))
        out: List[int] = []
        if loc is not None:
            index = {nm: i for i, nm in enumerate(names)}
            for element, stat in loc.ranked:
                if stat <= 0.0 or len(out) >= n_exploit:
                    break
                i = index.get(element[len("vlink:"):] if element.startswith("vlink:") else element)
                if i is not None and i not in out:
                    out.append(i)
        return out + self._rr(self.budget - len(out), out)


class Mcp(LinkPolicy):
    """Full MCP slow loop (controller/mcp_policy.py) over the sim's link candidates."""

    def __init__(self, n, budget, names: List[str], cfg: McpConfig):
        super().__init__(n, budget)
        self.names = names
        els = [f"vlink:{nm}" for nm in names]
        cfg.caps = {"probes": float(self.budget)}
        self.pol = McpPolicy(els, {e: {"probes": 1.0} for e in els}, cfg)
        self.state: Optional[infer.InferState] = None

    def choose(self, epoch, loc, names):
        st = self.state if self.state is not None else infer.InferState()
        chosen = self.pol.choose(st, loc)
        index = {f"vlink:{nm}": i for i, nm in enumerate(names)}
        out = [index[e] for e in chosen if e in index][: self.budget]
        return out + self._rr(self.budget - len(out), out)


def run(obs_path: str, act_path: str, policy_name: str, explore: float, epoch_us: int,
        h: float, faulty: List[int], log_path: Optional[str], baseline_mode: str = "pooled",
        mcp_cfg: Optional[McpConfig] = None) -> None:
    obs = open(obs_path, "r")            # blocks until the sim opens it for writing
    act = open(act_path, "w")            # blocks until the sim opens it for reading
    header = obs.readline().split()
    assert header and header[0] == "H", f"bad header {header!r}"
    n, budget, names = int(header[1]), int(header[2]), header[3:]
    log.info("sim: %d candidates, budget %d, policy %s", n, budget, policy_name)

    if policy_name == "uniform":
        pol: LinkPolicy = Uniform(n, budget)
    elif policy_name == "oracle":
        pol = Oracle(n, budget, faulty)
    elif policy_name == "cusum":
        pol = Cusum(n, budget, explore)
    elif policy_name == "mcp":
        pol = Mcp(n, budget, names, mcp_cfg or McpConfig())
    else:
        sys.exit(f"unknown policy {policy_name}")

    state = infer.InferState()
    loc: Optional[infer.Localization] = None
    logf = open(log_path, "w") if log_path else None
    if logf:
        logf.write("epoch,anomaly,top,top_stat,chosen\n")

    epoch = 1
    chosen = pol.choose(epoch, loc, names)
    act.write(",".join(map(str, chosen)) + "\n")
    act.flush()
    for line in obs:
        parts = line.split()
        if not parts or parts[0] != "O":
            continue
        epoch = int(parts[1])
        samples = []
        for rec in parts[2:]:
            idx, dtx, ddrop = (int(x) for x in rec.split(":"))
            samples.append(Sample(element=f"vlink:{names[idx]}", delivered=max(dtx - ddrop, 0),
                                  lost=ddrop, latency_us=(), t_us=epoch * epoch_us))
        state = infer.update(state, samples, {}, baseline_mode=baseline_mode)
        loc = infer.localize(state, k=budget, h=h)
        if isinstance(pol, Mcp):
            loads = {f"vlink:{names[int(r.split(':')[0])]}": float(r.split(':')[1]) for r in parts[2:]}
            pol.state = state
            pol.pol.observe(state, loc, loads)
        chosen = pol.choose(epoch + 1, loc, names)
        if logf:
            top = loc.ranked[0] if loc.ranked else ("-", 0.0)
            logf.write(f"{epoch},{int(loc.anomaly)},{top[0]},{top[1]:.3f},{';'.join(map(str, chosen))}\n")
        act.write(",".join(map(str, chosen)) + "\n")
        act.flush()
    log.info("sim closed the observation stream after epoch %d", epoch)
    if logf:
        logf.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--obs", required=True)
    ap.add_argument("--act", required=True)
    ap.add_argument("--policy", default="cusum", choices=["uniform", "oracle", "cusum", "mcp"])
    ap.add_argument("--baseline-mode", default="pooled", choices=["per_element", "pooled"])
    ap.add_argument("--learner", default="linucb", choices=["linucb", "dlinucb", "swlinucb"])
    ap.add_argument("--alpha", type=float, default=1.0)
    ap.add_argument("--explore-floor", type=float, default=0.25)
    ap.add_argument("--ablation", default="", help="comma list of: no_prices,no_context,no_explore,reset")
    ap.add_argument("--explore", type=float, default=0.5)
    ap.add_argument("--epoch-us", type=int, default=100000)
    ap.add_argument("--h", type=float, default=infer.H_DEFAULT)
    ap.add_argument("--faulty", type=int, nargs="*", default=[])
    ap.add_argument("--log", default=None)
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO if a.v else logging.WARNING, format="%(levelname)s %(message)s")
    ab = set(x for x in a.ablation.split(",") if x)
    cfg = McpConfig(learner=a.learner, alpha=0.0 if "no_explore" in ab else a.alpha,
                    no_prices="no_prices" in ab, no_context="no_context" in ab,
                    reset_each_epoch="reset" in ab, kappa=a.h, explore_floor=a.explore_floor)
    run(a.obs, a.act, a.policy, a.explore, a.epoch_us, a.h, a.faulty, a.log, a.baseline_mode, cfg)


if __name__ == "__main__":
    main()
