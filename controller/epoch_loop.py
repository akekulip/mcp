#!/usr/bin/env python3
"""epoch_loop.py — the MCP slow loop for the hardware arm.

Every --epoch-ms: observe (adapter) -> infer.update -> infer.localize -> policy ->
write reg_attn (all 256 slots, all pipes: pipe_id 0xffff) -> one CSV row.

    python3 controller/epoch_loop.py --dry-run --epochs 20 --epoch-ms 10 --out x.csv
    python3 controller/epoch_loop.py --iface enp3s0f1 --policy uniform --budget 16
    python3 controller/epoch_loop.py --pcap copies.pcap --freeze-controller

--freeze-controller: observe and log, never write (PREREG H7 frozen-controller mode).
--dry-run: synthetic adapter, no switch, no bfrt import.
--pcap: replay copies from a file instead of the live collector socket.

STATUS: --dry-run and the CSV path are tested (controller/tests/test_epoch_loop.py).
The bfrt path (BfrtAdapter in hw_adapter.py, client_id 4) is code-complete but has NOT
been run against the switch — another engineer held the testbed while this was written.
"""
import argparse
import csv
import logging
import os
import random
import sys
import time
from types import ModuleType
from typing import Any, Dict, List, Optional

if __package__ in (None, ""):                       # run as a script from anywhere
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller import hw_adapter as hw              # noqa: E402
from controller import policies                      # noqa: E402

logger = logging.getLogger("controller.epoch_loop")

CSV_COLUMNS = [
    "epoch", "t_host_us", "t_switch_ns", "anomaly", "suspects", "ranked",
    "n_samples", "n_copies", "n_measured", "n_lost", "coverage_paths",
    "t_read_us", "t_sync_us", "t_infer_us", "t_write_us", "tau_slow_us",
    "probes_per_s", "mirror_bytes_per_s", "reg_writes", "counter_reads",
    "policy", "budget", "chosen", "frozen", "attn_p0_mean", "attn_hi_slots",
    "vlink_deltas",
]


# ----------------------------------------------------------------------------- inference
def load_infer(mode: str) -> ModuleType:
    """`controller.infer` is written by another builder; import it lazily.  In --dry-run
    (mode 'auto') fall back to the in-file stub with a warning; otherwise require it."""
    if mode != "stub":
        try:
            from controller import infer               # type: ignore
            return infer
        except ImportError as e:
            if mode == "real":
                raise
            logger.warning("controller.infer not importable (%s): using StubInfer", e)
    return StubInfer  # type: ignore[return-value]


class _StubLoc:
    def __init__(self, anomaly: bool, ranked: List[Any]) -> None:
        self.anomaly = anomaly
        self.ranked = ranked
        self.suspects = [e for e, _ in ranked]


class StubInfer:
    """Minimal placeholder honouring the infer contract: per-element loss fraction.
    NOT the inference layer under test — only so the loop runs before infer.py lands."""

    H_DEFAULT = 0.1

    class InferState(dict):
        pass

    @staticmethod
    def update(state: Any, samples: List[Any], path_to_links: Dict[str, List[str]]) -> Any:
        state = StubInfer.InferState(state)
        for s in samples:
            d, l = state.get(s.element, (0, 0))
            state[s.element] = (d + s.delivered, l + s.lost)
        return state

    @staticmethod
    def localize(state: Any, k: int, h: float) -> _StubLoc:
        stats = sorted(((l / (d + l)) if d + l else 0.0, e) for e, (d, l) in state.items())
        ranked = [(e, st) for st, e in reversed(stats)][:k]
        return _StubLoc(bool(ranked) and ranked[0][1] > h, ranked)


# ----------------------------------------------------------------------------- synthetic
class SyntheticAdapter:
    """No-switch adapter for --dry-run: fabricates copies through hw.build_copy() so the
    full parse -> aggregate path runs.  Path `faulty_path` drops `loss` of its packets."""

    def __init__(self, seed: int = 1, faulty_path: int = 5, loss: float = 0.3,
                 copies_per_epoch: int = 200, a0: int = 4096) -> None:
        self._rng = random.Random(seed)
        self.faulty_path, self.loss, self.n = faulty_path, loss, copies_per_epoch
        self.attn = [a0] * hw.N_PATHS
        self.reg_writes = 0
        self.written: List[List[int]] = []

    def observe(self, epoch: int) -> hw.Observation:
        t_us = int(time.time() * 1e6)
        obs = hw.Observation(epoch=epoch, t_host_us=t_us)
        t0 = time.perf_counter()
        frames: List[bytes] = []
        deltas = {v: (0, 0) for v in range(hw.N_VLINKS)}
        for _ in range(self.n):
            src, dst = self._rng.randrange(hw.N_LEAF), self._rng.randrange(hw.N_LEAF)
            spray = self._rng.randrange(hw.N_SPINE)
            pid, up, dn = hw.path_id(dst, spray), hw.vlink_up(src, spray), hw.vlink_dn(spray, dst)
            ts = epoch * 100_000_000 + self._rng.randrange(100_000_000)
            deltas[up] = (deltas[up][0] + 1, deltas[up][1] + 1500)
            if pid == self.faulty_path and self._rng.random() < self.loss:
                frames.append(hw.build_copy(up, pid, hw.FLAG_DROPPED, ts, self.attn[pid], 1))
                continue
            deltas[dn] = (deltas[dn][0] + 1, deltas[dn][1] + 1500)
            if self._rng.randrange(65536) < self.attn[pid]:
                frames.append(hw.build_copy(up, pid, hw.FLAG_MEASURED, ts, self.attn[pid], 1))
                frames.append(hw.build_copy(
                    dn, pid, hw.FLAG_MEASURED, ts + 2000, self.attn[pid], 2, hw.FABRIC_ETYPE,
                    {"worst_vlink": up, "worst_tdelta": self._rng.randrange(50_000)}))
        copies = hw.parse_copies(frames)
        obs.t_read_us = int((time.perf_counter() - t0) * 1e6)
        obs.attn = [[a, a] for a in self.attn]
        obs.clean = [[0, 0] for _ in self.attn]
        hw._fill(obs, copies, deltas, t_us)
        return obs

    def write_attn(self, vec: List[int]) -> None:
        self.attn = list(vec[:hw.N_PATHS])
        self.written.append(list(self.attn))
        self.reg_writes += len(self.attn)

    def close(self) -> None:
        return None


# ----------------------------------------------------------------------------- the loop
class EpochLoop:
    def __init__(self, adapter: Any, infer: ModuleType, policy: policies.Policy,
                 epoch_ms: int, out_path: str, k: int = 3, h: Optional[float] = None,
                 freeze: bool = False) -> None:
        self.adapter, self.infer, self.policy = adapter, infer, policy
        self.epoch_us = epoch_ms * 1000
        self.k, self.freeze = k, freeze
        self.h = float(getattr(infer, "H_DEFAULT", 0.1)) if h is None else h
        self.state: Any = infer.InferState()
        self.rows_written = 0
        self._fh = open(out_path, "w", newline="")
        self._csv = csv.DictWriter(self._fh, fieldnames=CSV_COLUMNS)
        self._csv.writeheader()

    def step(self, epoch: int) -> Dict[str, Any]:
        t_start = time.perf_counter()
        obs = self.adapter.observe(epoch)
        t0 = time.perf_counter()
        self.state = self.infer.update(self.state, obs.samples, obs.path_to_links)
        loc = self.infer.localize(self.state, self.k, self.h)
        t_infer = int((time.perf_counter() - t0) * 1e6)

        current = [a[0] if a else 0 for a in obs.attn]
        vec = self.policy.choose(epoch, current)
        t0 = time.perf_counter()
        writes = 0
        if vec is not None and not self.freeze:
            self.adapter.write_attn(vec)
            writes = len(vec)
        t_write = int((time.perf_counter() - t0) * 1e6)
        tau = int((time.perf_counter() - t_start) * 1e6)
        secs = self.epoch_us / 1e6
        row: Dict[str, Any] = {
            "epoch": epoch, "t_host_us": obs.t_host_us, "t_switch_ns": obs.t_switch_ns,
            "anomaly": int(bool(loc.anomaly)),
            "suspects": ";".join(str(e) for e in loc.suspects[:self.k]),
            "ranked": ";".join("%s=%.4g" % (e, st) for e, st in loc.ranked[:self.k]),
            "n_samples": len(obs.samples), "n_copies": obs.n_copies,
            "n_measured": obs.n_measured, "n_lost": obs.n_lost,
            "coverage_paths": len(obs.path_to_links),
            "t_read_us": obs.t_read_us, "t_sync_us": obs.t_sync_us,
            "t_infer_us": t_infer, "t_write_us": t_write, "tau_slow_us": tau,
            "probes_per_s": 0,                           # hardware arm injects no probes
            "mirror_bytes_per_s": int(obs.mirror_bytes / secs) if secs else 0,
            "reg_writes": writes, "counter_reads": obs.counter_reads,
            "policy": self.policy.name, "budget": self.policy.budget,
            "chosen": ";".join(str(i) for i in self.policy.last_chosen),
            "frozen": int(self.freeze),
            "attn_p0_mean": (sum(current) / len(current)) if current else 0,
            "attn_hi_slots": sum(1 for a in current if a >= self.policy.a_hi),
            # per-vlink packet deltas this epoch, straight from the counter samples:
            # the direct check that the counter read is tracking real traffic
            "vlink_deltas": ";".join(
                "%s=%d" % (str(s.element).split(":")[1], s.delivered)
                for s in obs.samples
                if str(s.element).startswith("vlink:") and s.delivered),
        }
        self._csv.writerow(row)
        self._fh.flush()
        self.rows_written += 1
        if obs.fail_truth:
            logger.debug("GROUND TRUTH tbl_fail (log only): %s", obs.fail_truth)
        return row

    def run(self, epochs: Optional[int]) -> int:
        epoch = 0
        next_t = time.perf_counter()
        try:
            while epochs is None or epoch < epochs:
                epoch += 1
                row = self.step(epoch)
                if row["tau_slow_us"] > self.epoch_us:
                    logger.warning("epoch %d: tau_slow %d us > epoch %d us",
                                   epoch, row["tau_slow_us"], self.epoch_us)
                next_t += self.epoch_us / 1e6
                delay = next_t - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
        except KeyboardInterrupt:
            logger.info("interrupted after %d epochs", epoch)
        finally:
            self.close()
        return epoch

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()
        self.adapter.close()


# ----------------------------------------------------------------------------- cli
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--epoch-ms", type=int, default=100)
    ap.add_argument("--epochs", type=int, default=None, help="stop after N epochs (default: run forever)")
    ap.add_argument("--out", default="epoch_log.csv")
    ap.add_argument("--policy", choices=("uniform", "random", "oracle", "mcp_stub"), default="mcp_stub")
    ap.add_argument("--budget", type=int, default=16, help="elements at high attention per epoch (sim -mcp_budget)")
    ap.add_argument("--a-hi", type=int, default=policies.A_HI_DEFAULT)
    ap.add_argument("--a-lo", type=int, default=policies.A_LO_DEFAULT)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--manifest", help="run manifest JSON with the injected fault (oracle only)")
    ap.add_argument("--k", type=int, default=3, help="top-k suspects logged")
    ap.add_argument("--h", type=float, default=None, help="localize() threshold (default: infer.H_DEFAULT)")
    ap.add_argument("--freeze-controller", action="store_true", help="observe and log, never write (H7)")
    ap.add_argument("--dry-run", action="store_true", help="synthetic adapter, no switch")
    ap.add_argument("--pcap", help="replay copies from this pcap instead of a live socket")
    ap.add_argument("--iface", default="enp3s0f1", help="collector interface for live copies")
    ap.add_argument("--infer", choices=("auto", "real", "stub"), default="auto")
    ap.add_argument("--faulty-path", type=int, default=5, help="dry-run: synthetic faulty path")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.dry_run:
        adapter: Any = SyntheticAdapter(seed=args.seed, faulty_path=args.faulty_path)
        infer = load_infer(args.infer)
    else:
        source = hw.PcapSource(args.pcap, args.epoch_ms * 1000) if args.pcap else hw.LiveSource(args.iface)
        adapter = hw.BfrtAdapter(source)
        infer = load_infer("real" if args.infer == "auto" else args.infer)
    policy = policies.make_policy(args.policy, args.budget, args.seed, args.manifest, args.a_hi, args.a_lo)
    loop = EpochLoop(adapter, infer, policy, args.epoch_ms, args.out, args.k, args.h,
                     args.freeze_controller)
    n = loop.run(args.epochs)
    logger.info("done: %d epochs -> %s", n, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
