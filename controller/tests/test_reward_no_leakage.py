"""Reward must be a pure function of Observation; it must not touch fault ground truth.

Adapted from PREREG section 7.3 to unittest.  ``sim.faults`` / ``sim.oracle`` do not exist yet in
this repository, so the ground-truth types are stand-ins defined here and the oracle tripwire is
installed as a synthetic ``sim.oracle`` module in ``sys.modules``.
"""
import ast
import dataclasses
import inspect
import os
import random
import sys
import types
import unittest
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import controller.reward as reward_mod  # noqa: E402
from controller import infer  # noqa: E402
from controller.infer import InferState, Sample  # noqa: E402
from controller.reward import RewardConstants, compute_reward, make_observation  # noqa: E402
from controller.types import Observation  # noqa: E402


# --- ground-truth stand-ins (would be sim.faults.FaultSet / FaultLabel) -----------------------
@dataclasses.dataclass(frozen=True)
class FaultLabel:
    element: str
    kind: str
    magnitude: float


@dataclasses.dataclass(frozen=True)
class FaultSet:
    faults: Tuple[FaultLabel, ...]


PATHS = {"path:%d" % p: ["vlink:%d" % p, "vlink:%d" % ((p + 1) % 8)] for p in range(8)}
CONSTS = RewardConstants(beta=1.0, kappa=4.0)
RESOURCES = ("probe_bytes", "tag_bytes", "nic_reads", "cpu")


def make_prices() -> Dict[str, float]:
    return {r: 0.5 for r in RESOURCES}


def make_observations(seed: int, faulty: str = "", loss: float = 0.0, epochs: int = 30
                      ) -> List[Observation]:
    """Observation records from a synthetic run; ``faulty``/``loss`` shape the SAMPLES only."""
    rng = random.Random(seed)
    state = InferState()
    out = []
    for e in range(epochs):
        samples = []
        for path, links in PATHS.items():
            rate = loss if faulty in links else 0.0
            lost = sum(1 for _ in range(1000) if rng.random() < rate)
            samples.append(Sample(path, 1000 - lost, lost, (rng.gauss(50, 2),), e))
        new = infer.update(state, samples, PATHS)
        usage = {r: 0.015 + 0.01 * rng.random() for r in RESOURCES}
        out.append(make_observation(state, new, PATHS, usage, {r: 0.02 for r in RESOURCES}))
        state = new
    return out


def run_epoch(ground_truth: FaultSet, obs: Observation, prices: Dict[str, float]) -> float:
    """Harness mirroring the evaluation loop: ground truth exists here but is never passed on."""
    del ground_truth  # available to the harness, invisible to the reward
    return compute_reward(obs, prices, CONSTS)


class TestRewardNoLeakage(unittest.TestCase):
    def test_reward_module_has_no_fault_imports(self):
        tree = ast.parse(inspect.getsource(reward_mod))
        banned = ("sim.faults", "sim.oracle", "sim.groundtruth", "sim")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
                self.assertFalse(any(n == b or n.startswith(b + ".") for n in names for b in banned),
                                 ast.dump(node))

    def test_observation_carries_no_fault_field(self):
        fields = {f.name for f in dataclasses.fields(Observation)}
        self.assertFalse(fields & {"fault", "faults", "fault_set", "label", "ground_truth",
                                   "oracle", "injected", "true_loss"})

    def test_signature_has_no_ground_truth_argument(self):
        params = inspect.signature(compute_reward).parameters
        self.assertEqual(list(params), ["obs", "prices", "constants"])
        for name in params:
            self.assertNotIn("truth", name)
            self.assertNotIn("fault", name)
            self.assertNotIn("oracle", name)
        self.assertEqual(list(inspect.signature(make_observation).parameters),
                         ["prev", "cur", "paths", "usage", "caps"])

    def test_reward_invariant_to_ground_truth(self):
        """Same observations, different injected faults -> bit-identical reward."""
        obs_run = make_observations(seed=1, faulty="vlink:3", loss=1e-3)
        prices = make_prices()
        gt_a = FaultSet((FaultLabel("spine3-up2", "loss", 1e-4),))
        gt_b = FaultSet(())
        gt_c = FaultSet((FaultLabel("vlink:3", "loss", 1e-3), FaultLabel("nic:0", "latency", 300.0)))
        for obs in obs_run:
            r_a = run_epoch(gt_a, obs, prices)
            r_b = run_epoch(gt_b, obs, prices)
            r_c = run_epoch(gt_c, obs, prices)
            self.assertEqual(r_a.hex(), r_b.hex())
            self.assertEqual(r_a.hex(), r_c.hex())

    def test_reward_changes_with_observations(self):
        """Ground truth fixed, observations differ -> reward differs."""
        gt = FaultSet((FaultLabel("vlink:3", "loss", 1e-3),))
        prices = make_prices()
        run_a = make_observations(seed=1, faulty="vlink:3", loss=1e-3)
        run_b = make_observations(seed=2, faulty="vlink:3", loss=1e-3)   # different samples
        run_c = make_observations(seed=1, faulty="", loss=0.0)            # samples see no fault
        r_a = [run_epoch(gt, o, prices) for o in run_a]
        r_b = [run_epoch(gt, o, prices) for o in run_b]
        r_c = [run_epoch(gt, o, prices) for o in run_c]
        self.assertNotEqual(r_a, r_b)
        self.assertNotEqual(r_a, r_c)

    def test_reward_formula_terms(self):
        obs = Observation(epoch=1, sigma2_prev={"path:0": 4e-6}, sigma2={"path:0": 1e-6},
                          cusum={"path:0": 8.0}, usage={"probe_bytes": 0.03},
                          caps={"probe_bytes": 0.02})
        r = compute_reward(obs, {"probe_bytes": 10.0}, CONSTS)
        import math
        self.assertAlmostEqual(r, math.log(4.0) + 1.0 - 10.0 * 0.01)

    def test_reward_raises_on_oracle_access(self):
        """Any read of a (synthetic) fault oracle during reward computation is a failure."""
        def _trip(*a, **k):
            raise AssertionError("reward touched the fault oracle")
        oracle = types.ModuleType("sim.oracle")
        oracle.injected_faults = _trip
        oracle.true_loss = _trip
        saved = {k: sys.modules.get(k) for k in ("sim", "sim.oracle")}
        sys.modules["sim"] = types.ModuleType("sim")
        sys.modules["sim.oracle"] = oracle
        try:
            for obs in make_observations(seed=2, faulty="vlink:1", loss=1e-3, epochs=5):
                compute_reward(obs, make_prices(), CONSTS)
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v


if __name__ == "__main__":
    unittest.main()
