"""PREREG section 3.3 verification: one frozen localizer shared by every arm."""
import os
import random
import sys
import unittest
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from controller import infer  # noqa: E402
from controller.infer import InferState, Localization, Sample  # noqa: E402

N_LINKS = 16
PROBES_PER_PATH = 1000
EPOCH_US = 1_000_000
# 16 paths of 2 links each, ring-overlapping so that link j is on paths j-1 and j
# (Pingmesh-style intersection then isolates a single faulty link).
PATH_TO_LINKS: Dict[str, List[str]] = {
    "path:%d" % p: ["vlink:%d" % p, "vlink:%d" % ((p + 1) % N_LINKS)] for p in range(N_LINKS)
}


# Two "arms" -- their sample adapters differ (here trivially); the localizer must not.
def arm_mcp_localize(state: InferState, k: int, h: float) -> Localization:
    """MCP arm: calls the common localizer."""
    return infer.localize(state, k, h)


def arm_b3_localize(state: InferState, k: int, h: float) -> Localization:
    """Pingmesh-like baseline arm: calls the common localizer."""
    return infer.localize(state, k, h)


ARMS = {"MCP": infer.localize, "B3": infer.localize}


def synth_epoch(rng: random.Random, epoch: int, faulty: str, loss_rate: float) -> List[Sample]:
    """Path-level probe samples for one epoch; a path loses probes iff it contains ``faulty``."""
    out = []
    for path, links in PATH_TO_LINKS.items():
        rate = loss_rate if faulty in links else 0.0
        lost = sum(1 for _ in range(PROBES_PER_PATH) if rng.random() < rate)
        lat = tuple(rng.gauss(50.0, 2.0) for _ in range(8))
        out.append(Sample(path, PROBES_PER_PATH - lost, lost, lat, epoch * EPOCH_US))
    return out


def run(seed: int, epochs: int, faulty: str = "", loss_rate: float = 0.0,
        warmup: int = 0, h: float = infer.H_DEFAULT) -> Tuple[InferState, List[Localization]]:
    rng = random.Random(seed)
    state = InferState()
    locs = []
    for e in range(warmup + epochs):
        f = faulty if e >= warmup else ""
        state = infer.update(state, synth_epoch(rng, e, f, loss_rate), PATH_TO_LINKS)
        locs.append(infer.localize(state, 1, h))
    return state, locs


class TestCommonInference(unittest.TestCase):
    def test_i_same_function_object(self):
        self.assertIs(ARMS["MCP"], ARMS["B3"])
        self.assertIn("localize", arm_mcp_localize.__code__.co_names)
        self.assertIn("localize", arm_b3_localize.__code__.co_names)

    def test_ii_module_hash_matches_frozen(self):
        cfg = infer.load_frozen_config()
        self.assertEqual(cfg["module_sha256"], infer.module_hash())
        self.assertEqual(len(cfg["module_sha256"]), 64)

    def test_iii_identical_stream_identical_suspects(self):
        rng_a, rng_b = random.Random(7), random.Random(7)
        sa, sb = InferState(), InferState()
        for e in range(30):
            ea = synth_epoch(rng_a, e, "vlink:5", 1e-3)
            eb = synth_epoch(rng_b, e, "vlink:5", 1e-3)
            self.assertEqual(ea, eb)
            sa = infer.update(sa, ea, PATH_TO_LINKS)
            sb = infer.update(sb, eb, PATH_TO_LINKS)
            self.assertEqual(arm_mcp_localize(sa, 3, 4.0).suspects,
                             arm_b3_localize(sb, 3, 4.0).suspects)

    def test_iv_synthetic_fault_localized(self):
        # 20 fault-free epochs establish each element's own baseline, then 50 faulty epochs.
        state, locs = run(seed=1, epochs=50, faulty="vlink:3", loss_rate=1e-3, warmup=20)
        final = infer.localize(state, 1, infer.H_DEFAULT)
        self.assertEqual(final.ranked[0][0], "vlink:3")
        self.assertEqual(final.suspects, ["vlink:3"])
        first_alarm = next((i for i, l in enumerate(locs) if l.anomaly), None)
        self.assertIsNotNone(first_alarm, "anomaly bit never turned on")
        self.assertGreaterEqual(first_alarm, 20, "alarm during fault-free warm-up")
        self.assertEqual(locs[first_alarm].suspects, ["vlink:3"])
        # Exclusion of composite paths from the ranking: paths still carry posteriors/CUSUMs.
        self.assertTrue(all(not e.startswith("path:") for e, _ in final.ranked))
        self.assertGreater(state.get("path:3").cusum, 0.0)

    def test_iv_no_fault_no_false_alarm(self):
        for seed in (11, 12, 13):
            _, locs = run(seed=seed, epochs=200)
            self.assertFalse(any(l.anomaly for l in locs), "false alarm with seed %d" % seed)

    def test_v_determinism(self):
        s1, _ = run(seed=3, epochs=25, faulty="vlink:9", loss_rate=1e-3, warmup=5)
        s2, _ = run(seed=3, epochs=25, faulty="vlink:9", loss_rate=1e-3, warmup=5)
        self.assertEqual(s1, s2)
        self.assertEqual(infer.localize(s1, 3, 4.0), infer.localize(s2, 3, 4.0))

    def test_deaggregation_uniform_prior(self):
        s = infer.update(InferState(), [Sample("path:0", 900, 100, (40.0,), 1)], PATH_TO_LINKS)
        for link in PATH_TO_LINKS["path:0"]:
            st = s.get(link)
            self.assertAlmostEqual(st.loss_alpha, infer.PRIOR_BETA_ALPHA + 50.0)
            self.assertAlmostEqual(st.loss_beta, infer.PRIOR_BETA_BETA + 450.0)
            self.assertAlmostEqual(st.latency_mean, 20.0, places=1)
        self.assertAlmostEqual(s.get("path:0").loss_alpha, infer.PRIOR_BETA_ALPHA + 100.0)


# --- sparse-probe reproduction (co-sim finding: budget 4 of 128 links per epoch) ---------------
SPARSE_LINKS = ["vlink:%d" % i for i in range(128)]
SPARSE_PATHS = {l: [l] for l in SPARSE_LINKS}  # direct link probes, no de-aggregation needed
SPARSE_FAULTY = "vlink:48"  # round-robin budget 4 -> probed at epochs 12, 44 (both >= warm-up)


def sparse_run(seed: int, epochs: int, mode: str, faulty: str = "", loss_rate: float = 0.0,
               fault_from: int = 5, background: float = 0.0) -> List[Localization]:
    """128 links, 4 probed per epoch round-robin, ~5000 packets per probe."""
    rng = random.Random(seed)
    state = InferState()
    locs = []
    for e in range(epochs):
        samples = []
        for j in range(4):
            link = SPARSE_LINKS[(4 * e + j) % 128]
            rate = loss_rate if (link == faulty and e >= fault_from) else background
            lost = sum(1 for _ in range(5000) if rng.random() < rate)
            samples.append(Sample(link, 5000 - lost, lost, (rng.gauss(50.0, 2.0),), e * EPOCH_US))
        state = infer.update(state, samples, SPARSE_PATHS, baseline_mode=mode)
        locs.append(infer.localize(state, 1, infer.H_DEFAULT))
    return locs


class TestPooledBaseline(unittest.TestCase):
    def test_sparse_probe_pooled_detects_per_element_does_not(self):
        pooled = sparse_run(1, 60, "pooled", SPARSE_FAULTY, 1e-3)
        first = next((i for i, l in enumerate(pooled) if l.anomaly), None)
        self.assertIsNotNone(first, "pooled mode never fired by epoch 60")
        self.assertEqual(pooled[first].suspects, [SPARSE_FAULTY])
        self.assertEqual(pooled[-1].ranked[0][0], SPARSE_FAULTY)
        self.assertTrue(pooled[-1].anomaly)
        per_el = sparse_run(1, 60, "per_element", SPARSE_FAULTY, 1e-3)
        self.assertFalse(any(l.anomaly for l in per_el))

    def test_pooled_no_fault_no_false_alarm(self):
        for seed in (21, 22, 23):
            locs = sparse_run(seed, 200, "pooled", background=1e-4)
            self.assertFalse(any(l.anomaly for l in locs), "false alarm with seed %d" % seed)

    def test_default_mode_is_per_element_and_bad_mode_rejected(self):
        self.assertEqual(infer.load_frozen_config()["baseline_mode"], "per_element")
        self.assertEqual(infer.BASELINE_MODE, "per_element")
        with self.assertRaises(ValueError):
            infer.update(InferState(), [], {}, baseline_mode="global")


if __name__ == "__main__":
    unittest.main()
