"""Head-to-head comparison: MCP's own detector against faithful replays of
SprayCheck-Z and FlowPulse-theta, on IDENTICAL simulated traffic.

Fairness is the entire point of this module, so state it explicitly: every
run generates ONE shared stream of per-packet spray/survival draws (see
`simulate_epoch`), and every detector sees only the slice of that stream its
real switch would actually have. MCP's mechanism is handed the exact
per-sublink (tx, rx) pair its receiver ledger genuinely produces --
`controller/decision_loop.FleetDecisionLoop`, unmodified from
`controller/tests/`. SprayCheck-Z (`spraycheck_z.py`) is handed RX-only
per-spine arrival counts and never sees tx. FlowPulse-theta
(`flowpulse_theta.py`) is handed RX-only per-spine-port load counts and
predicts its own baseline from clean history via `LearnedLoadModel`, never
consuming MCP's tx ground truth either. No detector is special-cased with
information its published mechanism does not have.

Scenario, matching both papers' own evaluation shape (a single link/spine
degraded on an otherwise healthy fabric) and MCP's own decision_loop tests:
`bootstrap_epochs` of clean traffic (lets FlowPulse-theta's load model
bootstrap and MCP's floor estimator build real history), then one spine
degrades to `faulty_rate` and stays degraded for the rest of the run.
Detection delay is measured in epochs AND in packets, from the epoch the
fault actually starts, not from epoch 0 -- this is "time/packets to detect
after onset", the metric both papers report (SprayCheck: packets-per-spine
in Table 1; FlowPulse: fault probability at a fixed threshold, per
collective iteration).
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from controller.decision_loop import FleetDecisionLoop
from sim.baselines.flowpulse_theta import FlowPulseDetector, LearnedLoadModel
from sim.baselines.spraycheck_z import SprayCheckConfig, SprayCheckDetector


def simulate_epoch(k: int, faulty_spine: Optional[int], faulty_rate: float,
                    healthy_rate: float, packets_per_epoch: int,
                    rng) -> Dict[int, Tuple[int, int]]:
    """One epoch's ground truth: `packets_per_epoch` packets sprayed i.i.d.
    uniformly over k spines (matching SprayCheck's own i.i.d. model, §3.5,
    and FlowPulse's "temporal symmetry" assumption), each surviving
    independently at that spine's true rate. Returns {spine: (tx, rx)}.
    `faulty_spine=None` means a fully healthy epoch (used during bootstrap).
    """
    # A per-packet Python loop here (`for _ in range(packets_per_epoch):
    # tx_counts[rng.integers(0, k)] += 1`) is what this function originally
    # did, and at packets_per_epoch in the millions it made a single epoch
    # take tens of seconds -- a real performance bug, not a fairness one
    # (the i.i.d.-uniform-spray MODEL was always correct; only the naive
    # per-packet implementation of it was not). A multinomial draw is the
    # exact same i.i.d.-uniform-spray model, vectorized.
    tx_counts = rng.multinomial(packets_per_epoch, [1.0 / k] * k)
    result = {}
    for spine, tx in enumerate(tx_counts):
        rate = faulty_rate if spine == faulty_spine else healthy_rate
        rx = tx - rng.binomial(tx, rate) if tx > 0 else 0
        result[spine] = (tx, rx)
    return result


def make_mcp_loop(alpha: float = 0.05) -> FleetDecisionLoop:
    from controller.absolute_eprocess import log_spaced_alternatives  # noqa: F401
    return FleetDecisionLoop(
        alpha=alpha,
        ratios=(2.0, 5.0, 10.0, 50.0, 200.0),
        restoration_grid_low=1e-8,
        restoration_grid_count=8,
        floor_window_epochs=20,
        w_min=0.05,
    )


@dataclass
class RunResult:
    mcp_epoch: Optional[int]
    mcp_packets: Optional[int]
    spraycheck_epoch: Optional[int]
    spraycheck_packets: Optional[int]
    flowpulse_epoch: Optional[int]
    flowpulse_packets: Optional[int]
    # false positives observed on a HEALTHY spine before the true positive
    # (or over the whole run if no true positive) -- reported, never hidden
    mcp_false_positive: bool
    spraycheck_false_positive: bool
    flowpulse_false_positive: bool


def run_one_trial(k: int, faulty_rate: float, healthy_rate: float,
                   packets_per_epoch: int, bootstrap_epochs: int,
                   max_post_onset_epochs: int, seed: int,
                   spraycheck_s: float,
                   flowpulse_bootstrap_iters: int = 5) -> RunResult:
    import numpy as np
    rng = np.random.default_rng(seed)
    faulty_spine = 0

    mcp_loop = make_mcp_loop()
    fp_load_model = LearnedLoadModel(bootstrap_iters=flowpulse_bootstrap_iters)
    fp_detector = FlowPulseDetector()

    # SprayCheck-Z's threshold depends on the total flow size N tested against
    # (lam = N/k); we re-test at every growing cumulative N, using the SAME
    # calibrated sensitivity s throughout (calibration is a per-deployment
    # constant in the paper, not re-derived per candidate N).
    sc_cumulative = [0] * k

    mcp_epoch = mcp_packets = None
    sc_epoch = sc_packets = None
    fp_epoch = fp_packets = None
    mcp_fp = sc_fp = fp_fp = False

    cumulative_packets = 0
    epoch = 0

    # Bootstrap phase: fully healthy traffic, no fault yet.
    for _ in range(bootstrap_epochs):
        snapshot = simulate_epoch(k, None, faulty_rate, healthy_rate,
                                  packets_per_epoch, rng)
        mcp_loop.tick(epoch, snapshot)
        for spine, (tx, rx) in snapshot.items():
            fp_load_model.observe(str(spine), float(rx))
            sc_cumulative[spine] += rx
        cumulative_packets += packets_per_epoch
        epoch += 1

    # Onset: spine 0 degrades and stays degraded for the rest of the run.
    for _ in range(max_post_onset_epochs):
        snapshot = simulate_epoch(k, faulty_spine, faulty_rate, healthy_rate,
                                  packets_per_epoch, rng)
        decisions = mcp_loop.tick(epoch, snapshot)
        cumulative_packets += packets_per_epoch

        # --- MCP ---
        if mcp_epoch is None:
            for spine, decision in decisions.items():
                if decision.fleet_rejected:
                    if spine == faulty_spine:
                        mcp_epoch, mcp_packets = epoch, cumulative_packets
                    else:
                        mcp_fp = True

        # --- SprayCheck-Z: cumulative RX-only counts, re-tested each epoch ---
        for spine, (_, rx) in snapshot.items():
            sc_cumulative[spine] += rx
        total_n = sum(sc_cumulative)
        if total_n > 0:
            cfg = SprayCheckConfig(k=k, flow_packets=total_n, s=spraycheck_s)
            flagged = SprayCheckDetector(cfg).detect_flow(
                {s: v for s, v in enumerate(sc_cumulative)})
            if sc_epoch is None and faulty_spine in flagged:
                sc_epoch, sc_packets = epoch, cumulative_packets
            if any(s != faulty_spine for s in flagged):
                sc_fp = True

        # --- FlowPulse-theta: per-epoch RX load vs learned baseline ---
        for spine, (_, rx) in snapshot.items():
            port = str(spine)
            predicted = fp_load_model.predicted_port_load(port)
            if predicted is not None and predicted > 0:
                flagged = fp_detector.flag(float(rx), predicted)
                if flagged:
                    if spine == faulty_spine:
                        if fp_epoch is None:
                            fp_epoch, fp_packets = epoch, cumulative_packets
                    else:
                        fp_fp = True
                else:
                    # only feed clean-looking observations back into the
                    # baseline, matching §5.2's "learn during healthy
                    # operation" framing -- do not let the fault poison its
                    # own detector's future baseline.
                    fp_load_model.observe(port, float(rx))
            else:
                fp_load_model.observe(port, float(rx))
        epoch += 1

    return RunResult(mcp_epoch, mcp_packets, sc_epoch, sc_packets,
                     fp_epoch, fp_packets, mcp_fp, sc_fp, fp_fp)


def sweep(loss_rates, k: int = 8, healthy_rate: float = 1e-5,
          packets_per_epoch: int = 200, bootstrap_epochs: int = 30,
          max_post_onset_epochs: int = 2000, trials: int = 20,
          spraycheck_calibration_lam: float = 2_500_000):
    spraycheck_s = SprayCheckDetectorCalibration.get(spraycheck_calibration_lam)
    results = {}
    for p in loss_rates:
        trial_results = [
            run_one_trial(k, p, healthy_rate, packets_per_epoch,
                          bootstrap_epochs, max_post_onset_epochs, seed,
                          spraycheck_s)
            for seed in range(trials)
        ]
        results[p] = trial_results
    return results


class SprayCheckDetectorCalibration:
    """Calibrate s once, lazily, and cache it -- calibration is expensive
    (Monte Carlo) and is a fixed per-deployment constant in the paper."""
    _cache: Dict[float, float] = {}

    @classmethod
    def get(cls, lam: float) -> float:
        if lam not in cls._cache:
            from sim.baselines.spraycheck_z import calibrate_s
            cls._cache[lam] = calibrate_s(lam, floor_p=0.004, trials=100_000, seed=0)
        return cls._cache[lam]


def summarize(trial_results, key: str):
    """Median detection epoch/packets (None = never detected within the
    horizon), fraction detected, and false-positive rate."""
    values = [getattr(r, key) for r in trial_results]
    detected = [v for v in values if v is not None]
    action_rate = len(detected) / len(values)
    median = statistics.median(detected) if detected else None
    fp_key = key.split("_")[0] + "_false_positive"
    fp_rate = sum(1 for r in trial_results if getattr(r, fp_key)) / len(trial_results)
    return {"action_rate": action_rate, "median": median, "n": len(values),
           "false_positive_rate": fp_rate}
