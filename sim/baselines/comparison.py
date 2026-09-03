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
from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence, Tuple

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
    # CounterPair-0B arm (see `counterpair_tx`), one entry per read-skew level
    # swept in the same trial on the same shared stream: skew_frac -> value.
    cp_epoch: Dict[float, Optional[int]] = field(default_factory=dict)
    cp_packets: Dict[float, Optional[int]] = field(default_factory=dict)
    cp_false_positive: Dict[float, bool] = field(default_factory=dict)


def counterpair_tx(tx_true: int, rx: int, per_link_rate_per_epoch: float,
                   skew_frac: float, prev_offset: float, rng) -> Tuple[int, float]:
    """The zero-byte counter-pair arm's TX observation for one link-epoch.

    A counter pair keeps a per-directed-link transmit register on the SENDING
    switch and a receive register on the RECEIVING switch, with no stamp on
    the wire (RFC 6374 style; the "Theta(1) but skew-limited" row of the
    related-work comparison). The controller reads the two registers on two
    devices at two instants. Let the TX read of epoch e land at t_e + d_e^tx
    and the RX read at t_e + d_e^rx, each offset drawn independently and
    uniformly from [0, skew) where `skew` is the span of the controller's read
    loop, expressed here as a fraction of the epoch (`skew_frac`). The epoch's
    TX delta then counts the packets sent in a window shifted by
    o_e = d_e^tx - d_e^rx relative to the RX window, so the observed TX is the
    true TX plus rate * (o_e - o_{e-1}): a zero-mean disturbance with standard
    deviation about rate * skew / sqrt(6), which the arm cannot distinguish
    from loss. Packets in flight on the link (microseconds) are negligible
    beside the read skew (milliseconds) and are not modelled. If the
    disturbance would make TX fall below RX, the arm clamps to zero loss, as a
    real controller would. `skew_frac = 0` is the idealized bound: the same
    information as the in-band witness, read at one instant.
    Returns (observed_tx, this_epoch_offset)."""
    if skew_frac <= 0.0:
        return tx_true, 0.0
    offset = float(rng.uniform(0.0, skew_frac) - rng.uniform(0.0, skew_frac))
    phantom = int(round(per_link_rate_per_epoch * (offset - prev_offset)))
    tx_obs = max(tx_true + phantom, rx)
    return tx_obs, offset


def run_one_trial(k: int, faulty_rate: float, healthy_rate: float,
                   packets_per_epoch: int, bootstrap_epochs: int,
                   max_post_onset_epochs: int, seed: int,
                   spraycheck_s: float,
                   flowpulse_bootstrap_iters: int = 5,
                   counterpair_skews: Sequence[float] = ()) -> RunResult:
    import numpy as np
    rng = np.random.default_rng(seed)
    faulty_spine = 0

    mcp_loop = make_mcp_loop()
    fp_load_model = LearnedLoadModel(bootstrap_iters=flowpulse_bootstrap_iters)
    fp_detector = FlowPulseDetector()
    # CounterPair-0B: one independent copy of the SAME decision rule per skew
    # level, fed (skewed tx, rx). Its own rng stream keeps the shared
    # spray/survival draw identical across arms and skew levels.
    cp_loops = {s: make_mcp_loop() for s in counterpair_skews}
    cp_rng = np.random.default_rng(seed + 1_000_003)
    cp_prev = {s: [0.0] * k for s in counterpair_skews}
    cp_epoch: Dict[float, Optional[int]] = {s: None for s in counterpair_skews}
    cp_packets: Dict[float, Optional[int]] = {s: None for s in counterpair_skews}
    cp_fp: Dict[float, bool] = {s: False for s in counterpair_skews}
    per_link_rate = packets_per_epoch / k

    # SprayCheck-Z's threshold depends on the total flow size N tested against
    # (lam = N/k); we re-test at every growing cumulative N, using the SAME
    # calibrated sensitivity s throughout (calibration is a per-deployment
    # constant in the paper, not re-derived per candidate N).
    sc_cumulative = [0] * k

    mcp_epoch = mcp_packets = None
    sc_epoch = sc_packets = None
    fp_epoch = fp_packets = None
    mcp_fp = sc_fp = fp_fp = False

    epoch = 0

    # Bootstrap phase: fully healthy traffic, no fault yet.
    for _ in range(bootstrap_epochs):
        snapshot = simulate_epoch(k, None, faulty_rate, healthy_rate,
                                  packets_per_epoch, rng)
        mcp_loop.tick(epoch, snapshot)
        for s in counterpair_skews:
            cp_loops[s].tick(epoch, snapshot)   # warm the floor on clean data
        for spine, (tx, rx) in snapshot.items():
            fp_load_model.observe(str(spine), float(rx))
            sc_cumulative[spine] += rx
        epoch += 1

    # Packets-to-detect is counted from the fault's ONSET, as the module
    # docstring and the paper's metric definition state. An earlier version of
    # this loop started the counter at epoch 0 and so folded the
    # `bootstrap_epochs * packets_per_epoch` of clean warm-up traffic into
    # every reported cost (a constant 20 M at the sweep's settings), which put
    # the costs and the post-onset budget on different origins; found by a
    # referee's arithmetic on the reported medians and fixed here, with the
    # sweep regenerated. The origin is now the onset epoch.
    cumulative_packets = 0

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

        # --- CounterPair-0B: same (tx, rx) information, read on two devices
        # at two instants; TX perturbed by the read-skew model. ---
        for s in counterpair_skews:
            skewed = {}
            for spine, (tx, rx) in snapshot.items():
                tx_obs, off = counterpair_tx(tx, rx, per_link_rate, s,
                                             cp_prev[s][spine], cp_rng)
                cp_prev[s][spine] = off
                skewed[spine] = (tx_obs, rx)
            cp_dec = cp_loops[s].tick(epoch, skewed)
            for spine, decision in cp_dec.items():
                if decision.fleet_rejected:
                    if spine == faulty_spine:
                        if cp_epoch[s] is None:
                            cp_epoch[s], cp_packets[s] = epoch, cumulative_packets
                    else:
                        cp_fp[s] = True

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
                     fp_epoch, fp_packets, mcp_fp, sc_fp, fp_fp,
                     cp_epoch, cp_packets, cp_fp)


def sweep(loss_rates, k: int = 8, healthy_rate: float = 1e-5,
          packets_per_epoch: int = 200, bootstrap_epochs: int = 30,
          max_post_onset_epochs: int = 2000, trials: int = 20,
          spraycheck_calibration_lam: float = 2_500_000,
          counterpair_skews: Sequence[float] = ()):
    spraycheck_s = SprayCheckDetectorCalibration.get(spraycheck_calibration_lam)
    results = {}
    for p in loss_rates:
        trial_results = [
            run_one_trial(k, p, healthy_rate, packets_per_epoch,
                          bootstrap_epochs, max_post_onset_epochs, seed,
                          spraycheck_s, counterpair_skews=counterpair_skews)
            for seed in range(trials)
        ]
        results[p] = trial_results
    return results


def summarize_counterpair(trial_results, skew: float, what: str):
    """`summarize` for the CounterPair-0B arm at one skew level; `what` is
    "epoch" or "packets"."""
    values = [getattr(r, f"cp_{what}").get(skew) for r in trial_results]
    detected = [v for v in values if v is not None]
    n = len(values)
    median = statistics.median(detected) if detected else None
    q1 = q3 = None
    if len(detected) >= 4:
        quantiles = statistics.quantiles(detected, n=4)
        q1, q3 = quantiles[0], quantiles[2]
    fp_rate = sum(1 for r in trial_results if r.cp_false_positive.get(skew)) / n
    return {"action_rate": len(detected) / n,
            "action_rate_ci95": wilson_ci(len(detected), n),
            "median": median, "iqr": (q1, q3), "n": n,
            "false_positive_rate": fp_rate, "skew_frac": skew}


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
    """Median (with an IQR and a Wilson 95% CI on the action rate -- the
    binomial quantity a handful of seeds estimates least reliably), fraction
    detected, and false-positive rate."""
    values = [getattr(r, key) for r in trial_results]
    detected = [v for v in values if v is not None]
    n = len(values)
    action_rate = len(detected) / n
    median = statistics.median(detected) if detected else None
    q1 = q3 = None
    if len(detected) >= 4:
        quantiles = statistics.quantiles(detected, n=4)
        q1, q3 = quantiles[0], quantiles[2]
    fp_key = key.split("_")[0] + "_false_positive"
    fp_rate = sum(1 for r in trial_results if getattr(r, fp_key)) / n
    return {"action_rate": action_rate, "action_rate_ci95": wilson_ci(len(detected), n),
           "median": median, "iqr": (q1, q3), "n": n,
           "false_positive_rate": fp_rate}


def wilson_ci(successes: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score interval for a binomial proportion -- well-behaved at the
    small n and extreme (0 or 1) proportions this sweep actually produces,
    unlike the normal (Wald) approximation."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half_width = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - half_width), min(1.0, center + half_width))
