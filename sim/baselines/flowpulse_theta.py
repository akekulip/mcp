"""FlowPulse-theta — a faithful replay of FlowPulse's temporal-symmetry
detector (Krebs, Gavrilenko, Amir, Landau Feibish, Silberstein, "FlowPulse:
Catching Network Failures in ML Clusters", ACM HotNets '25), verified against
the primary source PDF fetched and read this session
(conferences.sigcomm.org/hotnets/2025/papers/hotnets25-final37.pdf), §4, §5,
§6, Fig. 1, Fig. 5.

WHAT THE PAPER'S SWITCH SEES, AND WHAT THIS ARM IS THEREFORE GIVEN
--------------------------------------------------------------------
"Every leaf switch counts the data volume received at each ingress port from
spines during each collective iteration" (§5.3, "Detection") -- an RX-side,
per-(leaf, spine ingress port) counter, nothing else. It has no TX counter
and no drop counter; the comparison is entirely against its OWN model of what
that port *should* see. This module therefore consumes only a per-(leaf,
spine) RX count per collective iteration, plus, for the load model, RX
counts from the collective's own *earlier* iterations -- never our witness
ledger's TX ground truth.

THE LOAD MODEL (§5.2)
--------------------------------------------------------------------
The paper gives three prediction methods and states the equation only for
the analytical one: "If a given source-destination pair is expected to send
d bytes, f spines have failed links to either the source or destination, and
there are s total spines, then each remaining spine is traversed by
d/(s-f) bytes ... Adding up the contributions from each source-destination
pair whose destination corresponds to a given leaf switch is all that is
needed to predict the load on each of the leaf switch's ingress ports."
`AnalyticalLoadModel` implements exactly this sum.

The paper's third method, "Learning" (§5.2): "It is also possible to learn
the expected load on each port by simply measuring the load during the first
iterations of the collective." `LearnedLoadModel` implements this -- it is
the one used for the fidelity check and for feeding this arm from our own
replayed counter logs, because it needs no external demand-matrix input
(only RX-side observations FlowPulse's own switch would already have),
whereas the analytical model needs the per-source-destination demand matrix
`d`, which our sublink counter logs do not carry in per-flow-pair form.

THE DETECTION TEST (§5.3, quoted verbatim)
--------------------------------------------------------------------
"At the end of each iteration ... the switch compares the observations
against the model prediction. If the discrepancy exceeds a predefined
threshold, the switch declares a fault ... FlowPulse uses a detection
threshold of 1%." This is the one constant in either paper that is stated as
an exact number, not something calibrated per deployment -- `THRESHOLD_1PCT`
below is that number, unmodified.

LOCALIZATION (§5.3, Fig. 4)
--------------------------------------------------------------------
"FlowPulse compares the traffic volumes received from different senders over
the given port. If traffic from all senders is equally affected, the local
link is marked as failed. [If] only one sender is affected, the link between
the spine switch and the leaf switch of the sender is marked as failed."
This requires PER-SENDER decomposition of a single leaf's ingress-port
counter, which our replayed sublink counter logs do not carry (a downlink
counter aggregates over every source leaf using that spine-to-destination
path, matching FlowPulse's OWN leaf-ingress-port counter exactly, but not
broken out per remote sender the way the paper's Fig. 4 example needs).
`localize_by_sender` is implemented from the stated rule and unit-tested on
hand-built per-sender inputs, but -- like SprayCheck's localization -- it is
NOT part of this module's fidelity check, because the paper's published
numbers (Fig. 5, "1% threshold is a perfect classifier for >=1.5%", the
radix and collective-size sweeps) are all DETECTION numbers, not
localization-accuracy numbers.

JUDGMENT CALLS DISCLOSED HERE
--------------------------------------------------------------------
1. Fig. 5's x-axes (collective size, switch radix) are evaluated on the
   paper's own ns-3 fat-tree/Ring-AllReduce setup (32 leaf/16 spine, 5us RTO)
   which this replay does not reproduce packet-for-packet. The fidelity
   check instead reproduces the STATISTICAL MECHANISM the paper's own
   Fig. 5(a) curves are built on -- a fixed 1% threshold applied to a
   per-port count whose noise shrinks like the observed load's inverse
   square root, exactly as for SprayCheck's Z-test SNR (both papers rely on
   the same "more packets => tighter distribution around the mean" argument;
   FlowPulse's is just applied at a fixed threshold instead of a calibrated
   one). The per-port packet/byte scale needed to reproduce the qualitative
   ROC shape in Fig. 5(a) (near-perfect at 1.5% drop, degraded at
   0.08-0.32%) is chosen by this project, not read off the paper, because
   the paper does not state the per-port packet count for its default
   setup; see `tests/test_flowpulse_theta.py` for the derivation and the
   explicit disclosure that this is a scale CHOICE, not a reproduced number.
2. The switch-radix experiment (Fig. 5(b)) is reproduced only qualitatively
   (monotonic degradation of detectability with radix) via a stated,
   disclosed mapping from radix to per-port aggregate load; the paper's
   exact FPR/FNR-vs-radix curve depends on its specific fat-tree topology
   and is not independently reconstructable from the text alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

THRESHOLD_1PCT = 0.01  # the one number the paper states exactly (§5.3)


@dataclass
class AnalyticalLoadModel:
    """§5.2 "Analytical prediction": per-source-destination demand d, spread
    evenly over the (s - f) spines not already known-failed for that pair."""
    total_spines: int
    known_failed_spines: int = 0

    def predicted_port_load(self, demand_per_pair: Dict[str, float],
                             pair_to_dest_leaf: Dict[str, str], leaf: str) -> float:
        """Sum, over every source-destination pair whose destination is
        `leaf`, of d/(s-f) -- the load one remaining spine carries for that
        pair (§5.2, quoted in the module docstring)."""
        s_minus_f = self.total_spines - self.known_failed_spines
        if s_minus_f <= 0:
            raise ValueError("no live spines: total_spines <= known_failed_spines")
        return sum(d / s_minus_f for pair, d in demand_per_pair.items()
                   if pair_to_dest_leaf.get(pair) == leaf)


@dataclass
class LearnedLoadModel:
    """§5.2 "Learning": baseline = the mean RX load on a port over the first
    `bootstrap_iters` collective iterations, before any fault is assumed
    present. This is what §5.2's Fig. 3 mechanism does going forward too
    ("FlowPulse learns an improved baseline after transient fault
    recovery") -- `rebaseline` implements that re-learning step."""
    bootstrap_iters: int = 5
    _samples: Dict[str, List[float]] = field(default_factory=dict)
    _baseline: Dict[str, float] = field(default_factory=dict)

    def observe(self, port: str, load: float) -> None:
        if port not in self._baseline:
            self._samples.setdefault(port, []).append(load)
            if len(self._samples[port]) >= self.bootstrap_iters:
                self._baseline[port] = sum(self._samples[port]) / len(self._samples[port])

    def predicted_port_load(self, port: str) -> Optional[float]:
        """None while still bootstrapping (the paper's switch has no
        prediction to compare against yet either, during the first
        `bootstrap_iters` iterations of a new training task)."""
        return self._baseline.get(port)

    def rebaseline(self, port: str, load: float) -> None:
        """§5.2 Fig. 3: after a fault heals, replace the stale baseline with
        the new, better-balanced measurement so the detector does not keep
        alarming on the recovery."""
        self._baseline[port] = load
        self._samples[port] = [load]


class FlowPulseDetector:
    """§5.3 "Identifying faults": compare one iteration's observed port load
    to the load model's prediction; flag if the relative discrepancy exceeds
    `threshold` (paper default 1%, THRESHOLD_1PCT)."""

    def __init__(self, threshold: float = THRESHOLD_1PCT):
        self.threshold = threshold

    def deviation(self, observed: float, predicted: float) -> float:
        if predicted <= 0:
            raise ValueError("predicted load must be positive")
        return abs(observed - predicted) / predicted

    def flag(self, observed: float, predicted: float) -> bool:
        return self.deviation(observed, predicted) > self.threshold

    @staticmethod
    def localize_by_sender(per_sender_observed: Dict[str, float],
                            per_sender_expected: Dict[str, float],
                            threshold: float = THRESHOLD_1PCT) -> str:
        """§5.3 "Localization" / Fig. 4: if every sender on the port is
        equally affected, the LOCAL link (this leaf's own spine ingress) is
        the failure; if only one sender is affected, THAT sender's remote
        leaf-to-spine link is the failure. Returns "local" or the affected
        sender's id; raises if no sender shows a deviation (nothing to
        localize)."""
        affected = [s for s in per_sender_observed
                    if abs(per_sender_observed[s] - per_sender_expected.get(s, 0.0))
                    / max(per_sender_expected.get(s, 1e-12), 1e-12) > threshold]
        if not affected:
            raise ValueError("no sender shows a deviation to localize")
        if len(affected) == len(per_sender_observed):
            return "local"
        if len(affected) == 1:
            return affected[0]
        # more than one but not all senders affected: the paper's stated
        # rule (§5.3) only covers the "all" and "exactly one" cases;
        # anything else is outside what FlowPulse's own text specifies.
        raise ValueError(
            f"{len(affected)} of {len(per_sender_observed)} senders affected: "
            "outside the two cases FlowPulse's localization rule (§5.3) covers"
        )
