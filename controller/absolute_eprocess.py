"""Primary anytime-valid detector: absolute e-process against a fleet-estimated
floor (`docs/review/BRAINSTORM-2026-09-01.md` C2, "Primary, absolute").

A log-spaced grid of loss-rate alternatives approximates the "log-uniform
mixture over unknown loss rate (a GRO-style Bayes factor, not six hand-picked
points)" the design calls for -- a fine enough grid makes the discrete mixture
and the continuous integral it approximates agree to the precision this
project needs. A fixed convex mixture of e-processes is itself an e-process
for any finite grid, exactly as already derived and tested in
`evidence_ledger.py`. This module differs from that one in two required ways:

1. The null is *dynamic*: each epoch's likelihood-ratio term is computed
   against that epoch's own fleet-estimated floor (`floor_estimator.py`),
   supplied by the caller. Validity requires the floor to be previsible --
   estimated without using this sublink's own current-epoch outcome, which
   leave-one-out estimation guarantees. The martingale property
   (E[LR] = 1 under the true, previsible null) holds for a fixed alternative
   against any previsible null value, so a moving null does not break
   validity -- it only changes the test's power epoch to epoch, which is the
   point (the null tracks the fleet rather than a guessed constant).
2. Censored epochs contribute a factor of exactly one: no reset of
   accumulated wealth, no alpha-halving restart ("Censored epochs contribute
   a factor of one; no restarts, no alpha halving", brainstorm C2). This
   differs from `SequentialEvidenceLedger`, which resets and alpha-spends on
   every censor for its own, still-valid, fixed-null design used elsewhere.
   A genuine repair (a new `repair_generation`) is a fresh sequence here as
   there, since a repaired link has a different loss rate by construction
   and no wealth carries meaning across it.
"""

import math
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple


def log_spaced_alternatives(low: float, high: float, count: int) -> Tuple[float, ...]:
    """A grid approximating a log-uniform mixture over loss rates in (low, high)."""
    if not 0.0 < low < high < 1.0:
        raise ValueError("require 0 < low < high < 1")
    if count < 1:
        raise ValueError("count must be positive")
    log_low, log_high = math.log(low), math.log(high)
    if count == 1:
        return (math.exp((log_low + log_high) / 2.0),)
    step = (log_high - log_low) / (count - 1)
    return tuple(math.exp(log_low + i * step) for i in range(count))


@dataclass(frozen=True)
class FleetEpochRecord:
    epoch: int
    tx: int
    rx: int
    floor: float
    censored: bool = False
    repair_generation: int = 0


@dataclass(frozen=True)
class FleetEProcessResult:
    epoch: int
    repair_generation: int
    wealth: float
    alarmed: bool


class FleetAbsoluteEProcess:
    """One independent sealed sequence per sublink."""

    def __init__(self, alpha: float, alternatives: Sequence[float]):
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must lie in (0, 1)")
        alternatives = tuple(float(value) for value in alternatives)
        if not alternatives:
            raise ValueError("at least one alternative is required")
        if any(not 0.0 < value < 1.0 for value in alternatives):
            raise ValueError("every alternative must lie in (0, 1)")
        self.alpha = float(alpha)
        self.alternatives = alternatives
        self._log_capitals = [0.0] * len(alternatives)
        self._repair_generation = 0
        self._last_epoch: Optional[int] = None

    def ingest(self, record: FleetEpochRecord) -> FleetEProcessResult:
        if record.tx < 0 or record.rx < 0:
            raise ValueError("counts must be non-negative")
        if record.rx > record.tx:
            raise ValueError("rx cannot exceed tx")
        if not 0.0 < record.floor < 1.0:
            raise ValueError("floor must lie in (0, 1)")
        if record.repair_generation < self._repair_generation:
            raise ValueError("repair_generation must not move backwards")

        if record.repair_generation > self._repair_generation:
            self._repair_generation = record.repair_generation
            self._log_capitals = [0.0] * len(self.alternatives)
            self._last_epoch = None

        if self._last_epoch is not None and record.epoch <= self._last_epoch:
            raise ValueError(
                "epochs must be strictly increasing within a repair generation")
        self._last_epoch = record.epoch

        if not record.censored and record.tx > 0:
            delivered = record.rx
            lost = record.tx - delivered
            healthy_delivery = 1.0 - record.floor
            for index, alternative in enumerate(self.alternatives):
                alt_delivery = 1.0 - alternative
                self._log_capitals[index] += (
                    delivered * math.log(alt_delivery / healthy_delivery) +
                    lost * math.log(alternative / record.floor)
                )
        # censored and idle (tx == 0) epochs contribute a factor of one:
        # log_capitals are untouched, but last_epoch still advances.

        wealth = self._wealth()
        return FleetEProcessResult(
            epoch=record.epoch,
            repair_generation=self._repair_generation,
            wealth=wealth,
            alarmed=wealth >= 1.0 / self.alpha,
        )

    def _wealth(self) -> float:
        weight = 1.0 / len(self.alternatives)
        terms = [math.log(weight) + capital for capital in self._log_capitals]
        largest = max(terms)
        log_wealth = largest + math.log(sum(math.exp(t - largest) for t in terms))
        if log_wealth >= 700.0:
            return math.inf
        return math.exp(log_wealth)
