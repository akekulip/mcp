"""Secondary congestion-vs-gray discriminator: a sublink's share of a stratum's
total losses, tested against its known spray weight.

Used only inside a queue-depth stratum where the primary absolute test
(`absolute_eprocess.py`) cannot tell a hot spine port -- which raises loss on
every sibling roughly equally -- from a genuinely gray link -- which raises one
sibling's share disproportionately. Demoted from headline detector to this
role after red-team finding 9.6 in `docs/review/BRAINSTORM-2026-09-01.md`: it
costs 14x more packets than the absolute test at typical background rates and
degrades as (excess/background)^2, which gives back exactly the sub-1% regime
the project targets. It stays valuable here because it needs no floor
estimate at all: under H0, a sublink's losses given the stratum's total
losses this epoch are exactly Binomial(total_losses, known_share) -- exact
under any temporal burstiness, because the spray weight is the design's own
randomization, not an estimate.

A stratum-epoch with zero total losses carries no information and is skipped
(a factor of one), matching the fleet-level censoring rule.
"""

import math
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class RelativeEpochRecord:
    epoch: int
    stratum_total_losses: int
    sublink_losses: int


class RelativeExchangeabilityTest:
    """One independent sequence per (sublink, queue-depth stratum) pair."""

    def __init__(self, alpha: float, known_share: float,
                 excess_shares: Sequence[float]):
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must lie in (0, 1)")
        if not 0.0 < known_share < 1.0:
            raise ValueError("known_share must lie in (0, 1)")
        excess_shares = tuple(float(value) for value in excess_shares)
        if not excess_shares:
            raise ValueError("at least one excess-share alternative is required")
        if any(not known_share < value < 1.0 for value in excess_shares):
            raise ValueError("every excess share must lie in (known_share, 1)")

        self.alpha = float(alpha)
        self.known_share = float(known_share)
        self.excess_shares = excess_shares
        self._log_capitals = [0.0] * len(excess_shares)
        self._last_epoch = None

    def ingest(self, record: RelativeEpochRecord) -> float:
        if record.stratum_total_losses < 0 or record.sublink_losses < 0:
            raise ValueError("counts must be non-negative")
        if record.sublink_losses > record.stratum_total_losses:
            raise ValueError("sublink losses cannot exceed the stratum total")
        if self._last_epoch is not None and record.epoch <= self._last_epoch:
            raise ValueError("epochs must be strictly increasing")
        self._last_epoch = record.epoch

        if record.stratum_total_losses > 0:
            n = record.stratum_total_losses
            k = record.sublink_losses
            for index, share in enumerate(self.excess_shares):
                self._log_capitals[index] += (
                    k * math.log(share / self.known_share) +
                    (n - k) * math.log((1.0 - share) / (1.0 - self.known_share))
                )
        return self.wealth()

    def wealth(self) -> float:
        weight = 1.0 / len(self.excess_shares)
        terms = [math.log(weight) + capital for capital in self._log_capitals]
        largest = max(terms)
        log_wealth = largest + math.log(sum(math.exp(t - largest) for t in terms))
        if log_wealth >= 700.0:
            return math.inf
        return math.exp(log_wealth)

    @property
    def alarmed(self) -> bool:
        return self.wealth() >= 1.0 / self.alpha
