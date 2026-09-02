"""Leave-one-out estimate of the fleet's healthy loss floor, p0(t).

The primary absolute e-process (`absolute_eprocess.py`) needs a null that moves
with the fleet rather than a fixed constant (`docs/review/BRAINSTORM-2026-09-01.md`
C2: "a floor estimated continuously from the fleet's own healthy sublinks").
This estimator answers "what loss rate do this sublink's healthy siblings show
right now", excluding the sublink itself and any sublink currently outside the
healthy pool, so a genuinely bad link cannot inflate the floor used to judge it
or its siblings. Excluding the sublink's own counts also keeps the estimate
previsible with respect to that sublink's own next outcome, which the primary
e-process's validity depends on.
"""

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict


@dataclass(frozen=True)
class _EpochSample:
    epoch: int
    tx: int
    lost: int
    healthy: bool


class FleetFloorEstimator:
    """Trailing-window, leave-one-out loss-rate estimate across sublinks."""

    def __init__(self, window_epochs: int, min_floor: float = 1e-6,
                 min_pool_tx: int = 1):
        if window_epochs <= 0:
            raise ValueError("window_epochs must be positive")
        if not 0.0 < min_floor < 1.0:
            raise ValueError("min_floor must lie in (0, 1)")
        if min_pool_tx <= 0:
            raise ValueError("min_pool_tx must be positive")
        self.window_epochs = int(window_epochs)
        self.min_floor = float(min_floor)
        self.min_pool_tx = int(min_pool_tx)
        self._samples: Dict[int, Deque[_EpochSample]] = {}

    def record_epoch(self, sublink: int, epoch: int, tx: int, rx: int,
                      healthy: bool) -> None:
        if tx < 0 or rx < 0:
            raise ValueError("counts must be non-negative")
        if rx > tx:
            raise ValueError("rx cannot exceed tx")
        window = self._samples.setdefault(sublink, deque())
        window.append(_EpochSample(epoch=epoch, tx=tx, lost=tx - rx,
                                    healthy=healthy))
        while len(window) > self.window_epochs:
            window.popleft()

    def floor_for(self, sublink: int) -> float:
        """Leave-one-out p0 estimate excluding `sublink` and unhealthy siblings."""
        pool_tx = 0
        pool_lost = 0
        for other, window in self._samples.items():
            if other == sublink:
                continue
            for sample in window:
                if not sample.healthy:
                    continue
                pool_tx += sample.tx
                pool_lost += sample.lost
        if pool_tx < self.min_pool_tx:
            return self.min_floor
        estimate = pool_lost / pool_tx
        return max(self.min_floor, min(estimate, 1.0 - self.min_floor))
