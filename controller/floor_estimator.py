"""Leave-one-out estimate of the fleet's healthy loss floor, p0(t).

The primary absolute e-process (`absolute_eprocess.py`) needs a null that moves
with the fleet rather than a fixed constant (`docs/review/BRAINSTORM-2026-09-01.md`
C2: "a floor estimated continuously from the fleet's own healthy sublinks").
This estimator answers "what loss rate do this sublink's healthy siblings show
right now", excluding the sublink itself and any sublink currently outside the
healthy pool, so a genuinely bad link cannot inflate the floor used to judge it
or its siblings.

`floor_for` returns `None` when the leave-one-out pool has too little traffic
to trust (cold start, a single-sublink fleet, or every sibling currently under
mitigation). Substituting a fallback number there was tried and rejected
(`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md`, CRITICAL 1): a
fixed anti-conservative floor such as `min_floor` makes every epoch look like
overwhelming evidence of loss and produced 200/200 false alarms on a fully
healthy fleet in the reachable single-sublink case. The caller must treat
`None` the same way it treats any other invalid-null epoch: censored, a
factor of one, no reset.

Each sublink keeps a running (tx, lost) total over its own currently-healthy,
unexpired samples, incrementally updated on insert and eviction, rather than
re-summing its whole window on every query (the same review's M2 finding:
re-summing made `floor_for` O(S*W) per call, measured at 1.76s for a single
tick at the design's own 1024-sublink target scale). `floor_for` is now O(S).
"""

from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional


@dataclass(frozen=True)
class _EpochSample:
    epoch: int
    tx: int
    lost: int
    healthy: bool


class _SublinkWindow:
    def __init__(self) -> None:
        self.samples: Deque[_EpochSample] = deque()
        # healthy-only totals -- feed the leave-one-out floor pool
        self.running_tx = 0
        self.running_lost = 0
        # unfiltered totals -- this sublink's own recent behaviour regardless
        # of its healthy/unhealthy tag, used to estimate ITS OWN suspect rate
        self.raw_tx = 0
        self.raw_lost = 0

    def append(self, sample: _EpochSample) -> None:
        self.samples.append(sample)
        if sample.healthy:
            self.running_tx += sample.tx
            self.running_lost += sample.lost
        self.raw_tx += sample.tx
        self.raw_lost += sample.lost

    def prune(self, cutoff_epoch: int) -> None:
        while self.samples and self.samples[0].epoch <= cutoff_epoch:
            evicted = self.samples.popleft()
            if evicted.healthy:
                self.running_tx -= evicted.tx
                self.running_lost -= evicted.lost
            self.raw_tx -= evicted.tx
            self.raw_lost -= evicted.lost


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
        self._windows: Dict[int, _SublinkWindow] = {}
        self._latest_epoch: Optional[int] = None

    def record_epoch(self, sublink: int, epoch: int, tx: int, rx: int,
                      healthy: bool) -> None:
        if tx < 0 or rx < 0:
            raise ValueError("counts must be non-negative")
        if rx > tx:
            raise ValueError("rx cannot exceed tx")
        self._latest_epoch = (epoch if self._latest_epoch is None
                              else max(self._latest_epoch, epoch))
        window = self._windows.setdefault(sublink, _SublinkWindow())
        window.append(_EpochSample(epoch=epoch, tx=tx, lost=tx - rx,
                                    healthy=healthy))
        window.prune(epoch - self.window_epochs)

    def floor_for(self, sublink: int) -> Optional[float]:
        """Leave-one-out p0 estimate excluding `sublink` and unhealthy siblings.

        Returns `None` when the pool has too little traffic to trust -- the
        caller must censor that epoch rather than substitute a number. Every
        sibling's window is pruned against the fleet's own latest-seen epoch
        before reading its running total, not just its own last-write epoch,
        so a sublink that has stopped reporting still ages out of the pool.
        """
        pool_tx = 0
        pool_lost = 0
        cutoff = (None if self._latest_epoch is None
                 else self._latest_epoch - self.window_epochs)
        for other, window in self._windows.items():
            if other == sublink:
                continue
            if cutoff is not None:
                window.prune(cutoff)
            pool_tx += window.running_tx
            pool_lost += window.running_lost
        if pool_tx < self.min_pool_tx:
            return None
        estimate = pool_lost / pool_tx
        return max(self.min_floor, min(estimate, 1.0 - self.min_floor))

    def own_rate_estimate(self, sublink: int, min_tx: int = 1) -> Optional[float]:
        """This sublink's own recent loss rate over the trailing window,
        regardless of its healthy/unhealthy tag -- unlike `floor_for`, which
        deliberately excludes unhealthy epochs from the leave-one-out pool,
        this answers "how has this specific sublink actually been behaving
        lately", which is what estimating ITS OWN suspect rate needs
        (`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md`, HIGH D: a
        lifetime average dilutes toward the historical floor the longer a
        link was healthy before degrading; a trailing window does not).
        Returns `None` when there is too little recent data to trust.
        """
        window = self._windows.get(sublink)
        if window is None:
            return None
        if self._latest_epoch is not None:
            window.prune(self._latest_epoch - self.window_epochs)
        if window.raw_tx < min_tx:
            return None
        return window.raw_lost / window.raw_tx
