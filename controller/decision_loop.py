"""Wires the fleet floor estimator, the primary absolute e-process, e-BH fleet
control, and the continuous mitigation weight into one per-epoch tick
(`docs/review/BRAINSTORM-2026-09-01.md` §5 build step 5).

This resolves the round-3 review's RPC-in-critical-path finding by
construction: the statistical decision was always meant to run "at the epoch
level as a bounded-mean betting process" (brainstorm C2), so `tick()` only
ever consumes a caller-supplied snapshot of each sublink's (tx, rx) counters
for the epoch that just closed -- the same numbers a periodic background poll
(`p4/hw/loop/controller_loop.py`'s `CensusWorker`) already produces on its own
schedule. Nothing here performs a synchronous, targeted RPC call; the
existing per-gap-event resolver (`resolve_ledger_gap_event`) keeps serving its
own immediate-diagnostics purpose on a separate path and is untouched.

Two rounds of adversarial review
(`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md`) found and this
revision fixes:

- **Previsibility (CRITICAL 2).** Floors for every sublink are computed from
  the estimator's state as of the end of the *previous* tick, before any
  sublink's current-epoch counts are recorded. Verified fixed by the second
  review.
- **Anti-conservative floor fallback (CRITICAL 1) / unreachable censoring
  (HIGH 1).** `FleetFloorEstimator.floor_for` returns `None` when its pool is
  too thin to trust; `None` is treated as a censored epoch (factor of one, no
  reset), never a numeric substitute. Verified fixed by the second review.
- **Restoration arming crash (CRITICAL A, found in round 2).** A sublink
  blackholed for its entire recorded history produces a raw suspect-rate
  ratio of exactly 1.0, which used to raise uncaught from
  `RestorationEProcess.arm` and permanently wedge `tick()`.
  `_SublinkState.suspect_rate_estimate` and `RestorationEProcess.arm` both
  now clamp below 1.0.
- **Restoration grid coupling (CRITICAL B, round 2: CRITICAL 3's first fix
  was necessary but not sufficient).** A restoration grid fixed once at
  construction can sit below a fleet floor that has since drifted, or below
  the true background rate a spuriously-armed, actually-healthy sublink is
  really producing -- both make restoration practically unreachable even
  though `arm()`'s "suspect_rate exceeds every alternative" guard was
  satisfied. The healthy-alternatives grid is now built fresh at every arm
  attempt from the CURRENT floor for that sublink (`floors[sublink]` from
  this same tick's pass 1), not a fixed construction-time grid.
- **Suspect-rate dilution (HIGH D, round 2).** Estimating the suspect rate
  from a sublink's *lifetime* cumulative totals dilutes toward its historical
  (healthy) average the longer it was healthy before degrading, making later
  armings close to indistinguishable from the background. The estimate now
  comes from `FleetFloorEstimator.own_rate_estimate`, a trailing window of
  that sublink's own recent behaviour, matching the floor's own window.

**NOT PRODUCTION READY as of 2026-09-02 -- three review rounds, each finding a
deeper structural problem than the last (`docs/review/artifacts/
STATS-LAYER-REVIEW-2026-09-02.md` has the full record). This module has no
production caller anywhere in the repo (grep confirms it -- only its own test
suite exercises it), so nothing live is at risk, but it must not be wired
into `p4/hw/loop/controller_loop.py` or used for any paper claim until the
open items below are resolved with human design judgment, not another
autonomous patch cycle:**

- **CRITICAL C (round 2, unresolved).** Under a shared shock across siblings
  (e.g. a hot spine port), the pooled floor lags a fleet-wide change and the
  false-rejection rate was measured up to 1.00 in an adversarial
  configuration. Needs `relative_eprocess.py`'s congestion-vs-gray
  discriminator wired with queue-depth/context stratification -- a real
  design task, not a small fix.
- **CRITICAL 1, round 3 -- a single degraded link can drive the ENTIRE fleet
  into a permanent, unrecoverable absorbing deadlock.** The `healthy` tag fed
  to the floor estimator is previsible (correctly so) but therefore stale by
  exactly one epoch, so a newly-degraded link's first bad epoch still counts
  as healthy evidence and pollutes its siblings' floors upward. Because the
  primary alternatives grid is FIXED at construction while the floor can
  rise, clean traffic against an inflated floor can itself alarm (measured:
  wealth 1.2e+74 from clean 1e-3 traffic once the floor rose to 0.1). This
  cascades: mitigated sublinks compound the floor contamination for the rest
  of the fleet, until every sublink is mitigated, every leave-one-out pool is
  empty, every epoch censors, and wealth freezes forever -- measured: still
  100% mitigated 4800 epochs after the single triggering fault was repaired.
  Fix direction (measured to work): couple the PRIMARY alternatives grid to
  the current floor the same way `_restoration_grid` already couples the
  restoration grid, and give the loop an escape hatch from an all-censored
  state.
- **CRITICAL 2, round 3 -- HIGH D is not actually fixed; restoration action
  rate measured at 0/8 against the design's required >=0.9.** The trailing
  window in `own_rate_estimate` removes lifetime dilution but arming still
  fires on the SAME tick the primary detector first reacts, when the window
  contains zero degraded epochs yet -- measured suspect_rate understated by
  9x to 194x versus the true degraded rate, arming a restoration sequence
  against a null that is barely distinguishable from the healthy floor.
  Window size does not fix this; the estimate needs to be anchored to the
  evidence that triggered arming (e.g. epochs since the primary process's
  wealth started climbing, or the primary mixture's own argmax alternative),
  not a fixed-length trailing window measured from the arming tick.
- **HIGH -- `restoration_grid_low` is an unvalidated config trap.**
  Unchecked against `floor_min` or any achievable floor; when there is no
  headroom, arming silently no-ops with no error or log line, and every
  mitigated sublink stays pinned at `w_min` forever with no visible cause.
- Round 3 also found two of this round's own regression tests do not
  actually kill the mutants they were written for (a full revert of the
  restoration-grid coupling and a full revert of both `suspect_rate` clamps
  both leave the 206-test suite green) -- the test suite currently
  overstates how protected these fixes are.

Flagged for Philip's explicit decision: this needs a design pass on how the
primary detector's null tracks a moving floor without becoming self-alarming,
and on how suspect-rate estimation should anchor to "evidence since arming"
rather than any fixed window -- not a fourth autonomous fix-and-review cycle.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

from controller.absolute_eprocess import (
    FleetAbsoluteEProcess,
    FleetEpochRecord,
    log_spaced_alternatives,
)
from controller.fleet_control import e_bh_reject
from controller.floor_estimator import FleetFloorEstimator
from controller.mitigation_weight import RestorationEProcess, weight_from_wealth


@dataclass(frozen=True)
class SublinkDecision:
    sublink: int
    wealth: float
    fleet_rejected: bool
    weight: float
    restoring: bool
    censored: bool


class _SublinkState:
    def __init__(self, alternatives: Sequence[float], alpha: float):
        self.process = FleetAbsoluteEProcess(alpha=alpha, alternatives=alternatives)
        self.restoration = RestorationEProcess(alpha=alpha)
        self.repair_generation = 0
        self.last_weight = 1.0


class FleetDecisionLoop:
    def __init__(self, alpha: float, alternatives: Sequence[float],
                 restoration_grid_low: float, restoration_grid_count: int,
                 floor_window_epochs: int, w_min: float, floor_min: float = 1e-6,
                 arm_weight_threshold: float = 0.8, suspect_min_tx: int = 1):
        self.alpha = float(alpha)
        self.alternatives = tuple(float(v) for v in alternatives)
        if not self.alternatives:
            raise ValueError("at least one alternative is required")
        if not 0.0 < restoration_grid_low < 1.0:
            raise ValueError("restoration_grid_low must lie in (0, 1)")
        if restoration_grid_count < 1:
            raise ValueError("restoration_grid_count must be positive")
        if not 0.0 < w_min < 1.0:
            raise ValueError("w_min must lie in (0, 1)")
        if not 0.0 < arm_weight_threshold <= 1.0:
            raise ValueError("arm_weight_threshold must lie in (0, 1]")
        self.restoration_grid_low = float(restoration_grid_low)
        self.restoration_grid_count = int(restoration_grid_count)
        self.w_min = float(w_min)
        self.arm_weight_threshold = float(arm_weight_threshold)
        self.suspect_min_tx = int(suspect_min_tx)
        self.floor = FleetFloorEstimator(window_epochs=floor_window_epochs,
                                          min_floor=floor_min)
        self._states: Dict[int, _SublinkState] = {}

    def _state_for(self, sublink: int) -> _SublinkState:
        state = self._states.get(sublink)
        if state is None:
            state = _SublinkState(self.alternatives, self.alpha)
            self._states[sublink] = state
        return state

    def _restoration_grid(self, current_floor: float) -> Optional[Sequence[float]]:
        """A fresh healthy-alternatives grid spanning up to the CURRENT
        floor, so genuine post-repair traffic at today's background rate
        falls inside the grid's coverage (CRITICAL B) rather than below a
        stale, more-optimistic grid fixed at construction time."""
        high = min(current_floor, 1.0 - 1e-6)
        if high <= self.restoration_grid_low:
            return None
        return log_spaced_alternatives(self.restoration_grid_low, high,
                                       self.restoration_grid_count)

    def tick(self, epoch: int,
             snapshots: Dict[int, Tuple[int, int]]) -> Dict[int, SublinkDecision]:
        """One epoch tick over every sublink reporting counts this epoch.

        `snapshots` maps sublink -> (tx, rx) for the epoch that just closed.
        """
        # Pass 1: read every floor -- and every sublink's own recent-rate
        # estimate, used only for restoration arming -- from state as of the
        # END of the PRIOR tick, before this epoch's counts are recorded
        # anywhere. This is what makes the null previsible with respect to
        # every sublink's current-epoch outcome, not just the sublink it is
        # judged for, and keeps arming from using the very epoch it then
        # immediately tests.
        floors = {sublink: self.floor.floor_for(sublink) for sublink in snapshots}
        suspect_rates = {sublink: self.floor.own_rate_estimate(sublink, self.suspect_min_tx)
                         for sublink in snapshots}

        # Pass 2: now record this epoch's counts (affects only FUTURE floors).
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            self.floor.record_epoch(sublink, epoch=epoch, tx=tx, rx=rx,
                                     healthy=state.last_weight >= 1.0)

        wealths: Dict[int, float] = {}
        censored_flags: Dict[int, bool] = {}
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            floor = floors[sublink]
            censored = floor is None
            censored_flags[sublink] = censored
            result = state.process.ingest(FleetEpochRecord(
                epoch=epoch, tx=tx, rx=rx, floor=floor if floor is not None else 0.5,
                censored=censored, repair_generation=state.repair_generation))
            wealths[sublink] = result.wealth

        rejected = e_bh_reject(wealths, alpha=self.alpha)

        decisions: Dict[int, SublinkDecision] = {}
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            weight = weight_from_wealth(wealths[sublink], self.w_min)
            floor = floors[sublink]

            if (weight <= self.arm_weight_threshold and not state.restoration.armed
                    and floor is not None):
                suspect_rate = suspect_rates[sublink]
                if suspect_rate is not None:
                    suspect_rate = min(suspect_rate, 1.0 - 1e-9)
                    grid = self._restoration_grid(floor)
                    if grid is not None and suspect_rate > max(grid):
                        state.restoration.arm(suspect_rate, healthy_alternatives=grid)
                # otherwise: not enough evidence, or no valid floor/grid yet
                # to arm safely -- wait for a later tick.

            restoring = state.restoration.armed
            if restoring:
                state.restoration.ingest(epoch=epoch, tx=tx, rx=rx,
                                         censored=censored_flags[sublink])
                if state.restoration.recovered:
                    state.restoration.disarm()
                    state.repair_generation += 1
                    weight = 1.0
                    restoring = False

            state.last_weight = weight
            decisions[sublink] = SublinkDecision(
                sublink=sublink,
                wealth=wealths[sublink],
                fleet_rejected=sublink in rejected,
                weight=weight,
                restoring=restoring,
                censored=censored_flags[sublink],
            )
        return decisions
