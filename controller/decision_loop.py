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

**Not resolved this pass, and explicitly NOT safe to treat as resolved
(CRITICAL C, round 2):** under a shared shock across siblings (e.g. a hot
spine port raising loss on every sibling roughly equally), the previsibility
fix removes the CRITICAL 2 leak but the pooled floor still lags a
fleet-wide change, and the second review measured the false-rejection rate
under a strong common shock rising to 1.00 (worse than the original leaky
code's 0.15 in that same adversarial configuration, though better in the
narrower scenario CRITICAL 2's own regression test targets). This is exactly
the failure mode `relative_eprocess.py`'s congestion-vs-gray discriminator
was kept in the design for (brainstorm C2, secondary mechanism) -- it
requires a queue-depth/context stratification key this snapshot shape does
not carry, which is a real design task, not a small wiring fix. **Until that
discriminator is wired, this layer's fleet-wide false-alarm control is not
preregistration-safe under non-stationary or common-mode load, and must not
be used for a paper claim about FDR control without that precondition stated
or the discriminator in place.** Tracked in WORKING_NOTES.md; flagged for
Philip's explicit decision on scope and on whether PREREG.md needs an
amendment before this is relied upon.
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
