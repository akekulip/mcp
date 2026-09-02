"""Wires the fleet floor estimator, the primary ratio-relative e-process,
e-BH fleet control, and the continuous mitigation weight into one per-epoch
tick (`docs/review/BRAINSTORM-2026-09-01.md` §5 build step 5).

This resolves the round-3 review's RPC-in-critical-path finding by
construction: the statistical decision was always meant to run "at the epoch
level as a bounded-mean betting process" (brainstorm C2), so `tick()` only
ever consumes a caller-supplied snapshot of each sublink's (tx, rx) counters
for the epoch that just closed -- the same numbers a periodic background poll
(`p4/hw/loop/controller_loop.py`'s `CensusWorker`) already produces on its own
schedule. Nothing here performs a synchronous, targeted RPC call; the
existing per-gap-event resolver (`resolve_ledger_gap_event`) keeps serving its
own immediate-diagnostics purpose on a separate path and is untouched.

Three review rounds (`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md`,
`STATS-LAYER-STATUS-2026-09-02.md`) found problems of increasing depth in an
earlier version of this wiring; the redesign proposal
(`STATS-LAYER-REDESIGN-PROPOSAL-2026-09-02.md`) analyzed each and this
revision implements the recommended fixes, in the recommended order:

- **Q3, incident-regime circuit breaker.** When the fraction of sublinks
  currently mitigated (previsibly, from `last_weight` as of the prior tick)
  reaches `incident_fraction_threshold`, a slow, fleet-wide historical
  baseline (an exponentially-weighted (tx, lost) accumulator, updated only
  OUTSIDE an incident so contamination cannot poison it) is offered as a
  fallback floor for any sublink whose live leave-one-out pool is too thin
  to trust -- instead of unconditional censoring. This is what breaks the
  round-3 absorbing deadlock: a pool that is empty because "everyone is
  mitigated" now still yields a real, previously-measured floor rather than
  freezing every sublink's wealth forever with no escape.
- **Q1, ratio-relative primary detector.** The primary process is now a
  `FleetRatioEProcess` (`absolute_eprocess.py`): its alternatives are fixed
  RATIOS above the current floor, not fixed absolute rates, so a floor that
  drifts upward (e.g. from the previsible-but-stale `healthy` tag admitting
  one contaminated epoch) cannot leave clean traffic looking better-fit to a
  now-too-low fixed grid than to the inflated null -- the mechanism that
  produced the measured 1.2e+74 false alarm and drove the round-3 cascade.
- **Q2, CUSUM-anchored suspect-rate estimation.** Restoration's suspect rate
  no longer comes from a fixed trailing window (which measured a 9x-194x
  understatement, since it mixes a long healthy prefix with the few epochs
  since a fast-triggering primary detector reacted). It is now estimated
  from raw counts accumulated only since `FleetRatioEProcess.change_point_epoch()`
  -- a CUSUM change-point estimate already available from the primary
  process's own state, re-anchored automatically as that estimate advances.

**Q4 (wiring `relative_eprocess.py` as a corroboration gate on mitigation
actions) is NOT implemented this pass** -- it needs queue-depth/context
stratification plumbing that does not exist anywhere in the repo yet (a real
data-plumbing lift, not a controller-side change) and its own measurement
plan from the redesign proposal. Until it lands, the CRITICAL C finding
(false-rejection rate up to 1.00 under a strong shared/common-mode shock
across siblings) remains open, and this layer's fleet-wide false-alarm
control is still not preregistration-safe under non-stationary or
common-mode load. Flagged for Philip's decision on scope and on whether
PREREG.md needs an amendment before this is relied upon for a paper claim.

Verification status as of this revision, measured directly (not asserted):
the exact round-3 cascade scenario (a single link degraded for 100 epochs on
a 16-sublink fleet) no longer cascades at all -- at most 1 of 16 sublinks is
ever mitigated, versus the prior 15/16 by epoch 2500, still 100% at epoch
4999. Restoration's action rate measured 8/8 at both degraded rates the
round-3 review used (0.20 and 0.05), versus the prior 0/8, meeting the
design's own >=0.9 target (brainstorm H2/H3). One additional defect was
found and fixed while validating Q2: `FleetRatioEProcess.change_point_epoch`
needed a minimum-climb gate, since a low-ratio alternative's log-capital
random-walks with slightly negative drift under a true null and touches a
"new minimum" almost every epoch by construction -- an un-gated running-min
epoch tracked essentially "now" throughout ordinary healthy operation and
discarded a real fault's own early evidence right when arming needed it
(collapsing the action-rate fix on its own). All of the above are permanent
regression tests in `controller/tests/test_decision_loop.py` and
`controller/tests/test_ratio_eprocess.py`. CRITICAL C (Q4, not implemented
this pass) remains open and unchanged in status -- a fresh empirical check
found ~22% false-alarm rate under a common-mode shock in one configuration,
consistent with "still an open problem," not newly regressed by Q1's change
to the primary detector. A fresh adversarial review is still warranted
before this is considered settled, given the pattern of the first three
rounds.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

from controller.absolute_eprocess import FleetEpochRecord, FleetRatioEProcess
from controller.fleet_control import e_bh_reject
from controller.floor_estimator import FleetFloorEstimator
from controller.mitigation_weight import RestorationEProcess, weight_from_wealth
from controller.absolute_eprocess import log_spaced_alternatives


@dataclass(frozen=True)
class SublinkDecision:
    sublink: int
    wealth: float
    fleet_rejected: bool
    weight: float
    restoring: bool
    censored: bool
    incident_fallback: bool = False


class _SublinkState:
    def __init__(self, ratios: Sequence[float], alpha: float):
        self.process = FleetRatioEProcess(alpha=alpha, ratios=ratios)
        self.restoration = RestorationEProcess(alpha=alpha)
        self.repair_generation = 0
        self.last_weight = 1.0
        self._suspect_accum_start_epoch: Optional[int] = None
        self._suspect_accum_tx = 0
        self._suspect_accum_lost = 0

    def suspect_rate_estimate(self, min_tx: int) -> Optional[float]:
        """Raw rate accumulated since the primary process's own CUSUM
        change-point estimate -- read BEFORE this tick's `update_suspect_
        accumulator` call, so it never includes the current epoch."""
        if self._suspect_accum_tx < min_tx:
            return None
        return self._suspect_accum_lost / self._suspect_accum_tx

    def update_suspect_accumulator(self, tx: int, rx: int) -> None:
        change_point = self.process.change_point_epoch()
        if change_point != self._suspect_accum_start_epoch:
            self._suspect_accum_start_epoch = change_point
            self._suspect_accum_tx = 0
            self._suspect_accum_lost = 0
        if change_point is not None:
            self._suspect_accum_tx += tx
            self._suspect_accum_lost += tx - rx

    def reset_suspect_accumulator(self) -> None:
        self._suspect_accum_start_epoch = None
        self._suspect_accum_tx = 0
        self._suspect_accum_lost = 0


class FleetDecisionLoop:
    def __init__(self, alpha: float, ratios: Sequence[float],
                 restoration_grid_low: float, restoration_grid_count: int,
                 floor_window_epochs: int, w_min: float, floor_min: float = 1e-6,
                 arm_weight_threshold: float = 0.8, suspect_min_tx: int = 1,
                 incident_fraction_threshold: float = 0.3,
                 baseline_decay: float = 0.98):
        self.alpha = float(alpha)
        self.ratios = tuple(float(v) for v in ratios)
        if not self.ratios:
            raise ValueError("at least one ratio is required")
        if not 0.0 < restoration_grid_low < 1.0:
            raise ValueError("restoration_grid_low must lie in (0, 1)")
        if restoration_grid_count < 1:
            raise ValueError("restoration_grid_count must be positive")
        if not 0.0 < w_min < 1.0:
            raise ValueError("w_min must lie in (0, 1)")
        if not 0.0 < arm_weight_threshold <= 1.0:
            raise ValueError("arm_weight_threshold must lie in (0, 1]")
        if not 0.0 < incident_fraction_threshold <= 1.0:
            raise ValueError("incident_fraction_threshold must lie in (0, 1]")
        if not 0.0 < baseline_decay < 1.0:
            raise ValueError("baseline_decay must lie in (0, 1)")
        self.restoration_grid_low = float(restoration_grid_low)
        self.restoration_grid_count = int(restoration_grid_count)
        self.w_min = float(w_min)
        self.arm_weight_threshold = float(arm_weight_threshold)
        self.suspect_min_tx = int(suspect_min_tx)
        self.incident_fraction_threshold = float(incident_fraction_threshold)
        self.baseline_decay = float(baseline_decay)
        self.floor = FleetFloorEstimator(window_epochs=floor_window_epochs,
                                          min_floor=floor_min)
        self._states: Dict[int, _SublinkState] = {}
        self._baseline_tx = 0.0
        self._baseline_lost = 0.0

    def _state_for(self, sublink: int) -> _SublinkState:
        state = self._states.get(sublink)
        if state is None:
            state = _SublinkState(self.ratios, self.alpha)
            self._states[sublink] = state
        return state

    @property
    def in_incident(self) -> bool:
        if not self._states:
            return False
        mitigated = sum(1 for state in self._states.values() if state.last_weight < 1.0)
        return (mitigated / len(self._states)) >= self.incident_fraction_threshold

    def _baseline_floor(self) -> Optional[float]:
        if self._baseline_tx <= 0.0:
            return None
        return self._baseline_lost / self._baseline_tx

    def _restoration_grid(self, current_floor: Optional[float]) -> Optional[Sequence[float]]:
        """A fresh healthy-alternatives grid spanning up to the CURRENT
        floor, so genuine post-repair traffic at today's background rate
        falls inside the grid's coverage (round-2 CRITICAL B) rather than
        below a stale, more-optimistic grid fixed at construction time."""
        if current_floor is None:
            return None
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
        # `in_incident` and every floor/suspect-rate read below use state as
        # of the END of the PRIOR tick, before any of this epoch's counts are
        # recorded anywhere -- previsibility with respect to every sublink's
        # current-epoch outcome, not just the sublink it is judged for, and
        # keeps arming from using the very epoch it then immediately tests.
        incident = self.in_incident
        baseline_floor = self._baseline_floor()

        floors: Dict[int, Optional[float]] = {}
        incident_fallback: Dict[int, bool] = {}
        for sublink in snapshots:
            floor = self.floor.floor_for(sublink)
            fallback = False
            if floor is None and incident and baseline_floor is not None:
                floor = baseline_floor
                fallback = True
            floors[sublink] = floor
            incident_fallback[sublink] = fallback

        suspect_rates = {
            sublink: self._state_for(sublink).suspect_rate_estimate(self.suspect_min_tx)
            for sublink in snapshots
        }

        # Now record this epoch's counts (affects only FUTURE floors) and the
        # slow historical baseline (frozen during an incident so contamination
        # cannot poison the very fallback meant to survive it).
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            self.floor.record_epoch(sublink, epoch=epoch, tx=tx, rx=rx,
                                     healthy=state.last_weight >= 1.0)
            if not incident:
                self._baseline_tx = self._baseline_tx * self.baseline_decay + tx
                self._baseline_lost = (self._baseline_lost * self.baseline_decay +
                                       (tx - rx))

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
            state.update_suspect_accumulator(tx, rx)

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
                    state.reset_suspect_accumulator()
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
                incident_fallback=incident_fallback[sublink],
            )
        return decisions
