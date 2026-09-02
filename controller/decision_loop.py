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

Four review rounds now (`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md`,
`STATS-LAYER-STATUS-2026-09-02.md`, and round 4 recorded below) have found
problems of increasing depth, and this docstring has twice been caught
overstating what was actually verified -- read it as a status report with
its own history of correction, not a finished spec.

## What genuinely works, independently re-measured by round 4 on fresh seeds

- **Q1, ratio-relative primary detector.** The primary process is a
  `FleetRatioEProcess` (`absolute_eprocess.py`): its alternatives are fixed
  RATIOS above the current floor, not fixed absolute rates. **This, alone,
  is what ends the round-3 absorbing deadlock** -- round 4 instrumented the
  exact cascade scenario and found Q3 (below) never engages in it at all (0
  incident epochs). Confirmed on 5 seeds: at most 1-2 of 16 sublinks are
  ever mitigated simultaneously (versus 15/16 by epoch 2500 previously,
  still 100% at epoch 4999), and the fault recovers within roughly 600-800
  epochs of its own end.
- **Q2, CUSUM-anchored suspect-rate estimation**, using
  `FleetRatioEProcess.change_point_epoch()` (gated by a minimum log-capital
  climb -- see below) instead of a fixed trailing window. Restoration's
  action rate measured 8/8 at both of round 3's degraded rates (0.20, 0.05)
  across 8 fresh seeds, checked against the actual `repair_generation`
  counter (not just "weight back near 1"), meeting the design's own >=0.9
  target (brainstorm H2/H3) -- versus 0/8 before. No cross-fault state leak:
  two sequential faults on the same sublink, and a second fault on a
  different sublink, both estimate cleanly with no trace of prior evidence.
  One defect was found and fixed while validating this: the running-min
  tracker needs a minimum-climb gate (`change_point_epoch(min_climb=3.0)`),
  since under a true null a low-ratio alternative's log-capital random-walks
  with negative drift and touches a "new minimum" almost every epoch by
  construction -- an ungated estimate tracked essentially "now" throughout
  ordinary operation and discarded a fault's own early evidence right when
  arming needed it, which by itself made the action-rate fix ineffective.
  Both headline results (no cascade, action rate) are mutant-tested: reverting
  either Q1 or Q2 alone is caught by a dedicated regression test in
  `controller/tests/test_decision_loop.py`.

## What is newly broken or still broken (round 4)

- **CRITICAL -- Q1 measurably REGRESSES the common-mode-shock case; an
  earlier version of this docstring incorrectly claimed the opposite.**
  Round 4 measured that under a sustained EXOGENOUS shock across all
  sublinks (nothing individually faulty), Q1's ratio grid can pin the
  ENTIRE fleet at `w_min` with e-BH rejections on nearly every sublink-epoch
  -- two to three orders of magnitude worse than the pre-Q1 code in the same
  scenario. Mechanism: during a shock the leave-one-out floor lags, i.e.
  UNDER-estimates the true rate; because Q1's alternatives scale with the
  floor, an under-estimated floor times a ratio can land close to the
  fleet's new true rate, so every epoch looks like strong evidence for the
  ratio alternative rather than the (also moved) truth. This is exactly the
  "mirrored risk" the redesign proposal flagged as unprotected and
  unvalidated for Q1, and it fails when actually measured. There is also a
  closed-form breakeven, independent of any shock: a healthy link whose true
  rate persistently exceeds ~1.44x the fleet's estimated floor alarms with
  probability -> 1 even with no fault ever injected. **This is not fixed.**
  It needs either a floor-staleness guard (censor, or widen the tested null,
  when the fleet-aggregate rate has moved faster than the floor window can
  track) or Q4's corroboration gate -- both are design work, not a small
  patch, and CRITICAL C's status (below) is the same underlying problem
  viewed from the fleet-FDR side rather than the single-link side.
- **CRITICAL C (common-mode shock, Q4 not implemented) is open and, per the
  above, is the same root cause as the new CRITICAL just described, not an
  independent one.** Wiring `relative_eprocess.py` needs queue-depth/context
  stratification plumbing that does not exist anywhere in the repo yet.
  Until either that or a floor-staleness guard lands, this layer's
  fleet-wide false-alarm control is not preregistration-safe under
  non-stationary or common-mode load, and per-link detection is not safe
  when the fleet's own aggregate rate is moving quickly, independent of any
  single link's own true behavior.
- **HIGH -- restoration can prematurely declare a fault repaired while it is
  still active, at low severities close to the floor.** `suspect_min_tx`
  defaulted to 1 (arming reachable on a single epoch's worth of evidence);
  raising it reduces but does not eliminate this, because at true rates only
  slightly above the floor the risk is closer to an inherent property of a
  bounded-alpha hypothesis test than a fixable estimation bug -- restoration
  runs its own alpha, and a nonzero false-restoration rate under a
  genuinely-still-faulty null is not automatically zero just because the
  primary side of the same alpha is well controlled. `suspect_min_tx` now
  defaults to 2000 (a few thousand packets, not one epoch); the regression
  tests report the premature-restoration rate NEXT TO the action rate, not
  in isolation (a usefulness number without its safety number beside it is
  an incomplete report), and both are 0.0/8 and 8/8 respectively at the
  degraded rates the design's own H2/H3 target uses. The residual risk at
  much lower severities (true rate within ~2-3x of the floor) is disclosed,
  not eliminated, and would need its own dedicated statistical treatment
  (e.g. a minimum required log-capital climb before trusting a restoration
  verdict, analogous to Q2's `min_climb` gate) if the design ever needs
  reliable restoration that close to the noise floor.
- Two lower-severity implementation bugs found and fixed by round 4: the
  slow fleet-wide baseline's exponential decay was applied once PER SUBLINK
  inside the per-epoch loop rather than once per epoch, silently shrinking
  its effective memory with fleet size (measured ~1 epoch of memory at the
  design's own 1024-sublink target, instead of "much slower than the 20-epoch
  live window" as intended) -- fixed to decay exactly once per epoch. The
  baseline's output was also unclamped and could reach exactly 0.0 or 1.0,
  which `FleetRatioEProcess.ingest` rejects -- now clamped to
  `[floor_min, 1 - floor_min]`.
- Known, not yet addressed: the fleet-wide baseline is not leave-one-out
  (a sublink's own traffic feeds the very baseline handed back to it as a
  fallback null) and is not immune to a single fault below the incident
  threshold (a 1-in-16 fault, 6.25%, never triggers `incident_fraction_threshold`
  at its default 0.3, so it still feeds the "frozen" baseline directly);
  `_states` is never evicted for a sublink that stops reporting, so
  `in_incident` and the baseline can latch onto stale state indefinitely;
  `incident_fraction_threshold` quantizes coarsely at small fleet sizes
  (any single sublink is already >=1/3 of a 3-sublink fleet).

A fifth adversarial review is warranted before any of this is considered
settled, given the pattern of every round so far finding something the
previous one missed or misreported.
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
                 arm_weight_threshold: float = 0.8, suspect_min_tx: int = 2000,
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
        if suspect_min_tx < 1:
            raise ValueError("suspect_min_tx must be positive")
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
        estimate = self._baseline_lost / self._baseline_tx
        floor_min = self.floor.min_floor
        return max(floor_min, min(estimate, 1.0 - floor_min))

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
        # cannot poison the very fallback meant to survive it). The decay is
        # applied exactly ONCE per epoch here, not once per sublink inside the
        # loop below -- round-4 review measured that decaying per-sublink made
        # the "slow" baseline's effective memory shrink with fleet size (3.6
        # epochs at 16 sublinks, ~1 epoch at the design's 1024-sublink target),
        # silently defeating the point of a baseline slower than the live
        # floor window.
        if not incident:
            self._baseline_tx *= self.baseline_decay
            self._baseline_lost *= self.baseline_decay
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            self.floor.record_epoch(sublink, epoch=epoch, tx=tx, rx=rx,
                                     healthy=state.last_weight >= 1.0)
            if not incident:
                self._baseline_tx += tx
                self._baseline_lost += tx - rx

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
