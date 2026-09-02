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

An adversarial review (`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md`)
found and this revision fixes three critical defects in an earlier version of
this wiring:

- **Previsibility (CRITICAL 2).** Floors for every sublink are computed from
  the estimator's state as of the end of the *previous* tick, before any
  sublink's current-epoch counts are recorded. Recording used to happen
  before computing floors, which let a sibling's own current-epoch outcome
  leak into the null it was judged against under a shared shock (e.g. a hot
  spine port) -- measured false-rejection rate up to 0.500 on a fully healthy
  fleet. The fix is strict ordering: read every floor, THEN record every
  sublink's epoch.
- **Anti-conservative floor fallback (CRITICAL 1) / unreachable censoring
  (HIGH 1).** `FleetFloorEstimator.floor_for` returns `None` when its pool is
  too thin to trust (cold start, one sublink, or every sibling under
  mitigation). This used to be silently replaced by `min_floor`, the most
  anti-conservative null available -- measured 200/200 false alarms on a
  healthy single-sublink fleet. `None` is now treated as a censored epoch:
  the primary process is fed `censored=True` (factor of one, no reset,
  brainstorm C2 verbatim), never a numeric substitute.
- **Restoration arming (CRITICAL 3).** Arming used to trigger on `wealth >
  1.0` (roughly a coin flip under the null) using the arming epoch's own
  empirical rate as the null it then immediately tested (circular). Arming
  now requires the mitigation weight to have dropped to `arm_weight_threshold`
  or below (a real, sustained signal), and estimates the suspect rate from
  the sublink's cumulative (tx, lost) totals accumulated strictly *before*
  the arming epoch -- never the epoch it is about to test.

Deliberately NOT wired this pass, and left dead rather than pretending
otherwise: `relative_eprocess.py`'s congestion-vs-gray discriminator (needs a
queue-depth/context stratification key this snapshot shape does not carry
yet) and context (4-bit) stratification of the primary detector itself. Both
are the brainstorm's C2 stratification requirement and remain open work,
tracked in WORKING_NOTES.md rather than silently absent.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Sequence, Tuple

from controller.absolute_eprocess import FleetAbsoluteEProcess, FleetEpochRecord
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
    def __init__(self, alternatives: Sequence[float],
                 restoration_alternatives: Sequence[float], alpha: float):
        self.process = FleetAbsoluteEProcess(alpha=alpha, alternatives=alternatives)
        self.restoration = RestorationEProcess(
            alpha=alpha, healthy_alternatives=restoration_alternatives)
        self.repair_generation = 0
        self.last_weight = 1.0
        self.cumulative_tx = 0
        self.cumulative_lost = 0

    def suspect_rate_estimate(self) -> Optional[float]:
        """The empirical rate from evidence strictly before the current epoch."""
        if self.cumulative_tx == 0:
            return None
        return self.cumulative_lost / self.cumulative_tx


class FleetDecisionLoop:
    def __init__(self, alpha: float, alternatives: Sequence[float],
                 restoration_alternatives: Sequence[float],
                 floor_window_epochs: int, w_min: float, floor_min: float = 1e-6,
                 arm_weight_threshold: float = 0.8):
        self.alpha = float(alpha)
        self.alternatives = tuple(float(v) for v in alternatives)
        if not self.alternatives:
            raise ValueError("at least one alternative is required")
        self.restoration_alternatives = tuple(float(v) for v in restoration_alternatives)
        if not self.restoration_alternatives:
            raise ValueError("at least one restoration alternative is required")
        if not 0.0 < w_min < 1.0:
            raise ValueError("w_min must lie in (0, 1)")
        if not 0.0 < arm_weight_threshold <= 1.0:
            raise ValueError("arm_weight_threshold must lie in (0, 1]")
        self.w_min = float(w_min)
        self.arm_weight_threshold = float(arm_weight_threshold)
        self.floor = FleetFloorEstimator(window_epochs=floor_window_epochs,
                                          min_floor=floor_min)
        self._states: Dict[int, _SublinkState] = {}

    def _state_for(self, sublink: int) -> _SublinkState:
        state = self._states.get(sublink)
        if state is None:
            state = _SublinkState(self.alternatives, self.restoration_alternatives,
                                   self.alpha)
            self._states[sublink] = state
        return state

    def tick(self, epoch: int,
             snapshots: Dict[int, Tuple[int, int]]) -> Dict[int, SublinkDecision]:
        """One epoch tick over every sublink reporting counts this epoch.

        `snapshots` maps sublink -> (tx, rx) for the epoch that just closed.
        """
        # Pass 1: read every floor from state as of the END of the PRIOR
        # tick, before this epoch's counts are recorded anywhere. This is
        # what makes the null previsible with respect to every sublink's
        # current-epoch outcome, not just the sublink it is judged for.
        floors = {sublink: self.floor.floor_for(sublink) for sublink in snapshots}

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

            if (weight <= self.arm_weight_threshold and not state.restoration.armed):
                suspect_rate = state.suspect_rate_estimate()
                if (suspect_rate is not None and
                        suspect_rate > max(self.restoration_alternatives)):
                    state.restoration.arm(suspect_rate)
                # otherwise: not enough prior evidence yet (or it isn't
                # clearly elevated) to arm safely -- wait for a later tick.

            restoring = state.restoration.armed
            if restoring:
                state.restoration.ingest(epoch=epoch, tx=tx, rx=rx,
                                         censored=censored_flags[sublink])
                if state.restoration.recovered:
                    state.restoration.disarm()
                    state.repair_generation += 1
                    state.cumulative_tx = 0
                    state.cumulative_lost = 0
                    weight = 1.0
                    restoring = False

            # Cumulative totals feed only the NEXT tick's arming decision, so
            # the epoch just processed is never used to arm and then test
            # itself in the same tick.
            state.cumulative_tx += tx
            state.cumulative_lost += tx - rx

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
