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

`controller/` does not import from `p4/hw/loop` (the reverse direction is
already established: `controller_loop.py` imports from `controller`), so this
module is deliberately transport-agnostic -- the caller turns whatever census
source it has into the `{sublink: (tx, rx)}` snapshot `tick()` expects.
"""

from dataclasses import dataclass
from typing import Dict, Sequence, Tuple

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


class _SublinkState:
    def __init__(self, alternatives: Sequence[float],
                 restoration_alternatives: Sequence[float], alpha: float):
        self.process = FleetAbsoluteEProcess(alpha=alpha, alternatives=alternatives)
        self.restoration = RestorationEProcess(
            alpha=alpha, healthy_alternatives=restoration_alternatives)
        self.repair_generation = 0
        self.last_weight = 1.0


class FleetDecisionLoop:
    def __init__(self, alpha: float, alternatives: Sequence[float],
                 restoration_alternatives: Sequence[float],
                 floor_window_epochs: int, w_min: float, floor_min: float = 1e-6):
        self.alpha = float(alpha)
        self.alternatives = tuple(alternatives)
        self.restoration_alternatives = tuple(restoration_alternatives)
        self.w_min = float(w_min)
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
        The healthy-pool membership fed to the floor estimator reflects each
        sublink's weight as of the *previous* tick, so a sublink's own
        current-epoch outcome never enters the floor used to judge it.
        """
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            self.floor.record_epoch(sublink, epoch=epoch, tx=tx, rx=rx,
                                     healthy=state.last_weight >= 1.0)

        wealths: Dict[int, float] = {}
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            floor = self.floor.floor_for(sublink)
            result = state.process.ingest(FleetEpochRecord(
                epoch=epoch, tx=tx, rx=rx, floor=floor,
                repair_generation=state.repair_generation))
            wealths[sublink] = result.wealth

        rejected = e_bh_reject(wealths, alpha=self.alpha)

        decisions: Dict[int, SublinkDecision] = {}
        for sublink, (tx, rx) in snapshots.items():
            state = self._state_for(sublink)
            weight = weight_from_wealth(wealths[sublink], self.w_min)

            if weight < 1.0 and not state.restoration.armed:
                suspect_rate = (1.0 - rx / tx) if tx > 0 else self.floor.floor_for(sublink)
                suspect_rate = min(max(suspect_rate, 1e-6), 1.0 - 1e-6)
                state.restoration.arm(suspect_rate)

            restoring = state.restoration.armed
            if restoring:
                state.restoration.ingest(epoch=epoch, tx=tx, rx=rx)
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
            )
        return decisions
