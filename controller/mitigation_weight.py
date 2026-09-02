"""Continuous mitigation weight and its restoration counterpart
(`docs/review/BRAINSTORM-2026-09-01.md` C3).

The health gate's spray weight for a suspect sublink is a continuous function
of the primary absolute e-process's wealth, never a step at a threshold
crossing -- "a lone drop nudges a suspect sibling's share down slightly; only
sustained evidence reaches the floor weight", tightened by red-team finding 5:
the paper must never describe this as "the e-value crosses 1/alpha, therefore
quarantine". Restoration is "the same absolute test run the other way on the
residual share": once weight has dropped below one, a second e-process runs
on the traffic the link still receives, testing for evidence it now behaves
like the healthy floor rather than the degraded rate that justified the cut.
"""

from typing import Optional, Sequence

from controller.absolute_eprocess import (
    FleetAbsoluteEProcess,
    FleetEpochRecord,
    FleetEProcessResult,
)


def weight_from_wealth(wealth: float, w_min: float) -> float:
    """Continuous in wealth: constant at 1 for wealth <= 1 (sub-1 wealth is
    not evidence against the null), strictly decreasing on (1, inf), and
    w(inf) -> w_min."""
    if not 0.0 < w_min < 1.0:
        raise ValueError("w_min must lie in (0, 1)")
    if wealth < 0.0:
        raise ValueError("wealth must be non-negative")
    if wealth <= 1.0:
        return 1.0
    if wealth == float("inf"):
        return w_min
    return w_min + (1.0 - w_min) / wealth


class RestorationEProcess:
    """One independent restoration sequence, armed once mitigation begins."""

    def __init__(self, alpha: float, healthy_alternatives: Sequence[float]):
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must lie in (0, 1)")
        healthy_alternatives = tuple(float(v) for v in healthy_alternatives)
        if not healthy_alternatives:
            raise ValueError("at least one healthy alternative is required")
        self._alpha = alpha
        self._healthy_alternatives = healthy_alternatives
        self._inner: Optional[FleetAbsoluteEProcess] = None
        self._suspect_rate: Optional[float] = None
        self._recovered = False

    def arm(self, suspect_rate: float) -> None:
        """Start a fresh restoration sequence testing against `suspect_rate`.

        `suspect_rate` must exceed every healthy alternative -- otherwise
        every mixture component bets in the wrong direction and wealth
        decays monotonically forever, permanently preventing restoration
        (`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md`, CRITICAL 3).
        """
        if not 0.0 < suspect_rate < 1.0:
            raise ValueError("suspect_rate must lie in (0, 1)")
        if suspect_rate <= max(self._healthy_alternatives):
            raise ValueError(
                "suspect_rate must exceed every healthy alternative; "
                "otherwise restoration can never be reached")
        self._inner = FleetAbsoluteEProcess(alpha=self._alpha,
                                            alternatives=self._healthy_alternatives)
        self._suspect_rate = suspect_rate
        self._recovered = False

    @property
    def armed(self) -> bool:
        return self._inner is not None

    def disarm(self) -> None:
        self._inner = None
        self._suspect_rate = None
        self._recovered = False

    def ingest(self, epoch: int, tx: int, rx: int,
               censored: bool = False) -> FleetEProcessResult:
        if self._inner is None:
            raise RuntimeError("arm() must be called before ingest()")
        result = self._inner.ingest(FleetEpochRecord(
            epoch=epoch, tx=tx, rx=rx, floor=self._suspect_rate,
            censored=censored))
        self._recovered = result.alarmed
        return result

    @property
    def recovered(self) -> bool:
        return self._recovered
