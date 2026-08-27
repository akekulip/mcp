"""Shared record types for the controller (observation side only, no ground truth)."""
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class Sample:
    """One measurement record produced by an arm's sample adapter (PREREG section 3.3, item 1).

    Attributes:
        element: Element id, e.g. ``"vlink:3"``, ``"path:2"``, ``"spine:1"``, ``"nic:0"``.
        delivered: Count of delivered probes/packets attributed to the element.
        lost: Count lost.
        latency_us: Latency samples in microseconds (may be empty).
        t_us: Epoch/sample timestamp in microseconds (switch or sim clock).
    """

    element: str
    delivered: int
    lost: int
    latency_us: tuple
    t_us: int


@dataclass(frozen=True)
class Observation:
    """Everything the slow-loop reward may see for one epoch (PREREG section 7.1).

    All fields derive from received samples, the common localizer state and measured resource
    consumption. There is deliberately no fault / label / oracle field.

    Attributes:
        epoch: Epoch index ``t``.
        sigma2_prev: Per-path posterior variance of the loss estimate at ``t-1``.
        sigma2: Per-path posterior variance of the loss estimate at ``t``.
        cusum: Per-path CUSUM statistic ``C_p(t)`` against the path's own running baseline.
        usage: Measured consumption ``c_r(t)`` per resource ``r`` (bytes counted, reads
            issued, CPU sampled), in the unit of the corresponding cap.
        caps: Cap ``B_r`` per resource, same unit as ``usage``.
    """

    epoch: int
    sigma2_prev: Dict[str, float]
    sigma2: Dict[str, float]
    cusum: Dict[str, float]
    usage: Dict[str, float]
    caps: Dict[str, float]


__all__: Tuple[str, ...] = ("Sample", "Observation")
