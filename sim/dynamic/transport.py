#!/usr/bin/env python3
"""Feedback-path delay for the dynamic behavioural-sublink experiment.

The C-W4 discontinuity is observed DOWNSTREAM, but the spray decision it has to change is made
UPSTREAM, so an event has to travel before anything can be quarantined. Production keeps landing
on the faulty sublink for the whole of that trip, which is why the delay is modelled explicitly
instead of being folded into the epoch boundary.

**No end-to-end downstream-C-W4-event to upstream-health-gate latency has ever been measured in
this project.** ``tau_us`` is therefore a swept PARAMETER, never a result, and every reference
value carries its provenance:

* ``0`` -- the instantaneous-feedback bound every earlier capacity number implicitly assumed
  (docs/review/CAPSULE-RESULT.md, HEALTH-GATE-RESULT.md). Not achievable; kept as the upper bound.
* ``100 us`` -- an unmeasured data-plane candidate, i.e. a design target for carrying the event in
  the fabric rather than through the controller. It is a hypothesis about a path that does not
  exist yet. (The measured 97.4 us F6 number is a same-switch congestion-attention reaction and is
  NOT this path; it must not be cited as if it were.)
* ``2200 us`` (2.20 ms) -- the repository's minimal one-slot controller reference: a single
  register read plus a single write, measured on the controller path (sim/sublink/feedback.py).
* ``106600 us`` (106.6 ms) -- the median of the existing full-sweep Python controller loop
  (sim/sublink/feedback.py). The pessimistic end of the sweep: the mechanism as it runs today.

The transport itself is deliberately trivial -- a monotone delay line with total, deterministic
ordering -- because the experiment's conclusions must depend on tau and on the controller state
machine, not on any queueing behaviour invented here.
"""

import heapq
from dataclasses import dataclass, field
from typing import Any, List, Tuple

# The tau values frozen in sim/dynamic/PREREG.md, in microseconds. Provenance above; none of them
# is a measurement of the path under test.
TAU_SWEEP_US: Tuple[int, ...] = (0, 100, 2200, 106600)


@dataclass(frozen=True, order=True)
class Delivery:
    """One in-flight item and the time it becomes visible to the receiver.

    ``seq`` is a per-delay-line monotonic counter. It exists so that ordering is TOTAL even when an
    arbitrary number of items share ``at_us``: comparison never reaches ``item`` (which may be of
    any type, and need not be orderable at all), so the delivery order of simultaneous items is the
    send order, deterministically, on every machine and every Python version. ``item`` is excluded
    from comparison for that reason; ``(at_us, seq)`` already identifies a delivery uniquely within
    its line.
    """

    at_us: int
    seq: int
    item: Any = field(compare=False)


class DelayLine:
    """A fixed-delay, order-preserving channel: an item sent at ``t`` is due at ``t + tau_us``.

    ``tau_us == 0`` is a real configuration (the instantaneous-feedback bound), so an item sent at
    ``t`` must be returned by ``due(t)`` in the same call, not one step later.
    """

    def __init__(self, tau_us: int) -> None:
        if tau_us < 0:
            raise ValueError("tau_us must be non-negative, got %r" % (tau_us,))
        self.tau_us: int = tau_us
        self._heap: List[Delivery] = []
        self._seq: int = 0

    def send(self, t_us: int, item: Any) -> None:
        """Hand ``item`` to the channel at ``t_us``; it becomes due at ``t_us + tau_us``."""
        delivery = Delivery(at_us=t_us + self.tau_us, seq=self._seq, item=item)
        self._seq += 1
        heapq.heappush(self._heap, delivery)

    def due(self, t_us: int) -> List[Any]:
        """Remove and return every item due at or before ``t_us``, in ``(at_us, seq)`` order.

        O(k log n) in the k items actually delivered: the heap is popped, never scanned or rebuilt,
        so polling a large in-flight population costs nothing when nothing is due.
        """
        delivered: List[Any] = []
        while self._heap and self._heap[0].at_us <= t_us:
            delivered.append(heapq.heappop(self._heap).item)
        return delivered

    def pending(self) -> int:
        """Items sent but not yet returned by ``due``."""
        return len(self._heap)
