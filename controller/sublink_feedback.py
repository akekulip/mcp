"""sublink_feedback.py — P3 mechanism: carry a downstream C-W4 event to the source selector.

The witness raises a gap at the DOWNSTREAM switch; the spray choice that would avoid the faulty
sublink is made UPSTREAM. Something has to carry the event back, and `docs/review/P3-FEEDBACK-
RESULT.md` measures what the delay costs: at a 1e-2 fault the 107 ms controller round trip is
99.7 % of the exposure, while at 1e-5 it is a third of it. This is the controller path the plan
asks for first; whether the data-plane fast path is also built is decided by that measurement, not
by preference.

Four things the plan requires, and the reason each is here rather than "later":

* **Coalescing** — a fault produces a gap per discontinuity, not one event. Installing per gap
  would hammer the control plane and, worse, make the install rate a function of the fault rate.
  One install per (sublink, epoch) is the contract.
* **Epoch / reset** — every event carries the epoch it was observed in. An event from a previous
  epoch describes a fabric that no longer exists.
* **Stale feedback** — dropped by epoch, not by timestamp. This is what stops a slow loop
  quarantining a context that has already recovered (95 false quarantines at a 20 ms flap period
  in the measurement above).
* **Flapping** — a sublink that has been quarantined and restored repeatedly must not be allowed
  to oscillate at the loop's own frequency, so restoration requires sustained clean evidence and
  re-quarantine is progressively damped.

The decision itself is NOT re-invented here: evidence goes to `controller/infer.py`, the one frozen
inference layer every arm in this project shares (PREREG §3.3).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from controller import infer

log = logging.getLogger("controller.sublink_feedback")

QUARANTINED, PROBATION, HEALTHY = "QUARANTINED", "PROBATION", "HEALTHY"


@dataclass(frozen=True)
class GapEvent:
    """One downstream C-W4 discontinuity, attributed to a behavioural sublink."""
    vlink: int
    context: int
    epoch: int
    gap: int                 # expected - observed, modulo 2^16: large => loss, small => reorder
    observed_packets: int

    @property
    def sublink(self) -> int:
        return (self.vlink << 4) | self.context

    @property
    def lost(self) -> int:
        """A gap of g means 2^16 - g packets vanished; a small positive g is a duplicate/reorder."""
        return (1 << 16) - self.gap if self.gap > (1 << 15) else 0


@dataclass
class SublinkState:
    state: str = HEALTHY
    epoch_installed: int = -1
    quarantines: int = 0            # for damping: a sublink that keeps failing is held longer
    clean_epochs: int = 0


class SublinkFeedback:
    """Consumes gap events, decides per behavioural sublink, and installs/removes gate entries.

    `install` and `remove` are injected so this is testable without a switch and so the same logic
    drives the bfrt adapter, the simulator, and the model.
    """

    def __init__(self, install: Callable[[int, int, int], None],
                 remove: Callable[[int, int], None],
                 h: float = infer.H_DEFAULT,
                 clean_epochs_to_restore: int = 3,
                 alt_spray_for: Optional[Callable[[int, int], int]] = None):
        self.install, self.remove, self.h = install, remove, h
        self.clean_epochs_to_restore = clean_epochs_to_restore
        self.alt_spray_for = alt_spray_for or (lambda vlink, ctx: 1)
        self.state: Dict[int, SublinkState] = {}
        # ONE shared inference state across every sublink, not one per sublink. The frozen layer
        # uses a POOLED baseline, so a per-sublink state would compare each sublink only against
        # itself -- the baseline becomes the observation and nothing can ever alarm (caught by the
        # first smoke test). Sharing it makes the pool the fabric, so sibling sublinks carrying
        # production supply the background rate for free, which is the same property witness-stop
        # relies on.
        self.infer_state = infer.InferState()
        self.current_epoch = 0
        self.stale_dropped = 0
        self.coalesced = 0
        self.installs = 0

    # ---- epoch handling ---------------------------------------------------------
    def begin_epoch(self, epoch: int) -> None:
        self.current_epoch = epoch

    def _st(self, sublink: int) -> SublinkState:
        return self.state.setdefault(sublink, SublinkState())

    # ---- the event path ---------------------------------------------------------
    def on_gap(self, ev: GapEvent) -> Optional[str]:
        """-> the action taken, or None. Stale and coalesced events return None by design."""
        if ev.epoch < self.current_epoch:
            # STALE: this describes a fabric that has already moved on. Dropping by epoch rather
            # than by wall clock is what makes the rule independent of the loop's own latency.
            self.stale_dropped += 1
            log.debug("stale gap on sublink %d from epoch %d (now %d)",
                      ev.sublink, ev.epoch, self.current_epoch)
            return None

        st = self._st(ev.sublink)
        if st.state == QUARANTINED and st.epoch_installed == ev.epoch:
            self.coalesced += 1          # already acted on this sublink this epoch
            return None

        self.infer_state = infer.update(
            self.infer_state,
            [infer.Sample(element="sublink:%d" % ev.sublink,
                          delivered=max(ev.observed_packets - ev.lost, 0),
                          lost=ev.lost, latency_us=(), t_us=ev.epoch * 100000)],
            {}, baseline_mode="pooled")
        loc = infer.localize(self.infer_state, k=1, h=self.h)
        if not (loc.anomaly and loc.suspects and
                loc.suspects[0] == "sublink:%d" % ev.sublink):
            return None

        st.state = QUARANTINED
        st.epoch_installed = ev.epoch
        st.quarantines += 1
        st.clean_epochs = 0
        self.installs += 1
        self.install(ev.vlink, ev.context, self.alt_spray_for(ev.vlink, ev.context))
        log.info("quarantined sublink vlink=%d ctx=%d at epoch %d (quarantine #%d)",
                 ev.vlink, ev.context, ev.epoch, st.quarantines)
        return "QUARANTINE"

    def observe_clean(self, vlink: int, context: int, packets: int, epoch: int) -> None:
        """Feed a clean observation of a sibling sublink into the SHARED pool.

        This is what gives the decision a background rate it did not have to assume: the other
        behavioural sublinks are carrying production right now, and the same witness sees them.
        """
        self.infer_state = infer.update(
            self.infer_state,
            [infer.Sample(element="sublink:%d" % ((vlink << 4) | context),
                          delivered=packets, lost=0, latency_us=(), t_us=epoch * 100000)],
            {}, baseline_mode="pooled")

    def on_clean_epoch(self, vlink: int, context: int) -> Optional[str]:
        """A quarantined sublink that has gone a whole epoch without a gap.

        Restoration needs SUSTAINED evidence, and the requirement grows with the number of previous
        quarantines: a sublink that has failed repeatedly is damped rather than flapped, which is
        the failure the 20 ms flap-period measurement exposes.
        """
        sublink = (vlink << 4) | context
        st = self._st(sublink)
        if st.state != QUARANTINED:
            return None
        st.clean_epochs += 1
        needed = self.clean_epochs_to_restore * max(1, st.quarantines)
        if st.clean_epochs < needed:
            return None
        st.state = HEALTHY
        st.clean_epochs = 0
        self.remove(vlink, context)
        log.info("restored sublink vlink=%d ctx=%d after %d clean epochs", vlink, context, needed)
        return "RESTORE"

    # ---- reporting --------------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        return {"installs": self.installs, "coalesced": self.coalesced,
                "stale_dropped": self.stale_dropped,
                "quarantined": sum(1 for s in self.state.values() if s.state == QUARANTINED)}
