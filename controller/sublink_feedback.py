"""P3 decision core and BFRT boundary for behavioural-sublink feedback.

The witness observes a gap at the downstream switch while the health gate is programmed at the
source.  This module starts *after* an attributed :class:`GapEvent` has arrived: it validates and
coalesces the event, applies the frozen inference layer, expands one directed sublink into the
exact P2 path keys, and writes or removes those entries.  It does not yet provide the event source,
event transport, or probation traffic needed for end-to-end P3.

The implemented state rules are:

* **Coalescing** — a fault produces a gap per discontinuity, not one event. Installing per gap
  would hammer the control plane and, worse, make the install rate a function of the fault rate.
  One install per (sublink, epoch) is the contract.
* **Epoch / reset** — every event carries the epoch it was observed in. An event from a previous
  epoch describes a fabric that no longer exists.
* **Stale feedback** — dropped by epoch, not by timestamp, so an old event cannot change a newer
  topology/configuration epoch.
* **Reorder credit** — the C-W4 witness manufactures loss out of pure reordering: a late packet
  moves ``expected`` backwards, so the next in-order arrival reports a discontinuity that never
  happened. After a resync a SMALL POSITIVE gap can only mean a packet previously counted missing
  has now arrived; real loss never produces one. Such an event is therefore a receipt that cancels
  one packet of previously reported loss on that sublink, not new evidence. Netting is done
  *within one epoch* against at most one held loss-bearing event, which fits the coalescing
  contract above and adds no cross-epoch latency (`docs/review/P3-DYNAMIC-RESULT.md`, rule 2).
* **Flapping** — a sublink that has been quarantined and restored repeatedly must not be allowed
  to oscillate at the loop's own frequency. Restoration requires sustained *observed* probation
  evidence and repeated quarantine increases that requirement. Silence is never health evidence.
* **Evidence-sized probation** — counting clean *rounds* discards the magnitude of the evidence and
  leaves the restoration criterion dimensionless: one round carries at most
  ``AUDIT_ROUND_MAX_TOKENS`` packets, so the frozen three-round rule certified a still-faulty 1e-3
  sublink 95.3 % of the time (measured, `docs/review/P3-DYNAMIC-RESULT.md`, rule 4). Restoration
  therefore also requires ``probation_packets_required(p_restore_target, restore_alpha)`` observed
  probation packets, damped by the same repeat-quarantine multiplier as the round count.

The decision itself is NOT re-invented here: evidence goes to `controller/infer.py`, the one frozen
inference layer every arm in this project shares (PREREG §3.3).
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from controller import infer

log = logging.getLogger("controller.sublink_feedback")

QUARANTINED, PROBATION, HEALTHY = "QUARANTINED", "PROBATION", "HEALTHY"
AUDIT_UDP_DST = 4792
AUDIT_ROUND_MAX_TOKENS = 16      # ``tbl_audit_steer`` capacity: the packets one round can declare
EPOCH_US = 100000                # the controller epoch the frozen layer is fed with
REORDER_CREDIT_MAX = 16          # gaps in 1..this are reorder receipts, never loss


def probation_packets_required(p_target: float, alpha: float) -> int:
    """Clean packets needed to exclude a per-packet loss rate ``p_target`` at confidence 1-alpha.

    ``N`` consecutive clean packets on a link that really loses at ``p_target`` happen with
    probability ``(1 - p_target) ** N``; requiring that to fall below ``alpha`` gives
    ``N >= log(alpha) / log(1 - p_target)``.  This is what makes restoration a statement about
    evidence rather than about how many times a timer fired.
    """
    if not 0.0 < p_target < 1.0:
        raise ValueError("p_restore_target must be a probability in (0, 1)")
    if not 0.0 < alpha < 1.0:
        raise ValueError("restore_alpha must be a probability in (0, 1)")
    return int(math.ceil(math.log(alpha) / math.log(1.0 - p_target)))


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


@dataclass(frozen=True)
class AuditReceipt:
    """One downstream receipt for a controller-declared audit packet.

    ``token`` is the packet's UDP source port.  The controller installs that exact token in
    ``tbl_audit_steer`` before sending the packet, so a receipt can be matched to a finite send
    set.  ``witness_seq`` is retained for diagnostics and duplicate forensics; it is not treated
    as a controller-known nonce.  A non-zero ``gap`` makes the receipt explicit negative evidence.
    """
    vlink: int
    context: int
    epoch: int
    token: int
    witness_seq: int
    gap: int = 0

    @property
    def sublink(self) -> int:
        return (self.vlink << 4) | self.context


@dataclass(frozen=True)
class AuditResult:
    """Closed audit-round evidence; suitable for the run manifest and paper metrics."""
    vlink: int
    context: int
    epoch: int
    status: str
    sent: int
    received: int
    missing: Tuple[int, ...]
    gap_tokens: Tuple[int, ...]
    invalid_receipts: int
    duplicate_receipts: int


@dataclass
class AuditRound:
    """Match positive receipts against one declared, bounded probation send set.

    This object is deliberately independent of packet injection and timers.  The runtime creates
    a round, installs/sends every ``expected_token``, feeds receipts until its deadline, and calls
    :meth:`finish`.  Only a complete set of same-sublink, same-epoch, gap-free receipts advances
    restoration.  Therefore silence has meaning only relative to packets the runtime says it sent.
    """
    vlink: int
    context: int
    epoch: int
    expected_tokens: Tuple[int, ...]
    receipts: Dict[int, AuditReceipt] = field(default_factory=dict, init=False)
    invalid_receipts: int = field(default=0, init=False)
    duplicate_receipts: int = field(default=0, init=False)
    _result: Optional[AuditResult] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.expected_tokens = tuple(self.expected_tokens)
        if not self.expected_tokens:
            raise ValueError("an audit round requires at least one declared token")
        if len(self.expected_tokens) > AUDIT_ROUND_MAX_TOKENS:
            raise ValueError("an audit round cannot exceed the %d-entry P4 steering table"
                             % AUDIT_ROUND_MAX_TOKENS)
        if len(set(self.expected_tokens)) != len(self.expected_tokens):
            raise ValueError("audit tokens must be unique within a round")
        if not 0 <= self.context < 16:
            raise ValueError("context must fit the four-bit capsule")
        if not 0 <= self.vlink < 16:
            raise ValueError("vlink must fit the configured 4x2 fabric")
        if any(not 0 <= token <= 0xFFFF for token in self.expected_tokens):
            raise ValueError("audit tokens must fit a UDP source port")

    @property
    def sublink(self) -> int:
        return (self.vlink << 4) | self.context

    def accept(self, receipt: AuditReceipt) -> bool:
        """Accept one exact receipt; reject stale, foreign, undeclared, and duplicate copies."""
        if self._result is not None:
            return False
        if (receipt.sublink != self.sublink or receipt.epoch != self.epoch or
                receipt.token not in self.expected_tokens):
            self.invalid_receipts += 1
            return False
        if receipt.token in self.receipts:
            self.duplicate_receipts += 1
            return False
        self.receipts[receipt.token] = receipt
        return True

    def finish(self, feedback: "SublinkFeedback") -> AuditResult:
        """Close the round once; only complete, current, gap-free evidence can advance health."""
        if self._result is not None:
            return self._result
        missing = tuple(token for token in self.expected_tokens if token not in self.receipts)
        gap_tokens = tuple(token for token in self.expected_tokens
                           if token in self.receipts and self.receipts[token].gap != 0)
        if feedback.current_epoch != self.epoch:
            status = "STALE"
        elif missing:
            status = "INCOMPLETE"
        elif gap_tokens:
            status = "LOSS"
        else:
            status = feedback.on_clean_epoch(
                self.vlink, self.context, observed_packets=len(self.receipts)) or "CLEAN"
        self._result = AuditResult(
            vlink=self.vlink, context=self.context, epoch=self.epoch, status=status,
            sent=len(self.expected_tokens), received=len(self.receipts), missing=missing,
            gap_tokens=gap_tokens, invalid_receipts=self.invalid_receipts,
            duplicate_receipts=self.duplicate_receipts)
        return self._result


@dataclass
class HeldGap:
    """One loss-bearing gap event held back for within-epoch reorder netting.

    It is held, never dropped: ``lost`` is the running net loss after credits, and the event is
    delivered to the frozen layer as soon as it is displaced or the epoch ends.
    """
    event: GapEvent
    lost: int


@dataclass
class SublinkState:
    state: str = HEALTHY
    epoch_installed: int = -1
    quarantines: int = 0            # for damping: a sublink that keeps failing is held longer
    clean_epochs: int = 0
    clean_packets: int = 0          # accumulated observed probation evidence, not round count
    gate_keys: Tuple[Tuple[int, int, int, int], ...] = ()


def gate_keys_for_sublink(vlink: int, context: int,
                          n_leaf: int = 4, n_spine: int = 2
                          ) -> Tuple[Tuple[int, int, int, int], ...]:
    """Map one directed physical sublink to every exact P2 health-gate key it affects.

    The P2 table is path-keyed, while C-W4 evidence is link-keyed.  An uplink failure affects every
    destination reached from one ``(source, spray)``; a downlink failure affects every source that
    reaches one ``(spray, destination)``.  Enumerating the small fixed topology here prevents the
    controller from protecting only the first path that happened to expose the fault.
    """
    if not 0 <= context < 16:
        raise ValueError("context must fit the four-bit capsule")
    n_uplink = n_leaf * n_spine
    n_vlink = n_uplink * 2
    if not 0 <= vlink < n_vlink:
        raise ValueError("vlink %d is outside the %dx%d fabric" % (vlink, n_leaf, n_spine))
    if vlink < n_uplink:
        src_leaf, spray = divmod(vlink, n_spine)
        return tuple((src_leaf, dst_leaf, spray, context) for dst_leaf in range(n_leaf))
    spray, dst_leaf = divmod(vlink - n_uplink, n_leaf)
    return tuple((src_leaf, dst_leaf, spray, context) for src_leaf in range(n_leaf))


class BfrtHealthGate:
    """Narrow BFRT writer for the P2 behavioural-health table.

    The client connection and target are owned by the existing hardware adapter; this object owns
    only the exact table schema and its add/modify/delete behavior.  Keeping that boundary small
    lets the controller path be tested offline without pretending a switch connection exists.
    """

    def __init__(self, gc, bfrt, target) -> None:
        self.gc = gc
        self.target = target
        self.table = bfrt.table_get("pipe.Ingress.tbl_health_gate")

    def _key(self, src_leaf: int, dst_leaf: int, spray: int, context: int):
        return self.table.make_key([
            self.gc.KeyTuple("md.src_leaf", src_leaf),
            self.gc.KeyTuple("md.dst_leaf", dst_leaf),
            self.gc.KeyTuple("md.spray_idx", spray),
            self.gc.KeyTuple("md.ctx", context),
        ])

    def install(self, src_leaf: int, dst_leaf: int, spray: int,
                context: int, alt_spray: int) -> None:
        key = self._key(src_leaf, dst_leaf, spray, context)
        data = self.table.make_data(
            [self.gc.DataTuple("alt_spray", alt_spray)], "Ingress.sublink_reroute")
        try:
            self.table.entry_add(self.target, [key], [data])
        except self.gc.BfruntimeRpcException:
            self.table.entry_mod(self.target, [key], [data])

    def remove(self, src_leaf: int, dst_leaf: int, spray: int, context: int) -> None:
        self.table.entry_del(self.target, [self._key(src_leaf, dst_leaf, spray, context)])


class BfrtAuditSteer:
    """Exact BFRT writer for the 16-entry declared-audit steering table."""

    def __init__(self, gc, bfrt, target) -> None:
        self.gc = gc
        self.target = target
        self.table = bfrt.table_get("pipe.Ingress.tbl_audit_steer")

    def _key(self, token: int):
        return self.table.make_key([
            self.gc.KeyTuple("hdr.udp.dst_port", AUDIT_UDP_DST),
            self.gc.KeyTuple("hdr.udp.src_port", token),
        ])

    def install(self, token: int, spray: int) -> None:
        if not 0 <= token <= 0xFFFF:
            raise ValueError("audit token must fit a UDP source port")
        if spray not in (0, 1):
            raise ValueError("audit spray must name one of the configured two spines")
        key = self._key(token)
        data = self.table.make_data(
            [self.gc.DataTuple("spray", spray)], "Ingress.set_audit_spray")
        try:
            self.table.entry_add(self.target, [key], [data])
        except self.gc.BfruntimeRpcException:
            self.table.entry_mod(self.target, [key], [data])

    def remove(self, token: int) -> None:
        if not 0 <= token <= 0xFFFF:
            raise ValueError("audit token must fit a UDP source port")
        self.table.entry_del(self.target, [self._key(token)])


class SublinkFeedback:
    """Consumes gap events, decides per behavioural sublink, and installs/removes gate entries.

    `install` and `remove` are injected so this is testable without a switch and so the same logic
    drives the bfrt adapter, the simulator, and the model.
    """

    def __init__(self, install: Callable[[int, int, int, int, int], None],
                 remove: Callable[[int, int, int, int], None],
                 h: float = infer.H_DEFAULT,
                 clean_epochs_to_restore: int = 3,
                 alt_spray_for: Optional[Callable[[int, int, int, int], int]] = None,
                 reorder_credit_max: int = REORDER_CREDIT_MAX,
                 p_restore_target: float = 1e-3,
                 restore_alpha: float = 0.05):
        self.install, self.remove, self.h = install, remove, h
        self.clean_epochs_to_restore = clean_epochs_to_restore
        self.alt_spray_for = alt_spray_for or (lambda src, dst, spray, ctx: 1 - spray)
        self.reorder_credit_max = reorder_credit_max
        self.p_restore_target = p_restore_target
        self.restore_alpha = restore_alpha
        # The per-quarantine evidence budget, derived once: restoration is priced in packets.
        self.probation_packets = probation_packets_required(p_restore_target, restore_alpha)
        self.state: Dict[int, SublinkState] = {}
        # At most one loss-bearing event per sublink, held only within its own epoch so that a
        # reorder receipt arriving right behind it can cancel the loss it never suffered.
        self.held: Dict[int, HeldGap] = {}
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
        self.reorder_credits = 0     # credit events that cancelled one packet of reported loss
        self.netted_out = 0          # held events whose net loss reached zero: no evidence at all

    # ---- epoch handling ---------------------------------------------------------
    def begin_epoch(self, epoch: int) -> None:
        """Close the previous epoch.  Nothing is ever held across an epoch boundary.

        A sublink that emits one loss event and then falls silent -- exactly what a link failing to
        a blackhole looks like -- would otherwise hold its only evidence forever.
        """
        self.flush_held()
        self.current_epoch = epoch

    def flush_held(self) -> List[str]:
        """Deliver every held event to the frozen layer; returns the actions actually taken."""
        actions = []
        for sublink in sorted(self.held):
            action = self._release(sublink)
            if action is not None:
                actions.append(action)
        return actions

    def _st(self, sublink: int) -> SublinkState:
        return self.state.setdefault(sublink, SublinkState())

    # ---- the event path ---------------------------------------------------------
    def is_reorder_credit(self, ev: GapEvent) -> bool:
        """A small POSITIVE gap after a resync: a packet counted missing has arrived."""
        return 0 < ev.gap <= self.reorder_credit_max

    def on_gap(self, ev: GapEvent) -> Optional[str]:
        """-> the action taken by this call, or None. Stale and coalesced events return None.

        A loss-bearing event is not decided on immediately: it is HELD until a following event on
        the same sublink in the same epoch either cancels a packet of it (a reorder credit) or
        displaces it, or until the epoch ends.  The action reported here may therefore belong to
        the event this call displaced rather than to ``ev`` itself.
        """
        if ev.epoch < self.current_epoch:
            # STALE: this describes a fabric that has already moved on. Dropping by epoch rather
            # than by wall clock is what makes the rule independent of the loop's own latency.
            self.stale_dropped += 1
            log.debug("stale gap on sublink %d from epoch %d (now %d)",
                      ev.sublink, ev.epoch, self.current_epoch)
            return None

        if self.is_reorder_credit(ev):
            return self._credit(ev)

        released = self._release(ev.sublink)   # any non-credit event displaces the held one
        st = self._st(ev.sublink)
        if st.state == QUARANTINED and st.epoch_installed == ev.epoch:
            self.coalesced += 1          # already acted on this sublink this epoch
            return released
        if ev.lost > 0:
            self.held[ev.sublink] = HeldGap(event=ev, lost=ev.lost)
            return released
        return self._decide(ev, ev.lost) or released

    def _credit(self, ev: GapEvent) -> Optional[str]:
        """Cancel one packet of held loss on this sublink; a credit is never loss evidence."""
        held = self.held.get(ev.sublink)
        if held is not None and held.event.epoch == ev.epoch:
            held.lost -= 1
            self.reorder_credits += 1
            if held.lost <= 0:
                del self.held[ev.sublink]
                self.netted_out += 1     # no net loss: no evidence, and therefore no decision
                log.debug("reorder netted out on sublink %d in epoch %d", ev.sublink, ev.epoch)
        # The receipt still witnesses arrivals, which belong in the shared pool exactly as they
        # did before netting existed; it can never quarantine, because it carries no loss.
        self.observe_clean(ev.vlink, ev.context, ev.observed_packets, ev.epoch)
        return None

    def _release(self, sublink: int) -> Optional[str]:
        """Deliver the event held for one sublink, at its netted loss."""
        held = self.held.pop(sublink, None)
        if held is None:
            return None
        return self._decide(held.event, held.lost)

    def _decide(self, ev: GapEvent, lost: int) -> Optional[str]:
        """Feed one event at its NETTED loss to the frozen layer and act on the verdict."""
        st = self._st(ev.sublink)
        self.infer_state = infer.update(
            self.infer_state,
            [infer.Sample(element="sublink:%d" % ev.sublink,
                          # ``observed_packets`` counts packets that arrived. The modular gap
                          # separately counts missing packets; subtracting it here would count the
                          # same loss twice and inflate the estimated loss rate.
                          delivered=ev.observed_packets,
                          lost=lost, latency_us=(), t_us=ev.epoch * EPOCH_US)],
            {}, baseline_mode="pooled")
        loc = infer.localize(self.infer_state, k=1, h=self.h)
        if not (loc.anomaly and loc.suspects and
                loc.suspects[0] == "sublink:%d" % ev.sublink):
            return None

        st.state = QUARANTINED
        st.epoch_installed = ev.epoch
        st.quarantines += 1
        st.clean_epochs = 0
        st.clean_packets = 0
        st.gate_keys = gate_keys_for_sublink(ev.vlink, ev.context)
        self.installs += 1
        for src_leaf, dst_leaf, spray, context in st.gate_keys:
            alt_spray = self.alt_spray_for(src_leaf, dst_leaf, spray, context)
            self.install(src_leaf, dst_leaf, spray, context, alt_spray)
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
                          delivered=packets, lost=0, latency_us=(), t_us=epoch * EPOCH_US)],
            {}, baseline_mode="pooled")

    def probation_packets_needed(self, vlink: int, context: int) -> int:
        """The packet budget this particular sublink must show, after flap damping."""
        st = self._st((vlink << 4) | context)
        return self.probation_packets * max(1, st.quarantines)

    def probation_budget(self, quarantines: int = 1) -> Dict[str, float]:
        """What one certification costs, in the three units the paper reports.

        Rounds are bounded by the 16-entry ``tbl_audit_steer``, and one round closes per epoch.
        Every number here is derived from the configured target, never asserted.
        """
        packets = self.probation_packets * max(1, quarantines)
        rounds = -(-packets // AUDIT_ROUND_MAX_TOKENS)     # ceil, integer arithmetic
        return {"p_target": self.p_restore_target, "alpha": self.restore_alpha,
                "packets": packets, "packets_per_round": AUDIT_ROUND_MAX_TOKENS,
                "rounds": rounds, "seconds": rounds * EPOCH_US / 1e6}

    def on_clean_epoch(self, vlink: int, context: int,
                       observed_packets: int = 0) -> Optional[str]:
        """Record one explicitly observed clean probation/audit epoch.

        A quarantined primary carries no production, so merely reaching the end of an epoch without
        a gap is not evidence of health.  The caller must supply a positive packet count obtained by
        deliberately exercising the original sublink.  Restoration then needs sustained evidence:
        both a sustained number of clean rounds AND enough accumulated clean packets to exclude
        ``p_restore_target`` at ``restore_alpha``.  Both requirements grow with the number of
        previous quarantines.  Counting rounds alone would make the criterion dimensionless -- one
        round carries at most sixteen packets, so three of them exclude nothing.
        """
        sublink = (vlink << 4) | context
        st = self._st(sublink)
        if st.state != QUARANTINED:
            return None
        if observed_packets <= 0:
            return None
        self.observe_clean(vlink, context, observed_packets, self.current_epoch)
        st.clean_epochs += 1
        st.clean_packets += observed_packets
        damping = max(1, st.quarantines)
        needed = self.clean_epochs_to_restore * damping
        needed_packets = self.probation_packets * damping
        if st.clean_epochs < needed or st.clean_packets < needed_packets:
            return None
        observed = st.clean_packets
        st.state = HEALTHY
        st.clean_epochs = 0
        st.clean_packets = 0
        for key in st.gate_keys:
            self.remove(*key)
        st.gate_keys = ()
        log.info("restored sublink vlink=%d ctx=%d after %d clean rounds and %d observed packets "
                 "(budget %d, excludes p=%g at alpha=%g)",
                 vlink, context, needed, observed, needed_packets,
                 self.p_restore_target, self.restore_alpha)
        return "RESTORE"

    # ---- reporting --------------------------------------------------------------
    def summary(self) -> Dict[str, int]:
        return {"installs": self.installs, "coalesced": self.coalesced,
                "stale_dropped": self.stale_dropped,
                "reorder_credits": self.reorder_credits,
                "netted_out": self.netted_out,
                "held": len(self.held),
                "probation_packets": self.probation_packets,
                "quarantined": sum(1 for s in self.state.values() if s.state == QUARANTINED)}
