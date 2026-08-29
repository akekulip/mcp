#!/usr/bin/env python3
"""Drive the REAL feedback state machine over time — the dynamic operating point.

This is the *controller* half of `sim/dynamic/PREREG.md`, and it closes audit gap #6 of
`docs/review/P2-P3-INDEPENDENT-AUDIT.md`: until now specificity, false quarantine, unsafe
exposure, restoration and flap behaviour were arguments about a state machine rather than
measurements of one.

**Nothing here re-implements a decision.**  Every quarantine and every restoration in the
`cw4_feedback` and `directed_w4` arms comes out of `controller.sublink_feedback.SublinkFeedback`
and, through it, the frozen `controller/infer.py`.  This module supplies only the three things the
controller does not own — a clock, a transport, and probation traffic — and then records what the
real object did.  Where the real object makes something awkward, the awkwardness is measured and
reported, never smoothed:

* **Events that arrive after the epoch turns are dropped as STALE.**  `on_gap` drops by epoch, not
  by wall clock, so at `tau_feedback = 106.6 ms` (the repository's measured full-sweep controller
  loop) every event lands in the following epoch and is discarded.  The mechanism does not degrade
  at that tau; it stops entirely.  That is reported as `stale_dropped`, not engineered around.
* **Audit rounds close STALE for the same reason.**  `AuditRound.finish` compares the round's epoch
  against `feedback.current_epoch`, so a probation round whose receipts need longer than one epoch
  to come back can never advance restoration.  The four audit outcomes are counted per run
  (`audit_clean`, `audit_loss`, `audit_incomplete`, `audit_stale`) and printed, because
  "restoration never happened" and "restoration was never given the chance" are different findings
  and a single restore-rate column cannot tell them apart.
* **Probation is a small sample.**  A round is `audit_tokens` packets wide.  At a fault rate of
  1e-3 an 8-token round survives intact 99.2 % of the time, so the real state machine restores a
  sublink that is still faulty.  Those are counted as `unsafe_restorations` against the fabric's
  own `p_eff`, next to the restore rate, per the repo rule that a safety number and a usefulness
  number share a row.

Quarantine is measured at the **effective gate** (the keys actually present in the fabric), not at
the controller's internal state.  That is the only definition that compares the four arms on equal
terms: `oracle` has no controller state at all, and `directed_w4` gates sublinks the controller
still believes are healthy — scoring it off `SublinkFeedback.state` would have credited it with
zero false quarantines while it diverted three sibling contexts.

Two simplifications are deliberate and are named so they are not mistaken for results.  Clean
sibling observations feed the pooled baseline without transport delay (only the decision-bearing
gap events traverse the delay line); and the faulty sublink is drawn per seed with
`scenario_seed`, never with Python's salted `hash`.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple

from controller.sublink_feedback import (
    QUARANTINED,
    AuditReceipt,
    AuditResult,
    AuditRound,
    SublinkFeedback,
    gate_keys_for_sublink,
)
from sim.dynamic.fabric import (
    EPOCH_US,
    PKT_PER_LINK_EPOCH,
    WITNESS_MODES,
    Fabric,
    FaultSpec,
)
from sim.dynamic.metrics import RunRecord
from sim.dynamic.transport import DelayLine
from sim.gate.replay import scenario_seed

ARMS: Tuple[str, ...] = ("none", "cw4_feedback", "directed_w4", "oracle")

SCENARIOS: Tuple[str, ...] = (
    "persistent_partial", "repaired", "intermittent", "reorder_only",
    "wrap", "selective_blackhole", "all_context_blackhole", "no_fault",
)

#: Scenarios that inject a LOSS fault, i.e. the ones the oracle floor (PREREG tripwire 1) applies
#: to.  ``reorder_only`` injects a perturbation but no loss, and PREREG decision rule 2 requires
#: zero quarantines there, so an oracle that fired on it would itself be the bug.
FAULT_SCENARIOS: Tuple[str, ...] = (
    "persistent_partial", "repaired", "intermittent",
    "selective_blackhole", "all_context_blackhole",
)


class HarnessError(AssertionError):
    """A tripwire fired: the measurement apparatus is broken, so no result may be reported.

    Derived from ``AssertionError`` because that is what it is — the H29/H32 lesson written down.
    An upper-bound arm that cannot find an answer it was handed means the harness never injected
    the fault, or never delivered it to the arm, and every other number in the sweep is then a
    statement about the harness.
    """


#: The share vector every result before 2026-08-29 was measured under: four contexts, a uniform
#: quarter each.  It is the DEFAULT and not a law of the fabric.  HURDLES H37: the headline
#: "7x less collateral than directed quarantine" decomposes into 1/0.25 = 4.00x that follows from
#: this vector alone plus a 1.75x residual, and until the vector was a parameter that decomposition
#: could not be produced at all.  Keeping the default byte-identical is what makes every earlier
#: number reproducible; making it settable is what makes the claim falsifiable.
UNIFORM_QUARTER: Tuple[float, ...] = (0.25, 0.25, 0.25, 0.25)

#: The share vector must sum to the whole link.  A vector that sums to less would silently model an
#: under-loaded link, and every collateral ratio computed on it would be a statement about the
#: missing load rather than about the mechanism.
SHARE_SUM_TOL = 1e-9


@dataclass(frozen=True)
class RunConfig:
    """One point of the frozen sweep: `sim/dynamic/PREREG.md` "Frozen sweep"."""

    scenario: str
    arm: str
    tau_feedback_us: int
    tau_write_us: int
    h: float
    clean_epochs_to_restore: int
    p_fault: float
    p_bg: float = 1e-6
    epochs: int = 60
    seed: int = 0
    audit_tokens: int = 8
    onset_epoch: int = 10
    #: Which compiled witness the fabric emulates.  Defaulting to ``baseline`` keeps every
    #: previously reported number reproducible by re-running the same config.
    witness_mode: str = "baseline"
    #: How the link's traffic splits across the compiled behavioural contexts, and how many there
    #: are.  Swept by `sim/dynamic/share_sweep.py`; see ``UNIFORM_QUARTER`` above for why the
    #: default must stay exactly what it is.
    n_context: int = 4
    context_share: Tuple[float, ...] = UNIFORM_QUARTER

    def __post_init__(self) -> None:
        if self.scenario not in SCENARIOS:
            raise ValueError("unknown scenario %r; frozen set is %s" % (self.scenario, SCENARIOS))
        if self.arm not in ARMS:
            raise ValueError("unknown arm %r; frozen set is %s" % (self.arm, ARMS))
        if self.witness_mode not in WITNESS_MODES:
            raise ValueError("unknown witness_mode %r; supported modes are %s"
                             % (self.witness_mode, WITNESS_MODES))
        if self.epochs <= self.onset_epoch:
            raise ValueError("a run must outlast its own fault onset")
        if not 1 <= self.audit_tokens <= 16:
            raise ValueError("audit tokens must fit the 16-entry P4 steering table")
        # ``md.sublink = (vlink << 4) | context``, so the context index is four bits wide in the
        # compiled data plane; a harness that swept past 16 would be describing silicon that does
        # not exist.
        if not 1 <= self.n_context <= 16:
            raise ValueError("n_context must fit the four-bit capsule, got %r" % (self.n_context,))
        if len(self.context_share) != self.n_context:
            raise ValueError("context_share has %d entries for %d contexts"
                             % (len(self.context_share), self.n_context))
        if any(not 0.0 <= s <= 1.0 for s in self.context_share):
            raise ValueError("every context share must be a fraction, got %r"
                             % (self.context_share,))
        if abs(sum(self.context_share) - 1.0) > SHARE_SUM_TOL:
            raise ValueError("context_share must sum to 1.0, got %r summing to %r"
                             % (self.context_share, sum(self.context_share)))


class CellKey(NamedTuple):
    """Identifies one cell of the sweep; used as the key of the reporting table."""

    scenario: str
    arm: str
    tau_feedback_us: int
    tau_write_us: int
    h: float
    clean_epochs_to_restore: int
    p_fault: float
    #: Part of the KEY, not a footnote: a sweep may carry both witness semantics at once, and two
    #: rows that differ only in which silicon they model must never merge into one cell.
    witness_mode: str = "baseline"
    #: Also part of the key, and PRINTED, for the reason H37 records: a collateral ratio is a
    #: property of the workload split until you show it is not, so a row that does not name its
    #: share vector cannot be decomposed by the reader.
    context_share: Tuple[float, ...] = UNIFORM_QUARTER

    def __str__(self) -> str:
        return "%s/%s wit=%s tau=%d/%d h=%.1f k=%d p=%g share=%s" % (
            self.scenario, self.arm, self.witness_mode, self.tau_feedback_us, self.tau_write_us,
            self.h, self.clean_epochs_to_restore, self.p_fault,
            "/".join("%g" % s for s in self.context_share))


def cell_key(cfg: RunConfig) -> CellKey:
    """The cell a run belongs to: everything but the seed."""
    return CellKey(scenario=cfg.scenario, arm=cfg.arm, tau_feedback_us=cfg.tau_feedback_us,
                   tau_write_us=cfg.tau_write_us, h=cfg.h,
                   clean_epochs_to_restore=cfg.clean_epochs_to_restore, p_fault=cfg.p_fault,
                   witness_mode=cfg.witness_mode, context_share=cfg.context_share)


@dataclass
class RunTrace:
    """The live objects and the raw event log of one run, for tests and for diagnostics.

    ``feedback`` is the actual :class:`SublinkFeedback` instance the run drove.  Tests assert
    against it directly so that "the harness drives the real class" is checked rather than
    claimed.
    """

    config: RunConfig
    fabric: Fabric
    feedback: SublinkFeedback
    faulty: Optional[Tuple[int, int]]
    faulty_set: Tuple[Tuple[int, int], ...]
    write_ops: List[Tuple[int, str, Tuple[int, int, int, int]]] = field(default_factory=list)
    audit_results: List[AuditResult] = field(default_factory=list)
    gate_effective_us: Optional[int] = None
    restore_effective_us: Optional[int] = None


# ------------------------------------------------------------------------------------------
# Scenario construction
# ------------------------------------------------------------------------------------------
#: The emulated fabric of `sim/dynamic/PREREG.md`: 4 leaves x 2 spines, 16 directed vlinks.
N_LEAF, N_SPINE = 4, 2


def fault_site(scenario: str, seed: int, n_context: int = 4) -> Tuple[int, int]:
    """The ``(vlink, context)`` the fault is drawn onto, without building the fabric.

    Split out of :func:`build_scenario` because the share sweep has to put the faulty context's
    share on the RIGHT index: a curve of collateral against "the faulty context's share" is
    meaningless if the share landed on one of its healthy siblings.  The draw is the same CRC-32
    stream `build_scenario` always used (`scenario_seed`, never salted ``hash``) and depends only
    on the scenario, the seed and ``n_context``, so calling it here does not move the fault.
    """
    rng = random.Random(scenario_seed("%s/%d" % (scenario, seed), "faultsite"))
    return rng.randrange(N_LEAF * N_SPINE * 2), rng.randrange(n_context)


def build_scenario(cfg: RunConfig) -> Tuple[Fabric, Optional[Tuple[int, int]]]:
    """Build the fabric for one run and name the sublink the fault was injected on.

    Returns ``(fabric, faulty)`` where ``faulty`` is ``(vlink, context)`` or ``None`` when the
    scenario injects no loss fault (``reorder_only``, ``wrap``, ``no_fault``).  For a whole-link
    fault (``all_context_blackhole``) the returned pair names the *representative* sublink used for
    detection and exposure accounting; :func:`faulty_sublinks` returns the full set.

    Which sublink fails is drawn per seed rather than fixed, so a result cannot be an artifact of
    one position in the topology; the draw is CRC-32 (`scenario_seed`), never salted ``hash``.
    """
    n_leaf, n_spine, n_context = N_LEAF, N_SPINE, cfg.n_context
    vlink, context = fault_site(cfg.scenario, cfg.seed, n_context)

    faults: List[FaultSpec] = []
    reorder_rate = 0.0
    p_bg = cfg.p_bg
    seq_start = 0
    faulty: Optional[Tuple[int, int]] = (vlink, context)

    if cfg.scenario == "persistent_partial":
        faults.append(FaultSpec(vlink=vlink, context=context, p_fault=cfg.p_fault,
                                onset_epoch=cfg.onset_epoch))
    elif cfg.scenario == "repaired":
        # The repair lands one third of the way through the post-onset window, so the same rule
        # gives a repair inside the run at every epoch budget the sweep uses.
        clear = cfg.onset_epoch + max(1, (cfg.epochs - cfg.onset_epoch) // 3)
        faults.append(FaultSpec(vlink=vlink, context=context, p_fault=cfg.p_fault,
                                onset_epoch=cfg.onset_epoch, clear_epoch=clear))
    elif cfg.scenario == "intermittent":
        faults.append(FaultSpec(vlink=vlink, context=context, p_fault=cfg.p_fault,
                                onset_epoch=cfg.onset_epoch, duty=(2, 3)))
    elif cfg.scenario == "reorder_only":
        # PREREG: "adjacent swaps, zero loss".  p_bg is set to zero here on purpose: the control
        # must isolate reordering, and a background loss rate would leave it arguable which of the
        # two produced any event that appeared.
        reorder_rate, p_bg, faulty = cfg.p_fault, 0.0, None
    elif cfg.scenario == "wrap":
        # Start the 16-bit witness counter close enough to the top that every sublink crosses
        # 65535 -> 0 inside the first epoch (a context carries ~52k packets per epoch).
        seq_start, faulty = (1 << 16) - 26041, None
    elif cfg.scenario == "selective_blackhole":
        faults.append(FaultSpec(vlink=vlink, context=context, p_fault=1.0,
                                onset_epoch=cfg.onset_epoch))
    elif cfg.scenario == "all_context_blackhole":
        faults.append(FaultSpec(vlink=vlink, context=None, p_fault=1.0,
                                onset_epoch=cfg.onset_epoch))
        faulty = (vlink, context)
    elif cfg.scenario == "no_fault":
        faulty = None
    else:                                                     # pragma: no cover - guarded above
        raise ValueError("unhandled scenario %r" % (cfg.scenario,))

    fab = Fabric(seed=cfg.seed, scenario=cfg.scenario, p_bg=p_bg, faults=faults,
                 context_share=cfg.context_share,
                 n_leaf=n_leaf, n_spine=n_spine, n_context=n_context,
                 reorder_rate=reorder_rate, seq_start=seq_start,
                 witness_mode=cfg.witness_mode)
    return fab, faulty


def faulty_sublinks(fab: Fabric) -> Tuple[Tuple[int, int], ...]:
    """Every ``(vlink, context)`` covered by an injected fault, in fabric order.

    A whole-link fault carries ``context is None`` and therefore covers four sublinks; they are
    all excluded from the healthy denominators, otherwise a sublink that is broken by construction
    would be counted as a false quarantine when the arm gates it.
    """
    out: List[Tuple[int, int]] = []
    for vlink in range(fab.n_vlink):
        for context in range(fab.n_context):
            for spec in fab.faults:
                if spec.vlink == vlink and spec.context in (None, context):
                    out.append((vlink, context))
                    break
    return tuple(out)


# ------------------------------------------------------------------------------------------
# The run
# ------------------------------------------------------------------------------------------
class _Clock:
    """The send timestamp the write path should use, in microseconds.

    ``SublinkFeedback`` calls ``install``/``remove`` with no notion of time, so the timestamp of
    the decision that triggered the write has to be carried alongside.  It is the delivery time of
    the gap event being processed, or the closing time of the audit round — never the epoch
    boundary, which would hide up to a full epoch of write latency.
    """

    def __init__(self) -> None:
        self.t_us = 0


def _gated(fab: Fabric, vlink: int, context: int) -> bool:
    """True when EVERY gate key of this sublink is present in the fabric's table.

    Quarantine is scored here, on the effective gate, rather than on the controller's own state:
    it is the only definition that means the same thing for all four arms, and it is the one that
    corresponds to traffic actually leaving the sublink.
    """
    keys = gate_keys_for_sublink(vlink, context, fab.n_leaf, fab.n_spine)
    return all(key in fab.installed_keys for key in keys)


def run(cfg: RunConfig) -> RunRecord:
    """Execute one run and return its record."""
    return run_verbose(cfg)[0]


def run_verbose(cfg: RunConfig) -> Tuple[RunRecord, RunTrace]:
    """Execute one run, returning the record and the live objects that produced it."""
    fab, faulty = build_scenario(cfg)
    faulty_set = faulty_sublinks(fab)
    faulty_keys = set(faulty_set)
    clock = _Clock()

    write_line = DelayLine(cfg.tau_write_us)
    event_line = DelayLine(cfg.tau_feedback_us)
    # PREREG: "audit sends and receipts carry the same delay", so a probation round costs a full
    # round trip.  Modelling only the receipt leg would make the round look one tau fresher than
    # it is, which is exactly the quantity the STALE result turns on.
    audit_line = DelayLine(2 * cfg.tau_feedback_us)

    def _send_write(op: str, key: Tuple[int, int, int, int], alt_spray: int) -> None:
        due = clock.t_us + cfg.tau_write_us
        write_line.send(clock.t_us, (due, op, key, alt_spray))

    def install(src_leaf: int, dst_leaf: int, spray: int, context: int, alt_spray: int) -> None:
        """The injected writer.  It must not touch the fabric: writes take tau_write to land."""
        contexts = range(fab.n_context) if cfg.arm == "directed_w4" else (context,)
        for ctx in contexts:
            _send_write("install", (src_leaf, dst_leaf, spray, ctx), alt_spray)

    def remove(src_leaf: int, dst_leaf: int, spray: int, context: int) -> None:
        contexts = range(fab.n_context) if cfg.arm == "directed_w4" else (context,)
        for ctx in contexts:
            _send_write("remove", (src_leaf, dst_leaf, spray, ctx), 0)

    fb = SublinkFeedback(install=install, remove=remove, h=cfg.h,
                         clean_epochs_to_restore=cfg.clean_epochs_to_restore)
    trace = RunTrace(config=cfg, fabric=fab, feedback=fb, faulty=faulty, faulty_set=faulty_set)

    onset_us = cfg.onset_epoch * EPOCH_US
    unsafe_packets = 0
    collateral_packets = 0
    false_quarantine_epochs = 0
    healthy_epochs = 0
    evidence_epochs = 0
    unsafe_restorations = 0
    flaps = 0
    offered_faulty = lost_faulty = offered_healthy = lost_healthy = 0
    audit_counts = {"CLEAN": 0, "LOSS": 0, "INCOMPLETE": 0, "STALE": 0}

    gated_now: Set[Tuple[int, int]] = set()
    ever_gated: Set[Tuple[int, int]] = set()
    q_then_h: Set[Tuple[int, int]] = set()          # for flap counting: Q -> H -> Q
    pending_rounds: List[Tuple[int, AuditRound]] = []   # (deadline_us, round)
    token_counter = 0

    for epoch in range(cfg.epochs):
        now_us = epoch * EPOCH_US
        fb.begin_epoch(epoch)
        clock.t_us = now_us

        # -- the epoch's traffic, under whatever gate is effective right now -------------
        out = fab.step(epoch)
        for (vlink, context), n in out.offered.items():
            n_lost = out.lost[(vlink, context)]
            base = int(PKT_PER_LINK_EPOCH * fab.context_share[context])
            if (vlink, context) in faulty_keys:
                offered_faulty += n
                lost_faulty += n_lost
            else:
                offered_healthy += n
                lost_healthy += n_lost
                collateral_packets += base - n
                healthy_epochs += 1
                if (vlink, context) in gated_now:
                    false_quarantine_epochs += 1
        if faulty is not None and epoch >= cfg.onset_epoch and trace.gate_effective_us is None:
            unsafe_packets += out.lost[faulty]
        watched = faulty_keys if faulty_keys else set(out.offered)
        if any((ev.vlink, ev.context) in watched for _, ev in out.gap_events):
            evidence_epochs += 1

        # -- evidence into the controller ------------------------------------------------
        if cfg.arm in ("cw4_feedback", "directed_w4"):
            # The pooled baseline is what makes an alarm possible at all: without the siblings,
            # the faulty sublink becomes its own baseline and the CUSUM never moves.
            for vlink, context, packets in out.clean_obs:
                fb.observe_clean(vlink, context, packets, epoch)
            for t_us, ev in out.gap_events:
                event_line.send(t_us, (t_us + cfg.tau_feedback_us, "gap", ev))
        elif cfg.arm == "oracle" and faulty is not None and epoch == cfg.onset_epoch:
            # Handed the answer at onset; it still pays the transport and the write.
            event_line.send(now_us, (now_us + cfg.tau_feedback_us, "oracle", faulty))

        # -- feedback delivery -----------------------------------------------------------
        # The write clock is the event's own DELIVERY time, not the epoch boundary: charging the
        # boundary would hide up to a full epoch of latency inside a metric named "detection".
        for delivered_us, kind, payload in event_line.due(now_us + EPOCH_US):
            clock.t_us = delivered_us
            if kind == "gap":
                fb.on_gap(payload)
            else:
                vlink, context = payload
                for src_leaf, dst_leaf, spray, ctx in gate_keys_for_sublink(
                        vlink, context, fab.n_leaf, fab.n_spine):
                    install(src_leaf, dst_leaf, spray, ctx, 1 - spray)

        # -- probation --------------------------------------------------------------------
        if cfg.arm in ("cw4_feedback", "directed_w4"):
            outstanding = set(rnd.sublink for _, rnd in pending_rounds)
            for sublink, st in sorted(fb.state.items()):
                vlink, context = sublink >> 4, sublink & 0xF
                # Probation needs the quarantine to EXIST: the audit packets are steered onto a
                # sublink the gate has already emptied.  Probing between the decision and the
                # write would also invert the write order -- a round that closed CLEAN in the
                # decision's own epoch enqueued its `remove` ahead of the still-in-flight
                # `install`, and the delay line delivered them in that order, leaving the gate
                # installed forever while the controller believed it had restored.  That showed up
                # as the impossible result "k=1 never restores, k=3 always does".
                if (st.state != QUARANTINED or sublink in outstanding
                        or (vlink, context) not in gated_now):
                    continue
                tokens = tuple((token_counter + i) % 0xFFFF + 1 for i in range(cfg.audit_tokens))
                token_counter += cfg.audit_tokens
                rnd = AuditRound(vlink=vlink, context=context, epoch=epoch,
                                 expected_tokens=tokens)
                survivors = fab.audit_survivals(vlink, context, epoch, tokens)
                for token in survivors:
                    audit_line.send(now_us, AuditReceipt(vlink=vlink, context=context,
                                                         epoch=epoch, token=token,
                                                         witness_seq=token, gap=0))
                pending_rounds.append((now_us + audit_line.tau_us, rnd))

            for receipt in audit_line.due(now_us + EPOCH_US):
                for _, rnd in pending_rounds:
                    if rnd.sublink == receipt.sublink and rnd.epoch == receipt.epoch:
                        rnd.accept(receipt)
                        break
            still_open: List[Tuple[int, AuditRound]] = []
            for deadline, rnd in pending_rounds:
                if deadline > now_us + EPOCH_US:
                    still_open.append((deadline, rnd))
                    continue
                clock.t_us = max(deadline, now_us)
                result = rnd.finish(fb)
                trace.audit_results.append(result)
                # ``finish`` returns "RESTORE" when the complete, gap-free, current round was the
                # one that met the restoration requirement; it is a CLEAN round either way.
                audit_counts["CLEAN" if result.status in ("CLEAN", "RESTORE")
                             else result.status] += 1
            pending_rounds = still_open

        # -- writes land ------------------------------------------------------------------
        for due, op, key, alt_spray in write_line.due(now_us + EPOCH_US):
            trace.write_ops.append((due, op, key))
            if op == "install":
                fab.install(key[0], key[1], key[2], key[3], alt_spray)
            else:
                fab.remove(*key)
            after = set()
            for vlink in range(fab.n_vlink):
                for context in range(fab.n_context):
                    if _gated(fab, vlink, context):
                        after.add((vlink, context))
            for sub in after - gated_now:
                if sub in q_then_h:
                    flaps += 1
                    q_then_h.discard(sub)
                ever_gated.add(sub)
                if faulty is not None and sub == faulty and trace.gate_effective_us is None:
                    trace.gate_effective_us = due
            for sub in gated_now - after:
                q_then_h.add(sub)
                if fab.p_eff(sub[0], sub[1], epoch) > fab.p_bg:
                    unsafe_restorations += 1
                if (faulty is not None and sub == faulty
                        and trace.restore_effective_us is None):
                    trace.restore_effective_us = due
            gated_now = after

    summary = fb.summary()
    detect_us = (None if trace.gate_effective_us is None
                 else trace.gate_effective_us - onset_us)
    restored = trace.restore_effective_us is not None
    restore_us = (None if not restored or trace.gate_effective_us is None
                  else trace.restore_effective_us - trace.gate_effective_us)
    record = RunRecord(
        quarantined_faulty=faulty is not None and faulty in ever_gated,
        unsafe_packets=unsafe_packets,
        detect_us=detect_us,
        healthy_epochs=healthy_epochs,
        false_quarantine_epochs=false_quarantine_epochs,
        collateral_packets=collateral_packets,
        restored=restored,
        restore_us=restore_us,
        unsafe_restorations=unsafe_restorations,
        flaps=flaps,
        installs=summary["installs"],
        coalesced=summary["coalesced"],
        stale_dropped=summary["stale_dropped"],
        offered_faulty=offered_faulty,
        lost_faulty=lost_faulty,
        offered_healthy=offered_healthy,
        lost_healthy=lost_healthy,
        evidence_epochs=evidence_epochs,
        epochs=cfg.epochs,
        audit_clean=audit_counts["CLEAN"],
        audit_loss=audit_counts["LOSS"],
        audit_incomplete=audit_counts["INCOMPLETE"],
        audit_stale=audit_counts["STALE"],
    )
    return record, trace


# ------------------------------------------------------------------------------------------
# Tripwire 1: the oracle floor
# ------------------------------------------------------------------------------------------
def check_oracle_floor(records_by_cell: Mapping[CellKey, Sequence[RunRecord]]) -> None:
    """Abort the sweep if the arm that was handed the answer failed to act (PREREG tripwire 1).

    Twice on 2026-08-28 (HURDLES H29, H32) an "upper bound" arm lost to a baseline, and both times
    the cause was the harness — the fault never reached the arm, or the injector had overwritten
    the background rate instead of composing with it.  So an oracle that does not quarantine an
    injected fault raises rather than being reported: the rest of the sweep would be a description
    of the harness.
    """
    for key, records in records_by_cell.items():
        if key.arm != "oracle" or key.scenario not in FAULT_SCENARIOS:
            continue
        missed = [i for i, r in enumerate(records) if not r.quarantined_faulty]
        if missed:
            raise HarnessError(
                "oracle floor breached in cell [%s]: %d of %d runs failed to quarantine an "
                "injected fault (run indices %s). An upper bound that cannot find the answer it "
                "was handed is a harness bug (HURDLES H29/H32), not a result."
                % (key, len(missed), len(records), missed[:5]))
