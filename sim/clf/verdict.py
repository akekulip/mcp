#!/usr/bin/env python3
"""The Context Liveness Frontier verdict: combine source, receiver and continuity evidence.

This is the decision half of CLF and it is deliberately separate from the data plane, so the truth
table can be tested exhaustively without a switch. `sim/clf/PREREG.md` freezes the table; this
module implements exactly it and nothing more.

The rule that matters is the one that is easy to get wrong: a FAULTY verdict requires POSITIVE
SOURCE EVIDENCE. Absence of arrivals is only meaningful against a source that says it sent. Every
state outside the frozen table is INCONCLUSIVE, never FAULTY.
"""
from enum import Enum


class Verdict(str, Enum):
    IDLE = "IDLE"                      # TX=0 RX=0 -- untested, NOT faulty
    HEALTHY = "HEALTHY"                # TX=1 RX=1, continuity contiguous
    PARTIAL_LOSS = "PARTIAL_LOSS"      # TX=1 RX=1, continuity discontinuous
    BLACKHOLE = "BLACKHOLE"            # TX=1 RX=0 -- the case C-W4 cannot see
    IMPOSSIBLE = "IMPOSSIBLE"          # TX=0 RX=1 -- arrival without departure
    INCONCLUSIVE = "INCONCLUSIVE"      # anything else, including missing evidence


def verdict(tx, rx, gap_seen, evidence_complete=True):
    """One (directed link, context, epoch) verdict.

    tx, rx           : bool -- frontier bits for this context this epoch
    gap_seen         : bool or None -- C-W4 saw a discontinuity; None = no continuity evidence
    evidence_complete: bool -- both frontiers were actually read for this epoch. When a frontier
                       is missing (agent unreachable, bank not yet settled, management path down)
                       the answer is INCONCLUSIVE, never FAULTY: a management failure must not be
                       reported as a link failure.
    """
    if not evidence_complete:
        return Verdict.INCONCLUSIVE
    if not tx and not rx:
        return Verdict.IDLE
    if not tx and rx:
        # Arrival without departure. Physically impossible across one directed link, so this is a
        # harness or epoch-race defect. Report it; never classify it as a link state.
        return Verdict.IMPOSSIBLE
    if tx and not rx:
        return Verdict.BLACKHOLE
    if gap_seen is None:
        return Verdict.INCONCLUSIVE
    return Verdict.PARTIAL_LOSS if gap_seen else Verdict.HEALTHY


def frontier_mask(seen_by_sublink, vlink, n_context=16):
    """Pack per-sublink liveness bytes into the per-link 16-bit mask that crosses the wire.

    The data plane stores a byte per sublink because a per-link mask would need a one-hot
    `1 << ctx` and the compiler cannot shift a runtime value. Packing here is what preserves the
    batched record -- one 16-bit mask per directed link per epoch rather than K heartbeats -- which
    is where the O(L) rather than O(L*K) argument lives.
    """
    m = 0
    for ctx in range(n_context):
        if seen_by_sublink.get((vlink << 4) | ctx):
            m |= (1 << ctx)
    return m


def compare(tx_mask, rx_mask):
    """Contexts the source committed but the receiver never saw."""
    return tx_mask & ~rx_mask & 0xFFFF
