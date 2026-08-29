#!/usr/bin/env python3
"""Packet-level fabric and C-W4 evidence generator for the dynamic operating point.

This is the *environment* half of `sim/dynamic/PREREG.md`.  It re-implements none of the
controller: it produces `controller.sublink_feedback.GapEvent` objects and honours the exact P2
gate keys that `SublinkFeedback` installs, so the experiment measures the implemented state
machine rather than a model of it.

Three properties are the scientific content here, and each exists because a previous harness got
it wrong (HURDLES H29/H32, repo doctrine "cross-check before concluding"):

* **Loss composes, it never overwrites.**  `p_eff = 1 - (1 - p_bg)(1 - p_fault)`.  A fault
  injector that assigns `p_eff = p_fault` silently deletes the background rate, which is what made
  every arm — including the oracle — look censored.
* **Evidence needs a survivor.**  A C-W4 discontinuity is observable only when a later packet in
  the same `(vlink, context)` sequence arrives.  Lost packets are drawn as geometric inter-loss
  gaps and grouped into maximal runs; a run emits one `GapEvent` only when a packet after it
  survives, and a run still open at the end of an epoch carries into the next one.  Consequently a
  total blackhole emits nothing at all *by construction*, so "UNDETECTED" is a derived property of
  the mechanism rather than an assumption written into the harness.
* **Reordering is not benign.**  The witness is one register action
  (`p4/witness/mcp_fabric_gate_event.p4:749`): `gap = expected - observed; expected = observed + 1`,
  emitting whenever `gap != 0`.  Applied to the real arrival ORDER, a single adjacent swap emits
  THREE events -- `0xFFFF`, `0x0002`, `0xFFFF` -- two of which the controller reads as `lost = 1`,
  even though no packet left the link.  Loss and reorder are therefore one mechanism here, not two
  special cases; modelling a swap as a single benign `gap = 2` would have credited reordering with
  zero false evidence and made the pre-registration's `reorder_only` control pass trivially.
* **Both witness semantics are modelled, so the proposed silicon fix can be MEASURED.**
  ``witness_mode="baseline"`` is the register action above, as compiled today.
  ``witness_mode="advance_only"`` is `p4/witness/mcp_fabric_gate_event_advonly.p4:749`, which
  predicates the resync on the SIGNED sign of the difference the SALU already computes
  (`if ((int<16>)(v - seq) <= 0) v = seq + 1;`), so `expected` can only move forward and a late
  packet can no longer rewind it.  That variant compiles on bf-p4c 9.13.1 at 11 ingress / 4 egress,
  identical to the baseline, for a two-instruction `.bfa` delta.  The predicate is transcribed
  literally here and reordering is NOT special-cased: the two-event trace for a swap and the
  unchanged loss trace both fall out of the arithmetic, which is the only way this harness can be
  evidence about the fix rather than a restatement of it.
* **The gate is honoured.**  Installing gate keys removes the affected context from the sublink, so
  exposure *and* evidence stop together.  Offered load is scaled by the fraction of the sublink's
  keys currently installed; a fully gated sublink offers zero packets and is therefore silent —
  silence is not health evidence, which is precisely why the controller needs probation traffic.

Arrivals and inferred losses stay disjoint: the arrival register returns its PRE-update value and
is zeroed by any non-zero gap, and the mirror decoder reports that value plus the survivor that
exposed the gap (`p4/ptf/gap_event/test.py:84`, asserted as 3 by Test50).  `observed_packets` is
therefore that controller-facing count, while the modular `gap` separately counts the missing
packets; the frozen inference layer adds the two, so overlapping them would double-count the loss.
The arrival register is 16 bits with a saturating increment, so a long clean run reports at most
65536 arrivals -- real silicon under-reports the baseline, and the model reproduces that.

All randomness comes from `sim.gate.replay.scenario_seed` (CRC-32); Python's salted `hash()` is
barred because it changes the fault identity between processes.
"""
from __future__ import annotations

import math
import random
from bisect import bisect_left
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from controller.sublink_feedback import GapEvent, gate_keys_for_sublink
from sim.gate.replay import scenario_seed

EPOCH_US = 100_000
PKT_PER_LINK_EPOCH = 208_333          # 25 Gbit/s of 1500 B packets for one 100 ms epoch
SEQ_MASK = 0xFFFF                     # the C-W4 witness sequence counter is 16 bits
SEQ_HALF = 1 << 15                    # the forward window of the 2^16 ring; the signed sign bit
ARRIVAL_MAX = 0xFFFF                  # reg_wit_observed is bit<16> with a SATURATING increment

#: The two witness semantics the harness can carry.  ``baseline`` is the compiled
#: `p4/witness/mcp_fabric_gate_event.p4` register action; ``advance_only`` is the compiled variant
#: `p4/witness/mcp_fabric_gate_event_advonly.p4`.  Anything else is rejected rather than silently
#: treated as one of them -- confusing the two would make every reorder number unattributable.
WITNESS_MODES: Tuple[str, ...] = ("baseline", "advance_only")


@dataclass(frozen=True)
class FaultSpec:
    """One injected conditional fault.

    ``context is None`` means every context on that directed vlink (a physical-link fault);
    a concrete context is the class-selective gray failure C-W4 is meant to separate.
    """

    vlink: int
    context: Optional[int]
    p_fault: float
    onset_epoch: int
    clear_epoch: Optional[int] = None
    duty: Optional[Tuple[int, int]] = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.p_fault <= 1.0:
            raise ValueError("p_fault must be a probability")
        if self.duty is not None:
            on, off = self.duty
            if on <= 0 or off < 0:
                raise ValueError("duty must be (on_epochs > 0, off_epochs >= 0)")

    def active(self, epoch: int) -> bool:
        if epoch < self.onset_epoch:
            return False
        if self.clear_epoch is not None and epoch >= self.clear_epoch:
            return False
        if self.duty is None:
            return True
        on, off = self.duty
        return (epoch - self.onset_epoch) % (on + off) < on


@dataclass(frozen=True)
class EpochOutput:
    """Everything one epoch of the fabric produced, ready for the arms to consume."""

    gap_events: Tuple[Tuple[int, GapEvent], ...]
    clean_obs: Tuple[Tuple[int, int, int], ...]
    offered: Dict[Tuple[int, int], int]
    lost: Dict[Tuple[int, int], int]


@dataclass
class _SublinkState:
    """Per-(vlink, context) witness state, and the two SALUs that read it.

    ``expect_seq`` is ``reg_wit_expect`` and ``arrivals`` is ``reg_wit_observed``.  Both persist
    ACROSS epochs, which is what makes a lost run with no survivor yet *not* evidence: the event
    fires when the closing survivor arrives, in whatever epoch that happens to be.
    """

    next_seq: int
    expect_seq: int
    arrivals: int = 0
    open_run: int = 0
    witness_mode: str = "baseline"

    def observe(self, seq: int) -> Tuple[int, int]:
        """One witness-bearing arrival -> ``(gap, observed_packets)``.

        This is `wit_check` and `wit_count` from `p4/witness/mcp_fabric_gate_event.p4:749,764`
        transcribed, plus the mirror decoder's ``prior_arrivals + 1``.

        ``baseline`` resynchronises UNCONDITIONALLY, which is what limits a loss burst to exactly
        one event -- and what makes a reordered arrival emit an event on the way out of order and
        again on the way back in.

        ``advance_only`` is `mcp_fabric_gate_event_advonly.p4:749` transcribed just as literally:
        the same difference is reinterpreted as ``int<16>`` and the resync is predicated on its
        sign, so ``expected`` moves only towards a sequence at or ahead of it in the 32768-wide
        forward window.  ``gap`` is still returned unconditionally (it is the SALU's ``rv``, not
        its write), and ``wit_count`` is untouched in both modes because the variant does not
        change it.  Nothing here inspects "was this a reorder?" -- the swap trace and the loss
        trace are both consequences of that one predicate.
        """
        gap = (self.expect_seq - seq) & SEQ_MASK
        if self.witness_mode == "baseline":
            self.expect_seq = (seq + 1) & SEQ_MASK
        elif self.witness_mode == "advance_only":
            # (int<16>)(v - seq) <= 0, i.e. the top half of the ring is the negative half.
            if gap == 0 or gap >= SEQ_HALF:
                self.expect_seq = (seq + 1) & SEQ_MASK
        else:                                       # pragma: no cover - guarded at construction
            raise ValueError("unknown witness_mode %r" % (self.witness_mode,))
        prior = self.arrivals
        if gap != 0:
            self.arrivals = 0
        elif self.arrivals < ARRIVAL_MAX:
            self.arrivals += 1
        return gap, prior + 1


def _geom_jump(p: float, rng: random.Random) -> int:
    """Number of surviving packets before the next loss, for i.i.d. loss at rate ``p``.

    Sampling the inter-loss gap makes an epoch cost O(losses) instead of O(208333); at p_bg = 1e-6
    the per-packet loop would dominate the whole experiment.
    """
    u = rng.random()
    if u <= 0.0:
        u = 5e-324
    return int(math.log(u) / math.log1p(-p))


def _loss_runs(n: int, p: float, rng: random.Random) -> List[List[int]]:
    """Maximal runs ``[start, end]`` of lost packet indices within one epoch."""
    if n <= 0 or p <= 0.0:
        return []
    if p >= 1.0:
        return [[0, n - 1]]                      # O(1); the per-packet loop here would be 208k spins
    runs: List[List[int]] = []
    i = 0
    while True:
        i += _geom_jump(p, rng)
        if i >= n:
            break
        if runs and runs[-1][1] == i - 1:
            runs[-1][1] = i
        else:
            runs.append([i, i])
        i += 1
    return runs


class Fabric:
    """4 x 2 virtual fabric carrying production traffic, with an honoured health gate."""

    def __init__(self, seed: int, scenario: str, p_bg: float = 1e-6,
                 faults: Sequence[FaultSpec] = (),
                 context_share: Sequence[float] = (0.25,) * 4,
                 n_leaf: int = 4, n_spine: int = 2, n_context: int = 4,
                 reorder_rate: float = 0.0, seq_start: int = 0,
                 witness_mode: str = "baseline") -> None:
        self.seed, self.scenario = seed, scenario
        self.p_bg = p_bg
        self.faults = tuple(faults)
        self.context_share = tuple(context_share)
        self.n_leaf, self.n_spine, self.n_context = n_leaf, n_spine, n_context
        self.n_vlink = n_leaf * n_spine * 2
        self.reorder_rate = reorder_rate
        if len(self.context_share) < n_context:
            raise ValueError("context_share must cover every context")
        if witness_mode not in WITNESS_MODES:
            raise ValueError("unknown witness_mode %r; supported modes are %s"
                             % (witness_mode, WITNESS_MODES))
        self.witness_mode = witness_mode
        stem = "%s/%d" % (scenario, seed)
        self.rng_loss = random.Random(scenario_seed(stem, "loss"))
        self.rng_reorder = random.Random(scenario_seed(stem, "reorder"))
        self.rng_audit = random.Random(scenario_seed(stem, "audit"))
        self.installed_keys = set()
        self._keys: Dict[Tuple[int, int], Tuple[Tuple[int, int, int, int], ...]] = {}
        self._sub: Dict[Tuple[int, int], _SublinkState] = {}
        for vlink in range(self.n_vlink):
            for context in range(n_context):
                self._keys[(vlink, context)] = gate_keys_for_sublink(vlink, context, n_leaf, n_spine)
                self._sub[(vlink, context)] = _SublinkState(
                    next_seq=seq_start & SEQ_MASK, expect_seq=seq_start & SEQ_MASK,
                    witness_mode=witness_mode)

    # ---- the honoured gate ------------------------------------------------------
    def install(self, src_leaf: int, dst_leaf: int, spray: int, context: int,
                alt_spray: int) -> None:
        """Same signature as ``SublinkFeedback``'s injected writer; the model obeys it."""
        self.installed_keys.add((src_leaf, dst_leaf, spray, context))

    def remove(self, src_leaf: int, dst_leaf: int, spray: int, context: int) -> None:
        self.installed_keys.discard((src_leaf, dst_leaf, spray, context))

    def _offered(self, vlink: int, context: int) -> int:
        keys = self._keys[(vlink, context)]
        gated = sum(1 for k in keys if k in self.installed_keys)
        base = int(PKT_PER_LINK_EPOCH * self.context_share[context])
        return int(base * (1.0 - gated / float(len(keys))))

    # ---- the loss model ---------------------------------------------------------
    def p_eff(self, vlink: int, context: int, epoch: int) -> float:
        """Composed loss probability.  The background survives every fault (HURDLES H32)."""
        survive = 1.0
        faulty = False
        for f in self.faults:
            if f.vlink != vlink:
                continue
            if f.context is not None and f.context != context:
                continue
            if f.active(epoch):
                survive *= (1.0 - f.p_fault)
                faulty = True
        if not faulty:
            return self.p_bg
        return 1.0 - (1.0 - self.p_bg) * survive

    def audit_survivals(self, vlink: int, context: int, epoch: int,
                        tokens: Sequence[int]) -> Tuple[int, ...]:
        """Probation packets bypass the gate: the controller steers them explicitly.

        Without this bypass a quarantined sublink could never be re-exercised, so restoration would
        rest on silence — the exact failure the feedback state machine refuses to accept.
        """
        p = self.p_eff(vlink, context, epoch)
        return tuple(t for t in tokens if self.rng_audit.random() >= p)

    # ---- one epoch --------------------------------------------------------------
    def step(self, epoch: int) -> EpochOutput:
        events: List[Tuple[int, GapEvent]] = []
        clean: List[Tuple[int, int, int]] = []
        offered: Dict[Tuple[int, int], int] = {}
        lost: Dict[Tuple[int, int], int] = {}
        for vlink in range(self.n_vlink):
            for context in range(self.n_context):
                n = self._offered(vlink, context)
                offered[(vlink, context)] = n
                n_lost, sub_events = self._run_sublink(vlink, context, epoch, n)
                lost[(vlink, context)] = n_lost
                events.extend(sub_events)
                delivered = n - n_lost
                if delivered > 0 and not sub_events:
                    clean.append((vlink, context, delivered))
        events.sort(key=lambda te: te[0])          # stable: generation order breaks ties
        return EpochOutput(gap_events=tuple(events), clean_obs=tuple(clean),
                           offered=offered, lost=lost)

    def _run_sublink(self, vlink: int, context: int, epoch: int,
                     n: int) -> Tuple[int, List[Tuple[int, GapEvent]]]:
        """Emit one epoch of arrivals through the witness, in ARRIVAL order.

        Only the neighbourhood of a perturbation can produce a non-zero gap, so contiguous
        in-order stretches advance the arrival register in O(1) and the per-packet emulation runs
        only inside the dirty windows.  ``test_fast_path_matches_a_brute_force_per_packet_witness``
        pins this optimisation against a literal per-packet emulation.
        """
        st = self._sub[(vlink, context)]
        if n <= 0:
            return 0, []
        seq_base = st.next_seq
        p = self.p_eff(vlink, context, epoch)
        runs = _loss_runs(n, p, self.rng_loss)
        ends = [r[1] for r in runs]
        n_lost = sum(end - start + 1 for start, end in runs)
        delivered = n - n_lost
        swaps = self._swap_points(n, runs, ends)

        windows: List[List[int]] = []
        for start, end in runs:                       # the event fires on the CLOSING survivor
            windows.append([start, min(end + 1, n - 1)])
        for a in swaps:                               # ... and one packet past the swapped pair
            windows.append([a, min(a + 2, n - 1)])
        if st.expect_seq != seq_base:
            # A run or swap left open by the PREVIOUS epoch: the first arrival here is the
            # discontinuity that closes it, so it must go through the witness rather than be
            # skipped as clean.  Without this the carried evidence is silently swallowed.
            windows.append([0, 0])
        windows.sort()
        merged: List[List[int]] = []
        for w in windows:
            if merged and w[0] <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], w[1])
            else:
                merged.append(w)

        out: List[Tuple[int, GapEvent]] = []
        ordinal = 0
        cursor = 0
        for w0, w1 in merged:
            clean = w0 - cursor                       # in order and delivered: gap is 0 throughout
            if clean > 0:
                st.arrivals = min(ARRIVAL_MAX, st.arrivals + clean)
                st.expect_seq = (seq_base + w0) & SEQ_MASK
                ordinal += clean
            for idx in self._arrival_order(w0, w1, runs, ends, swaps):
                gap, observed = st.observe((seq_base + idx) & SEQ_MASK)
                if gap != 0:
                    out.append((epoch * EPOCH_US + (ordinal * EPOCH_US) // max(1, delivered),
                                GapEvent(vlink=vlink, context=context, epoch=epoch,
                                         gap=gap, observed_packets=observed)))
                ordinal += 1
            cursor = w1 + 1
        if cursor < n:
            tail = n - cursor
            st.arrivals = min(ARRIVAL_MAX, st.arrivals + tail)
            st.expect_seq = (seq_base + n) & SEQ_MASK
            ordinal += tail

        st.next_seq = (seq_base + n) & SEQ_MASK
        st.open_run = (st.next_seq - st.expect_seq) & SEQ_MASK
        return n_lost, out

    @staticmethod
    def _arrival_order(w0: int, w1: int, runs: List[List[int]], ends: List[int],
                       swaps: Sequence[int]) -> List[int]:
        """Indices in the order the witness sees them: lost ones absent, swapped pairs exchanged."""
        swapset = set(swaps)
        order: List[int] = []
        i = w0
        while i <= w1:
            if Fabric._is_lost(i, runs, ends):
                i += 1
            elif i in swapset and i + 1 <= w1 and not Fabric._is_lost(i + 1, runs, ends):
                order.append(i + 1)
                order.append(i)
                i += 2
            else:
                order.append(i)
                i += 1
        return order

    def _swap_points(self, n: int, runs: List[List[int]], ends: List[int]) -> List[int]:
        """Start indices of adjacent delivered pairs whose arrival order is exchanged.

        A swap moves no packet off the link.  It is emphatically NOT benign evidence: see
        ``_SublinkState.observe`` and the ``reorder_only`` tests.
        """
        if self.reorder_rate <= 0.0 or n < 2:
            return []
        points: List[int] = []
        a = 0
        while True:
            a += _geom_jump(self.reorder_rate, self.rng_reorder)
            if a >= n - 1:
                break
            if not (self._is_lost(a, runs, ends) or self._is_lost(a + 1, runs, ends)):
                points.append(a)
                a += 2                             # swaps do not overlap
            else:
                a += 1
        return points

    @staticmethod
    def _is_lost(idx: int, runs: List[List[int]], ends: List[int]) -> bool:
        k = bisect_left(ends, idx)
        return k < len(runs) and runs[k][0] <= idx
