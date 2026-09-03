#!/usr/bin/env python3
"""bench_feedback_path.py — microbenchmark of the CONTROLLER-HOST segment of the P3 feedback path.

The path a downstream C-W4 gap must travel before the source stops spraying onto a bad
behavioural sublink is::

    downstream C-W4 gap -> mirror/event transport -> controller -> BFRT write -> tbl_health_gate live

This file times ONLY the middle software segment: the part that runs on the controller host and
needs no switch.

===========  ==========================================================================
stage        what is timed
===========  ==========================================================================
S1           ``hw_adapter.parse_copy(bytes)``      one mirrored copy off the wire -> dict
S2           ``hw_adapter.gap_event_from_copy()``  dict -> ``GapEvent``
S3           ``SublinkFeedback.on_gap(event)``     frozen inference, decision, key expansion
S4           ``BfrtHealthGate.install(...)``       controller-side key/data marshalling for every
                                                   expanded key, against a fake gc/bfrt whose
                                                   ``entry_add`` does nothing
===========  ==========================================================================

EXCLUDED, and therefore absent from every number this file prints: the mirror/event transport
from the downstream witness to the controller, the BFRT gRPC round trip, and the switch-side
table programming time.

**The end-to-end C-W4-event-to-health-gate latency remains unmeasured** (P2/P3 audit gap #4).
The totals reported here are a LOWER BOUND on the controller's contribution to that latency.
They are not the feedback latency, and a number from this file must never be presented as one —
the retraction recorded in ``docs/review/P3-FEEDBACK-RESULT.md`` exists because a measurement of
one mechanism was once reported as a measurement of a different one.

Two arms are timed, because the cost of the path depends entirely on whether a decision is made:

``quarantine``
    the event alarms; the frozen localizer runs and one directed sublink expands into the four
    exact P2 gate keys, all four of which are marshalled through the real writer;
``coalesced``
    a repeat event on a sublink already quarantined in this epoch; ``on_gap`` returns before the
    inference layer and nothing is installed.

The difference between the two totals is the marginal cost of an actual decision.
"""
import argparse
import json
import os
import platform
import random
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

if __package__ in (None, ""):                       # run as a script from anywhere
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.hw_adapter import (                 # noqa: E402
    FABRIC_ETYPE,
    FLAG_GAP_EVENT,
    FLAG_MEASURED,
    build_copy,
    gap_event_from_copy,
    parse_copy,
)
from controller import sublink_feedback as sfb                            # noqa: E402
from controller.sublink_feedback import BfrtHealthGate, SublinkFeedback  # noqa: E402

# The one label every reported total must carry.
SCOPE_LABEL = ("controller-host software segment; excludes mirror transport and "
               "BFRT gRPC + switch programming")
DISCLAIMER = (
    "The end-to-end C-W4-gap-to-live-health-gate latency remains unmeasured (P2/P3 audit gap "
    "#4). Every total below is a LOWER BOUND on the controller's contribution to it, not the "
    "feedback latency.")

STAGES = ("S1_parse_copy", "S2_gap_event_from_copy", "S3_on_gap_decision",
          "S4_health_gate_install")
STAGE_LABELS = {
    "S1_parse_copy": "S1 parse_copy(bytes)",
    "S2_gap_event_from_copy": "S2 gap_event_from_copy(dict)",
    "S3_on_gap_decision": "S3 on_gap(event) + flush_held() [one decision]",
    "S4_health_gate_install": "S4 BfrtHealthGate.install(key) x expanded keys",
}
ARMS = ("quarantine", "coalesced", "reorder_credit")

DEFAULT_ITERATIONS = 2000
WARMUP_ITERATIONS = 200        # discarded, so the frozen layer's baseline warm-up is not timed

FAULT_VLINK = 2                # an uplink: gate_keys_for_sublink expands it into N_LEAF=4 keys
FAULT_CONTEXT = 3
SIBLING_CONTEXTS = (0, 1, 2)   # the other behavioural sublinks of the same link, carrying production
EXPECTED_KEYS_PER_DECISION = 4
SIBLING_PACKETS = 65536        # per sibling per iteration: keeps the POOLED baseline the fabric's
PREWARM_PACKETS = 150000       # per sibling per pre-warm epoch; the pool needs 1e5 packets (frozen)
PREWARM_EPOCHS = (1, 2, 3)
EPOCH_WRAP = 60000             # the copied CSIG epoch field is 16 bits wide
MAX_ATTN = 0xFFFF              # the mirror metadata field carrying the observed-packet count
PHANTOM_LOSS_GAP = (1 << 16) - 1   # a one-packet gap: the phantom loss a reorder manufactures


# ----------------------------------------------------------------------------- fake BFRT boundary
class NullGC:
    """The ``bfrt_grpc.client`` surface ``BfrtHealthGate`` uses, with no gRPC behind it."""

    class BfruntimeRpcException(Exception):
        pass

    @staticmethod
    def KeyTuple(name, value):
        return (name, value)

    @staticmethod
    def DataTuple(name, value):
        return (name, value)


class NullGateTable:
    """Real key/data marshalling, no I/O: ``entry_add`` only counts.

    S4 therefore measures what the controller does before the request leaves the host and nothing
    that happens after it.
    """

    def __init__(self) -> None:
        self.adds = 0

    def make_key(self, fields):
        return tuple(fields)

    def make_data(self, fields, action):
        return action, tuple(fields)

    def entry_add(self, target, keys, data):
        self.adds += 1

    def entry_mod(self, target, keys, data):
        raise AssertionError("the benchmark never provokes a duplicate-entry modify")

    def entry_del(self, target, keys):
        raise AssertionError("the benchmark never removes a gate entry")

    def reset(self) -> None:
        self.adds = 0


class NullBfrt:
    def __init__(self, table: NullGateTable) -> None:
        self.table = table

    def table_get(self, name: str) -> NullGateTable:
        if name != "pipe.Ingress.tbl_health_gate":
            raise AssertionError("wrong BFRT table %s" % name)
        return self.table


# ----------------------------------------------------------------------------- event stream
def build_gap_copy(vlink: int, context: int, epoch: int, gap: int, attn: int) -> bytes:
    """One wire-format C-W4 gap-event copy, exactly as the deparser would emit it."""
    sublink = (vlink << 4) | context
    return build_copy(
        vlink=sublink, pid=gap, flags=FLAG_MEASURED | FLAG_GAP_EVENT, tstamp_ns=epoch * 100000,
        attn=attn, next_hop=2, inner_etype=FABRIC_ETYPE,
        csig={"worst_hop": 1, "worst_vlink": sublink, "worst_qdepth": 0, "worst_tdelta": 0,
              "path_id": gap, "epoch": epoch},
        witness={"seq": gap})


def build_event_stream(seed: int, n: int, arm: str) -> List[bytes]:
    """Deterministic synthetic copy stream: the same seed yields byte-identical frames.

    Each event carries close to a full 16-bit ``attn`` of observed arrivals, so the frozen
    layer's packet-counted baseline warm-up (1e5 packets in the pool, not update calls) is long
    past by the time any timed iteration runs.  In the ``coalesced`` arm every event names the
    same sublink and the same epoch, which is what makes ``on_gap`` return early.
    """
    if arm not in ARMS:
        raise ValueError("arm must be one of %s" % (ARMS,))
    rng = random.Random(seed)
    stream: List[bytes] = []
    for i in range(n):
        lost = rng.randint(8, 64)                       # a gap of 2^16 - lost means `lost` vanished
        attn = rng.randint(60000, MAX_ATTN)
        epoch = 1 if arm == "coalesced" else 1 + (i % EPOCH_WRAP)
        # The reorder arm's loss is EXACTLY one packet, because that is what a reorder fabricates:
        # the witness sees one packet missing and the packet then arrives out of order.  One
        # credit cancels one packet, so this is the case that can net to zero.
        gap = PHANTOM_LOSS_GAP if arm == "reorder_credit" else (1 << 16) - lost
        stream.append(build_gap_copy(FAULT_VLINK, FAULT_CONTEXT, epoch, gap, attn))
    return stream


def build_credit_stream(seed: int, n: int) -> List[bytes]:
    """The reorder receipts that cancel the ``reorder_credit`` arm's phantom loss, one per event.

    A receipt is a SMALL POSITIVE gap: a packet previously counted missing has arrived.  Its
    epoch tracks the paired loss event, because a credit only cancels loss held in its own epoch.
    """
    rng = random.Random(seed + 977)
    return [build_gap_copy(FAULT_VLINK, FAULT_CONTEXT, 1 + (i % EPOCH_WRAP),
                           rng.randint(1, sfb.REORDER_CREDIT_MAX), rng.randint(60000, MAX_ATTN))
            for i in range(n)]


def _prewarm(fb: SublinkFeedback) -> None:
    """Sibling behavioural sublinks carrying production supply the pooled background rate."""
    for context in SIBLING_CONTEXTS:
        for epoch in PREWARM_EPOCHS:
            fb.observe_clean(FAULT_VLINK, context, PREWARM_PACKETS, epoch)


# ----------------------------------------------------------------------------- statistics
def _nearest_rank(sorted_ns: Sequence[int], q: float) -> int:
    idx = int(-(-len(sorted_ns) * q // 1)) - 1          # ceil(q*n) - 1, integer arithmetic
    return sorted_ns[min(max(idx, 0), len(sorted_ns) - 1)]


def summarize(samples_ns: Sequence[int]) -> Dict[str, Any]:
    """Median/p95/p99 in microseconds.  No mean: the distribution is skewed by scheduling."""
    ordered = sorted(samples_ns)
    n = len(ordered)
    median_ns = (ordered[n // 2] if n % 2
                 else (ordered[n // 2 - 1] + ordered[n // 2]) / 2.0)
    return {"median_us": median_ns / 1000.0,
            "p95_us": _nearest_rank(ordered, 0.95) / 1000.0,
            "p99_us": _nearest_rank(ordered, 0.99) / 1000.0,
            "n": n}


# ----------------------------------------------------------------------------- the arms
def run_arm(arm: str, iterations: int = DEFAULT_ITERATIONS, seed: int = 1,
            warmup: int = WARMUP_ITERATIONS) -> Dict[str, Any]:
    """Time S1..S4 for one arm.  Returns per-stage and per-iteration-total statistics.

    The S3/S4 seam: ``SublinkFeedback`` calls its ``install`` callback itself, so to price the
    decision and the writer separately the callback here only records the expanded key (one list
    append per key) and S4 then replays those keys through the real ``BfrtHealthGate.install``.
    S3 therefore carries four list appends that the production wiring would not, and S4 carries a
    counter increment in place of the gRPC call it excludes.  Both are noted rather than
    corrected for, because both are far below the stage costs they sit inside.
    """
    if arm not in ARMS:
        raise ValueError("arm must be one of %s" % (ARMS,))
    if iterations < 1:
        raise ValueError("iterations must be positive")
    table = NullGateTable()
    gate = BfrtHealthGate(NullGC, NullBfrt(table), target="bench")
    expanded: List[Tuple[int, int, int, int, int]] = []

    def record(src_leaf: int, dst_leaf: int, spray: int, context: int, alt_spray: int) -> None:
        expanded.append((src_leaf, dst_leaf, spray, context, alt_spray))

    fb = SublinkFeedback(record, lambda *key: None)
    _prewarm(fb)
    stream = build_event_stream(seed, warmup + iterations, arm)
    credits = build_credit_stream(seed, warmup + iterations) if arm == "reorder_credit" else None

    if arm == "coalesced":
        # One real decision up front, untimed: every timed event then repeats it in the same
        # epoch, which is the case the coalescing contract must return early on.
        fb.begin_epoch(1)
        fb.on_gap(gap_event_from_copy(parse_copy(stream[0])))
        fb.flush_held()
        expanded.clear()
        table.reset()

    per_stage_ns: Dict[str, List[int]] = {stage: [] for stage in STAGES}
    totals_ns: List[int] = []
    decisions = 0
    for i, frame in enumerate(stream):
        timed = i >= warmup
        if arm != "coalesced":
            epoch = 1 + (i % EPOCH_WRAP)
            fb.begin_epoch(epoch)
        if arm == "quarantine":
            for context in SIBLING_CONTEXTS:
                fb.observe_clean(FAULT_VLINK, context, SIBLING_PACKETS, epoch)
        expanded.clear()

        t0 = time.perf_counter_ns()
        copy = parse_copy(frame)
        credit_copy = parse_copy(credits[i]) if credits is not None else None
        t1 = time.perf_counter_ns()
        event = gap_event_from_copy(copy)
        credit_event = gap_event_from_copy(credit_copy) if credit_copy is not None else None
        t2 = time.perf_counter_ns()
        action = fb.on_gap(event)
        if credit_event is not None:
            action = fb.on_gap(credit_event) or action
        # The decision now lands in the FLUSH, not necessarily in on_gap: a loss-bearing event is
        # held for within-epoch reorder netting and released when displaced or when the epoch
        # ends.  Flushing inside the window keeps S3 the cost of one COMPLETE decision.
        flushed = fb.flush_held()
        t3 = time.perf_counter_ns()
        for src_leaf, dst_leaf, spray, context, alt_spray in expanded:
            gate.install(src_leaf, dst_leaf, spray, context, alt_spray)
        t4 = time.perf_counter_ns()

        if not timed:
            table.reset()
            continue
        decisions += 1 if (action == "QUARANTINE" or "QUARANTINE" in flushed) else 0
        per_stage_ns["S1_parse_copy"].append(t1 - t0)
        per_stage_ns["S2_gap_event_from_copy"].append(t2 - t1)
        per_stage_ns["S3_on_gap_decision"].append(t3 - t2)
        per_stage_ns["S4_health_gate_install"].append(t4 - t3)
        totals_ns.append(t4 - t0)

    summary = fb.summary()
    return {
        "arm": arm,
        "stages": {stage: summarize(per_stage_ns[stage]) for stage in STAGES},
        "total": summarize(totals_ns),
        "quarantine_decisions": decisions,
        "coalesced_events": summary["coalesced"],
        "reorder_credits": summary["reorder_credits"],
        "netted_out": summary["netted_out"],
        "copies_parsed_per_iteration": 2 if credits is not None else 1,
        "installs_recorded_by_fake_bfrt": table.adds,
        "expected_keys_per_decision": EXPECTED_KEYS_PER_DECISION,
    }


def measure_isolated(stream: Sequence[bytes], warmup: int = WARMUP_ITERATIONS) -> Dict[str, Any]:
    """S1/S2 timed on their own: same frames, tight loop, no controller state around the call.

    The in-loop S1/S2 medians are NOT isolated call costs.  They move with whatever else the
    controller does around them -- the quarantine arm's pooled-baseline sibling updates roughly
    double them.  This function is the reference the reader needs to see that, and it also pins
    the frame class being parsed: a C-W4 gap-event copy carries fabric_h + csig_h + the copied
    witness and is parsed and validated far more deeply than an ordinary data copy.
    """
    s1_ns: List[int] = []
    s2_ns: List[int] = []
    for i, frame in enumerate(stream):
        t0 = time.perf_counter_ns()
        copy = parse_copy(frame)
        t1 = time.perf_counter_ns()
        gap_event_from_copy(copy)
        t2 = time.perf_counter_ns()
        if i < warmup:
            continue
        s1_ns.append(t1 - t0)
        s2_ns.append(t2 - t1)
    return {"S1_parse_copy": summarize(s1_ns),
            "S2_gap_event_from_copy": summarize(s2_ns),
            "frame_bytes": len(stream[0]),
            "frame_shape": "mirror_h + eth + fabric_h + csig_h + witness + payload (gap event)"}


class _TimedInfer:
    """Delegating proxy over ``controller.infer`` that accumulates time in update+localize.

    ``controller/infer.py`` is the ONE frozen inference layer (PREREG section 3.3) and is not
    edited to obtain this split.  The proxy is bound over the module reference that
    ``sublink_feedback`` holds, for the duration of one extra timed pass only, and is removed
    again in a ``finally``.  Every attribute other than the two timed calls is delegated
    unchanged, so the decision the frozen layer makes is identical.
    """

    def __init__(self, module) -> None:
        self._m = module
        self.ns = 0
        # Bind the hot non-timed attributes directly: routed through __getattr__ they would add a
        # Python-level delegation to every on_gap call and land that cost in "rest of on_gap",
        # which is exactly the term the decomposition is trying to read.
        self.Sample = module.Sample
        self.InferState = module.InferState
        self.H_DEFAULT = module.H_DEFAULT

    def __getattr__(self, name):
        return getattr(self._m, name)

    def update(self, *args, **kwargs):
        t0 = time.perf_counter_ns()
        out = self._m.update(*args, **kwargs)
        self.ns += time.perf_counter_ns() - t0
        return out

    def localize(self, *args, **kwargs):
        t0 = time.perf_counter_ns()
        out = self._m.localize(*args, **kwargs)
        self.ns += time.perf_counter_ns() - t0
        return out


def measure_s3_decomposition(iterations: int = DEFAULT_ITERATIONS, seed: int = 1,
                             warmup: int = WARMUP_ITERATIONS) -> Dict[str, Any]:
    """Split S3 into the frozen localizer call pair and everything else ``on_gap`` does.

    S3 is the dominant term, so the reader must be able to see whether the cost is the frozen
    inference layer or the P3 hold/net/coalesce/expand logic added around it.  This is a SEPARATE
    timed pass: the S3 figure reported for the arms is measured without the proxy, so the
    wrapper's own cost cannot inflate it.  The proxied ``on_gap`` median is reported next to it
    so the wrapper overhead is visible rather than assumed.
    """
    expanded: List[Tuple[int, int, int, int, int]] = []
    fb = SublinkFeedback(lambda *key: expanded.append(key), lambda *key: None)
    _prewarm(fb)
    stream = build_event_stream(seed, warmup + iterations, "quarantine")
    events = [gap_event_from_copy(parse_copy(frame)) for frame in stream]  # S1/S2 excluded here

    proxy = _TimedInfer(sfb.infer)
    original = sfb.infer
    sfb.infer = proxy
    frozen_ns: List[int] = []
    rest_ns: List[int] = []
    on_gap_ns: List[int] = []
    try:
        for i, event in enumerate(events):
            epoch = 1 + (i % EPOCH_WRAP)
            fb.begin_epoch(epoch)
            for context in SIBLING_CONTEXTS:
                fb.observe_clean(FAULT_VLINK, context, SIBLING_PACKETS, epoch)
            del expanded[:]
            proxy.ns = 0                      # after the sibling churn: it also calls update()
            t0 = time.perf_counter_ns()
            fb.on_gap(event)
            fb.flush_held()                   # the decision now lands here, not in on_gap
            t1 = time.perf_counter_ns()
            if i < warmup:
                continue
            on_gap_ns.append(t1 - t0)
            frozen_ns.append(proxy.ns)
            rest_ns.append((t1 - t0) - proxy.ns)
    finally:
        sfb.infer = original                  # the frozen module reference is always restored
    frozen = summarize(frozen_ns)
    rest = summarize(rest_ns)
    proxied = summarize(on_gap_ns)
    return {"frozen_infer_update_localize": frozen,
            "rest_of_on_gap": rest,
            "on_gap_under_timing_proxy": proxied,
            "frozen_share_of_proxied_median_pct": 100.0 * frozen["median_us"] / proxied["median_us"],
            "note": ("separate pass; medians of parts do not sum to the median of the whole. "
                     "controller/infer.py is not edited: the split is timed from the outside.")}


def machine_identity() -> Dict[str, Any]:
    """A timing claim without a machine is not reproducible."""
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": "%s %s" % (platform.python_implementation(), platform.python_version()),
        "perf_counter_resolution_ns": time.get_clock_info("perf_counter").resolution * 1e9,
    }


def run_bench(iterations: int = DEFAULT_ITERATIONS, seed: int = 1,
              warmup: int = WARMUP_ITERATIONS) -> Dict[str, Any]:
    return {
        "scope_label": SCOPE_LABEL,
        "disclaimer": DISCLAIMER,
        "measured_stages": list(STAGES),
        "excluded": ["mirror/event transport from the downstream witness to the controller",
                     "BFRT gRPC round trip", "switch-side table programming"],
        "machine": machine_identity(),
        "seed": seed,
        "iterations": iterations,
        "warmup_iterations_discarded": warmup,
        "arms": {arm: run_arm(arm, iterations, seed, warmup) for arm in ARMS},
        "isolated_reference": measure_isolated(
            build_event_stream(seed, warmup + iterations, "quarantine"), warmup),
        "s3_decomposition": measure_s3_decomposition(iterations, seed, warmup),
    }


# ----------------------------------------------------------------------------- reporting
def _stage_rows(arm_result: Dict[str, Any]) -> List[str]:
    rows = []
    for stage in STAGES:
        s = arm_result["stages"][stage]
        rows.append("  %-48s %10.3f %10.3f %10.3f %8d"
                    % (STAGE_LABELS[stage], s["median_us"], s["p95_us"], s["p99_us"], s["n"]))
    t = arm_result["total"]
    rows.append("  %-48s %10.3f %10.3f %10.3f %8d"
                % ("TOTAL S1+S2+S3+S4", t["median_us"], t["p95_us"], t["p99_us"], t["n"]))
    return rows


def format_report(result: Dict[str, Any]) -> str:
    m = result["machine"]
    out = [
        "P3 feedback path — controller-host software segment (microbenchmark)",
        "",
        "machine   : %s | %s | %s" % (m["platform"], m["machine"], m["python"]),
        "processor : %s" % (m["processor"] or "unreported"),
        "clock     : time.perf_counter_ns, resolution %.0f ns" % m["perf_counter_resolution_ns"],
        "run       : seed %d, %d timed iterations per arm, first %d discarded"
        % (result["seed"], result["iterations"], result["warmup_iterations_discarded"]),
        "",
        "SCOPE",
        "  measured : S1 parse_copy -> S2 gap_event_from_copy -> S3 SublinkFeedback.on_gap",
        "             -> S4 BfrtHealthGate.install for every expanded key (fake entry_add, no I/O)",
        "  excluded : %s" % "; ".join(result["excluded"]),
        "  label    : %s" % result["scope_label"],
        "  %s" % result["disclaimer"],
        "  hold     : a loss-bearing event is now HELD for up to one epoch for reorder netting",
        "             before it is decided.  That holding time is a deliberate mechanism delay,",
        "             not CPU work, and it is in NO figure below: S3 times on_gap + flush_held",
        "             back to back, i.e. the cost of a complete decision, never its elapsed time.",
        "  cite     : TOTAL and S3 are the figures this project cites.  The per-stage S1/S2",
        "             medians are IN-LOOP costs, sensitive to the surrounding controller work",
        "             (the quarantine arm's pooled-baseline sibling updates roughly double them);",
        "             they are not isolated call costs.  Quote the isolated reference for those.",
        "",
        "  %-48s %10s %10s %10s %8s" % ("stage", "median us", "p95 us", "p99 us", "n"),
    ]
    for arm in ARMS:
        a = result["arms"][arm]
        out.append("")
        out.append("arm %s" % arm)
        out.extend(_stage_rows(a))
        if a["copies_parsed_per_iteration"] > 1:
            out.append("  one iteration = a loss event AND its reorder receipt, so S1/S2 cover %d copies"
                       % a["copies_parsed_per_iteration"])
        out.append("  decisions %d | coalesced %d | reorder credits %d | netted out %d | "
                   "fake-BFRT entry_add calls %d"
                   % (a["quarantine_decisions"], a["coalesced_events"], a["reorder_credits"],
                      a["netted_out"], a["installs_recorded_by_fake_bfrt"]))
    iso = result["isolated_reference"]
    out.append("")
    out.append("isolated reference (same frames, tight loop, no controller state around the call)")
    for stage in ("S1_parse_copy", "S2_gap_event_from_copy"):
        st = iso[stage]
        out.append("  %-48s %10.3f %10.3f %10.3f %8d"
                   % (STAGE_LABELS[stage], st["median_us"], st["p95_us"], st["p99_us"], st["n"]))
    out.append("  frame parsed: %d B — %s" % (iso["frame_bytes"], iso["frame_shape"]))
    out.append("  A gap-event copy is parsed deeper than an ordinary data copy, which is why this")
    out.append("  reference is above a plain-copy parse figure; compare like frames only.")

    d = result["s3_decomposition"]
    out.append("")
    out.append("S3 decomposition (separate pass; frozen infer.update+infer.localize timed from outside)")
    out.append("  %-48s %10.3f %10.3f %10.3f %8d"
               % ("frozen localizer (infer.update + infer.localize)",
                  d["frozen_infer_update_localize"]["median_us"],
                  d["frozen_infer_update_localize"]["p95_us"],
                  d["frozen_infer_update_localize"]["p99_us"],
                  d["frozen_infer_update_localize"]["n"]))
    out.append("  %-48s %10.3f %10.3f %10.3f %8d"
               % ("rest (P3 hold, net, coalesce, expand, bookkeeping)",
                  d["rest_of_on_gap"]["median_us"], d["rest_of_on_gap"]["p95_us"],
                  d["rest_of_on_gap"]["p99_us"], d["rest_of_on_gap"]["n"]))
    out.append("  %-48s %10.3f" % ("on_gap under the timing proxy (overhead visible)",
                                   d["on_gap_under_timing_proxy"]["median_us"]))
    overhead = (d["on_gap_under_timing_proxy"]["median_us"]
                - result["arms"]["quarantine"]["stages"]["S3_on_gap_decision"]["median_us"])
    out.append("  %-48s %10.3f" % ("  minus the arm's unproxied S3 median = wrapper cost",
                                   overhead))
    out.append("  the frozen localizer is %.1f %% of the proxied on_gap median.  The wrapper cost"
               % d["frozen_share_of_proxied_median_pct"])
    out.append("  above is this decomposition's error bar against the arm's own S3 (it is inside")
    out.append("  run-to-run noise and may print negative); whatever of it is real sits in the")
    out.append("  untimed remainder, so 'rest of on_gap' is the upper-bound side.  %s" % d["note"])

    q = result["arms"]["quarantine"]["total"]["median_us"]
    c = result["arms"]["coalesced"]["total"]["median_us"]
    r = result["arms"]["reorder_credit"]
    out += [
        "",
        "marginal cost of one decision (quarantine median - coalesced median): %.3f us" % (q - c),
        "cost of correctly NOT acting on a reorder (reorder_credit total median): %.3f us"
        % r["total"]["median_us"],
        "  %d of %d reorder pairs (timed + warm-up) netted to zero: no decision, no gate write."
        % (r["netted_out"], r["total"]["n"] + result["warmup_iterations_discarded"]),
        "  Netting is not free: the receipt's arrivals still enter the shared pool, so this arm",
        "  still pays one pooled infer.update even though it correctly installs nothing.",
        "  All figures carry the same label: %s" % result["scope_label"],
    ]
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Time the controller-host segment of the P3 feedback path (S1..S4). "
                    "Excludes mirror transport and BFRT gRPC + switch programming; the "
                    "end-to-end feedback latency is not measured here.")
    ap.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                    help="timed iterations per arm (default %d)" % DEFAULT_ITERATIONS)
    ap.add_argument("--seed", type=int, default=1, help="synthetic event stream seed")
    ap.add_argument("--json", action="store_true", help="emit the result document as JSON")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    result = run_bench(args.iterations, args.seed)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
