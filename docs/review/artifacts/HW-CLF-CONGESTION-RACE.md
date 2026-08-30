# CLF: congestion does not fake a blackhole, and the guard interval is required — 2026-08-30

Two results on Tofino 1 with `mcp_fabric_clf_eg`: the post-TM soundness argument is now measured
rather than argued, and the epoch race the design anticipates is reproduced and explained.

## 1. `congestion_no_fault` — PREREG decision rule 2 PASSES

vlink 0 shaped to a trickle (the control plane reported `max_rate 0 Gb/s`), then blasted with
120,000 frames at 361 kpps ~= 4 Gbit/s. **No fault was injected.** The traffic manager discarded
the overwhelming majority.

    FALSE BLACKHOLES FROM CONGESTION: 0

This is the decisive test of the post-TM placement. Had TX been marked before the traffic manager,
the source would have recorded "sent" for every packet the TM then destroyed, RX would have seen
almost none, and `TX & ~RX` would have reported a blackhole on a healthy link — making the
mechanism unusable on any congested fabric. Because TX marks in EGRESS, a discarded packet never
reaches the mark, and congestion reads as HEALTHY or IDLE.

Until this run, that property rested on where a table sits in the pipeline. It is now a
measurement.

## 2. The IMPOSSIBLE state is a reader artifact, and the guard interval is its fix

The frozen truth table has no entry for `TX=0, RX=1` — arrival without departure is impossible
across one directed link — so `sim/clf/verdict.py` returns IMPOSSIBLE and the PREREG requires it be
reported as a harness defect, never classified as a link state. It fired:

    vlink 0 ctx 0 : TX=0 RX=1 -> IMPOSSIBLE

**Cause, reproduced deliberately.** Both banks were zeroed while packets were in flight. A packet
that had already marked TX arrived after the zero and marked RX, leaving RX set with TX clear. Three
things confirm it: the anomaly was on ctx 0, which the probe never sends; the TX mask was missing
exactly that bit; and re-zeroing on an otherwise idle fabric reproduced it from background traffic
alone —

    F 0 0  TX=0x0000  RX=0x0001     (no traffic sent by the experiment)

**With a guard interval — quiesce, zero, quiesce, then measure — the artifact disappears:**

| | |
|---|---|
| IMPOSSIBLE states | **0** |
| BLACKHOLE verdicts | **0** |
| sublinks HEALTHY | **7 of 7** across vlinks 0, 1, 2 |

So this is not a defect in the frontier. It is the failure mode that double-buffered banks and a
guard interval exist to prevent, demonstrated by omitting them. The operating rule follows directly:
**a reader must compare the INACTIVE bank after a settling interval and must never zero the active
bank while traffic is in flight.**

## Consequence for the reset discipline

Every per-trial reset in this campaign used a bare zero with no guard. That is safe for the results
already recorded — the blackhole detection showed RX missing exactly the injected context, which a
stale mark would have masked rather than created — but it is not safe in general, and any
false-blackhole rate measured with a bare zero would be contaminated by this artifact rather than by
the mechanism.

## What remains unmeasured

- The guard interval is qualitative here: "long enough that no packet straddles the zero". It has no
  measured value, and the bank-flip path itself has not been exercised (bank 0 throughout).
- n=1 for congestion. No repetition, no rate, no interval.
- `all_context_blackhole`, `direction_only`, reorder, wrap and controller-restart scenarios are
  still untested.
- The distributed agent exchange is still not exercised: both frontiers are on one chip.
