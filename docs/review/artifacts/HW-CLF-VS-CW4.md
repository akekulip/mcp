# What CLF sees that C-W4 structurally cannot — measured

**Date:** 2026-08-30. Program `mcp_fabric_clf_eg.p4`, source sha256 prefix `540d03a7a7c295f2`.
Sublink 2 (vlink 0, context 2) on the first directed link. PREREG rule 1 requires CLF to detect
where ordinary C-W4 detects 0%; this is the first hardware measurement of that comparison.

## How C-W4's state is read

`reg_wit_observed` (`p4/witness/mcp_fabric_clf_eg.p4`) is the register the gap signal derives from:

```p4
if (md.wit_result.gap != 0) { v = 0; } else { v = v |+| 1; }
```

It increments on each arrival and **resets to 0 when a discontinuity is seen**. If nothing
arrives, the action never executes and the value is frozen. So the counter distinguishes three
states directly: growing (healthy), reset (gap detected), frozen (no arrivals).

Read via the agent's `R 2` command. It counts roughly two increments per packet because the
witness counts an arrival at more than one hop, so absolute values are not packet counts; only
the changes matter here.

## Result 1 — a dark sublink and an idle sublink are the same to C-W4

Five repetitions, 60 packets per arm where sent:

| arm | C-W4 observed delta (5 runs) | CLF frontier | CLF verdict |
|---|---|---|---|
| A. IDLE, nothing sent | 0, 0, 0, 0, 0 | TX=0 RX=0 | IDLE |
| B. DARK, 60 sent and all dropped | **0, 0, 0, 0, 0** | TX=60–62 RX=0 | **BLACKHOLE, 5/5** |
| C. HEALTHY, 60 delivered | −8, −4, −4, 0, 0 | TX=60 RX=60 | HEALTHY |

Arms A and B produce **identical** C-W4 state — no change, in every run — and CLF separates them
in every run. That separation is the primitive's reason to exist: TX records that the source
committed the packets, so "nothing arrived" can be read as a failure rather than as absence of
demand.

Arm C's negative deltas are not noise: the counter *decreased*, which only happens on a reset,
because arm B's 60 destroyed packets are detected as a gap the moment traffic resumes. That is
measured directly below.

## Result 2 — C-W4 detects a total blackhole, but only retroactively

One controlled sequence on the same sublink:

| step | C-W4 observed | reading |
|---|---:|---|
| 1. clean traffic, 40 packets | 201 | accumulating normally |
| 2. **blackhole armed, 60 packets destroyed** | **201** | **unchanged — no signal during the outage** |
| 3. blackhole cleared, 20 packets sent | **45** | reset from 201, so the gap fired at the first survivor |

C-W4 is not permanently blind to a total context blackhole. It is blind **for exactly as long as
the blackhole lasts**, and recovers the information only when a later packet in the same context
survives to expose the discontinuity. During the outage its downstream state is unchanged.

This is a sharper and more defensible claim than "C-W4 detects 0%": the mechanisms differ in
*when* evidence exists, not merely whether. A detector that reports a link is dark only after it
comes back cannot drive mitigation while the link is dark.

## Scope and what this does not establish

* One directed link (source leaf -> spine); see `HW-CLF-FRONTIER-PLACEMENT.md` for why coverage
  does not currently extend to the second.
* `n = 5` for the A/B comparison; `n = 1` for the retroactive sequence, which is deterministic
  and mechanistically explained by the register definition above.
* This reads C-W4's **observed counter**, the register the gap signal is computed from. The
  mirror/gap-event transport path was not separately instrumented in this run, so the claim is
  about the witness state, not about end-to-end event delivery.
* `all_context_blackhole` is still unmeasured, and it carries its own kill criterion: a fully
  dark link is what ordinary link management already detects.
