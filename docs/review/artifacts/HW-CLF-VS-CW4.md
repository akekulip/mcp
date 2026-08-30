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

---

# Result 3 — `all_context_blackhole`, and its kill criterion

PREREG rule 1 names two scenarios. `selective_blackhole` is covered above; this is the second.

## Reaching four contexts without jumbo frames

`ctx = (dscp_class << 2) | size_bin`. Size bin 3 needs `total_len >= 2048`, which exceeds the
interface MTU of 1500 — a first attempt at a 2128-byte frame failed with `OSError: [Errno 90]
Message too long`. Varying the OTHER dimension supplies a fourth id at a small frame size, so the
probe uses contexts 0, 1, 2 (size bins, class 0) and 4 (size bin 0, class 1). Size bin 3 is
therefore untested at this MTU.

Baseline, 20 packets per context, no fault: `20/20`, `22/22`, `20/20`, `20/20`.

## Result

All four sublinks armed on vlink 0, 20 packets per context:

| context | CLF TX | CLF RX | CLF verdict | C-W4 observed before | after |
|---|---:|---:|---|---:|---:|
| 0 | 20 | 0 | BLACKHOLE | 80 | **80** |
| 1 | 22 | 0 | BLACKHOLE | 680 | **680** |
| 2 | 20 | 0 | BLACKHOLE | 133 | **133** |
| 4 | 20 | 0 | BLACKHOLE | 42 | **42** |

Injector drop counter: 84 (82 probe packets plus background on the same sublinks), so the fault
is confirmed in the data and not merely on the command line.

**CLF detects 4 of 4. C-W4's counters are byte-identical before and after — 0 of 4.** With every
context dark there is no surviving packet in any context, so no discontinuity can ever be
computed; this is the strongest form of the structural blindness, not a rate.

## The kill criterion, tested

The scenario carries its own objection: if an entire link goes dark, ordinary link management
already catches it, and CLF adds nothing. Measured while all four contexts were dark:

```
dp164  BF_SPEED_25G True   True   frames_rx=375  frames_tx=4823
```

**The physical port stays `up=True`.** The failure is confined to one virtual link — one TM queue
— on a port that remains healthy and continues carrying other virtual links, so the port-up/down
signal that link management watches shows nothing.

### Where this argument is and is not strong

Honest scope: in this emulation a "directed link" is a TM queue on a shared physical port, so the
port necessarily stays up. On a real fabric a directed link is a physical link, and an
all-context blackhole caused by a *hard* failure would coincide with link-down, where CLF would
indeed add nothing.

The scenario is meaningful for the case this project is actually about: a **gray** failure, where
forwarding is broken while the link stays up. The measurement shows exactly that signature — a
port reporting healthy while every context on it is dark. It does not, and cannot from this
testbed, establish how often real fabrics fail that way.
