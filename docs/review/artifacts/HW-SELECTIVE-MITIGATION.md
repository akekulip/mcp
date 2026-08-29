# Selective mitigation on silicon — 2026-08-29

Quarantining one behavioural sublink moves that traffic class off the directed link while every
other class keeps using it. This is the mitigation half of the thesis, on a Tofino 1.

## Method

One entry written to `tbl_health_gate` through the switch-side agent:

    Q src_leaf=0 dst_leaf=2 spray=0 ctx=2 -> sublink_reroute(alt_spray=1)

i.e. quarantine only the `>=1024 B` class on the directed link selected by spray 0, and send it via
spray 1 instead. Then 50 packets of each of three size classes from Vision.

## Result

| sublink | before | after | delta | |
|---|---:|---:|---:|---|
| vlink 0, ctx 0 (small) | 958 | 984 | **+26** | unaffected |
| vlink 0, ctx 1 (medium) | 2294 | 2321 | **+27** | unaffected |
| **vlink 0, ctx 2 (large)** | 276 | 276 | **+0** | **quarantined** |
| vlink 1, ctx 0 | 24 | 48 | +24 | normal spray share |
| vlink 1, ctx 1 | 126 | 150 | +24 | normal spray share |
| **vlink 1, ctx 2** | 264 | 314 | **+50** | **all of it rerouted here** |

50 packets were sent per class, and the ledger closes for each:

- ctx 0: 26 + 24 = 50, split across both vlinks by the hash spray, exactly as before the quarantine
- ctx 1: 27 + 24 = 51, same
- **ctx 2: 0 + 50 = 50 — every packet of the affected class avoided the quarantined sublink**

## Why this is the point of the abstraction

The quarantine was keyed on `(src_leaf, dst_leaf, spray, ctx)`. Traffic sharing the **link** but not
the **class** (ctx 0 and ctx 1 on vlink 0) was untouched, and traffic sharing the **class** but not
the **link** (ctx 2 on vlink 1) was untouched — it is the destination of the reroute. Only the pair
was acted on.

A per-link mitigation would have taken all three classes off vlink 0 to remove the fault affecting
one of them. Here the directed link stayed in service for 53 of the 151 packets that crossed it,
and would stay in service for all traffic of the two healthy classes indefinitely.

## The write cost, measured

The gate write is the switch-side component of the feedback path. Over 20 alternating
install/delete operations through the agent:

| | microseconds |
|---|---:|
| median | **1,990** |
| min / p90 | 1,782 / 2,204 |
| max (outlier) | 11,771 |
| agent transport (ping) | 3-5 |

So a health-gate write costs about **2.0 ms**, and the agent's own transport is negligible against
it. That number independently lands on the 2.20 ms "minimal one-slot controller reference" the
simulation has been using as a swept parameter, so that assumption is now grounded in a hardware
measurement rather than assumed.

## What this does NOT establish

- **The loop is still open.** This quarantine was installed by hand, not by a controller reacting to
  the gap event. `controller/sublink_feedback.py` has not driven a hardware decision.
- **No end-to-end latency.** The 2.0 ms is the write step only. The full path — gap event, mirror
  transport, collector, decision, write, gate live — is still unmeasured, and it is the go/no-go
  figure: simulation says restoration becomes structurally impossible past 60 ms.
- **No restoration.** The quarantine was not lifted by evidence; nothing exercised probation.
- One configuration, one run, no repetition and no intervals.

## An SDE constraint worth recording

SDE 9.13.2 permits only ONE client to bind the pipeline config: a second client is refused with
"Client ID N trying to bind but Client ID M already owns this P4", and a client that has not bound
cannot read either ("Unable to get bound_program"). A separate reader process therefore cannot
coexist with a writer. The agent consequently serves both reads and writes over one binding, which
is also the correct shape for a real controller.
