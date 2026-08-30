# What all four CLF defects had in common, and the redesign that removes the class

**Date:** 2026-08-30. **Program:** `p4/witness/mcp_fabric_clf_eg.p4`.
Follows `HW-CLF-FRONTIER-HOP.md`, which records the four defects individually.

## The common cause

Every one of the four was silent, and they were silent for the same reason:

```p4
RegisterAction<bit<8>, ...>(reg_rx_frontier) rx_seen = { rv = v; v = 1; }
```

`v = 1` is an idempotent write into a **bit<8>** register: seven of the eight bits were unused,
and the write discarded how many packets arrived. So `RX > 0` meant only "at least one packet,
from any source, at any time in this epoch". A single stray packet was indistinguishable from a
link at full load.

That is what made each defect a wrong answer rather than an error:

| defect | the RX bit came from |
|---|---|
| no zero step in the driver | a previous run's traffic |
| source leaf marked its own egress | a packet that had crossed no link |
| bank parity erased by `act_transit` | the other epoch's traffic |
| background packet between zero and arm | traffic that was not the measurement |

A one-bit flag cannot express *implausibly few*. Fix the four sources and a fifth will find the
same hole.

## The second, deeper finding: RX was on the wrong side of the traffic manager

TX is marked in **egress**, deliberately: post-TM, so our own queueing cannot be blamed on the
link. RX was **also** in egress — at the receiver. The mirror-image justification was never made,
and it does not hold: a packet that crosses the link cleanly, arrives, and is then dropped by the
*receiving* switch's traffic manager never marks RX.

The queue in question belongs to the receiver's **outgoing** link, so the failure mode is
congestion on the *downstream* link being reported as a blackhole on the *upstream* one.

### Measured on silicon

Spine downlink (vlink 10, dp174 qid0) shaped to 100 kb/s against a ~1.1 Mbit/s probe, no fault
injected anywhere. Port counters across one 400-packet probe:

| port | delta | meaning |
|---|---:|---|
| dp9 rx | +408 | probes enter the switch |
| dp164 tx | **+408** | every packet crossed link 0 |
| dp172 rx | +408 | every packet arrived at the spine |
| **dp174 tx** | **+96** | only 96 survived the spine's OWN traffic manager |

Link 0 delivered 408 of 408, and **76% of those deliveries were invisible to a post-TM RX mark**.
The undercount is a property of the receiver's queue, not of the link.

### Why the presence bit hid this too

With `v = 1`, 96 survivors and 408 survivors are the same value, so the congestion test passed —
`TX=0x0006 RX=0x0006`, zero blackholes, PREREG rule 2 satisfied. It passed **because the encoding
was insensitive**, which is the same property that let one stray packet mask a total blackhole.

That coupling is the reason the two changes below are not independent. Counting alone, with RX
left in egress, would have converted rule 2 from a pass into a false STARVED verdict on a link
that delivered everything. **The sensitivity fix requires the placement fix.**

## The redesign

1. **RX moves to the receiver's INGRESS.** TX post-TM at the sender means "we really put it on
   the wire"; RX pre-TM at the receiver means "it really came off the wire". Their difference is
   then exactly link loss and nothing else.
2. **Both frontiers become saturating counters** (`v = v |+| 1`) in the same bit<8> registers,
   using the SALU shape already proven in this program (`reg_attn`, `reg_wit_observed`).

Saturation costs nothing where it matters: if RX has saturated, the link is carrying traffic and
cannot be starved, so the ratio is only consulted while RX is small — exactly the regime the rule
decides.

### Two consequences that were not the goal

* **In ingress `md.hop` names the hop the packet is AT**, so entries `{1, 2}` are simply correct.
  The original author's numbering was right for the intended placement; the table had ended up in
  the wrong control.
* **Coverage doubles.** The destination leaf records the second link's arrival in ingress, before
  `csig` is removed at `LAST_HOP`. That link finally has an arrival counterpart, so TX can safely
  commit it too (`tbl_tx_frontier` entries `{1, 2}`). CLF previously covered one directed link.

### Cost

**11 ingress / 5 egress — unchanged.** Moving a stateful table into the ingress pipeline and
widening both frontiers from flags to counters cost zero additional stages and zero wire bytes.

## Validated on silicon

| condition | TX | RX | verdict |
|---|---:|---:|---|
| healthy fabric, no fault | 255 | 255 | HEALTHY |
| total blackhole on ctx 2 | 255 | 0 | BLACKHOLE |
| **downstream congestion, no fault** (spine TM discarding 76%) | 255 | **255** | **HEALTHY** |
| congestion AND blackhole | 255 | 0 | BLACKHOLE |

The third row is the point: under the receiver's queue discarding most of the traffic, the link is
still correctly reported healthy, because RX no longer measures the receiver's queue.

## New verdict class

`STARVED` (`sim/clf/verdict.py:verdict_counts`) covers the band the old encoding folded into
HEALTHY: source committed, arrivals present but far below commitment. **BLACKHOLE keeps its exact
meaning** — RX == 0 with positive source evidence — so results decided under the presence-bit
encoding remain comparable, and STARVED is reported separately rather than merged into the
blackhole metric. This is a PREREG amendment, not a redefinition of an existing rule.

## Harness lesson, paid for twice today

`bash val.sh | head -4` closed the pipe, SIGPIPE killed the script after it had armed a blackhole
and before its final clear, and the injector stayed armed. Every port measurement taken afterwards
read zero packets leaving the source and was interpreted as shaper behaviour. Separately, three
`$(ssh ...)` command substitutions returned empty strings, so `$((A-B))` evaluated `0-0` and
printed a delta of 0 that had never been measured.

Both produced the *expected* answer for the wrong reason, which is the failure mode this
repository's standing rules exist to catch: a teardown step that can be skipped by a signal is a
fault injector left armed, and a shell variable that can be empty is a measurement that can be
fabricated. Print the raw readings, not just the difference.
