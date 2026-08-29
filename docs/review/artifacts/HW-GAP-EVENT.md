# The gap event reaches the collector, on silicon — 2026-08-29

The full observability path exists on hardware: a conditional fault confined to one behavioural
sublink produces a data-plane event that leaves the switch, arrives at the collector, and decodes
with correct attribution.

## Method

`tbl_eg_fail` armed on sublink 2 (vlink 0, ctx 2 = the >=1024 B class) for 5 packets, seq
[209..213]. 120 packets of 1400 B payload sent from Vision. Collector: `tcpdump -Q in` on dp9
filtering `ether proto 0x88f1`, decoded with the same field offsets the PTF suite uses.

## Result

    mirror copies captured: 19
    GAP EVENT: sublink=2 (vlink 0 ctx 2)  gap=0xFFFB -> 5 lost  observed_packets=55
               flags=0x8  inner_link=2  inner_seq=214
    total gap events: 1

Every field is exactly the predicted value:

| field | value | why it is right |
|---|---|---|
| `sublink` | 2 | vlink 0 x ctx 2 — the event names the behavioural sublink, so it is actionable rather than a bare loss alarm |
| `gap` | `0xFFFB` | 2^16 - 5; the injector's own DirectCounter reports 5 dropped |
| `inner_seq` | 214 | drops were 209..213, so 214 is exactly the survivor that exposed the gap |
| `inner_link` | 2 | agrees with `sublink` — mirror attribution matches the copied witness, the cross-check `p4/ptf/gap_event/test.py` asserts |
| `flags` | `0x8` | GAP_EVENT_FLAG |
| count | **1** | one forced event per discontinuity, not one per lost packet — the coalescing contract holds on silicon |

19 mirror copies arrived and exactly one carried the gap flag, so the event is cleanly separable
from ordinary attention/CSIG traffic by flag alone.

## An open question from the runbook, now answered

The hardware runbook flagged as unverified whether `$mirror.cfg` is pipe-scoped on SDE 9.13.2, and
warned that gap events arm on the loop ports (**pipe 1**) while the collector is dp9 (**pipe 0**),
so a pipe-scoped mirror session would make gap events silently invisible. **It is not pipe-scoped
here:** the event crossed from pipe 1 to pipe 0 with a single `$mirror.cfg` write and no per-pipe
handling. That removes the first suspect from the C1 latency measurement's failure list.

## The chain that now exists on hardware

    conditional fault (one traffic class, one directed link)
      -> per-sublink sequence witness detects the discontinuity
      -> data-plane event, one per discontinuity
      -> mirrored across pipes to the collector
      -> decoded with the sublink identity intact

## What is still missing

- **No decision.** Nothing consumed the event, `controller/sublink_feedback.py` was not driven by
  it, and `tbl_health_gate` was not written. The loop is open.
- **No latency number.** Both ends of the interval are instrumented (`mirror_h.tstamp` is 48 bits
  of `ig_intr_md.ingress_mac_tstamp`) but the measurement has not been run. This remains the
  go/no-go figure: simulation says restoration is structurally impossible past 60 ms and the
  mechanism stops entirely at 106.6 ms.
- **One run.** No false-event rate, no interval, no repetition.
- `tbl_wit_verdict` still fails to allocate (H42), so `wit_ctr` remains unavailable.
