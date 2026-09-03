# Silicon detection- and localization-fidelity of the receiver ledger — 2026-09-03

Real-Tofino evaluation captured on the last day of switch access, to anchor the paper's detection
and localization claims on hardware rather than simulation alone. Program: `mcp_fabric_ledger`
(wire-reduction, 2-byte witness, build `6ace4fb1`), live on the shared Tofino 1. Baselines
(SprayCheck-Z, FlowPulse-θ) are passive host-side systems and cannot run on this fabric, so the
head-to-head stays in the software replay harness (`sim/baselines/`); what silicon adds is that
**MCP's own side of that comparison is measured, not modelled.**

Every existing silicon detection artifact used a single deterministic 5-packet drop
(`HW-SELECTIVE-DETECTION.md`, `HW-LEDGER-WIRE-REDUCTION-SMOKE-TEST.md`). Missing was the **loss-rate
regime**: does the ledger recover loss accurately down to 1e-4 — the regime where the passive
baselines collapse (SprayCheck-Z 0% at 1e-4, FlowPulse earlier) — with no false positives? These
two experiments close that gap.

## Method

Traffic from Vision (`multicontext_probe.py`, 1400 B payload, DSCP→context) at 20 k pps. The exact
`A <sublink> <D>` injector arms exactly D post-stamp drops on a chosen behavioural sublink; the
ledger's recovered loss is `Δ(reg_wit_seq) − Δ(reg_wit_observed)` read via the gate agent's `R`
census. `reg_wit_seq` is 16-bit, so Δseq is taken mod 65536 and every cell sends < 65536 packets
(one wrap at most). Ground truth is the exact armed count D. Injectors cleared before and after
every cell.

## Result 1 — detection fidelity across the loss regime (sublink 2, vlink 0, ctx 2)

Expect recovered = D exactly; clean expects 0.

| cell | packets N | D injected | rate D/N | Δseq | Δobs | recovered | match |
|---|---|---|---|---|---|---|---|
| clean | 20,000 | 0 | 0 | 20,000 | 20,000 | **0** | ✓ (FP = 0) |
| — | 20,000 | 0 | 0 | 22,050 | 22,050 | **0** | ✓ (FP = 0, earlier v1 run) |
| 1e-2 | 5,000 | 50 | 1.0e-2 | 5,000 | 4,950 | **50** | ✓ |
| 1e-2 (rep) | 5,000 | 50 | 1.0e-2 | 5,000 | 4,950 | **50** | ✓ |
| 1e-3 | 30,000 | 30 | 1.0e-3 | 30,000 | 29,970 | **30** | ✓ |
| 1e-3 (rep) | 30,000 | 30 | 1.0e-3 | 30,000 | 29,970 | **30** | ✓ |
| 5e-4 | 40,000 | 20 | 5.0e-4 | 40,000 | 39,980 | **20** | ✓ |
| 1e-4 | 60,000 | 6 | 1.0e-4 | 60,000 | 59,994 | **6** | ✓ |
| 1e-4 (rep) | 60,000 | 6 | 1.0e-4 | 60,000 | 59,994 | **6** | ✓ |

**Every cell recovers the exact injected loss, down to 1e-4 (6 drops in 60,000 packets), with zero
false positives on 40,000+ clean packets.** Detection is O(1): the ledger reports the exact loss on
the first census read after the traffic, at any rate — it does not accumulate packets to reach a
statistical threshold. This is the structural contrast with the passive baselines, whose
packets-to-detect scales as ~1/p and whose action rate collapses below 1e-3
(`BASELINE-COMPARISON-2026-09-02.md`): here the witness recovers a 1e-4 grayhole exactly, on real
silicon, where the sprayed-fabric state of the art detects nothing.

## Result 2 — localization fidelity (inject sublink 2, read all 8 tracked sublinks)

50 drops injected on sublink 2 only; 20,000 packets sent across all four contexts (5,000 each) so
every sublink carries traffic.

| sublink | vlink | ctx | Δseq | Δobs | recovered loss |
|---|---|---|---|---|---|
| **2** | 0 | 2 | 5,000 | 4,950 | **50** ← injected |
| 6 | 0 | 6 | 5,000 | 5,000 | 0 |
| 10 | 0 | 10 | 5,000 | 5,000 | 0 |
| 14 | 0 | 14 | 5,000 | 5,000 | 0 |
| 162 | 10 | 2 | 4,950 | 4,950 | 0 |
| 166 | 10 | 6 | 5,000 | 5,000 | 0 |
| 170 | 10 | 10 | 5,000 | 5,000 | 0 |
| 174 | 10 | 14 | 5,000 | 5,000 | 0 |

**The loss is attributed to exactly the injected directed link (sublink 2, +50) and to no other —
zero false attribution across the other seven sublinks.** Sublink 162 (the downstream hop of the
same context) correctly shows 4,950 arrivals rather than 5,000 — the 50 packets dropped at the
sublink-2 uplink never reached the downlink to be stamped — yet manufactures no loss there
(Δseq = Δobs). This is exact single-directed-link localization on silicon, and it is the property
the passive baselines structurally lack: under spraying they collapse to the ambiguous
{uplink, downlink} 2-set at low loss (`LOCALIZATION-COMPARISON-2026-09-02.md`), while the per-hop
witness disaliases the two directed links directly.

## Scope and honesty

- Single independent per-link fault, PREREG v1.9; 4-leaf × 2-spine virtual fabric (the testbed's
  fixed loopback topology). Correlated/common-mode faults remain out of scope.
- Overhead (2 B/packet, ~0.14% at 1400 B; 12/5 MAU stages; SRAM/TCAM) is from the compile gates
  (`LEDGER-WIRE-REDUCTION-2026-09-02.md`); the ~0.14% added-load figure is computed (2/1404), not a
  saturating-throughput measurement.
- The `A` injector places an exact contiguous burst; total-loss recovery (Δseq − Δobs) is
  magnitude-based and identical for burst vs dispersed loss (dispersed exactness was shown at small
  scale in the smoke tests). These cells measure recovery fidelity and false-attribution, not the
  one-gap-event-per-discontinuity property (covered separately in the model/PTF suite).

These two results give the paper its silicon anchor: on real Tofino, the receiver ledger recovers
per-directed-link loss exactly from 1e-2 down to 1e-4 with zero false positives, and localizes it to
the exact directed link with zero false attribution — the measured half of the "what a 2-byte
witness buys" story, in the regime where the passive baselines fail.
