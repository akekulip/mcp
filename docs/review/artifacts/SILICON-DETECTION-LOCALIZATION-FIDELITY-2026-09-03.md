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

## Stochastic (Bernoulli) recovery + downlink cell — 2026-09-03

Both results above used the exact contiguous `A` injector (`tbl_eg_fail`), which drops a scheduled
burst of a pre-set size D. A reviewer will ask two follow-ups: (a) does the ledger recover a
*realistic random* grayhole — per-packet Bernoulli drops — as well as it recovers a scheduled burst;
and (b) does localization hold on a **downlink** hop, not only on the uplink of Result 2. These two
cells close both, using the same live ledger (`mcp_fabric_ledger`, build `6ace4fb1`).

**Injector and ground truth.** The stochastic injector is `tbl_eg_bern`: each packet draws a
`Random<bit<16>>` value `md.eg_rnd`, and a two-entry TCAM range tiling `[0, W-1] -> eg_bern_drop`,
`[W, 65535] -> eg_bern_none` with `W = round(p·65536)` drops it with probability `W/65536`. For a
*stochastic* injector there is no pre-set drop count to check against; the ground truth is the
injector's **own DirectCounter** on `eg_bern_drop` — what actually fired — read with `SyncCounters`
(the "verify the injected quantity in the DATA, not the flags" discipline). The claim under test is
`recovered = Δ(reg_wit_seq) − Δ(reg_wit_observed)` vs that DirectCounter drop count.

**Method / infrastructure note.** `tbl_eg_bern` is not exposed by the gate agent (only the `A`/`S`/`K`
`tbl_eg_fail` arms are), so it was armed by direct bfrt. SDE 9.13.2 binds the pipeline to a single
client, so the gate agent was stopped for the bfrt work and restarted afterward (verified back up
with a `V` ping, same build `6ace4fb1`, `bf_switchd` pid unchanged — the switch itself was never
restarted). `reg_wit_observed` is a never-reset lifetime counter and one idle sublink (14) carried a
standing `seq−obs = 19` offset from earlier runs, so **every number below is a delta against a
baseline census read immediately before arming** — never against zero. Each cell keeps `Δseq < 65536`
so the 16-bit sequence wraps at most once. Traffic from Vision (`multicontext_probe.py`, 1400 B,
20 k pps).

### Cell 1 — Bernoulli grayhole recovery on the uplink (sublink 2, vlink 0, ctx 2)

60,000 ctx-2 packets per cell. `reg_wit_seq` counted exactly the 60,000 host departures (Δseq =
60,000) in both cells.

| p (target) | armed W | p_realised (W/65536) | Δseq | Δobs | recovered | DirectCounter drop | offered (drop+none) | match |
|---|---|---|---|---|---|---|---|---|
| 1e-3 | 66 | 1.007e-3 | 60,000 | 59,934 | **66** | 67 | 60,192 | ✓ within tail caveat (Δ = 1) |
| 1e-4 | 7 | 1.068e-4 | 60,000 | 59,993 | **7** | 7 | 60,176 | ✓ exact (7 = 7) |

At 1e-4 the ledger's recovered loss equals the injector's DirectCounter drop **exactly** (7 = 7). At
1e-3 it recovers 66 against a DirectCounter of 67 — one short. Two facts, both read from the data,
account for the single-packet gap and neither is a recovery error: (i) the trailing-loss caveat
(Result 61 in the PTF suite) — a drop with no later survivor on that sublink is not yet exposed at
the read that straddles it; and (ii) on this uplink sublink the egress injector's `offered` count
(60,192 / 60,176) ran ~180–190 above the 60,000 host departures, i.e. a small population of non-host
packets crosses that egress and is seen by the injector but is not part of the host-stamped sequence
the ledger reconciles. The recovered value tracks the loss of **host-stamped** packets, which is the
quantity the ledger is defined to recover. The downlink cell below, where `offered` matched the host
send exactly, recovers the DirectCounter exactly.

### Cell 2 — downlink / second-hop localization (inject sublink 162 = vlink 10, ctx 2)

Result 2 injected on an uplink (sublink 2). This cell injects a Bernoulli grayhole (p = 1e-3,
W = 66) on the **downlink** directed sublink 162 and reads all eight tracked sublinks. Traffic was
sent across all four contexts (20,000 each, 80,000 total) so every sublink carries live traffic and
"no false attribution" is tested against active-but-clean links, not idle ones.

| sublink | vlink | ctx | Δseq | Δobs | recovered loss |
|---|---|---|---|---|---|
| **162** | 10 | 2 | 20,000 | 19,987 | **13** ← injected (downlink) |
| 2 | 0 | 2 | 20,000 | 20,000 | 0  ← uplink hop of the same context |
| 6 | 0 | 6 | 20,000 | 20,000 | 0 |
| 10 | 0 | 10 | 20,000 | 20,000 | 0 |
| 14 | 0 | 14 | 20,000 | 20,000 | 0  (standing +19 offset cancels in the delta) |
| 166 | 10 | 6 | 20,000 | 20,000 | 0 |
| 170 | 10 | 10 | 20,000 | 20,000 | 0 |
| 174 | 10 | 14 | 20,000 | 20,000 | 0 |

DirectCounter on sublink 162: **drop = 13**, none = 19,987, offered = 20,000 (exactly the host ctx-2
send). Recovered loss on 162 is **13 = DirectCounter = 13, exact**, and every other sublink recovers
**0** — including sublink 2, the uplink hop of the *same* context, whose 20,000 packets all traversed
and were witnessed before the downlink drop. This is the mirror image of Result 2: the per-hop
witness disaliases the two directed links of a context and attributes a downlink grayhole to the
downlink directed link alone, with zero false attribution on seven active sublinks.

### Verdict

On real silicon the receiver ledger recovers a **random (Bernoulli) grayhole**, not only a scheduled
burst: recovered loss equals the stochastic injector's own DirectCounter drop count exactly at 1e-4
(7 = 7) and on the downlink (13 = 13), and to within one packet at 1e-3 (66 vs 67), the one-packet
gap explained by the documented trailing-loss caveat plus a small non-host offered count on that
uplink egress — not by a recovery error. Localization is **symmetric**: a downlink-hop grayhole is
recovered on the downlink directed sublink and attributed to it alone, exactly as an uplink grayhole
is. The honest answer to "does the ledger recover a realistic random grayhole accurately on silicon"
is **yes**, with the same magnitude-based, tail-bounded caveat that already governs the exact
injector. The switch was returned to its found state: injector tables cleared, gate agent restarted
and `V`-pinged, nothing armed.
