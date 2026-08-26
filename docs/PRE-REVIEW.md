# PRE-REVIEW — MCP "the data plane decides what to measure" (SIGCOMM'27 / NSDI'28 PC-member pass, pre-build, 2026-08-25)

Produced by the `ieee-journal-reviewer` agent; saved verbatim by the main session. Inputs: plan
§"The gap and the thesis"; `docs/NOVELTY-MATRIX.md`; `paper/PREREG.md`; `docs/P4-DESIGN-SPACE.md`
§§1,5,6,11,12; `HURDLES.md`. Prior art verified against primary sources: SprayCheck (arXiv
2605.03702), OmniPath Ping abstract, FANcY (SIGCOMM'22), FS-INT (ICT Express 2019), Cisco adaptive-INT patents.

## Summary as a reviewer would state it
Two-timescale measurement controller for sprayed RDMA/AI fabrics: per-(dst-leaf, spine) attention
weight in SALU registers gates mirroring / a CSIG-style tag toward uncertain or deviant paths (fast
loop); NIC reflects quantized per-path RTT/ECN/PSN-gap evidence into that register; a constrained
bandit with shadow prices sets per-resource budgets per collective iteration (slow loop). Stated
crisply, the contribution is smaller than the plan's language.

## 1. Top-3 rejection reasons

### R1 — "The data plane does not decide; it samples at a rate the controller wrote."
*"The on-chip 'decision' is `rnd < attn` where `attn` is written by the control plane every epoch
and per-path statistics are computed off-chip. That is Sel-INT / FS-INT rate sampling with a
controller-set knob — the same architecture as ChameleMon. The only in-data-plane update is the NIC
evidence packet."* P4-DESIGN-SPACE §5.2 recommends "count on chip, price off chip"; §11 concedes
variance/Z-score cannot live in the SALU; §5.7 has the control plane write `reg_attn`/`reg_thresh`
per epoch. **No autonomous in-switch update rule exists.** PREREG ablation A6 (fast-loop only) is
therefore undefined, and there is no falsification condition for the fast loop.
**MUST:** (i) specify and pre-register the in-switch update rule (e.g. SALU `attn += k` on threshold
exceedance / NIC evidence, `attn -= 1` per N clean samples, clamp — feasible under N8/N9); (ii) add
to PREREG §0: "if A7 (slow-loop only) is within CI of full MCP on H1, the data-plane loop is not the
contribution"; (iii) add a decision-latency hypothesis: fast-loop reaction to a loss step measured on
silicon in µs vs slow-loop ms–s.

### R2 — "The closest competitor never meets the system on real hardware, and the hardware is one chip with software RDMA."
Tier-2 arms are MCP, B3, B9, B11 — **B7 SprayCheck is absent from hardware**, though SprayCheck's
own testbed (2× Tofino-1, CX-6 DX, DCQCN, 16 virtual switches) is stronger than ours. Calibration
covers probe RTT and counter-read latency but not the mechanism under test (gating on real
`deq_qdepth`; NIC-evidence path latency). **Feasibility hole not in HURDLES:** `rdma_rxe` is
go-back-N; under per-packet spraying it will NAK and retransmit continuously (Themis's motivating
problem), so PSN-gap evidence is contaminated by reordering, ECN evidence does not exist (no
DCQCN), and Gloo all-reduce may not complete.
**MUST:** add B7 to Tier-2 arms (a few hundred bytes of P4); add hurdle "rxe under spraying" with a
pass/fail test (all-reduce completes; NAK rate under no-fault spraying = evidence-noise floor); add
fast-loop reaction-time measurement to §9.2(b).

### R3 — "TTL differences come from different localizers, not from measurement steering; and 'equal budget' is not equal."
MCP localizes with Beta-Binomial/Normal-Gamma + CUSUM; B3 by path intersection; B7 by path-set
difference; B2/B4 unspecified. Confounded. H2 (weak dominance in all five units incl. SRAM/stages)
is unpassable against zero-SRAM arms (probe mesh, NIC-only). Budget B must state whether evidence
packets and collector-port mirror bytes count.
**MUST:** add PREREG §3.3 "Common inference layer" — one frozen localizer shared by all arms; restate
H2 as dominance on (F1, β_probe+β_tag) with other units as side constraints or descriptive; define B
to include evidence and mirror bytes wherever they traverse a fabric or collector link.

## 2. Novelty verdict
| Qualifier | Holds against | Thin because |
|---|---|---|
| Per sprayed path | ChameleMon, INTaaS, CoordSamp, DynATOS+, BRIGHT, FANT | SprayCheck/FlowPulse already per-spine in-switch under spraying; OPP per-path by construction. Baseline in 2026. |
| Decision loop in the data plane | every controller-epoch system | As designed, switch applies a controller-written rate. FANcY zooms in-data-plane toward lossy prefixes; FS-INT and Cisco patents decide per packet on queue thresholds. Defensible only with the R1 update rule. |
| NIC+switch jointly | all | **The genuinely unoccupied cell.** Also the one the hardware can least demonstrate (Soft-RoCE, no ECN, reordering-confounded PSN gaps). Rests on ablation C3 shown cleanly. |
| Budgeted multi-resource per iteration | SprayCheck/FlowPulse/OPP | INTaaS primal–dual pricing, BRIGHT posterior-directed budgeting, CoordSamp chance-constrained sampling are prior art. |

Housekeeping: OPP is named in claim (1) but has no PREREG arm — build an OPP-style arm or drop it
from the claim. Do not lead with "attention" (FANT, ChameleMon own the word).

## 3. Weakest link and the single best additional experiment
Weakest: one Tofino-1 pipe, 16 TM queues as virtual links, 3 recirc passes, Soft-RoCE on a lossy
fabric with no PFC/DCQCN/ECN, XDP "NIC" on a 10 G Agilio leg whose port may no longer exist. 3-level
(claim 2) is simulation-only on hardware.
**Survivable scaling:** Tier-2 claims exactly (a) primitives compile + measured cost, (b) fast-loop
reaction latency in µs vs slow-loop install latency, (c) calibrated simulator predicts hardware TTL
on ★ faults within its 95 % band. Say "software-RDMA, lossy, single-chip emulation, as SprayCheck
did" in the first paragraph of Implementation; never call it a "testbed"; drop "3-level" from the
hardware section; rename H6 "simulated CCT overhead".
**Single best experiment:** MCP vs SprayCheck round-robin (B7) vs uniform 1/N (B2) on the same
silicon, same virtual fabric, same budget, F1 at 1e-3 and 1e-2, 10 reps, same localizer. Second:
the rxe-under-spraying no-fault run quantifying the NAK/reorder noise floor.

## 4. Over-claims, unfalsifiable statements, straw men
- Over-claimed: "Nobody steers the measurement budget inside the data plane" (FANcY, FS-INT, Cisco
  patents do) → narrow to "per sprayed path, from fused NIC+switch evidence, under a priced
  multi-resource budget". OPP named without an arm. H6 near-tautological in sim. Hardware NIC arm
  must not be called "MetaRoCE-like" (RTT + reorder-confounded PSN gaps only).
- Unfalsifiable/mis-specified: claim (2) "lossy fabrics" needs a **background-loss sweep factor**
  (0, 1e-5, 1e-4, 1e-3 fabric-wide) — PREREG sweeps only fault loss. Fast loop has no falsification
  condition. H2 unpassable. H5 "≥70 % of oracle" arbitrary → descriptive.
- Straw men: B7 SprayCheck run unchanged on a lossy fabric guarantees false alarms → pre-register
  both "as-published" and "SprayCheck-L" (baseline-loss-aware threshold); claim (2) must beat the
  latter. B11 NIC-only must be allowed to **aggregate across NICs** at a controller (Meta does) —
  otherwise claim (3) is hollow. B1 fixed INT "infeasible at B" must not enter the H1 "best baseline"
  set. B5 must not carry CPRANT's name (content unknown).

## 5. Scores
| Axis | Score | Rationale |
|---|---|---|
| Novelty | 3 | NIC-evidence-into-switch-attention cell is unoccupied and timely; "data plane decides"/"per path" weaker than claimed; pricing is INTaaS/BRIGHT lineage. → 4 with a real in-switch update rule and a clean C3 result. |
| Significance | 4 | Gray failures under spraying in AI fabrics is first-tier in 2026. |
| Soundness of plan | 4 | PREREG well above venue norm; docked for localizer confound, H2, missing background-loss factor, undefined fast-loop rule. |
| Feasibility | 2 | Untested sim chain at 14k runs (H18 >10 min/seed for Llama), rxe under spraying unaddressed, Agilio port uncertain, ≤3 weeks of shared Tofino, SIGCOMM'27 ~January. |

**What would make me accept:** Tier-2 shows on one Tofino-1 that (i) the attention gate reacts to an
injected loss step in µs without controller involvement, (ii) MCP localizes F1/F4 faster than
SprayCheck round-robin and 1/N on the same silicon, same budget, same localizer, (iii) removing the
NIC evidence channel measurably slows localization of access-link and one-direction faults the
switch cannot see alone; Tier-1 extends these to 1k–4k NICs, lossy fabrics with swept background
loss, and 3-level topologies against SprayCheck-L and an aggregating NIC-only arm. The contribution
sentence must be about the fused NIC+switch per-path loop, not "attention" or "learning".

## MUST-FIX before building
1. Pre-register the in-switch attention update rule and a fast-loop falsification condition (R1).
2. Add B7 SprayCheck (as-published + SprayCheck-L) to hardware arms; add an OPP-style arm or drop OPP from claim (1).
3. Common inference layer for all arms; restate H2; define B to include evidence and mirror bytes (R3).
4. Background-loss sweep factor for claim (2); aggregating NIC-only arm for claim (3).
5. HURDLES rows: rxe under per-packet spraying (NAK/reorder floor), ECN absence on NIC arm, dp65 existence, fast-loop latency measurement.
