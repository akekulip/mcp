# Numbers sheet for paper/ton — every number in the draft, with provenance (2026-09-03)

Transcribed by the PI from the committed artifacts while drafting; nothing computed anew. Use this
sheet to audit the manuscript: every figure in `sections/*.tex` must trace to a row here.
Abbreviations: BC = `docs/review/artifacts/BASELINE-COMPARISON-2026-09-02.md`; LC =
`LOCALIZATION-COMPARISON-2026-09-02.md`; SC = `SCALING-CURVE-A3-2026-09-03.md`; CF =
`CORRELATED-FAULT-STRESS-2026-09-03.md`; WR = `LEDGER-WIRE-REDUCTION-2026-09-02.md`; SI =
`SILICON-DETECTION-LOCALIZATION-FIDELITY-2026-09-03.md`; SA = `HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md`.

## Setup parameters (Sections II, IV)
| item | value | source |
|---|---|---|
| replay topology | n_leaves = 4, k = 8 spines, 64 directed links (2·4·8) | LC "Fairness"; CF config |
| spray model | i.i.d. uniform across k = 8 | BC "Fairness" |
| healthy background loss | 1e-5 | LC; CF config |
| bootstrap epochs | 10 | BC scenario; sweep script `bootstrap_epochs=10` |
| detection epoch volume | 2,000,000 packets per epoch (fleet), raised from 200,000 | BC "Two real methodological bugs" |
| detection budget | 80 post-onset epochs = 160 M packets | BC "Detection results"; sweep `max_post_onset_epochs=80` |
| localization epoch volume | 2,000,000 packets per ordered leaf pair per epoch | LC "Budget disclosure" |
| localization budget | 60 post-onset epochs | LC "Budget disclosure" |
| correlated window | 40 post-onset epochs | CF config |
| seeds | 50 per cell | BC, LC, CF |
| SprayCheck s | 3.24, calibrated at λ = 2.5 M under its Poisson model | CF config; sweep `SprayCheckDetectorCalibration.get(2_500_000)` |
| FlowPulse threshold | 1 % fixed; single-epoch FPR 0.0000 at 2 M/epoch; false-alarmed 100 % at 200 k | BC "bugs"; `THRESHOLD_1PCT` |
| relative spray noise at 200 k | ≈ 0.6 % | BC "bugs" |
| CI method | Wilson 95 %; percentile bootstrap on set size; paired exact McNemar | BC, LC headers |
| silicon switch | Intel Tofino 1, SDE 9.13.2, program `mcp_fabric_ledger` build 6ace4fb1 | SI header; WR §5 |
| silicon fabric | 4 leaves × 2 spines virtual, cage 5↔6 4-lane 25G DAC loopback, one TM queue per virtual link | SI "Scope"; CLAUDE.md testbed |
| tracked sublinks | 1024 (directed vlink × ctx) | BC overhead table ("every one of 1024 links") |
| traffic | Vision host, 1400 B payload, 20 k pps, DSCP→context | SI "Method" |
| seq register | 16-bit (wraps at 65536); observed register 32-bit lifetime | SI "Method"; WR |
| model tests | 9 PTF tests pass (items 60–68) | WR §3 |

## Fig. 1 / Table I — detection (Section V), 50 seeds, FP = 0.00 all cells
| p | Ledger act / median pkts | SprayCheck-Z | FlowPulse-θ | source |
|---|---|---|---|---|
| 1.5 % | 1.00 [0.93,1.00] / 22.0 M | 1.00 / 24.0 M | 1.00 / 22.0 M | BC table; SC table |
| 1.0 % | 1.00 / 22.0 M | 1.00 / 26.0 M | 1.00 / 22.0 M | same |
| 0.5 % | 1.00 / 22.0 M | 1.00 / 32.0 M | 0.38 [0.26,0.52] / 88.0 M | same |
| 1e-3 | 1.00 / 22.0 M | 0.78 [0.65,0.87] / 114.0 M | 0.00 [0.00,0.07] / never | same |
| 1e-4 | 1.00 / 22.0 M | 0.00 [0.00,0.07] / never | 0.00 / never | same |
Ledger IQR 22–24 M; detects at first post-onset epoch (median epoch 10 = onset) — SC finding 1.
SprayCheck IQR (24,24) M at 1.5 % → (82,148) M at 1e-3 — BC. FlowPulse IQR at 0.5 % (46,132) M — BC.
"114 M is 5× MCP" — SC finding 3. SNR condition λp > s√λ ⇒ λ > s²/p² — SC finding 2.

## Table II — localization (Section VI), 50 seeds, generous 60-epoch budget
Ledger: exact 1.00 [0.93,1.00], size 1.00, wrong 0.00 in every cell, both families — LC finding 1.
Down family (S0→L0): SC 1.00/0.96/0.34/0.00/0.00 exact; amb 0.00/0.04/0.66/1.00/0.26; miss 0/0/0/0/0.74; size 1.00/1.04/1.70/2.00/2.00. FP-θ 0.94/0.22/0.00/0.00/0.00; amb 0.06/0.78/0/0/0; miss 0/0/1/1/1; size 1.18/2.74. — LC down table.
Up family (L1→S0): SC 1.00/1.00/0.26/0.02/0.00; amb 0/0/0.74/0.92/0.26; miss 0/0/0/0.06/0.74; size 1.00/1.00/1.78/1.98/2.00. FP-θ 0.00 exact, miss 1.00 at all rates. — LC up table.
McNemar: ties p = 1.0 at 1.5 % (both) and 1.0 % (up); all other diffs p ≤ 3.6e-12. — LC.
FlowPulse uplink dilution: ~1/(senders); 1.5 % uplink loss across 3 senders ≈ 0.5 % port deficit < 1 % threshold — LC finding 3.

## Table III + silicon prose (Section VII)
Exact injector cells (sublink 2): clean 20,000→0; clean 22,050→0 (v1 run); 5,000/50→50 (×2); 30,000/30→30 (×2); 40,000/20→20; 60,000/6→6 (×2). Clean total 42,050 ("more than 42,000"). — SI Result 1.
Uplink localization: 50 drops on sublink 2, 20,000 packets (5,000 per ctx), sublink 2 = 50, seven others = 0; sublink 162 shows Δseq=Δobs=4,950. — SI Result 2.
Bernoulli uplink: p=1e-3 W=66 realised 1.007e-3, 60,000 pkts, recovered 66 vs DirectCounter 67, offered 60,192; p=1e-4 W=7 realised 1.068e-4, recovered 7 = 7, offered 60,176. Offered excess ≈ 180–190 above 60,000. — SI Cell 1.
Bernoulli downlink: sublink 162, W=66, 80,000 pkts (20,000 per ctx); recovered 13 = DirectCounter 13; seven others 0. — SI Cell 2.

## Tables IV–V — correlated gate (Section VIII), 50 seeds, 40 epochs, 64 directed links
R1 (recall / exact-all / FP union,final / mean-false): M=2 0.5 %: Ledger 1.00/1.00/0.00,0.00/0.00; SC 1.00/0.28/0.72,0.00/1.20. M=3 0.5 %: SC 1.00/0.18/0.82,0.02/1.44. M=2 1e-3: SC 0.75/0.00/0.98,0.52/2.54. M=3 1e-3: SC 0.63/0.00/0.96,0.54/2.58. FlowPulse recall 0.00 (FP 0.02 union at M=3 0.5 %). — CF R1 table.
R2 (FP union/final; mean-false union/final): shock 0.5 %: Ledger 1.00/1.00, 64.0/64.0; SC 0.20/0.02, 0.48/0.04; FP-θ 1.00/1.00, 64.0/33.3. shock 0.1 %: Ledger 1.00/1.00, 64/64; SC 0.28/0.02, 0.68/0.04; FP-θ 0/0. — CF R2 table.
R3: shock 0.1 % culprit 1 %: Ledger 1.00/0.00/1.00,1.00/63.0; SC 1.00/0.86/0.14,0.00/0.22; FP-θ 1.00/0.00/1.00,0.50/3.0. shock 0.5 % culprit 5 %: Ledger 1.00/0.00/1.00,1.00/63.0; SC 1.00/0.98/0.02,0.00/0.02; FP-θ 1.00/0.00/1.00,1.00/33.9. — CF R3 table.
Realised loss verified: R1 0.005 vs 1e-5; R3 0.05/0.01 vs 0.005/0.001. — CF cross-checks.

## Table VI — cost (Section IX)
wit_h 4 B → 2 B; added load 4/1404 ≈ 0.28 % → 2/1404 ≈ 0.14 %; ingress stages 11 → 12 (ceiling), egress 5 → 5; tables 40 → 41; SRAM 89 → 91; TCAM 15 → 16; map RAM 27; meter ALUs 7; stat ALUs 5; 0 errors, 5 warnings both; identical on 9.13.1 and 9.13.2. — WR §2, §5.
Per-directed-sublink state 6 B (16-bit + 32-bit). SprayCheck < 2 KB, one flow at a time, ~1 min reset; FlowPulse SRAM not stated; SprayCheck ±0.25 % prioritized-flow distortion. — BC overhead table.

## Discussion numbers
Soak: 57/57 recovery cycles; two unarmed sublinks one "stamp with no arrival" each; ~3,200 historical cycles clean; MAC counters + 30 s idle window rule-outs. — WR §7; SA.

## Headline sentences (abstract / intro / conclusion)
1. Flat ~22 M packets, action 1.00, FP 0.00, 1.5 % → 1e-4 (BC/SC).
2. SprayCheck 24 → 114 M, action 1.00 → 0.78 → 0.00 (BC/SC).
3. FlowPulse fails one order earlier: 0.38 at 0.5 %, 0.00 at 1e-3 (BC).
4. Exact DL localization 1.00 all cells; SprayCheck ties at 1.0–1.5 %, pair at 1e-3 (LC).
5. Silicon exact recovery 1e-2 → 1e-4 (6 in 60,000), FP 0 on > 42,000 clean (SI).
6. Bernoulli 7 = 7 at 1e-4, 66 vs 67 at 1e-3; downlink 13 = 13 (SI).
7. R1 holds/widens; R2 ledger flags all 64; SC FP 0.02 final; R3 SC exact-all 0.86–0.98 (CF).
8. Cost 2 B, ~0.14 %, 6 B/sublink, 12/5 stages, +1 stage, 91/16 SRAM/TCAM (WR).

## CONFLICTS noticed (flagged, not resolved)
- BC "Detection results" prose says ledger median "22.0–24.0 M" while the table shows 22.0 M at every
  rate; SC gives median 22.0 M with IQR 22–24 M. The draft uses 22.0 M median, IQR 22–24 M.
- BC overhead table describes the 4-byte version (pre-reduction); WR supersedes it with 2 B / 0.14 %.
  The draft reports both, labelled.
- SI Result 1 "zero false positives on 40,000+ clean packets" vs the two clean cells summing to
  42,050; the draft says "more than 42,000".

## 2026-09-03 revision (referee response) — new and superseding numbers
Sources: BC3 = `BASELINE-COMPARISON-SWEEP-2026-09-03.json` (post-onset origin; supersedes the
2026-09-02 file, which included 20 M of warm-up); FL = `FLOOR-SWEEP-2026-09-03.json`; LC3 =
`LOCALIZATION-COMPARISON-SWEEP-2026-09-03.json`; CF3 = `CORRELATED-FAULT-STRESS-SWEEP-2026-09-03b.json`;
RL = `READ-LOOP-BENCH-2026-09-03.md`; AI = `APP-IMPACT-HTSIM-MAKEBREAK-2026-09-03.md`.

| item | value | source |
|---|---|---|
| Ledger post-onset median packets, 1.5 %…1e-4 | 2 M (IQR 2–2; 2–4 at 1e-4), epoch 10 = first post-onset | BC3 |
| Ledger at 5e-5 / 2e-5 / 1e-5 | 6 M (IQR 4–8, epoch 12) / 36 M (26–44, epoch 27) / no detection | BC3 |
| SprayCheck-Z post-onset | 4 / 6 (6–8) / 12 (11.5–16) / 94 M (62–128, action 0.78) / none at ≤1e-4 | BC3 |
| FlowPulse-θ post-onset | 2 / 2 (2–4) / 68 M (26–112, action 0.38) / none at ≤1e-3 | BC3 |
| Separation at 1e-3 | 94 M / 2 M = 47× | BC3 |
| CounterPair-0B σ=0 | identical to ledger, every cell | BC3 |
| CounterPair-0B σ=1e-4 FP | 0.28 (≥0.5 %), 0.94 (1e-3), 1.00 (≤1e-4); action 1.00; at p=f action 0.62 (noise) | BC3 |
| CounterPair-0B σ≥1e-3 (incl. 2.6e-2) FP | 1.00 at every p | BC3 |
| Phantom-loss std | ≈ λσ/√6: ≈10 pkts at σ=1e-4, ≈2 700 at 2.6e-2 (λ=250 k) | model, BC3 |
| Read loop | 2.6 ms per sublink; 347.5 ms median (304–358) per 1024-sublink census | RL |
| Wrap bound | 2.17 Mpps/port at 1438 B wire; 30 ms per wrap; ≤187 kpps per sublink at 350 ms | RL |
| Floor sweep, action at p=f / 2f / 5f | 0.00 / (0.18, 1.00, 1.00) / 1.00 at f=1e-6, 1e-5, 1e-4 | FL |
| Floor sweep, median epochs after onset at 2f / 5f / 10f / 50f | f=1e-6: –, 14, 5, 1; f=1e-5: 18, 3, 1, 1; f=1e-4: 8.5, 2, 1, – | FL (median_epoch − 9) |
| SprayCheck at p=5e-4 over f=1e-5 / 1e-4 | action 0.16 / 0.06 | FL |
| Localization CounterPair σ=0 | exact 1.00 every cell | LC3 |
| Localization CounterPair σ=0.026 | exact 0.00 [0,0.07], wrong 1.00, set size 2.88–3.00 | LC3 |
| R4 incast 0.5 % / 0.1 %, ledger | FP 1.00/1.00, mean false 8.0 (final) | CF3 |
| R4 incast, SprayCheck | FP union 0.26 / 0.32, final 0.02; mean false 0.60/0.72 union, 0.04 final | CF3 |
| R4 culprit outside (u13 1 %) | ledger recall 1.00 exact-all 0.00 false 8.0; SC 1.00 / 0.96 / FP 0.04→0.00; FP-θ recall 0 | CF3 |
| R4 culprit inside (d00 1 %) | ledger 1.00 / 0.00 / false 7.0; SC 1.00 / 0.92 / FP 0.08→0.00; FP-θ 1.00 / 0.00 / false 3.0 union, 0.88 final, FP 1.00→0.32 | CF3 |
| App impact | CCT 3.58752 s → 3.63638 s = +1.362 % at 1e-3, τ=40 ms, 255 drops / 307 609 pkts; ~99.5 % absorbed; no actuator in htsim | AI |
| Added load by packet size (2 B / wire bytes incl. 20 B preamble+IFG) | 64 B: 2.4 %; 256 B: 0.7 %; 1400 B payload: 0.14 %; 9000 B: 0.02 % | computed |
| Anomaly | 2/57 (two-byte) vs 0/100 (four-byte, matched); MAC 9 224/9 224; idle trigger 3 of 14 after walk-back | SA §7 |
| Decision rule | α=0.05; ratios {2,5,10,50,200}; floor window 20 epochs; w_min 0.05 | `comparison.py:make_mcp_loop` |
