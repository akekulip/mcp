# MCP panel report — chair's synthesis (2026-08-27)

Panel: six reviewers (SIGCOMM/NSDI PC systems researcher; bandit/QCD theorist; hyperscaler RDMA reliability engineer; Tofino/SmartNIC engineer; anti-over-engineering PC member; IEEE ToN statistical-rigor reviewer; second-year PhD "explain it in five minutes"), plus a literature sweep and a red-team pass that attacked every critique and every proposed idea.

**Verdict: pivot — unanimous (6/6).** Not "revise", not "tune". The engineering is real and honestly reported; the *thesis* is dead at its own pre-registered operating point.

Three chair-level findings, all generated and verified during this review, change the numbers everyone was arguing about. They are in §4 and they are the first things to fix.

---

## 1. Problem framing

**Consensus (all six).** The operational problem is real and first-tier for SIGCOMM'27/NSDI'28: on a per-packet-sprayed fabric every flow touches every path, so a flow-level symptom names no link, and the NIC routes around a sick link before an operator learns which one it is (REPS, arXiv 2407.21625, sub-100 µs failure reroute — `NOVELTY-MATRIX.md` row 26; MetaRoCE; R-Pingmesh SIGCOMM'24). The venue climate confirms it: SprayCheck (arXiv 2605.03702, May 2026), FlowPulse (HotNets'25), OmniPath Ping and CSIG (SIGCOMM'26), Themis (EuroSys'26).

**Consensus on the framing being wrong.** `PREREG §0` frames MCP as an *allocation* problem — a budgeted bandit that decides where to spend a scarce measurement budget. All six reviewers rejected that premise on repo evidence:

- **The rationed resource costs nothing on the fabric.** In `sim/htsim/htsim/sim/mcp.cpp:133-152` a "probe" is a `p->pkts_tx()` / `p->silent_drops()` delta since that link was last read — an exact, noiseless per-link loss observation with no packet on the wire. `run_tier1_cosim.sh:10` rations it to 41 of 1024 uplinks. `mcp.cpp:120-125` writes the same counters for **all 2048 links** (1024 uplinks + 1024 downlinks) every epoch anyway. Priced in `PREREG §2.3`'s own currency, every budgeted arm has β_probe = β_tag = **0**.
- **Proof, verified this session:** the `seed*.counters.csv` files are byte-identical across all five arms (oracle, uniform, random, cusum, mcp) for the same seed — **120/120 arm-seed pairs**. The measurement policy has no effect on the simulated fabric whatsoever. Tier-1 is not a systems experiment; it is a scheduling puzzle played over a fixed trace.
- **The currency is undefined at the operating point.** `§2.3` defines B in five units (β_probe + β_tag as the tested budget; SRAM/stages, NIC reads/s, host CPU as side constraints), default B = 2 %, sweep {0.5, 1, 2, 5, 10, 20} %. Amendment v1.2 then redefines the operating point as *4 % = 41 of 1024 uplinks* — a sixth unit, link count, that appears nowhere in §2.3 — chosen because 2 % was "TOO HARD" by the §10 rule.
- **The binding constraint is evidence, not schedule.** `HURDLES H27`: fault observability is traffic-phased (896/1024 uplinks idle in epoch 10, all busy in epoch 16). The frozen localizer needs ~2 drops per element (`frozen.yaml`: δ = 1e-4, h = 6.5), i.e. ~2e4 packets on the link before any detector can fire.

**Disagreements.** The hyperscaler and Tofino engineers wanted the whole framing to become conservation (count in vs count out), arguing "silent loss has no in-band evidence" (`h7-timing-F1.md`) is a harness artifact, not physics. The ML theorist wanted "observability-gated QCD". The anti-over-engineering member wanted a detector/floor question. The chair sides with the detector/floor framing; observability gating was refuted empirically (§4.3).

**Survived the red team.** "The scarcity is fictional at Tier-1." Attacked on four fronts, all failed. `sim/calib/` — the §9.3 sim↔hardware calibration promised to ground the cost model — does not exist. The only *measured* scarcity anywhere in the repo is control-plane read throughput (`slow-loop-silicon.md`: t_sync 94.7 ms for 64 counter rows + 256 register rows on one chip), and that does not produce a fleet-wide 41-link cap, since 1024 uplinks span 128 switches read in parallel.

**Refuted.** "Control-plane reads are the only real scarcity, therefore the only defensible problem is read scheduling." It cannot be measured on this harness (β_probe = β_tag = 0 for every arm by construction, now verified byte-for-byte); two of its three hardware cost axes are flat (SRAM is quantized at 16 KB — `reg_attn` is 2 blocks whether it holds 256 or 1024 slots); and it is contradicted by a measured 14–22× margin (a single-slot bfrt register read is 1.37 ms and the minimal read+write path 2.20 ms, against a 97.4 µs in-band reaction — `h7-timing-F6.md`).

**Chair's decision.** Drop "budgeted measurement allocation" as the problem statement. The problem is: *on a sprayed fabric, how few packets must cross a gray link before that link is named, and what mechanism reaches that floor?*

---

## 2. Design

**Consensus on what is good and must be kept.**
- The in-switch update rule as built and verified on silicon (`PREREG §7.4` v1.3; `step5-7-silicon-v2.md`): one 32-bit SALU word `{attn16, clean16}`, saturating bump on exceedance, decay every `n_clean` clean packets, 256-row TCAM gate on `attn[15:8]`. Every count exact: 487 mirrored copies against ~500 predicted at P = 1/16 over 2 passes × 4000 packets; fault mirrors 246/246 == `fail_ctr inj_drop`; evidence +1024/pkt in both pipes; `csig.worst_vlink` correct 269/269 (was 0/508 in v1). The loop closes end to end with **no controller** — a shaped uplink drives sampling from 6.25 % to ~100 %.
- The frozen common inference layer (`controller/infer.py`, `PREREG §3.3`) as evaluation discipline. Its recorded hash in `conf/infer/frozen.yaml` (`be12e7b2…`) matches HEAD exactly, verified this session; 36 tests pass; 0 false alarms across the 90 LULESH rehearsal runs after four localizer bug fixes.
- The 4×2 virtual fabric on one chip (9 ingress + 3 egress stages, SDE 9.13.1 and 9.13.2, no ingress headroom — `step7.md`), runtime fault injection with a DirectCounter as ground truth, the htsim/UEC hooks, and the 14-class bf-p4c constraint catalogue.

**Consensus on what is over-engineered.** The slow loop. `controller/mcp_policy.py` is LinUCB over a 7-dimensional hand-built context (`D = 7`) in three variants, with a shadow-price knapsack whose own module docstring states the prices are **inert** in the sim: "in the htsim gate there is ONE resource with unit cost per probe and a hard per-epoch cap, so the prices are inert there (ablation A1 == full MCP in that setting)". The tuning block (730 runs) selected `explore_floor = 0.75` — three-quarters of every epoch's slots reserved, by the code's own comment, "for the least-recently probed elements" — and `COSIM-RESULTS.md` says in its own words "the learner has nothing to learn here". Four ablations of that, plus a matrix whose main block alone is 5,100 runs (`PREREG §11`), does not close before any deadline.

**Consensus on what is missing.** An in-band evidence source for silent loss. Both ends of every virtual link sit on the same pipeline; `p4/mcp_fabric.p4:482` already declares a per-vlink `DirectCounter` attached to the ingress `tbl_vlink` (line 499), and `tbl_eg_vlink` (line 915) has none. The F1 "fast loop" is instead a Python host probe (`nic/evidence_probe.py`, 5 ms grace + 10 ms window).

**Consensus that the actuators are not contributions.** CSIG is shipped and standardized; packet trimming ships on current merchant silicon; drop-event capture (WJH) is years old; NIC per-path counters are commodity (MetaRoCE, Themis). Worse, MCP's tag is single-pipe by construction (`DESIGN-ALTERNATIVES §4.1`: the source leaf never sees a downstream tag), the opposite of deployed CSIG, which reflects the value to the sender. *(The specific standardization dates and product versions in the panel's sweep — UEC CSIG 0.50, an IEEE 802.1 contribution, a Cumulus release number — are not sourced anywhere in this repo; treat them as unverified until fetched.)*

**Disagreements.** The ML theorist wanted the gate reframed as DE-CuSum (Banerjee & Veeravalli, *Data-Efficient Quickest Change Detection in Minimax Settings*, IEEE T-IT 2012) and made the headline hardware claim. The Tofino engineer and PC member wanted per-link conservation or sequence numbering instead. The hyperscaler wanted the gate demoted to a second-stage "zoom" after a counter names the link.

**Survived the red team.**
1. *The learner is a noisy re-implementation of coverage.* Confirmed mechanically: `infer.py`'s forgetting factor is applied inside `_posterior_step`, i.e. only on *observed* epochs, so the reward's variance term is large exactly once per element and its greedy maximiser is "cover the never-probed first". The tuned Tier-1 config is `--learner dlinucb --alpha 0 --explore-floor 0.75`, and in `mcp/seed1000.bridge.csv` every one of the 41 slots went to a never-before-probed link in **21 of the first 27 epochs**.
2. *H3 has no valid test anywhere.* The price λ can never leave 0 in htsim (usage ≤ cap is enforced before the dual step), and there is no multi-resource wiring on the hardware path either.
3. *The two-timescale story has no fault class where both loops matter* — and, a new finding, the hardware "F6" run is a **50 Mb/s max-rate TM shaper on vlink 1** (`h7-timing-F6.md:83`), i.e. `PREREG §5.2`'s **F5 congestion hotspot**, not the pre-registered F6 black-hole. The only H7-supported fault is not a pre-registered H7 fault.

**Refuted.**
1. *"DE-CuSum is the only defensible hardware claim."* Refuted. DE-CuSum's contribution is a deterministic two-threshold on-off control driven by the CuSum statistic, and its own abstract defines its advantage *against* "fractional sampling, in which the observations are skipped using the outcome of a sequence of coin tosses". MCP's gate is a Bernoulli draw with P = attn/65536 — state-dependent fractional sampling, which sits strictly between the two. Adopting the framing would claim 2011–2012 prior art *and* misdescribe the mechanism.
2. *"Per-vlink count mismatch gives a 100 µs F1 fast loop."* Refuted by arithmetic. Median time to the first drop is ln2/(p·R). At p = 1e-3 and the ~75 kpps the F6 session actually put on one vlink, that is 9.2 ms; at the ~300 kpps peak blast demonstrated in `step5-7-silicon-v2.md:235`, 2.3 ms. At 1e-4, 92 ms and 23 ms. No detector, in-band or not, beats the fault's own evidence rate. The right claim is "one pipeline pass after the drop", never "100 µs detection".
3. *Both proposals are prior art in mechanism.* LinkGuardian (SIGCOMM'23, DOI 10.1145/3603269.3604853 — link-local retransmission on Tofino, detecting corruption loss per link and cutting a 1e-3 loss rate by six orders of magnitude at 8 % link-speed cost); FANcY (SIGCOMM'22, inter-switch counter synchronisation on Tofino); LossRadar (CoNEXT'16); RFC 9341 alternate marking. **Correction to the panel's draft:** FANcY *is* in `docs/NOVELTY-MATRIX.md` with a full row (#23) explicitly naming it "the right precedent for data-plane attention", and LossRadar appears inside the ChameleMon row. LinkGuardian, RFC 9341/8321, dDrops and WJH are genuinely absent from the 34-row matrix. The gap is real but narrower than claimed.

**Chair's decision.** Keep the SALU word + TCAM gate as a *second-stage evidence-capture* mechanism, not the headline. Build the in-band per-link loss evidence source (§5). Delete LinUCB, the three variants, the shadow prices, the knapsack and A1–A4 from the contribution set; keep one appendix ablation. Drop the CSIG tag and the NIC evidence producer from the claims; cite CSIG/UEC and keep the tag as an input signal.

---

## 3. Evaluation

**Consensus.** The pre-registration is above venue norm in intent (KM + log-rank, Holm family, censoring, four RNG streams, a common localizer) and has drifted exactly where pass/fail is decided.

- **Metric mismatch with the field.** Nobody in the closest work reports median TTL at one h per arm. SprayCheck reports minimum detectable per-link loss vs training iterations (1.5 % in 1 iteration, 0.5 % in 5, Llama-3-70B, 64 spines) with ROC, at <2 KB SRAM per 32 spines. FlowPulse reports FP/FN at a 1 % threshold per iteration (misses 0.8 % at radix 32). OPP reports 10 ms service tracing at 181 KB SRAM. The QCD literature reports ADD vs ARL at a stated observation cost.
- **The operating point cannot separate arms.** F1 = 1e-4 sits well below every published detection floor; with h = 6.5 and δ = 1e-4 a link needs ~2e4 packets to alarm, so every budgeted arm is evidence-bound.
- **Compliance defects.** τ_slow was redefined post hoc to the full-sweep epoch (ratio 907) after the minimal-path definition gave 22 and "not met" (`h7-timing-F6.md` ratio table). The §6.5 seed commitment was not executed: measured ρ(uniform, random) = 0.05 < 0.3 triggers the escalation clause, which at CV ≈ 0.5 and Holm-adjusted α implies ~50 seeds, while the script printed "verdict OK". `analyze_real.py` computes, by its own docstring, a "KM-free median" despite §2.1 mandating KM medians. `delta_loss` in `frozen.yaml` is set equal to the injected fault rate, by comment. `frozen.yaml` records `baseline_mode: per_element` while every Tier-1 run passes `--baseline-mode pooled`, and the LULESH rehearsal ran under module hash `116ffc9f`, which is no longer reproducible from HEAD. The tree is dirty (modified and deleted result files).
- **Cost of the plan.** Measured per run: median wall **3863 s (64 min)**, range 54–67 min, peak RSS **21.5 GB** (90 runs, `results_real_v12_summary.txt`) — against `PREREG §11`'s estimate of 2–6 min, an error of 10–30× that `HURDLES H18` flagged. The full matrix is ≈18,400 runs (main block 5,100; tuning 4,480), i.e. ~2.2 years of one host or ~54 days of the whole 15-wide fleet — and the main block includes F2–F9, which the simulator does not implement: `sim/htsim/htsim/sim/pipe.h` offers only per-link Bernoulli silent loss with an onset time. There is no flap, no corruption, no black-hole, no latency inflation.

**Disagreements.** ToN reviewer: 50 seeds and full compliance repair first. PC member: replace the matrix with one figure. ML theorist: ADD-vs-ARL curves. Chair: all three, in that order of cost — the compliance repair is a day, the figure is the paper, the ARL axis is affordable only via replay.

**Survived the red team.** The Tier-1/Tier-2 modality mismatch. In htsim a probe reads a *cumulative* counter — skipping is free, and `infer.py` forgets only on observed epochs, so not looking costs nothing. On silicon the gate *samples packets*, and un-sampled evidence is gone: `hw_adapter.aggregate` (lines ~180–207) builds every per-path delivered/lost figure from mirrored copies only, and `reg_attn` is read, per the module docstring, "for logging and §2.3 cost accounting". A sampling-policy claim cannot be made from a read-scheduling simulation. Ablations A6/A7 — one of the two pre-registered falsification conditions — are unrunnable at Tier-1, which has no attention register at all.

**Refuted.** Pricing everything on three hardware axes and declaring full coverage free (§1) — the axes are unmeasurable or flat on this harness. Also refuted: "run the regime map with Thompson sampling" — TS on `infer.py`'s Beta(1,1) priors is a uniform random permutation over never-probed links, which is the *worst* measured arm (random: median 26 under the frozen localizer, 13/30 censored — §4.3).

**Chair's decision.** Replace the 18,400-run matrix with: (a) exact offline replay from the logged per-link counters for every schedule-class arm — now provably sound (§4.2); (b) one figure — packets-on-the-faulty-link (and collective iterations) until localization vs per-link loss rate, with FPR/FNR — plus one hardware table (τ_fast, ADD vs duty cycle, SRAM KB, stages, mirror/collector bytes, control-plane reads/s). TTL_obs (KM, log-rank) becomes secondary. Report τ_slow as a range across controller implementations (2.20 ms minimal slot, 88.8 ms raw sweep, 96.2–116.6 ms Python loop), never as a 100× hurdle.

---

## 4. Results

### 4.1 Every published TTL comes from the wrong detector

`PREREG §3.3` promises "one frozen localizer for all arms". That is true of what the *policies* see and false of what the *metric* uses. `mcp.cpp:133-152` computes `verdict = argmax(ddrop/dtx)` over the probed set if it exceeds a threshold, and writes the `correct` column; `analyze_real.py:read_run` takes TTL as the first epoch at or after the onset epoch with `correct == 1`. `controller/infer.py` never enters the reported number. TTL as published is therefore a **first-hit time** — the first epoch in which an arm probes the faulty link after it has accumulated one drop — which is why `cusum ≡ uniform` per seed in 30/30 seeds and why no post-hit behaviour is ever scored.

Recomputed by the chair from `results_tier1_cosim/moe8x8b_n16/*/seed*.bridge.csv` (the frozen localizer's own `anomaly` and `top` columns, same 30 seeds, same faults, same onsets, same `onset_epoch = floor(onset/epoch)` convention as `analyze_real.py`):

| detector | mcp | cusum (≡ uniform per seed) |
|---|---|---|
| sim ratio rule (as published) | median 18, 1/30 censored | median **15**, 1/30 censored |
| frozen localizer `infer.py` | median **19.0**, 2/30 censored | median **19.5**, 6/30 censored |

Paired under the frozen localizer: MCP faster in 11, slower in 19, sign p = 0.20 — against the published 7/23, p = 0.0052. The headline "MCP is significantly slower than uniform" is an artifact of the wrong detector. The honest statement: **under the pre-registered localizer the arms are statistically indistinguishable, and H1 (≥30 % lower median) is met by none of them.** Both statements falsify the thesis; only one is defensible in a paper.

### 4.2 Replay is exactly sound — verified

The measurement policy does not perturb the simulated fabric. The `seed*.counters.csv` files are **byte-identical across all five arms for every seed: 120/120 arm-seed pairs** (oracle, random, cusum, mcp vs uniform). Two consequences:

1. Offline replay of any read-scheduling policy against the logged counters is not an approximation — it is exact. The M1 harness rests on a verified invariant, not a hope.
2. The 18,400-run matrix exists, for every probe-free arm, only to regenerate a counter trace that is identical for all of them. That alone justifies deleting it.

*Caveat the plan must carry:* the chair's independent replay does **not** yet reproduce the recorded arms bit-for-bit, because the C++ `_candidates` ordering differs from a lexicographic sort of link names, which changes which links a round-robin cursor visits when. Replaying `uniform` from a name-sorted candidate list gives median 19.0 with 7/30 censored, against the recorded cusum-bridge 19.5 with 6/30. Matching the C++ ordering is a concrete, small task, not a research risk.

### 4.3 What no schedule can do, and what one can

Chair's replay, 30 recorded seeds, frozen `infer.py`, h = 6.5, exact counter deltas since each link's last read:

| budget | oracle | uniform RR | load-gated RR | greedy max-unobserved | random |
|---|---|---|---|---|---|
| 10 (1 %) | — | 29 (27 cens) | 29 (28) | 29 (23) | 29 (29) |
| 20 (2 %) | — | 28 (20) | 25.5 (13) | 27 (18) | 29 (23) |
| **41 (4 %)** | **10.0 (0)** | **19.0 (7)** | **19.0 (1)** | **20.0 (7)** | **26.0 (13)** |
| 82 (8 %) | — | 16 (0) | 14 (0) | 14 (0) | 16.5 (7) |
| 200 (19.5 %) | — | 11 (0) | 12 (0) | 12 (0) | 12 (1) |

Median TTL from onset; censored counts in parentheses.

**The decomposition, at budget 41 (median TTL_obs from the first observable drop):** oracle 1 epoch, uniform RR 13, load-gated RR 11. So of the oracle's 10 epochs, ~9 are the fault's own evidence rate (waiting for the traffic phase) and 1 is detector lag; of round-robin's 19, ~12 are pure coverage.

**Load gating is dead.** Computed from the same 30 seeds: at the epoch of the **first observable drop**, the busy-uplink count is **1024 in the median seed, ≥768 in 21/30 seeds, and below 512 in only 2/30** (values 128 and 192). The 128-busy regime of `H27` occurs in epochs where the faulty link is itself idle and drops nothing. Load-gating therefore removes ~0 % of the candidate set exactly when it would have to pay. Its median matches uniform's at 3 of 5 budgets and its p95 is no better at 3 of 5 (worse at 2 %, worse at 8 %, tied at 19.5 %). Its one real effect is on censoring (7/30 → 1/30 at budget 41) — a tail benefit, not a detection-time benefit.

Also killed: the "regime map" (an ARL axis in-loop is unaffordable), the three-axis cost reframing, and any 100 µs target for silent-loss detection.

### 4.4 The counter-argument the panel got wrong

The panel's draft claimed "no schedule can compress detection delay; the floor is the fault's evidence rate". **The repo's own oracle refutes that.** At budget 41 the oracle localizes in 10 epochs against round-robin's 19 — a 47 % reduction, *above* H1's own 30 % bar. Schedule matters, and there is roughly 2× of headroom sitting in the coverage term.

What is true, and what the paper can defend, is narrower and sharper:

1. **Detection delay decomposes into evidence time plus coverage time**, and at sub-1e-3 loss on a sprayed fabric the coverage term dominates and is the only compressible one (9 vs 12 epochs at B = 4 %).
2. **No schedule computable from per-link counters closes that gap.** Uniform 19, load-gated 19, greedy-information 20, LinUCB 19 (§4.1), Thompson/random 26, oracle 10. The reason is informational and we can show it: at the first-drop epoch essentially every uplink is busy, so load carries no signal; and the localizer's statistic is identically zero on every unprobed link, so there is no gradient to follow. The only usable signal is "have I looked here", whose optimal policy is round-robin. Round-robin is already near-minimax for the one thing that can be known.
3. **Silent loss has no in-band evidence in the built system**, so its "fast loop" is a host timer in the same millisecond regime as the controller (τ_fast 10.115 ms, BCa 10.101–10.127; ratio 8.8, CI 8.6–9.1 — H7 fails structurally for the fault class the paper is about). Tightening to `window = 2 ms, grace = 3 ms` reaches 2.028 ms and ratio 43.8, still short of 100, and costs specificity (1 of 6 reps raised a healthy path against 0 of 15 at the default). The floor is the measurement path's RTT tail, ~2.5 ms on this testbed, capping the ratio near 35. This is a property of what was built, not of the ASIC: both ends of every virtual link are on one pipeline and the chip already mirrors every injected drop exactly (246/246).
4. **The congestion fast loop works and is not novel:** CSIG compare-and-replace plus a threshold register, single-pipe. τ_fast 97.4 µs (BCa 67.9–215.1), ramp to saturation 1.209 ms, specificity 0/13 healthy path-instances raised, ratio **907 (452–1143)** against the full-sweep epoch — but **22 (6–27)** against the 2.20 ms minimal controller path, which fails the pre-registered "entirely above 100" criterion. The 88.8 ms denominator is entirely raw bfrt I/O (48.5 ms register read + 29.8 ms counter sync/read + 9.6 ms register write); the Python loop adds a further ~16 ms of `to_dict()` decoding, reaching 96.2 ms observe-only and 116.6 ms when writing, at which point 30/30 epochs overrun a 100 ms budget.
5. **Hardware localizes a path, not a link.** With one source leaf, `vlink:9` (41.44) and `vlink:0` (40.92) — the genuinely faulty uplink — track each other to within 1 %, with the wrong one consistently a hair ahead. Separating them needs a second vantage.

---

## Where we are

**Built and verified (keep):** a 4-leaf × 2-spine virtual fabric on one Tofino 1 (SDE 9.13.1 and 9.13.2, 9 ingress + 3 egress stages, no ingress headroom); per-packet spraying; runtime fault injection with ground-truth counters; the frozen §7.4 attention word and TCAM gate, closing a loop on-chip with no controller and exact counts; a 14-B CSIG-style tag (`csig_h`: worst_hop, worst_vlink, worst_qdepth, worst_tdelta, path_id, epoch); mirror sessions carrying a `mirror_h` with the pass verdict, path id, attention value and ASIC timestamp (30 B as declared at `mcp_fabric.p4:149-163`; `HURDLES H5` records 24 B — one of the two is stale); a bfrt controller loop; an htsim/UEC fork with per-link counters, silent-loss injection, `-rto_min_us` and an epoch scheduler; a co-simulation bridge; a frozen Bayesian + binomial-LLR CUSUM localizer with 36 passing tests and 0 false alarms across 90 rehearsal runs; a 34-system novelty matrix; a pre-registration with amendments v1.2–v1.4 and a written record of every failure.

**Measured (report as-is):** F5-congestion fast loop τ_fast 97.4 µs, specificity 0/13; F1 loss fast loop 10.115 ms, H7 fails; τ_slow 88.8 ms raw / 96.2–116.6 ms in Python; Tier-1 at the frozen point — oracle 8, uniform 15, random 23 under the ratio rule, and MCP 19.0 vs uniform-sweep 19.5 under the frozen localizer (p = 0.20); replay: oracle 10, uniform 19, gated 19, greedy 20, random 26 at B = 4 %; LULESH rehearsal all arms tied; tuning selects a 0.75 coverage floor; 64 min and 21.5 GB per simulation run.

**Not built:** in-band silent-loss evidence; a second source leaf (so no link-level hardware claim); SprayCheck (B7/B7'), FlowPulse and OPP arms on either tier; F2–F9 in the simulator (`pipe.h` has Bernoulli loss only); multi-fault, background-loss and non-stationarity blocks; the Tier-1 tuning block; Tier-2 two-host runs; the §9.3 calibration (`sim/calib/` does not exist).

**Dead:** H1 as pre-registered (not met under either detector). H3 (prices provably inert; no valid test on either tier). H7 for F1 (structural, floored by the measurement path's RTT tail). The 18,400-run matrix (unaffordable and largely unimplemented). "Learned budget allocation" as a contribution.

---

## The contribution we should claim

The panel's first draft claimed "spraying makes gray loss self-localizing, and the floor is the fault's own evidence rate — not the measurement schedule". Three attacks kill that sentence: the mechanism (per-link sequence gap) is topology-agnostic and works identically on ECMP, so spraying is not what makes it work; the repo's own oracle compresses delay by 47 %, so the schedule *does* matter; and comparing an always-on in-band primitive against budget-limited sampling is not an equal-budget comparison. Rewritten to survive all three:

**One idea.** *On a sprayed fabric the operator's signal is link-local or it is nothing — and the cost of not being link-local is a coverage term that no computable schedule removes.* Every published spray-aware detector — SprayCheck, FlowPulse, OmniPath Ping, Pingmesh/R-Pingmesh/Hostmesh, NIC per-path counters — builds an aggregate statistic over many packets and many paths, and pays two costs in series: waiting for the fault to make enough evidence, then waiting for its turn in whatever coverage schedule the aggregate implies. We measure both, show the second dominates and is not compressible from the aggregates themselves, and remove it with a link-local invariant that costs 0.05 % of capacity.

Three claims, each measurable:

- **C1 — the decomposition.** Detection delay = evidence time + coverage time. At the pre-registered point, 30 paired seeds, frozen localizer: 9 epochs evidence, 12 epochs coverage at B = 4 %, with an oracle handed the answer paying 1 epoch of detector lag. Coverage is the dominant and the only compressible term.
- **C2 — the negative result, scoped.** No schedule computable from per-link counters closes the coverage gap: uniform 19, load-gated 19, greedy-information 20, LinUCB 19, Thompson/random 26, oracle 10, across a five-point budget sweep, by exact replay. We publish *why*: at the first-drop epoch the median seed has 1024/1024 uplinks busy, so load carries no signal, and the localizer's statistic is identically zero on every unprobed link, so there is no gradient. Scope is stated plainly — one stationary fault at sub-1e-3 loss — and M1 tests the multi-fault and moving-fault cases before the claim is written.
- **C3 — the link-local alternative, priced.** A per-link sequence gap at the next hop (or an alternate-marking counter diff, RFC 9341) makes the first drop a localized event: coverage time goes to zero and delay collapses to evidence time, ~1/p packets on the faulty link. On Tofino 1 it fits in the same SALU/TCAM budget as the frozen §7.4 attention word, and costs 2 B of shim per packet — 0.05 % of capacity at 4096 B MTU, 0.13 % at 1500 B — against §2.3's default budget of 2 %. Alternate marking costs one bit in an existing field. **The comparison against SprayCheck and against every budgeted schedule is therefore an equal-budget comparison, not a straw man**, and that is the sentence that must appear in the evaluation section. The attention gate becomes stage two: once the link is named, raise mirroring on its paths to capture headers of what is dying, then decay off.

**One plot.** X: per-link loss rate p ∈ {1e-4, 1e-3, 5e-3, 1.5e-2}. Y (log): packets on the faulty link until it is named. Curves: the 1/p information floor; our in-band primitive (on the floor); SprayCheck as published (1.5 % in 1 iteration, 0.5 % in 5, 64 spines, <2 KB per 32 spines) and SprayCheck-L; uniform coverage at budget B and the LinUCB learner (both at coverage × 1/p, indistinguishable from each other); oracle. Two panels: lossless 2-level, where SprayCheck and FlowPulse are valid, and lossy 3-level MoE AlltoAll, where their own §6 sections say they are not. A grad student explains it in one sentence: *"the drop tells you which link it died on, so you only wait for a drop; everything else waits for a drop **and** for its turn in the sweep."*

**Honest novelty position.** The mechanism is prior art — LinkGuardian (SIGCOMM'23) numbers packets per link on Tofino for loss recovery; FANcY (SIGCOMM'22) matches counters between neighbours and is already row 23 of our matrix; LossRadar (CoNEXT'16) diffs digests; RFC 9341 standardizes alternate marking. What is unclaimed is (i) the **decomposition and the paired negative result** on sprayed AI fabrics, with the informational reason it holds; (ii) the **sprayed-fabric instantiation** with multi-vantage intersection for link (not path) attribution on a *lossy*, AlltoAll-dominated fabric where the closest systems state they do not apply; and (iii) the **two-stage composition** — floor-rate detection feeding an in-switch sampling gate that captures the evidence operators act on. We cite all four systems on the first page and stake nothing on the primitive's novelty. The negative result is the paper's second half, not an appendix.
