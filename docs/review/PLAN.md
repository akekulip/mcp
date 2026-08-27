# MCP plan — 2026-08-27 → submission

Target: **SIGCOMM'27**, deadline assumed ~29 Jan 2027 (`HURDLES H15`: CFP not out; Philip confirmed the venue 2026-08-25; re-verify monthly). Fallback: **NSDI'28 spring**, ~Apr 2027. Five months of calendar, one person plus AI agents, one Tofino, two hosts (Vision 72 c / 250 GB, Hulk 72 c / 125 GB), 64 min and 21.5 GB per htsim run, fleet width 15 concurrent (Vision 10 / Hulk 5, `H26`).

Reframed thesis, and what would kill it:

> On a sprayed fabric, detection delay is evidence time plus coverage time; the coverage term
> dominates at sub-1e-3 loss and is not compressible by any schedule computable from per-link
> counters; a link-local in-band invariant removes it for 0.05 % of capacity.

Three things can kill it, in order of cheapness: (1) a counter-computable schedule closes a material share of the oracle's 47 % gap, or the negative result fails to hold under multiple or moving faults; (2) the in-band check produces false gaps under spraying at a rate above the fault rate; (3) the check does not fit the chip. M1 tests (1) in days on data already on disk; M2 tests (2) and (3) on silicon.

Owners: **P** = Philip (hardware sessions, cabling, sudo, submissions, final judgement), **C** = Claude (code, harness, analysis, drafts), **A** = agents (`deep-research` / `literature-reviewer` for sources, `builder`+`qa-verifier` for baselines, `ieee-journal-reviewer` for the adversarial gate, `ieee-paper-figures` for figures).

---

## M0 — Pre-registration repair and honest re-issue · 28 Aug – 4 Sep · owner C, sign-off P

**Goal.** Every number in the repo is computed by the detector the pre-registration names, the budget has one currency, and the dead hypotheses are retired on the record before new work starts.

**Work.**
1. **Detector provenance (blocking).** `sim/gate/analyze_real.py` must compute TTL from the frozen localizer's `bridge.csv` (`anomaly == 1 && top == faulty`), not from the sim's `correct` column (`mcp.cpp:133-152` ratio rule). Re-issue the pilot table. Verified values: MCP 19.0 (2/30 censored) vs cusum/uniform-sweep 19.5 (6/30), paired 11/19, sign p = 0.20 — against the published 18 vs 15, p = 0.0052. Keep the ratio column as a labelled diagnostic.
2. **KM medians everywhere.** §2.1 requires medians read from the KM curve; `analyze_real.py`'s own docstring admits it computes a "KM-free median". Fix and re-run all summaries.
3. **Budget currency.** One tested unit: β_probe + β_tag in bytes over fabric capacity (§2.3), with SRAM KB, MAU stages, mirror/collector bytes and control-plane reads/s reported beside every arm as side constraints. Zero-probe arms report zero. Retire "4 % = 41 of 1024 uplinks" as a *budget* — link count is not one of §2.3's five units; keep 41 as the probe-arm operating point and label it as such. Price the M2 shim explicitly (2 B/packet = 0.049 % at 4096 B MTU) so the equal-budget comparison is on the record from the start.
4. **Record the replay-soundness finding.** The `counters.csv` files are byte-identical across all five arms for every seed (120/120 pairs). State it in §9.1: at Tier-1 the measurement policy does not perturb the fabric, so β_probe = β_tag = 0 for every budgeted arm, H6 is untestable for probe-free arms, and offline replay is exact rather than approximate.
5. **Retire on the record:** H1 as stated, H3 (λ provably pinned at 0 in htsim; no multi-resource wiring on hardware), H5, the 18,400-run matrix, "attention"/"bandit"/"shadow prices" in the contribution sentence, the CSIG tag and `nic/evidence_probe.py` as contributions.
6. **Add, in the PREREG hypothesis namespace (H1–H7 is full; use H8/H9 — *not* H28/H29, which collide with `HURDLES`):** H1' (coverage-gap attainment: the primitive reaches evidence time + ≤1 epoch), H7' (reaction = one pipeline pass; ADD vs pre-change duty cycle at fixed false-alarm rate; τ_slow reported as the range 2.20 ms / 88.8 ms / 96.2–116.6 ms), **H8** (false-gap floor of the in-band check), **H9** (schedule-invariance of median detection delay among counter-computable policies, with the oracle gap reported as the headroom). Decouple `delta_loss` from the injected rate (fixed grid, swept). Record that the hardware "F6" run is §5.2's F5 congestion (a 50 Mb/s TM shaper on vlink 1), not F6 black-hole.
7. **Hygiene:** align `conf/infer/frozen.yaml`'s `baseline_mode` with what the runs pass (`pooled`) — the recorded module hash `be12e7b2…` already matches HEAD, verified; note that the LULESH rehearsal's `116ffc9f` is not reproducible from HEAD and mark those results as superseded. Commit with a clean tree. Re-run §6.5 power on TTL_obs with the measured CV and ρ = 0.05 and record the seed count it implies (~50) or the explicit decision not to meet it. Reconcile the `mirror_h` size (30 B in P4 source vs 24 B in `HURDLES H5`).

**Metric / proof.** The re-issued pilot table plus a diff of every changed number, in `PREREG §14`.
**Compute.** None (analysis only).
**Gate.** If the re-computed pilot shows any arm ≥30 % below the best baseline under the frozen localizer, H1 is alive and M1 becomes the main block. Expected: it does not.

---

## M1 — Replay harness, the decomposition, and the scoped negative result · 31 Aug – 11 Sep · owner C

**Goal.** Establish, cheaply and paired, (a) how detection delay splits between evidence and coverage, (b) that no counter-computable schedule closes the coverage gap, and (c) that (b) survives multiple and moving faults — and replace the simulation matrix with a method that costs seconds instead of hours.

The panel's first draft framed this as "prove no schedule compresses detection delay". That is refuted by the repo's own oracle (10 vs 19 epochs at B = 41, a 47 % reduction above H1's bar). The goal is the decomposition plus the *computability* result, which is what actually survives.

**Work.**
1. Build `sim/gate/replay.py`: read `seed*.counters.csv` (per-link cumulative tx/rx/drop per epoch, logged for **all 2048 links** every epoch by `mcp.cpp:120-125`), replay any schedule against it, feed the frozen `infer.py`, emit TTL and TTL_obs. Soundness is already proven (counters policy-independent, 120/120). The remaining validation task is to match the C++ `_candidates` ordering so the replayed `uniform` arm reproduces the recorded arm seed-for-seed; a name-sorted candidate list currently gives 19.0 / 7-censored against the recorded 19.5 / 6-censored.
2. Score every schedule class on the 30 recorded seeds at budgets {1, 2, 4, 8, 19.5 %}: uniform RR, random, load-gated RR (tx > 0 since last read), threshold-gated RR (tx ≥ 2/δ), greedy max-unobserved-traffic, Thompson on the Beta posteriors, LinUCB MCP as tuned, oracle. Chair's first pass at 4 %: oracle 10.0 (0 censored), uniform 19.0 (7), gated 19.0 (1), greedy 20.0 (7), random 26.0 (13); TTL_obs 1 / 13 / 11 for oracle / uniform / gated.
3. **Semi-synthetic multi-fault and moving-fault replay** — this closes the biggest review hole and costs nothing. Inject a second (and third) Bernoulli fault into the replay by thinning the recorded tx stream of another link, and move the fault mid-run. If a learner ever beats round-robin, it is here, and §8 of the pre-registration says so.
4. Sweep h for every open-loop arm (free in replay) to produce the ADD-vs-false-alarm curve the QCD and telemetry literature expects.

**Metric.** KM median and p95 of TTL and TTL_obs with paired sign/Wilcoxon and log-rank, censoring fraction, delay ratio to oracle, per budget, per fault count. Plus the busy-set statistic already computed — at the first-drop epoch the busy uplink count is 1024 in the median seed and ≥768 in 21/30 — published as the reason load gating cannot pay.

**Compute.** Minutes on Vision. No htsim runs.
**Gate.** If any counter-computable schedule closes ≥30 % of the oracle gap with paired p < 0.05 at any budget or fault count, the allocation thesis is alive: stop, re-open H1, re-plan around it. Otherwise the scoped negative result is fixed and M2 becomes the critical path. (Prediction from data in hand: no single-fault schedule wins; gated RR's only effect is on censoring and p95, and its p95 is no better than uniform's at 3 of 5 budgets. Multi-fault is genuinely open.)

---

## M2 — In-band per-link loss evidence on silicon · 7 Sep – 2 Oct · owner P (chip) + C (P4/analysis)

**Goal.** Make the first silent drop a localized, in-band event on the Tofino, and measure the resulting delay. This is the experiment the paper stands on.

**Design.** Primary: a per-link sequence stamp (LinkGuardian, SIGCOMM'23) — the sending side writes a 16-bit per-link counter into the existing `csig_h.epoch` field (`mcp_fabric.p4:108`; **not** `worst_qdepth`, which carries the working congestion loop); the receiving pass keeps one SALU word per link with the last sequence seen; a gap beyond a small reorder window is a localized drop that bumps `reg_attn` through the existing `tbl_exceed_*` path and emits one truncated mirror. Fallback if it does not fit or false-gaps: alternate marking (RFC 9341) — a one-bit colour in the shim plus per-colour ingress/egress counters per vlink (`tbl_vlink` already has a DirectCounter at `mcp_fabric.p4:482`; `tbl_eg_vlink` at line 915 has none), diffed per colour period.

**Work.** (a) compile gate first — ingress has no headroom (`step7.md`: 9 ingress stages, "next feature must reuse a stage"), so the check must live in egress or replace a stage; (b) tofino-model + PTF; (c) silicon.

**Experiments.**
1. **F0 false-gap floor.** No fault, per-packet spraying, ≥10 × 60 s, plus a multi-queue/TC run. Metric: false gaps per 1e6 packets, and per healthy vlink.
2. **F1 at p ∈ {1e-2, 1e-3, 1e-4}, 12 reps each.** Metric: packets on the faulty link until the first detected gap (expected ≈ 1/p) against the ~2/δ the frozen CUSUM needs; τ_fast under the v1.4 ramp estimator; specificity over the 15 healthy vlinks. Ground truth is on-chip (`fail_ctr`; fault mirrors already 246/246) and the detector must never read it. **State the packet rate with every time figure**: the F6 session put ~75 kpps on the shaped vlink (150 kpps blast, hash-sprayed over two spines); `step5-7-silicon-v2.md` demonstrates ~300 kpps peak. At 75 kpps, 1/p at 1e-4 is 133 ms; at 300 kpps, 33 ms.
3. **Cost table** from `*.resources.json`: SRAM KB, stages, TCAM, per primitive — plus the shim's β_tag in §2.3 units.

**Compute.** Chip time only; three to four evening sessions. No sim.
**Gate.** Kill condition: false-gap rate at F0 exceeds the fault event rate at 1e-4 (7.5 events/s at 75 kpps, 30/s at 300 kpps), or per-path FIFO ordering does not hold. Then fall back to alternate marking; if that also fails, the paper becomes "negative results + congestion fast loop" and the target moves to NSDI'28. Confirm condition: detection at ~1/p packets with 0 healthy-vlink reactions, which closes H7 for F1 with a data-plane loop and produces the paper's floor curve.

**Note to keep the claim honest.** The claim is "one pipeline pass after the drop", never "100 µs detection of 1e-4 loss".

---

## M3 — Second vantage: link, not path · 28 Sep – 16 Oct · owner P

**Goal.** Remove the identifiability limit: with one source leaf, `vlink:9` (41.44) and `vlink:0` (40.92, the genuinely faulty uplink) track each other to within 1 %, so today's hardware localizes a path.

**Work.** Cable Hulk as a second source leaf (or emulate one on spare ports) and intersect two destination-leaf reports, as SprayCheck does. Move the mirror collector off the shared host port dp9 while the cabling is open. Fix `mirror_h.hop` off-by-one and the evidence-copy path-0 mislabel.

**Metric.** Separation of uplink from downlink under an injected one-directional fault, 12 reps; report localization granularity explicitly.
**Gate.** If a second vantage is not achievable by 16 Oct, the paper says "path" everywhere in the hardware section and claims link granularity only in simulation. Not a blocker for M2 or M5.

---

## M4 — The competitors, implemented for real · 5 Oct – 30 Oct · owner C + A(builder/qa-verifier)

**Goal.** The paper is measured against the 2026 state of the art, not against uniform-at-41.

**Work.** Implement, in the replay harness and (where cheap) in P4:
- **B7 SprayCheck** as published and **B7' SprayCheck-L** (background-loss-aware threshold): per-(dst-leaf, spine) count imbalance with a one-sided Z-test, <2 KB SRAM per 32 spines, its published sensitivity being 1.5 % per-link drop in 1 iteration and 0.5 % in 5 (Llama-3-70B, 64 spines).
- **FlowPulse-style** per-ingress-port byte comparison against a per-iteration load model, 1 % threshold (misses 0.8 % at radix 32, per its own §6).
- **B13 OPP-style** first-hop probe duplication with dedup — only if the SIGCOMM'26 full text is obtained (`PREREG B13` decision rule; ACM DL 403 from here — P to fetch via campus). Its published point is 10 ms service tracing at 181 KB SRAM.
- **B11 NIC-only, non-aggregating**, with the strongest commodity evidence (OOS, local-ACK timeout, per-path SACK) — the operational comparator, not an arm to beat.

**Metric.** Each on the paper's axes: packets-on-the-faulty-link (and collective iterations) to localization at p ∈ {1e-4, 1e-3, 5e-3, 1.5e-2}, FPR/FNR ROC over the threshold knob, SRAM KB, probe/collector bytes, localization granularity — all in §2.3 units.
**Gate.** If our primitive does not sit ≥1 order of magnitude below SprayCheck in packets-to-detect at 0.5 % — the point where SprayCheck is strongest — the floor claim is weak and the paper leads with the lossy/AlltoAll regime instead, where SprayCheck's §6 states it does not apply.

---

## M5 — The simulation block, resized · 26 Oct – 20 Nov · owner C

**Goal.** One figure, at a compute cost that closes.

**Runs.** 30 seeds × F1 p ∈ {1e-4, 1e-3, 1e-2} × background loss F0 ∈ {0, 1e-5, 1e-4} = 270 htsim runs, logging all-link counters and per-link drop events. Plus ~60 in-loop runs for arms that actually inject traffic (SprayCheck's prioritized flow, OPP probes) so H6 stays honest — replay is sound only for probe-free arms — and 30 no-fault seeds for the false-alarm axis. Implementing F2–F9 in `pipe.h` is explicitly *out of scope*: only Bernoulli silent loss exists today, and adding four fault mechanisms is a project, not a milestone.

**Compute.** ~360 runs × 64 min / 15 concurrent ≈ 26 h wall, ~2 nights on the fleet, 21.5 GB per slot. Everything else — every schedule, every h, every localizer variant, multi-fault, moving faults — comes from replay in seconds.

**Metric.** The paper's figure (packets-to-localize vs p, two panels: lossless 2-level and lossy MoE AlltoAll) plus KM/TTL_obs as the secondary time axis, with the sequence/alternate-marking arm, SprayCheck, SprayCheck-L, FlowPulse-style, uniform, LinUCB MCP and oracle on the same axes.
**Gate.** The in-band arm must land at TTL_obs 0–1 epoch in ≥27/30 seeds with 0 false alarms across F0 levels. If it does not, the sim model of the invariant is wrong (most likely in-flight accounting) — fix it before the hardware claim is written.

---

## M6 — Fast loop as stage two, and the cost table · 16 Nov – 11 Dec · owner P + C

**Goal.** Give the working silicon a defensible role and the field's metric pair.

**Work.** Re-drive the attention gate from the M2 evidence source; report **average detection delay vs pre-change sampling duty cycle at a fixed false-alarm rate** by sweeping `a_min` ∈ {1, 6, 25, 100 %} and `k_up`/`n_clean`, 10+ reps, for F1 and F5 congestion, controller frozen. Report τ_fast in absolute µs against the pipeline bound and τ_slow as a range (2.20 ms minimal slot, 88.8 ms raw sweep, 96.2–116.6 ms Python loop), with the breakdown that makes it honest: 48.5 ms register read + 29.8 ms counter sync/read + 9.6 ms register write of raw bfrt I/O, plus ~16 ms of `to_dict()` decoding. Produce the per-arm cost table from `*.resources.json` and measured mirror/collector bytes.

**Metric.** ADD within x % of always-on mirroring at ≤6 % pre-change duty cycle, 0 healthy-path reactions; bytes of mirror per identified drop; time from counter alarm to first header sample.
**Gate.** If the gate gives no ADD advantage over fixed-rate sampling at equal duty cycle, report that and demote it to "evidence capture after localization" — still a needed stage, no longer a claim. Note in the text that a Bernoulli gate with a state-dependent probability is state-dependent fractional sampling, which is weaker than DE-CuSum's deterministic on-off control; do not claim QCD optimality.

---

## M7 — Writing, figures, related work · 7 Dec – 15 Jan · owner C, direction P, A for sources

**Work.** Structure with `systems-paper-writing`; voice with `paper-voice` + `academic-humanizer` (never the generic humanizer); figures with `ieee-paper-figures`; final `remove-ai-marks` Layer A. Related work must **add** to the 34-row matrix: **LinkGuardian** (SIGCOMM'23, DOI 10.1145/3603269.3604853), **LossRadar** (CoNEXT'16, currently mentioned only inside the ChameleMon row), **RFC 9341/8321** alternate marking, **dDrops**, **WJH**, packet trimming on current merchant silicon. **FANcY (SIGCOMM'22) is already row 23** — position against it, do not "add" it. Keep and sharpen the existing positioning against SprayCheck, FlowPulse, OPP, CSIG, R-Pingmesh, Hostmesh, MetaRoCE, REPS, Themis, ChameleMon, and the bandit-QCD line (Gopalan et al. NeurIPS'21; Banerjee & Veeravalli 2011/2012/2013; Sonata; DynATOS). Chase primary motivation numbers with the citation checked before use — e.g. the Llama-3 herd paper reports 466 job interruptions over 54 days of which 419 were unexpected; do not paraphrase from a survey.

**Gate (15 Dec, hard).** If M2 confirmed and M5 produced the figure → SIGCOMM'27. If either failed → NSDI'28 (Apr 2027), using the extra quarter for the second vantage, fault mechanisms in the simulator, and a larger-scale sim.

---

## M8 — Adversarial review, artifact, submission · 15 Jan – 29 Jan · owner P + A

`ieee-journal-reviewer` pass at venue standards; fix or disclose every finding; package the artifact (traces, replay harness, P4, controller, the 30-seed counter logs — the replay harness is itself a contribution a reviewer can run in seconds); submit. Keep a running "what we did not do" paragraph: single-chip emulation (stated in the first paragraph of Implementation, as SprayCheck does), software RDMA, no absolute-latency claims from the loopback fabric, one stationary fault class implemented in the simulator.

---

## What we drop, explicitly

LinUCB and its three variants, the 7-dimensional context, shadow prices, the dual-ascent knapsack, the coverage floor and ablations A1–A4 (retained only as one appendix ablation showing they do not beat round-robin); H1 as pre-registered, H3, H5; the ≈18,400-run matrix and the 730-run tuning block; the CSIG-style tag and `nic/evidence_probe.py` as contributions; baselines B1, B4, B5, B8; the 100 ms fixed epoch as the reporting clock (use the collective's iteration/burst clock, as SprayCheck and FlowPulse do); the words "attention", "bandit" and "shadow price" from the contribution sentence.

## Standing risks

`H26` memory (21.5 GB/run) bounds every htsim block — M5 is sized to it. Chip availability is one machine shared with `defense4`; M2 and M6 need ~8 evening sessions total, booked ahead. `H20/H21` (Soft-RoCE, no ECN, reorder-confounded PSN gaps) mean no "switch beats NIC" claim can come from hardware — B11 is a comparator, not a defeated baseline. `H19` (segfault on 2-tier topologies) keeps every sim on 3-tier fat trees. SIGCOMM'27 dates are assumed; re-verify monthly (`H15`).
