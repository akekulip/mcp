# MCP plan — 2026-08-27 → submission

Target: **SIGCOMM'27**, deadline assumed ~29 Jan 2027 (`HURDLES H15`: CFP not out; Philip confirmed the venue 2026-08-25; re-verify monthly). Fallback: **NSDI'28 spring**, ~Apr 2027. Five months of calendar, one person plus AI agents, one Tofino, two hosts (Vision 72 c / 250 GB, Hulk 72 c / 125 GB), 64 min and 21.5 GB per htsim run, fleet width 15 concurrent (Vision 10 / Hulk 5, `H26`).

Approved thesis, scoped so that prior-art mechanisms are not misclaimed:

> On a sprayed fabric with action-local selective observability, detection delay decomposes into
> evidence time plus coverage time. When unmeasured links are observationally exchangeable,
> adaptive counter-computable schedules retain a coverage lower bound. A post-TM, link-local
> order witness removes that term for non-tail partial loss, and hard-capped zoom spends detailed
> telemetry only on the implicated directed link.

The paper has three possible contributions, all gated: (1) a nontrivial and tight characterization of the coverage term under the stated observation model; (2) a compileable post-TM order witness that reaches the evidence floor for non-tail partial loss; and (3) an equal-cost Tofino result that moves the localization/false-alarm/overhead Pareto frontier with bounded evidence capture. Sequence numbering, alternate marking, paired counting, generic zoom, and learned scheduling are prior art or baselines, not inventions here. Do not call the witness “minimal” or “optimal” without a bit/state lower bound; report its concrete 2 B or 4 B cost instead.

> **GATE OUTCOME, 2026-08-28: BOTH HALVES FAILED — the pivot below is in force.**
> Three independent reviews (`docs/review/NOVELTY-GATE.md`, PREREG v1.7) found the coverage bound to
> be the perfect-detection case of Bellman (1957) / Blackwell's index rule, restated for budgeted
> policy classes in IEEE TIT by Chaudhuri–Fellouris–Tajer (2024) and Xu–Mei–Moustakides (2021); and
> the order witness to be NetSeer's inter-switch drop detection (SIGCOMM'20 §3.3), with LinkGuardian
> (SIGCOMM'23) and UEC 1.0.2 §5.1 LLR as independent occupants. The §4 "spraying collapses the
> pooled-test design space" argument is refuted by SprayCheck. Per this gate's own rule: the bound is
> demoted to an attributed lemma, M2 becomes *instantiate and cost a known primitive*, and the
> novelty budget moves to the measured decomposition, the equal-cost frontier (M4/M5) and the
> hard-capped zoom (M6). H8 is withdrawn and replaced by H8′ (equal-cost frontier).

**Novelty kill/pivot gate.** Before major P4 work, an independent theory/prior-art review must show that the bound is not merely a classical coverage/search lemma relabeled for fabrics and that it has a tight or near-tight construction. Before the paper claim is frozen, the system must create a preregistered equal-cost Pareto-frontier shift against the strongest applicable baseline, with non-inferiority bounds for false alarms and overhead. If either gate fails, demote the bound to an explanatory lemma and publish the scoped negative result/replay benchmark rather than a recombination claim.

Owners: **P** = Philip (hardware sessions, cabling, sudo, submissions, final judgement). Installed roles: `researcher` (primary prior art), `planner`/`architect`/`critic` (claim and design gates), `executor` (bounded implementation), `test-engineer` (reproducibility and experiment harness), `verifier` (acceptance evidence), `code-reviewer` (artifact review), `writer` (paper text), and `ieee-paper-figures` (figures). The research handoff is `$autoresearch-goal`; use `$team` only after the theory/novelty gate approves parallel replay, P4, and evaluation lanes.

The full RALPLAN-DR record, ADR, verification matrix, staffing plan, and execution gates are in `.omx/plans/high-novelty-telemetry-plan.md`. This tracked file is the canonical schedule and must remain synchronized with it before source implementation.

---

## M0 — Pre-registration repair and honest re-issue · 28 Aug – 4 Sep · owner executor, sign-off P

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

## M1 — Replay, theory gate, and scoped negative result · 31 Aug – 11 Sep · owners researcher + executor

**Goal.** Define the exact observation model; establish, cheaply and paired, how detection delay splits between evidence and coverage; test the scoped schedule-invariance claim under single, multiple, and moving faults; and replace the simulation matrix with a method that costs seconds instead of hours.

The panel's first draft framed this as "prove no schedule compresses detection delay". That is refuted by the repo's own oracle (10 vs 19 epochs at B = 41, a 47 % reduction above H1's bar). The goal is the decomposition plus the *computability* result, which is what actually survives.

**Work.**
1. **Theory/nontriviality gate.** Define the fault prior/adversary, policy action, action-local observation, sampling budget, exchangeability condition, stopping/localization objective, and whether measurement perturbs traffic. Prove the lower bound and a matching/near-matching construction. Record counterexample attempts and compare it with classical adaptive inspection/search results. If independent review finds only a textbook lemma, keep it as explanation and remove “formal lower bound” from the contribution list.
2. Stabilize `sim/gate/replay.py`: read `seed*.counters.csv` (per-link cumulative tx/rx/drop per epoch, logged for **all 2048 links** every epoch by `mcp.cpp:120-125`), replay any schedule against it, feed the frozen `infer.py`, emit TTL and TTL_obs. Preserve the already-verified simulator candidate order and exact uniform replay. Replace salted `hash(stem)` with a stable scenario seed; emit chosen fault identities; and name multi-fault success semantics separately as “any,” “all,” or “original among distractors.” Moving-fault semantics must be deterministic.
3. Score every schedule class on the 30 recorded seeds at budgets {1, 2, 4, 8, 19.5 %}: uniform RR, random, load-gated RR (tx > 0 since last read), threshold-gated RR (tx ≥ 2/δ), greedy max-unobserved-traffic, Thompson on the Beta posteriors, LinUCB MCP as tuned, oracle.
4. **Semi-synthetic multi-fault and moving-fault replay.** Inject the second/third faults and movement from stable scenario ids, evaluate the preregistered “any” and “all” objectives, and keep “original among distractors” only as a separately labelled robustness test.
5. Sweep h for every open-loop arm to produce the ADD-vs-false-alarm curve.

**Metric.** KM median and p95 of TTL and TTL_obs with paired sign/Wilcoxon and log-rank, censoring fraction, delay ratio to oracle, per budget, per fault count. Plus the busy-set statistic already computed — at the first-drop epoch the busy uplink count is 1024 in the median seed and ≥768 in 21/30 — published as the reason load gating cannot pay.

**Compute.** Minutes on Vision. No htsim runs.
**Gate.** Proceed to M2 only after replay is process-reproducible and the claim is either (a) an independently accepted nontrivial/tight result or (b) explicitly demoted to an explanatory lemma. If any counter-computable schedule closes ≥30 % of the oracle gap with paired p < 0.05 at a preregistered budget/fault objective, re-open the allocation result rather than hiding it.

---

## M2 — In-band per-link loss evidence on silicon · 7 Sep – 2 Oct · owner P (chip) + executor/test-engineer

**Goal.** Make the first silent drop a localized, in-band event on the Tofino, and measure the resulting delay. This is the experiment the paper stands on.

**Design.** The primitive is **prior art** (NetSeer SIGCOMM'20 §3.3: egress-inserted per-neighbour
sequence number, downstream ingress reads inconsecutive numbers as drops, 4 B, on Tofino); this
milestone instantiates and costs it, and does not claim it. Adopt rather than reinvent: LinkGuardian's
**era bit** for modulo wrap and its **self-replenishing lowest-priority dummy packet** for the
idle-tail and blackhole cases. NetSeer's detection surface is now a **mandatory arm**, compiled side
by side from one source tree. Note the witness is post-TM and therefore does **not** see upstream TM
drops — a discarded packet is never numbered and creates no gap.

**COMPILE GATE PASSED, 2026-08-28** (`p4/witness/COMPILE-GATE.md`, built on the switch's own bf-p4c
9.13.2; compile only, chip untouched). Baseline 8 ingress / 3 egress; **W2 8/3 and W4 8/3 — the
witness costs zero MAU stages**, with 4 ingress and 9 egress stages still free. Arming the fast loop
from a gap event costs exactly +1 ingress stage. **W4 (explicit 16-bit link id) is the variant to
take to silicon**: W2's premise is false on this testbed, because `setup_skeleton.py` maps
`leaf l → spine s` onto `(port, qid)` and one loop port carries `N_SPINE = 2` directed vlinks, so
ingress port identifies the link only up to a factor of 2 — a question M3 was going to have to ask on
hardware, answered at compile time. Also found: the existing injector drops in *ingress*, before the
egress stamp, so it cannot produce a single gap event; the egress-side injector is compiled and
costed (+0 stages over the armed variant, +3 egress SRAM, +2 egress TCAM).

Original design text, retained: a standalone byte-aligned post-TM order witness—never `csig_h.epoch`, whose packed container cannot be rewritten from the required egress sources (`mcp_fabric.p4:102-108,690-694`). After `tbl_eg_vlink`, the upstream egress increments a modular 16-bit counter keyed by directed vlink and writes the returned value before deparse. The downstream ingress compares it with expected state keyed by the incoming directed link. Use a 2 B sequence-only form only when ingress-port/topology mapping proves link identity; otherwise compile and cost a 4 B `link_id + sequence` form. Fallback: RFC 9341 alternate marking with explicitly costed color periods and control-plane reads.

**Work.** Compile gate first against the fresh recorded baseline—currently 8 ingress + 3 egress stages (`docs/DESIGN-ALTERNATIVES.md:3-6`), not the stale 9-ingress assertion. In order: (a) source compile and placement/resource delta for 2 B and 4 B candidates; (b) model/PTF for initialization, reset/resynchronization, modulo wrap, duplicates, allowed reorder, consecutive losses, and multi-queue traffic; (c) silicon. Place fault injection after upstream sequence allocation and before downstream validation; a pre-increment drop cannot validate wire-loss semantics.

**Experiments.**
1. **F0 false-gap floor.** No fault, per-packet spraying, ≥10 × 60 s, plus multi-queue/TC, wrap, duplicate, reorder, reset, and idle/resume runs. Report the exact one-sided binomial upper confidence bound from the packet denominator against a preregistered operational limit.
2. **F1 at p ∈ {1e-2, 1e-3, 1e-4}, 12 reps each.** Separate time-to-first-loss from gap-to-reaction. For non-tail partial loss, the receiver should react on the next survivor; the time to create evidence is still ≈1/p. Ground truth is on-chip and unread by the detector. State packet rate with every time figure.
3. **Limit cases.** Consecutive partial loss is revealed by the next survivor. Idle-tail loss and a 100% blackhole require a separately priced marker plus timeout/control path; exclude them from the main witness claim if that path is not built.
4. **Cost table** from `*.resources.json`: source and placed stages, SRAM, TCAM, SALUs, tag bytes at both 1500 B and 4096 B, marker/probe bytes, mirror/collector bytes, and control-plane reads/writes.

**Compute.** Chip time only; three to four evening sessions. No sim.
**Gate.** Admit silicon only if one primary form compiles, directed-link identity is proven, and all model/PTF semantics pass. Kill/fallback if the preregistered false-gap bound fails, ordering assumptions fail, the resource delta is unacceptable, or link attribution is ambiguous. Then use alternate marking; if it also fails, pivot to the scoped negative result. Never force `csig_h.epoch`.

**Note to keep the claim honest.** The claim is “the next surviving packet reveals a post-TM sequence discontinuity,” not “the dropped packet is mirrored” and never “100 µs detection of 1e-4 loss.”

---

## M3 — Directed-link attribution, local first · 28 Sep – 16 Oct · owner P

**Goal.** Remove the identifiability limit: with one source leaf, `vlink:9` (41.44) and `vlink:0` (40.92, the genuinely faulty uplink) track each other to within 1 %, so today's hardware localizes a path.

**Work.** First prove whether receiver ingress port plus topology uniquely identifies the upstream directed link; if not, use the M2 explicit 16-bit link id. Cable Hulk as a second source leaf and intersect reports only if the one-chip emulation remains ambiguous after both local methods. Move the mirror collector off shared host port dp9 and fix `mirror_h.hop` plus the evidence-copy path-0 mislabel.

**Metric.** Separation of uplink from downlink under an injected one-directional fault, 12 reps; report localization granularity explicitly.
**Gate.** Correct directed-link attribution in hardware is mandatory for the link-local headline. If local identity, explicit id, and second vantage all fail, say “path” everywhere and remove directed-link localization from the contribution list.

---

## M4 — Equal-cost baseline pack · 5 Oct – 30 Oct · owner executor + test-engineer

**Goal.** The paper is measured against the 2026 state of the art, not against uniform-at-41.

**Work.** Use tiers rather than gratuitous full reimplementations:
- **Direct empirical:** exact-replay uniform and oracle; SprayCheck and FlowPulse semantic reproductions; RFC alternate marking; always-on evidence/mirroring; the strongest feasible paired-counter/FANcY-style detector; and NIC-only evidence as an operational comparator.
- **Mechanism/cost:** LinkGuardian sequencing/recovery and FANcY's published hardware costs. Reproduce only the surface needed for the compared axis and never label that a full reproduction.
- **Policy ablations:** current LinUCB/attention and ChameleMon-, DynATOS-, or DE-CuSum-style policies only where observation/action semantics match replay. Otherwise use a primary-source published point and mark assumptions as unmatched.
- Label every row `reproduced`, `semantic reimplementation`, `replay-only`, or `published point`.

**Metric.** Each on the paper's axes: packets-on-the-faulty-link (and collective iterations) to localization at p ∈ {1e-4, 1e-3, 5e-3, 1.5e-2}, FPR/FNR ROC over the threshold knob, SRAM KB, probe/collector bytes, localization granularity — all in §2.3 units.
**Gate.** Preregister the primary localization metric, a material frontier margin, and non-inferiority bounds for false alarms and total overhead from operational requirements or pilot variance—not from the observed winner. A post-hoc one-axis win does not pass.

---

## M5 — The simulation block, resized · 26 Oct – 20 Nov · owner executor + test-engineer

**Goal.** One figure, at a compute cost that closes.

**Runs.** 30 seeds × F1 p ∈ {1e-4, 1e-3, 1e-2} × background loss F0 ∈ {0, 1e-5, 1e-4} = 270 htsim runs, logging all-link counters and per-link drop events. Plus ~60 in-loop runs for arms that actually inject traffic (SprayCheck's prioritized flow, OPP probes) so H6 stays honest — replay is sound only for probe-free arms — and 30 no-fault seeds for the false-alarm axis. Implementing F2–F9 in `pipe.h` is explicitly *out of scope*: only Bernoulli silent loss exists today, and adding four fault mechanisms is a project, not a milestone.

**Compute.** ~360 runs × 64 min / 15 concurrent ≈ 26 h wall, ~2 nights on the fleet, 21.5 GB per slot. Everything else — every schedule, every h, every localizer variant, multi-fault, moving faults — comes from replay in seconds.

**Metric.** One Pareto figure: packets/time to directed-link localization versus total measurement cost, with false-alarm non-inferiority shown at the fixed operating point. Report KM/TTL_obs secondarily. Include sequence/alternate marking, SprayCheck, FlowPulse-style, paired counters, always-on evidence, uniform, LinUCB ablation, and oracle on honest matched axes. Reorder, wrap, duplicate, consecutive-loss, moving/multiple-fault, tail, and overload cases use replay/model/PTF where htsim lacks the fault mechanism; do not pretend they are native htsim results.
**Gate.** The system must be non-dominated and move the preregistered equal-cost frontier by the material margin while satisfying false-alarm and overhead bounds. Otherwise pivot to the negative-result/replay artifact.

---

## M6 — Hard-capped directed-link zoom and cost table · 16 Nov – 11 Dec · owner P + executor

**Goal.** Give the working silicon a defensible role and the field's metric pair.

**Work.** Replace the proposed stochastic path-attention mechanism with a vlink-keyed finite-state machine: `QUIET -> SUSPECT -> ZOOM(K packets/bytes) -> COOLDOWN`, enforced by a token bucket/hard episode cap. The M2 gap event arms the implicated vlink; the controller only installs thresholds/budgets. Keep existing probabilistic attention as an ablation. Test loss and congestion separately: loss reacts on the next survivor; the already-working congestion loop reacts on the evidence packet. Preserve the measured τ_slow breakdown and produce the resource/cost table plus a fault-storm collector-stress run.

**Metric.** Gap-to-first-context packet, context packets/bytes per episode, p95 concurrent-fault mirror bytes, collector drops, cooldown/re-arm correctness, and ADD versus pre-change duty cycle at fixed false-alarm rate.
**Gate.** Mirror volume never exceeds the configured cap and the collector drops none at the declared operating envelope. If bounded zoom has no equal-duty advantage, demote it to evidence capture after localization. Do not claim QCD optimality.

---

## M7 — Writing, figures, related work · 7 Dec – 15 Jan · owner writer, direction P, researcher for sources

**Work.** Structure with `systems-paper-writing`; voice with `paper-voice` + `academic-humanizer` (never the generic humanizer); figures with `ieee-paper-figures`; final `remove-ai-marks` Layer A. Related work must **add** to the 34-row matrix: **LinkGuardian** (SIGCOMM'23, DOI 10.1145/3603269.3604853), **LossRadar** (CoNEXT'16, currently mentioned only inside the ChameleMon row), **RFC 9341/8321** alternate marking, **dDrops**, **WJH**, packet trimming on current merchant silicon. **FANcY (SIGCOMM'22) is already row 23** — position against it, do not "add" it. Keep and sharpen the existing positioning against SprayCheck, FlowPulse, OPP, CSIG, R-Pingmesh, Hostmesh, MetaRoCE, REPS, Themis, ChameleMon, and the bandit-QCD line (Gopalan et al. NeurIPS'21; Banerjee & Veeravalli 2011/2012/2013; Sonata; DynATOS). Chase primary motivation numbers with the citation checked before use — e.g. the Llama-3 herd paper reports 466 job interruptions over 54 days of which 419 were unexpected; do not paraphrase from a survey.

**Gate (15 Dec, hard).** SIGCOMM'27 only if the theorem is correctly classified, M2/M3 prove the claimed granularity, M5 moves the preregistered frontier, and M6 enforces bounded capture. Otherwise use NSDI'28 time for the honest pivot or missing evidence; do not stretch the claim to meet a date.

---

## M8 — Adversarial review, artifact, submission · 15 Jan – 29 Jan · owner P + code-reviewer/verifier

Use `code-reviewer`, `verifier`, and an independent systems-paper critic at venue standards; fix or disclose every finding. Package traces, deterministic replay, P4, controller, compiler/resource reports, baseline provenance labels, and counter logs. Keep a running “what we did not do” paragraph: single-chip emulation, software RDMA, no absolute-latency claims from loopback hardware, simulator-native fault limits, and excluded liveness cases.

---

## What we drop, explicitly

LinUCB and its variants, the 7-dimensional context, shadow prices, the dual-ascent knapsack, and probabilistic attention as contributions (retain one appendix ablation); H1 as pre-registered, H3, H5; the ≈18,400-run matrix and 730-run tuning block; the CSIG-style tag and `nic/evidence_probe.py` as contributions; baselines with no matched axis; the 100 ms fixed epoch as the primary reporting clock. Never claim sequence numbers, alternate marking, paired counters, generic zoom, or a textbook coverage lemma as inventions.

## Standing risks

`H26` memory (21.5 GB/run) bounds every htsim block. Chip availability is one shared machine; compile/model evidence precedes evening silicon sessions. `H20/H21` mean no “switch beats NIC” claim can come from hardware. `H19` keeps simulations on 3-tier fat trees. Sequence evidence is blind to idle-tail loss and a 100% blackhole without a separately priced liveness path. The current one-source hardware result is path-level until M3 proves otherwise. SIGCOMM'27 has an official site, but no research-paper CFP/deadline was found as of 2026-08-27; re-verify monthly (`H15`).
