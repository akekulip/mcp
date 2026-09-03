> **RESOLVED 2026-09-03 — the make-or-break htsim measurement returned NULL.** The
> single decisive test (CLEAN vs DO-NOTHING, 1e-3 on a fully-loaded uplink, τ = 40 ms) shows a
> do-nothing CCT slowdown of only **+1.362 %** — losses are pipeline-hidden even under RTO-dominated
> recovery, and 40 ms is the worst-case RTO so the NULL is robust across the range. The
> application-impact top-venue path fails at the informative regime; ship the mechanism/localization
> contribution to ToN/IMC. Full numbers, realised-parameter cross-check, the "no mitigation actuator
> in htsim" finding, and the `-mcp_loss_clear_ms` actuator feasibility assessment:
> `APP-IMPACT-HTSIM-MAKEBREAK-2026-09-03.md`.

# Application-impact gate verdict — 2026-09-02

**Question.** Before spending the 62-min / 21.5 GB htsim collective block, does MCP's faster/exact
grayhole detection+localization translate into a *measurably smaller collective-completion-time
(CCT) slowdown* than SprayCheck-Z and FlowPulse-θ, under a grayhole on a packet-sprayed training
fabric — or is the effect masked, or dominated by mitigation cost, so the application-impact
top-venue path does not hold?

**Verdict: CONDITIONAL PASS — run the htsim campaign, but scoped to the low-loss regime and with
the make-or-break assumption below tested first.** There is a real, detection-*behaviour*-limited
CCT gap in which MCP measurably beats both baselines, but it lives in a specific regime, and the
lever is detection **coverage and localization accuracy**, *not* raw detection latency. Three
regimes are uninformative and must not be claimed. A NULL is still fully possible and is fenced
precisely below.

Code: `sim/gate/cct_model.py` (closed-form Ring-AllReduce CCT model), `sim/gate/app_impact_gate.py`
(feeds each arm its own MEASURED detect+localize into the identical model), tests
`sim/gate/tests/test_cct_model.py` (38 tests, all pass). Reproduce:
`python3 -m pytest sim/gate/tests -q` then `$RESEARCH_PYTHON -m sim.gate.app_impact_gate`.

## What the arms were fed (measured, not invented)

The arms differ in EXACTLY ONE thing — their own measured detect-latency and localization outcome,
transcribed from `BASELINE-COMPARISON-2026-09-02.md` and `LOCALIZATION-COMPARISON-2026-09-02.md`
(down fault family) — feeding an IDENTICAL mitigation (detect → localize → reroute the faulty
directed link off the spray set) and an IDENTICAL CCT model. Packets-to-detect are converted to wall
time at the baseline harness fleet rate (2e6 pkt/spine/epoch × 8 spines / 0.1 s = 160 Mpkt/s):
MCP ≈ 138 ms flat + EXACT at every rate; SprayCheck slower and AMBIGUOUS/MISS below 1 %; FlowPulse
MISSes below 0.5 %.

Fabric anchors are the measured htsim `moe8x8b_n16` run (`results_real_v12/.../seed1000`): clean
CCT 3.586 s (`.finish`), onset 0.38 s (`.onset`), 200 Gbps links, ~15 µs base RTT, k = 8 spray,
mitigation cost 5 ms (the HW-measured 4.998 ms event-to-first-rerouted). RTO (`tau`), the per-link
critical-path packet rate (`lam`), and the recovery model are swept as first-class parameters
(H25). Bounds — an instant-perfect ORACLE and a never-mitigate DO-NOTHING — are reported beside
every arm; deterministic `scenario_seed()` (CRC-32), never `hash()`.

## Findings (numbers first) — batched recovery, reroute_cap_cost = 0

CCT ratios are CCT(arm)/CCT_clean, lower is better. `lam = 1e5` pkt/s (a busy active link):

| p (loss) | e | detect ms MCP/SC/FP | MCP / SC / FP | oracle | do-nothing | regime |
|---|---|---|---|---|---|---|
| 1e-2, τ=10ms | 1.00 | 138/150/138 | 1.020 / 1.022 / 1.020 | 1.001 | 1.894 | **all arms tie near oracle — fault severity swamps detection** |
| 1e-3, τ=10ms | 0.63 | 138/712/miss | 1.015 / 1.078 / 1.565 | 1.001 | 1.565 | MCP beats SC (accuracy) and FP (coverage); mixed |
| 1e-4, τ=10ms | 0.095 | 138/miss/miss | **1.004** / 1.085 / 1.085 | 1.000 | 1.085 | **MCP beats both by ~96% of span; baselines tie DO-NOTHING (miss)** |
| 1e-4, τ=50ms | 0.39 | 138/miss/miss | **1.011** / 1.352 / 1.352 | 1.000 | 1.352 | same regime, larger: MCP ~1.01 vs baselines 1.35 |

1. **Q1 — is there a measurable slowdown at all?** YES, but only when recovery is RTO-dominated and
   the fault sits on a traffic-carrying link. do-nothing reaches 1.09–1.89× at τ ≥ 10 ms. Under
   **fast-retransmit** recovery (no timeout) the whole effect collapses to ≤ 2 % even at 1.5 % loss
   (`fast_rtt`: do-nothing 1.020 at 1e-2, 1.001 at 1e-3) → **detection is irrelevant there, NULL.**
   The RTO is the make-or-break knob, exactly as H25 warned.

2. **Q2 — is the recovered gap detection-limited, and does MCP win?** YES, at low loss. At **1e-4**
   both baselines MISS entirely (tie do-nothing at 1.085–1.352) while MCP recovers to 1.004–1.011 —
   a **6–35 % relative CCT reduction**, clearing the ≥ 5 % promotion bar in
   `VERIFICATION-2026-08-29.md`. At **1e-3** MCP (1.015) beats SprayCheck (1.078, ambiguous 2-set
   strands a healthy link) and FlowPulse (1.565, miss). **The lever is coverage/accuracy, not
   latency:** MCP's 138 ms vs SprayCheck's 712 ms contributes little — the dominant terms are
   "baseline misses the fault" (FP at 1e-4/1e-3) and "baseline aliases to a 2-link set" (SC at 1e-3).

3. **Q3 — where does detection *speed* actually move CCT?** Almost nowhere on its own. At high loss
   (≥ 0.5 %) every arm detects within ~15 ms of MCP, e saturates at 1.0, and all arms tie near the
   oracle — **fault severity swamps detection differences** (do NOT claim a benefit here). Pure
   latency (138 vs 162 ms) is invisible against a 1.9× do-nothing penalty everyone recovers. The
   only place raw latency contributes is a narrow band at 1e-3 with high τ, and even there
   localization accuracy dominates it.

4. **Mitigation can be net-negative (reported, not hidden).** With a bandwidth-bound
   `reroute_cap_cost = 1/k`, rerouting a path off the spray set costs capacity permanently. When the
   loss overhead is below that cost (masked / fast-recovery corner), **even the ORACLE loses to
   DO-NOTHING** — mitigating a masked fault is worse than tolerating it. At the high-impact corner
   (λ=1e6, τ=50 ms) mitigating still pays (oracle 1.13 < do-nothing 1.89). The measured collectives
   run each 200 Gbps link at < 1 % utilisation, so `reroute_cap_cost = 0` is the honest default, but
   the sensitivity is why a bandwidth-bound collective could still flip this to NULL.

5. **Recorded-counter cross-check (grounds the low end).** The actual injected fault in
   `seed1000` (`US55->CS15`) carried 283 k pkts over the 3.5 s job and dropped **28** packets
   (p ≈ 9.9e-5, λ ≈ 81 k pkt/s). The model reproduces a do-nothing slowdown of **+6.9 %** at
   τ=10 ms batched, **+0.01 %** under fast-retransmit — i.e. even this near-idle fault is
   detection-relevant ONLY if recovery is RTO-driven.

## Threats to validity (the honest caveats)

- **The model assumes losses land on the barrier critical path** — every retransmission stalls the
  collective. Ring-AllReduce pipelines 2(N−1) chunks, so real htsim will hide some losses behind
  other chunks' slack. **This is the single make-or-break assumption**: the numbers above are an
  *upper bound* on detection-relevant impact. If htsim shows losses are largely pipeline-hidden, the
  gap shrinks toward NULL. The full campaign exists precisely to measure this fraction.
- **Placement (H27) is decisive.** The recorded fault landed on a near-idle link; a fault on a link
  carrying no critical-path traffic shows ~zero impact regardless of detector. The campaign MUST
  place the fault on a traffic-carrying critical-path link AND report the traffic denominator, or it
  measures nothing.
- **Modal localization outcomes** are used per arm; SprayCheck's mid-loss behaviour is a mixture
  (0.34 exact at 0.5 %). The paired-seed htsim run should carry the full distribution, not the mode.
- **CCT_clean anchor** (3.586 s) itself contained the masked 1e-4 fault; treated as clean (28 drops,
  negligible). A true no-fault control is one of the campaign's required cells.

## What the full htsim campaign must measure (the PASS is conditional on this design)

1. **RTO as the primary swept factor** (H25): report CCT vs {fast-retransmit, τ=10/20/40/60 ms}. If
   the fabric is fast-retransmit-dominated, expect and report NULL.
2. **Loss regime scoped to 1e-3 and 1e-4** — the headline. Do NOT lead with ≥ 0.5 %: all arms tie
   the oracle there. Frame the contribution as "at the low loss where passive baselines miss/alias
   the faulty directed link, MCP's exact localization recovers X % of the CCT they leave on the
   table."
3. **Fault placement controlled to a traffic-carrying critical-path directed link**, with the
   per-link traffic denominator reported (H27); include a near-idle-link cell to show the boundary.
4. **DO-NOTHING and ORACLE bounds in every cell**, plus the {none, whole-link, directed, sublink,
   oracle} mitigation arms from the CAMPAIGN-PLAN §3 block; paired per-seed CCT ratios, cluster
   bootstrap CIs, 15 seeds.
5. **reroute_cap_cost measured, not assumed** — report link utilisation so the net-negative regime
   is either excluded or shown.
6. **Report unsafe exposure in application terms** (retransmitted packet = latency, not loss).

## Bottom line

The application-impact path is viable **as a low-loss coverage/accuracy story under RTO-dominated
recovery**, not as a detection-latency story. If the htsim collective confirms (a) RTO-dominated
recovery and (b) that a meaningful fraction of losses hit the barrier critical path, MCP delivers a
≥ 5 % paired CCT improvement over both baselines at 1e-3–1e-4 where they miss or alias — a top-venue
application result. If recovery is fast-retransmit-dominated, or losses are pipeline-hidden, or the
collective is bandwidth-bound enough that rerouting costs more than the fault, the result is NULL and
we ship the mechanism/localization contribution to ToN/IMC. The gate has located both the viable
regime and its NULL boundaries; the htsim run is now a targeted confirmation, not a fishing trip.
