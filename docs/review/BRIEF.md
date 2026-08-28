# MCP project — briefing for the review panel (state as of 2026-08-27)

> **Superseded framing notice (2026-08-28):** §1 below describes the original attention/bandit
> thesis and remains useful only as historical context. Both novelty gates failed; the active
> direction is now the counterfactual audit/recovery lifecycle in `docs/review/PLAN.md`, with the
> exact verdict in `docs/review/NOVELTY-GATE.md`. W4 and the replay remain infrastructure, not
> contributions.

Repository: /home/philip/Projects/mcp (read anything; nothing here is secret). Key files:
`paper/PREREG.md` (pre-registration v1.1 + amendments §14), `HURDLES.md` (H1–H27),
`docs/P4-DESIGN-SPACE.md` (+ errata), `docs/DESIGN-ALTERNATIVES.md`, `docs/NOVELTY-MATRIX.md`,
`docs/PRE-REVIEW.md` (an earlier adversarial pre-review), `WORKING_NOTES.md` (chronological log),
`p4/reports/*.md` (silicon reports), `sim/gate/*.md|*_summary.txt` (simulation results),
`controller/` (inference layer, learner, epoch loop), `nic/` (evidence producer).

## 1. The problem as currently framed

Gray failures (silent packet loss, latency inflation, ICRC corruption) on packet-**sprayed** AI
training fabrics (per-packet multipath, UEC/RoCE-style transports) are hard to localize: every
flow touches every spine, so flow-level symptoms do not point at a link, and always-on telemetry
at 25–400 G is too expensive. The project's thesis (PREREG §0): a **two-timescale measurement
controller** — a per-path *attention* weight loop in the switch data plane (fast loop) that gates
sampling/mirroring, plus a budgeted contextual bandit with shadow prices in the control plane that
re-prices the fast loop each epoch (slow loop) — localizes gray failures faster than fixed-policy
measurement at equal budget, with negligible collective-completion-time overhead.
Target venue: SIGCOMM '27 (deadline ~Jan 2027) or NSDI '28.

Falsification conditions are pre-registered: H1 (≥ 30 % lower median time-to-localize than the
best tuned baseline at equal budget) failing, or the fast loop not mattering (ablation A7 within
CI of full MCP; H7 failing on silicon).

## 2. What exists (all verified with evidence in git)

**Hardware (Intel Tofino 1, SDE 9.13.2, one host = Vision at 25 G; Hulk not yet cabled):**
- `p4/mcp_fabric.p4`: a 4-leaf × 2-spine virtual fabric emulated on one switch (4 physical 25 G
  loopback links, one TM queue per virtual link), per-packet spraying (hash/random/RR/selector),
  runtime failure injection (drop/corrupt, range TCAM), per-path attention register with the
  frozen PREREG §7.4 rule (bump on exceedance evidence, decay on clean samples; controller sets
  3 constants), a TCAM measurement gate (P = attn/65536), truncated mirrors carrying a header with
  the pass verdict + switch timestamp, a 14-B CSIG-style "worst hop" tag compare-and-replaced in
  egress, NIC-evidence packets consumed by the switch. 8 ingress + 3 egress stages; 14 bf-p4c
  constraint classes documented (`~/.claude/skills/tofino-p4`).
- Silicon results (`p4/reports/step5-7-silicon-v2.md`): every count exact (gate 487/4000 at
  6.25 %, fault mirrors == injected drops, evidence +1024/pkt in both pipes, decay exact); the loop
  closes end-to-end: a shaped uplink → tag over threshold → attention saturates → sampling 6 % → 100 %,
  no controller involved.
- H7 timing (`h7-timing-F6.md`, `h7-timing-F1.md`, PREREG v1.4 definitions): congestion (F6)
  τ_fast 97 µs vs τ_slow 88.8 ms (full-sweep controller epoch), ratio 907, CI 452–1143, specificity
  perfect — SUPPORTED. Silent loss (F1): τ_fast 10.1 ms, ratio 8.8 — FAILS, structurally: loss has
  no in-band evidence; the F1 "fast loop" is host software (`nic/evidence_probe.py`, RTT-tail bound).
- Slow loop on silicon (`slow-loop-silicon.md`): bfrt adapter correct, τ_slow 96–117 ms (≈ 95 ms of
  it is bfrt reads/decoding), epoch cannot hold 100 ms when writing → 200 ms.
- Known limits: single source leaf → uplink/downlink of a path unidentifiable; collector shares
  the host port; CSIG evidence is single-pipe by construction; F1 loop is host-bound.

**Simulation (htsim/UEC fork, `sim/htsim` commit 4a9ad8b hooks):** silent-loss injection per
uplink, per-link counters, epoch scheduler with uniform/random/oracle/extern policies, F0
background loss, `-rto_min_us`. Co-simulation bridge: the sim's per-epoch probe decisions come
from the same Python controller code as hardware (PREREG §3.3 "one frozen localizer for all arms").

**Controller (`controller/`):** frozen common inference layer (`infer.py`, hash be12e7b2): Beta/
Normal-Gamma posteriors, upper-sided binomial-LLR CUSUM on loss (δ = 1e-4, h = 6.5 nats), pooled
baseline, ranking; observation-only reward (§7.2) with a no-leakage test (§7.3); learner
(`mcp_policy.py`: LinUCB stationary/discounted/window, per-element context, shadow-price knapsack,
ablations A1–A4, coverage floor); hardware epoch loop; NIC evidence producer. 36 tests.

## 3. Evaluation design and results so far

- PREREG §10 gate at the frozen §14 point (MoE8x8B-64 ATLAHS trace on a 1024-NIC fat tree, one
  3.5 s iteration, 100 ms epochs, budget 4 % of uplinks = 41, F1 1e-4 on a random uplink, onset
  U[0.3, 0.9] s, 30 seeds): oracle TTL 8 [5, 9]; uniform 15 [10, 22] (3 % censored); random 23
  [16, 27] (37 %); TTL from first *observable* drop: 0 / 9 / 14. CV(log TTL) 0.18–0.51; ρ(uniform,
  random) 0.05. Each run 62 min, 21.5 GB (per-flow state in htsim never freed — H26).
- Key physics found (H27): the MoE fabric is idle outside three communication bursts (896/1024
  uplinks carry nothing in a typical epoch); a fault is observable only when its link carries
  traffic; TTL is dominated by the trace's schedule and by *when the faulty link is first probed*.
- Rehearsal on LULESH-128 (`sim/gate/COSIM-RESULTS.md`): after fixing four localizer false-alarm
  sources, uniform / random / cusum (localizer suspects + round-robin) / MCP all tie at equal
  budget (medians 9/8/9/9 at budget 32; 31/22/31/34 at budget 4). The §3.2 tuning block (730
  runs) selects coverage-like MCP configs (floor 0.75).
- Tier-1 pilot at the frozen point (`results_tier1_cosim_summary.md`, 30 paired seeds): cusum ≡
  uniform exactly; MCP (LULESH-tuned config, no Tier-1 tuning) 18 [14, 24] vs uniform 15 — slower
  in 23/30 (sign p = 0.005). H1 NOT met by this configuration.
- Not yet run: the pre-registered main block (14 baselines × F0–F9 × 30 seeds ≈ 18k runs),
  ablations, non-stationarity block, sweeps, Tier-2 two-host runs, Tier-1 tuning of MCP.

## 4. Baselines and literature already positioned (see docs/NOVELTY-MATRIX.md, 34 systems)

Closest: SprayCheck (arXiv 2605.03702, round-robin prioritized flow across spray paths),
OmniPath Ping (SIGCOMM '26, probe duplication), ChameleMon-style adaptive sampling, Pingmesh /
R-Pingmesh / Hostmesh, FlowPulse, DynATOS, NIC-side fleet telemetry (Meta), CSIG (Google),
UEC congestion signalling, INT/HPCC. Pre-review findings (docs/PRE-REVIEW.md, H24): SprayCheck
absent from hardware arms, OPP not implemented, localizer confound (fixed by §3.3), H2 as stated
unpassable, background-loss sweep needed, NIC-only arm must not aggregate.

## 5. The honest situation

The engineering works and is measured; the *thesis* is not yet demonstrated. Where the data plane
can see the fault (congestion), the fast loop is real and ~900× faster than the controller. Where
it cannot (silent loss), the loop is host-bound, and at the frozen operating point every
budgeted policy — including an untuned learner — is bounded by probe coverage of a single
stationary fault. The panel is asked whether the problem framing, the design, the evaluation, and
the way forward should change, and to propose innovative but *simple* contributions with
metrics and comparisons that can be proven, not caveated.
