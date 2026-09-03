# Healing lifecycle result-gate — VERDICT: **FAIL** — 2026-09-02

Decisive, simulation-only test of the plan's **§11 stop condition** *before any P4 is written*:

> "the lifecycle does not improve certified restoration or stranded capacity at equal probe
> cost." → STOP.

**Verdict: FAIL.** Under honest parameters the evidence-lease / audit / probation healing
lifecycle **ties a trivial round-robin baseline exactly**, at every concurrency and every audit
budget tested. The novel scheduling machinery buys nothing the trivial baseline does not already
get. This ends the healing thread cleanly and is a valid, program-relevant result — not a failure
of the harness. Retain W4 as a costed known primitive and the honest replay/negative-result
artifact, per the plan's FAIL branch.

## What was tested

The healing decision, not detection (detection is `sim/gate/replay.py`): a directed link is
quarantined (rerouted off, so it carries no passive traffic), it physically recovers at an
**unknown** time, and the policy must decide when to certify-and-restore it. Metrics, reported
**together** per the repo cross-check rule: unsafe restorations (safety), act-rate = fraction of
links ever restored (usefulness), stranded capacity (Gbps·epoch), certified-restore delay.

Arms (`sim/gate/healing.py`), all sharing one driver and the **same per-epoch audit budget B**:

- `oracle` — restores each link exactly at its true recovery time (lower bound; 0 audit).
- `continuous_probe` — audits every quarantined link every epoch ("probing is free" reference).
- `earliest_deadline` — **the lifecycle arm**: evidence-lease, audit the links whose lease
  expired earliest (stalest first), restore on a healthy audit.
- `round_robin` — trivial matched-cost baseline: audit the stalest links first, same restore rule.
- `capacity_weighted` — weighted round-robin (audit big links first); the lifecycle's best shot.
- `fixed_timer` — trivial no-probe baseline: restore all links blind at t_q + T.
- `permanent_quarantine` — never restores (the always-INCONCLUSIVE arm).

Design choices were made **maximally generous to the novel arm**: an audit reveals a link's true
state *with certainty* (no per-audit statistics — every audit is a perfect per-link oracle), and
`earliest_deadline` is given a full evidence-lease scheduler. 30 seeds per cell,
`scenario_seed()` (CRC-32) determinism, mean recovery deliberately short (2 s) to give the budget
its best chance to bind, 15% permanent faults so blind restoration is genuinely unsafe.

## The load-bearing finding

**Absent a recovery-time predictor, the evidence-lease earliest-deadline schedule is
byte-identical to round-robin.** "Audit the link whose lease expired earliest" = "audit the link
not read for longest" = round-robin. Neither policy uses any information about *which* link is
about to recover, because none exists — and the spec's §10 lists "a learned scheduler as a
headline contribution" as an explicit **non-goal**. So the lifecycle cannot out-schedule
round-robin even in principle. This is proven, not merely observed:
`test_earliest_deadline_equals_round_robin_without_a_predictor` asserts identical
(stranded, unsafe, restored, audit_reads) across 30 seeds × 4 budgets, and the pilot confirms
`earliest_deadline: TIES round_robin exactly` in **every** cell (K ∈ {8,32,128}, B swept from
scarce to abundant).

## The numbers (medians over 30 seeds; full log: `sim/gate/results_healing/pilot_2026-09-02.txt`)

Representative cells (stranded = Gbps·epoch; unsafe = restorations while link still bad):

| cell | arm | unsafe | act-rate | stranded | restore delay |
|---|---|---|---|---|---|
| K=8, B=1 (budget binds) | oracle | 0 | 0.82 | 0 | 0.0 |
| | earliest_deadline (lifecycle) | 0 | 0.82 | 1900 | 2.2 |
| | round_robin | 0 | 0.82 | **1900** | 2.2 |
| | capacity_weighted | 0 | 0.82 | 1625 | 2.0 |
| | fixed_timer | 3 | 1.00 | 10675 | 19.5 |
| | permanent_quarantine | 0 | **0.00** | 127875 | n/a |
| K=128, B=24 (budget binds) | earliest_deadline (lifecycle) | 0 | 0.85 | 15925 | 1.0 |
| | round_robin | 0 | 0.85 | **15925** | 1.0 |
| | capacity_weighted | 0 | 0.85 | 15275 | 1.0 |
| K=128, B=128 (budget abundant) | earliest_deadline (lifecycle) | 0 | 0.85 | **0** | 0.0 |
| | round_robin | 0 | 0.85 | **0** | 0.0 |
| | oracle | 0 | 0.85 | 0 | 0.0 |

Three facts settle it:

1. **Lifecycle ties round-robin exactly, always.** The one axis where the lifecycle was supposed
   to help — scheduling audits under a budget — is identical to a five-line round-robin.
2. **At any abundant budget, every audit arm ties the oracle** (stranded → 0). The budget only
   binds when B < K; the honest arithmetic (`GATE2-AUDIT-BUDGET.md`) says a shared 400 G upstream
   port sustains ~24–111 full audits per 100 ms epoch, so for realistic concurrency the audit arms
   sit in the abundant regime where the whole trade-off collapses. The "equal-probe-cost frontier"
   is vacuous, exactly as the two prior gates argued.
3. **The only arm that ever beats round-robin is `capacity_weighted`** — itself a trivial
   weighted-round-robin, not the lifecycle — and only in the budget-binding regime, by ~2–15 %
   (e.g. 15275 vs 15925), vanishing to an exact tie once the budget is abundant. It never involves
   the evidence-lease, the switch-cap, probation, or INCONCLUSIVE.

## Cross-check discipline (repo CLAUDE.md) — applied, not bypassed

- **Safety and usefulness reported together.** `permanent_quarantine` shows 0 unsafe **and**
  act-rate 0.00 with maximal stranded capacity — scored as safe-and-useless, never as "0% unsafe"
  alone. `fixed_timer` shows act-rate 1.00 **and** 3–42 unsafe restorations — the blind arm buys
  action with danger.
- **Cheap/clean/decisive was interrogated.** The audit arms' 0.0/0.0 columns are honest *because
  the audit was modelled as a perfect per-link oracle by construction* — the generous choice. Even
  so, the novel arm ties the trivial one; the finding points against the novel bet, which is the
  safe direction for a generosity bias.
- **The upper bound behaves.** `oracle` and `continuous_probe` dominate everything and never post
  unsafe restorations; had they lost, the harness would be suspect (they don't).

## Why this is a FAIL, not a "needs tuning"

The tie is **structural, not parametric**. `earliest_deadline == round_robin` holds for any
recovery-time distribution, any budget, any concurrency, because neither policy consults recovery
information. Making recovery bursty, correlated, or heavy-tailed changes both arms identically. The
only thing that could break the tie is a predictor of which starved link will recover next — and
that is a non-goal (§10) and would be the contribution, not the lifecycle. There is no honest knob
that revives the lifecycle as a Pareto winner over a trivial baseline.

This matches and quantifies the two prior gates: `GATE2-AUDIT-BUDGET.md` (the cap protects ~67 ms
of a link quarantined for minutes-to-days → the overhead axis is vacuous) and
`NOVELTY-GATE-HEALING-2026-09-02.md` (NARROW, with the explicit caveat that an always-INCONCLUSIVE
arm is safe-but-useless and the equal-cost frontier must be shown non-vacuous before any P4). The
frontier is vacuous.

## What survives (unchanged from the prior gates — none of it is the lifecycle)

The gate does **not** touch the two things the novelty gate isolated as genuinely unoccupied,
because neither is a healing-*policy* claim:

1. **Steered acquisition of congruent, witness-validated evidence on a directed sublink that
   per-packet spraying has starved** — a *capability* nobody has, needing no budget and no
   lifecycle to be interesting.
2. **The empirical dark-link quantification** — how much of a real sprayed fabric goes
   observationally dark under a stated mitigation policy, and for how long.

Those remain candidate contributions on their own merits. The *healing lifecycle as a scheduling /
evidence-lease / probation policy* is not — a trivial round-robin ties it.

## Recommendation

Stop lifecycle Tasks 2–5 and 7–10 of
`docs/superpowers/plans/2026-08-28-counterfactual-observability.md`. Do not write the audit-cap
P4, the lifecycle policy, or the BFRT audit loop on the strength of a healing-policy advantage —
there is none over a trivial baseline. Keep Task 6 (W4 semantic closure) as costed known
infrastructure. If the direction proceeds, it must proceed on the **capability** (steered
acquisition under spraying) and the **empirical measurement**, framed as such — not on the
lease/cap/probation/scheduling lifecycle.

## Reproduce

```bash
sim/.venv/bin/python -m pytest sim/gate/tests/test_healing.py -q      # 12 tests, incl. the crux
sim/.venv/bin/python -m sim.gate.healing_gate --seeds 30              # the tables above
```

Artifacts: `sim/gate/healing.py`, `sim/gate/healing_gate.py`,
`sim/gate/tests/test_healing.py`, `sim/gate/results_healing/pilot_2026-09-02.txt`.
`controller/infer.py` untouched (hash `1cc6349a`); no hardware, no P4, no switch access.
