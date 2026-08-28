# M1 — exact replay: the decomposition and the scoped negative result (2026-08-27)

Harness: `sim/gate/replay.py`. Inputs: the per-link counter logs recorded by htsim for the 30
pre-registered gate seeds (`results_real_v12/`). Detector: the frozen localizer
(`controller/infer.py`, hash **`0a989aaf`**, h = 6.5 nats, δ = 1e-4, pooled) — the detector PREREG
§3.3 names, not the simulator's ratio rule (PREREG v1.5 §1).

**Re-issued 2026-08-28 under PREREG v1.6.** Every number below was recomputed after four fixes; the
v1.5 numbers this file previously carried are superseded, not deleted (the amendment tabulates
both). (1) The localizer's warm-up counted *update calls*, so a schedule reading every fourth epoch
was held in warm-up four times as long as one reading every epoch with the same packets per read —
it is now counted in observed packets (1e5 = 10/δ). (2) Semi-synthetic fault identities came from
Python's per-process-salted `hash()` and were not reproducible; they now use CRC-32. (3) Multi-fault
success was implicitly "the recorded fault, distractors ignored"; the objective is now explicit
(`any` / `all` / `original`) and printed in every run header. (4) The oracle was handed only the
recorded fault, so under `all` it was not an upper bound (uniform beat it); it is now handed every
injected fault.

## Why replay is exact

The counter logs are **byte-identical across all five measured arms for every seed (120/120
arm-seed pairs)**: the measurement policy never perturbs the simulated fabric. Replaying a
different read schedule over the recorded counters therefore reproduces exactly what that schedule
would have observed — it is not a model.

**Validation.** Replaying `uniform` reproduces the recorded arm per seed: of 10 seeds checked,
every uncensored seed matches to the epoch (31, 27, 18, 14, 19, 17, 26) and all three censored
seeds are censored in both. The candidate order matters and was the earlier discrepancy: the
simulator enumerates uplinks agg-major, core-minor (`main_uec.cpp:816-819`), not lexicographically.

Cost: **3 minutes** for 6 schedules × 5 budgets × 30 seeds, against 64 minutes *per run* in htsim.

## C1 — detection delay decomposes into evidence time + coverage time

At the pre-registered budget (41 of 1024 uplinks), medians over uncensored runs:

| schedule | evidence time (first observable drop − onset) | coverage time (localization − first drop) |
|---|---|---|
| oracle (handed the faulty link) | 8.0 | **1.0** |
| in-band invariant (H8) | 8.0 | **1.0** |
| in-band, collected every 4th epoch | 8.0 | **1.0** |
| uniform round-robin | 8.0 | **10.0** |
| threshold-gated round-robin | 8.0 | **11.0** |
| load-gated round-robin | 8.0 | **16.0** |

Evidence time is a property of the fault and the traffic phase — no scheduler touches it. Coverage
time is the entire compressible term, and it is the larger one at this operating point.

## C2 / H9 — no counter-computable schedule closes the coverage gap

KM median TTL from onset, 30 seeds, censored counts in parentheses; the paired column is a
two-sided sign test against uniform.

| budget | uniform | random | load-gated | threshold-gated | greedy-information | oracle | **in-band (H8)** | in-band, sync/4 | gap closed by the best counter-computable schedule |
|---|---|---|---|---|---|---|---|---|---|
| 10 (1 %) | >32 (27) | >32 (28) | >32 (27) | >32 (27) | >32 (23) | 9.0 (0) | **9.0 (0)** | 10.0 (0) | — (all censored) |
| 20 (2 %) | >31 (15) | >32 (20) | 27.0 (12) | 27.0 (12) | >32 (18) | 9.0 (0) | **9.0 (0)** | 10.0 (0) | — |
| **41 (4 %, frozen point)** | **18.0 (4)** | 22.0 (13) | 24.0 (3) | 20.0 (1) | 22.0 (7) | **9.0 (0)** | **9.0 (0)** | 10.0 (0) | **0 %** |
| 82 (8 %) | 15.0 (0) | 20.0 (6) | 14.0 (0) | 14.0 (0) | 14.0 (0) | 9.0 (0) | **9.0 (0)** | 10.0 (0) | 17 %, p = 0.56 |
| 200 (19.5 %) | 11.0 (0) | 12.0 (0) | 11.0 (0) | 11.0 (0) | 12.0 (0) | 9.0 (0) | **9.0 (0)** | 10.0 (0) | 0 % |

**The in-band column does not move with the budget.** Every counter-computable schedule degrades as
the read budget falls — at 1 % of uplinks they are all censored past the horizon — while the in-band
invariant sits at 9.0 epochs from 1 % to 19.5 %, because its evidence is carried by the packets and
is not budgeted at all. That, not a win at one operating point, is the shape of the claim.

**Wrong-link alarms: 0 epochs in 0/30 seeds for every arm at every budget** on these clean-background
runs (h = 6.5). The false-alarm axis proper needs the F0 background-loss block (BG_LOSS = 1e-4, no
fault), which is running.

**Robustness (the review's biggest hole, now closed).** At the frozen budget:

Multi-fault success semantics are now stated per row rather than assumed (`--objective`):
*any* = the top-ranked element is any injected fault; *all* = every injected fault has been
top-ranked; *original* = the recorded fault only, the synthetic ones are distractors.

| regime | objective | uniform | threshold-gated | oracle | **in-band** | in-band sync/4 | gap closed by in-band |
|---|---|---|---|---|---|---|---|
| single fault | — | 18.0 (4 cens) | 20.0 (1) | 9.0 (0) | **9.0 (0)** | 10.0 (0) | **100 %** |
| two faults (1 recorded + 1 synthetic at 1e-4) | any | 13.0 (0) | 11.0 (1) | 4.0 (0) | **4.0 (0)** | 4.0 (0) | **100 %** |
| two faults | all | 25.0 (8) | 28.0 (13) | 15.0 (9) | **17.0 (10)** | 20.0 (11) | 80 % |
| two faults | original | 20.0 (8) | 22.0 (6) | 13.0 (8) | **15.0 (9)** | 16.0 (8) | 71 % |
| three faults | any | 11.0 (0) | 7.0 (0) | 2.0 (0) | **2.0 (0)** | 2.0 (0) | **100 %** |
| three faults | all | >32 (23) | 32.0 (20) | >32 (21) | >32 (23) | >32 (24) | — (horizon-bound) |
| fault moves to another link at epoch 20 | any | >32 (19) | >32 (24) | 9.0 (1) | **9.0 (1)** | 10.0 (3) | **100 %** |

Two rows deserve their caveat rather than a headline. Under *all* with three faults **nothing
finishes**, the oracle included: 36 epochs is not enough to top-rank three links one after another,
so that row measures the horizon, not the arms. And the moving fault is where wrong-link alarms
appear: uniform raises 121 stale-suspicion alarm epochs across 15/30 seeds and threshold-gated 199
across 23/30 (the vacated link's CUSUM stays elevated after the fault leaves), against 14 in 1/30
seeds for in-band. Stale suspicion is a cost of accumulating counter evidence, and it is one the
in-band invariant largely avoids.

**H9 gate (PREREG v1.5): not tripped.** No counter-computable schedule closes ≥ 30 % of the oracle
gap *with paired p < 0.05* at any budget, fault count or objective. The nearest miss is
threshold-gated under two faults with the *any* objective (22 % of the gap, p = 0.86) and under
three faults (44 %, p = 0.59) — both statistically indistinguishable from uniform. The gate now
evaluates both conditions in the harness output instead of leaving the significance test to the
reader, and it ranks only counter-computable schedules: the in-band arms answer a different
question and are reported apart. The allocation thesis stays retired.

**The honest nuance, against the panel's stronger claim.** Load gating is not uniformly dead: at
budget 82 it is significantly faster than uniform (22/8 seeds, p = 0.016) — but it buys 20 % of the
oracle gap, and at the operating point it is *worse* (KM 24 vs 20, though it censors less: 3 vs 6).
Nothing computable from counters approaches the oracle, which is the claim the paper makes.

## What the oracle proves

The oracle localizes in 9 epochs — 8 of them evidence time, 1 coverage — against uniform's 18. So
schedule *does* matter (a 50 % reduction is available), and no schedule computable from per-link
counters can take it. That is the gap a **link-local in-band invariant** closes by construction
(H8, M2): the first drop is itself the localization event, so coverage time → 0 and delay →
evidence time. Replayed, the invariant does exactly that — it ties the oracle to the epoch at every
budget and under every fault regime that finishes, and it keeps doing so when its verdicts are
collected only every fourth epoch (10.0 vs 9.0), which is the deployable version. What replay
cannot tell us is whether the invariant compiles into the pipeline and whether its false-gap floor
on silicon is below the fault rate; that is M2, and it is the claim's load-bearing risk.

## Still open in M1

The h-sweep (ADD vs false-alarm rate) needs no-fault (F0) counter logs. The batch is running on
Vision (seeds 2000–2019, BG_LOSS = 1e-4) and Hulk (seeds 2020–2029, clean); each run is ~62 min and
peaks near 21.5 GB, so the fleet is memory-bound and under watch. Once those logs land, the ROC axis
is a replay sweep over h, not new simulation.

The theory gate (M1 step 1) is untouched: the coverage/evidence decomposition is measured, but
whether the coverage lower bound is a nontrivial result or a relabelled classical adaptive-search
lemma has not been independently reviewed. Per the plan that review gates the major P4 work.
