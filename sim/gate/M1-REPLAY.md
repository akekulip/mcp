# M1 — exact replay: the decomposition and the scoped negative result (2026-08-27)

Harness: `sim/gate/replay.py`. Inputs: the per-link counter logs recorded by htsim for the 30
pre-registered gate seeds (`results_real_v12/`). Detector: the frozen localizer
(`controller/infer.py`, hash `be12e7b2`, h = 6.5 nats, δ = 1e-4, pooled) — the detector PREREG §3.3
names, not the simulator's ratio rule (PREREG v1.5 §1).

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
| uniform round-robin | 8.0 | **10.0** |
| load-gated round-robin | 8.0 | **16.0** |

Evidence time is a property of the fault and the traffic phase — no scheduler touches it. Coverage
time is the entire compressible term, and it is the larger one at this operating point.

## C2 / H9 — no counter-computable schedule closes the coverage gap

KM median TTL from onset, 30 seeds, censored counts in parentheses; the paired column is a
two-sided sign test against uniform.

| budget | uniform | random | load-gated | threshold-gated | greedy-information | oracle | gap closed by the best non-oracle |
|---|---|---|---|---|---|---|---|
| 10 (1 %) | >29 (27) | >29 (28) | >29 (27) | >29 (27) | >29 (23) | 10.0 (0) | — (all censored) |
| 20 (2 %) | >27 (15) | >28 (20) | 27.0 (12) | 27.0 (12) | >27 (18) | 10.0 (0) | — |
| **41 (4 %, frozen point)** | **20.0 (6)** | 22.0 (13) | 24.0 (3) | 20.0 (1) | 22.0 (7) | **10.0 (0)** | **0 %** |
| 82 (8 %) | 15.0 (0) | 20.0 (6) | **14.0 (0)**, 22 faster/8 slower, p = 0.016 | 14.0 (0) | 14.0 (0) | 10.0 (0) | 20 % |
| 200 (19.5 %) | 12.0 (0) | 12.0 (0) | 11.0 (0) | 11.0 (0) | 12.0 (0) | 10.0 (0) | 50 %, p = 1.0 |

**Robustness (the review's biggest hole, now closed).** At the frozen budget:

| regime | uniform | best non-oracle | oracle | gap closed |
|---|---|---|---|---|
| single fault | 20.0 (6 cens) | 20.0 | 10.0 | 0 % |
| two faults (1 recorded + 1 synthetic at 1e-4) | 21.0 (10) | 21.0 | 10.0 | 0 % |
| three faults | 26.0 (13) | 26.0 | 10.0 | 0 % |
| fault moves to another link at epoch 20 | >32 (21) | >32 | 10.0 | 0 % |

**H9 gate (PREREG v1.5): not tripped.** No counter-computable schedule closes ≥ 30 % of the oracle
gap with p < 0.05 at any budget or fault count. The allocation thesis stays retired.

**The honest nuance, against the panel's stronger claim.** Load gating is not uniformly dead: at
budget 82 it is significantly faster than uniform (22/8 seeds, p = 0.016) — but it buys 20 % of the
oracle gap, and at the operating point it is *worse* (KM 24 vs 20, though it censors less: 3 vs 6).
Nothing computable from counters approaches the oracle, which is the claim the paper makes.

## What the oracle proves

The oracle localizes in 10 epochs — 8 of them evidence time, 1 coverage, 1 detector lag — against
uniform's 20. So schedule *does* matter (a 50 % reduction is available), and no schedule computable
from per-link counters can take it. That is the gap a **link-local in-band invariant** closes by
construction (H8, M2): the first drop is itself the localization event, so coverage time → 0 and
delay → evidence time.

## Still open in M1

The h-sweep (ADD vs false-alarm rate) needs no-fault (F0) counter logs, which do not exist yet:
`-mcp_bg_loss` runs were never recorded at the frozen point. One 30-seed F0 batch (~2 h on the
fleet, or replay from a single F0 recording) is required before the ROC axis can be drawn.
