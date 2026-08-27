# Co-simulation results on the rehearsal trace (LULESH-8, 128-node fat tree) — 2026-08-27

Setup: htsim `-mcp_policy extern:` ↔ `controller/sim_bridge.py`; frozen localizer
`controller/infer.py` (hash `116ffc9f…`: upper-sided binomial-LLR loss CUSUM, pooled baseline,
zero-count probes = no information, h = 6.5 nats); one uplink drawn per seed with 1e-3 silent
loss from 500 ms; 100 ms epochs; 55 epochs per run; TTL from onset, censored at the horizon.
Tuning split = seeds 6–10 (PREREG §3.2: 64 mcp configs, 9 cusum configs, `run_tuning.sh`,
`analyze_tuning.py` → `conf/tuned/*.yaml`); evaluation split = seeds 1–5 (`run_eval_tuned.sh`).

| budget | arm | median TTL (epochs) | TTLs seeds 1–5 | censored |
|---|---|---|---|---|
| 32/128 | uniform (B10) | 9 | 4, 7, 9, 33, 36 | 0/5 |
| 32/128 | random (B9) | 8 | 8, 8, 8, 36, 39 | 0/5 |
| 32/128 | cusum (localizer suspects + round-robin, tuned explore 0) | 9 | 4, 7, 9, 33, 36 | 0/5 |
| 32/128 | mcp (tuned: dlinucb, α 0, floor 0.75) | 9 | 8, 8, 9, 30, 35 | 0/5 |
| 4/128 | uniform | 31 | 31, 25, 10, 36, 50 | 1/5 |
| 4/128 | random | 22 | 9, 10, 22, 50, 50 | 2/5 |
| 4/128 | cusum (tuned explore 0) | 31 | 31, 25, 10, 36, 50 | 1/5 |
| 4/128 | mcp (tuned: linucb, α 2, floor 0.75) | 34 | 26, 25, 34, 35, 50 | 1/5 |

**Reading.** With one stationary silent-loss fault and no informative context, time-to-localize
is decided by *when the faulty link is first probed after onset*; every arm at equal budget
covers links at the same rate, so all arms tie within seed noise. The tuning block selected the
most coverage-like MCP configurations (floor 0.75) — the learner has nothing to learn here.
Localizer sanity: every alarm in every run is on the faulty link (0 false alarms in 90 runs).

**What this does and does not say.** It validates the pipeline (co-sim, common inference layer,
equal-budget tuning) and sets the floor for H1: MCP must beat uniform by ≥ 30 % on the *Tier-1
evaluation* (PREREG §9: MoE traces, fault catalogue F0–F9, non-stationary configurations), where
context (per-link load — the MoE fabric is idle outside communication bursts, H27) and multi-fault
/ background-loss scenarios give a learner something to exploit. On this rehearsal trace the
thesis's H1 would be *falsified*; that is the baseline the Tier-1 runs have to move.

Bugs found on the way (all fixed, all in git): per-element warm-up blind to sparse probing;
two-sided loss CUSUM tripping on healthy links; idle (0/0) probes read as 50 % loss; Beta prior
mass on light probes alarming; learner exploitation collapse (coverage floor added).
