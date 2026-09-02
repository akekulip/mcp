# Plan: statistical decision layer (roadmap step 4) + RPC-critical-path resolution (step 5)

Approved design: `docs/review/BRAINSTORM-2026-09-01.md` §2 (C2, C3) and §5 build-order steps 5, as
narrowed by the red-team (§9, findings 3/5/6). Authorized 2026-09-02 ("all authorized").

## Scope for this pass

In scope: C2's primary absolute e-process with a fleet-estimated floor, e-BH fleet control, C2's
secondary relative/multinomial discriminator, C3's continuous mitigation weight and restoration,
and wiring the whole decision loop to run off periodic census snapshots only (resolves the
RPC-in-critical-path finding from the round-3 review, disclosed via `ledger_rpc_seconds` until now).

Out of scope, explicitly deferred to later roadmap steps (§5 steps 6-9): replay arms
(SprayCheck-Z/FlowPulse-θ), JSQ spray in htsim, the physical selectivity bench, shadow probation,
data-plane e-process. None of these are touched.

## Why new modules instead of extending `evidence_ledger.py`

`SequentialEvidenceLedger` is live: used by `p4/hw/loop/sequential_trials.py` (hardware trial
harness) and `sim/clf/sequential_eval.py` (sim eval), both against a *fixed* `healthy_delivery`
null with restart-on-censor alpha-spending — a different, still-valid design for the older
epoch/bank CLF scheme. The new design needs a null that moves every epoch (the fleet floor) and
censored epochs that contribute a factor of one with no restart — a different contract, not a
generalization of the old one. Building it as new modules leaves the existing call sites and their
tests untouched.

## Modules (build order; independent pieces first, in parallel)

1. **`controller/floor_estimator.py`** — `FleetFloorEstimator`: leave-one-out $\hat p_0(t)$ over a
   trailing window of `W` epochs, excluding the sublink itself and any sublink currently outside
   the healthy pool (so a bad link cannot poison the floor used to judge it or its siblings).
   Clamped to `[min_floor, 1)`. Independent of everything else.
2. **`controller/fleet_control.py`** — `e_bh_reject(evalues, alpha)`: the Wang–Ramdas e-BH
   procedure (sort descending, reject the largest prefix `k` with `e_(k) >= n/(k*alpha)`).
   Independent, pure function.
3. **`controller/relative_eprocess.py`** — `RelativeExchangeabilityTest`: the secondary,
   stratified-by-queue-depth multinomial test used only to separate a hot spine port from a gray
   link when the absolute test cannot (brainstorm §2, second half of C2). Independent.
4. **`controller/absolute_eprocess.py`** — `FleetAbsoluteEProcess`: the primary mechanism. A
   log-spaced grid of alternatives between a configurable floor and the *current epoch's* dynamic
   null (fed in per call, not fixed at construction — this is the generalization the old ledger
   doesn't have), mixture log-likelihood-ratio betting exactly as already proven in
   `evidence_ledger.py`'s docstring, but: censored epochs multiply wealth by exactly one (no reset,
   no alpha halving — brainstorm §2 "Censored epochs contribute a factor of one; no restarts, no
   alpha halving"), and repair-generation resets keep the existing, still-correct, semantics
   (a genuine repair is a fresh sequence; a data-quality censor is not). Depends on
   `floor_estimator` only through the caller supplying the current floor per call.
5. **`controller/mitigation_weight.py`** — `weight_from_wealth(wealth, w_min)`: continuous,
   monotonically decreasing in wealth, `w(1) = 1`, `w(∞) → w_min`, never a step function
   (brainstorm §2 C3, red-team finding 5). `RestorationEProcess`: the opposite one-sided e-process
   run on the residual (weighted) stream once a link is below full weight; crossing its own
   threshold restores weight, re-armed on any subsequent repair-generation bump. Depends on (4).
6. **`controller/decision_loop.py`** — wiring. Runs on a fixed epoch tick, reads only the
   already-running `CensusWorker`'s periodic background poll results (`p4/hw/loop/controller_loop.py`
   §`CensusWorker`) — **no synchronous per-event RPC anywhere in this loop**. This is the concrete
   resolution of the round-3 review's RPC-in-critical-path finding: the statistical decision was
   always meant to run at epoch granularity (brainstorm §2: "run at the epoch level as a
   bounded-mean betting process"), so it never needed the targeted per-gap-event RPC
   (`resolve_ledger_gap_event`) that finding was about. That function is unchanged and keeps serving
   its own purpose (immediate loud-drop diagnostics on the existing `--ledger` CLI path); it is
   simply not on this new loop's path.

## Verification

Each module gets real unit tests before being called done, including at least one Monte Carlo
validity check where applicable (empirical false-alarm rate under a true null, not just a
hand-picked example) — this is new sequential-testing code and deserves the same standard as the
brainstorm's own `seq_design.out`/`peer_relative.out` simulations. `qa-verifier` runs the full
suite independently; `code-reviewer` runs the Four Hunts on the diff. Given this is genuinely new
statistics (a previsible/plug-in-null mixture e-process plus e-BH fleet control — both individually
established in the sequential-testing literature, but not previously combined and reviewed for
this specific construction), flag in the closeout that a dedicated statistics review
(`research-scientist` or the campaign's own red-team pattern) should confirm nominal alpha control
empirically before any of this feeds a paper claim — this plan delivers correct, tested engineering
of an already-approved design, not a fresh statistical proof.
