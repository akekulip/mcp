# Adversarial review — statistical decision layer (2026-09-02)

Dispatched `code-reviewer` agent report, filed verbatim (lightly reformatted) because the earlier
qa-verifier PASS on the same code did not catch any of this. Reviewed against
`docs/review/BRAINSTORM-2026-09-01.md` §2 and `docs/superpowers/plans/2026-09-02-statistical-decision-layer-plan.md`.

Baseline: `python3 -m pytest controller/ -q` -> 187 passed. The tests pass; several pass *because
of* the bugs below.

## Verdict: BLOCK -- 3 CRITICAL, 3 HIGH

The statistics itself is right; the wiring is not. Both likelihood ratios were independently
re-derived and confirmed correct (`absolute_eprocess.py`, `relative_eprocess.py`), the e-BH
procedure is a genuine largest-qualifying-k Wang-Ramdas implementation (`fleet_control.py`), and
restoration really does reuse the same engine with null/alternative swapped
(`mitigation_weight.py`). Every critical defect is in `decision_loop.py` and `floor_estimator.py`
-- the layer that feeds these correct kernels.

### CRITICAL 1 — empty leave-one-out pool falls back to `min_floor`, guaranteeing false alarms

`floor_estimator.py:67-68`: `if pool_tx < self.min_pool_tx: return self.min_floor` (1e-6 by
default) — the most anti-conservative null available. Reachable on the first tick, on a
single-sublink snapshot, and when every sibling is under mitigation simultaneously (the loop marks
`healthy = last_weight >= 1.0`, so a mitigated fleet empties its own pool).

Measured (fleet fully healthy, 2e-3 background, alpha=0.05):

| configuration | false e-BH rejections |
|---|---|
| single sublink in the snapshot (empty LOO pool) | 200 / 200 |
| 6 sublinks, all siblings under mitigation | 195 / 200, floor in use = 1e-06 |

Single sublink, 2000 trials, W=20, true rate 2e-3: no warm-up -> 34.3% of trials alarm on epoch 0
alone; 20-epoch warm pool -> 0.016.

**Fix:** `floor_for` returns `Optional[float]` (`None` when the pool is thin), and the caller
treats `None` as a censored epoch (factor of one, no reset) rather than substituting a number.

### CRITICAL 2 — the floor is not previsible as wired

`decision_loop.py:78-86`: every sublink's *current-epoch* `(tx, rx)` is recorded into the estimator
before floors are computed. Leave-one-out removes the sublink's own sample but not siblings'
same-epoch outcomes, so under a shared shock (exactly the scenario the relative-test discriminator
exists for) the floor is contaminated.

| scenario (all healthy, alpha=0.05) | P(any e-BH rejection) |
|---|---|
| stationary, W=20 | 0.185 |
| common per-epoch congestion shock, W=20 | 0.500 |
| common shock, W=1 | 0.320 |

The two docstring claims of previsibility (`absolute_eprocess.py:14-17`, `floor_estimator.py:9-11`)
overclaim and need correcting either way. The `healthy` flag itself IS genuinely previsible
(computed from `last_weight` as of the end of the prior tick); the leak is in the counts, not the
flag.

**Fix:** two-pass ordering — compute all floors from the window through epoch t-1, *then* record
epoch t. The two CRITICAL bugs mask each other: fixing only one in isolation measured *worse*
(previsible ordering with a cold pool measured 0.366). Must fix together.

### CRITICAL 3 — restoration can arm on a null derived from the epoch it then tests, and can become permanently unrestorable

`decision_loop.py:99-106` sets `suspect_rate` from the arming epoch's own empirical rate and then
immediately ingests that same epoch against it (circular, directionally conservative but a data
leak). Worse: arming triggers as soon as `weight < 1.0` (roughly `wealth > 1.0`, a low bar), and if
the arming epoch's rate is at or below the largest healthy alternative, every mixture component
bets the wrong way and wealth decays monotonically forever. At an ordinary per-epoch packet count
(tx=5000), 4/4 armings on a fully healthy fleet produced an unrestorable null. Directly breaks the
brainstorm's H2/H3 "action rate >= 0.9 per repaired fault."

**Fix:** arm from evidence accumulated *before* the arming epoch (not the arming epoch itself);
add a guard in `RestorationEProcess.arm` rejecting `suspect_rate <= max(healthy_alternatives)`;
arm on real sustained evidence, not `wealth > 1.0`.

### HIGH 1 — censoring implemented but unreachable

`FleetEpochRecord.censored` is correctly implemented (factor of one, no reset, no alpha-halving)
but `FleetDecisionLoop.tick` never sets it and `RestorationEProcess.ingest` has no such parameter
at all. Same fix as CRITICAL 1.

### HIGH 2 — `relative_eprocess.py` is dead code

Referenced only by its own test file. `decision_loop.py` never calls it, so the congestion-vs-gray
discriminator the design specifically kept is unreachable.

### HIGH 3 — no context (4-bit) stratification anywhere

Brainstorm C2 requires both detectors to stratify by context; none of the three fleet-facing
modules carry a stratum key.

## Weakened tests

- `test_fleet_control.py`'s `test_non_monotone_qualifying_k_is_still_found` asserts a case where
  the correct answer and a broken (break-on-first-failure) implementation agree — zero real
  coverage of e-BH's one non-obvious property. A discriminating case exists (`{1:5.0, 2:4.0,
  3:3.0}`, alpha=0.5 -> correct answer rejects all 3, broken implementation rejects none).
- The Monte Carlo validity assertions in `test_absolute_eprocess.py`/`test_relative_eprocess.py`
  used `< 0.15` against a realized rate of 0.010 for the correct implementation — loose enough that
  a plausible off-by-one in the exponent (using `tx` instead of `delivered`) or a 10x-mis-scaled
  alternative grid both still pass. A direct `E[e_t] == 1` assertion is the sharp, mutation-sensitive
  check.
- `test_decision_loop.py::test_weight_never_drops_below_w_min` and
  `test_floor_estimator.py::test_cold_start_returns_min_floor` both exercise/assert CRITICAL 1's
  failure path as if it were intended behaviour.

## Medium (not blocking, worth doing while in this code)

- **M1** the "trailing window" never actually reads the stored `epoch` field to prune by age, only
  by count — pruning should be `sample.epoch <= epoch - window_epochs`.
- **M2** `floor_for` is O(S) per call and called once per sublink per tick -> O(S^2 * W) per tick;
  measured 1.76s for a single tick at S=1024, W=20 (the design's own target scale). Maintain
  running per-sublink and fleet totals instead.
- **M3** the idle-epoch (`tx==0`) restoration-arming fallback uses the *healthy* floor as the
  *suspect* rate — backwards.
- **M4** restoration arms on `wealth > 1.0` (roughly a coin flip under the null: 51/200 armed on a
  healthy fleet in one measurement) and never disarms except on recovery, so `restoring=True` can
  be reported for a link already back at full weight.
- **M5** the alternative grid is fixed at construction while the floor moves; validity survives but
  power is silently lost once the floor drifts above grid points.
- **M6** `fleet_control.e_bh_reject`'s `value < 0.0` check passes for `NaN`, which then corrupts the
  sort.
- **M7** several constructors defer validation to first use rather than validating eagerly.
- **M8** missing type hints on several private attributes/returns (repo style rule); `controller/__init__.py`'s `__all__` was never updated for the six new modules.
- **M9** `mitigation_weight.py`'s docstring says "strictly decreasing"; the function is constant at
  1.0 for `wealth <= 1`, strictly decreasing only on `(1, inf)`.

## What was NOT wrong

No scope creep (six focused files, 509 lines total, largest 132; every out-of-scope item from the
plan really is absent; no pre-existing file was touched). No fake progress at module level — every
function does what its name says in isolation. The fake progress, if any, is one level up:
`decision_loop.py` presents itself as wiring everything together while omitting the relative
discriminator, never exercising the censoring path, and computing a null that invalidates the
property the layer exists to provide.

## Suggested order of work (adopted for the overnight fix pass)

1. CRITICAL 1 + 2 together (they mask each other) — re-run a fleet-scale null Monte Carlo and
   require the empirical rate <= alpha.
2. CRITICAL 3 — the `arm()` guard first, then the arming policy.
3. HIGH 1 falls out of the CRITICAL 1 fix.
4. Fix the two weak tests with the discriminating e-BH case and an `E[e_t] = 1` assertion.
5. Decide explicitly whether HIGH 2 (relative test) and HIGH 3 (context stratification) are wired
   this pass or formally deferred — do not leave them silently dead.
6. M1 and M2 before this ever runs at 1024-sublink scale.
