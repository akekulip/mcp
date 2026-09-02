# Statistical decision layer: redesign proposal for the four open questions (2026-09-02)

Scope: a design proposal for Philip to evaluate, not an implementation — no code is touched. It
answers the four questions in `STATS-LAYER-STATUS-2026-09-02.md` §"Why this is a stop-and-replan
point", grounded in `controller/floor_estimator.py`, `controller/absolute_eprocess.py`,
`controller/mitigation_weight.py`, `controller/relative_eprocess.py`, `controller/decision_loop.py`,
and the round 1-3 measurements in `STATS-LAYER-REVIEW-2026-09-02.md`. Confidence is stated per
claim; several parts are judgment calls flagged for a statistician's sign-off, not settled math.

## Q1 — Coupling the primary detector's alternatives grid to a moving floor

**Mechanism.** Do not copy `_restoration_grid`'s pattern (rebuild the whole grid, and a fresh
`FleetAbsoluteEProcess`, from scratch) onto the primary detector. Restoration recenters at one
discrete event (`arm()`) with an all-zero log-capital vector, so nothing needs reconciling. The
primary detector accumulates log-capital continuously across thousands of epochs; rebuilding its
grid every tick would strand capital for vanished alternatives or force a reset every tick, which
defeats "sustained evidence" and re-creates the alpha-spend-on-every-change problem already
rejected for censoring. Instead, re-parameterize the grid as **fixed ratios above the floor**
rather than fixed absolute rates: fix multipliers `r_1 < ... < r_k` once at construction (e.g. 2x,
5x, 10x, 50x), and at tick `t` use `alt_j(t) = min(floor(t) * r_j, 1 - eps)` in the LR term.
`log_capitals` stays indexed by the fixed ratio `j`, not an absolute value, so nothing needs
reconciling — only the number substituted each tick changes.

**Argument.** The martingale property `E[e_t | F_{t-1}] = 1` requires only that the null AND every
alternative used in epoch `t` be `F_{t-1}`-measurable — not fixed across time. This is exactly the
argument the code already uses to justify a moving null against a fixed alternative, and it
generalizes without modification to a moving alternative against a moving null: the expectation is
per-epoch, conditional on both numbers already being fixed before that epoch's outcome. I am
confident re-centering on `floor(t-1)` this way needs no different mathematical treatment. What
actually caused the 1.2e+74 explosion is not "the grid was fixed" but which direction the floor
error pushed it relative to the truth: fixed absolute alternatives sat below the contaminated
(inflated to 0.1) floor, so clean ~1e-3 traffic fit those low alternatives far better than the
inflated null, and every term was strongly positive. Ratio-above-floor alternatives structurally
cannot land on that side of an inflated floor: if floor is wrong-high, the alternatives are
wrong-higher still, so floor stays the relatively better fit and log-capital decays instead of
exploding. This specifically neutralizes the inflated-floor direction that caused the cascade.

**Risks.** This does not fix floor mis-calibration, only one direction of its symptom. If the floor
is under-estimated instead (thin or unlucky cold pool), a ratio-above-floor alternative can land
close to a sublink's true, still-healthy rate and the same false-alarm mechanism reappears mirrored
— coupling protects against wrong-high, not wrong-low. Re-parameterizing as ratios also changes
their engineering meaning from an absolute target ("detect 2e-3") to a relative one ("detect 5x the
current floor"), so the H1 power targets (14k/54k packets at δ=1e-3) need re-derivation, not
inheritance. I am not fully confident the previsibility argument survives cleanly once the floor
used to build `alt_j(t)` is itself a leave-one-out estimate rather than an exogenous previsible
constant — the docstring's own claim already rests on "any previsible null value," so this
inherits rather than introduces the assumption, but it is exactly what Q3 shows can be violated at
fleet scale. A statistician should confirm the argument is unaffected by estimator-induced (versus
exogenous) drift.

**Validation plan.** (1) `E[e_t] = 1` Monte Carlo under a stationary floor (regression baseline).
(2) Same under a previsible-but-drifting floor including step changes. (3) Exact replay of the
round-3 cascade with the ratio-grid substituted in, confirming clean-sibling wealth no longer
explodes. (4) The mirrored case — deliberately deflate the floor and check whether false alarms
reappear, to size how directional the fix really is. (5) Re-derive the packets-to-alarm power curve
under the new grid against the 14k/54k figures.

## Q2 — Anchoring suspect-rate estimation to evidence since degradation actually started

**Mechanism.** Drop the separately-tracked trailing window. Use the primary process's own
`_log_capitals` to locate a change-point, then compute the suspect rate from raw counts only after
that point: (1) track, per alternative, the epoch of the running minimum of its cumulative
log-capital trajectory — one cheap running-minimum scalar per alternative, added to
`FleetAbsoluteEProcess`. (2) At arming time, let `j* = argmax_j log_capitals[j]` and `t_start` = the
last running-minimum epoch for `j*`. (3) Estimate `suspect_rate` from raw `(tx, lost)` totals over
`[t_start, t]` only, reusing `floor_estimator.py`'s existing raw-total bookkeeping, re-anchored from
a fixed lookback to `t_start`.

**Argument.** `j* = argmax_j log_capitals[j]` is the discretized GLR statistic: the alternative the
accumulated evidence currently supports best. The running-minimum-of-cumulative-log-LR construction
is the standard CUSUM change-point estimator (Page 1954): given a post-change hypothesis, the MLE of
the change time is where that hypothesis's cumulative log-LR trajectory last bottomed out before its
final climb. This is an established estimator, not a bespoke one, and needs no state beyond what the
primary process already carries. It directly targets the round-3 failure: arming fired on the same
tick a fixed backward-window contained zero degraded epochs; the change-point estimate instead
points at or before the actual turn, so the raw-count window is guaranteed to include some of the
epochs that produced the climb rather than being dominated by a long healthy prefix.

**Risks.** CUSUM estimators have a known detection delay — they tend to place the change slightly
after the true onset, since early post-change epochs still look like noise. So the anchored window
will still understate the true rate somewhat, just far less than a fixed window or a lifetime
average; this needs measuring, not assuming. At low degraded-epoch counts `t_start` can sit right
next to `t`, giving a 1-2 epoch, high-variance estimate that feeds `RestorationEProcess.arm`'s
validity guard directly — it can either fail the guard (safe but delayed) or, by chance, overshoot
into an artificially easy restoration null. This argues for a minimum sample-size floor on
`[t_start, t]` before arming — a real tuning knob, not something to skip. I considered and reject
seeding restoration's initial capital directly from a transform of the primary process's own
`log_capitals`: that reuses the same data twice (once building the primary belief, again inside a
"fresh" process meant to start unbiased at wealth 1), corrupting restoration's own anytime-validity.
The change-point-then-fresh-raw-count design avoids this because raw counts are plain sufficient
statistics, not an already-processed LR sequence.

**Validation plan.** Replicate round 3's 4/4 and 0/8 measurements with the anchored estimator, swept
across degradation severities and onset-to-arming delays, reporting suspect-rate estimation error
(not just action-rate) against ground truth. Check the CUSUM estimator's own delay/false-alarm
trade-off in this Bernoulli setting against the closed-form sequential-changepoint literature rather
than re-deriving it. Re-measure the H2/H3 restoration action-rate target (≥0.9) end to end, since
arming can still fail downstream for unrelated reasons (e.g. the grid-headroom trap already noted).

## Q3 — Designed behavior when a large fraction of the fleet is simultaneously unhealthy

**Evaluated options.** A fixed absolute fallback (`min_floor`) is correctly rejected — it is chosen
with no reference to what the fleet looks like when healthy, so it manufactures false alarms by
construction (measured 200/200). A **longer historical baseline fallback** is different: an EWMA or
block-average of the fleet's healthy rate on a much slower timescale than the live leave-one-out
window, **frozen rather than updated while the live estimator is untrustworthy** (refreshed only
during confirmed-healthy stretches). This approximates the fleet's typical healthy rate rather than
guessing a constant, sidestepping round 1's actual objection. Expanding the live pool to include
recently-unhealthy siblings with a discount factor is, on inspection, a knob on how much of the same
contamination to admit, not a fix — it reintroduces the round-3 feedback loop more slowly, so I do
not recommend it as a primary mechanism.

**Recommendation.** Add an explicit fleet-wide incident regime, gated on a calibrated threshold θ
(e.g. the fraction of sublinks with `weight < 1.0`). Below θ, keep current behavior (censor on a
thin live pool — the ordinary cold-start case round 1 addressed, where censoring remains correct).
Above θ: (a) freeze the slow-moving baseline so the incident cannot corrupt it, (b) let thin-pooled
sublinks fall back to that frozen baseline, discounted (treated as lower-confidence — shrunk
effective sample size or wider alpha margin — not a fully trusted numeric floor), and (c) hand
primary attribution responsibility to the relative discriminator (Q4) for the incident's duration,
since an absolute test against any floor cannot itself distinguish many independently bad links from
one shared cause depressing apparent fleet health, while a floor-free relative test can. Crossing θ
should itself be an operator-facing signal, not a silent continuation of per-link decisions — this
mirrors standard multiple-testing practice of treating an implausibly high rejection fraction as
evidence the testing machinery has a systematic problem, not that 30-50% of the population
independently turned out non-null.

**Risks.** θ and the discount factor are genuine judgment calls needing simulation, not intuition —
too low triggers on ordinary noise and loses power permanently; too high lets the cascade run most
of its course first. The frozen baseline can be stale if the fleet's true healthy rate has genuinely
shifted (e.g. a permanent firmware regression, not a transient incident) — freezing protects against
contamination but fights a genuine permanent shift, and the loop has no way to tell these apart
except operator intervention or a long re-baselining period after the regime ends.

**Validation plan.** Sweep θ against the round-3 cascade and measure how much of the fleet is
falsely mitigated before the regime engages, versus false-trigger rate on ordinary healthy-fleet
noise across seeds. Separately simulate a genuine widespread degradation to confirm the regime does
not suppress the response to a real event it should flag loudly.

## Q4 — Does the relative discriminator help the shared-shock problem and the cascade equally

**Analysis.** These are causally distinct, and the conditional-multinomial-given-totals construction
handles only one by default. A common-mode shock (round-2 CRITICAL C) is exogenous: it raises loss
roughly uniformly across siblings sharing the affected resource, so conditional on the stratum
total, each sibling's share stays near its known spray weight. Because the relative test conditions
on the total and needs no floor estimate, it is blind to aggregate magnitude and sees only share
deviation — exactly the disambiguation it was built for; I am confident wiring it addresses
CRITICAL C essentially as specified.

The round-3 cascade is endogenous: many sublinks' actual delivered traffic never degraded together
— the floor estimator's own bookkeeping (delayed healthy-tagging plus the fixed-vs-moving grid
mismatch) produced false absolute alarms on sublinks whose real behavior never changed. Those
sublinks' true loss shares, where there is any loss to condition on at all, would still sit at their
known spray weight, so a relative test run purely in parallel would see nothing anomalous and would
not by itself prevent round-3's deadlock.

It can still help in a different role: **gate mitigation actions on corroboration** rather than
report alongside the absolute test — require genuine excess share (whenever a stratum-epoch has
enough loss to be informative) before acting on an absolute-test alarm. A falsely-cascading sublink
would then fail to show excess share and stay unmitigated, while the one genuinely degraded sublink
would show both an absolute alarm and real excess share and still be acted on. This is a meaningful
design change from "wire it as designed" — it changes how the two processes compose, not just
whether the second one runs.

**Risks.** The relative test needs a stratum-epoch with nonzero total loss to say anything; if the
one real fault's losses sit in a different context/stratum than the falsely-cascading siblings,
there may be no informative epoch to exonerate them with. There is also a self-starving risk
specific to the gating role: once a falsely-cascading sublink's weight drops from the absolute-side
false alarm, it carries less traffic, meaning less data to accumulate the corroborating evidence
that would clear it — starved exactly when needed most. This also requires the queue-depth/context
stratification that does not exist anywhere yet (round 1's HIGH 3), a real data-plumbing lift, not
a pure controller-side change.

**Validation plan.** Confirm the relative test alone resolves CRITICAL C (re-run the round-2
common-mode scenario as a parallel stream, check the false-rejection rate returns to baseline).
Separately confirm a parallel, non-gating stream does NOT prevent the round-3 cascade (the
falsifiable null result here), then re-run with the gating composition and measure whether the
cascade breaks and how much traffic reduction the corroboration signal survives before starving.

## Recommended build order if all four are approved

1. **Q3's incident-regime circuit breaker first.** Cheapest, most self-contained change (a
   fraction-mitigated threshold plus a frozen historical baseline), and bounds the worst-case blast
   radius — permanent fleet-wide deadlock — regardless of how the harder fixes below turn out.
2. **Q1's ratio-relative primary grid next.** Most localized and best-understood mathematically,
   directly targets the measured 1.2e+74 trigger; everything downstream (arming, the relative-test
   gate) depends on the primary detector's alarms being trustworthy first.
3. **Q2's change-point-anchored suspect-rate estimation third.** Depends on Q1 being stable and is
   otherwise a self-contained addition to `floor_estimator.py` and `decision_loop.py`.
4. **Q4's relative-discriminator gating last.** Largest lift (real stratification plumbing, not
   just controller logic); its cascade-mitigating value can only be measured meaningfully once Q1
   already removes the primary trigger, or an observed improvement cannot be attributed correctly.
5. Before any of this: fix the two tests round 3 found do not kill their intended mutants (a full
   revert of the restoration-grid coupling, and a full revert of both `suspect_rate` clamps, both
   still pass 206/206) — the suite should catch a regression of any of the four fixes above, and
   currently would not.
