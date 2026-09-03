# Application-impact make-or-break htsim measurement — 2026-09-03

**Question (the one that gates the campaign).** Under RTO-dominated recovery, does a 1e-3 grayhole
on a traffic-carrying spray uplink produce a DO-NOTHING collective-completion-time (CCT) slowdown
that mitigation could recover — or is the loss still pipeline-hidden (NULL)? This directly tests the
single make-or-break assumption fenced in `APP-IMPACT-GATE-2026-09-02.md` ("the model assumes losses
land on the barrier critical path … if htsim shows losses are largely pipeline-hidden, the gap
shrinks toward NULL").

**Verdict: NULL.** At 1e-3 on a fully-loaded uplink, with RTO-dominated recovery at τ = 40 ms, the
do-nothing CCT slowdown is **+1.362 %** (3.58752 s → 3.63638 s). That is below the 5 % promotion bar
and, because it is measured at the *largest* RTO (the worst case for do-nothing), it bounds every
smaller-τ regime too. The application-impact top-venue path does not hold at the informative loss
regime. **Recommendation: ship the mechanism / localization contribution to ToN or IMC; do not build
the full arm-differentiated application-impact campaign.**

## The measurement (seed 1000, the decisive set)

| arm | fault | rto_min_us | CCT (ps) | CCT (s) | vs CLEAN |
|---|---|---|---|---|---|
| CLEAN (no fault) | none | 40000 | 3 587 520 645 | 3.587521 | — (ceiling) |
| DO-NOTHING | US41→CS1 @ 1e-3, onset 381.7 ms | 40000 | 3 636 376 374 | 3.636376 | **+48.86 ms = +1.362 %** |

One seed is sufficient by design: seed variance on this fabric is ~0.2 %, so a >5 % effect would be
unambiguous. The effect (1.36 %) is above seed noise but well below the bar.

CCTs are read from each run's `.finish` (`Maximum finishing time`), which is independent of the
counter bookkeeping discussed below. Runs: `sim/gate/results_makebreak/{clean_rto40,donothing_rto40}`,
driven by `sim/gate/makebreak_chain.sh` over the frozen `run_gate_real.sh` invocation. Wall time
~31 min/run (`wall_s=1840`), one htsim at a time (21.5 GB RAM/run).

## Why CLEAN is the mitigation ceiling (a harness finding, verified)

The htsim MCP layer has **no mitigation actuator.** `sim/htsim/htsim/sim/mcp.{h,cpp}` show that
`McpEpoch` and every scheduler — `uniform`, `random`, **`oracle`**, `extern` — only *read* per-link
counters, pick which links to probe under a budget, and write a localization verdict to a log. None
of them ever calls `set_loss_prob`, reroutes, or otherwise perturbs the fabric. Empirical proof: at
rto300 the `uniform`, `random`, and `oracle` policies finish at the **identical picosecond**
(3 586 278 207 ps), and the repo's own note states the counter logs are byte-identical across arms.

Consequence for this gate: htsim's "oracle" is a *measurement* oracle, not the instant-perfect-
mitigation arm the task assumed — running it would reproduce DO-NOTHING exactly and waste a
62-min/21.5-GB slot. The honest instant-perfect-mitigation **ceiling** is the no-fault **CLEAN** run
(perfect mitigation removes the fault, approaching no-fault CCT). So:

> gap = DO-NOTHING − CLEAN = the **maximum CCT any mitigation could recover.** Here that ceiling is
> 48.86 ms (1.362 %). Even a perfect, instantaneous, zero-cost mitigation cannot recover more than
> 1.362 %; any real detector recovers a fraction of that. There is no 5 % to compete for.

## Realised-parameter cross-check (per CLAUDE.md — verify the fault in the DATA)

The injected fault is real, correctly sized, and on real traffic:

- **Placement.** US41→CS1 carried 307 609 packets over the job. All 1024 spray uplinks carry
  300–312 k (the spray balances load nearly perfectly); US41→CS1 is 98.4 % of the busiest uplink —
  a genuinely fully-loaded critical-path uplink, **not** the near-idle placement the gate warned
  against (H27 satisfied).
- **Magnitude.** 255 silent drops on the fault link; fabric-wide total drops = 255 (no background
  loss, so the fault is the only drop source). This is corroborated independently by the run log,
  which contains exactly 255 `MCP_DROP` lines (log 40 KB, clean finish — not truncated). Measured
  p = 255/307 609 = 8.3e-4 over the whole run, ≈ 9e-4 on post-onset traffic ≈ the nominal 1e-3.
- **Onset.** Loss active from 381.7 ms; first drop at 1.46 s (the link's incremental traffic is
  small until it ramps at ~1.5 s), last at 3.57 s. Consistent with correct onset, no injection bug.

*Correction recorded for honesty:* the counter CSV columns are **cumulative**, not per-epoch. An
initial read that summed the cumulative rows reported an inflated "4.8 M pkt / 3190 drops"; the
correct figures are the final-epoch cumulative values (307 609 pkt / 255 drops), which match the log
tally exactly. The CCT verdict is unaffected (CCT comes from `.finish`, not the counters).

## Why it is NULL: the loss is pipeline-hidden

255 drops, each able to trigger a 40 ms RTO, would cost 10.2 s if the stalls serialized onto the
barrier critical path. The actual CCT cost is 48.9 ms — roughly **99.5 % of the loss is absorbed.**
The MoE collective pipelines many chunks; a timeout on one flow's packet overlaps with other chunks'
slack, and only the worst-case straggler moves the barrier. This is exactly the make-or-break
assumption the closed-form gate flagged, now measured and found false at the informative regime.

**RTO monotonicity (why the τ = 10 ms bracket was correctly skipped).** Do-nothing CCT is
monotone increasing in `rto_min_us` — a longer minimum RTO makes every timeout stall longer, so
τ = 40 ms is the *worst case* for the do-nothing penalty. Since even the worst case is 1.362 % < 5 %,
τ = 10 ms and fast-retransmit are necessarily smaller. The NULL is robust across the whole RTO range;
no further RTO cell can rescue it. (The chain was wired to run τ = 10 ms only if τ = 40 ms cleared
5 %; it correctly did not.)

**Loss-regime reminder (from the gate).** Going higher than 1e-3 does not help the *detection*
story: at ≥ 5e-3 fault severity swamps detection and all arms tie the oracle (uninformative). 1e-3 is
the informative regime, and it is pipeline-hidden. There is no loss regime that is both
detection-informative and CCT-material on this fabric.

## Actuator feasibility (design-only, no build) — `-mcp_loss_clear_ms` as scheduled fault-CLEAR

**Assessment: a small, faithful change for the detect-latency + localization-correctness question,
but it deliberately does NOT model reroute capacity cost (the known NULL-flip risk). Effort ≈ half a
day including recompile and driver glue. Given today's NULL, build it only after a regime with a
>5 % do-nothing penalty is first found.**

The loss model is a single predicate in one place. `Pipe` (`pipe.h`) holds `_loss_prob`,
`_loss_onset` ("loss inactive before t"), `_loss_rng`; the only drop site (`pipe.cpp` L67–68) is
`if (_loss_prob>0 && now()>=_loss_onset && rand<_loss_prob) drop`. A scheduled clear is the
symmetric upper bound on that same predicate.

htsim code change — mechanical, ~8–10 lines across 3 files, backward-compatible:
- `pipe.h`: add `simtime_picosec _loss_clear{0};` and `void set_loss_clear(simtime_picosec t){_loss_clear=t;}` (2 lines).
- `pipe.cpp`: extend the drop predicate with `&& (_loss_clear==0 || now() < _loss_clear)` — the `==0`
  sentinel means "never clear", so existing runs are unchanged (1 line).
- `main_uec.cpp`: parse `-mcp_loss_clear_ms` (mirror the `-mcp_loss_onset_ms` block at L428–429,
  ~3 lines) and call `l.pipe->set_loss_clear(timeFromMs(mcp_loss_clear_ms))` in the fault-injection
  loop after `set_loss_onset` (~1 line); optionally echo it to the log.
- Recompile htsim (~2–4 min).

Driver/campaign glue (the real work, but pure Python, no new sim semantics, no change to the frozen
`infer.py`): per (arm, seed), set `clear_ms = onset_ms + measured_detect_ms(arm)` **iff** the arm
localizes the true faulty link correctly; for a miss or a mislocalization, omit `-mcp_loss_clear_ms`
(fault persists = do-nothing) or point the clear at the wrongly-named link (a healthy link, no
effect). The per-arm detect latency and localization outcome already exist in
`BASELINE-COMPARISON-*.md` / `LOCALIZATION-COMPARISON-*.md` — the same inputs the closed-form gate
consumed. Arm differentiation lives entirely in `clear_ms`; htsim stays policy-agnostic.

Faithfulness:
- **Captures** the two arm-differentiating effects: detect latency (a later clear = more accumulated
  loss/RTOs before recovery) and localization correctness (miss → no clear → full do-nothing
  penalty; mislocalize → clear a healthy link → no benefit). This is precisely the physics the
  campaign needs.
- **Does not capture** the reroute capacity cost (spray width k → k−1). Fault-clear is strictly
  optimistic — an oracle-with-latency, not a reroute — so it upper-bounds mitigation benefit and
  cannot exhibit the "mitigation net-negative" regime (gate finding #4). Modeling that needs removing
  the link from the spray set or derating its service rate — a larger change touching routing, out of
  scope for this knob.
- **Consistency:** detection acts at 100 ms epoch boundaries; `measured_detect_ms` already reflects
  that cadence, so `clear_ms` is consistent with the observation model.

Load-bearing caveat: a fault-clear campaign can only show a >5 % *arm* gap if the *do-nothing*
penalty is >5 % to begin with. Today's measurement puts do-nothing at 1.36 % (τ = 40 ms, 1e-3), so a
perfect clear recovers at most 1.36 % and arm-to-arm differences are a fraction of that — far below
5 %. The actuator is cheap; the make-or-break result is that there is no headroom for it to reveal at
this operating point.

## Bottom line

Under the informative loss regime (1e-3) and the worst-case RTO (τ = 40 ms), a correctly-injected
grayhole on a fully-loaded spray uplink costs the collective only 1.36 % of CCT with no mitigation at
all. Losses are pipeline-hidden; the recoverable headroom is below the promotion bar and robust
across the RTO range. The application-impact top-venue framing fails here. Ship the localization
mechanism to ToN/IMC. Revisit an actuator only if a future operating point (a genuinely
critical-path-serializing collective, or a bandwidth-bound fabric) first shows a >5 % do-nothing
penalty — the `-mcp_loss_clear_ms` change is ready to drop in if so.
