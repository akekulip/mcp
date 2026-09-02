# Head-to-head comparison: MCP vs SprayCheck-Z and FlowPulse-theta (2026-09-02)

Real, primary-source-grounded comparative numbers, per Philip's instruction that evaluation must
use the baselines' own mechanisms and metrics, not an invented question. Code:
`sim/baselines/comparison.py` (harness), `sim/baselines/run_comparison_sweep.py` (this sweep),
raw output `docs/review/artifacts/BASELINE-COMPARISON-SWEEP-2026-09-02.json`.

## Correction to an earlier claim

Earlier today I reported "SprayCheck-Z detects nothing at MCP's target regime (1e-3, 1e-4) at any
practical packet budget up to 2 million packets/spine." That was an accurate description of the
specific bounded search I ran at the time, but it read as a stronger claim than the evidence
supported. Running the real head-to-head with a wider budget shows SprayCheck-Z **can** detect at
1e-3 -- it just needs about 3.4x more packets than MCP and only succeeds in 62% of trials even with
a generous budget. The genuinely decisive gap is one order of magnitude lower, at 1e-4, where
SprayCheck-Z fails completely within the same budget MCP succeeds in every time. Correcting this in
the open rather than letting the overstated version stand.

## Fairness of the harness

One shared stream of per-packet spray/survival draws feeds all three detectors every epoch (i.i.d.
uniform spray across k=8 spines, matching SprayCheck's own model and FlowPulse's "temporal
symmetry" assumption). Each detector sees only what its real switch would have:

- **MCP** (`controller/decision_loop.FleetDecisionLoop`, unmodified from `controller/tests/`): the
  exact per-sublink (tx, rx) pair its receiver ledger genuinely produces.
- **SprayCheck-Z**: RX-only per-spine arrival counts. No TX, no drop column exists in its function
  signature to pass by mistake.
- **FlowPulse-theta**: RX-only per-spine load, predicted from its own bootstrapped history
  (`LearnedLoadModel`) -- never MCP's TX ground truth.

Scenario: 10 epochs of clean bootstrap traffic, then one spine degrades to the target rate and
stays degraded. Detection delay is measured in epochs and total packets from the fault's actual
onset, at k=8 spines (SprayCheck's own Table 1 topology, for maximum comparability), across 8
seeds per loss rate.

## A real methodological bug found and fixed before trusting any of this

A per-packet Python loop generating the simulated traffic made a single 2-million-packet epoch
take tens of seconds, and separately, an initial per-epoch packet volume (200,000) was too small:
FlowPulse-theta's fixed 1% threshold, tested against a single epoch's own natural spraying sampling
noise (relative std ≈0.6% at that scale), false-alarmed on a healthy spine 100% of the time --
confirmed by isolating the single-spine, single-epoch false-positive rate independent of any
injected fault. Neither of these was a fairness problem (the underlying i.i.d.-spray model was
always correct); both were implementation bugs, found by directly measuring the false-positive
rate rather than trusting a first result, fixed (vectorized traffic generation; packets/epoch
raised to 2,000,000, ~a realistic collective-iteration scale), and re-verified to bring the
false-positive rate to 0.0000 -- matching the paper's own <1% claim -- before this sweep was run.

## Results

Total packets across the fleet (8 spines) to first correctly flag the actual faulty spine; false
positive = any healthy spine flagged; action rate = fraction of 8 trials that detected within an
80-epoch (160M-packet) budget.

| loss rate | MCP action / median packets / FPR | SprayCheck-Z action / median packets / FPR | FlowPulse-theta action / median packets / FPR |
|---|---|---|---|
| 1.5% | 1.00 / 22.0M / 0.00 | 1.00 / 24.0M / 0.00 | 1.00 / 22.0M / 0.00 |
| 1.0% | 1.00 / 22.0M / 0.00 | 1.00 / 26.0M / 0.00 | 1.00 / 22.0M / 0.00 |
| 0.5% | 1.00 / 22.0M / 0.00 | 1.00 / 31.0M / 0.00 | 0.12 / 88.0M / 0.00 |
| 1e-3 | 1.00 / 22.0M / 0.00 | 0.62 / 74.0M / 0.00 | 0.00 / never / 0.00 |
| 1e-4 | 1.00 / 24.0M / 0.00 | 0.00 / never / 0.00 | 0.00 / never / 0.00 |

Per-spine packet units (dividing by k=8, matching SprayCheck's own Table 1 convention): MCP needs
roughly 2.8-3.0M packets/spine to detect at every rate tested, essentially flat across four orders
of magnitude of loss rate. SprayCheck-Z needs 3.0M/spine at 1.5% (closely matching MCP there) and
degrades sharply going down: 9.2M/spine at 1e-3 (3.4x MCP, and unreliable — only 62% of trials
succeed at all), and never within 20M/spine at 1e-4, where MCP still succeeds every time. FlowPulse-
theta degrades even faster, from parity at 1.5%/1% down to failing completely at 0.5% and below.

## What this does and does not show

**Does show**: a real, fairly-measured, zero-false-positive gap in minimum detectable loss rate,
consistent with the campaign plan's own prediction that this (not "less overhead" -- SprayCheck
needs literally zero probes) is the defensible comparative claim. MCP's detection cost is flat
across loss rates that make both baselines fail or become unreliable, which is the headline result
this whole redesign effort was built to be able to measure honestly.

**Does not show**: overhead in the baselines' own currency (switch SRAM, added network load,
probe/mirror bytes) -- this sweep reports packets-to-detect only. Localization accuracy (both
baseline papers' own localization rules are implemented but not fidelity-checked against a
published localization number, since neither paper publishes one). Restoration/healing comparison
against CorrOpt/REPS-style/BFD-style (a separate, not-yet-built workstream). Robustness under
common-mode/non-stationary load (the still-open gap from `STATS-LAYER-STATUS-2026-09-02.md`) --
this sweep's scenario is a single independent per-link fault, matching the PREREG v1.9 scope
boundary exactly, not a claim about the harder regime.

Only 8 seeds per loss rate: enough to see a real, large, consistent effect, not enough for a
publication-grade confidence interval -- more seeds is cheap to add (the harness now runs in
seconds, not minutes, since the vectorization fix) and should be done before this goes in a paper
figure.
