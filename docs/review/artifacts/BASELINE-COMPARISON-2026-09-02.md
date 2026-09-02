# Head-to-head comparison: MCP vs SprayCheck-Z and FlowPulse-theta (2026-09-02)

Real, primary-source-grounded comparative numbers, per Philip's instruction that evaluation must
use the baselines' own mechanisms and metrics, not an invented question. Code:
`sim/baselines/comparison.py` (harness), `sim/baselines/run_comparison_sweep.py` (this sweep),
raw output `docs/review/artifacts/BASELINE-COMPARISON-SWEEP-2026-09-02.json`. 50 seeds per loss
rate, with Wilson 95% confidence intervals on the action rate and an IQR on packets-to-detect.

## Correction to an earlier claim

Earlier today I reported "SprayCheck-Z detects nothing at MCP's target regime (1e-3, 1e-4) at any
practical packet budget up to 2 million packets/spine." That was an accurate description of the
specific bounded search I ran at the time, but it read as a stronger claim than the evidence
supported. The real head-to-head shows SprayCheck-Z **can** detect at 1e-3 -- 78% of trials
(95% CI [0.65, 0.87], n=50), needing far more packets than MCP. The genuinely decisive gap is one
order of magnitude lower, at 1e-4, where SprayCheck-Z's action rate is 0.00 (CI [0.00, 0.07])
within the same budget MCP succeeds in every time. Correcting this in the open rather than letting
the overstated version stand.

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
onset, at k=8 spines (SprayCheck's own Table 1 topology, for maximum comparability).

## Two real methodological bugs found and fixed before trusting any of this

A per-packet Python loop generating the simulated traffic made a single 2-million-packet epoch
take tens of seconds (a full 5-loss-rate x 8-trial sweep did not finish inside a 20-minute budget);
vectorized with `rng.multinomial`, ~1000x speedup, no change to the underlying i.i.d.-spray model.
Separately, an initial per-epoch packet volume (200,000) was too small: FlowPulse-theta's fixed 1%
threshold, tested against a single epoch's own natural spraying sampling noise (relative std
≈0.6% at that scale), false-alarmed on a healthy spine 100% of the time -- confirmed by isolating
the single-spine, single-epoch false-positive rate independent of any injected fault, and traced to
a gap the original per-module fidelity check never exercised (it tested the threshold logic against
a fixed, exact Poisson(PORT_LOAD) value, never `LearnedLoadModel`'s own bootstrap-estimated
baseline). Fixed by raising the per-epoch volume to 2,000,000 packets (~a realistic collective-
iteration scale) and re-verified FPR -> 0.0000, matching the paper's own <1% claim, before this
sweep was run.

## Detection results

Total packets across the fleet (8 spines) to first correctly flag the actual faulty spine; false
positive = any healthy spine flagged; action rate = fraction of 50 trials that detected within an
80-epoch (160M-packet) budget, with a Wilson 95% CI.

| loss rate | MCP action rate (CI) / median pkts | SprayCheck-Z action rate (CI) / median pkts | FlowPulse-theta action rate (CI) / median pkts |
|---|---|---|---|
| 1.5% | 1.00 [0.93,1.00] / 22.0M | 1.00 [0.93,1.00] / 24.0M | 1.00 [0.93,1.00] / 22.0M |
| 1.0% | 1.00 [0.93,1.00] / 22.0M | 1.00 [0.93,1.00] / 26.0M | 1.00 [0.93,1.00] / 22.0M |
| 0.5% | 1.00 [0.93,1.00] / 22.0M | 1.00 [0.93,1.00] / 32.0M | 0.38 [0.26,0.52] / 88.0M |
| 1e-3 | 1.00 [0.93,1.00] / 22.0M | 0.78 [0.65,0.87] / 114.0M | 0.00 [0.00,0.07] / never |
| 1e-4 | 1.00 [0.93,1.00] / 22.0M | 0.00 [0.00,0.07] / never | 0.00 [0.00,0.07] / never |

False-positive rate is 0.00 for all three methods at every loss rate (confirmed, not assumed).

MCP's median packet cost is essentially flat (22.0-24.0M total, ~2.8-3.0M/spine) across four orders
of magnitude of loss rate, with a tight IQR throughout. SprayCheck-Z is competitive at 1.5-0.5% loss
but its packet cost and variance both grow sharply below that (IQR widens from (24.0M,24.0M) at
1.5% to (82.0M,148.0M) at 1e-3), and its action rate visibly degrades (100% -> 78% -> 0%).
FlowPulse-theta degrades even faster: parity with MCP at 1.5%/1%, a wide-variance partial detection
at 0.5% (IQR (46.0M,132.0M)), then complete failure at 1e-3 and below.

## Overhead comparison (in the baselines' own currency, not an invented one)

Verified directly against the P4 source and the existing hardware compile-gate report
(`docs/review/artifacts/LEDGER-COMPILE-GATE.md`), not estimated:

| | MCP (receiver ledger, C1) | SprayCheck-Z | FlowPulse-theta |
|---|---|---|---|
| Wire overhead | **4 bytes/packet** (`wit_h`: 16-bit link_id + 16-bit seq, `p4/witness/mcp_fabric_ledger.p4:156-159`), stripped before host delivery per the project's XDP-strip design -- an in-fabric-only cost, invisible to endpoints but real bandwidth on every hop | 0 bytes/packet (fully passive, counts existing traffic) | 0 bytes/packet (fully passive) |
| Added network load | ~0.28% of payload bytes at a 1400 B payload (4/1404) -- the same order of magnitude as SprayCheck's own reported ±0.25% prioritized-flow distortion, just structured as a fixed per-packet tag rather than a flow-priority skew | 0% (SprayCheck's own claim: "zero added network load") | 0% (pure passive byte counting) |
| Per-link switch state | **6 bytes/monitored directed link** (`reg_wit_expect`: 16-bit hi + `reg_wit_observed`: 32-bit lo, `p4/witness/mcp_fabric_ledger.p4:872,921`), and it covers **every one of 1024 links continuously, all the time** -- no round-robin | <2 KB total, but only for **one flow at a time**, round-robin across which flow is instrumented, "control-plane reset ~1 min" -- broader flows monitored only by taking turns | not stated in the paper (no SRAM number found in the HotNets PDF read this session) |
| MAU stage / table cost | **Zero added stages** vs. the CLF epoch/bank/guard scheme it replaced (11 ingress / 5 egress, unchanged), and it is CHEAPER on every other axis measured (tables -2, SRAM -3 blocks, stateful ALUs -1) -- real, hardware-compiled numbers, not simulated | not applicable -- SprayCheck's own resource claim (<2 KB) is for a real Tofino-1 testbed program, but we have not built or compiled their design ourselves to get an independently-measured stage count | not applicable, same caveat |

**Honest framing, not cherry-picked:** MCP pays a real, non-zero wire and per-packet-load cost that
the two fully-passive baselines do not pay at all -- this is a genuine trade-off, not something to
minimize. What MCP gets for that cost is (a) continuous per-link coverage of the entire fabric
rather than a round-robin sample of one flow at a time, and (b) the detection-sensitivity result
above. Whether that trade is worth it depends on what a reviewer weights more; both sides of the
ledger are reported, not just the favorable one. The MAU-stage and per-link-state numbers for MCP
are independently, hardware-compiled measurements (bf-p4c on the actual switch's SDE lineage); the
baselines' own resource numbers are what those papers themselves report, since we have not
reimplemented their mechanisms in P4 -- only replayed their detection algorithms in software, which
is what the detection-accuracy comparison above needed and no more.

## What this still does not show

Localization accuracy (both baseline papers' localization rules are implemented but not fidelity-
checked against a published localization number, since neither paper publishes one). Restoration/
healing comparison against CorrOpt/REPS-style/BFD-style (a separate, not-yet-built workstream).
Robustness under common-mode/non-stationary load (the still-open gap from
`STATS-LAYER-STATUS-2026-09-02.md`) -- this sweep's scenario is a single independent per-link
fault, matching the PREREG v1.9 scope boundary exactly, not a claim about the harder regime.
