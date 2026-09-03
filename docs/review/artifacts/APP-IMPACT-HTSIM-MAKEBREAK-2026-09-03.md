# Application-impact make-or-break htsim run: NULL (2026-09-03)

The decisive htsim measurement that gates the application-impact top-venue campaign. It settles the
one question the closed-form gate (`APP-IMPACT-GATE-2026-09-02.md`) left open — is the training
slowdown pipeline-hidden? — with real htsim, not a model. **Verdict: NULL.**

## What was run

Real MoE collective (`moe8x8b_n16`, the anchor trace) on the 1024-NIC fat tree, seed 1000, at the
RTO-dominated recovery the gate said was the ONLY regime where the effect could live.

| run | fault | RTO | CCT | vs clean |
|---|---|---|---|---|
| CLEAN control | none | τ=40 ms | 3.58752 s | — |
| DO-NOTHING | US41→CS1 @ 1e-3, onset 381.7 ms | τ=40 ms | 3.63638 s | **+1.362%** |

Fault placement was controlled to the **busiest healthy uplink** (US41→CS1, 4,805,187 pkt over the
job → ~4,400 expected drops at 1e-3), specifically to avoid the near-idle-link (H27) trap the gate
flagged. CLEAN is the honest perfect-mitigation ceiling; DO-NOTHING is the floor.

## Why this is decisive, and robust on one seed

- **CLEAN vs DO-NOTHING is the ceiling on recoverable slowdown.** Perfect mitigation can recover at
  most the gap between them: **1.36%**. That is below the ≥5% promotion bar in
  `VERIFICATION-2026-08-29.md`. No arm — MCP, oracle, anything — can beat the baselines by more than
  that gap, because the gap is all there is to recover.
- **The RTO trend confirms it is not a fluke of one RTO setting.** The 210 pre-existing runs ran at
  τ=0.3 ms (fast-retransmit) and were flat to ≤0.2% (even the measurement-oracle). Raising RTO 130×
  to τ=40 ms moved the do-nothing penalty only to 1.36%. The effect does not grow into a top-venue
  signal as RTO rises; it stays small.
- **This is exactly the make-or-break assumption the gate named.** The closed-form model assumed
  losses land on the barrier critical path (an upper bound), predicting 1.35–1.57× do-nothing
  penalties. Real htsim shows Ring-AllReduce's 2(N−1)-chunk pipelining absorbs the grayhole losses —
  the model's upper bound was ~40× optimistic. The τ=10 ms bracket was correctly skipped (only
  warranted if the gap had exceeded 5%).

## Structural finding carried from the run (independently important)

htsim's schedulers — uniform, random, and **oracle** — only *read* per-link counters and write a
localization verdict; **none actuate mitigation** (no `set_loss_prob`, no reroute). Proof: at
τ=0.3 ms, uniform, random, and oracle finish at the *identical picosecond*. Consequence: the
project's prior 210-run "gate" arm comparisons were CCT-identical by construction and never measured
a mitigation effect. Any future arm-differentiated CCT campaign would first need an actuator.

**Actuator feasibility (design-only, assessed from source):** a scheduled fault-CLEAR is small and
faithful — `pipe.h` holds `_loss_prob`/`_loss_onset` with setters; `pipe.cpp` has the single drop
predicate `if (_loss_prob>0 && now()>=_loss_onset && rand<_loss_prob) drop`; `main_uec.cpp` parses
`-mcp_loss_onset_ms` (L428) and applies it (L855). Adding a `-mcp_loss_clear_ms` companion so the
fault turns off at (onset + each arm's measured detect latency) is a symmetric one-clause change to
that predicate. **But it is moot: with only a 1.36% ceiling to recover, arm-differentiated CCT
cannot produce a top-venue result even with a perfect actuator.**

## Verdict and consequence

**NULL. The application-impact top-venue path does not hold.** Well-designed pipelined collectives
absorb grayhole losses; even perfect mitigation of a busy-link 1e-3 fault at an aggressive 40 ms RTO
recovers only ~1.4% of completion time — a real but sub-threshold effect, not a top-venue
contribution.

This exhausts the top-venue avenues, all determined cheaply in simulation before any expensive
campaign or hardware:
1. Novel detector mechanism → occupied prior art (NetSeer/LinkGuardian/LossRadar/dShark/UEC).
2. Healing lifecycle → structural FAIL (ties round-robin; `HEALING-RESULT-GATE-2026-09-02.md`).
3. Identifiability reframe → refuted by SprayCheck (`NOVELTY-GATE-IDENTIFIABILITY-2026-09-02.md`).
4. Application impact → NULL (this doc; pipeline-hidden, 1.36% ceiling).

**The honest, defensible outcome is the ToN/IMC measurement paper** framed per
`CONTRIBUTION-FRAMING-2026-09-02.md`: the first faithful, silicon-measured head-to-head of the two
newest sprayed-fabric detectors against an in-fabric witness, quantifying what a 2 B/packet witness
buys (flat detection + exact localization where the passive baselines miss/alias at low loss) and
costs. "Better than the others" holds at the telemetry level; it does not translate to a top-venue
application-level result, and this run is why we can say that honestly rather than by assertion.
