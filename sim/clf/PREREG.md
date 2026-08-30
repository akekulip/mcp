# Context Liveness Frontier — detection gate (frozen before results)

**Frozen:** 2026-08-30, after the compile gate (`docs/review/CLF-COMPILE-GATE.md`, 11 ingress /
5 egress) and before any CLF behaviour has been observed on the model or on silicon.

## Question

C-W4 reports a discontinuity only when a LATER packet in the same context survives. A context that
goes completely dark produces no survivor and therefore no evidence, and its silence is
indistinguishable from "nothing was sent". Does the frontier pair close that gap without
manufacturing false blackholes?

## The frozen truth table

`TX` = the source marked this context as departed post-TM. `RX` = the receiver marked it arrived.

| TX | RX | C-W4 | verdict |
|---|---|---|---|
| 0 | 0 | none | **IDLE** — untested, never FAULTY |
| 1 | 1 | contiguous | **HEALTHY** |
| 1 | 1 | discontinuity | **PARTIAL LOSS** |
| 1 | 0 | no survivor | **TOTAL CONTEXT BLACKHOLE** |
| 0 | 1 | any | **IMPOSSIBLE** — arrival without departure; a harness or epoch-race bug, and it must be reported as such rather than classified |

Any state that is not one of the first four is reported **INCONCLUSIVE**, never FAULTY. A verdict of
FAULTY requires positive source evidence.

## Frozen scenarios

`idle` (no demand) · `healthy` · `partial_loss` (the C-W4 case) · `selective_blackhole` (one context
100% lost, siblings alive) · `all_context_blackhole` (every context on the link lost) ·
`direction_only` (one direction dark, the reverse healthy) · `congestion_no_fault` (TM drops, no
link fault — must NOT produce a blackhole verdict, because TX is post-TM) · `epoch_race` (traffic
straddling a bank flip) · `reorder` · `wrap` · `controller_restart`.

## Frozen metrics

- **false-blackhole rate**: verdicts of TOTAL BLACKHOLE where no blackhole was injected, per
  (link, context, epoch), with a cluster bootstrap over runs — NOT a Wilson interval over
  correlated sublink-epochs (H44).
- **missed-blackhole rate**: injected blackholes not reported within N epochs.
- **detection latency** in epochs and microseconds, Kaplan-Meier with never-detected censored.
- **INCONCLUSIVE rate**, reported beside every other rate. A mechanism that always answers
  INCONCLUSIVE is perfectly safe and perfectly useless, and must be visible as such.
- **frontier traffic**: bytes per directed link per epoch, and the central controller event rate,
  to test the O(L) rather than O(LK) claim.

## Decision rules

The CLF detection gate PASSES only if all hold:

1. `selective_blackhole` and `all_context_blackhole` are detected in >= 95% of runs, where ordinary
   C-W4 detects **0%** — the whole point of the primitive.
2. `congestion_no_fault` produces **zero** blackhole verdicts. TX is post-TM specifically so that
   our own queueing cannot be blamed on the link; if this fails, the post-TM argument is wrong.
3. `idle` produces zero FAULTY verdicts of any kind. Absence of demand is not evidence of failure.
4. `epoch_race` produces zero false blackholes at the frozen guard interval, or the guard interval
   is reported as the value at which it does.
5. The 0/1 (arrival without departure) state never occurs; if it does, the run is a harness bug and
   is reported, not classified.
6. Frontier traffic scales as O(L), not O(L*K), measured rather than asserted.

Failing 1 removes the contribution. Failing 2, 3 or 5 means the evidence model is wrong and must be
corrected before any detection claim. Failing 4 sets a documented operating constraint.

## Explicitly out of scope for this gate

Application-level benefit, retained-capacity comparison against directed-link quarantine, the
5-percentage-point / 5% CCT publication gate, restoration, and the distributed agent exchange on
real multi-switch hardware. Those belong to the evaluation gate, not to the detection gate.

## Known limitation, stated in advance

The 4x2 fabric is emulated on ONE Tofino via loopback, so both frontiers live on the same chip. The
comparison is therefore local and the agent-to-agent exchange is NOT exercised. Any O(L) claim from
this gate is an accounting argument plus a measured local aggregation cost, not a measured
distributed cost, and must be labelled as such.
