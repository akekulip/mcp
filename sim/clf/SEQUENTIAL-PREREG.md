# Sealed-Epoch Sequential Evidence Preregistration

Status: controller-only Phase B prototype. This does not change the P4 wire format or claim a
new observability primitive.

## Claim boundary

The mechanism composes three existing evidence types into an auditable controller record:

- exact frozen-bank CLF departures and arrivals;
- C-W4 gap presence as corroborating metadata, never a second count of the same loss;
- declared audit receipts for restoration, with missing or invalid receipts treated as censoring.

`TX > 0, RX = 0` is an immediate operational `BLACKHOLE` observation. Gray-loss action is a
separate sequential statistical claim. It does not distinguish physical link loss from congestion
or another cause of packet non-delivery.

## Fixed statistical model

- Null: every measured packet has conditional delivery probability at least `p0 = 0.99`, given
  all prior observations and controller actions in the current repair generation.
- Alpha: `0.05` per repair generation.
- Fixed alternatives: delivery probabilities `(0.01, 0.10, 0.50, 0.75, 0.90, 0.97)`, equally
  weighted before evidence is observed.
- Exact epoch size for the simulation sweep: 32 departures, below the 8-bit frontier saturation
  value 255.
- Horizon: 50 sealed epochs.
- Monte Carlo campaigns: 2,000 per survival point, seed 20260830.
- Survival points: `0, .01, .05, .10, .125, .15, .25, .50, .75, .90, .95, .97, .99, 1.0`.

For an alternative delivery probability `p1 < p0`, one exact epoch with `x` arrivals and `n-x`
losses multiplies capital by

`(p1/p0)^x * ((1-p1)/(1-p0))^(n-x)`.

Under the packetwise conditional null, the conditional expectation of each per-packet factor is at
most one; products and a fixed convex mixture are therefore e-processes. Ville's inequality makes
crossing `1/alpha_k` anytime-valid for sequence `k`. A censored sequence restarts with
`alpha_k = alpha / 2^(k+1)`, so the union-bound spend over arbitrarily many restarts is at most
`alpha` inside one repair generation. Repair starts a new data-generating regime and a separately
reported certificate.

This is the same proof obligation emphasized by work on betting confidence sequences and vector
confidence sequences; tests enumerate the null expectation and an optional-stopping case rather
than relying only on Monte Carlo ([betting confidence sequences](https://arxiv.org/abs/2010.09686),
[vector-valued confidence sequences](https://arxiv.org/abs/2402.03683)).

## Censoring and invalidity

The following never become numeric loss evidence: stale or duplicate epoch, missing epoch,
boundary race, incomplete read, counter reset, saturation, `RX > TX`, missing receipt, or invalid
receipt. A repair-generation change resets all prior capital. A management failure is therefore
`INCONCLUSIVE`, never a link fault.

## Fixed comparison arms

1. Presence frontier: acts only on positive TX and zero RX.
2. Current count threshold: one-epoch `RX/TX <= 1/8` (`STARVED_RATIO = 8`).
3. Sealed sequential ledger: immediate zero-arrival action plus the preregistered mixture e-process.

The comparison reports detection probability and median first-action epoch. Statistical false
actions are checked at survival 0.99 and 1.0. The Phase B mechanism survives only if it detects a
nontrivial gray-loss band that the two fixed arms miss while empirical statistical false actions
remain at or below 0.05. Silicon promotion additionally requires exact runtime/build identity,
exact `tbl_eg_vlink` readback, non-saturated counts, injector counter ground truth, and teardown
proof.
