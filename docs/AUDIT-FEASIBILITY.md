# What a counterfactual audit costs, and what it can honestly certify

Status 2026-08-28. Input to the counterfactual-observability track (`docs/superpowers/specs/
2026-08-28-counterfactual-observability-design.md`). Derived analytically and checked numerically;
no simulation involved. Written because the recorded feasibility figure — ~29,956 zero-loss packets
to clear a link of persistent 1e-4 loss at 5 % false-restoration risk — is load-bearing for the new
direction, and a load-bearing number should be re-derived by someone else before it is built on.

## 1. The number is right, and it is a rule, not a coincidence

A link that is still faulty at rate `p` survives `N` observed packets with no loss with probability
`(1-p)^N`. Restoring it when that probability is still above `α` is a false restoration at risk `α`,
so certification needs

```
N  ≥  ln(α) / ln(1-p)   ≈   ln(1/α) / p
```

At `p = 1e-4`, `α = 0.05`: **N = 29,956** packets (`ln(20)/1e-4 = 29,957` to the same figure). This is
the one-sided generalisation of the rule of three, and it says something the design must internalise:
**the audit's cost is set by the loss-rate ceiling it certifies, not by the link, the topology, or
the mechanism.** No witness, sequence number, probe format or scheduler changes it — they change
*how* the packets are obtained, never *how many* are needed.

| ceiling p | α | packets | bytes @1500 B | 25 G | 100 G | 400 G |
|---|---|---|---|---|---|---|
| 1e-3 | 0.05 | 2,994 | 4.5 MB | 1.4 ms | 0.4 ms | 0.09 ms |
| 1e-3 | 0.01 | 4,603 | 6.9 MB | 2.2 ms | 0.6 ms | 0.14 ms |
| **1e-4** | **0.05** | **29,956** | **44.9 MB** | **14.4 ms** | **3.6 ms** | **0.90 ms** |
| 1e-4 | 0.01 | 46,049 | 69.1 MB | 22.1 ms | 5.5 ms | 1.38 ms |
| 1e-5 | 0.05 | 299,572 | 449.4 MB | 143.8 ms | 35.9 ms | 8.99 ms |
| 1e-5 | 0.01 | 460,515 | 690.8 MB | 221.0 ms | 55.3 ms | 13.82 ms |

## 2. It is a design constraint, not a blocker

Reading the figure as "30k packets is a lot" is the wrong reading. On the wire it is **45 MB, or
0.9 ms of a 400 G link** — three orders of magnitude below the multi-second collective iterations
these fabrics run. What it actually constrains is the *ceiling* the lifecycle is allowed to claim:
certifying `p ≤ 1e-5` costs ten times as much as `p ≤ 1e-4`, and the cost is linear in `1/p`
throughout. So the design should **certify a stated loss-rate ceiling with a stated risk**, and the
lifecycle's public verdict should carry both numbers rather than the word "healthy". That is the
same conclusion the spec reaches from the other side with its INCONCLUSIVE state, and this is the
quantitative reason for it.

## 3. Background loss is the term that actually hurts — recomputed consistently

**Correction (2026-08-28).** The first version of this section mixed two different tests: the
`b = 0` row came from the exact zero-event bound above (α only, power 1 by construction because a
healthy link cannot drop a packet), while the `b > 0` rows came from a normal approximation with
α = 0.05 *and* 90 % power. The resulting "4×" was an artifact of switching tests between rows, and
the normal approximation was invalid at `b = 1e-5` anyway — it implies **0.35 expected events**
under H0, where a normal approximation to a binomial does not hold. Both defects were found in an
independent review of this file and are corrected here.

Every row below is now the **same exact binomial design**, in the framing certification actually
needs: over `N` audit packets, certify the link iff losses ≤ `c`, where

* **α = P(certify | the link is really faulty at b + δ) ≤ 0.05** — the false-restoration risk, and
* **1 − β = P(certify | the link is really healthy at b) ≥ 0.90** — so audits usually conclude
  rather than returning INCONCLUSIVE forever.

`N` is the exact minimum by bisection, δ = 1e-4:

| background b | N packets | certify iff losses ≤ | P(false restore) | P(certify when healthy) | vs b = 0 |
|---|---|---|---|---|---|
| 0 | **29,956** | 0 | 0.050 | 1.000 | 1.0× |
| 1e-5 | **43,125** | 1 | 0.050 | 0.930 | 1.4× |
| 1e-4 | **139,392** | 19 | 0.050 | 0.926 | **4.7×** |

At `b = 0` the design collapses to the zero-event bound of §1, which is why the headline figure
survives unchanged. The honest background-loss penalty at `b = 1e-4` is **4.7×**, and the reason is
visible in the expected counts: the test must separate 13.9 expected losses from 27.9, rather than
0 from 3.

This matters for our own numbers because the F0 block runs at exactly `b = 1e-4`: **on that fabric
an audit costs 139,392 packets — 209 MB at 1500 B, or 4.2 ms of a 400 G link — not the 45 MB of
the headline.** Any evaluation quoting 29,956 without stating the background-loss assumption is
quoting the best case, and the ceiling being certified must be stated with it.

## 4. Fleet scale — the 2 / 8 / 25 % concurrent-recovery axis

At the `p ≤ 1e-4`, α = 0.05 operating point with 1024 directed links, using the corrected §3
figures (zero background, then the `b = 1e-4` case our own F0 block actually runs at):

| links recovering | count | audit bytes at b = 0 (29,956 pkt) | at b = 1e-4 (139,392 pkt) | at 400 G aggregate, b = 1e-4 |
|---|---|---|---|---|
| 2 % | 20 | 0.90 GB | 4.2 GB | 84 ms |
| 8 % | 82 | 3.7 GB | 17.1 GB | 343 ms |
| 25 % | 256 | 11.5 GB | 53.5 GB | 1.07 s |

This is where "where and when to measure" stops being free. At 2 % the audit is negligible and any
policy works; at 25 % under realistic background loss it is 53 GB and over a second of a 400 G
aggregate, and the scheduling question is real. It is also the regime where returning INCONCLUSIVE
early is worth the most, because a faulty link declares itself in ~1/p packets on average while a
healthy one must pay the full N to be cleared.

## 5. What this does not say

It assumes losses are independent across packets at a constant rate, which is the same assumption
the fault model in `paper/PREREG.md` makes and is wrong for bursty or correlated corruption — a
burst-loss link can pass a 30k-packet audit and fail immediately after. It assumes the audit traffic
is representative of production traffic (same size distribution, same queues); an audit that uses
small packets on an empty queue is not testing what production will meet. And it prices bytes only:
the audit's real cost also includes whatever capacity is stranded while the link is out, which is
the other half of the metric pair the spec names.
