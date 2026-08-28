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

## 3. Background loss is the term that actually hurts

With any background loss `b > 0`, a zero-loss run is not achievable and the test becomes separating
`b` from `b + δ`. For a one-sided test at α = 0.05 with 90 % power (normal approximation,
`N ≈ ((z_α√(b(1-b)) + z_β√((b+δ)(1-b-δ)))/δ)²`), at δ = 1e-4:

| background b | packets to separate b from b+1e-4 | vs the zero-background case |
|---|---|---|
| 0 | 29,956 | 1.0× |
| 1e-5 | 34,754 | 1.2× |
| 1e-4 | 119,515 | **4.0×** |

This matters because our own F0 block is measured at exactly `b = 1e-4`: **on a fabric with that much
background loss the audit costs four times its headline figure**, 180 MB and ~3.6 ms at 400 G. Any
evaluation that quotes 29,956 without stating the background-loss assumption is quoting the best
case. The audit-byte bound in the evaluation should therefore be expressed per certified ceiling and
per background level, not as a single constant.

## 4. Fleet scale — the 2 / 8 / 25 % concurrent-recovery axis

At the `p ≤ 1e-4`, α = 0.05 operating point, with 1024 directed links and zero background loss:

| links recovering | count | total audit bytes | at 400 G aggregate | at 4×400 G |
|---|---|---|---|---|
| 2 % | 20 | 0.90 GB | 18 ms | 4 ms |
| 8 % | 82 | 3.68 GB | 74 ms | 18 ms |
| 25 % | 256 | 11.50 GB | 230 ms | 58 ms |

Multiply by 4 at `b = 1e-4` (46 GB, ~0.9 s at 400 G aggregate for the 25 % case). This is where the
"where and when to measure" question becomes real: at 2 % the audit is free and any policy works; at
25 % under background loss the audit budget is a genuine scheduling problem, and that is the regime
the evaluation should be built around. It is also the regime where returning INCONCLUSIVE early —
rather than spending the full N on a link that is clearly still bad — is worth the most, because a
faulty link declares itself in ~1/p packets on average while a healthy one needs the full ln(1/α)/p
to be cleared.

## 5. What this does not say

It assumes losses are independent across packets at a constant rate, which is the same assumption
the fault model in `paper/PREREG.md` makes and is wrong for bursty or correlated corruption — a
burst-loss link can pass a 30k-packet audit and fail immediately after. It assumes the audit traffic
is representative of production traffic (same size distribution, same queues); an audit that uses
small packets on an empty queue is not testing what production will meet. And it prices bytes only:
the audit's real cost also includes whatever capacity is stranded while the link is out, which is
the other half of the metric pair the spec names.
