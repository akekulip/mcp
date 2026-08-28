# Witness-stop: certify a suspect link with production traffic, and stop within one packet

An engineered answer to the question the gates left standing, built and measured rather than
argued. `sim/audit/ramp.py`, 150 trials per cell, background loss b = 1e-4, certification budget
139,392 packets (the exact figure for that background, `docs/AUDIT-FEASIBILITY.md` §3).

## The idea

Every audit design so far tries to *manufacture* traffic that resembles production, and gate 1
(`GATE2-REPLAY-RESULT.md`) showed a competent synthetic prober matches live cloning on every
marginal dimension — so manufacturing is solved and uninteresting. Invert it: **do not remove the
traffic.** A sprayed fabric already admits traffic to a link through the spray weight, and W4
already witnesses *every* packet on that link at line rate, per directed link, with no scheduling
and no sampling. So the suspect link can be certified on production traffic whose distribution is
correct by construction — nothing to enumerate, no correlation structure to guess — and the
control comes free, because sibling links are carrying production concurrently and the same
witness measures them. The background rate is never assumed; it is observed.

## The result

| arm | p = 1e-3 exposed / epochs / stranded | p = 1e-4 exposed / epochs / stranded | detection |
|---|---|---|---|
| full restore (CorrOpt-style) | 21.7 / 1.1 / 0 | 11.5 / 4.9 / 0 | 100 % / 61 % |
| probe then restore | 0 / 7.0 / 7.0 | 0 / 7.0 / 7.0 | 100 % / 100 % |
| metered ramp | 4.0 / 5.4 / 5.2 | 8.7 / 13.5 / 10.2 | 100 % / 72 % |
| **witness-stop** | **4.1 / 1.0 / 0** | 11.8 / **3.3** / **0** | 100 % / **77 %** |
| ramp + witness-stop | 5.1 / 3.3 / 3.0 | 13.7 / 8.1 / 4.4 | 100 % / 68 % |

*exposed* = production packets actually lost to the fault while deciding; *stranded* =
capacity-epochs the link sat unused; both lower is better.

**At p = 1e-3 witness-stop dominates every arm that carries production**: 4.1 exposed packets
against full restore's 21.7 — a **5.3× reduction** — while deciding in a single epoch and
stranding nothing. The metered ramp reaches the same exposure but takes 5.4 epochs and strands 5.2
capacity-epochs to do it.

## The mechanism, and the counterintuitive part

The advantage is **not** admission control. It is *reaction granularity*. For a fixed evidence
requirement, expected exposure is roughly (packets the test needs) × p, which is almost invariant
to the rate at which those packets are admitted — so metering only delays the verdict. What
actually costs full restore its 21.7 packets is that it commits a **whole epoch** of production
before it can react, because counter polling is epoch-quantised. W4 raises the gap *on the packet*,
at line rate, so admission can be cut the instant the evidence crosses.

That is why combining the two is worse than witness-stop alone (5.1 exposed and 3.0 stranded
against 4.1 and 0): the ramp buys nothing and pays in time. **The knob everyone reaches for —
admission rate — is unnecessary; the property that matters is that the data plane, not the
controller, decides when to stop.** Counter polling cannot have it at any budget.

## What is not yet good enough

Stated as work, not as caveat:

* **Specificity.** Every production-carrying arm certifies a genuinely healthy link only 64–78 % of
  the time at b = 1e-4, witness-stop included (66 %). That is a threshold problem — h = 6.5 against
  a `p0` estimated from a noisy concurrent control — and it is the next thing to fix, because a
  mechanism that wrongly quarantines a third of healthy links is not deployable.
* **The 2× fault stays hard.** At p = 1e-4 no arm exceeds 77 % detection, consistent with C9, where
  the coexistence cohort needed ~18 epochs of coverage even for an oracle.
* **The probe arm is modelled at its best case** — perfectly representative, zero exposure. Gate 1
  showed a real prober can be made representative on marginals, so this row is a fair opponent on
  exposure and an unfair one on realism; the open question it leaves is correlation structure.

## Why this is buildable here, now

Nothing in it needs a new primitive. The spray weight is a `tbl_vlink` action-data write that
`p4/control/setup_skeleton.py` already programs; W4's gap event already sets `md.exceed` through
`tbl_wit_arm` (validated on the model, `p4/ptf/PTF-MODEL.md`, `act_attn_exceed` firing exactly once
per gap); and cutting admission on that event is the same table write with a different weight. The
next step is the P4 path that closes that loop in the data plane instead of through the controller.
