# The audit budget cannot bind — checked before writing any P4

Gate evidence, 2026-08-28. Two independent prior-art reviews of the counterfactual-observability
direction each arrived at the same stop condition, and it is arithmetic rather than literature, so
it is settled here first.

## The claim under test

The proposed contribution is a **bounded** counterfactual audit: a hard cap on packets and bytes,
enforced in the data plane, that lets a quarantined link be certified "without increasing probe
overhead". A safety–capacity–**overhead** frontier only exists if the overhead term can bind.

## It cannot

Using the corrected exact sample sizes from `docs/AUDIT-FEASIBILITY.md` — 29,956 audit packets to
certify a 1e-4 ceiling at 5 % false-restoration risk on a clean fabric, and 139,392 at the 1e-4
background our own F0 block runs at:

| case | packets | bytes @1500 B | 25 G | 100 G | 400 G | as % of a 1-day quarantine (25 G) |
|---|---|---|---|---|---|---|
| b = 0 | 29,956 | 45 MB | 14.4 ms | 3.6 ms | 0.9 ms | 0.00002 % |
| b = 1e-4 | 139,392 | 209 MB | **66.9 ms** | 16.7 ms | 4.2 ms | **0.00008 %** |

Against the quarantine durations the literature actually reports — CorrOpt's repair tickets run in
**days** ("each failed repair attempt adds two more days during which the link must be disabled"),
Aegis's host reboot-and-stress-test cycle in **minutes** — the audit is free. At the worst
realistic operating point you would need **~12,900 sequential audits of one link** to spend even
1 % of a one-day outage.

## What follows

1. **The overhead axis is vacuous**, so the "safety–capacity–overhead frontier" is really a
   one-dimensional safety-versus-stranded-capacity trade-off. A fixed retry timer that blasts a
   full test train at every quarantined link is nearly free and gets the same certification.
2. **A data-plane exposure cap is therefore a solution to a non-problem** *as motivated*. It may
   still be novel — no published system enforces a per-`(link_id, audit_id)` packet budget in the
   switch — but novelty is not the issue; there is nothing to protect against. An audit on a
   quarantined link cannot steal bandwidth from production, because the link is idle by definition,
   and LinkGuardian's strict-lowest-priority dummy queue already guarantees non-interference by
   scheduling rather than by counting.
3. **The claim has to move to the enabler.** What the reviews agree nobody has is the ability to
   *obtain* the evidence at all: forcing an exactly-targeted train onto one directed inter-switch
   link that packet spraying has emptied, and validating its post-TM delivery. CorrOpt, Envoy,
   circuit breakers and NetBouncer all re-admit by restoring real traffic and watching passively,
   because in their settings the quarantined resource is directly addressable. On a sprayed fabric
   it is not. That is a capability claim, not an efficiency claim, and it does not need a budget.

## The regimes where the budget could still bind

Named so they can be tested rather than assumed, and none of them is the motivating case:

* many simultaneous quarantines sharing one upstream port (the 25 % concurrent-recovery row is
  53.5 GB at b = 1e-4, which is 1.07 s of a 400 G aggregate — still small, but no longer free);
* a flapping link that must be re-certified repeatedly, where the cost is per attempt;
* audits that must share the pipe with production **during probation**, where the link is carrying
  real traffic again and the exposure being bounded is damage rather than bandwidth.

The third of these is the only one where "bounded" does real work, and it is a *probation* budget,
not an audit budget. If the direction proceeds, that is the version to build.
