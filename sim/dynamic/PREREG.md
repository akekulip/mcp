# Dynamic operating point for behavioural-sublink feedback (frozen before results)

**Frozen:** 2026-08-29, before `sim/dynamic/` contained any runnable code or any result.

Closes audit gap #6 of `docs/review/P2-P3-INDEPENDENT-AUDIT.md`: specificity, false quarantine,
unsafe exposure, restoration and flap behaviour replayed through the **implemented** feedback state
machine, with confidence intervals.

## Unit under test

The harness drives the real objects and re-implements none of them:
`controller.sublink_feedback.SublinkFeedback`, `GapEvent`, `AuditRound`, `AuditReceipt`,
`gate_keys_for_sublink`, and the frozen `controller/infer.py` (PREREG §3.3). `install` and `remove`
are wired to a virtual gate table that the fabric model **honours**: once a key is installed the
affected context leaves the faulty sublink, so exposure stops and evidence stops. A harness that did
not honour installs would be measuring a model of the controller rather than the controller.

## Fabric and evidence model

- 4 leaves x 2 spines, 16 directed vlinks, contexts 0..3 (the four compiled size strata).
- Epoch = 100 ms, matching the controller's `t_us = epoch * 100000`.
- 25 Gbit/s, 1500 B packets: 2.083 Mpkt/s per link, 208,333 packets per link-epoch, split across
  the four contexts by a frozen share vector.
- Loss composes, never overwrites: `p_eff = 1 - (1 - p_bg)(1 - p_fault)` (HURDLES H32).
- Randomness is `sim.gate.replay.scenario_seed()` (CRC-32). Python's salted `hash()` is barred.

**C-W4 emission rule (the load-bearing part).** A discontinuity is observable only when a later
packet in the same `(vlink, context)` sequence survives. Loss positions are drawn as geometric
inter-loss gaps; maximal runs of lost packets that are followed by a survivor each emit one
`GapEvent` with `gap = (-run_length) mod 2^16` and `observed_packets` = survivors since the previous
event on that sublink, so arrivals and inferred losses stay disjoint. A trailing lost run with no
subsequent survivor emits nothing and carries into the next epoch. Consequently a total blackhole
emits no evidence at all, by construction rather than by assumption.

## Feedback transport

Events are delivered at `t + tau_feedback`; gate writes take effect at delivery + `tau_write`; audit
sends and receipts carry the same delay. **No end-to-end C-W4-to-health-gate latency has been
measured**; every non-zero tau below is a swept parameter labelled with its provenance, not a result.

## Arms

| arm | behaviour |
|---|---|
| `none` | no mitigation; lower bound on collateral, upper bound on exposure |
| `cw4_feedback` | the implemented `SublinkFeedback` state machine |
| `directed_w4` | same evidence, but quarantines every context on the directed link |
| `oracle` | handed the injected fault directly at onset; upper bound and harness tripwire |

## Frozen scenarios

`persistent_partial`, `repaired` (fault clears mid-run), `intermittent` (on/off, drives flapping),
`reorder_only` (adjacent swaps, zero loss: must not quarantine), `wrap` (sequence crosses 65535->0),
`selective_blackhole` (one context 100% lost, siblings alive), `all_context_blackhole` (every context
lost; must be recorded UNDETECTED by C-W4), `no_fault` (control; source of the false-positive rate).

## Frozen sweep

- `tau_feedback` in {0 (bound), 100 us (unmeasured data-plane candidate), 2.20 ms (minimal one-slot
  controller reference), 106.6 ms (full-sweep controller reference)};
- `h` in {5.0, 6.5, 8.0, 10.0};
- `clean_epochs_to_restore` in {1, 3};
- fault rate `p` in {1e-2, 1e-3, 1e-4};
- background `p_bg` = 1e-6; 30 seeds per cell; 60 epochs per run.

## Metrics — safety and usefulness on the same row

Every false-positive number is reported beside the rate at which the mechanism actually acts. A rule
that never fires is reported as INERT, never as safe.

- **quarantine rate**: faulty sublink-runs quarantined / faulty sublink-runs (Wilson 95%);
- **unsafe exposure**: production packets lost on the faulty sublink from onset to gate-effective;
- **detection latency**: onset to gate-effective, median with bootstrap 95% percentile interval;
- **false quarantine**: healthy sublink-epochs quarantined / healthy sublink-epochs (Wilson 95%);
- **collateral**: healthy packets diverted by the quarantine decision;
- **restoration**: rate, latency, and *unsafe restorations* (restored while the fault is present);
- **flaps**: quarantine -> restore -> quarantine transitions per sublink-run;
- `SublinkFeedback.summary()` verbatim: installs, coalesced, stale_dropped.

## Harness tripwires (mechanical, asserted in tests, per repo doctrine)

1. **Oracle floor.** If the `oracle` arm fails to quarantine an injected fault, the run aborts as a
   harness bug (H29/H32 tell) rather than being reported.
2. **Realised-parameter dump.** Every cell prints packets offered, the faulty sublink's measured loss
   rate against the healthy mean, and the fraction of epochs carrying evidence. A faulty/healthy
   ratio not above 1 means no fault was injected.
3. **Never-acts detector.** Any cell with zero quarantines prints INERT beside its false-positive
   number.
4. **Emission-rule cross-check.** The generator's discontinuity rule is validated against the exact
   P4 gap-event PTF expectations (`p4/ptf/gap_event/test.py::Test50OneForcedEventPerDiscontinuity`),
   not asserted. That test is the ground truth: sending sequence 0, 1, 4, 5 on one sublink must
   produce exactly ONE event, carrying `gap == 0xFFFE` (a run of two lost packets) and
   `observed_packets == 3` (the two prior arrivals PLUS the survivor that exposed the gap), followed
   by silence because the witness resynchronises unconditionally after emitting. The harness must
   reproduce those three values exactly from its own generator.

## Decision rules

The dynamic-operating-point gate PASSES only if all hold. Rules may be amended only in a dated
amendment below, never edited away.

1. At every swept `h`, the `no_fault` control's false-quarantine rate has a 95% upper bound below
   1e-2 per sublink-epoch **and** the same `h` quarantines the persistent partial fault in at least
   90% of runs at p=1e-3 (safety and usefulness together).
2. `reorder_only` and `wrap` produce zero quarantines at every swept `h`.
3. `all_context_blackhole` is reported UNDETECTED by C-W4; any arm claiming detection there is a
   harness bug.
4. Unsafe restorations are zero at `clean_epochs_to_restore = 3` in every scenario where the fault
   persists, and the same setting still restores in `repaired` within 10 epochs of repair.
5. `cw4_feedback` collateral is strictly below `directed_w4` collateral on `selective_blackhole` and
   `persistent_partial`, at equal or lower unsafe exposure.
6. Exposure and detection latency are reported for every tau, including the tau values that make the
   mechanism useless. Unfavourable cells are published.

Failing rules 1-4 stops the P3 dynamic claim. Failing 5 keeps P3 but removes the selectivity benefit
from the paper.

## Amendments

**A1 (2026-08-29, PROPOSED — awaiting sign-off, not yet in force).** Rule 2 names no reorder rate,
so its reorder half has no operating point and cannot be evaluated. Proposal: fix the rule-2 reorder
operating point at the rate physically reachable on this fabric. Because `reg_wit_seq` stamps the
sequence in egress AFTER the spray decision, spraying cannot reorder a sublink's own sequence, so the
reachable rate is intra-link reordering only. Until a measured intra-link reorder rate exists, rule
2's reorder half is recorded as FAILING rather than being quietly rescoped.

**Which system the verdict describes, stated explicitly because the harness now models two.**
Rule 2's reorder half FAILS on the **compiled-today baseline witness** — the semantics in
`p4/witness/mcp_fabric_gate_event.p4`, which is what runs on silicon — at every swept rate from 1e-6
to 3e-5 (h = 5.0 and 6.5), and at 3e-5 for h = 8.0. It PASSES under `witness_mode="advance_only"`,
which models `mcp_fabric_gate_event_advonly.p4`: a variant compiled locally on bf-p4c 9.13.1 at the
same 11/4 stage cost, **not yet recompiled on the switch's 9.13.2 and not adopted**. No result may
cite the advance_only column as the behaviour of the current system. An earlier single-rate
measurement at 1e-4 is superseded: that is the one rate where the baseline plus the controller-side
credit happens to pass, so it must not be used as the operating point.
