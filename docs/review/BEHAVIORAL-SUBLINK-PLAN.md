# Behavioral Sublinks plan — primary research direction

**Status:** active and re-verified, 2026-08-30. This supersedes the audit-lease/lifecycle direction
in `PLAN.md`; W4 and witness-stop remain infrastructure and baselines. The evidence/claim ledger
is `VERIFICATION-2026-08-29.md`.

## Thesis and claim boundary

A physical link can be healthy for some demand-carrying packet contexts and faulty for others.
Treating it as one Boolean resource unnecessarily removes safe capacity. The system should instead
observe and control a **behavioral sublink**:

```text
(directed physical link, source-switch-declared context)
```

The first implemented context is coarse packet size. The target context is a four-bit, source-leaf
label encoding size x service class in existing shim padding. Do not claim arbitrary predicates,
load envelopes, application benefit, or class isolation until the corresponding mechanism and gate
below pass.

## Proposed contributions

1. **Abstraction:** behavioral sublinks make link health conditional and demand-scoped rather than
   binary. Evidence and mitigation use the same declared context id.
2. **Primitive:** context-indexed post-TM W4 sequences, with the context carried without additional
   wire bytes and isolated state per `(directed_link, context)`.
3. **System:** a behavioral health gate reroutes only a quarantined path-context while other
   contexts continue on the physical link; downstream evidence reaches the upstream selector.
4. **Result:** at the same unsafe-packet bound, retain useful primary capacity and reduce detour
   pressure/CCT relative to physical- and directed-link quarantine.

W4 gap detection, downstream notification, fast reroute, leases, circuit-breaker states, and active
probes are attributed infrastructure, not novelty claims.

## What exists and what is proven

- Generated `mcp_fabric_cw4.p4` uses the existing 16-bit witness id as `vlink[15:4] | stratum[3:0]`;
  no added wire bytes and 1024 cells per sequence register.
- Exact-source compiles place armed W4 at 9/3 stages, C-W4 at 9/4, Context Capsule at 9/4,
  Capsule + health gate at 10/4, and the current event/audit/fault-injection program at 11/4.
  The old 9/3 Capsule and 10/3 gate rows are retracted: they contained an invalid packed-width
  parser copy. The full prototype leaves one ingress and eight egress stages.
- Four software-model tests pass, including an end-to-end upstream classifier/wire-stamp test.
- P2's hostile model suite passes 5/5: exact-context reroute, same-link healthy-context retention,
  accurate post-reroute accounting, restoration by entry deletion, and no-entry no-op.
- The controller can bind the C-W4 program, supplies the pre-shifted vlink base, maps one attributed
  directed sublink to every exact P2 gate key, and performs tested BFRT add/modify/delete operations.
- The current data plane emits an attributed gap event, authorizes audit steering by source role,
  emits downstream receipts, and includes a post-stamp exact-sublink fault injector. The current
  source passes its software-model suite and compiles at 11/4.
- Silicon demonstrations prove forwarding, 17/17 behavioral identities, selective discontinuity,
  attributed event delivery, automated frozen inference, a four-row gate batch, and selective
  mitigation. In 20/20 valid hardened trials, event-to-first-rerouted-packet latency was 4.998 ms
  median (3.998–5.499 ms); a separate mixed-context check moved only context 2 to the backup.
- The frozen post-localization value gate passes for aligned direction x size faults: median +25
  percentage points safe delivered demand over directed W4, 100% oracle-gap closure, zero unsafe
  primary bytes. It exposes 25-point gaps for a within-bin boundary and a class-only fault.

Not yet built or proven: a full audit/probation/removal lifecycle on silicon; total-blackhole
liveness; dynamic specificity with confidence intervals; or trace-driven application performance.
The measured closed loop begins at a partial-loss gap event, not at fault onset, and its elevated
backup observation probability is instrumentation rather than a production-overhead result.

One structural limit is now explicit: C-W4 needs a later survivor in the same context to expose a
sequence gap. It cannot by itself detect a context that becomes a complete black hole. P4 may not
treat the motivating `>1 KB` total-drop case as detected until a separately priced liveness witness
or a validated cross-context witness closes that hole.

## Where, when, and when to stop measuring

**Where:** measure behavioral sublinks that currently carry demand, have stale/insufficient
evidence, intersect a conditional-fault boundary, or impose high detour/application cost when
quarantined. A physical link with no demanded context is not the scheduling unit.

**When:** trigger on a C-W4 gap, demand for a quarantined or stale context, configuration/transceiver
epoch change, requested restoration, or evidence expiry for a demanded context.

**Stop:** every demanded behavioral sublink is either certified within the registered error bound or
quarantined with a safe route. Reopen measurement when demand crosses an uncertified boundary.

## Implementation sequence and gates

### P0 — Evidence integrity and bring-up contract — DONE

Correct stage counts, archive build evidence, add end-to-end classification PTF, and make the BFRT
setup programs support C-W4 action data.

**Gate:** fresh compile, 4/4 model tests, offline controller tests. All pass.

### P1 — Context Capsule (size x service class) — BUILT, MODEL-GREEN, COMPILE-GREEN

At the source leaf, classify stable packet headers into a four-bit context id and write it into
unused fabric-shim padding. Preserve it across hops. Index every egress witness with
`(vlink << 4) | context`. Start with four size bins x four DSCP-derived service classes; keep the
mapping control-plane programmable and publish it.

**Gate:** zero added wire bytes; at most 12 stages in either gress; distinct contexts produce
independent wire sequences end-to-end; source, transit, and downstream agree on the id; forged or
out-of-domain labels fail closed or are explicitly out of scope. If the 4x4 classifier does not fit,
fall back to 2x2 and report the lost oracle envelope rather than hiding it.

### P2 — Behavioral health gate — BUILT, MODEL-GREEN, COMPILE-GREEN

Before `tbl_vlink`, key an exact table on source, destination, selected spray path, and context. A
quarantine entry rewrites only the spray choice to a prevalidated backup; `tbl_vlink` then resolves
and counts the actual path. Keep the ordinary default as no-op. Do not override forwarding after
the counted table because that would make the ground-truth counter name the wrong link.

**Gate:** hostile PTF proves bad-context reroute, healthy-context continued use on the same physical
link, no loops/black holes, accurate post-reroute counters, and no action on a healthy/no-entry
packet. Compile and resource report required.

### P3 — Topology-realistic feedback and state — PARTIAL-LOSS LOOP SILICON-GREEN, LIFECYCLE OPEN

Carry a downstream C-W4 event to the source selector using an attributed notification mechanism;
do not claim notification novelty. The controller first installs this mapping; a later data-plane
fast path is allowed only if it materially improves unsafe exposure. Include event coalescing,
sequence epoch/reset, stale feedback, and flapping.

The data plane produces an attributed gap event and carries it to the collector on silicon. The
running controller consumes a demand-targeted pooled census, parses `GapEvent`, applies the frozen
inference layer, and writes every affected gate row as one batch. Twenty repeated trials measured
4.998 ms median from the downstream switch event to the first exact probe on the backup. Targeted
census reduced one agent read from about 250 ms to 7.7 ms median; otherwise the write could queue
behind telemetry. What remains open is the second half of the lifecycle: no running controller has
yet injected sufficient probation traffic, consumed all declared receipts, and removed the gate on
silicon. The old 97.4 us comparison remains retracted because it measured same-switch congestion
attention, not this path.

Add a mandatory liveness sub-gate: demonstrate partial conditional loss, a selective total
blackhole, and an all-context blackhole. For the latter two, either price an explicit liveness/audit
mechanism or narrow the detector claim. A gap-only C-W4 result cannot pass this sub-gate.

**Gate:** compare with real feedback latency, not an instantaneous simulator stop. At matched false-
alarm operating points, conditional mitigation must keep unsafe packets within the preregistered
bound and must not quarantine a healthy context at an unacceptable rate.

### P4 — Trace-driven value and application experiment — BLOCKED ON P3 LIVENESS/RESTORATION

Replay Ring-AllReduce and MoE AlltoAll demand through htsim/ATLAHS. Required faults: CorrOpt-style
direction asymmetry, Aegis-style `>1 KB`, direction x size, class-selective, persistent/repaired/
flapping, and the two negative-control boundary cases.

Do not implement an instantaneous-detector shortcut. The partial-loss event-to-gate latency
distribution is now measured; P4 begins only after restoration evidence, the reorder contract, and
total-blackhole treatment are fixed. An earlier post-localization analytical value gate remains
useful but is not an application result.

Baselines: physical-link disable, directed W4, topology-realistic witness-stop, size-only C-W4,
Context-Capsule C-W4, exact oracle, and varied synthetic probes for detection coverage. Match on
unsafe packets/restorations first; compare performance only among arms satisfying the safety bound.

Primary metrics: unsafe production packets, safe primary capacity retained, detour bytes and peak
detour utilization, blocked demand, collective completion time, false-safe/false-quarantine per
context, time to safe-envelope identification, feedback/audit bytes, and P4 stages/PHV/SRAM/SALUs.

**Gate:** on held-out traces, the contextual system must improve either safe delivered demand by at
least 5 percentage points or median CCT by at least 5% over directed W4, with a CI excluding zero,
while meeting the identical unsafe-packet bound. Otherwise narrow the paper to the mechanism and
negative characterization.

### P5 — Silicon and robustness — PARTIAL

The switch's SDE 9.13.2 compiled and loaded the event program, and the functional virtual fabric
proved forwarding, behavioral identity, post-stamp selective detection, automated conditional
reroute, targeted census, batch actuation, repeated reset, and modular injector wrap. Still validate
reordering on the adopted witness, background-loss specificity, restoration, flapping, and
control-plane restart.

**Gate:** model/silicon agreement on packet semantics and resource fit; all divergences reported.

## Publication stop conditions

Stop or narrow the primary claim if a targeted prior-art gate finds the same context-indexed
post-TM witness plus partial-link mitigation contract; the Context Capsule/health gate does not fit;
trace-driven benefit disappears at matched safety; classification granularity strands most of the
oracle-safe demand; feedback/specificity makes conditional mitigation operationally unsafe; or the
headline fault class is unobservable without an unpriced auxiliary liveness mechanism.

The publishable result may still be negative: coarse binary link health is measurably wasteful, but
fixed context bins fail to approximate the safe envelope. That result must remain visible rather
than being optimized away post hoc.
