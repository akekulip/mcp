# MCP plan — counterfactual observability pivot · 2026-08-28 → submission

Target: **SIGCOMM'27** if its research-paper schedule and the gates below close; fallback:
**NSDI'28 / IEEE-ACM ToN**. The SIGCOMM'27 research CFP/deadline remains unverified (`HURDLES H15`),
so re-check monthly and do not weaken a gate to meet an assumed date.

Detailed design: `docs/superpowers/specs/2026-08-28-counterfactual-observability-design.md`

Task-by-task implementation plan: `docs/superpowers/plans/2026-08-28-counterfactual-observability.md`
Full decision/verification record: `.omx/plans/high-novelty-telemetry-plan.md`

## Direction and claim boundary

The original novelty gate has fired. `docs/review/NOVELTY-GATE.md` shows that the coverage result is
classical Bellman/Blackwell search and that the post-TM order witness is occupied by NetSeer,
LinkGuardian, and UEC LLR. SprayCheck also refutes the strong claim that spraying eliminates pooled
localization. Those results and mechanisms remain useful infrastructure and baselines; they are not
contributions.

The approved new question is:

> How can a packet-sprayed AI fabric safely determine whether an avoided or quarantined directed
> link remains faulty, has recovered, or is flapping after its own routing action has removed the
> passive traffic that supplied evidence?

The gated thesis is:

> Adaptive routing and mitigation make observability endogenous. While a link carries production
> traffic, a known link-local witness can localize post-TM loss. Once the link is quarantined,
> passive evidence disappears. An evidence lease plus a switch-capped counterfactual audit can
> restore identifiability, shorten safe restoration and reduce healthy capacity stranded without
> increasing unsafe restorations or audit cost.

Potential contributions, each independently gated:

1. **Problem/model:** measure the self-hiding-failure lifecycle and formalize the loss of
   identifiability after traffic allocation becomes zero.
2. **Abstraction/primitive:** an evidence lease and bounded counterfactual-audit contract for an
   explicitly targeted directed link. The switch enforces the exposure cap; restoration requires a
   confidence-qualified result.
3. **System/result:** a Tofino-backed `detect -> quarantine -> audit -> probation -> restore`
   lifecycle that advances the safety–capacity–overhead frontier in a three-tier simulation.

Do not claim sequence numbers, gap detection, era bits, dummy packets, alternate marking, active
probing, sequential tests, generic zoom, or learned scheduling. “Observability debt” is state used
by the scheduler unless a separate theory gate proves more.

## What exists now — verified 2026-08-28

### Complete enough to reuse

- Exact deterministic replay in `sim/gate/replay.py`; `sim/gate/M1-REPLAY.md` records the measured
  evidence/coverage decomposition and the scoped negative scheduling result.
- The original theory/mechanism novelty gate is closed and failed; the corrected result is retained
  only as attributed explanation in `paper/THEORY.md`.
- The W2/W4 compile study in `p4/witness/COMPILE-GATE.md` passed on bf-p4c 9.13.2.
- W4 is the only correct variant for the current virtual testbed: one loop port carries two
  directed vlinks, so port-only W2 identity is ambiguous.
- W4 stamp/check/count adds zero placed MAU stages; arming the old attention path adds one ingress
  stage. The explicit 4-byte W4 header costs 0.267% at 1500 B and 0.0977% at 4096 B.
- `mcp_fabric_w4_egdrop.p4` provides the required post-stamp fault placement for testing. The
  existing ingress injector cannot create W4 gap evidence.

### Still open

- W4 model/PTF semantics: initialization, reset, wrap, duplicates, allowed reorder, consecutive
  loss, multi-queue traffic, stale headers, and exact gap counting.
- W4 silicon validation and correct directed-link report path.
- The old `QUIET -> SUSPECT -> ZOOM -> COOLDOWN` hard cap is planned but not implemented.
- No quarantine, evidence lease, counterfactual audit, probation, restoration, or audit scheduler
  exists in the controller, simulator, P4, or PTF suite.
- Hulk is not yet a second source; the current hardware fabric is functional emulation, not a scale
  or absolute-latency testbed.

## System shape

```text
production traffic
      |
known W4/NetSeer-style evidence
      v
   SUSPECT -> QUARANTINED -> AUDIT -> PROBATION -> HEALTHY
                    ^          |          |
                    +----------+----------+
                    fault, timeout, or relapse
```

An audit contract is:

```text
audit(link_id, audit_id, max_packets, packet_size, traffic_class, deadline_us)
    -> HEALTHY(evidence) | FAULTY(evidence) | INCONCLUSIVE(evidence)
```

First implementation: host/controller injects a fixed-size audit train at the upstream endpoint;
the switch validates `audit_id` and `link_id` and enforces `max_packets`. A packet generator or
self-replenishing dummy packet is an optional later optimization and a LinkGuardian-derived
comparator, not a prerequisite or novelty claim.

## Milestones and gates

### M0 — Preserve the honest record and reissue · 28 Aug – 4 Sep

Finish the already-open M0 repairs in PREREG and replay: detector provenance, KM medians, one budget
currency, stable seed/scenario semantics, hypothesis retirements, and mirror-header reconciliation.
Do not rewrite historical failed results; label them superseded and retain their hashes.

**Gate:** all current tables reproduce from the frozen detector and stable scenarios. No new
confirmatory evaluation begins before this passes.

### M1 — Counterfactual-observability prior-art gate · 28 Aug – 11 Sep

Search primary work on failed-link rehabilitation, revalidation, quarantine/probation, safe
exploration, active diagnosis after rerouting, and routing/measurement feedback. For every close
system record whether it: (1) loses passive evidence after mitigation, (2) targets an avoided
directed link, (3) enforces an exposure cap in hardware, and (4) requires confidence-qualified
evidence before restoration.

**Gate:** write `PASS`, `NARROW`, or `FAIL` in `docs/review/NOVELTY-GATE.md`. `FAIL` stops M3–M7,
while M2 may finish as the existing W4 attempt; the submission direction returns to the negative
replay/W4 artifact. `NARROW` removes occupied capabilities from the claim before code is written.

### M2 — Close W4 as borrowed infrastructure · 1 Sep – 25 Sep

Add PTF/model tests for contiguous delivery, wrap, duplicate, reorder, consecutive loss, reset,
explicit link identity, and multiple traffic classes. Regenerate variants through
`p4/witness/gen_variants.py`, recompile, update the cost table, and run W4 on silicon only after the
semantic suite passes.

**Gate:** exact directed-link attribution, declared ordering scope, zero unexplained false gaps, and
post-stamp fault injection. If W4 fails, use a published alternate-marking/paired-counter surface;
the counterfactual lifecycle remains the research question.

### M3 — Event-level lifecycle proof and preregistration · 12 Sep – 9 Oct

Create a dependency-free `sim/audit/` event simulator and pure `controller/audit_types.py` /
`audit_policy.py` state machine. Model persistent loss, recovery, blackhole, one relapse, and
flapping, plus concurrent quarantine/recovery bursts over multiple unequal-capacity links.
Quarantine must set production evidence to zero; only explicit audits can certify recovery.
Implement permanent-quarantine, fixed-timer, continuous-probe, round-robin, earliest-deadline, and
oracle baselines.

Before the pilot, compute the published sample-complexity floor for every tested
`(p_healthy, p_faulty, alpha_restore, beta_keep_quarantined)` pair. An insufficient audit returns
`INCONCLUSIVE`, never healthy. Use a labelled pilot to choose the material margin, error bounds,
and seed count. Amend PREREG before confirmatory runs; keep paper hypothesis ids visually distinct
from `HURDLES` ids.

**Gate:** deterministic replay, exact audit-byte accounting, an operationally justified unsafe-
restoration bound, and a nontrivial feasible region. If fixed timer already matches the new policy
at equal cost, stop the primitive claim before P4 expansion.

### M4 — Switch-capped directed-link audit · 12 Oct – 13 Nov

Derive one W4 audit variant under `p4/audit/`. Reuse W4's existing `link_id + sequence`; do not add
them again. First try a reserved `fabric.flags` bit plus audit-only reuse of `csig.epoch` for
`audit_id`, which adds zero fabric bytes. If compiler or semantic tests reject that encoding, add
only a standalone 2-byte `audit_id` and record the delta. Keep the packet cap in per-link switch
state. The safe install order is tokens=0, new id, target, then tokens. Reject stale ids, wrong
targets, oversend, and concurrent reuse. Use fixed packet size so the hard byte cap is exactly
`max_packets * packet_size`.

Host/controller injection is primary. Investigate Tofino packet generation only after this version
passes and only if it reduces overhead or removes a real liveness dependency.

**Gate:** bf-p4c fit plus hostile PTF evidence that accepted packets never exceed the installed cap
and only the requested directed link is exercised. If exact steering is unavailable, remove the
arbitrary-link claim; if the cap is unenforceable, stop the primitive claim.

### M5 — Controller and htsim integration · 16 Nov – 11 Dec

Add a thin BFRT adapter; lifecycle decisions remain in the pure policy module. Extend only the
existing htsim Bernoulli fault path with time-varying `p(t)` and explicit audit traffic. Do not revive
the retired F2–F9 matrix. Cross-validate the event simulator, htsim, and virtual Tofino topology on
identical scenarios.

**Gate:** the three layers agree on packet counts and lifecycle decisions; no detector sees fault
ground truth; repeated seeds materialize identical fault/recovery schedules.

### M6 — Integrated lifecycle evaluation · 14 Dec – 22 Jan

Workloads: Ring-AllReduce and MoE AlltoAll. Functional hardware: 4-leaf x 2-spine virtual fabric.
Scaled simulation: three-tier fabric. Faults: `p in {1e-4, 1e-3, 1e-2, 1}`, recovery after
`{1, 10, 100}` audit opportunities, one relapse, flapping, concurrent recovery bursts affecting
`{2, 8, 25%}` of links, and separately labelled background loss/congestion.

Direct baselines:

- permanent quarantine;
- fixed retry timer plus fixed probe train;
- continuous probing;
- round-robin and earliest-deadline audits;
- SprayCheck/W4 detection followed by conventional retry;
- OPP/NetBouncer-style active coverage on matched axes;
- LinkGuardian-style liveness traffic as a cost comparator;
- oracle recovery time.

Primary result: minimize time to certified restoration and healthy-capacity-time stranded, subject
to the fixed unsafe-restoration and audit-byte bounds. Also report bad packets exposed, false
quarantine, `INCONCLUSIVE` audit frequency/duration, collective completion time, header bytes,
SRAM, stages, SALUs, and BFRT operations.

**Gate:** the integrated system must move the preregistered safety–capacity frontier at equal audit
cost without violating application non-inferiority. No post-hoc composite score.

### M7 — Bounded forensic zoom · 11 Jan – 22 Jan

Implement `QUIET -> SUSPECT -> ZOOM(K) -> COOLDOWN` only after M4 proves the audit cap. Keep zoom
orthogonal: it captures diagnostic context for an identified link; it does not certify restoration.
Reuse the same token-cap enforcement where possible and retain probabilistic attention only as an
ablation.

**Gate:** mirror volume never exceeds the episode cap and the collector does not drop at the
declared fault-storm envelope. Otherwise remove zoom from the contribution list.

### M8 — Writing, artifact, and venue gate · 18 Jan – submission

Package exact replay, event simulator, htsim schedules, P4 sources, PTF, BFRT adapter, compiler
reports, raw counter logs, baseline provenance labels, and the preregistered analysis. Use a
reviewer who has not written the mechanism to audit claim boundaries.

**Hard decision:**

- **Integrated systems paper:** M1–M7 pass.
- **Negative-result/replay artifact:** the lifecycle gate fails, but the decomposition/replay
  result is independently complete and useful.
- **Stop:** neither result supports a defensible contribution.

## Publication portfolio

Default to one integrated paper. A separate negative-result paper is allowed only if it has a
distinct question, claims, figures, and evaluation and does not reuse the same W4 result as an
independent contribution. A later journal extension must add substantial theory, implementation,
or evaluation and disclose overlap.

## What remains dropped

LinUCB, shadow prices, multi-resource knapsack, the 7-dimensional context, probabilistic attention,
CSIG-style tags, NIC evidence, generic zoom, sequence numbering, and the classical coverage lemma
are not headline contributions. Do not revive the 18,400-run matrix, the 730-run tuner, or “switch
beats NIC” from the Soft-RoCE hardware subset.

## Standing risks

- The new gap is provisional until M1 completes a primary-source gate.
- A fixed timer plus probes may be sufficient; M3 is designed to discover that cheaply.
- Exact steering to an arbitrary internal directed link may require adjacent-switch packet
  generation; host steering alone is not assumed.
- W4 observes post-egress loss, not upstream TM drops.
- Timeout remains a priced controller/tick path until proved otherwise.
- One-chip emulation supports functional claims only.
- `H26` still limits full htsim runs to 21.5 GB each; event-level simulation is the default for
  policy sweeps.
- The audit lifecycle creates active traffic, so the old exact-replay argument does not apply to
  audit arms; run them in-loop.
