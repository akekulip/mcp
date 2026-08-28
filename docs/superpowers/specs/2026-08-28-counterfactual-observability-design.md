# Counterfactual Observability for Self-Hiding Gray Failures

**Status:** Approved direction, 2026-08-28

**Repository:** `/home/philip/Projects/mcp`

**Target:** one integrated systems paper; preserve a separable negative-result/replay artifact only if it independently clears its claim gate

## 1. Outcome

Build and evaluate a complete link-health lifecycle for packet-sprayed AI fabrics:

1. detect and localize post-TM link loss while production traffic still uses the link;
2. quarantine the directed link;
3. obtain bounded, representative evidence after routing has removed production traffic;
4. place the link in probation or keep it quarantined; and
5. restore it only after an explicit evidence contract is satisfied.

The paper's new question is not “how do we detect gray loss?” It is:

> How can a fabric safely determine whether an avoided or quarantined link is still faulty, has recovered, or is flapping when its own mitigation action has removed the passive evidence?

## 2. Repository-grounded starting point

The project already contains useful infrastructure, but its original novelty thesis has failed its own gate:

- `docs/review/NOVELTY-GATE.md` records that the coverage result is classical Bellman/Blackwell search and that the post-TM order witness is occupied by NetSeer, LinkGuardian, and UEC LLR.
- `sim/gate/M1-REPLAY.md` provides exact, deterministic counter replay and a measured evidence/coverage decomposition.
- `p4/witness/COMPILE-GATE.md` shows that W4, an explicit 16-bit link id plus 16-bit sequence, compiles on Tofino 1 with no additional placed MAU stage for stamp/check/count; arming the existing attention path adds one ingress stage.
- W4 has not passed model/PTF or silicon semantics. The existing ingress fault injector cannot create a post-TM gap; `mcp_fabric_w4_egdrop.p4` is the compiled test vehicle.
- The current hard-capped zoom state machine is planned but not implemented.

These results become infrastructure and baselines. They are not headline inventions.

## 3. Thesis and contribution boundary

### 3.1 Gated thesis

Adaptive routing and mitigation make link observability endogenous: a suspect link receives less traffic, quarantine removes traffic entirely, and passive evidence becomes stale exactly when the operator must decide whether to restore the link. A bounded counterfactual audit can create only the evidence required to certify or reject restoration, reducing healthy capacity stranded without increasing unsafe restorations or probe overhead.

### 3.2 Potential contributions

1. **Problem and model:** quantify self-hiding failures and the loss of identifiability after traffic allocation to a link becomes zero.
2. **Evidence-lease abstraction and counterfactual-audit contract:** make recent, confidence-qualified evidence a precondition for restoration; enforce the audit exposure cap in the data plane.
3. **Lifecycle system and result:** integrate active-link localization, quarantine, bounded audit, probation, and restoration, and move the safety–capacity–overhead frontier on Tofino plus a three-tier simulator.

Each contribution is gated. The passive indistinguishability observation and sequential-test sample complexity must be attributed if they are standard results. “Observability debt” is a useful scheduling state, not automatically a theoretical contribution.

### 3.3 Explicit non-claims

Do not claim invention of:

- sequence numbers, gap detection, era bits, dummy packets, alternate marking, paired counters, packet generators, active probing, sequential tests, generic telemetry zoom, round-robin scheduling, or bandits;
- the existing W4 witness, NetSeer-compatible detection surface, or LinkGuardian-style liveness traffic;
- an arbitrary-link audit unless the upstream endpoint can force the audit onto that exact directed link;
- an all-data-plane timeout unless a packet-generator/tick design actually enforces it;
- safe restoration without a preregistered false-restoration bound.

## 4. System contract

### 4.1 Evidence lease

A directed link may enter or remain in `HEALTHY` only while it has a valid evidence lease. A lease records:

- directed `link_id`;
- evidence source and fault class covered;
- evidence packet count and byte count;
- observation interval;
- estimated loss/degradation result;
- decision confidence or error bound; and
- expiration time.

Lease expiration does not declare the link faulty. It makes the link uncertified and triggers an audit or continued quarantine.

### 4.2 Counterfactual audit

The control-plane interface is:

```text
audit(link_id, audit_id, max_packets, packet_size, traffic_class, deadline_us)
    -> HEALTHY(evidence)
     | FAULTY(evidence)
     | INCONCLUSIVE(evidence)
```

Requirements:

- `max_packets * packet_size` is a hard exposure and bandwidth cap.
- The upstream endpoint of `link_id` originates or steers the audit train onto that link.
- Audit packets use an explicitly declared traffic class and packet-size profile.
- W4 or an equivalent published witness validates delivery at the downstream endpoint.
- The data plane rejects stale audit ids and packets beyond the installed token cap.
- A missing final observation becomes `INCONCLUSIVE` or `FAULTY` through a separately priced timeout path; it is never silently treated as success.
- The first implementation uses host/controller-injected audit packets with a switch-enforced cap. A Tofino packet-generator or self-replenishing dummy design is a later feasibility optimization, not a prerequisite.

### 4.3 State machine

```text
HEALTHY -> SUSPECT -> QUARANTINED -> AUDIT -> PROBATION -> HEALTHY
               ^          |           |          |
               |          +-----------+----------+
               |          faulty, timeout, or relapse
               +----------------------------------
```

- `HEALTHY`: production traffic supplies current evidence.
- `SUSPECT`: link-local or aggregate evidence crosses the configured trigger.
- `QUARANTINED`: production traffic is removed; no passive-health conclusion is permitted.
- `AUDIT`: one bounded audit contract is active.
- `PROBATION`: a small declared routing share of production traffic is restored while evidence
  remains valid; this share is not conflated with the hard audit-packet cap.

The pre-existing `QUIET -> SUSPECT -> ZOOM -> COOLDOWN` capture path remains an orthogonal forensic mechanism. Zoom collects context; audit certifies whether an unused link may return to service.

## 5. Where and when to look

### 5.1 Where

Audit only links that are quarantined or whose evidence lease will expire before the next scheduling opportunity. Among eligible links, use a deterministic earliest-deadline policy; break ties by capacity impact and then `link_id`. Keep risk-weighted or learned policies as ablations until they independently beat this transparent baseline.

### 5.2 When

Start an audit when any of the following holds:

- a quarantined link reaches its earliest safe recheck time;
- its evidence lease reaches the preregistered staleness deadline;
- restoration is requested by the routing controller; or
- a probationary link produces relapse evidence.

Do not audit merely because a fixed periodic timer fired when the link already has sufficient fresh production evidence.

### 5.3 How much

Use a declared hypothesis pair `p_healthy` and `p_faulty` with error limits `alpha_restore` and `beta_keep_quarantined`. Derive the audit packet target using a published sequential or fixed-sample test. Report the information-theoretic/sample-complexity result as prior art unless the project proves a new constrained scheduling result.

Compute this bound before P4 expansion. In the zero-background-loss case, observing zero losses can
reject a persistent fault rate `p_faulty` with false-restore probability at most `alpha_restore`
only after
`ceil(log(alpha_restore) / log(1 - p_faulty))` delivered audit packets. At
`p_faulty = 1e-4` and `alpha_restore = 0.05`, that is roughly 30,000 packets. A small audit may
therefore return `INCONCLUSIVE`; it must never be relabelled healthy. Sequential testing may stop
early on fault evidence, while successful certification pays the full evidence cost.

Probation begins only after the audit rule returns `HEALTHY`. It restores a small declared traffic
share, uses that production evidence to renew the lease, and immediately requarantines on relapse.
The probation share and exposed packets are charged to the safety result, not hidden as free
measurement.

## 6. Architecture and ownership boundaries

### 6.1 Pure policy layer

`controller/audit_types.py` owns states, immutable events, audit contracts, and commands. `controller/audit_policy.py` owns deterministic transitions and audit selection. Neither imports BFRT or simulator code.

### 6.2 Simulation layer

`sim/audit/` owns a small event simulator for fault onset, quarantine, recovery, flapping, audit delivery, and lifecycle metrics. It is used to validate the research question before expensive htsim or silicon work. htsim later adds only a time-varying Bernoulli fault schedule and explicit audit traffic; it does not add the retired F2–F9 matrix.

### 6.3 Data-plane layer

`p4/audit/` derives one auditable W4 variant from the frozen witness baseline. It validates
`audit_id`, forces the declared directed vlink, decrements a per-link packet token, and counts
accepted/rejected audit packets. It does not originate arbitrary traffic in the first version.

The encoding follows a reuse-first rule. W4 already carries `link_id + sequence`; never duplicate
those fields. Prefer one reserved `fabric.flags` bit as the audit marker and reuse `csig.epoch` as
`audit_id` only on audit packets, targeting **zero additional fabric bytes**. If parser/action
constraints make that unsafe, add only a standalone 2-byte `audit_id` header and price it. The
encoding is an implementation optimization, not the novelty claim.

### 6.4 Control-plane layer

`controller/audit_loop.py` translates pure policy commands into BFRT writes and reads. `p4/control/setup_audit.py` installs audit ids, tokens, target links, and mirror/report sessions. Hardware-specific code never decides the lifecycle policy.

## 7. Evaluation contract

### 7.1 Primary comparison

For genuinely recovered links, minimize time to certified restoration and healthy-capacity stranded, subject to:

- a preregistered upper bound on unsafe restoration;
- an equal probe-byte budget; and
- no worse application completion time than the declared non-inferiority margin.

For persistently faulty or flapping links, report bad production packets exposed, false restoration, requarantine delay, and audit bytes.

### 7.2 Baselines

- permanent quarantine;
- fixed retry timer with a fixed probe train;
- continuous probing;
- round-robin audits;
- earliest-deadline audits without capacity tie-breaking;
- OPP/NetBouncer-style fixed active coverage on matched axes;
- SprayCheck or W4 detection followed by a conventional retry timer;
- LinkGuardian-style dummy traffic as a liveness/cost comparator;
- oracle recovery time.

Every baseline must be labelled `reproduced`, `semantic reimplementation`, `replay-only`, or `published point`.

### 7.3 Fault and workload matrix

- post-TM partial loss `p in {1e-4, 1e-3, 1e-2}`;
- complete blackhole `p = 1`;
- recovery after `{1, 10, 100}` audit opportunities;
- one relapse and periodic flapping;
- concurrent quarantine/recovery bursts affecting `{2, 8, 25%}` of links, with both homogeneous
  and traffic-derived capacity values;
- background congestion/loss as a separate condition;
- Ring-AllReduce and MoE AlltoAll;
- two-level hardware-functional topology and three-level scaled simulation.

### 7.4 Required metrics

- time to quarantine and time to certified restoration;
- healthy link-capacity-time stranded;
- number and duration of `INCONCLUSIVE` audits;
- unsafe restoration and false quarantine rates;
- bad production packets exposed;
- audit packets/bytes and fabric fraction;
- W4/audit header bytes, SRAM, PHV, MAU stages, SALUs, and control-plane operations;
- application collective completion time;
- timeout, duplicate, stale-id, overflow, reset, wrap, and concurrent-audit behavior.

## 8. Novelty and publication gates

1. **Prior-art gate:** before lifecycle implementation, search primary work on failure rehabilitation, link revalidation, safe exploration, quarantine/probation, and active diagnosis under adaptive routing. If an existing system already exposes the same contract and lifecycle, revise or stop. W4 semantic closure may continue independently because it belongs to the existing infrastructure attempt.
2. **Primitive gate:** demonstrate a capability absent from fixed probes: explicit link targeting after avoidance, switch-enforced exposure cap, confidence-qualified restoration, and lifecycle integration. If the result is only “run probes after a timer,” it is not a contribution.
3. **Feasibility gate:** prove exact directed-link steering, W4 PTF semantics, and hard token enforcement before claiming hardware support.
4. **Result gate:** move the preregistered safety–capacity frontier at equal audit cost. Otherwise publish only the negative result/replay artifact if that artifact independently warrants publication.

## 9. Publication portfolio

Default to one integrated paper:

> active-link evidence -> quarantine -> bounded counterfactual audit -> probation -> safe restoration.

A separate Paper A is allowed only if the measured decomposition plus negative replay result forms a complete, independently useful contribution with distinct claims and figures. Do not split identical W4 experiments or baseline tables across submissions. Any later journal extension must add substantial new theory, implementation, or evaluation and clearly disclose overlap.

## 10. Non-goals

- General root-cause classification across optics, NICs, software, and congestion.
- A new transport or retransmission protocol.
- Replacing OPP, R-Pingmesh, or fleet-wide service tracing.
- A learned scheduler as a headline contribution.
- Full production deployment or absolute latency claims from the one-chip virtual fabric.

## 11. Stop conditions

Stop the integrated systems claim if any of these holds:

- the prior-art gate finds the same closed-loop contract;
- exact directed-link audit steering cannot be demonstrated;
- the data plane cannot enforce the packet/byte exposure cap;
- the preregistered unsafe-restoration bound is missed;
- the lifecycle does not improve certified restoration or stranded capacity at equal probe cost; or
- the result depends on a post-hoc composite score.

In that event, retain W4 as a costed known primitive and finish only the honest replay/negative-result artifact.
