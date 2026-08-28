# Counterfactual-observability gate — VERDICT (revised 2026-08-28, second pass)

> **FAIL the original lease / cap / lifecycle novelty claims. PASS a redesigned
> production-conditioned recovery primitive to a focused novelty gate.**

The first pass of this verdict (below, kept intact) killed the wording. It also overreached, and
the overreach is recorded here rather than quietly edited away.

2026-08-28. `docs/superpowers/plans/2026-08-28-counterfactual-observability.md` requires a
PASS / NARROW / FAIL literature gate *before* lifecycle implementation. Three independent reviews
ran against the spec's §3 (thesis, contributions) and §4 (system contract). This is the record and
the verdict. Nothing in `controller/audit_*`, `sim/audit/` or `p4/audit/` should be written on the
strength of the claim as it stands.

## Where the first pass overreached

The 67 ms figure in `GATE2-AUDIT-BUDGET.md` is arithmetically right and **only valid for
stationary IID loss under the audit's own packet distribution**. It was then used to conclude that
recovery evidence is cheap in general, which the evidence does not support. Formally, an audit
measures

    L_audit = E_{x ~ Q} [ loss(x) ]

while restoration needs

    L_production = E_{x ~ P} [ loss(x) ]

where x carries packet size, traffic class, timing, offered load, queue occupancy and switch
configuration. **If Q does not cover P, no number of cheap probes yields a production-loss
guarantee** — the cost axis is not the binding constraint, *coverage* is. This file's own §5
already conceded it ("an audit that uses small packets on an empty queue is not testing what
production will meet"), and Aegis reports the failure in production: their 64-byte Pingmesh probes
missed a fault that only dropped packets larger than 1 KB.

Five specific corrections:

| first-pass claim | what the evidence supports |
|---|---|
| a fixed full audit train suffices | only for stationary IID loss under the audit distribution |
| Aegis published the same solution | Aegis published the *problem*, dramatically — the 64 B/1 KB miss. It does not implement directed-link recovery certification |
| CorrOpt has the same directed-link lifecycle | CorrOpt disables **both directions** because its hardware cannot disable one independently, and never safely exercises an isolated sprayed link before readmission |
| steering is the surviving novelty | unsafe: OPP already does full-path active measurement under spraying, UET supports entropy-selected path probes, Everflow supports guided probes and replay |
| dual control / positivity occupies the problem | they supply the vocabulary, not a line-rate mechanism that restores overlap for an internal sprayed link |
| the budget is vacuous | mostly vacuous for an isolated IID physical-link audit; it returns for concurrent links, production-conditioned faults, control links, probation, and load-dependent behaviour |

The reframed question is therefore **not** "how few packets certify a link" but "**how does a
switch obtain evidence drawn from the production distribution on a link production no longer
uses**". That is a different problem and the prior art above does not answer it.

## Verdict by contribution (first pass — the wording that stays dead)

| spec §3.2 contribution | verdict | what occupies it |
|---|---|---|
| 1. Problem and model: quantify self-hiding failures **and the loss of identifiability** | **DUPLICATE** | Feldbaum's dual control (1960–61): *"the controller must inject a probing signal or perturbation to get more information about the process"*, and the closed-loop identifiability result that follows. Reads to a causal-inference audience as a **positivity/overlap violation under a deterministic policy**. Also apple tasting (Helmbold et al. 2000), selective labels (KDD'17), preventive-maintenance right-censoring. And **Aegis (NSDI'25) published the observation itself** as an operational lesson: their parallel diagnosis misses core/aggregation faults *"since we delicately minimize traffic passing Core and Aggregation switches"*. |
| 2. Evidence-lease abstraction + data-plane-enforced audit cap | **DUPLICATE (primitive) + VACUOUS (motivation)** | "Evidence lease" is a **lease** — Gray & Cheriton, SOSP'89 — time-bounded validity expiring into *unknown*, not *bad*; also RSVP soft state, DHCP, OpenFlow `idle_timeout`. The enforcement primitive is **TVA (SIGCOMM'05)**: *"capabilities that grant the right to send up to N bytes along a path within the next T seconds"*, with routers checking both expiry and the byte cap — your contract with `max_packets × packet_size` for N and `deadline_us` for T. **NETCAP (NDSS'26)** is the Tofino 1 instance. **PINT (SIGCOMM'20)** owns "bounds the amount of information added to each packet" in the data plane. And separately, the cap has nothing to protect: see `GATE2-AUDIT-BUDGET.md`. |
| 3. Lifecycle system and frontier result | **DUPLICATE** | **CorrOpt (SIGCOMM'17)** runs detect → disable → repair → re-enable → relapse → re-disable on *directed links* in 70+ datacenters under a per-ToR capacity constraint — the same safety–capacity frontier. **Aegis (NSDI'25)** does quarantine → generated audit workload → certified return. **Circuit-breaker half-open** is PROBATION. **RFC 4427 Wait-to-Restore** gates restoration on sustained cleared-defect evidence; **RFC 2439** standardised the reuse threshold in 1998. |

## The finding that decides it

The bounded audit's own arithmetic removes its reason to exist. Certifying a 1e-4 ceiling at 5 %
false-restoration risk costs 29,956 packets on a clean fabric and 139,392 at the 1e-4 background
our F0 block runs at — **67 ms of a 25 G link, against quarantine durations the literature reports
in minutes (Aegis) to days (CorrOpt)**. That is 0.00008 % of a one-day outage; ~12,900 sequential
audits of one link would be needed to spend 1 % of it. So the "safety–capacity–**overhead**
frontier" is one-dimensional, a fixed retry timer with a full test train is nearly free and gets
the same certification, and an exposure cap protects against nothing: a quarantined link is idle by
definition, so an audit on it cannot steal production bandwidth. Full working:
`docs/review/GATE2-AUDIT-BUDGET.md`.

## What actually survives

1. **Steering, not bounding.** No published system can *obtain* evidence on a directed
   inter-switch link that packet spraying has emptied. CorrOpt, Envoy, circuit breakers and
   NetBouncer all re-admit by restoring real traffic and watching passively, because in their
   settings the quarantined resource is directly addressable end-to-end; on a sprayed fabric it is
   not. This is a **capability**, and it needs no budget to be interesting.
2. **INCONCLUSIVE as a priced third state.** Every prior system collapses inconclusive into
   healthy — pass the check, return to the pool. Making "uncertified" neither healthy nor faulty,
   with the restoration error bound written as a function of the evidence actually obtained, is
   defensible and small.
3. **An empirical quantification nobody has**: on a real sprayed AI fabric under a stated
   mitigation policy, what fraction of directed links goes observationally dark, for how long, and
   how stale the last evidence is when the restore decision is taken.

Note the cruel detail: the steering that survives is **cheap** — `tbl_vlink` already writes
`ucast_egress_port` and `qid`, and `setup_skeleton.py` maps leaf→spine onto `(port, qid)`, so
audit steering is *taking `md.spray_idx` from the audit header instead of the spray draw*: no new
tables, ~no stages. Cheap to build is good engineering and a weak contribution.

## Recommendation

**Do not build the lifecycle as specified.** It is a conjunction of known mechanisms — the same
failure mode that killed gate 1. The defensible paper is empirical, not architectural:

> On a packet-sprayed AI fabric, mitigation makes directed links observationally dark. We measure
> how much and for how long; we show that CorrOpt-style restore-and-watch either strands healthy
> capacity or exposes production to unsafe restorations; and we show that a targeted, witness-
> validated audit — which sprayed fabrics uniquely cannot perform today — closes that gap, at a
> cost of N packets per certified loss-rate ceiling.

Everything else is cited: the lease to Gray & Cheriton, probation to the circuit breaker,
restoration gating to Wait-to-Restore, the decision rule to truncated SPRT / thresholding bandits /
non-inferiority testing, the enforcement contract to TVA and NETCAP, the lifecycle to CorrOpt and
Aegis.

**Before any P4 is written**, the plan's own §11 stop condition is the one closest to firing, and
it is not prior art: *the lifecycle must improve certified restoration or stranded capacity at
equal probe cost*, and the arithmetic above says probe cost is negligible, which makes an
equal-cost comparison vacuous. Settle that with `sim/gate/replay.py` first.

## Engineering findings worth keeping regardless

From the data-plane review, all costed against `p4/witness/COMPILE-GATE.md`:

- **Do not use a TNA `Meter`.** A meter is a refilling *rate* limiter; `max_packets` is a finite
  one-shot quantity, and a counter cannot drop. A register with a saturating decrement is the only
  primitive that expresses "this audit has permanently spent its quota".
- **Stale-id rejection is nearly free**: one exact-match table on `(audit_id, vlink_id, hop)`, one
  control-plane row per live audit, miss → drop + count. Deleting the row is instant revocation.
- **The stage risk is a write-after-write on `drop_ctl`**, not the SALU — three sites already write
  it, and COMPILE-GATE §4 measured that hazard class moving identical logic between 8, 9 and 10
  ingress stages while the dependency depth stayed at 8.
- **A controller-free timeout means the Tofino one-shot packet generator**, and it must be armed on
  **pipe 1**: `setup_skeleton.py` puts dp9 in pipe 0 and the loop ports in pipe 1, and registers are
  per-pipe. LinkGuardian's dummy-packet ring is the wrong price here — its generator emits every
  5 µs, ~102 Mbps continuously per protected direction, which contradicts bounded exposure.
- **Count the reject action, never assume the miss path runs.** The PTF gateway-folding defect
  (`p4/ptf/PTF-MODEL.md`) is exactly this failure and it was invisible to the compile gate.
