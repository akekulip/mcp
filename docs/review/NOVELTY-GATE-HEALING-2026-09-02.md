# Novelty gate — the counterfactual-observability healing lifecycle — 2026-09-02

Adversarial prior-art gate on the **healing lifecycle** (not the CLF/witness detector, which earlier
gates already ruled `NARROW`/occupied). Run BEFORE lifecycle Tasks 2–5 and 7–10 of
`docs/superpowers/plans/2026-08-28-counterfactual-observability.md`. A `FAIL` here stops that branch
and leaves only the W4 semantic-closure work (Task 6).

**Mechanism under test — the four-part conjunction claimed as novel:**

- (a) recovery evidence gathered by a **switch-enforced, capped counterfactual audit** of a directed
  link that mitigation (reroute/quarantine) has **starved** of passive traffic;
- (b) **reusing the existing loss-witness state** (W4 `link_id` + `sequence`) at near-zero added bytes;
- (c) a **probation** stage with a **safety bound on unsafe restorations**;
- (d) an explicit **`INCONCLUSIVE`** outcome under insufficient evidence (never silently "healthy").

## Verdict: `NARROW` — confirms and refines the 2026-08-30 verdict; not overturned

The earlier pass (`NOVELTY-GATE.md` M1, `NOVELTY-GATE-2.md` claim 3, `GATE2-VERDICT.md`) rated the
lifecycle `NARROW` and killed the "evidence-lease / cap / lifecycle" wording as `DUPLICATE`. Current
(Sept 2026) evidence — REPS (2025), self-healing-network automation (2025), production AI-cluster
diagnosis (Aegis NSDI'25, ARGUS/ByteDance 2025–26), and the 2024–26 safe-exploration literature —
introduces **no new single-system occupant of the full conjunction**, so the verdict does **not**
move to `FAIL`. It also cannot move to `PASS`: three of the four parts are individually occupied by
primary prior art. `NARROW` stands.

### The conjunction is not occupied by any one system (why it is not `FAIL`)

No retrieved system does all four. The nearest full-loop occupants each miss the load-bearing part:

| system | loop it runs | why it does not occupy the conjunction |
|---|---|---|
| **CorrOpt**, SIGCOMM'17 (Zhuo et al., *Understanding and Mitigating Packet Corruption in DCNs*) | detect → **disable** → repair ticket → **re-enable & watch passively** → relapse → re-disable | disables **both directions** (hardware cannot isolate one), the quarantined resource is end-to-end addressable so it re-admits with **real traffic and passive watching** — no capped active audit of a *starved* link, no spray, no `INCONCLUSIVE`. |
| **Aegis**, NSDI'25 (Dong et al.) §4.2 | quarantine → **generated audit workload** → certified return before delivery | host-side generated workload, **not switch-capped**; on its own account it *"delicately minimize[s] traffic passing Core and Aggregation switches,"* so it structurally **cannot audit** the very links a sprayed fabric hides; 64 B Pingmesh missed a >1 KB-only fault (the coverage problem, not the cost problem). |
| **REPS**, arXiv:2407.21625 (2025, Ultra Ethernet spray LB) | on failure **reroute away < 100 µs**, freeze exploration, reuse cached good paths, later **re-explore** | recovery of an avoided path = resuming **real data** exploration; a fresh 2025 sprayed-fabric instance of "restore-and-watch," with **no cap, no probation bound, no `INCONCLUSIVE`, no witness reuse**. |
| **Self-healing networks** (2025 automation / surveys) | detect → diagnose → remediate → **verify by re-checking metrics** → rollback | verification is generic metric recheck, **not** a directed-link audit of a starved link; no spray regime, no witness reuse, no priced third state. |

So detection/localization of silent black holes is prior art (dShark NSDI'19; Aegis) and the *closed
loop* is prior art (CorrOpt, Aegis, circuit-breaker half-open, RFC 4427 Wait-to-Restore), but **no
single system runs the capped-counterfactual-audit-of-a-spray-starved-directed-link with probation and
an `INCONCLUSIVE` floor**. That absence is what keeps this above `FAIL`.

### Three of the four parts are individually occupied (why it is not `PASS`)

- **(a) switch-enforced cap — `DUPLICATE` and, worse, vacuous.** The byte+time exposure cap is TVA
  (SIGCOMM'05, "up to N bytes within T seconds," routers enforce both), instantiated on Tofino 1 by
  NETCAP (NDSS'26); PINT (SIGCOMM'20) owns "bound the information added per packet in the data plane."
  Beyond duplication, `GATE2-AUDIT-BUDGET.md` shows the cap **protects nothing**: a quarantined link
  is idle by definition, and certifying a 1e-4 ceiling costs ~67 ms of a 25 G link against
  quarantines of minutes (Aegis) to days (CorrOpt). The novelty of (a) is **not** the cap.
- **(b) witness reuse — not novel.** The witness itself is occupied (NetSeer SIGCOMM'20, LinkGuardian
  SIGCOMM'23, UEC LLR — see `NOVELTY-GATE.md` gate 2). Reusing its `link_id`+`sequence` for the audit
  at near-zero added bytes is a good engineering optimization; the spec (§6.3) itself labels it "an
  implementation optimization, not the novelty claim." Cheap-to-build is a weak contribution.
- **(c) probation with a safety bound — `DUPLICATE` as a mechanism.** Probation = circuit-breaker
  half-open (Nygard); gated restoration on sustained cleared-defect evidence = RFC 4427 Wait-to-Restore;
  the reuse-threshold-after-flap discipline = RFC 2439 route-flap damping (1998); the conceptual frame
  = safe-exploration / conservative-restoration RL (2024–26). A *preregistered* unsafe-restoration
  bound is standard evaluation hygiene, not a mechanism invention.

### What survives the narrowing — the only framing the paper may claim as novel

Exactly what `GATE2-VERDICT.md` "What actually survives" already isolated, now re-confirmed against
2025–26 sources:

1. **Steering to obtain counterfactual evidence under per-packet spraying (the load-bearing survivor).**
   No published system can *obtain production-distribution-representative evidence on a directed
   inter-switch link that spraying has emptied*. CorrOpt/Aegis/REPS/circuit-breakers all re-admit by
   restoring real traffic and watching, because in their settings the quarantined resource is
   end-to-end addressable; under per-packet spraying it is not, and header-based path pinning
   (Everflow-style) no longer selects a path. Placing a **size/class-congruent, witness-validated
   audit on one chosen directed sublink from inside the fabric** is the capability nobody has. This is
   a *capability under a specific regime*, and it needs no cap to be interesting.
2. **`INCONCLUSIVE` as a priced third restoration state.** Prior loops collapse "uncertified" into
   "healthy" (pass the check → return to pool). Making insufficient evidence a first-class outcome
   that **forbids restoration**, with the restoration error bound written as a function of the
   evidence actually obtained, is a small, defensible composition. (The abstain/continue region
   exists in truncated SPRT and non-inferiority testing — cite it; the novelty is wiring it as a
   restoration state in a link-health lifecycle, not the statistical idea.)
3. **Empirical quantification (motivation, not mechanism):** on a real sprayed AI fabric under a
   stated mitigation policy, what fraction of directed links goes observationally dark, for how long,
   and how stale the last evidence is at the restore decision. Unoccupied, and it is the motivation
   the paper needs.

### Publishability caveat (separate from novelty)

`NARROW` here means "novel only as this specific composition on this specific regime." It does **not**
clear the *result* gate. `GATE2-VERDICT.md` and the repo's own cross-check rule warn that if the cap
protects nothing and audit-probe cost is negligible, the **equal-cost frontier comparison is vacuous**
— an arm that always returns `INCONCLUSIVE` is perfectly safe and perfectly useless. Settle that with
`sim/gate/replay.py` before any P4 is written (spec §11 stop condition). Novelty surviving as a
composition is necessary, not sufficient, for the paper.

## Consequences for the claim (before implementation)

- **Claim as novel, together:** (i) in-fabric steered acquisition of congruent, witness-validated
  evidence on a directed sublink that spraying has starved; (ii) `INCONCLUSIVE` as a priced restoration
  state; (iii) the empirical dark-link quantification. State them as a *composition on a sprayed
  fabric*, not as new primitives.
- **Cite, do not claim:** the exposure cap (TVA/NETCAP/PINT), the evidence-lease (Gray & Cheriton
  SOSP'89, RSVP soft state), witness reuse (NetSeer/LinkGuardian/UEC), probation (circuit breaker,
  RFC 4427, RFC 2439), black-hole detection/localization (dShark, Aegis), the audit-budget "frontier"
  (vacuous per `GATE2-AUDIT-BUDGET.md`).
- **Withdraw:** "a new evidence-lease / cap / lifecycle primitive," and any equal-probe-cost frontier
  framing until the replay result shows it is not vacuous.
- **Plan effect:** proceed with lifecycle Tasks under the narrowed claim; remove the cap and the
  lease/probation framings from the novelty budget. This matches the plan's `NARROW` branch
  ("remove those parts from the claim and proceed").

## Sources retrieved / re-verified this session (2026-09-02)

CorrOpt SIGCOMM'17 — dl.acm.org/doi/10.1145/3098822.3098849 (disable-both-directions + repair-ticket
+ re-enable, verified) · REPS arXiv:2407.21625 (spray reroute-away <100 µs, cache/re-explore) · Aegis
NSDI'25, usenix.org/system/files/nsdi25-dong.pdf (quarantine→generated-workload→certified-return;
minimizes core/agg traffic) · self-healing-network automation (2025 industry + arXiv self-healing
surveys; detect→remediate→verify-by-recheck→rollback) · safe-exploration / conservative-restoration
RL, arXiv:2409.01245, 2306.06265, 2201.07286 (2024–26; abstain/recovery vocabulary) · US12348436B2
*Intelligent quarantine on switch fabric* (security-isolation domain — adjacent, non-occupying).

Carried from prior gates (primary sources already read there): TVA SIGCOMM'05 · NETCAP NDSS'26 · PINT
SIGCOMM'20 · Gray & Cheriton SOSP'89 · circuit breaker (Nygard, *Release It!*) · RFC 4427 · RFC 2439
· dShark NSDI'19 · NetSeer SIGCOMM'20 · LinkGuardian SIGCOMM'23 · NetBouncer NSDI'19 · Everflow
SIGCOMM'15 · SprayCheck arXiv:2605.03702.
