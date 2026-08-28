# Novelty gate — outcome: BOTH GATES FAIL (2026-08-28)

`docs/review/PLAN.md` sets a kill/pivot gate before major P4 work: *"an independent theory/prior-art
review must show that the bound is not merely a classical coverage/search lemma relabeled … If
either gate fails, demote the bound to an explanatory lemma and publish the scoped negative
result/replay benchmark rather than a recombination claim."*

Three independent reviews ran against `paper/THEORY.md` and the M2 mechanism. Both novelty gates
fail, on retrieved primary sources rather than on recollection. This file records the verdicts, the
evidence I verified myself, and what the project does next. **The gate is tripped; the pivot it
prescribes is now in force.**

## Gate 1 — the coverage bound: DUPLICATE

The proposition (under observational exchangeability, any counter-computable policy needs
E[delay] ≥ (n−B)/2B, tight and attained by round-robin) is the perfect-detection case of **discrete
search for a stationary target**, which is Bellman, *Dynamic Programming* (1957), Ch. III Ex. 3,
p. 90, and Blackwell's index rule (reported in Matula 1964; independently Black 1965). With equal
priors and equal costs every Blackwell index ties, every search order is optimal, and the expected
number of looks is (n+1)/2 — which divided by the batch size B and shifted by the round in which
the wait starts is exactly (n−B)/2B. Blackwell's result is *strictly stronger*: it solves arbitrary
priors and costs, and shows the optimum is a fixed non-adaptive sequence. Our exchangeability
hypothesis is not a new sufficient condition for "adaptivity does not help" — it is the degenerate
case in which all indices tie, i.e. the easiest case of a 1957 textbook exercise.

Two modern restatements sit directly in the literature §6 of THEORY.md flagged, both in IEEE
Transactions on Information Theory:

- **Chaudhuri, Fellouris & Tajer**, *Round Robin Active Sequential Change Detection for Dependent
  Multi-Channel Data*, IEEE TIT 70(12):9327–9351, 2024 (arXiv:2403.16297). K sources, exactly m < K
  sampled per slot, data-driven selection — our budgeted counter-read model. Thm 3.1 is a universal
  lower bound over all budget-respecting policies; Thm 4.3(ii) with Rmk 4.1 shows **round-robin is
  first-order asymptotically optimal** within that class under a homogeneity condition that is our
  exchangeability condition.
- **Xu, Mei & Moustakides**, *Optimum Multi-Stream Sequential Change-Point Detection With Sampling
  Control*, IEEE TIT 67(11):7627–7636, 2021. Their Thm 1 delay bound carries an additive term
  **linear in (M−1)** — the coverage term, quantified, four years ago.

There is a real modelling observation left, and it argues against depth rather than for it: because
switch counters are **cumulative**, not looking *defers* evidence instead of destroying it, which
places this problem in the perfect-detection (q = 1) stationary-target regime — the 1957 problem —
rather than in the sampling-control QCD regime whose constants assume unobserved samples are lost.
That is worth two sentences in the Design section as an explanation of why the QCD literature's
constants do not transfer. It is not a contribution.

## Gate 1b — the "spraying collapses the pooled-test design space" argument: REFUTED

THEORY.md §4 claimed that under per-packet spraying every flow's pooled test has near-identical
composition, so pooled tests stop discriminating and only singleton counter reads remain. The
strong form is **false**, and the counterexample is the closest related system:

- **SprayCheck** (arXiv:2605.03702) localizes faulty leaf–spine links from purely passive,
  path-level, pooled evidence *under* spraying. Spraying does not homogenize the pools; it
  decomposes one flow into k parallel per-spine tests (arrivals per spine, λ = N/k, one-sided test
  on the deficit). Spraying *supplies* the pooled design rather than destroying it.
- The pools are not near-identical because spraying randomizes only the middle hop: a flow's pool is
  {uplinks of its source leaf} ∪ {downlinks to its destination leaf}, so pools are stratified by
  endpoint before any scheduler acts, and SprayCheck decodes exactly as group testing does — by
  intersecting reports that share a link but differ in leaf.
- The general principle (identifiability is bounded by the *routing scheme*, not the number of
  measurements) is the core of Boolean network tomography: Bartolini, He, Arrigoni & Massini,
  *On Fundamental Bounds on Failure Identifiability by Boolean Network Tomography*, IEEE/ACM ToN
  2020 (arXiv:1903.10636). NetBouncer (NSDI'19) is the constructive converse.

What survives is only: *per-link byte counters are singleton tests, and this controller reads
counters rather than reconstructing path-level pools.* That is a statement about the instrument we
chose, not about the fabric.

## Gate 2 — the post-TM link-local order witness: DUPLICATE

**NetSeer**, *Flow Event Telemetry on Programmable Data Plane*, SIGCOMM 2020, §3.3. I read the
retrieved PDF text myself rather than take the reviewer's word for it. Verbatim:

> "The key idea is to use a four-byte consecutive packet ID between two neighboring switches to
> detect packet loss. … packets are sent from Switch-1's egress to Switch-2's ingress. ① Switch-1
> inserts a private sequence number, which increases by 1 per packet, into each packet it sends out
> to Switch-2 … ③ At the downstream side, Switch-2 treats inconsecutive sequence numbers of incoming
> packets as a sign of packet drops."

That is the M2 mechanism: post-TM, egress-inserted, per-directed-link, checked at downstream
ingress, localizing at the next surviving packet, on Tofino. Our 4 B candidate is NetSeer's exact
encoding; our 2 B candidate is a width reduction of it. Two more independent occupants:

- **LinkGuardian**, SIGCOMM 2023 — per link (per port), sequence number added in egress, receiver
  detects the gap on the next packet; 3 B = 16-bit seqNo + era bit + type. Its **era bit** is the
  published answer to our modulo-wrap work item, and its **self-replenishing lowest-priority dummy
  packet** closes the idle-tail and blackhole blindness we listed as an open hole — no timeout, no
  controller, already validated on Tofino.
- **Ultra Ethernet 1.0.2 §5.1 Link Layer Retry** — per-link sequence number in the MAC preamble,
  NACK triggered by receipt of a subsequent frame, with per-port counters already exposed. In the
  fabrics this paper targets, the primitive is being standardized into the MAC.

### A correctness error in our own statement, found by the same review

We described the witness as seeing "TM drops as well as wire loss". **That is false.** A packet
dropped by the upstream TM never reaches the egress pipeline, so it never receives a sequence
number and creates no gap. Post-TM numbering witnesses exactly the losses that occur *after* egress
processing. NetSeer needs a separate mechanism (redirect MMU-dropped packets to an internal port)
precisely for this reason. `PLAN.md` M2 gets the fault-injection placement right; the prose claim
did not, and it is corrected in `paper/THEORY.md` and here.

## What this changes

1. **The coverage bound is demoted** to an explanatory lemma in the Design section, attributed to
   Bellman/Blackwell with a pointer to Chaudhuri–Fellouris–Tajer for the budgeted-class version.
   Attributing it costs nothing; presenting it as a proposition would be a credibility loss the
   rest of the paper would have to pay for.
2. **The order witness is not a contribution.** M2 becomes "instantiate and cost a known primitive",
   and the comparison against NetSeer's detection surface becomes mandatory rather than optional.
   The compile study already under way is still exactly the right work — it now answers *what does
   the known primitive cost here*, not *is this new*.
3. **The novelty budget moves to what is actually ours**: the measured coverage/evidence
   decomposition on a sprayed AI fabric, the equal-cost frontier against scheduled counter reading
   (which neither NetSeer, LinkGuardian, FANcY nor the UEC spec has ever reported), and the
   hard-capped zoom of M6.
4. **SprayCheck is promoted to the primary external threat** — it is concurrent work that occupies
   the motivating gap with a passive Tofino localizer for sprayed fabrics, and it needs its own
   delta section, not a citation in passing.
5. **Adopt rather than reinvent**: LinkGuardian's era bit for wrap, its dummy-packet queue for the
   idle-tail/blackhole case.

## Approved second-stage pivot — gate not yet passed (2026-08-28)

The failed verdict above remains final for the original theory and witness. It does not validate a
replacement claim. The approved second-stage hypothesis asks whether mitigation itself creates an
unaddressed observability problem: after routing or quarantine drives production allocation on a
suspect link to zero, how can the fabric determine safely whether that link is still faulty,
recovered, or flapping?

The candidate contribution is an evidence lease plus a switch-capped counterfactual audit inside a
`detect -> quarantine -> audit -> probation -> restore` lifecycle. W4 is borrowed infrastructure;
active probes, liveness packets, sequential tests, and generic scheduling remain prior art.

Before implementation is allowed to support a novelty claim, the M1 review must determine whether
close rehabilitation/revalidation work already combines all four capabilities:

1. mitigation explicitly removes the passive evidence on which diagnosis depends;
2. the system deliberately exercises an avoided directed link;
3. hardware enforces a packet/byte exposure cap rather than trusting the sender/controller; and
4. restoration requires fresh confidence-qualified evidence, with probation or relapse handling.

Allowed verdicts are `PASS`, `NARROW`, and `FAIL`. `FAIL` stops the lifecycle branch before its
simulator or P4 implementation; only the already-started W4 semantic closure continues, and the
deterministic replay/W4 result becomes the primary artifact. `NARROW` removes every occupied
capability from the claim before implementation.
Until that verdict is written, "counterfactual observability" and "evidence lease" are research
hypotheses, not novelty claims.

## Sources retrieved this session

NetSeer (SIGCOMM'20) doi:10.1145/3387514.3406214 · LinkGuardian (SIGCOMM'23)
doi:10.1145/3603269.3604853 · FANcY (SIGCOMM'22) · UEC Specification 1.0.2 §5.1 · RFC 9341 / 9342 ·
SprayCheck arXiv:2605.03702 · OmniPath Ping (SIGCOMM'26) doi:10.1145/3789240.3829105 · LossRadar
(CoNEXT'16) · Lidbetter, *A Review of Minimum Cost Box Searching Games*, arXiv:2502.10551 (carries
Bellman 1957, Blackwell in Matula 1964, Black 1965) · Chaudhuri–Fellouris–Tajer arXiv:2403.16297 ·
Xu–Mei–Moustakides IEEE TIT 2021 · Halme–Koivunen arXiv:2604.18008 · Bartolini et al.
arXiv:1903.10636.
