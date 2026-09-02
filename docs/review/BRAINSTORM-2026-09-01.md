# Brainstorm 2026-09-01 — re-pointing MCP: the spray is the experiment

**Status:** candidate design, awaiting Philip's approval. Nothing here is implemented. Panel: principal
investigator, networks expert, P4/Tofino engineer (six local compiles), evaluation scientist,
sequential-statistics theorist (three simulations), hyperscaler operator persona, plus my own pass
with the creative-thinking frameworks. Red-team pass recorded in §9. Inputs: `ASSESSMENT-2026-09-01.md`.

## 1. The one idea

Per-packet spraying is a randomized assignment of packets to sibling links. Nobody treats it that
way. SprayCheck and FlowPulse infer from the *distribution* of arrivals and must assume the spray
share; probing systems pay a coverage term; sequence witnesses (LinkGuardian, NetSeer) test an
absolute loss threshold. If the switch records the assignment after the spray decision (the
post-TM witness we already have) then:

- a lost packet is a labelled outcome of a randomized experiment, so link attribution is a causal
  effect with a randomization test, not an inference from shares;
- the headline test is **absolute**, against a floor estimated continuously from the fleet's own
  healthy sublinks (not a fixed constant), so the null moves with the fabric rather than being
  guessed. **Correction after red-team §9.6:** an initial design made the null *relative*
  ("siblings are exchangeable") the headline. Simulation showed that test costs 14x more packets
  than an absolute test calibrated to the true local floor, and degrades as (excess/background)²,
  which gives back exactly the sub-1% regime the project is chasing once background loss is
  non-trivial. The relative test is kept, demoted to a **congestion-versus-gray discriminator**:
  used inside queue-depth strata to tell a hot spine port from a genuinely bad link, where an
  absolute test cannot distinguish the two;
- the spray weight can be the *bet*: a **continuous** function of the absolute test's wealth, never
  a step at a threshold. A lone drop nudges a suspect sibling's share down slightly; only sustained
  evidence reaches the floor weight. Validity survives data-dependent weights as long as the weight
  is fixed before each epoch, so mitigation and measurement are the same act;
- restoration is the same absolute test run the other way on the residual share.

Two-sentence test: *Gray-failure detection on sprayed AI fabrics currently struggles below 1 % loss,
under adaptive spraying, and after quarantine, because every detector tests an absolute rate or an
assumed share and quarantine destroys its own evidence. We record the spray assignment in the
switch and treat it as a randomized experiment, which works because the assignment is the null
hypothesis, the loss is the labelled outcome, and the spray weight is a predictable bet.*

This absorbs, rather than replaces, what is built: the context-indexed post-TM witness, the TX
frontier, the health gate, audit steering, the evidence ledger, the replay harness. It fixes the
three blocking defects in the assessment at once: the rate ceiling (32-bit registers are free, and
the ledger needs no epoch), the null-versus-target contradiction (the null becomes relative, or an
absolute null against a *measured* floor), and the ledger being off the action path (the weight is
the ledger's output).

## 2. Contributions, as a reviewer would list them

**C1 Mechanism: a receiver ledger that makes loss readable at any instant.** Replace epoch, bank
and guard with two single-field stateful ALUs at the receiver ingress per sublink: `hi` = advance-only
highest sequence seen, `lo` = arrivals. Loss over any interval is Δhi − Δlo (the RTCP receiver-report
estimator, executed per directed link inside the switch). Because TX is stamped post-TM onto a FIFO
link, every packet that will ever arrive with sequence below `hi` has already arrived, so a read
is self-consistent up to one bandwidth-delay product of in-flight packets, and the IMPOSSIBLE state
cannot occur. Dark and starved sublinks are detected by *read order* (read the source TX count, then
the receiver pair), not by a guard interval. Compiled locally (`s7.p4`): 11 ingress / 5 egress
stages, 40 tables, 89 SRAM blocks, 7 stateful ALUs, which is cheaper than today's program on every
axis, with a Bernoulli fault injector and 32-bit TX frontier included. Counter width was never a
cost: a 2048 × 32-bit register occupies the same single unit RAM as the 512 × 8-bit one.

**C2 Inference: anytime-valid attribution against a floor the fleet estimates for itself.** Two
e-processes on the same ledger, one primary and one diagnostic. (i) **Primary, absolute**: a
log-uniform mixture over unknown loss rate (a GRO-style Bayes factor, not six hand-picked points),
run at the epoch level as a bounded-mean betting process so bursty loss does not break it, against a
floor $\hat p_0(t)$ estimated continuously from the healthy pool of sibling sublinks (leave-one-out,
refreshed as links join and leave the pool). This is the headline mechanism; it is scale-free
because the floor moves with the fleet, not because the null is relative. (ii) **Diagnostic,
relative**: given an epoch's total losses across k siblings, the split is multinomial with the known
spray weights under the null of exchangeability; used only inside a queue-depth stratum to tell a
gray link from a hot spine port, because it is exact under any temporal burstiness (the design
randomization is the null) but costs far more packets than (i) and must not carry the headline
claim (red team §9.6). Both stratify by the 4-bit context. Fleet-level control with e-BH across 1024
sublinks. Censored epochs contribute a factor of one; no restarts, no alpha halving. Mitigation
weight (C3) is driven only by (i), continuously, never by a threshold crossing.

Headline quantity: **drops-to-decision** d* = ⌈ln(1/α)/ln(p/p0)⌉, one lost packet at 1e-3 and two at
1e-4 against a 1e-5 floor; and **attribution entropy**, bits of link identity per lost packet:
6.6 for the witness versus 7×10⁻⁴ for a destination-side distribution test, a factor of 10⁶ in
packets-to-attribution at p = 1e-3 over 64 paths. The first version of that simulation handed the
destination the exact per-path transmit counts and detected everything; that error is the theorem.
The witness conditions out the spray; a distribution test cannot, so the spray's own entropy is its
noise floor.

**C3 Action: evidence-weighted spraying with a priced residual.** The health gate gains a range key
on a per-packet random so that a quarantine entry matches only a fraction 1 − w of a sublink's
packets; w is set per epoch from the ledger's wealth, floored at w_min. Exposure is bounded by
w × rate × time-to-decision, printed beside every verdict. Restoration is the opposite one-sided
e-process on the residual stream; a still-faulty link is re-quarantined after a bounded expected
number of losses independent of its rate. Where production traffic is absent the residual is
supplied by audit packets through the existing steering table, scheduled work-conserving in the
link's idle windows (the previous iteration's TX timeline predicts the next). Baselines: three
clean rounds, CorrOpt enable-and-watch, REPS-style freeze-and-timeout, BFD-style hold-down.

The 4-bit context stays as the granularity of the object and as a stratification variable. It is
promoted to a headline (Behavioral Sublinks) only if the physical size-selectivity bench in §6
shows a decade of loss difference across frame sizes on a degraded link.

"Sealed evidence" becomes one design paragraph: TX post-TM, RX at the next-hop parser, read order,
typed censoring with capital carried. It is not a contribution and the paper does not say
"evidence validity contract".

## 3. What each panelist added that changed the design

| panelist | decisive input |
|---|---|
| PI | spray = randomized assignment; null = sibling exchangeability; weight = bet; gates the thesis on a valid two-sample e-process with data-dependent allocation |
| statistics | that e-process exists and is simpler than the literature's (conditional multinomial on losses); validity condition: weights fixed before each epoch, every sibling under test keeps w > 0; power 14 000 packets at δ = 1e-3 with no background, 54 000 at 1e-3 background, where the absolute test flags both siblings; bursty loss: epoch-level betting gives 1–2 % false alarms where the current packetwise null gives 12–45 %; carry capital across censors (58 % false alarms if clean epochs are censored, so the censor rule must never depend on the epoch's own cleanliness) |
| networks | kill the epoch: receiver (hi, lo) ledger with TX-then-RX read order; evidence floor table; JSQ is not a one-pass ingress decision on Tofino 1; half-open via a range key on the gate; idle-window audit from the TX timeline |
| P4 engineer | 32-bit is free; the pair-register form overflows to 13 stages but the two-SALU form places at 11/5 with fewer resources; a RegisterAction cannot test a bit-slice, so count-sealed banks need a two-entry ternary table; deleting the attention path frees one ingress stage and five TCAM blocks; a true trailer is impossible (deparser emits headers only), a 4-byte shim stripped by XDP is not |
| evaluation | KL floor not 1/p; replay-thinning injector makes 640 paired replays cost seconds; SprayCheck-Z and FlowPulse-θ as replay arms with a fidelity check against their published points; three primary hypotheses; competing-risks reporting of alarm / censored / silent; the selectivity bench on the Hulk cable with FEC mode and serdes de-tuning as repeatable degradation knobs |
| operator | per-link witness is the only unconditional yes; ledger belongs on the *restore* decision; context only after the physics bench; source-declared context is a tenant-controlled key into the quarantine table, so the switch must derive it or the paper must state the trust boundary; the deployable form on fixed-function ASICs is the evidence contract as a spec, not the P4 |

## 4. Ideas considered and where they landed

| idea | verdict | why |
|---|---|---|
| Self-sealing epochs by packet count | design option, not headline | compiles (+1 egress stage) but the receiver ledger makes epochs unnecessary; keep for the sealed-evidence paragraph and as the flip-event mirror that turns census polling into notification |
| E-process in the data plane (autonomous quarantine) | stretch goal | one 32-bit log-wealth SALU per sublink; no data-plane anytime-valid test exists in the literature the panel found; costs a stage we only have after deleting the attention path |
| Shadow probation (clone production packets onto the quarantined link, drop the copy at the destination leaf) | keep as a variant of C3 | zero production exposure and production-shaped traffic; needs one mirror session and one drop rule; prior art is service-mesh request shadowing, nothing in fabrics; check ICRC and the clone's effect on the link's own load |
| Contexts as controls (healthy contexts on the same link are the paired control for a failing one) | absorbed into C2 stratification | it is exactly the stratified conditional test |
| Audit in the collective's idle windows | inside C3 | work-conserving, not zero-exposure; the TX timeline predicts idle windows without Chakra |
| Workload-declared context (DSCP per collective phase) | one figure | keeps context on the evidence side; operator wants the health certificate more than the phase key |
| Per-packet attribution trailer to the NIC | dropped | not implementable on Tofino 1; a 4-byte shim stripped by XDP works only with Soft-RoCE; operator says every shim byte is contested |
| Switch publishes an entropy exclusion set so the UEC sender avoids a quarantined link | discussion paragraph | strong deployability story on fixed-function ASICs; no mechanism to build here |
| Per-iteration link health certificate consumed by the job scheduler | discussion paragraph | the operator's top ask; out of scope for the testbed |
| FEC physics of size-conditional faults | the §6 bench, one day | the only way to promote context honestly |
| Iteration-synchronous snapshots | dropped | FlowPulse owns it |
| "Evidence validity contract" as a contribution | dropped | RFC 9341 §5, Namkung SOSR'21, Speedlight, Panorama, and now The Abstention Protocol (arXiv 2608.21412, August 2026) occupy it |

## 5. Engineering plan, in build order

1. `s1`: widen both frontiers to 32 bits. Zero cost. Re-compile on 9.13.2.
2. `s7`: receiver ledger (advance-only `hi`, 32-bit `lo`, resets removed), delete `reg_rx_frontier`
   and the bank ORs, add the Bernoulli injector (`tbl_eg_bern`, exact sublink × 16-bit range,
   direct counter, floor 1.5e-5). 11/5, 7 SALUs.
3. Delete the attention/gate path (`tbl_exceed_*`, `tbl_attn`, `tbl_gate`): ingress 11 → 10, frees
   five TCAM blocks and one SALU. Nothing in C1–C3 reads `reg_attn`.
4. Weighted spraying: duplicate members in the FAIR action-selector group (control plane only);
   half-open quarantine: add `md.rnd_attn : range` to `tbl_health_gate`.
5. Controller: put `evidence_ledger` on the action path; replace the six-point mixture with the
   log-uniform grid and the epoch-level betting process; add the relative multinomial e-process;
   carry capital across censors; e-BH across sublinks; weight policy w(t) = f(wealth(t−1)) with
   w_min; restoration as the opposite e-process. Fix PROBATION, the clean-packet reset, and the
   epoch-wrap wedge on the way.
6. Replay arms: SprayCheck-Z (analytic and calibrated share), FlowPulse-θ, uniform probing; the
   Binomial-thinning injector over clean F0 counter logs; Gilbert–Elliott loss in the sim.
7. Silicon sessions: guard/noise-floor measurement (still needed as the read-order sanity check);
   rate-versus-censor curve with the Tofino pktgen once the chip is ours; packets-to-name at
   p = 1e-3 and 1e-4 with the Bernoulli injector, 100 trials; the lifecycle with 60 restoration
   opportunities per arm.
8. The selectivity bench day on the Hulk cable (§6).
9. JSQ spray in htsim; on silicon only as a slow re-weighting from CSIG queue depth.

## 6. Evaluation (from the evaluation scientist; details in the agent report, to be folded into a prereg)

- **H1 attribution.** At p = 1e-3 and p0 = 10 × measured healthy floor, under each of four spray
  policies, the witness's median packets-to-name is within 3 × the KL floor, its false-alarm rate on
  clean seeds is ≤ 1e-3 per run, and the paired log-ratio against the better of SprayCheck-Z and
  FlowPulse-θ has a 95 % BCa CI below ln 0.1. Figure A1: packets on the faulty link until named vs
  p, curves for floor, witness, both distribution arms, probing; censored cells as arrows. Figure A2:
  the same across spray policies, witness curves overlaid, baselines fanning out, realized false
  alarm printed per policy.
- **H2 restoration.** Evidence-weighted probation: zero false restorations in ≥ 59 opportunities on
  persistent and flapping faults, median time-to-restore no worse than three clean rounds, exposure
  after a false restore ≥ 10 × lower than enable-and-watch, action rate ≥ 0.9 per repaired fault.
  Figure B: safety vs usefulness, one marker per arm, action rate printed beside it.
- **H3 context (conditional).** On the degraded link, complementary-log-log slope of P(loss) in log
  frame size has a CI excluding zero, p(1500)/p(256) ≥ 10 with CI excluding 3, DSCP coefficient CI
  includes zero. Bench: Hulk link, FEC mode and serdes equalization as degradation knobs, sizes
  64–1500 (9000 if jumbo) × two DSCPs × four rates × three levels, 1e7 frames per cell, Latin-square
  order, pre/post-FEC and FCS counters as covariates. One day.
- Reporting: alarm / censored / silent as competing risks; unconditional false alarm (censor = no
  alarm) beside unconditional sensitivity (censor = miss); action rate beside every safety rate.
- Sim-to-silicon: deterministic-injection identity, stochastic injection with a shared salt, replay
  identity of the controller's online decisions.
- Workload: a communication-bound synthetic first, MoE-64 second with its loaded fraction stated;
  RTO as a factor; CCT gain vs RTO is the honest figure.
- Tuning seeds 1000–1019 and one switch session; confirmatory seeds 2000+ and a second session with
  the config hash committed before the first run.

## 7. What this does not claim

Not the first per-link sequence (LinkGuardian, NetSeer), not the first TX/RX comparison (LossRadar,
dShark), not the first e-process (Ramdas et al.), not the first per-class OAM (Y.1731), not the
first per-class link withdrawal (US 9,161,259), not multi-switch silicon, not production readiness.
The claim is the composition: the spray assignment recorded in the switch is a randomized experiment,
and treating it as one gives attribution, a scale-free null, a valid fractional mitigation, and
restoration from one mechanism.

## 8. Open decisions for Philip

1. Approve the spine (C1–C3) or revert to the assessment's Result A + B without the relative test.
2. Spend one day building a physically degraded link (needed for H3 and for any FEC argument).
3. Venue: the statistical centre of gravity suits SIGCOMM'27; the systems half suits NSDI'28.
4. Delete the attention/gate path from the program (it is the last trace of the bandit thesis).

## 9. Red-team pass

Run by me directly (two dispatched red-team subagents were cut off by a session rate limit before
producing findings; this section uses the six panel reports already in hand plus fresh checks, and
flags anything not personally verified against primary text as unverified).

**1. "SprayCheck already compares siblings at the destination; this is SprayCheck with a switch-side
label."** SURVIVES-NARROWED. SprayCheck detects 1.5% loss in one iteration and 0.5% in five, on a
64-spine topology, from passive flow statistics with no probes (`docs/review/LITERATURE.md`,
confirmed by the abstract this session). That is bundle/spine granularity from outside the fabric.
The campaign plan's own identifiability argument (§0: a 4x2 fabric gives a rank-7 measurement matrix
against 16 unknowns) says a host *cannot in principle* recover link-level attribution under
switch-local spraying, no matter how many packets it reads — it is a capability gap, not a cost
gap. State the comparison two ways, not one: (a) at link granularity, the witness has a delta
SprayCheck cannot exercise at all under switch-local spraying (capability); (b) at matched
bundle/spine granularity, the packets-to-attribution ratio is the real, comparable number, and it
will be far smaller than 10^6. Present both; the 10^6 figure alone is a straw-man magnitude.

**2. "A conditional multinomial randomization test is textbook."** SURVIVES. Web search this
session (network tomography + randomization/permutation tests, ECMP/spraying causal attribution)
found no prior work that removes the tomography identifiability problem by recording the exact
per-packet assignment in-network and testing it directly; classical network tomography exists
*because* the assignment is unobserved from outside and must be inferred (Vardi 1996 and its
descendants, `arxiv.org/pdf/1205.6244`, `arxiv.org/pdf/1510.07158`). The statistical kernel
(conditional multinomial given epoch totals) is standard; the paper must say so and cite it as
statistics, not claim the test as novel. What is new is *what the switch gives the test*: an exact,
noiseless observed assignment, which is why identifiability collapses to a two-line argument instead
of an estimation problem. State it exactly that way.

**3. "Evidence-weighted spraying is REPS or the bandit thesis again."** SURVIVES-NARROWED, with a
real defect to fix. REPS explores/freezes on ECN with no statistical guarantee and produces no
verdict (confirmed via WebFetch on the REPS HTML this session); the panel already killed the old
MCP bandit for optimizing a *learned reward* over where to read, with prices proven inert
(`docs/review/PANEL-REPORT.md` §2, "the learner has nothing to learn here"). The distinction that
survives: the new weight is a **predictable function of an e-process's wealth with a stated validity
condition** (statistics report §8b: weight fixed before each epoch), not a reward-maximizing policy,
and it comes with an exposure bound instead of a regret bound. That is a different kind of object
and must be described as one, explicitly contrasted with the retired bandit in one paragraph so a
reviewer does not pattern-match it to H3. The real defect: as written, `w_min` traffic is still
*production* traffic crossing a suspect link, which is exactly the exposure the operator persona
said they would not accept without a number attached. Fix: make the mitigation action continuous in
wealth (a small wealth spike nudges the weight down slightly; only wealth crossing a much higher
threshold reaches `w_min`), and reserve the *zero-exposure* case for shadow probation (idea in §4),
not for `w_min` production traffic. State this plainly or a reviewer reads "never starve the
evidence" as "never protect the operator."

**4. "One BDP ambiguity is RFC 9341 with different words."** SURVIVES-NARROWED, and it must be
reconciled with a finding already in the repo. HURDLES H33 records that the deployed witness infers
loss from a single adjacent reorder — i.e., packets on a nominally single sublink are *not*
guaranteed FIFO in this loopback fabric (multi-queue TM scheduling across a shared lane can reorder
even one directed link's own traffic). The receiver ledger's "loss is exact at any instant" claim
therefore does not hold as stated; it holds only after a reorder-credit window has elapsed (the
networks report's own advance-only SALU plus controller-side credit accounting is what makes this
safe, not the ledger alone). Restate: the read-order argument replaces an untested, arbitrary 2 s
sleep (`p4/hw/loop/sequential_trials.py:62`, never measured per the assessment) with a guard derived
from the fabric's own measured worst-case latency plus a reorder-credit window — smaller and
justified, not eliminated. That is still worth a lot (RFC 9341 §5 requires a timer guard by design
and never derives it from measurement either), but "kill the epoch" should read "shrink and measure
the guard" everywhere in the design doc.

**5. "d\* = one drop to decide is operationally absurd."** SURVIVES-NARROWED, and the design already
contains the fix if stated explicitly. The statistics simulation (`seq_design.out`) shows that
against a floor $p_0 = 10^{-5}$, a single loss under a log-uniform mixture *can* cross a
$1/\alpha=20$ threshold if the mixture's implied alternative is far from $p_0$ — i.e., one corrupted
frame could, in isolation, look like strong evidence. The design's own §2 answer is that action must
be a continuous function of wealth, not a step at threshold crossing (see #3): a lone drop nudges the
weight down by a small, boundedly reversible amount; only sustained evidence reaches `w_min` or full
quarantine. If the paper only ever describes "the e-value crosses $1/\alpha$, therefore quarantine,"
this attack lands. It must not describe it that way anywhere. Separately, "alpha per repair
generation" for a link that lives for months needs its own accounting: with e-BH across 1024
sublinks (statistics report §4, threshold $K/\alpha$) the effective per-decision cost rises to 3–5
drops, and the paper should report the fleet-level expected false-alarm count over a stated
observation window, not a per-link alpha in isolation.

**6. "The relative test costs 14x more and degrades as $(\delta/q)^2$; at background $10^{-2}$ it
needs 360k packets, so the scale-free null gives back the sub-1% regime it was meant to reach."**
KILLED AS WRITTEN — this is the most consequential finding of the red team and changes the spine.
The statistics simulation (`peer_relative.out`) confirms: at background $q=10^{-2}$ and excess
$\delta=10^{-3}$, the peer-relative test needs a median 357,500 packets and only 88% power, while an
absolute test *calibrated to the correct local floor* needs far fewer (the KL-divergence arithmetic
for $p_1=0.011$ vs $p_0=0.01$ gives roughly 60,000 packets, still worse than the ideal case but much
better). The peer-relative test's real value is not sample efficiency, it is **not needing to know
the floor**. **Required change to §1–§2:** demote the relative/exchangeability test from the
headline detector to a **congestion-versus-gray discriminator**, used specifically inside the
queue-depth strata where an absolute test cannot tell a hot spine port from a bad link. Promote the
**absolute e-process with a data-driven floor** (statistics report §4's healthy-pool estimator
$\hat p_0(t)$, refreshed from the fleet's own recent counts, with e-BH across sublinks) to the
headline mechanism. This keeps the "no fixed 0.99 null" fix from the assessment, keeps the
scale-free property (the floor moves with the fleet, not a constant), and avoids the sample-cost
trap the fixed-relative-null framing walked into. This is a spine change, not a footnote — §1 and §2
above should be edited before any implementation starts.

**7. "The context dimension is vestigial."** SURVIVES as already scoped (§4 table: stratification
variable, promoted only if the selectivity bench passes). Add one sentence for the paper: the title
and headline mechanism are the witness plus the exposure-priced action; context is a covariate
discussed in evaluation and one physical bench, never a title-level object unless H3 passes.

**8. "Deleting the attention path deletes the only autonomous closed loop demonstrated on
hardware."** SURVIVES-NARROWED, and costs nothing once separated correctly. The panel already ruled
that mechanism (CSIG compare-and-replace plus TCAM sampling gate) not a contribution — shipped,
standardized, and single-pipe in a direction opposite deployed CSIG (`docs/review/PANEL-REPORT.md`
§2). What must be deleted for stage budget is only the **ingress attention/sampling-rate control
loop** (`tbl_exceed_evid`, `tbl_exceed_csig`, `tbl_attn`, `tbl_gate`) that decided when to raise
mirroring, which existed to serve the retired bandit's budgeted-sampling thesis and is unneeded once
every packet is counted exactly. **CSIG's egress telemetry (`worst_qdepth` carriage) must be kept**
— the networks report's JSQ design and the congestion-stratification covariate in C2 both need it,
and the P4 engineer's `s5` compile already shows the egress half is nearly free. State this
distinction explicitly in the design doc; as written §5 step 3 could be misread as deleting CSIG
telemetry entirely.

**9. Other findings.** *Shadow probation's ICRC:* a mirrored clone carries the packet as arrived
plus a prepended `mirror_h` (per the repo's own note, "Mirror.emit copies the packet as arrived");
since the clone is dropped at the destination leaf and never reaches a RoCE-terminating NIC, its
frame/ICRC validity does not need to survive delivery — it only needs to survive far enough to be
counted by the frontier. The real cost is not corrupted delivery, it is that clones consume real
link bandwidth on the suspect sublink; "zero production exposure" must always be paired with
"nonzero audit-byte cost," which the evaluation design's audit-bytes metric already captures. State
both, always. *Trust boundary of source-declared context:* unresolved, carried from the assessment;
the paper must state whether the switch derives the context or trusts the source, and if the latter,
that a tenant can pin its own traffic into a quarantine. *Sender-driven spraying (UEC):* C3 as
designed (a switch-side spray-weight table) applies only where spraying is switch-local — this
testbed and Spectrum-X-style adaptive routing. Under UEC's sender-chosen entropy the switch cannot
unilaterally reweight a path without violating the "same entropy, same path" contract
(`docs/review/CAMPAIGN-PLAN.md` §0); the equivalent mechanism there is the switch publishing an
advisory entropy-exclusion set to the NIC (already listed in §4 as a discussion paragraph). Scope C3
to switch-local spraying explicitly in the design and keep the UEC variant as future work, not a
claimed result. *Multi-vendor deployability:* unchanged from the operator's finding — the
deployable artifact on Spectrum-X/Tomahawk is the evidence contract as a specification, not the P4
program; say so once, plainly, near the contribution list.

**Overall verdict.** The idea survives, narrowed in one load-bearing way: the relative/exchangeability
test is not the headline detector (finding 6 kills that framing on the panel's own numbers); the
headline is an absolute anytime-valid test against a floor estimated from the fleet's own healthy
sublinks, continuous in its action (never a step at threshold), with the relative test demoted to
separating gray failure from congestion inside queue-depth strata. Every other finding is a scoping
or wording fix, not a kill.

**Three highest-leverage changes before implementation:**
1. Swap the spine's headline mechanism: absolute e-process with a data-driven floor (not the
   sibling-exchangeability test) as C2's primary; keep the relative test as the congestion
   discriminator. Rewrite §1–§2 accordingly.
2. Make the mitigation weight a continuous function of wealth everywhere it is described, and add
   one paragraph distinguishing it from the retired MCP bandit by contract (exposure bound vs regret
   bound), not just by mechanism.
3. State the reorder-credit window explicitly wherever "exact at any instant" appears, and scope C3
   to switch-local spraying with the UEC exclusion-set variant marked as future work.
