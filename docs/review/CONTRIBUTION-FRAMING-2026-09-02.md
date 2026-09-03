# Contribution framing — adversarial pre-writing check (2026-09-02)

Reviewer-grade attack on the paper's contribution **before** prose is written, from the position
the project already reached in its own gates: the detector/localizer **mechanism is occupied prior
art** (NetSeer SIGCOMM'20, LinkGuardian SIGCOMM'23, UEC LLR per `NOVELTY-GATE.md` gate 2; dShark
NSDI'19 per `NOVELTY-GATE-DSHARK.md`; LossRadar CoNEXT'16 + RFC 6374 counter pair per
`NOVELTY-GATE-4.md`). Mechanism-occupancy and the two passive comparators (SprayCheck
arXiv:2605.03702, FlowPulse HotNets'25) were re-verified against primary sources.

## 1. Does DETECTION + LOCALIZATION + OVERHEAD, on its own, clear a top venue?

**It is a ToN / IMC paper, not a SIGCOMM'27 or NSDI'28 paper.** The measurement is real, honest,
well-instrumented — but standing alone it is not *surprising* to a top-systems PC, and the one
component that would surprise them (the mechanism) is prior art.

The standalone result, without inflation: an in-fabric per-directed-link (tx, rx) witness —
primitive is NetSeer/LinkGuardian, not ours — gives flat 100 %/FP-0 detection from 1.5 % down to
1e-4 where SprayCheck-Z and FlowPulse-θ degrade or collapse, and exact single-directed-link
localization where those baselines fall back to the ambiguous {uplink, downlink} 2-set, at a
measured, hardware-validated 2 B/packet cost.

Three structural problems the PC will find:

1. **The two headline numbers are information-structure consequences, not findings.** Flat
   detection across four orders (`BASELINE-COMPARISON-2026-09-02.md`) and exact localization
   (`LOCALIZATION-COMPARISON-2026-09-02.md`, exact = 1.00) both follow *by construction* from
   having per-link TX the passive arms structurally lack. The localization doc concedes it: "MCP's
   perfect score is partly definitional … the arms do not have equal information, by design." A
   reviewer reads "method that sees the answer beats methods that don't"; the McNemar p ≤ 3.6e-15
   measures the *size* of an a-priori advantage, not the difficulty of an inference.

2. **The mechanism is occupied and reviewers WILL find NetSeer.** Our 4 B witness is NetSeer's
   per-port egress sequence-number encoding (`NOVELTY-GATE.md` gate 2, verbatim); the 2 B version
   is a width reduction. Even the RFC 6374 counter pair (TX>0 & RX==0) detects a dark context
   (`NOVELTY-GATE-4.md`). A paper whose engine is a known primitive must make its contribution the
   *measurement/integration* and say so in the abstract, or it is desk-rejected on positioning.

3. **On the fabric's own currency, MCP loses.** Passive baselines pay 0 B; MCP pays 2 B/packet
   (~0.14 % load) and sits at the 12-stage ingress ceiling with zero headroom. The sprayed-fabric
   community weights added-load-on-the-monitored-fabric heavily. The trade (continuous full-fabric
   coverage + sensitivity for 0.14 %) is defensible, but it is a trade, not a dominance.

| venue | verdict on measurement alone | why |
|---|---|---|
| SIGCOMM'27 | **Not enough / reject** | occupied mechanism + by-construction results; no new primitive, no surprising insight |
| NSDI'28 | **Borderline → major-revision-to-reject** | tolerates measured tradeoffs, but "partly definitional" localization + wire/stage-ceiling cost cut against the deployability story |
| ToN | **Defensible accept-track** | thorough systems+measurement paper with honest nulls/CIs is in-scope |
| IMC | **Best natural home standalone** | a faithful primary-source-grounded head-to-head replay of the two newest sprayed-fabric detectors, with honest nulls, is exactly an IMC contribution |

## 2. Strongest defensible contribution statement (measurement only)

Frame it as a **quantified characterization**, never a mechanism, with the information-structure
honesty *inside* the claim so a reviewer cannot spring it:

> We give the first faithful, primary-source-grounded head-to-head of the two most recent passive
> sprayed-fabric loss detectors (SprayCheck, FlowPulse) against an in-fabric per-directed-link
> witness, on the sprayed AI-fabric regime all three target, and quantify — on real Tofino silicon
> — exactly what a 2-byte-per-packet witness buys and costs: flat 100 %/FP-0 detection across four
> orders of magnitude where the passive arms' packets-to-detect grows with 1/loss-rate and their
> action rate collapses below ~1e-3, and disambiguation of the {uplink, downlink} aliasing both
> baseline papers concede a single passive vantage cannot resolve — at a measured 0.14 % added
> load and a 12-stage ingress footprint with no headroom. The witness's disambiguating power is an
> information-structure property (it holds each directed link's own transmit count), not an
> inference advance; the contribution is quantifying that property's price and payoff on silicon,
> against faithful baselines, in a regime where the passive state of the art was previously
> unmeasured.

Survivable because it (a) claims a measurement not a primitive, (b) states the "definitional"
caveat as part of the claim, (c) leads with detection cost-*scaling* — the one genuinely
non-obvious number — not the localization 1.00.

## 3. Ranked reviewer attacks — answer + gap

**A1 — "The mechanism is NetSeer/LinkGuardian. Where's the novelty?" (fatal-tier).** We never claim
the primitive; the gates retire it in writing; contribution is the measured tradeoff + faithful
head-to-head. *Gap:* none evidentially — but this sets the venue ceiling. At SIGCOMM an occupied
mechanism + by-construction result is a reject no matter how honestly positioned. **This is why the
measurement alone is ToN/IMC.**

**A2 — "Localization is definitional; you compared a method that sees TX against ones that don't."
(high).** Yes, and we say so; baselines get their full paper-faithful localizers and a generous
budget; the honest null (SprayCheck ties at 1.0–1.5 %) is reported. *Gap:* an honestly-stated
structural advantage is still "expected result, not a finding." Localization 1.00 **cannot be the
headline**; detection cost-scaling + hardware cost must lead. Framing fix, not new data.

**A3 — "Why not run SprayCheck longer / size it bigger?" (high — strongest technical attack).**
It's a scaling law, not a budget artifact: MCP ~22 M packets flat across 1.5 %→1e-4; SprayCheck-Z
median 24 M→114 M, action rate 100 %→78 %→0 % within a 160 M budget. Passive-inference cost scales
with 1/loss-rate; the witness's does not. *Gap:* we show failure within a fixed (generous) budget,
not unbounded; the honest claim is **cost, not capability**. The primary artifact must be a
*packets-to-detect vs loss-rate scaling curve at fixed sensitivity* — data in hand, a framing + one
figure.

**A4 — "You only handle one independent single-link fault (PREREG v1.9)." (high — biggest evidence
gap).** Honest scoping, matches PREREG v1.9. *Gap:* genuine limitation, the one that most caps the
venue. Every headline number lives in the single-independent-fault regime. We do **not** have
multi-fault / common-mode / non-stationary results. **This is the single largest missing
experiment**; without at least a correlated-fault and a non-stationary-load stress, the ceiling
stays ToN/IMC even after A1–A3.

**A5 — "Overhead is apples-to-oranges; on added load you lose." (medium).** Both sides tabulated;
trade is continuous full-fabric coverage vs SprayCheck round-robin one-flow-at-a-time. *Gap:* we
assert the value of continuous coverage but never *demonstrate* a fault SprayCheck misses because
it round-robined off the faulty flow. Converting asserted→demonstrated is a cheap, strong new
experiment. Not in hand.

**A6 — "You're measuring a mechanism with an unexplained hardware anomaly." (medium, credibility).**
Injected-loss recovery passed 57/57 on silicon; anomaly is on unmeasured/unarmed sublinks; PI
decision on record. *Gap:* an unexplained "stamp with no arrival" undercuts "hardware-validated."
Root-cause or explicitly bound it before quoting the cost numbers as silicon-grade. Open.

## 4. Does the paper NEED the healing lifecycle? — plain call

**For ToN/IMC: no.** Detection + localization + hardware-cost, reframed per §2 and shored up on A4,
stands alone at that tier.

**For SIGCOMM'27 / NSDI'28: yes — with a hard condition not yet met.** The only remaining component
with a genuine PC-defensible novelty survivor is healing survivor #1 in
`NOVELTY-GATE-HEALING-2026-09-02.md`: *in-fabric steered acquisition of production-congruent,
witness-validated counterfactual evidence on a directed sublink that spraying has starved*, plus
`INCONCLUSIVE` as a priced restoration state. That converts the paper from "we measured a known
primitive's tradeoff" into "we identified a **new** observability problem — mitigation makes
observability endogenous under spraying, so quarantined links go dark and cannot be re-certified
passively — and built the thing that resolves it." That framing is SIGCOMM/NSDI-shaped; the
measurement is its motivation, not its headline.

**The condition, plainly:** healing's *novelty* survives (NARROW), but its *result* is unproven and
at explicit risk of being **vacuous** (`GATE2-AUDIT-BUDGET.md`: cap protects nothing, audit
negligibly cheap, an always-`INCONCLUSIVE` arm is safe and useless, so the equal-cost frontier may
not exist). **The paper's top-venue fate hinges on running `sim/gate/replay.py` to show the healing
frontier is non-vacuous, before any prose is committed.**

Decision tree:
- **Healing result gate non-vacuous** → build the paper around the healing lifecycle; detection/
  localization is motivation; the dark-link quantification (survivor #3, *unoccupied and currently
  unquantified*: what fraction of directed links go dark under a stated mitigation policy, for how
  long, how stale at restore) is the bridge. SIGCOMM'27/NSDI'28 attempt.
- **Healing result gate vacuous** → do **not** spend a SIGCOMM cycle. Ship the measurement as
  ToN/IMC under the §2 framing.

**Measure regardless of healing's outcome:** the dark-link quantification (survivor #3). Unoccupied,
cheap, and the empirical hinge that both motivates healing and strengthens the standalone paper's
story about why continuous in-fabric coverage is worth its wire cost — directly reinforcing the
weak side of A5.

## Bottom line for the writing decision
1. Reframe the contribution as a *measured characterization* (§2), never a witness/primitive.
2. Lead with detection **cost-scaling** (flat-vs-1/loss-rate), not the definitional localization 1.00.
3. Close A3 with a packets-to-detect-vs-loss-rate curve (data in hand); close A4 with at least one
   correlated-fault / non-stationary stress (**not in hand — the gating missing experiment**).
4. Run `sim/gate/replay.py` on the healing frontier **before writing**. Non-vacuous →
   SIGCOMM/NSDI around healing. Vacuous → ToN/IMC around the measurement. The measurement does
   **not** reach a top venue by itself.

Sources: SprayCheck arXiv:2605.03702; FlowPulse HotNets'25; NetSeer SIGCOMM'20; LinkGuardian
SIGCOMM'23. Grounding artifacts: `NOVELTY-GATE{,-4,-DSHARK,-HEALING-2026-09-02}.md`,
`BASELINE-COMPARISON-2026-09-02.md`, `LOCALIZATION-COMPARISON-2026-09-02.md`,
`LEDGER-WIRE-REDUCTION-2026-09-02.md`, `paper/PREREG.md`.
