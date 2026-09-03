# Novelty gate — sprayed-fabric identifiability reframing: **FAIL** (2026-09-02)

Adversarial prior-art gate on the candidate paper reframing that pivots away from a mechanism
contribution (conceded prior art: NetSeer/LinkGuardian/LossRadar/dShark/UEC LLR) to a
**fundamental-limits / identifiability** contribution.

## The claim under test (verbatim from the tasking)

> On a packet-sprayed leaf-spine fabric, passive/end-to-end loss localization is fundamentally
> IDENTIFIABILITY-LIMITED — because every host's traffic crosses a leaf's parallel uplinks in fixed
> proportion, the passive measurement matrix is rank-deficient (4x2 example: rank 7 vs 16
> directed-link unknowns), so a class of directed-link (uplink-vs-downlink) faults is unlocalizable
> by ANY amount of passive/end-to-end measurement; and the minimal information that provably
> restores full-rank identifiability is a single per-directed-link in-fabric counter/witness.
> Genre: identifiability lower bound + minimal in-fabric primitive that breaks it + silicon confirmation.

## Verdict: **FAIL** — the angle is occupied, and the strong form is provably false against SprayCheck.

The reframing fails on three independent grounds, any one of which is sufficient. All three rest on
primary sources retrieved and quoted this session, not recollection.

---

## 1. SprayCheck already states the exact ambiguity AND resolves it passively — so "unlocalizable by ANY passive measurement" is false in the project's own (single-fault) regime

SprayCheck (arXiv:2605.03702), retrieved this session (arxiv.org/html/2605.03702):

- **It states the identical directed-link ambiguity, §3.6 (verbatim):** *"When the central monitor
  receives a failure report, it flags the entire path between the source and destination switch as
  potentially failed. This path consists of two links: the uplink from the source leaf to the spine
  (link 1), and the downlink from the spine to the destination leaf (link 2). To determine which has
  failed, the central monitor waits for failure indications from other flows."* This is precisely the
  candidate's "class of directed-link (uplink-vs-downlink) faults" — SprayCheck names it first.

- **It resolves it PASSIVELY, §3.6 (verbatim):** *"If link 1 has failed, then additional flows from
  the same source leaf to different destination leaves will report a failed path including link 1,
  and similar for link 2 and flows from different source leaves. … a link is considered failed when
  it is in the intersection of multiple failure reports that include a different leaf switch."* This
  is a constructive passive identifiability argument: the single-vantage ambiguity is broken by
  observing more (source-leaf, dest-leaf) pairs — i.e. by more passive measurement, the exact
  quantity the candidate says cannot help.

- **It observes per-spine counts, not the spine-averaged aggregate, §4.2 (verbatim):** *"The data
  plane counts how many packets marked as measurable it received from each source leaf via each
  spine. … It stores the packet counts in a map indexed by the destination QP number and spine
  switch from which the packet was received."*

Consequence: for a single directed-link fault — the **only** regime the paper evaluates (PREREG
v1.9; every headline number in `BASELINE-COMPARISON-2026-09-02.md` and
`LOCALIZATION-COMPARISON-2026-09-02.md` is single-independent-fault) — passive measurement DOES
localize the exact directed link. `LOCALIZATION-COMPARISON-2026-09-02.md` measured this directly:
SprayCheck-Z ties MCP at 1.0–1.5% loss (exact=1.00, paired diff +0.00, p=1.0). The claim
"unlocalizable by ANY amount of passive/end-to-end measurement" is therefore refuted by the
project's own comparator and by SprayCheck's own text.

---

## 2. The rank-7-vs-16 result is a property of a strictly weaker (spine-blind) vantage, not of spraying or of passive measurement — and it makes the "minimality" claim false too

The repo's rank-7 model (`CAMPAIGN-PLAN.md` §0, verbatim) is `y_id = A_i + B_d` over 12 ordered
leaf pairs. That is the classical **two-way additive model**: `A_i` = the source leaf's *uplink
bundle*, `B_d` = the dest leaf's *downlink bundle*, rank `= r + c − 1 = 4 + 4 − 1 = 7`. It reaches
"16 directed-link unknowns" only by expanding each bundle into its two per-spine links — which the
model then declares unrecoverable: *"no number of probes separates a leaf's two uplinks."*

But that bundling is exactly the per-spine information SprayCheck §4.2 shows is **passively
observable** (the upstream spine is the previous hop, readable at the destination leaf). The rank-7
collapse is an artifact of choosing a host-only, spine-blind vantage — not a property of spraying
and not a property of passive measurement. Observe the spine (passively, as SprayCheck does) and:

- **single-fault:** identifiability is restored by cross-leaf intersection = group testing (rank
  question becomes the sparse-recovery question; resolved, see §1);
- **dense/linear:** the residual freedom is only a **per-spine gauge** (add `c_i` to all uplinks
  into spine `i`, subtract `c_i` from all downlinks out of it — every 2-hop path through `i`
  unchanged), i.e. rank **14** vs 16, *not* 7. The rank-7 figure overstates the deficiency by
  conflating "spine-blind" with "spraying."

This also **refutes the minimality claim.** SprayCheck restores single-fault directed-link
identifiability using only **per-spine counters** (coarser than per-directed-link) plus multiple
leaves — strictly less information than "a per-directed-link counter/witness on every link." The
per-directed-link witness is *sufficient* but demonstrably **not minimal**; a weaker in-fabric
primitive already breaks the limit in the evaluated regime.

---

## 3. Both the identifiability-bound framing and the spraying-breaks-localization problem statement are published prior art — and the repo already litigated and lost this argument

**(a) The framing "identifiability of link/directed-link failures is bounded by the routing/measurement
structure, and you design the monitoring scheme to restore/maximize it" is the core of Boolean
network tomography.** Bartolini, He, Arrigoni & Massini, *On Fundamental Bounds of Failure
Identifiability by Boolean Network Tomography*, IEEE/ACM ToN 2020 (arXiv:1903.10636): derives upper
bounds on the number of identifiable failures as a function of the routing scheme (arbitrary /
consistent / half-consistent / client-server), and its stated main contribution is *"the
optimization of identifying network failures through monitoring scheme design … how to design
topologies and related monitoring schemes to achieve the maximum identifiability"* (verified via the
paper's abstract/summary this session). That is the candidate's genre — identifiability lower bound
+ minimal-augmentation-to-restore-it — already owned, for failure localization, in a top networking
venue. The link-metric linear version (Ma, He, Leung, Towsley, Swami, *Identifiability of link
metrics from end-to-end path measurements*; and *optimal monitor placement for localizing node
failures*) owns the rank/monitor-placement variant.

**(b) Does classical tomography's fixed-single-path assumption make spraying a genuinely new
regime? No — spraying reduces to one of two already-classical cases:**
- **Spine-blind host vantage (the rank-7 model):** the measurement is a fixed convex combination
  (0.5, 0.5) of two paths → a *fractional* routing matrix. This is classical **linear/additive loss
  tomography** (Coates–Nowak; Chen–Cao–Bu), whose identifiability is the rank of the (here averaged)
  routing matrix. Standard linear algebra on a specific matrix, not a new regime.
- **Spine-aware in-fabric vantage (SprayCheck):** per-(source-leaf, spine) observation recovers the
  individual 2-hop path measurements → classical **Boolean/group-testing tomography** on the
  bipartite leaf-spine graph, with the per-spine gauge freedom in the dense case.

  The only genuinely spraying-specific modeling observation — that spraying forces *every* flow on a
  given (src,dst) pair to have identical fixed path composition, so you cannot manufacture
  independent measurements by using multiple flows on the same pair — is **the same argument this
  repo already recorded as REFUTED**: `NOVELTY-GATE.md` Gate 1b ("spraying collapses the pooled-test
  design space"), refuted by SprayCheck because *"spraying does not homogenize the pools; it
  decomposes one flow into k parallel per-spine tests,"* and it there cites Bartolini 2020 as owning
  the identifiability principle and NetBouncer (NSDI'19) as the constructive converse. The candidate
  is the linear-algebra restatement of the Gate-1b argument that already failed.

**(c) The problem statement "packet spraying breaks traditional localization primitives by creating
path ambiguity, and an in-network primitive resolves it" is published at SIGCOMM'26.** OmniPath Ping
(Yang et al., SIGCOMM 2026, doi:10.1145/3789240.3829105), abstract verified this session: *"Packet
spraying … causes traditional primitives to suffer from path ambiguity in failure localization …
OPP [is] the first diagnostic primitive designed for service tracing under packet spraying … an
in-network OmniPath cache that captures per-hop telemetry to resolve path ambiguity."* That is the
candidate's motivating limit (spraying → ambiguity) and its resolution shape (in-network per-hop
telemetry restores identifiability), in the target venue, one cycle ahead.

**(d) The "minimal in-fabric primitive" itself is conceded prior art.** Per `NOVELTY-GATE.md` gate 2
and `NOVELTY-GATE-4.md`: the per-directed-link witness is NetSeer's egress sequence number
(SIGCOMM'20), LinkGuardian's per-port seqNo (SIGCOMM'23), the RFC 6374 TX/RX counter pair, and
dShark's ingress-vs-egress record comparison (NSDI'19). Framing it as "the minimal identifiability
restorer" does not make a known primitive new; it re-describes it.

---

## What (thinly) survives — and why it does not rescue a top-venue attempt

The one statement that is true and not verbatim-published: **in the dense / multi-fault linear
regime, even spine-aware passive observation leaves a per-spine gauge freedom (rank 14 vs 16), which
SprayCheck's Boolean cross-leaf intersection does not resolve, and a per-directed-link counter
does.** This is a real, correct, two-line observation. It fails to support a contribution because:

1. It is outside the paper's evidence — multi-fault/common-mode is explicitly scoped OUT (PREREG
   v1.9; `CONTRIBUTION-FRAMING-2026-09-02.md` A4 names this as the largest unfilled gap). A limit in
   a regime you neither evaluate nor claim is a footnote, not a contribution.
2. It is standard bipartite-tomography gauge algebra; the general "identifiability = routing-matrix
   rank / monitoring-scheme design" is Bartolini 2020 and Ma et al.
3. SprayCheck §3.6 already gives the constructive multi-fault identifiability *condition* ("as long
   as there exist two flows which each involve a different victim leaf switch … our algorithm will
   be able to identify both failures"), so even the multi-fault boundary is partly occupied.

If the project still wants to write it down, the honest home is a **one-paragraph "why the residual
common-mode ambiguity motivates a per-directed-link counter" remark inside a Design section**,
attributed to Bartolini 2020 / classical tomography — exactly the demotion `NOVELTY-GATE.md`
prescribed for the earlier bound ("attributing it costs nothing; presenting it as a proposition
would be a credibility loss"). It is not an identifiability lower bound worth a paper.

---

## Bottom line

- **PASS?** No. The three pillars are each occupied: the identifiability-bound-from-routing-structure
  framing (Bartolini ToN'20; Ma et al.), the spraying-creates-localization-ambiguity problem
  statement (SprayCheck §3.6; OmniPath Ping SIGCOMM'26), and the minimal per-directed-link primitive
  (NetSeer/LinkGuardian/RFC 6374/dShark, already conceded).
- **The strong form is not merely unoriginal, it is false:** "a class of directed-link faults is
  unlocalizable by ANY amount of passive/end-to-end measurement" is contradicted by SprayCheck's own
  §3.6 passive resolution and by the project's own measured SprayCheck-Z tie at 1.0–1.5% loss. The
  rank-7 figure is an artifact of a spine-blind vantage; observe the spine passively (SprayCheck
  §4.2) and single-fault identifiability is restored with *less* than a per-directed-link witness,
  which also breaks the minimality claim.
- **This is the SAME argument the project already ran and lost** (`NOVELTY-GATE.md` Gate 1b), now in
  linear-algebra dress. Do not spend a top-venue cycle on it.

**Consequence for the writing decision:** this reframing does not raise the venue ceiling above the
one `CONTRIBUTION-FRAMING-2026-09-02.md` already set (ToN/IMC for the measurement; SIGCOMM/NSDI only
if the *healing / endogenous-observability* survivor in `NOVELTY-GATE-HEALING-2026-09-02.md` clears
its non-vacuity gate via `sim/gate/replay.py`). The identifiability angle is not an independent
path to a top venue.

## Sources retrieved this session (with provenance)

- **SprayCheck** — Krebs, Amir, Landau Feibish, Silberstein, arXiv:2605.03702; full HTML
  (arxiv.org/html/2605.03702) read this session; §3.6 uplink/downlink ambiguity + cross-leaf
  intersection + multi-fault condition, §4.2 per-(source-leaf, spine) counters, §6
  limitations (3-level, access links, lossy fabrics) quoted verbatim above.
- **OmniPath Ping** — Yang et al., ACM SIGCOMM 2026, doi:10.1145/3789240.3829105; abstract verified
  via DOI/Semantic Scholar this session ("path ambiguity … first diagnostic primitive … under
  packet spraying … in-network OmniPath cache … to resolve path ambiguity").
- **Bartolini, He, Arrigoni, Massini** — *On Fundamental Bounds of Failure Identifiability by Boolean
  Network Tomography*, IEEE/ACM ToN 2020, arXiv:1903.10636; abstract/summary verified this session
  (identifiability bounds as a function of routing scheme; monitoring-scheme design to maximize
  identifiability). PDF is image/binary-encoded — theorem statements read from the paper's
  abstract/summary and the repo's prior §1b citation, not the encoded body; flagged as such.
- **Ma, He, Leung, Towsley, Swami** — identifiability of link metrics from end-to-end path
  measurements / optimal monitor placement for localizing failures (classical linear/rank
  identifiability + monitor placement); cited from prior knowledge, consistent with the Bartolini
  line, not re-retrieved this session.
- **In-repo grounding (read this session):** `CAMPAIGN-PLAN.md` §0 (rank-7 model, verbatim);
  `NOVELTY-GATE.md` (Gate 1b refutation, Gate 2 mechanism occupancy, Bartolini/NetBouncer cites);
  `NOVELTY-GATE-4.md`, `NOVELTY-GATE-DSHARK.md` (mechanism prior art);
  `LOCALIZATION-COMPARISON-2026-09-02.md` and `BASELINE-COMPARISON-2026-09-02.md` (measured
  SprayCheck-Z tie at 1.0–1.5%, {uplink,downlink} 2-set at ≤0.5%); `CONTRIBUTION-FRAMING-2026-09-02.md`
  (venue ceiling); PREREG v1.9 single-fault scope.
