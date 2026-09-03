# Dynamic Writing Skill: IEEE/ACM Transactions on Networking — MCP measurement paper
Generated: 2026-09-03
Primary corpus papers analyzed: 5 (verified ToN; 3 more converted, cards pending)
Secondary corpus papers analyzed: 2 (NSDI'19 dShark, NetBouncer)
User/lab exemplars analyzed: 0 (the paper-voice skill's five-paper corpus stands in as the lab voice)
Static base skill: base_rules/cs_engineering.md
Companion files: `../journal_adapt/_style_cards/journal_style_card.md` (profile + conflict table),
`../journal_adapt/TON_GUIDELINES.md` (fetched format rules), `NUMBERS.md` (every number with provenance),
`references.bib` (24 verified entries), `../PAPER-SPINE-2026-09-03.md` (section → evidence map).

## PRIORITY RULES (Non-Negotiable)

### Priority 1 — HARD PRESERVE
Never modify: `\cite{}` keys (must exist in references.bib); every number, CI, seed count and unit in
NUMBERS.md (transcribe, never round differently in two places); the loss identity and the register/header
names as they appear in `LEDGER-WIRE-REDUCTION-2026-09-02.md`; the exact baseline names SprayCheck-Z and
FlowPulse-θ and the paper sections they replay (§3.6, §5.3); the scope wording "stationary, independent
per-directed-link faults"; figure/table labels; the frozen-localizer statement. No new facts, results, or
citations beyond the committed artifacts.

### Priority 2 — TARGET JOURNAL PATTERNS (ToN corpus)
1. Section order: I Introduction → II Background (fabric, grayhole, fault model, objectives O1–O4, scope)
   → III The receiver ledger (design, brief; primitive conceded) → IV Methodology (replay harness, baselines,
   silicon testbed) → V Detection → VI Localization → VII On silicon → VIII Robustness → IX Cost →
   X Discussion and Limitations → XI Related Work → XII Conclusion. Related Work second-to-last (6/7).
2. Introduction: importance hook with citations → 1–2 background paragraphs → the named limitation of the
   two closest efforts (SprayCheck, FlowPulse) → "In this paper, we ..." → contributions as 4–5 bullets,
   bold verb-first headline + 2–4 sentences each closing with the finding and its number → one results-
   preview sentence → roadmap paragraph. 1–1.5 pages.
3. Exactly one first-ness claim, scoped along the axes that are the columns of the Related Work comparison
   table; the same paragraph concedes the witness primitive to NetSeer/LinkGuardian/LossRadar/UEC.
4. Measurement-contribution verbs: measure, replay, quantify, compare, characterize, bound. Never "propose
   a novel mechanism".
5. Every result paragraph: pointer to figure/table → observation → "The reason is that ..." mechanism →
   scoped takeaway. Baseline wins (SprayCheck ties at 1.0–1.5 %, SprayCheck better under common-mode) are
   stated plainly, then contextualized.
6. Evaluation setup at ToN depth: switch model (Tofino 1, program name, SDE 9.13.2), hosts and NICs, link
   speed, simulator/harness name, seeds, epoch, budget, thresholds, baseline parameters — in a fixed
   template with bold run-in leads.
7. Objectives named once (O1 detection cost-scaling, O2 localization, O3 silicon fidelity, O4 robustness
   boundary) and reused as labels; Evaluation opens with a short bulleted map of O1–O4 to sections.
8. Failure cases get their own subsection with a mechanism story (common-mode: the leave-one-out floor
   cannot separate a fleet-wide shift from 64 faults).
9. Related Work: the two comparison tables (own row last) + four themed paragraphs (in-fabric witnesses;
   passive sprayed-fabric detectors; active probing/tomography; repair systems), each closed by a
   positioning contrast on objective or cost, never superiority.
10. Dedicated "Discussion and Limitations" section before Related Work; Conclusion restates one finding
    per results section + one limitations/future-work sentence.
11. Format: Index Terms (4–5); Roman sections; roadmap; tables captioned above; one-line result captions,
    multi-sentence captions for the schematic, the scaling figure and every table; author biography +
    acknowledgement blocks at the end; 13–14 pages.
12. Abstract: 200–240 words, one paragraph, no abbreviations (write "the receiver ledger", "false
    positives", "confidence interval" — no MCP/FP/CI), present tense, contribution at sentence 3–4,
    headline numbers in the closing sentences, no selling sentence.

### Priority 3 — SECONDARY CORPUS / paper-voice FOLLOW
- From NetBouncer: a "targets and limitations" scope paragraph at the end of Background, before any
  mechanism, with forward pointers to the sections that show the missed cases; every "why not X?" design
  rationale has a matching evaluation cell; the theory-to-practice gap is narrated, not hidden.
- From dShark: the drop-localizer evaluation restricts comparison to the subset where the naive method is
  applicable and says so; capture-noise robustness is shown by replaying under increased noise.
- From paper-voice (mandatory, enforced by voice_check.py): "Consequently," glue; fronted "Because ...,"
  clauses; purpose-fronted design sentences "To <goal>, we <verb> ..."; ~13 % short anchor sentences,
  ~25 % long chained sentences; "we" in ~29 % of sentences; hedges ~14/1000 via "can"; boosters ~1/1000;
  citations ~7/1000; assumptions stated then defended ("We argue that this is a reasonable assumption,
  as ..."); superiority framed by objective and cost after granting merit; fixed term set repeated verbatim
  (the receiver ledger, the witness, the directed link, the passive detectors); "To the best of our
  knowledge, this is the first ..." exactly once.

### Priority 4 — STATIC BASE SKILL DEFAULT (cs_engineering)
Define every term at first use; describe components in execution order; state hardware for every
latency/throughput number; report negative results and say why; conclusion = problem + solution in two
sentences, key number in one, honest limitation, one or two specific future directions.

### Priority 5 — ALWAYS REMOVE
"This paper explores/aims to", "It is worth noting that", "It should be noted that", empty "Furthermore/
Moreover/Additionally", "contributes to the growing literature", "Future research should explore", "Taken
together", "Our results highlight the importance of", "novel", "robust" (as praise), "comprehensive",
"seamless", "state-of-the-art" (as praise), "leverage", "utilize", "notably", "clearly", "importantly",
"remarkably", "significant(ly)" without an attached number, "prove/guarantee/optimal" for empirical results,
"paradigm", "crucial", "pivotal", "delve", "landscape", "underscore", "showcase", em dashes, "not only ...
but also", "As can be seen in Figure X".

## SECTION-SPECIFIC GUIDANCE

### Abstract
Problem (sprayed AI fabrics; grayholes at 1e-3–1e-4; spraying decomposes evidence) → limitation of the
passive state of the art (cost grows with 1/p; directed-link aliasing) → what we measured (a silicon-
measured head-to-head of an in-fabric per-directed-link witness against the two most recent passive
detectors) → venue (Tofino 1 silicon + a faithful replay harness, 50 seeds) → headline numbers verbatim
(flat ~22 M packets vs 24 M→114 M; 100 %/0 FP at 1e-4 where passive detection collapses; exact directed link
vs the two-link set; 2 bytes per packet, ~0.14 %) → one scope sentence (independent stationary faults;
under common-mode load a relative passive test is better). Do not: use abbreviations; sell; claim novelty
of the primitive.

### Introduction
Required sequence (P2 §2). Hook: packet spraying in AI training fabrics and why a silent partial-loss
link is hard to find (with citations to spraying, gray failure, UEC). Gap: SprayCheck and FlowPulse are
passive and pay nothing on the wire, but their evidence scales as ~1/p and a single vantage aliases the
uplink/downlink pair. Insight paragraph: holding each directed link's own transmit count is an
information-structure property, so what it buys and costs can be measured, not argued. Contributions
(bold verb-first): Measures the detection cost-scaling separation. / Measures directed-link localization
under spraying. / Measures the ledger on silicon. / Bounds the claim with a correlated-fault gate. /
Quantifies the wire and pipeline cost. Then the first-ness sentence with the primitive conceded. Roadmap.
Do not: put the mechanism in the intro; list numbers without a comparison set; exceed 1.5 pages.

### Background (II)
Define-before-use: leaf–spine, per-packet spray with width k, directed link, grayhole vs blackhole,
epoch. Fault model: assumptions each defended (stationary loss rate; independent per-directed-link faults;
one or several simultaneous). Objectives O1–O4 named. Scope paragraph: common-mode and restoration are
out of scope, with forward pointers to §X. Do not: bury the scope; use a theorem.

### The receiver ledger (III)
One overview figure (Fig. 2) walked in prose with the two-byte witness, link reconstruction at ingress,
the two registers, the loss identity as Eq. (1), and the fleet-floor ratio + e-BH decision as Eq. (2)–(3).
First paragraph states plainly that the per-directed-link sequence witness is NetSeer's and
LinkGuardian's primitive at reduced width and that this paper measures it. Run-in bold leads: Witness
stamp. / Link reconstruction. / Ledger registers. / Decision. Do not: claim design novelty; exceed 1 page.

### Methodology (IV)
Bold-lead template. Replay harness (shared spray/survival stream; each detector sees only what its switch
would; 50 seeds; Wilson CIs; FP reported next to action rate). Baselines: SprayCheck-Z (§3.6 intersection,
per-(leaf,spine) counts) and FlowPulse-θ (§5.3 per-sender rule) with the parameters used and the source
sections; fairness disclosures. Silicon testbed: Tofino 1, program, SDE, hosts/NICs, injectors, how
injected loss is verified in the data. Metrics defined precisely (action rate, packets-to-detect, exact
localization, set size, FP). Do not: omit a version number; describe the harness after the results.

### Detection (V), Localization (VI), On silicon (VII), Robustness (VIII), Cost (IX)
Each opens with the objective label and a one-sentence expectation, then the paper-voice experiment
template per result. V leads with Fig. 1 and the cost-not-capability framing (budget ceiling, hollow
markers). VI reports the honest tie at 1.0–1.5 % before the separation. VII reports every cell with
injected vs recovered and FP. VIII has three subsections (independent multiplicity; common-mode shock;
culprit within a shock) and says where SprayCheck is better. IX gives bytes, %, stages, SRAM/TCAM from the
compile gate and states the trade against 0-byte passive detectors. Do not: hide a baseline win; add
significance-test prose; use "prove".

### Discussion and Limitations (X)
Bold run-in paragraphs: Common-mode load (Q4 deferred, what a fix needs). / Restoration on a spray-
starved link (cited, not claimed). / Localization advantage is information-structure, not algorithmic. /
Wire cost is a real trade. / The soak anomaly on unmeasured sublinks (bounded caveat). Do not: introduce
new results; broaden claims.

### Related Work (XI)
Two comparison tables (own row last) + four themed paragraphs (families A–D), each ending in an
objective/cost contrast; the first-ness sentence read off the table. Concurrent work (OmniPath Ping)
acknowledged in its own sentence. Do not: criticize; claim dominance; cite anything not in references.bib.

### Conclusion (XII)
Mechanism-free recap of what was measured, the same headline numbers as the abstract, one scope sentence,
exactly one future-work sentence (common-mode gate). ≤ 0.3 page.

## CAUTIONS AND CONFLICTS
- Wilson CIs and McNemar tests exist in the artifacts; the corpus never reports them in prose. Keep them
  in tables/captions; mention "50 seeds, 95 % Wilson intervals" once in Methodology.
- ToN papers accept "Moreover/Thus/Overall"; paper-voice bans them — voice wins.
- ton_002/ton_003 use promotional adjectives; do not copy.
- The paper-voice threat-model scaffold is security-flavoured; here it is a fault model. Keep the
  assumption-defence grammar, drop attacker taxonomy.
- Author biographies/acknowledgements: leave placeholders; Philip fills.

## LANGUAGE REGISTER
- Voice: active, "we" agentive, alternating with "the ledger" as agent; passive only for setup facts.
- Sentence length: mean ~23 words; mix short anchors (<12), medium, and one chained long sentence per
  paragraph; vary openers (prepositional, "The ...", "Because ...", "To ...", "We ...").
- Hedging: "can" for capability; "may/likely" for interpretation; findings with a number unhedged; never
  boosters.
- Transitions: "Consequently,", "However,", "For example,", "First, ... Second, ... Last,"; "We note that"
  at most three times in the paper; explicit "Section~IV-B" cross-references.
- Mathematical prose: define by description, then name; each equation followed by a sentence reading it
  in words; ≤ 6 numbered equations.
