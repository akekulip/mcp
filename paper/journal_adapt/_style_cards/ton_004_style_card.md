## Paper Style Card: ton_004

**HARD RULE:** I will describe only structure and rhetorical patterns. I will not quote, paraphrase, or reproduce any content from this paper.

METADATA
- Paper ID: ton_004
- Authors: Nosyk, Y.; Korczyński, M.; Lone, Q.; Skwarek, M.; Jonglez, B.; Duda, A.
- Year: 2023 (IEEE/ACM Transactions on Networking; author-accepted text, journal running head present)
- Corpus role: primary_target_journal
- Conversion status: converted_checked
- Method type: empirical-measurement (Internet-wide active scanning campaign; no new protocol or system mechanism; the "mechanism" is a measurement technique)

A. ABSTRACT STYLE
- Opening move: definition of the practice being measured (term, then its accepted acronym), immediately followed by a contrast between the well-studied direction of that practice and the neglected direction that the paper measures.
- Structure (sequence of moves): (1) define the object of measurement; (2) contrast studied vs. under-studied variant and state why the under-studied one matters; (3) announce the named project and its two goals (measure, raise awareness); (4) claim a "first Internet-wide active measurement" of the under-studied variant; (5) one-sentence method summary (what is reached, what is inferred); (6) headline finding as proportions of two address families; (7) secondary finding on cross-family consistency; (8) closing consequence sentence: exposure count plus a list of named attack classes enabled.
- Tense pattern: present throughout ("we present", "we perform", "we reach", "we show"); no past tense.
- Contribution placement: middle of the abstract, after two sentences of framing; the "first" claim is explicit and sits at roughly the 40 % mark.
- Length: ~230 words.
- Register: formal, first-person plural, no mathematics, no hedging in the findings sentences; attack names dropped without explanation.

B. INTRODUCTION ARCHITECTURE
- Hook type: fundamental-property-of-the-Internet statement (a design property of packet headers) leading directly to the security consequence it enables.
- Opening move: property → resulting attacker capability → attack class that exploits it → history of the standardization response (cited RFC/BCP) → adoption of community terminology for the rest of the paper.
- Contribution placement: after five framing paragraphs (~35 % into the introduction). Preceded by an explicit gap sentence naming the two closest prior efforts (one long-running project, one concurrent work), then a sentence stating that the article extends the authors' own earlier conference paper.
- Contribution format: numbered list of six items, each formatted as an italic run-in headline (a full clause, verb-first) followed by a multi-sentence paragraph that explains the method step in enough detail to be understood standalone and closes with the resulting finding. Contribution paragraphs are long (5–10 sentences); collectively they occupy about a page.
- Literature positioning: both — the introduction names the two nearest efforts inline; a standalone Related Work section (III) follows a Background section (II).
- Roadmap: explicit, one paragraph, enumerating every section by number and topic, including the limitations/ethics subsection.
- Intro length: ~12 paragraphs (5 framing + 6 contribution paragraphs + 1 roadmap), spanning roughly 1.5 journal pages.

C. CONTRIBUTION EXPRESSION
- Voice: "we" throughout; "In this article, we present..." framing; occasional "This work shows...".
- Claim strength: strong. Multiple explicit "first" claims — a first Internet-wide active measurement of the target property in the abstract, a first Internet-wide scanning campaign in the introduction, and a "we are the first to propose a remote method that does not rely on ..." positioning sentence at the end of the Related Work subsection.
- Number of contributions: six, numbered.
- How a measurement-only contribution is framed: the verbs are *enumerate*, *propose a new measurement technique*, *perform Internet-wide scans*, *combine methods*, *compare*, *analyze*. Only the first contribution introduces a technique; the remaining five are analyses built on it (second address family, presence-vs-absence inference, cross-direction comparison via external data, cross-family comparison at host and AS level, geographic distribution). Each contribution paragraph ends with a "we show that ..." finding sentence. The "first" is scoped along explicit axes — remote (no vantage point inside tested networks), no reliance on pre-existing misconfigurations, the under-studied direction, and coverage of the entire routable space — and those same axes are the columns of the Related Work comparison table.

D. LITERATURE REVIEW
- Structure: standalone Section III "Related Work", placed after Background (II) and before Methodology (IV). Background (II) separately carries the threat model / attack scenarios with a three-panel scenario figure, so Related Work is purely about prior measurement methods.
- Organization: two thematic subsections — (A) prior methods for measuring the practice, (B) prior methods for identifying dual-stack hosts. Subsection A opens with a comparison table of prior methods along four binary/categorical axes (direction measured, presence vs. absence detectable, remote or not, dependence on misconfigurations) with the authors' own method as the final row.
- Critical engagement: high. Each prior method gets its mechanism, its coverage figure, and a stated limitation (representativeness of volunteer data, inability to confirm presence, reliance on misconfigurations). Concurrent work is named and acknowledged in its own paragraph. Each subsection closes with a positioning paragraph stating precisely what the present paper does differently and why the prior approach is insufficient for the question.

E. METHOD / MEASUREMENT DESIGN
- Entry point: one-sentence section overview naming the three things the methodology covers, then subsection A opens with a "core idea" sentence.
- Notation density: none — zero equations. Concrete example addresses drawn from documentation address ranges, monospace query-name examples with a described encoding scheme.
- Exposition style: procedural and figure-driven. Numbered steps in a setup figure; an enumerated four-case analysis of what can happen to a probe, ending with an explicit statement of which single case permits inference and which cases are indistinguishable. Subsections A–E map to scan components (first address family, second address family, unspoofed control scan, dual-stack candidate discovery, fingerprinting); fingerprinting is further sub-numbered by protocol with tool names footnoted as URLs.
- How methodology validity / ethics / limitations of the vantage are justified: validity is argued by the case analysis (inference is only made from the one unambiguous outcome) and by pairing every spoofed probe with an unspoofed control probe immediately afterward to control for temporal change. The vantage requirement (scanner must sit in a network that permits spoofing) is stated plainly. Ethics is not in the method section — it has its own subsection in Discussion (X-B), citing the Menlo Report and established scanning-practice references, describing probe-count caps per host, input randomization, spreading over days, an opt-out website, the number of exclusion requests honored, and a non-disclosure policy for per-network results. Tool availability is "upon request" plus a public project website.

F. RESULTS
- Primary vehicle: tables with counts and ratios (four results tables), CDF figures comparing three deployment categories, a choropleth world map, and a ranked-by-country table.
- Narrative style: bookkeeping first (hosts probed, requests received, deduplication rationale), then category definitions as a numbered list (consistent absence / partial absence / consistent presence), then a table walkthrough, then a bounding argument: a paragraph explaining why the headline count is a lower bound "for at least three reasons" (enumerated First/Second/Finally), and why the presence count is an upper bound. An extrapolation under a stated uniformity assumption is offered and labeled as a presumption.
- Mechanism emphasis: a dedicated section (VI) on factors influencing operator behavior, organized as numbered italic run-in leads per factor (address-space size, announcement stability, AS type, other). Each factor follows hypothesis → data source → test → verdict; one verdict is explicitly reported as contrary to the stated hypothesis. The "other" item reports a small operator outreach with only a handful of replies, used qualitatively.
- Robustness signaling: (a) a subsection comparing against an external vantage-point dataset obtained by contacting its maintainers, reporting the overlap size and the agreement percentage, and noting both methods' limitations; (b) fingerprint agreement across several protocols used to validate dual-stack pairings, with operator confirmation for a few pairs; (c) coverage ratios reported alongside every headline.
- Numbered questions / bold run-in leads: no numbered research questions. Italic numbered run-in leads (1)…4)) are used for enumerations and per-factor analyses; sections VII and VIII each open with a hypothesis sentence and then split into A. Network level / B. Autonomous-system level.
- How comparisons across arms/vantages are presented: as overlap sets — the intersection between the authors' data and each external dataset is sized, then agreement/disagreement is given as percentages of that intersection. Where an external method has an asymmetry (e.g., can detect absence but not presence), the text explicitly flags that the comparison must be read with caution and explains which cells of the comparison are unobservable.

G. DISCUSSION / LIMITATIONS
- Function: bound the claims and pre-empt reviewer objections. Section X "Discussion" has exactly two subsections: A. Limitations, B. Ethical Considerations.
- Scope of claims: consistently framed as lower bound on the vulnerable population and upper bound on the protected population, with transit filtering, absence of a resolver, and packet loss named as the three failure modes of the inference.
- Limitation acknowledgment: proactive — limitations appear in the method section (case analysis), in the results section (bounding paragraph), and again in the dedicated subsection. The paper states what a hypothetical ideal vantage would have revealed.
- Separate Discussion or Limitations section? Yes — a standalone Discussion section (X) with Limitations and Ethics subsections, placed after all results sections and before Conclusions (XI). Conclusions restate coverage figures, restate one finding per results section, and close with the project website and a notification-campaign outlook. Future work is folded into the conclusion, not separated.

H. LANGUAGE STYLE
- Voice: active, "we" in nearly every paragraph; passive is rare and used for external facts.
- Sentence length: medium (roughly 18–28 words); occasional long sentences with parenthetical clarifications and cross-references.
- Hedging level: moderate — "tend to", "suggest", "one possible explanation", "we hypothesize", "may"; findings sentences themselves are unhedged.
- Transition style: sentence-initial connectives ("However,", "On the contrary,", "Interestingly,", "Overall,", "Thus,", "Therefore,", "Note that"); heavy use of forward and backward section cross-references ("as explained in Section IV-D").
- Mathematical density: zero — no equations, no symbols; all quantities are counts and percentages in prose or tables.
- Paragraph length: medium, 4–8 sentences; contribution paragraphs and case-analysis items are longer.
- Other: uses a gendered pronoun for the attacker and "his/her" for the operator; monospace for query names and addresses; footnotes for tool URLs.

I. IEEE/ToN FORMAT MARKERS
- Index Terms: present (six terms).
- Section numbering: Roman numerals I–XI; subsections A–E; sub-subsections as italic numbered run-in leads 1)–6).
- Appendix usage: none.
- Related-work position: Section III, after Background (II), before Methodology (IV).
- Figure caption style: descriptive, multi-sentence, often interpretive (the caption states the trend the figure shows); tables captioned above with "TABLE N:"; figure captions below with "Fig. N:".
- Equations numbered: no equations at all.
- Subsection depth: three levels (Section / A. / 1)).
- Other: author biographies with photos at the end; acknowledgements naming reviewers, editor, and funding contracts; footnotes for URLs; a project website URL appears in the body.

J. WHAT THIS PAPER DOES NOT DO
1. No formal model, no equations, no statistical significance testing or confidence intervals — all results are raw counts, ratios, and CDFs.
2. No longitudinal analysis — a single measurement snapshot plus one month of external data; no temporal trend section.
3. No separate "Threat Model" section — the threat scenarios live in the Background section with a scenario figure.
4. No public artifact release — scanner is "upon request", raw per-network results are deliberately withheld; no reproducibility appendix.
5. No numbered research questions and no separate Future Work section (outlook is inside Conclusions).

K. DISTINCTIVE PATTERNS
1. **Comparison table as the positioning device.** Related Work opens with a table of prior methods along the exact axes on which the paper claims novelty, with the authors' method as the last row; the closing "we are the first to ..." sentence simply reads off that table. This is how a measurement paper without a new mechanism establishes novelty.
2. **Contributions as six method-plus-finding mini-paragraphs.** Each numbered contribution has an italic verb-first headline, explains the method step in full, and ends with the finding — the introduction effectively contains a compressed version of the whole paper.
3. **Case-analysis inference logic reused as limitation framing.** The method enumerates every possible outcome of a probe and states which one permits inference; the results then use the indistinguishable cases to argue lower/upper bounds; the Limitations subsection repeats the same three failure modes. One argument, stated three times at three levels.
4. **Hypothesis-per-factor with an honest negative.** The characteristics section tests each candidate explanatory factor as a stated hypothesis and reports one as unsupported rather than omitting it.
5. **External-vantage cross-validation reported as overlap size plus agreement percentage**, with explicit caveats about which comparison cells are structurally unobservable for each method.
