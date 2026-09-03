## Paper Style Card: ton_005

**HARD RULE:** I will describe only structure and rhetorical patterns. I will not quote, paraphrase, or reproduce any content from this paper.

METADATA
- Paper ID: ton_005
- Authors: Alasmar, M.; Clegg, R.; Zakhleniuk, N.; Parisis, G.
- Year: 2021 (IEEE/ACM Transactions on Networking; the corpus text is the authors' "complete version" preprint with a footnote stating acceptance — conference-style author block with emails, no ToN running head)
- Corpus role: primary_target_journal
- Conversion status: converted_checked
- Method type: empirical-measurement (longitudinal statistical characterization of public traffic traces; no new mechanism; two application sections are demonstrations, not systems)

A. ABSTRACT STYLE
- Opening move: states that the general problem is well known and often studied, then narrows to a sub-aspect described as equally important but less studied.
- Structure (sequence of moves): (1) problem is well known; (2) attention has gone to two other aspects; (3) the studied aspect is equally important but less studied; (4) dataset breadth (many traces, several network types) plus "state-of-the-art statistical techniques"; (5) main finding: proposed distribution fits better than the one commonly claimed in the literature; (6) an alternative heavy-tailed candidate also tested and ranked; (7) anomalous traces examined and attributed to an operational cause; (8) stationarity demonstrated at named window lengths, giving confidence for modelling use; (9) utility demonstrated in two named application contexts; (10) the proposed model is the better predictor in both.
- Tense pattern: present throughout ("We study", "We show", "We examine", "We demonstrate").
- Contribution placement: distributed — a chain of "We show / We also / We examine / We demonstrate" sentences from the fourth sentence to the end; no single contribution sentence.
- Length: ~220 words.
- Register: plain and slightly conversational (colloquial quantifier phrases), minimal jargon, no symbols; British spelling.

B. INTRODUCTION ARCHITECTURE
- Hook type: importance-plus-long-history statement about the field, then "early works discovered X", then a forward pointer to the Related Work section for how those works were later refined.
- Opening move: broad topic importance → what early work found → "by comparison, this aspect has seen less interest" → "this is surprising because" → concrete practical stakes (planning, over-capacity assessment, SLAs, pricing scheme).
- Contribution placement: paragraph 4 of ~8 ("In this paper, we use a well-established statistical methodology [ref] to show ..."), followed by a fresh question (does the fit persist across time windows — i.e. stationarity) that motivates the second half of the paper.
- Contribution format: prose only — no numbered or bulleted list. Contributions are spread over paragraphs 4–7 as consecutive "We show / We further show" sentences.
- Literature positioning: both — inline in the introduction (prior claims of the competing distribution, why their tests are inadequate for tail behavior, prior practice of assuming stationarity without testing it) and a standalone Related Work section (VII) placed just before the Conclusion.
- Roadmap: explicit, one paragraph, section by section, each with a one-clause summary of its finding (the roadmap pre-announces results, not just topics).
- Intro length: ~8 paragraphs, about one column and a half. Two footnotes define the two candidate distributions formally so the body stays prose.

C. CONTRIBUTION EXPRESSION
- Voice: "we show", "we demonstrate", "we investigate", "we examine", "we further show" — consistently first-person plural.
- Claim strength: strong on the empirical finding (phrased as holding for the vast majority of traces across the whole timescale range); superlative claim hedged as "the most comprehensive investigation the authors are aware of" rather than "the first"; deliberately weak on the applications (repeatedly described as motivational examples, not deployable systems).
- Number of contributions: five implicit — (i) best-fit distribution across diverse traces and timescales, (ii) ranking of a second heavy-tailed alternative, (iii) explanation of anomalous traces, (iv) stationarity validation, (v) two application demonstrations. Also an explicit statement that the work extends the authors' own prior conference paper, with the methodological difference (which distribution is used as the reference) spelled out.
- How a measurement-only contribution is framed: as (a) diversity of data — the dataset section opens by calling spatial/temporal diversity of the traces "a key contribution"; (b) rigor of method — "well-established", "state-of-the-art", "principled" framework vs. "straightforward" prior tests; (c) overturning a literature assumption — the title itself is a claim-versus-counterclaim; (d) downstream utility — two application sections that translate the finding into engineering decisions. No "first" claim; the novelty is comprehensiveness plus correction of a prevailing assumption.

D. LITERATURE REVIEW
- Structure: standalone Section VII "Related Work", placed after all results and application sections, immediately before Conclusion (VIII). The introduction also carries a compact critical literature paragraph.
- Organization: thematic, in five movements — (1) prior claims for the competing distribution and the tests they used; (2) heavy-tail and scaling literature; (3) stationarity: who assumed it, who tested it, common block-length practice; (4) link dimensioning approaches and their distributional assumption; (5) billing-scheme literature and its assumptions.
- Critical engagement: moderate-to-high. Prior tests characterized as simple goodness-of-fit; prior works noted to have skipped stationarity tests or discarded inconvenient trace segments; the first movement closes with an explicit contrast paragraph (modern principled methodology, spatially and temporally diverse traces, several hypotheses tested rather than one). Movements 4 and 5 identify the shared distributional assumption in prior engineering methods, which is exactly what the paper's application sections attack.

E. METHOD / MEASUREMENT DESIGN
- Entry point: a dedicated dataset section (II) precedes any analysis. It opens by claiming dataset diversity as a contribution, states the total span and count, then describes each of five public trace archives under a bold run-in lead with a fixed template: capture location and vantage, sampling regime, anonymization, number of traces used, capture years, average packet count and rate, link capacity. Code availability is footnoted with a repository URL. Section III then opens by naming the statistical framework adopted (cited), explaining its three steps in numbered prose, and stating which distribution is the reference and which are alternatives — and why this differs from the authors' earlier paper.
- Notation density: light-to-moderate. Eight numbered equations across the paper (a test-call expression, a correlation coefficient, its variation across timescales, a capacity-probability inequality, a Gaussian-assumption dimensioning formula, a tail bound, an inverse-CDF capacity, an empirical violation ratio). Symbols introduced in prose immediately after each equation. Distributions defined in footnotes rather than body.
- Exposition style: methodology is interleaved with results section by section (fitting, stationarity, provisioning, billing) rather than in one Method section. Each analysis section states the test, the decision rule (what a p-value above/below threshold means), then shows results. A hypothesis table (null vs. alternative for each of three stationarity tests, and what each p-value outcome means) makes decision semantics unambiguous.
- How methodology validity / ethics / limitations of the vantage are justified: validity by adoption of an established, cited framework and its reference implementation; by footnotes flagging non-comparability of certain paired test outputs and possible failure at very fine or very coarse granularity; by multiple independent fit criteria (likelihood ratio, correlation coefficient, cross-timescale variation, NRMSE). Ethics not discussed (public anonymized archives stated as such). Vantage limitation handled through diversity (several archives, countries, link types, years) rather than argued.

F. RESULTS
- Primary vehicle: multi-panel figure grids with one panel per trace archive (a)–(e), replicated row-wise across timescales or across tests; grayscale p-value heat maps (trace id × timescale) with a three-color legend explained in the caption; scatter plots of actual vs. predicted with a reference diagonal; bar panels per target criterion; a small NRMSE table.
- Narrative style: figure-by-figure walkthrough with assertive evaluative openers (clear / obvious / strong result / encouraging), exceptions counted per archive as "x out of y", and an overall percentage. Repeated "due to lack of space we omit ..." for secondary plots (Q-Q, other pairs), with a one-sentence summary of what the omitted plots showed.
- Mechanism emphasis: anomalous traces get their own subsection with side-by-side density plots (anomalous vs. well-fitted), a plausible operational cause offered as "a likely explanation", and an explicit admission of no definitive explanation for one case; a bimodal model is deferred to future work.
- Robustness signaling: layered — several fit criteria; four to seven aggregation timescales; the same tests re-run on hour-long subtraces of a day-long trace and on sliding windows of several lengths; three different stationarity tests plus a differencing follow-up when two tests disagree; a caveat that window alignment could change some results.
- Numbered questions / bold run-in leads: no numbered research questions. Bold run-in leads used in the dataset section (one per archive), for one methodological aside (de-trending), and for the limitations paragraph in the conclusion. Sequencing via "Firstly / Secondly / Next".
- How comparisons across arms are presented: three candidate models compared on one empirical criterion (achieved violation ratio vs. target) — first as a single worked trace with horizontal capacity lines from each model, then aggregated per archive × timescale × target in a 3×4 panel grid, with error-bar semantics defined in the caption; then a day-long trace split into hourly and quarter-hour pieces; finally a scatter of actual vs. predicted percentile per archive plus an NRMSE table with one row per model. The competing model's shortfall is stated in engineering terms (fails to meet the target), not just statistically.

G. DISCUSSION / LIMITATIONS
- Function: scope the applied sections and pre-empt over-interpretation. There is no separate Discussion section; disclaimers are placed inline at the transition into the application sections and again at the end of each application section (not fully worked systems; months of data would be needed).
- Scope of claims: restricted to normally functioning links, the studied window lengths, and the studied timescale range; day-scale non-stationarity is acknowledged and handled by proposing a piecewise-per-period modelling procedure.
- Limitation acknowledgment: proactive but compact — a single bold run-in paragraph ("Limitations and future work") inside the Conclusion, plus scattered footnote caveats.
- Separate Discussion or Limitations section? No. Conclusion (VIII) restates dataset breadth, the hypotheses compared, the finding, the stationarity result, the two applications, then the limitations/future-work paragraph.

H. LANGUAGE STYLE
- Voice: active, "we" dominant; occasional passive for prior work and for test procedures.
- Sentence length: medium, with a fair number of long sentences carrying parenthetical definitions.
- Hedging level: mixed — assertive evaluatives on the fit results, explicit hedges on generalization and on the applications; "could", "might", "a likely explanation", "one could speculate".
- Transition style: "Next", "Firstly/Secondly", "In contrast", "Overall", "It is worth mentioning/pointing out", "Here"; frequent forward references to later sections and to the authors' prior paper.
- Mathematical density: low-moderate — eight numbered equations, definitions in footnotes, symbol-light prose.
- Paragraph length: medium-to-long (5–9 sentences); dataset descriptions are dense single paragraphs.
- Other: British spelling throughout; colloquial phrasing tolerated ("a lot of attention", "well-known"); parenthetical "(i.e. ...)" clarifications common.

I. IEEE/ToN FORMAT MARKERS
- Index Terms: present (four terms).
- Section numbering: Roman numerals I–VIII; subsections A–D; no third level.
- Appendix usage: none.
- Related-work position: Section VII, after all results and applications, immediately before Conclusion.
- Figure caption style: long and interpretive — captions define the visual encoding (what circled points, black/grey/white areas, or a reference line mean), name the timescales shown, and often restate the decision rule; panel labels (a)–(t) referenced in text. Tables captioned above with "TABLE N:".
- Equations numbered: yes, (1)–(8), right-aligned numbers.
- Subsection depth: two levels (Section / A.).
- Other: heavy footnote use (13 footnotes: distribution definitions, code URL, omitted-figure notes, caveats, acceptance notice); no author biographies or acknowledgements in this preprint text; conference-style author block.

J. WHAT THIS PAPER DOES NOT DO
1. No numbered contribution list and no "first" claim — novelty is comprehensiveness and correction of an assumption.
2. No standalone Methodology section — the dataset section is separate, but each test's procedure is introduced in the section that reports it.
3. No separate Discussion, Limitations, Threat-model, or Ethics section — limitations are a bold run-in paragraph inside the Conclusion.
4. No Background section — technical definitions are footnoted rather than given a section.
5. No confidence intervals or effect sizes beyond p-value thresholds and NRMSE; no theorem/proof content despite the numbered equations.

K. DISTINCTIVE PATTERNS
1. **Title as claim-versus-counterclaim, plus a scope tag.** The title asserts the finding, names the assumption it overturns, and carries the longitudinal span and the applied implications — the abstract and introduction then re-enact that same three-part structure (overturn, span, implications).
2. **Dataset diversity framed as a contribution in its own right.** The dataset section's first sentence claims spatial and temporal diversity as a key contribution, and each archive is described under a bold run-in lead with an identical field template — a reusable pattern for a characterization paper whose value rests on data breadth.
3. **Anomalies as a first-class subsection with a mechanism story.** Traces that fail every model are not dropped; they get their own subsection, paired density plots, a plausible operational cause, a stationarity cross-check that confirms they are the same traces, and a deferred modelling fix.
4. **Applications with built-in disclaimers.** Two engineering demonstrations are bracketed by repeated statements that they are motivational examples rather than deployable systems, and each is run at three granularities (single worked trace → all traces per archive → day-long trace split into periods) with a proposed operator procedure.
5. **Late, critical Related Work.** Placing Related Work after the results lets it be written as a point-by-point critique of prior statistical practice (test choice, stationarity assumed not tested, discarded segments), each point already answered by an earlier section.
