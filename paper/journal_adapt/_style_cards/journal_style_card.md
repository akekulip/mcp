## Style Profile: IEEE/ACM Transactions on Networking (ToN)
Generated from 7 papers: 5 primary (ton_001 RIFO 2025, ton_002 RouteNet-Gauss 2026, ton_003 FERN 2023,
ton_004 Closed Resolver 2023, ton_005 Log-normal traffic 2021 — all verified ToN via journal-ref/DOI,
author-accepted text) + 2 secondary topic-similar NSDI'19 papers (nsdi_001 dShark, nsdi_002 NetBouncer).
ton_006–008 (three datacenter-flavoured ToN papers) were downloaded and converted but their cards were
lost to API failures; fold them in if they land. Mechanical metrics: `format_metrics.md`.
Generated 2026-09-03.

### Editorial Identity
- Research question type: a concrete networking mechanism or a concrete measurement question, stated with
  the environment and the failure of the standard approach up front. Two of five primary papers are pure
  measurement/characterization papers with no new mechanism (ton_004, ton_005) — ToN publishes these, and
  they establish novelty through comprehensiveness, rigor of method, correction of an assumption, and
  downstream utility, not through a new primitive.
- Methods valued: hardware prototypes described down to software versions (ton_001, ton_002); large or
  diverse datasets whose diversity is itself claimed as a contribution (ton_005); explicit fairness toward
  baselines (nsdi_002 discloses giving baselines an advantage); mechanism explanations attached to every
  result; parameter-sensitivity sweeps; an oracle/upper-bound experiment to bound what is achievable
  (ton_003, nsdi_002).
- Implied reader: academic specialist in networking who will check setup reproducibility and will look for
  the sentence that explains *why* each number came out as it did. Not policy-facing.

### Introduction Conventions
| Observed pattern | Corpus role | Papers |
|---|---|---|
| Hook = importance/trend statement with a citation cluster, 1–2 background paragraphs before the gap | primary | ton_001, ton_002, ton_003, ton_005 |
| Hook = fundamental property → consequence → attack/failure class | primary / secondary | ton_004, nsdi_001, nsdi_002 |
| Gap stated as a concrete limitation of the two closest prior efforts, named inline | primary | ton_002, ton_004, ton_005 |
| Requirements stated up front (numbered), prior work rejected per requirement | secondary | nsdi_002 |
| Proposal sentence arrives at paragraph 4–6 ("In this paper, we ...") | primary | ton_001, ton_002, ton_003, ton_004, ton_005 |
| Contributions as a list (bullets or numbered) | primary | ton_001 (5 bullets), ton_003 (5 bullets), ton_004 (6 numbered, italic verb-first run-in headlines + multi-sentence paragraphs) |
| Contributions in prose only | primary | ton_002, ton_005 |
| Explicit roadmap paragraph (section by section) at the end of the introduction | primary | ton_001, ton_002, ton_004, ton_005 (4/5) |
| Headline numbers appear in the introduction prose | primary | ton_001, ton_002, ton_003 |
| Statement that the article extends the authors' own conference paper, with the delta spelled out | primary | ton_004, ton_005 |
| Intro length 6–12 paragraphs, about 1–1.5 journal pages | primary | all |

Observed intro structure (most common): importance/trend hook with citations → 1–2 paragraphs of background →
concrete limitation of the closest prior work (named) → "In this paper, we ..." proposal/insight paragraph →
contribution list (verb-first) or contribution prose → roadmap paragraph.
What intros here do NOT do: open with a generic "networks are important" sentence and nothing concrete
(ton_001's textbook opener is immediately backed by metrics and citations); claim novelty without naming the
axis; put mechanism detail in the introduction; list more than 6 contributions; omit the roadmap (only ton_003
omits it).

### Contribution Expression
| Observed pattern | Corpus role | Papers |
|---|---|---|
| "we show / we present / we design / we demonstrate" first-person plural | primary | all |
| System name as grammatical subject alternating with "we" | primary / secondary | ton_001, ton_002, ton_003, nsdi_001, nsdi_002 |
| Strong claims always paired with a number and a comparison set | primary | ton_001, ton_002, ton_003 |
| "First" scoped along explicit axes, and those axes reappear as the columns of a related-work comparison table | primary | ton_004 |
| "To the best of our knowledge" hedge used once, in Related Work or to justify baseline choice | secondary | nsdi_001, nsdi_002 |
| No "first" claim; novelty = comprehensiveness + correction of a prevailing assumption | primary | ton_005 |
| Measurement-only contribution framed with verbs enumerate / propose a technique / perform / compare / analyze, each contribution ending in a "we show that ..." finding | primary | ton_004 |
Preferred format: 3–6 contributions, verb-first, each 2–4 sentences, closing with the finding; exactly one
scoped first-ness claim; numbers in the contributions or in a results-preview sentence.

### Literature Review
| Observed pattern | Corpus role | Papers |
|---|---|---|
| Standalone Related Work section placed late (after Evaluation/Discussion, before Conclusion) | primary / secondary | ton_001, ton_002, ton_003, ton_005, nsdi_001, nsdi_002 (6/7) |
| Related Work early (after Background, before Method) | primary | ton_004 |
| Additional short Background/Motivation section directly after the introduction | primary | ton_001, ton_002, ton_003, ton_004 |
| Thematic organisation with bold run-in leads per family | primary / secondary | ton_003, nsdi_001, nsdi_002 |
| Comparison table of prior methods on the novelty axes, own method as the last row | primary | ton_004 |
| Each family closed by a one-sentence positioning contrast (scope / objective / cost), not superiority | primary / secondary | ton_002, ton_003, ton_005, nsdi_001, nsdi_002 |
| Concurrent work named and acknowledged in its own paragraph | primary | ton_004 |
| Trace-collection / complementary systems explicitly labelled complementary | secondary | nsdi_001, nsdi_002 |

### Method / Model Norms
| Observed pattern | Corpus role | Papers |
|---|---|---|
| Overview figure at the top of the design section, walked in prose | primary / secondary | ton_001, ton_002, ton_003, nsdi_002 |
| Run-in bold paragraph leads carry structure inside subsections | primary / secondary | ton_001, ton_003, ton_005, nsdi_001, nsdi_002 |
| Every design choice justified, often by explicit alternative rejection ("why not X?") later validated by an ablation | primary / secondary | ton_001, ton_002, nsdi_002 |
| Hardware constraints presented as named challenges with one paragraph each on the workaround | primary | ton_001 |
| Fault/failure model assembled from: intro definition by contrast → scope paragraph ("targets and limitations") → formal assumptions with citations and a forward pointer to the discussion | secondary | nsdi_002 |
| Numbered equations few (0–8) unless the paper is theory-heavy (ton_003: 20) | primary | ton_001, ton_002, ton_004, ton_005 |
| Dataset/testbed documented as a fixed field template (bold lead per archive or bulleted hardware spec) | primary | ton_002, ton_005 |
| Statistical methodology adopted from a cited established framework, decision rule stated (what a p-value above/below threshold means) | primary | ton_005 |

### Results and Discussion Norms
| Observed pattern | Corpus role | Papers |
|---|---|---|
| Setup description very deep: switch/NIC/CPU models, SDE/DPDK/OS versions, simulator name, baselines, workloads, default parameters | primary | ton_001, ton_002, ton_003 |
| Evaluation opens with bulleted questions mapped 1:1 to subsections (or a one-sentence demonstration checklist with section pointers) | primary / secondary | ton_002, ton_003, nsdi_002 |
| Figure-by-figure walk: "Fig. N shows ..." → observation → "the main reason is ..." mechanistic explanation | primary | ton_001, ton_003, ton_005 |
| Cases where a baseline wins are stated plainly then contextualised | primary / secondary | ton_002, ton_003, nsdi_002 |
| Oracle / ideal upper-bound experiment to bound achievable gains | primary / secondary | ton_003, nsdi_002 |
| Parameter-sensitivity studies as their own numbered subsubsections | primary | ton_001 |
| Comparison across arms presented as overlap size + agreement %, with structurally unobservable cells flagged | primary | ton_004 |
| Lower-bound / upper-bound bounding argument, enumerated "for at least three reasons" | primary | ton_004 |
| Separate "Discussion and Limitations" section before Related Work | primary / secondary | ton_002, ton_004 (Discussion: Limitations + Ethics), nsdi_001, nsdi_002 |
| Limitations as a bold run-in paragraph inside the Conclusion | primary | ton_005 |
| Limitations distributed inline, no dedicated section | primary | ton_001, ton_003 |
| Anomalies/failure cases get their own subsection with a mechanism story, not dropped | primary | ton_003, ton_005 |
| No confidence intervals / significance tests anywhere; repetition reported as averages or max-spread | primary / secondary | ALL 7 |
| Conclusion restates findings per section + one limitations/future-work paragraph | primary | ton_004, ton_005 |

### Language Style Profile
| Dimension | Observed norm | Corpus role |
|---|---|---|
| Voice | active, "we"-dominant in every section incl. evaluation; system name as agent; passive only for external facts and setup | primary + secondary |
| Sentence length | medium, 15–28 words; occasional long chained sentence with a parenthetical (e.g., ...) gloss | primary |
| Hedging level | moderate: "may", "can", "likely", "we believe", "a likely explanation"; findings sentences with a number are unhedged | primary |
| Boosters | rare in ton_001/004/005; present in ton_002/003 ("remarkable", "great potential") — non-native register, not a norm to copy | primary |
| Mathematical density | low–moderate; formalism carried by pseudocode + notation table or by few numbered equations | primary |
| Transition style | enumerative First/Second/Finally; procedural "We now ..."; "We note that" as signpost; heavy explicit section cross-references ("as explained in Section IV-D", "§5") | primary |
| Paragraph length | 4–8 sentences; run-in bold leads open many paragraphs | primary |
| Captions | one-line for result figures; multi-sentence interpretive captions for mechanism/overview figures and for tables (define every encoding / abbreviation) | primary |

### IEEE/ToN format markers (5/5 primary unless noted)
Index Terms present (4–6 terms); Roman-numeral sections, lettered subsections, numbered 1) subsubsections
(ton_003 uses Arabic — a CS-society template variant); roadmap paragraph; tables captioned above in small
caps ("TABLE N"), figures below ("Fig. N"); author biographies + acknowledgements with grant numbers at the
end; appendices in 2/5 (hyperparameters, proofs, extra formulations); footnotes for URLs, caveats, and
acceptance notices; page count 14–15 (author-formatted arXiv versions; ToN's stated max is 16, 10 free).

### Conflict Table: Corpus Signals vs Static Base Rules vs paper-voice contract
| Dimension | Static base (cs_engineering) | Target journal (ToN corpus) | paper-voice contract (Philip's mandatory voice) | Resolution |
|---|---|---|---|---|
| Section order | Intro → Related Work (standalone, after intro) → System → Evaluation → Conclusion | Intro → Background/Motivation → Design → Implementation → Evaluation → [Discussion & Limitations] → Related Work (late, 6/7) → Conclusion | Intro → Background with fault model + named objectives EARLY → distinct Design → Implementation → Evaluation 1:1 vs objectives → Related Work second-to-last → Conclusion | ToN order = paper-voice order (both put Related Work second-to-last). Insert a standalone "Discussion and Limitations" before Related Work (ToN 002/004 + both NSDI). Base rule's early Related Work loses. |
| Threat/fault model | not addressed | "fault model" and a "targets and limitations" scope paragraph early (nsdi_002); scope in Background (ton_004) | explicit threat model with defended assumptions, named objectives, scope carve-outs with future-work deferral | Background carries a "Fault model, objectives and scope" subsection: assumptions each defended, objectives named (O1–O4) and reused as evaluation labels, common-mode carved out with a forward pointer to Discussion. |
| Contribution format | numbered list, 3–4, concrete verbs | list in 3/5 (ton_004: italic verb-first run-in headline + multi-sentence paragraph closing with the finding) | bulleted, bold verb-first headline ending in a period + 2–4 sentences | Bulleted, bold verb-first headline + 2–4 sentences, each closing with its finding and number; 4–5 items. Identical across all three once ton_004 is the model. |
| First-ness claim | "This is the first work to..." banned unless the search is cited | scoped along explicit axes that are the columns of the related-work comparison table (ton_004); hedge in Related Work (nsdi) | exactly one "To the best of our knowledge, this is the first ..." | Exactly one, scoped along the comparison-table axes (silicon-measured, sprayed fabric, 1e-3–1e-4 regime, head-to-head against the two passive detectors), placed in the contributions AND read off the comparison table in Related Work. The primitive is explicitly conceded as prior art in the same paragraph. |
| Voice / "we" | active, "we implement" | "we"-dominant everywhere | ~29 % of sentences contain "we"; "Consequently," glue; fronted "Because ..." clauses | No conflict; paper-voice fingerprint governs and voice_check enforces it. |
| Hedging / boosters | precise, no praise adjectives | moderate hedges; boosters only in the two non-native papers | hedges ~14/1000, boosters ~1/1000; "can" as workhorse modal; never "novel"/"robust"-as-praise | paper-voice wins (also the safer register for a hostile PC). Strike "novel", "remarkable", "significant" without a number. |
| Connectives | — | "Moreover", "Thus", "Overall", "In summary" appear | "Moreover" banned; "Furthermore" ≤2/paper; "Consequently," and "However," native | paper-voice wins. Use "We note that" sparingly (ToN-native signpost) — allowed. |
| Roadmap paragraph | "paper organization" in intro | 4/5 have it | not addressed | Include a one-paragraph roadmap at the end of the introduction (ToN norm). |
| Evaluation organisation | goals → setup → results → discussion | bulleted questions mapped 1:1 to subsections (2/5) + demonstration checklist (nsdi_002); run-in bold leads | organised 1:1 against named objectives; each experiment = why → setup → metric → result + figure pointer → "The reason is that ..." → takeaway | Name objectives O1–O4 in Background; open Evaluation with a short bulleted list mapping O1–O4 to subsections; every result paragraph carries the paper-voice experiment template. |
| Related-work device | group by approach, comparison table for 4+ systems | comparison table on the novelty axes (ton_004) + themed paragraphs with positioning sentences | themed paragraphs ending in objective/cost contrasts, "Compared to this work, X serves a different objective" | Both: the two comparison tables from RELATED-WORK-COMPARISON (own row last) + four themed paragraphs (families A–D), each closing with the paper-voice contrast move. |
| Discussion / limitations | limitations in conclusion | mixed; 4/7 have a dedicated section; failure cases get their own subsection | optional ~5 % discussion of deployment concerns | Dedicated "Discussion and Limitations" section (the paper has a real limitation — common-mode failure — that must be sectioned, not buried). Conclusion keeps one future-work sentence. |
| Statistics | mean ± sd across runs | none of the 7 report CIs | — | Keep Wilson CIs and seed counts, but in tables and captions, not in running prose; do not add significance-test language the corpus never uses. |
| Math density | state complexity for algorithms | 0–8 numbered equations typical | few equations; define by description then name | ≤ 6 numbered equations: ledger loss identity, the Z-test SNR condition that gives ~1/p, the e-BH threshold. No theorem environments (measurement paper). |
| Abstract | 150–200 words, one quantitative result | 170–230 words, present tense, contribution at sentence 3–4, numbers in the last two sentences | problem → limitation → proposal + mechanism → venue → verbatim headline numbers, no selling sentence | 200–240 words, one paragraph, NO abbreviations (ToN rule: spell out; no "FP", "CI", "MCP" — write "the ledger"), numbers close the abstract. |
| Tense | — | present throughout incl. results ("show") | present for framing/design, past for experimental acts, present for standing findings | paper-voice/scientific-style rule; ToN readers accept both. |
| Em dashes / parentheticals | — | ton_002 uses em-dash asides | em dashes banned; ", i.e.," / ", e.g.," glosses native | No em dashes. |
| Captions | self-explanatory captions naming variables | one-line result captions; interpretive multi-sentence captions for mechanism figures and tables | every result carries a figure/table pointer + mechanistic explanation in prose | One-line captions for result plots; multi-sentence captions defining encodings for the schematic, the scaling figure (budget ceiling, hollow markers), and every table. |
| Length | — | 14–15 pages author-formatted; 16 max, 10 free | — | Target 13–14 pages including references and biographies; appendix only for the silicon cell table if the body cannot hold it. |

### Red Flags (absent from the primary corpus or contradicted by it)
1. A "novel"/"robust"/"comprehensive" adjective doing the work of a number (only the two non-native papers do this; the measurement papers never do).
2. Mechanism detail or evaluation numbers in the introduction beyond one results-preview sentence.
3. An unscoped "first" claim (ton_004 scopes every axis; ton_005 refuses the word entirely).
4. Related Work placed before the method (1/7) — ToN readers expect it late.
5. Claims stated without a "the reason is" explanation (every corpus result paragraph has one).
6. Evaluation setup without hardware model and software versions (all three prototype papers give them).
7. Significance-test / confidence-interval language in prose (none of the 7 do it) — keep CIs in tables.
8. Dropping the failure cases: the corpus gives anomalies their own subsection (ton_003, ton_005) and names production false negatives (nsdi_002). The common-mode failure must be a section, not a footnote.
9. Missing Index Terms, roadmap, or author-biography block.
10. Over-formal apparatus (theorem/proof) in a measurement paper.
