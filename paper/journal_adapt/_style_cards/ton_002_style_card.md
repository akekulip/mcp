## Paper Style Card: ton_002

HARD RULE: I will describe only structure and rhetorical patterns. I will not quote, paraphrase, or reproduce any content from this paper.

METADATA
- Paper ID: ton_002
- Authors: Güemes-Palau, C.; Ferriol-Galmés, M.; Paillisse-Vilanova, J.; López-Brescó, A.; Barlet-Ros, P.; Cabellos-Aparicio, A.
- Year: 2026 (IEEE Transactions on Networking, special issue on AI and Networking; author-accepted version)
- Corpus role: primary_target_journal
- Conversion status: converted_checked
- Method type: system+evaluation (ML model trained on data from a physical testbed; empirical comparison against simulators)

A. ABSTRACT STYLE
- Opening move: one-sentence statement that a modeling activity is central to the field, with a range of example tasks.
- Structure (sequence of moves): (1) importance of the activity; (2) limitation of the traditional approach on two named axes (cost, accuracy); (3) "This paper introduces X, a novel integration of A with B" to address them; (4) mechanism in one sentence (the physical component used as an accelerator for data generation and fidelity); (5) headline results as a percentage reduction and a speedup multiplier versus state-of-the-art; (6) architectural property (modular, built dynamically from scenario characteristics) and the generalization consequence including a size multiple; (7) an additional named feature with its benefit; (8) closing sentence framing the approach as promising and useful to operators.
- Tense pattern: present throughout; results in present ("show").
- Contribution placement: sentence 3 of roughly 9; results in the middle; features and outlook at the end.
- Length (approx words): ~190.
- Register: formal with mildly promotional adjectives ("pivotal", "novel", "valuable"); numbers used as evidence.

B. INTRODUCTION ARCHITECTURE
- Hook type: trend statement ("in recent years, significant progress in ...") followed by a list of operator tasks with one citation each.
- Opening move: two paragraphs describing why models matter and the standard technique's strengths, before the problem is stated.
- Contribution placement: the proposal arrives in paragraph 4 ("In this paper, we propose a hybrid approach ...") and is named in paragraph 6 ("we introduce X (hereafter X-short)"); headline results are given in paragraph 8 with a workflow figure reference.
- Contribution format: prose only — no bulleted or numbered contribution list anywhere in the introduction.
- Literature positioning: integrated — a paragraph on prior accelerators (two named systems with their speedups) is used to show that they solve only one of the two labeled problems; a standalone Related Work section also exists at §VII.
- Roadmap: explicit, one closing paragraph with section numbers in parentheses.
- Intro length (paragraphs): 9 paragraphs, including a two-item numbered list of labeled problems and two early figures (a workflow figure and a motivating cost plot) placed within the introduction's page span.

C. CONTRIBUTION EXPRESSION
- Voice: mixed — "we propose / we introduce / we aim" in the intro; "This paper introduces / This paper proposes" in abstract, discussion opening, and conclusion; the system name as subject is very frequent.
- Claim strength: strong ("remarkable accuracy", "significantly reduces", "substantially outperforms") but always paired with a number and a comparison set.
- Number of contributions: not enumerated; implicitly four (testbed-plus-ML integration; dynamically constructed modular architecture that generalizes; the temporal aggregation feature; accuracy and speed results).

D. LITERATURE REVIEW
- Structure: standalone section (§VII Related Works), placed after the Discussion and Limitations section and before Conclusions. A separate §II Motivation (two subsections with their own experiments) also carries a critical framing of the dominant prior approach.
- Organization: chronological/taxonomic — early history (analytical models vs. simulation) → DES accelerators (parallelization; a link-decomposition simulator) → ML replacing parts of the simulation engine (two named systems) → end-to-end ML models (the authors' own predecessor) → testbed-grounded approaches (two named systems). Each item receives a one-sentence characterization followed by a one-sentence limitation contrasted with the proposed system.
- Critical engagement: moderate — every prior system is differentiated by scope (topology restriction, packet-count dependence, single-path focus, lack of temporal expressiveness), including the authors' own earlier model.

E. METHOD / SYSTEM
- Entry point: a dedicated Motivation section (§II) with two subsections, each presenting an original measurement (a cost-vs-packets plot; a simulator-vs-testbed error table) as evidence for one labeled problem. The design section (§III) then opens with intuition, an explanation of why the simplest end-to-end alternative fails, a bulleted list of element interactions, and an overview figure (example topology and its expanded representation) with a paragraph-length caption.
- Notation density: moderate but carried by pseudocode (two algorithm listings) and a notation table, not by numbered equations — the main text contains no numbered equations.
- Exposition style: explanatory and metaphor-driven (reusable "building blocks" shared across elements of the same type); each subsection first states what the design does, then why the obvious alternative is inadequate. A features table lists per-element inputs and whether each is constant or variable over time. The testbed section (§IV) is a bulleted hardware specification with nested sub-bullets for link speeds and a block-diagram figure.
- Assumption/design-choice justification: explicit — flow-level rather than packet-level granularity is justified in the introduction as a trade-off; shared neural blocks are justified by generalization; the temporal windowing is justified as a middle ground between two extremes; the readout design is justified in the discussion by an additivity property of the target metric.

F. RESULTS / EVALUATION
- Primary vehicle: comparison of the trained model against a legacy simulator, two accelerated simulators, and the authors' prior model, on data from the physical testbed plus real traffic traces; one scaling experiment uses simulated data with an explicit justification for why.
- Narrative style: opens by stating that the evaluation exists "to assess our claims" and lists four bulleted questions, two of which reference the labeled problems from the introduction. Subsections then answer them in order: inference cost, accuracy (synthetic then real traffic), generalization to larger unseen topologies, and the effect of the temporal window size. Results are read from tables and figures with ranges of error reduction; metric definitions are restated inside the evaluation section.
- Setup-description depth: high — server CPU, RAM, OS, ML framework version, footnoted code repository, appendix pointer for hyperparameters; dataset summary table with scenario counts and prediction counts per split; three traffic distributions described in a numbered list; topology size ranges and hop ranges stated.
- Mechanism emphasis: moderate — why the model generalizes is deferred to the Discussion section; the evaluation itself explains cost behavior (independence from packet count, dependence on window count).
- Robustness/limitation signaling: strong — cases where a baseline is better (a metric on real traces) are stated plainly, then contextualized by cost; the testbed's node-count ceiling is admitted and the use of simulated samples for the scale test is defended; the window-size trade-off is shown as a cost curve.
- Use of numbered evaluation questions or run-in bold paragraph leads: bulleted evaluation questions at the top of the section; lettered subsections; numbered subsubsections 1), 2) inside the accuracy subsection; no run-in bold leads.

G. DISCUSSION / LIMITATIONS
- Function: a separate, long §VI "Discussion and Limitations" with five lettered subsections — generalization to larger networks (with two numbered considerations), handling arbitrary traffic distributions, adapting to a transport protocol not yet evaluated, generalization to unseen hardware, and the temporal component. Each subsection follows the pattern: what the design does → why it should hold → what it cannot yet do → what future work would require.
- Scope of claims: explicitly bounded — evaluation is UDP-only; some features are scale-dependent; retraining is needed across time scales; hardware similarity is a precondition for generalization.
- Limitation acknowledgment: proactive and extensive; limitations are stated in their own titled section and revisited in the conclusion's framing.
- Separate Discussion or Limitations section: yes, combined, placed between Evaluation and Related Work.

H. LANGUAGE STYLE
- Voice: mixed — "we" in framing and procedure ("we compare", "we evaluate", "we argue"), with the system name as subject for most descriptive sentences; passive appears in setup descriptions ("were used", "is performed").
- Sentence length: medium-to-long (20–30 words common), with em-dash asides and parenthetical examples ("e.g., ...").
- Hedging level: moderate — "may", "we argue", "it is reasonable to consider", "suggests", "likely"; results sentences are unhedged when a number is attached.
- Transition style: enumerative ("First, ... Second, ... Finally, ..."), contrastive ("On one hand / On the other hand", "That said,"), and summarizing ("Overall,", "Altogether,", "In summary,"); frequent back-references ("as discussed in Section ...", "back in Section ...").
- Mathematical density: low in prose; formalism lives in two pseudocode listings and a symbol table.
- Use of first-person plural in evaluation: yes, alongside impersonal "the results show".
- Paragraph length: medium (4–7 sentences).

I. IEEE/ToN FORMAT MARKERS
- Index Terms present: yes (4 terms).
- Section numbering style: Roman numerals (I–VIII), lettered subsections (A.–E.), numbered subsubsections (1), 2)).
- Appendix usage: two appendices (a hyperparameter table with a short prose note on implementation versions; a figure gallery of training topologies), placed after Acknowledgments and before References.
- Where related work sits: §VII, after Discussion and Limitations, before Conclusions; Motivation (§II) directly follows the Introduction.
- Typical figure captions: mostly one-line; the design overview figure has a paragraph-length caption that explains the representation and the sharing of blocks; the cost-comparison figure has a multi-sentence caption explaining dashed/dotted line semantics.
- Equations numbered: none in the main text; algorithms are numbered (1, 2) with line numbers referenced from prose.
- Subsections/subsubsections depth: three levels (Roman → letter → number).
- Other markers: special-issue running header; IEEE copyright footer; footnotes for code repositories; tables with small-caps captions above; a bulleted hardware specification with nested bullets; short author biographies at the end (some one line); grant-numbered acknowledgments.

J. WHAT THIS PAPER DOES NOT DO
- No bulleted or numbered contribution list in the introduction.
- No numbered equations; no theorem or proof.
- No architectural ablation (only a window-size sweep); no confidence intervals or repeated-seed variance.
- No separate Background section — background is folded into an evidence-bearing Motivation section.
- No run-in bold paragraph leads anywhere.

K. DISTINCTIVE PATTERNS
- Two problems are labeled and numbered in the introduction and then threaded through the paper: cited in the abstract's logic, in the proposal paragraph, in the motivation subsections, and in two of the four evaluation questions.
- The Motivation section is a mini-study: each subsection presents an original measurement (plot or error table) rather than a literature summary, so the problem is demonstrated before the design is introduced.
- The evaluation opens with bulleted research questions that map one-to-one onto its subsections, and the Discussion and Limitations section is long, titled, multi-subsection, and placed before Related Work.
- Formalism is carried by pseudocode plus a notation table rather than numbered equations, and the physical testbed is documented as a bulleted specification list with a block diagram.
