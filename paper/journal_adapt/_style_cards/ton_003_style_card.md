## Paper Style Card: ton_003

HARD RULE: I will describe only structure and rhetorical patterns. I will not quote, paraphrase, or reproduce any content from this paper.

METADATA
- Paper ID: ton_003
- Authors: Liu, C.; Aggarwal, V.; Lan, T.; Geng, N.; Yang, Y.; Xu, M.; Li, Q.
- Year: 2023 (IEEE/ACM Transactions on Networking; arXiv v1 May 2023)
- Corpus role: primary_target_journal
- Conversion status: converted_checked
- Method type: mixed (learning-based framework + optimization recasting with a theorem and proof + simulation-based evaluation on real topologies)

A. ABSTRACT STYLE
- Opening move: a definitional sentence naming the problem area, stating its goal, and asserting it has received significant attention.
- Structure (sequence of moves): (1) problem definition and importance; (2) two-branch critique of existing approaches (model-based optimization does not scale; learning-based solutions are task-specific); (3) "In this paper, we show that X provides a common kernel" — an insight claim; (4) "we develop a unified learning-based framework, NAME" with the acronym expanded; (5) mechanism in one sentence (graph representation; local and global attention); (6) scope: three named problem instances that can be recast through the kernel and solved over a small critical subset; (7) experiments on real topologies with accuracy and generalization claims across two routing schemes; (8) closing sentence with three speedup multipliers, one per use case, and a "negligible gap" qualifier.
- Tense pattern: present throughout.
- Contribution placement: middle (sentences 3–4 of 8).
- Length (approx words): ~230.
- Register: formal, insight-led ("we show that ... provides a common kernel"), assertive.

B. INTRODUCTION ARCHITECTURE
- Hook type: trend statement (growth in scale and complexity makes failures common) supported by two dense citation clusters.
- Opening move: a survey paragraph listing the angles prior research has taken, then coining an umbrella term for the problem family, then stating the shared limitation (scalability of model-based optimization).
- Contribution placement: paragraph 2 opens with "We observe that ..." (the cornerstone insight); paragraph 3 opens with "In this paper, we identify ..." and names the framework; contributions are enumerated in a bulleted list after paragraph 6.
- Contribution format: bulleted list (5 bullets), each 2–4 lines, introduced by a colon sentence; followed by a closing paragraph that positions the work as unique and as a first step toward a new class of algorithms.
- Literature positioning: both — paragraphs 1–2 and 4 characterize prior optimization and learning approaches and their limits; §2.1 is a titled "limitations of existing approaches" subsection with a cost table; a standalone Related Work section exists at §7.
- Roadmap: absent from the introduction. Section-level roadmaps appear instead at the top of §2 (two sentences) and in §3 Overview (which previews the three recasts) and at the top of §4 (a four-step "first/second/third/finally" list).
- Intro length (paragraphs): 6 prose paragraphs + 5 bullets + 1 closing positioning paragraph.

C. CONTRIBUTION EXPRESSION
- Voice: mixed — "we show / we analyze / we present and prove / we further analyze" alternating with the framework name as subject ("NAME is able to support ...").
- Claim strength: strong — the kernel insight is framed as the central contribution; the closing intro paragraph uses "unique" and "new direction"; speedup magnitudes appear in the intro prose; later evaluation uses "great potential" language.
- Number of contributions: 5 bullets (the kernel insight; the attention-based architecture; three use cases with proven guarantees; real-topology evaluation; extension to a routing scheme that resists LP modeling).

D. LITERATURE REVIEW
- Structure: standalone section (§7 Related Work), placed after Evaluation and before Conclusion; plus §2 "Background and Motivation" whose first subsection is an explicit limitations-of-existing-work discussion with a computational-overhead table as evidence.
- Organization: by problem type with run-in bold leads — robust validation → robust planning → fault-tolerant traffic engineering → graph neural networks for network modeling and optimization. Each block: 2–4 prior works characterized, then a sentence on why their technique does not transfer or how the proposed framework is orthogonal/complementary.
- Critical engagement: high — states that duality/relaxation tricks used by named prior systems cannot be applied to other formulations; cites a paper showing a named prior scheme fails in certain cases; explicitly claims orthogonality to a named competitor and describes how the framework could assist it; observes that ML traffic-engineering work overlooks resiliency.

E. METHOD / SYSTEM
- Entry point: formal setup begins inside the Motivation section — three problems are defined in a bulleted list, a cost table and a distribution figure are presented as evidence, and the impact function is defined as Eq. (1) before the framework section starts. §3 Overview then gives a block-diagram figure (inputs → model → critical subset → three recast problems) and a bulleted list of three desired properties. §4 opens with a four-step preview.
- Notation density: high — numbered equations run from (1) through (20) across main text and appendices; set-builder definitions for three failure classes; three loss functions; three LP/ILP formulations set as display blocks; a notation table in Appendix A.
- Exposition style: insights-then-design. §4.1 introduces a simplified surrogate problem, validates it empirically with a figure, then lists five empirical "insights" under run-in bold leads, each an observation about the phenomenon that later justifies an architectural choice. §4.2 model design uses run-in bold leads (input graph; input state; model design; generalization; computational efficiency). §4.3 loss functions are motivated by an observed failure mode of the standard loss (conservative predictions) and by a sampling scheme. §4.4 training uses bold leads for two training phases and inference. §5 has three subsections, each following the pattern: original formulation as a numbered LP/ILP block → recast formulation using the learned function as a numbered equation → argument for why only a small subset must be considered; the second subsection states a theorem inline with the proof deferred to an appendix; the third subsection defers the full formulation to an appendix.
- Assumption/design-choice justification: explicit and empirical — architectural choices are tied back to the numbered insights; the surrogate problem is justified with a measured error distribution; a caveat paragraph admits the optimal-routing model may not be feasible in practice while arguing it is still widely used; the two-phase training is justified as a generalization/accuracy trade-off.

F. RESULTS / EVALUATION
- Primary vehicle: offline experiments — a trained model compared against a plain optimization solver on synthetic and real topologies, with real traffic matrices for two topologies; results in ROC curves, relative-error CDFs, time/memory plots, and three tables (large-topology metrics; real-traffic-matrix metrics; speedup ranges by topology-size bucket).
- Narrative style: opens with three bulleted key questions, each carrying a § pointer to the answering subsection. §6.1 setup uses run-in bold leads (dataset; training; then one lead per use case describing the baseline and the comparison). §6.2 and §6.3 use run-in bold leads per experiment. Result sentences follow a fixed template — "the results are shown in Fig./Table N" → "we can find that ..." → a reason or implication sentence. Model variants are reported as first-phase vs. first-plus-second-phase rows.
- Setup-description depth: high — CPU and GPU models, ML framework, solver name and version reference, topology generators and repositories, traffic-matrix generation model, link-capacity randomization scheme, train/test split rationale (seen vs. unseen topologies), training duration, memory ceiling of the server; two dataset tables (one per routing scheme).
- Mechanism emphasis: moderate — results are interpreted by referring back to the loss design and to the number of critical scenarios available for second-phase training; a memory-ceiling explanation is given for infeasible baseline runs.
- Robustness/limitation signaling: strong and candid — a topology where the regression model fails is named and explained; degradation on real traffic matrices before second-phase training is reported; an "ideal oracle" experiment with ground-truth critical sets is used to bound the achievable speedup; a closing paragraph of the evaluation states outright that the approach is not perfect on all test cases before restating its potential.
- Use of numbered evaluation questions or run-in bold paragraph leads: both — bulleted questions with § pointers at the top, run-in bold leads throughout setup and results.

G. DISCUSSION / LIMITATIONS
- Function: no separate discussion. Limitations appear inline: a trade-off paragraph at the start of §4.4; a practicality caveat at the end of §4.1; the candor paragraph closing §6.3; appendix notes on training difficulty.
- Scope of claims: broad in framing (a reusable kernel for a whole problem class) but bounded in the evaluation by explicit failure cases and by reporting speedup as min/max/mean ranges per size bucket.
- Limitation acknowledgment: moderate, distributed rather than sectioned.
- Separate Discussion or Limitations section: absent. Conclusion is a single summary paragraph with no future-work list.

H. LANGUAGE STYLE
- Voice: active, "we"-heavy ("we show", "we note that", "we can find that", "we propose"); the framework name is also used as subject. "We note that" and "We can find that" are the dominant signposts.
- Sentence length: medium (15–25 words), with some long sentences stacking clauses; non-native phrasing and a few typos are present in this author-accepted version.
- Hedging level: moderate-to-low — "could", "may", "potential" alongside strong evaluative words ("amazing potential", "great potential", "significant").
- Transition style: enumerative ("First, ... Second, ... Third, ... Finally, ..."), "To this end,", "In particular,", "Moreover,", "Further,", "Thus"; section-opening sentences state what the section will do.
- Mathematical density: high — display formulations, numbered equations, a theorem environment, set-builder notation, and a symbol table.
- Use of first-person plural in evaluation: yes, throughout.
- Paragraph length: medium-to-long (5–10 sentences), especially in method sections.

I. IEEE/ToN FORMAT MARKERS
- Index Terms present: yes (4 terms).
- Section numbering style: Arabic numerals (1, 2, 2.1, 4.3, 6.2 ...) with § used as the cross-reference symbol throughout; the preprint layout resembles the IEEE Computer Society transactions template (full-width abstract with a separator glyph) rather than the classic two-column IEEEtran abstract.
- Appendix usage: four appendices after the references — notations table; proof of the theorem; the full optimization formulation for one use case; experiment details with hyperparameter table, training procedure, a second dataset table for the alternative routing scheme, and additional figures including an oracle experiment.
- Where related work sits: §7, after Evaluation, before Conclusion; §2 Background and Motivation follows the Introduction.
- Typical figure captions: one-line for result figures (arranged three-across); table captions are multi-sentence, placed above tables, and carry caveats (e.g., what a failure marker or an infinity symbol denotes) and footnote references.
- Equations numbered: yes, (1)–(20) continuous across main text and appendices.
- Subsections/subsubsections depth: two numeric levels (x, x.y) plus run-in bold paragraph leads as the third level; no numbered subsubsections.
- Other markers: a numbered theorem with proof deferred to an appendix; footnotes used for experimental caveats; author affiliations in a first-page bulleted block; no author biographies in this version.

J. WHAT THIS PAPER DOES NOT DO
- No roadmap paragraph in the introduction; no separate Discussion or Limitations section; no future-work list in the conclusion.
- No hardware prototype or testbed — evaluation is entirely solver-based simulation on stored topologies.
- No architectural ablation (e.g., local vs. global attention removed) and no confidence intervals or seed variance.
- No numbered subsubsections — structure below x.y is carried entirely by run-in bold leads.
- No artifact-availability or reproducibility statement.

K. DISTINCTIVE PATTERNS
- A single "common kernel" insight is elevated to the headline contribution and repeated as the organizing frame in the abstract, the intro's second paragraph, the overview section, and each use-case subsection, where a classic formulation is displayed and then "recast" through the learned function.
- An empirical insights block precedes the model design: five observations under run-in bold leads, each validated with a figure or argument, and each later cited as the justification for an architectural or input-encoding choice.
- A theorem-and-proof performance guarantee sits inside an otherwise ML-systems paper, with the proof and a full formulation pushed to appendices, so the main text keeps a systems pace while claiming formal support.
- The evaluation opens with bulleted questions that carry § pointers, reports every model in two rows (general phase vs. general plus task-specific phase), includes an oracle upper-bound experiment, and closes with a candor paragraph admitting the method is not optimal everywhere.
